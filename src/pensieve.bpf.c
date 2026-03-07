// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <math.h>

#include "pensieve.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile unsigned long long granularity_ns = 1e9;

typedef enum thread_state {
  SCHEDULED_OUT = 0,
  SCHEDUDED_IN = 1,
} thread_state_t;

struct internal_thread_info {
  u64 thread_creation_ts;
  u64 block_start_ts;
  thread_state_t state;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, pid_t);
  __type(value, u64);
} exec_start SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, pid_t);
  __type(value, u64);
} scheduled_out_start SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, pid_t);
  __type(value, struct internal_thread_info);
} thread_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
  struct task_struct *task;
  unsigned fname_off;
  struct event *e;
  pid_t pid;
  u64 ts;

  /* remember time exec() was executed for this PID */
  pid = bpf_get_current_pid_tgid() >> 32;
  ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

  /* don't emit exec events when minimum duration is specified */
  if (min_duration_ns)
    return 0;

  /* reserve sample from BPF ringbuf */
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;

  /* fill out the sample with data */
  task = (struct task_struct *)bpf_get_current_task();

  e->exit_event = false;
  e->pid = pid;
  e->ppid = BPF_CORE_READ(task, real_parent, tgid);
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  fname_off = ctx->__data_loc_filename & 0xFFFF;
  bpf_probe_read_str(&e->filename, sizeof(e->filename),
                     (void *)ctx + fname_off);

  /* successfully submit it to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
  struct task_struct *task;
  struct event *e;
  pid_t pid, tid;
  u64 id, ts, *start_ts, duration_ns = 0;

  /* get PID and TID of exiting thread/process */
  id = bpf_get_current_pid_tgid();
  pid = id >> 32;
  tid = (u32)id;

  /* ignore thread exits */
  if (pid != tid)
    return 0;

  /* if we recorded start of the process, calculate lifetime duration */
  start_ts = bpf_map_lookup_elem(&exec_start, &pid);
  if (start_ts)
    duration_ns = bpf_ktime_get_ns() - *start_ts;
  else if (min_duration_ns)
    return 0;
  bpf_map_delete_elem(&exec_start, &pid);

  /* if process didn't live long enough, return early */
  if (min_duration_ns && duration_ns < min_duration_ns)
    return 0;

  /* reserve sample from BPF ringbuf */
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;

  /* fill out the sample with data */
  task = (struct task_struct *)bpf_get_current_task();

  e->exit_event = true;
  e->duration_ns = duration_ns;
  e->pid = pid;
  e->ppid = BPF_CORE_READ(task, real_parent, tgid);
  e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;
}

static s64 start_of_block(u64 current_time, u64 start_time) {
  if (current_time < start_time) {
    bpf_printk("start_of_block [%d] current is before start time\n");
    return -1;
  }
  long n = floor((current_time - start_time) / granularity_ns);
  return start_time + n * granularity_ns;
}

static int handle_sched_switch(void *ctx, bool preempt,
                               struct task_struct *prev,
                               struct task_struct *next) {
  // struct internal_key *i_keyp, i_key;
  // struct val_t *valp, val;
  s64 delta;
  // u32 pid;
  pid_t pid, tgid;
  u64 *scheduled_out_ts_p, scheduled_out_ts;

  // Handle the task that is scheduled out
  pid = BPF_CORE_READ(prev, pid);
  tgid = BPF_CORE_READ(prev, tgid);

  // bpf_printk("handle_sched_switch [%d] from (%d, %d) to (%d, %d)\n",
  //            bpf_get_smp_processor_id(), pid, tgid, BPF_CORE_READ(next, pid),
  //            BPF_CORE_READ(next, tgid));

  // The scheduled out thread was not the idle thread
  if (pid) {
    scheduled_out_ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&scheduled_out_start, &pid, &scheduled_out_ts, 0);
  }

  pid = BPF_CORE_READ(next, pid);
  tgid = BPF_CORE_READ(next, tgid);

  // The newly scheduled thread is the idle thread
  if (!pid)
    return 0;

  scheduled_out_ts_p = bpf_map_lookup_elem(&scheduled_out_start, &pid);
  if (!scheduled_out_ts_p) {
    bpf_printk("handle_sched_switch [%d] pid (%d, %d) not found in "
               "scheduled_out_start\n",
               bpf_get_smp_processor_id(), pid, tgid);
    return 0;
  }
  delta = (s64)(bpf_ktime_get_ns() - *scheduled_out_ts_p);
  if (delta < 0)
    goto cleanup;

  // bpf_printk(
  //     "handle_sched_switch [%d] pid (%d, %d) was scheduled out for %lld
  //     ns\n", bpf_get_smp_processor_id(), pid, tgid, delta);

  // delta /= 1000U;
  // valp = bpf_map_lookup_elem(&info, &i_keyp->key);
  // if (!valp)
  //   goto cleanup;
  // __sync_fetch_and_add(&valp->delta, delta);

cleanup:
  bpf_map_delete_elem(&scheduled_out_start, &pid);
  return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev,
             struct task_struct *next) {
  return handle_sched_switch(ctx, preempt, prev, next);
}

// SEC("raw_tp/sched_switch")
// int BPF_PROG(sched_switch_raw, bool preempt, struct task_struct *prev,
//              struct task_struct *next) {
//   return handle_sched_switch(ctx, preempt, prev, next);
// }

// Thread creation
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx) {
  bpf_printk("fork parent=%d child=%d\n", ctx->parent_pid, ctx->child_pid);

  return 0;
}

#define EXIT_COMM_LEN 16
// Thread destruction
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx) {
  char comm[TASK_COMM_LEN] = {};
  bpf_get_current_comm(&comm, sizeof(comm));
  // ctx->pid = thread id
  bpf_printk("exit: tid=%d, comm = %s \n", ctx->pid, comm);
  return 0;
}
