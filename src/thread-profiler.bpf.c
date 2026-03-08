// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <math.h>

#include "thread-profiler.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// const volatile unsigned long long granularity_ns = 1e9; // Second
const volatile unsigned long long granularity_ns = 1e8; // 0.1 Second
// const volatile unsigned long long granularity_ns = 1e6; // Millisecond
const volatile bool filter_by_tgid = false;
const volatile bool filter_by_pid = false;

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
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u8);
  __uint(max_entries, MAX_PID_NR);
} tgids SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u8);
  __uint(max_entries, MAX_TID_NR);
} pids SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

static bool allowed_pid_tgid(pid_t pid, pid_t tgid) {
  if (filter_by_tgid && !bpf_map_lookup_elem(&tgids, &tgid))
    return false;
  if (filter_by_pid && !bpf_map_lookup_elem(&pids, &pid))
    return false;
  return true;
}

static bool allowed_task(struct task_struct *task) {
  u32 pid = BPF_CORE_READ(task, pid);
  u32 tgid = BPF_CORE_READ(task, tgid);

  return allowed_pid_tgid(pid, tgid);
}

// SEC("tp/sched/sched_process_exec")
// int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
//   struct task_struct *task;
//   unsigned fname_off;
//   struct event *e;
//   pid_t pid;
//   u64 ts;

//   /* remember time exec() was executed for this PID */
//   pid = bpf_get_current_pid_tgid() >> 32;
//   ts = bpf_ktime_get_ns();
//   bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

//   /* don't emit exec events when minimum duration is specified */
//   if (min_duration_ns)
//     return 0;

//   /* reserve sample from BPF ringbuf */
//   e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
//   if (!e)
//     return 0;

//   /* fill out the sample with data */
//   task = (struct task_struct *)bpf_get_current_task();

//   e->exit_event = false;
//   e->pid = pid;
//   e->ppid = BPF_CORE_READ(task, real_parent, tgid);
//   bpf_get_current_comm(&e->comm, sizeof(e->comm));

//   fname_off = ctx->__data_loc_filename & 0xFFFF;
//   bpf_probe_read_str(&e->filename, sizeof(e->filename),
//                      (void *)ctx + fname_off);

//   /* successfully submit it to user-space for post-processing */
//   bpf_ringbuf_submit(e, 0);
//   return 0;
// }

// SEC("tp/sched/sched_process_exit")
// int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
//   struct task_struct *task;
//   struct event *e;
//   pid_t pid, tid;
//   u64 id, ts, *start_ts, duration_ns = 0;

//   /* get PID and TID of exiting thread/process */
//   id = bpf_get_current_pid_tgid();
//   pid = id >> 32;
//   tid = (u32)id;

//   /* ignore thread exits */
//   if (pid != tid)
//     return 0;

//   /* if we recorded start of the process, calculate lifetime duration */
//   start_ts = bpf_map_lookup_elem(&exec_start, &pid);
//   if (start_ts)
//     duration_ns = bpf_ktime_get_ns() - *start_ts;
//   else if (min_duration_ns)
//     return 0;
//   bpf_map_delete_elem(&exec_start, &pid);

//   /* if process didn't live long enough, return early */
//   if (min_duration_ns && duration_ns < min_duration_ns)
//     return 0;

//   /* reserve sample from BPF ringbuf */
//   e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
//   if (!e)
//     return 0;

//   /* fill out the sample with data */
//   task = (struct task_struct *)bpf_get_current_task();

//   e->exit_event = true;
//   e->duration_ns = duration_ns;
//   e->pid = pid;
//   e->ppid = BPF_CORE_READ(task, real_parent, tgid);
//   e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
//   bpf_get_current_comm(&e->comm, sizeof(e->comm));

//   /* send data to user-space for post-processing */
//   bpf_ringbuf_submit(e, 0);
//   return 0;
// }

static u64 get_block_index(u64 current_time, u64 start_time) {
  if (current_time < start_time) {
    bpf_printk("get_block_index [%d] current is before start time\n");
    return -1;
  }
  return (current_time - start_time) / granularity_ns;
}

static s64 start_of_block(u64 current_time, u64 start_time) {
  if (current_time < start_time) {
    bpf_printk("start_of_block [%d] current is before start time\n");
    return -1;
  }
  s64 n = (current_time - start_time) / granularity_ns;
  return start_time + n * granularity_ns;
}

static int create_new_thread_info(struct internal_thread_info *info_p,
                                  pid_t pid, thread_state_t initial_state,
                                  u64 current_time) {
  info_p->thread_creation_ts = current_time;
  info_p->block_index = 0;
  info_p->block_start_ts = current_time;
  info_p->first_block_event_ts = current_time;
  info_p->last_event_ts = current_time;
  info_p->offcpu_time_ns = 0;
  info_p->state = initial_state;

  return bpf_map_update_elem(&thread_map, &pid, info_p, BPF_ANY);
}

static int submit_current_block(pid_t pid,
                                struct internal_thread_info *info_p) {
  struct profile_block *profile_block_p;

  /* reserve sample from BPF ringbuf */
  profile_block_p = bpf_ringbuf_reserve(&rb, sizeof(*profile_block_p), 0);
  if (!profile_block_p)
    return 0;

  profile_block_p->tid = pid;
  profile_block_p->block_index = info_p->block_index;
  profile_block_p->block_start_time_ns = info_p->block_start_ts;
  profile_block_p->first_event_time_ns = info_p->first_block_event_ts;
  profile_block_p->last_event_time_ns = info_p->last_event_ts;
  profile_block_p->offcpu_time_ns = info_p->offcpu_time_ns;
  profile_block_p->end_state = info_p->state;

  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(profile_block_p, 0);
  return 0;
}

static int bump_block(struct internal_thread_info *info_p,
                      u64 current_block_index, u64 current_time_ts) {
  info_p->block_index = current_block_index;
  info_p->block_start_ts =
      start_of_block(current_time_ts, info_p->thread_creation_ts);
  info_p->first_block_event_ts = current_time_ts;
  info_p->last_event_ts = current_time_ts;
  info_p->offcpu_time_ns = 0;
  return 0;
}

// static struct internal_thread_info initial_thread_info = {};

static int handle_sched_switch(void *ctx, bool preempt,
                               struct task_struct *prev,
                               struct task_struct *next) {
  // struct internal_key *i_keyp, i_key;
  // struct val_t *valp, val;
  s64 delta;
  // u32 pid;
  pid_t pid, tgid;
  u64 current_time, current_block_index;

  struct internal_thread_info *info_p, info = {};

  // Handle the task that is scheduled out
  pid = BPF_CORE_READ(prev, pid);
  tgid = BPF_CORE_READ(prev, tgid);

  // bpf_printk("handle_sched_switch [%d] from (%d, %d) to (%d, %d)\n",
  //            bpf_get_smp_processor_id(), pid, tgid, BPF_CORE_READ(next, pid),
  //            BPF_CORE_READ(next, tgid));
  current_time = bpf_ktime_get_ns();

  // The scheduled out thread was not the idle thread
  if (pid && allowed_task(prev)) {
    // scheduled_out_ts = current_time;
    // bpf_map_update_elem(&scheduled_out_start, &pid, &scheduled_out_ts, 0);

    info_p = bpf_map_lookup_elem(&thread_map, &pid);
    if (!info_p) {
      // There was no thread info, create new
      bpf_printk("handle_sched_switch: no prev thread info (%d)\n", pid);
      // info.thread_creation_ts = current_time;
      // info.block_index = 0;
      // info.block_start_ts = current_time;
      // info.first_block_event_ts = current_time;
      // info.last_event_ts = current_time;
      // info.offcpu_time_ns = 0;
      // info.state = SCHEDULED_IN;
      create_new_thread_info(&info, pid, SCHEDULED_IN, current_time);

      // bpf_map_update_elem(&thread_map, &pid, &info, BPF_ANY);
      info_p = bpf_map_lookup_elem(&thread_map, &pid);
      if (!info_p) {
        bpf_printk(
            "handle_sched_switch: Could not create thread info for prev (%d)\n",
            pid);
        return 0;
      }
    }

    // bpf_printk("handle_sched_switch: prev thread info (%d)\n", pid);

    current_block_index =
        get_block_index(current_time, info_p->thread_creation_ts);
    // bpf_printk("handle_sched_switch: current_block_index (%lld)\n",
    //            current_block_index);

    if (current_block_index > info_p->block_index) {
      // The last event was in a previous block
      // We need to submit this block to the user space
      submit_current_block(pid, info_p);
      bump_block(info_p, current_block_index, current_time);
    }

    info_p->last_event_ts = current_time;
    info_p->state = SCHEDULED_OUT;
  }

  // Handle the task that is just scheduled in

  pid = BPF_CORE_READ(next, pid);
  tgid = BPF_CORE_READ(next, tgid);

  // The newly scheduled thread is the idle thread
  if (!pid || !allowed_task(next))
    return 0;

  // scheduled_out_ts_p = bpf_map_lookup_elem(&scheduled_out_start, &pid);
  // if (!scheduled_out_ts_p) {
  //   // bpf_printk("handle_sched_switch [%d] pid (%d, %d) not found in "
  //   //            "scheduled_out_start\n",
  //   //            bpf_get_smp_processor_id(), pid, tgid);
  //   return 0;
  // }
  info_p = bpf_map_lookup_elem(&thread_map, &pid);
  if (!info_p) {
    // This thread was not yet encountered
    create_new_thread_info(&info, pid, SCHEDULED_OUT, current_time);
    info_p = bpf_map_lookup_elem(&thread_map, &pid);
    if (!info_p) {
      bpf_printk(
          "handle_sched_switch: Could not create thread info for next (%d)\n",
          pid);
      return 0;
    }
  }

  // bpf_printk(
  //     "handle_sched_switch [%d] pid (%d, %d) was scheduled out for %lld
  //     ns\n", bpf_get_smp_processor_id(), pid, tgid, delta);

  current_block_index =
      get_block_index(current_time, info_p->thread_creation_ts);

  if (current_block_index > info_p->block_index) {
    // The last event was in a previous block
    // We need to submit this block to the user space
    delta =
        (s64)(info_p->block_start_ts + granularity_ns - info_p->last_event_ts);
    if (delta < 0) {
      bpf_printk(
          "handle_sched_switch: next delta previous block negative (%d)\n",
          pid);
      goto cleanup;
    }

    if (delta > granularity_ns) {
      bpf_printk("handle_sched_switch: WARNING (%d) delta of previous block is "
                 "higher than granularity_ns\n",
                 pid);
    }

    info_p->offcpu_time_ns += delta;
    info_p->last_event_ts = info_p->block_start_ts + granularity_ns;
    info_p->state = SCHEDULED_OUT;
    submit_current_block(pid, info_p);
    bump_block(info_p, current_block_index, current_time);
  }

  delta = (s64)(current_time - info_p->last_event_ts);
  if (delta < 0) {
    bpf_printk("handle_sched_switch: next delta current block negative (%d)\n",
               pid);
    goto cleanup;
  }

  if (delta > granularity_ns) {
    bpf_printk("handle_sched_switch: WARNING (%d) delta of current block is "
               "higher than granularity_ns\n",
               pid);
  }

  info_p->last_event_ts = current_time;
  info_p->offcpu_time_ns += delta;
  info_p->state = SCHEDULED_IN;

  // delta /= 1000U;
  // valp = bpf_map_lookup_elem(&info, &i_keyp->key);
  // if (!valp)
  //   goto cleanup;
  // __sync_fetch_and_add(&valp->delta, delta);

cleanup:
  // bpf_map_delete_elem(&scheduled_out_start, &pid);
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
  pid_t pid, tgid;
  struct internal_thread_info *info_p, info = {};

  pid = ctx->child_pid;
  tgid = ctx->parent_pid;

  if (!allowed_pid_tgid(pid, tgid)) {
    return 0;
  }

  bpf_printk("fork parent=%d child=%d\n", ctx->parent_pid, ctx->child_pid);

  info_p = bpf_map_lookup_elem(&thread_map, &pid);
  if (info_p) {
    bpf_printk("fork (%d) already in map\n", pid);
    return 0;
  }

  // info.thread_creation_ts = bpf_ktime_get_ns();
  // info.block_index = 0;
  // info.block_start_ts = info.thread_creation_ts;
  // info.state = THREAD_CREATE;

  int ret =
      create_new_thread_info(&info, pid, THREAD_CREATE, bpf_ktime_get_ns());

  // long ret = bpf_map_update_elem(&thread_map, &pid, &info, BPF_ANY);
  if (ret) {
    bpf_printk("fork (%d) failed to update element\n", pid);
  }

  return 0;
}

// Thread destruction
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx) {
  pid_t pid, tgid;
  s64 delta;
  struct internal_thread_info *info_p;
  struct profile_block *profile_block_p;
  char comm[TASK_COMM_LEN] = {};
  u64 pid_tgid, current_time_ts, current_block_index;

  current_time_ts = bpf_ktime_get_ns();

  bpf_get_current_comm(&comm, sizeof(comm));

  pid_tgid = bpf_get_current_pid_tgid();
  pid = pid_tgid >> 32;
  tgid = (u32)pid_tgid;

  if (!allowed_pid_tgid(pid, tgid)) {
    return 0;
  }

  bpf_printk("exit: pid=%d, comm = %s \n", pid, comm);

  info_p = bpf_map_lookup_elem(&thread_map, &pid);
  if (!info_p) {
    bpf_printk("exit (%d) not found in map\n", pid);
    return 0;
  }

  current_block_index =
      get_block_index(current_time_ts, info_p->thread_creation_ts);

  if (current_block_index > info_p->block_index) {
    // The last event was in a previous block
    // We need to submit this block to the user space
    submit_current_block(pid, info_p);
    bump_block(info_p, current_block_index, current_time_ts);
  }

  if (info_p->state == SCHEDULED_OUT) {
    // The thread was killed while it was scheduled out
    // This means that we must get to know how long it was waiting
    // This will make it possible to find the load imbalance.
  }

  // delta = (s64)(current_time_ts - info_p->thread_creation_ts);

  // current_block_index =
  //     get_block_index(current_time_ts, info_p->thread_creation_ts);

  // bpf_printk("exit (%d) FOUND in map, start = %lld, delta %lld ns, n = %ld, "
  //            "block_start_ts = %lld\n",
  //            pid, info_p->thread_creation_ts, delta, current_block_index,
  //            start_of_block(current_time_ts, info_p->thread_creation_ts));

  info_p->last_event_ts = current_time_ts;
  info_p->state = THREAD_EXIT;
  submit_current_block(pid, info_p);
  /* reserve sample from BPF ringbuf */
  // profile_block_p = bpf_ringbuf_reserve(&rb, sizeof(*profile_block_p), 0);
  // if (!profile_block_p)
  //   return 0;

  // profile_block_p->pid = pid;
  // profile_block_p->block_index = info_p->block_index;
  // profile_block_p->block_start_time_ns = info_p->block_start_ts;
  // profile_block_p->first_event_time_ns = info_p->first_block_event_ts;
  // profile_block_p->last_event_time_ns = current_time_ts;
  // profile_block_p->offcpu_time_ns = 0;
  // profile_block_p->end_state = THREAD_EXIT;

  // /* send data to user-space for post-processing */
  // bpf_ringbuf_submit(profile_block_p, 0);

  goto cleanup;

cleanup:
  bpf_map_delete_elem(&thread_map, &pid);
  return 0;
}
