// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "thread-profiler.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// These are settings that are set by the userspace before the eBPF is attached
const volatile unsigned long long granularity_ns = 1e8;
const volatile bool filter_by_tgid = false;
const volatile pid_t filter_tgid;

// This map holds the state needed for the per-thread state machine
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, pid_t);
  __type(value, struct internal_thread_info);
} thread_map SEC(".maps");

// This map maps from (dev + sector) to pid
// It is needed because disk IO operations can be completed by another thread
// than the one that issued the IO task.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, u64);
  __type(value, pid_t);
} disk_io_pid_map SEC(".maps");

// This is the ringbuffer that is used to send the profile blocks to the
// userspace.
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// This function is used to filter which probe triggers to analyse.
static bool allowed_tgid(pid_t tgid) {
  if (filter_by_tgid && tgid != filter_tgid)
    return false;
  return true;
}

// TODO: This can be a useful debugging tool.
// static void print_state_stack(struct internal_thread_info *info_p) {
//   bpf_printk("depth=%d [%s,%s,%s,%s,%s]", info_p->state_depth,
//              thread_state_name[info_p->state_stack[0]],
//              thread_state_name[info_p->state_stack[1]],
//              thread_state_name[info_p->state_stack[2]],
//              thread_state_name[info_p->state_stack[3]],
//              thread_state_name[info_p->state_stack[4]]);
// }

// This function returns the index of the block at a specific timestamp.
static u64 get_block_index(u64 current_time, u64 start_time) {
  if (current_time < start_time) {
    bpf_printk("get_block_index [%d] current is before start time\n");
    return -1;
  }
  return (current_time - start_time) / granularity_ns;
}

// This function returns the start of the block with index n.
static u64 get_start_of_nth_block(u64 start_time, u64 n) {
  return start_time + n * granularity_ns;
}

// This function is used to fill out the thread info fields so that the state
// machine can be started for that thread.
static int create_new_thread_info(struct internal_thread_info *info_p,
                                  pid_t pid, thread_state_t initial_state,
                                  u64 current_time) {
  info_p->thread_creation_ts = current_time;
  info_p->block_index = 0;
  info_p->block_start_ts = current_time;
  info_p->last_event_ts = current_time;
  info_p->offcpu_time_ns = 0;
  info_p->mutex_time_ns = 0;
  info_p->futex_time_ns = 0;
  info_p->disk_io_time_ns = 0;
  state_stack_push(info_p, initial_state);

  return bpf_map_update_elem(&thread_map, &pid, info_p, BPF_ANY);
}

// This function is used to make the current state machine advance by one block.
static int block_bump_one(struct internal_thread_info *info_p) {
  info_p->block_index++;
  info_p->block_start_ts =
      get_start_of_nth_block(info_p->thread_creation_ts, info_p->block_index);
  info_p->last_event_ts = info_p->block_start_ts;
  info_p->offcpu_time_ns = 0;
  info_p->mutex_time_ns = 0;
  info_p->futex_time_ns = 0;
  info_p->disk_io_time_ns = 0;
  return 0;
}

// This function is used to make the current state machine advance to the nth
// block.
static int block_bump_to_n(struct internal_thread_info *info_p,
                           u64 block_index) {
  info_p->block_index = block_index;
  info_p->block_start_ts =
      get_start_of_nth_block(info_p->thread_creation_ts, block_index);
  info_p->last_event_ts = info_p->block_start_ts;
  info_p->offcpu_time_ns = 0;
  info_p->mutex_time_ns = 0;
  info_p->futex_time_ns = 0;
  info_p->disk_io_time_ns = 0;
  return 0;
}

// This function adds a time value to a state machine field depending on the
// provided state.
static void add_to_component(struct internal_thread_info *info_p,
                             thread_state_t state, s64 value) {
  switch (state) {
  case SCHEDULED_OUT:
    info_p->offcpu_time_ns += value;
    break;
  case MUTEX:
    info_p->mutex_time_ns += value;
    break;
  case FUTEX:
    info_p->futex_time_ns += value;
    break;
  case DISK_IO:
    info_p->disk_io_time_ns += value;
    break;
  default:
    break;
  }
}

// This function is used to submit the current block to the userspace.
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
  profile_block_p->block_end_time_ns = info_p->last_event_ts;
  profile_block_p->offcpu_time_ns = info_p->offcpu_time_ns;
  profile_block_p->mutex_time_ns = info_p->mutex_time_ns;
  profile_block_p->futex_time_ns = info_p->futex_time_ns;
  profile_block_p->disk_io_time_ns = info_p->disk_io_time_ns;

  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(profile_block_p, 0);
  return 0;
}

// This function is used to submit the all the previous blocks to the userspace
// that have not yet been submitted.
// Example: No events has happend in 3 * granularity_ns. This means that the
// current block needs to be updated and submitted with the new knowledge.
// Additionally there is now a gap of 2 * granularity_ns in between the block in
// which the current event resides and the block that was just submitted.
// This gap is filled by a block of size 2 * granularity_ns. This block is then
// also sent to the userspace.
static void submit_previous_blocks(struct internal_thread_info *info_p,
                                   pid_t pid, thread_state_t state,
                                   u64 current_block_index) {
  s64 delta;
  u64 block_end = info_p->block_start_ts + granularity_ns;
  delta = block_end - info_p->last_event_ts;
  add_to_component(info_p, state, delta);
  info_p->last_event_ts = block_end;
  submit_current_block(pid, info_p);
  block_bump_one(info_p);
  if (current_block_index > info_p->block_index) {
    // There was at least one granularity_ns in between, submit a block of
    // that size
    block_end =
        get_start_of_nth_block(info_p->thread_creation_ts, current_block_index);
    delta = block_end - info_p->block_start_ts;
    add_to_component(info_p, state, delta);
    info_p->last_event_ts = block_end;
    submit_current_block(pid, info_p);
    block_bump_to_n(info_p, current_block_index);
  }
}

// This is the function that handles a scheduling event.
// It receives a task that that is just scheduled out and one that is just
// scheduled in.
static int handle_sched_switch(void *ctx, bool preempt,
                               struct task_struct *prev,
                               struct task_struct *next) {
  s64 delta;
  pid_t prev_pid, prev_tgid, next_pid, next_tgid;
  u64 current_time, current_block_index;
  thread_state_t state;
  u64 block_end;

  struct internal_thread_info *info_p, info = {};

  // Handle the task that is scheduled out
  // pid = BPF_CORE_READ(prev, pid);
  // tgid = BPF_CORE_READ(prev, tgid);

  prev_pid = prev->pid;
  prev_tgid = prev->tgid;
  next_pid = next->pid;
  next_tgid = next->tgid;

  bool prev_ok = prev_pid && allowed_tgid(prev_tgid);
  bool next_ok = next_pid && allowed_tgid(next_tgid);

  if (!prev_ok && !next_ok)
    return 0;

  // bpf_printk("handle_sched_switch [%d] from (%d, %d) to (%d, %d)\n",
  //            bpf_get_smp_processor_id(), pid, tgid, BPF_CORE_READ(next, pid),
  //            BPF_CORE_READ(next, tgid));

  // The scheduled out thread was not the idle thread
  if (prev_ok) {
    current_time = bpf_ktime_get_ns();
    info_p = bpf_map_lookup_elem(&thread_map, &prev_pid);
    if (!info_p) {
      // There was no thread info, create new
      // bpf_printk("handle_sched_switch: no prev thread info (%d)\n", pid);
      create_new_thread_info(&info, prev_pid, THREAD_CREATE, current_time);

      info_p = bpf_map_lookup_elem(&thread_map, &prev_pid);
      if (!info_p) {
        bpf_printk(
            "handle_sched_switch: Could not create thread info for prev (%d)\n",
            prev_pid);
        return 0;
      }
    }

    state = state_stack_peek(info_p);
    if (state == MUTEX || state == FUTEX || state == DISK_IO) {
      // The top of the state stack is an event where we ignore schedule out
      goto skip_prev;
    }

    if (state == SCHEDULED_OUT) {
      bpf_printk("handle_sched_switch: WARNING prev schedule out but it has "
                 "state SCHEDULED_OUT (%d)",
                 prev_pid);
    }

    current_block_index =
        get_block_index(current_time, info_p->thread_creation_ts);

    if (current_block_index > info_p->block_index) {
      // The last event was in a previous block. Because it was scheduled in and
      // not skipped we know that it was following ideal execution. There are no
      // components to update, just submit this block to the userspace.

      info_p->last_event_ts = info_p->block_start_ts + granularity_ns;
      submit_current_block(prev_pid, info_p);
      block_bump_one(info_p);
      if (current_block_index > info_p->block_index) {
        // There was at least one granularity_ns in between, submit a block of
        // that size. Note that no components are set. This is because there
        // were no slowdowns detected.
        info_p->last_event_ts = get_start_of_nth_block(
            info_p->thread_creation_ts, current_block_index);
        submit_current_block(prev_pid, info_p);
        block_bump_to_n(info_p, current_block_index);
      }
    }

    info_p->last_event_ts = current_time;
    state_stack_push(info_p, SCHEDULED_OUT);
  }

skip_prev:

  // Handle the task that is just scheduled in
  // pid = BPF_CORE_READ(next, pid);
  // tgid = BPF_CORE_READ(next, tgid);

  // The newly scheduled thread is the idle thread
  if (!next_ok)
    return 0;

  current_time = bpf_ktime_get_ns();

  info_p = bpf_map_lookup_elem(&thread_map, &next_pid);
  if (!info_p) {
    // This thread was not yet encountered
    // bpf_printk("handle_sched_switch: no next thread info (%d)\n", pid);
    create_new_thread_info(&info, next_pid, THREAD_CREATE, current_time);
    info_p = bpf_map_lookup_elem(&thread_map, &next_pid);
    if (!info_p) {
      bpf_printk(
          "handle_sched_switch: Could not create thread info for next (%d)\n",
          next_pid);
      return 0;
    }
  }

  state = state_stack_peek(info_p);
  if (state == MUTEX || state == FUTEX || state == DISK_IO) {
    // The top of the state stack is an event where we ignore schedule in
    goto cleanup;
  }

  if (state == SCHEDULED_IN) {
    bpf_printk("handle_sched_switch: WARNING next schedule in but it has "
               "state SCHEDULED_IN (%d)",
               next_pid);
  }

  if (state == SCHEDULED_OUT) {
    // Good, this is normal schedule out and back in
    state_stack_pop(info_p);
  }

  current_block_index =
      get_block_index(current_time, info_p->thread_creation_ts);

  if (current_block_index > info_p->block_index) {
    // The last event was in a previous block
    // We need to submit this block to the user space

    block_end = info_p->block_start_ts + granularity_ns;
    info_p->offcpu_time_ns += block_end - info_p->last_event_ts;
    info_p->last_event_ts = block_end;
    submit_current_block(next_pid, info_p);
    block_bump_one(info_p);
    if (current_block_index > info_p->block_index) {
      // There was at least one granularity_ns in between, submit a block of
      // that size.
      block_end = get_start_of_nth_block(info_p->thread_creation_ts,
                                         current_block_index);
      info_p->offcpu_time_ns += block_end - info_p->block_start_ts;
      info_p->last_event_ts = block_end;
      submit_current_block(next_pid, info_p);
      block_bump_to_n(info_p, current_block_index);
    }
  }

  delta = (s64)(current_time - info_p->last_event_ts);
  if (delta < 0) {
    bpf_printk(
        "handle_sched_switch: WARNING next delta current block negative (%d)\n",
        next_pid);
    goto cleanup;
  }

  if (delta > granularity_ns) {
    bpf_printk("handle_sched_switch: WARNING (%d) delta of current block is "
               "higher than granularity_ns\n",
               next_pid);
  }

  info_p->last_event_ts = current_time;
  info_p->offcpu_time_ns += delta;

cleanup:
  return 0;
}

// This is the general marking function for a probe.
// The idea is that this function makes sure to compute the current analysis.
// But it produces a new nested analysis over the current one.
static int enter_event(pid_t pid, thread_state_t new_state) {
  struct internal_thread_info *info_p, info = {};

  u64 current_time, current_block_index;
  s64 delta;
  thread_state_t state;

  current_time = bpf_ktime_get_ns();

  info_p = bpf_map_lookup_elem(&thread_map, &pid);
  if (!info_p) {
    // There was no thread info, create new
    bpf_printk("enter_event: no prev thread info (%d)\n", pid);
    create_new_thread_info(&info, pid, THREAD_CREATE, current_time);

    info_p = bpf_map_lookup_elem(&thread_map, &pid);
    if (!info_p) {
      bpf_printk("enter_event: Could not create thread info for "
                 "prev (%d)\n",
                 pid);
      return 0;
    }
  }

  state = state_stack_peek(info_p);

  current_block_index =
      get_block_index(current_time, info_p->thread_creation_ts);

  if (current_block_index > info_p->block_index) {
    // The last event was in a previous block
    // We need to submit this block to the user space

    submit_previous_blocks(info_p, pid, state, current_block_index);
  }

  delta = current_time - info_p->last_event_ts;
  add_to_component(info_p, state, delta);

  info_p->last_event_ts = current_time;
  switch (new_state) {
  case MUTEX:
  case DISK_IO:
    switch (state) {
    case SCHEDULED_OUT:
    case MUTEX:
    case FUTEX:
    case DISK_IO:
      state_stack_pop(info_p);
      break;
    default:
      break;
    }
    break;
  case FUTEX:
    switch (state) {
    case SCHEDULED_OUT:
    case FUTEX:
    case DISK_IO:
      state_stack_pop(info_p);
      break;
    default:
      break;
    }
    break;
  default:
    break;
  }
  state_stack_push(info_p, new_state);
  return 0;
}

// This is the general consuming function. The idea is that it will consume the
// currently running analysis so that the outer one can continue.
static int exit_event(pid_t pid, thread_state_t calling_state) {
  struct internal_thread_info *info_p, info = {};

  s64 delta;
  thread_state_t state;
  u64 current_time, current_block_index;
  u64 *field_ptr;

  current_time = bpf_ktime_get_ns();

  info_p = bpf_map_lookup_elem(&thread_map, &pid);
  if (!info_p) {
    // This thread was not yet encountered
    create_new_thread_info(&info, pid, THREAD_CREATE, current_time);
    info_p = bpf_map_lookup_elem(&thread_map, &pid);
    if (!info_p) {
      bpf_printk("exit_event: Could not create thread info for (%d)\n", pid);
      return 0;
    }
  }

  state = state_stack_peek(info_p);

  current_block_index =
      get_block_index(current_time, info_p->thread_creation_ts);

  if (current_block_index > info_p->block_index) {
    // The last event was in a previous block
    // We need to submit this block to the user space

    submit_previous_blocks(info_p, pid, state, current_block_index);
  }

  delta = current_time - info_p->last_event_ts;
  add_to_component(info_p, state, delta);

  info_p->last_event_ts = current_time;
  switch (calling_state) {
  case MUTEX:
  case DISK_IO:
    switch (state) {
    case SCHEDULED_OUT: // This one would be weird
    case MUTEX:
    case DISK_IO: // Maybe the IO uses locks? TODO: maybe look into this
      state_stack_pop(info_p);
      break;
    case FUTEX: // I would expect it to already be gone
      state_stack_pop(info_p);
      state_stack_pop(info_p);
      break;
    default:
      break;
    }
    break;
  case FUTEX:
    switch (state) {
    case SCHEDULED_OUT: // This one would be weird
    case FUTEX:         // I would expect it to already be gone
    case DISK_IO:       // Maybe the IO uses locks? TODO: maybe look into this
      state_stack_pop(info_p);
      break;
    default:
      break;
    }
    break;
  default:
    break;
  }

cleanup:
  return 0;
}

// This is the probe for scheduling switches.
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev,
             struct task_struct *next) {
  return handle_sched_switch(ctx, preempt, prev, next);
}

// This is the probe for thread creation.
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx) {
  pid_t pid, tgid;
  struct internal_thread_info *info_p, info = {};

  tgid = ctx->parent_pid;
  if (!allowed_tgid(tgid)) {
    return 0;
  }

  pid = ctx->child_pid;

  info_p = bpf_map_lookup_elem(&thread_map, &pid);
  if (info_p) {
    bpf_printk("fork (%d) already in map\n", pid);
    return 0;
  }

  int ret =
      create_new_thread_info(&info, pid, THREAD_CREATE, bpf_ktime_get_ns());

  if (ret) {
    bpf_printk("fork (%d) failed to update element\n", pid);
  }

  return 0;
}

// This is the probe for thread destruction.
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx) {
  pid_t pid, tgid;
  s64 delta;
  struct internal_thread_info *info_p;
  struct profile_block *profile_block_p;
  char comm[TASK_COMM_LEN] = {};
  u64 pid_tgid, current_time_ts, current_block_index;
  thread_state_t state;
  u64 block_end;

  current_time_ts = bpf_ktime_get_ns();

  bpf_get_current_comm(&comm, sizeof(comm));

  pid_tgid = bpf_get_current_pid_tgid();
  pid = (u32)pid_tgid;
  tgid = pid_tgid >> 32;

  if (!allowed_tgid(tgid)) {
    return 0;
  }

  info_p = bpf_map_lookup_elem(&thread_map, &pid);
  if (!info_p) {
    bpf_printk("exit (%d) not found in map\n", pid);
    return 0;
  }

  state = state_stack_peek(info_p);

  current_block_index =
      get_block_index(current_time_ts, info_p->thread_creation_ts);

  if (current_block_index > info_p->block_index) {
    // The last event was in a previous block
    // We need to submit this block to the user space

    submit_previous_blocks(info_p, pid, state, current_block_index);
    // submit_current_block(pid, info_p);
    // bump_block(info_p, current_block_index, current_time_ts);
  }

  // TODO: look into load imbalance
  // if (info_p->state == SCHEDULED_OUT) {
  //   // The thread was killed while it was scheduled out
  //   // This means that we must get to know how long it was waiting
  //   // This will make it possible to find the load imbalance.
  // }

  delta = current_time_ts - info_p->last_event_ts;
  add_to_component(info_p, state, delta);
  info_p->last_event_ts = current_time_ts;
  submit_current_block(pid, info_p);

cleanup:
  bpf_map_delete_elem(&thread_map, &pid);
  return 0;
}

// This is the probe for a call to pthread_mutex_wait()
// SEC("uprobe/libc.so.6:__pthread_mutex_lock")
// int BPF_PROG(uprobe_pthread_mutex_lock, void *unused) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   return enter_event(pid, MUTEX);
// }

// This is the probe for the return of a call to pthread_mutex_wait()
// SEC("uretprobe/libc.so.6:__pthread_mutex_lock")
// int BPF_PROG(uretprobe_pthread_mutex_lock, void *unused) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   return exit_event(pid, MUTEX);
// }

// This is the probe for the futex enter event.
SEC("tracepoint/syscalls/sys_enter_futex")
int trace_enter_futex(struct trace_event_raw_sys_enter *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
  if (!allowed_tgid(tgid))
    return 0;

  u32 pid = (u32)id;

  return enter_event(pid, FUTEX);
}

// This is the probe for the futex exit event.
SEC("tracepoint/syscalls/sys_exit_futex")
int trace_exit_futex(struct trace_event_raw_sys_exit *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
  if (!allowed_tgid(tgid))
    return 0;

  u32 pid = (u32)id;

  // bpf_printk("tracepoint: sys_exit_futex tgid=%u pid=%u\n", tgid, pid);
  return exit_event(pid, FUTEX);
}

// TODO: Add support for barrier detection
// Userspace barrier wait call
// SEC("uprobe/libc.so.6:pthread_barrier_wait")
// int BPF_PROG(uprobe_pthread_barrier_wait, void *unused) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;
//   u32 pid = (u32)id;

//   bpf_printk("UPROBE: pthread_barrier_wait tgid=%u pid=%u\n", tgid, pid);
//   return 0;
// }

// Userspace barrier wait return
// SEC("uretprobe/libc.so.6:pthread_barrier_wait")
// int BPF_PROG(uretprobe_pthread_barrier_wait, void *unused) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   bpf_printk("URETPROBE: pthread_barrier_wait tgid=%u pid=%u\n", tgid, pid);
//   return 0;
// }

// TODO: Add support for conditional variable detection
// Userspace conditional variable wait call
// SEC("uprobe")
// int BPF_PROG(uprobe_pthread_cond_wait, void *unused) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   bpf_printk("UPROBE: pthread_cond_wait tgid=%u pid=%u\n", tgid, pid);
//   return 0;
// }

// TODO: Add support for semaphore detection
// Userspace semaphore wait call
// SEC("uprobe/libc.so.6:sem_wait")
// int BPF_PROG(uprobe_sem_wait, void *unused) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   bpf_printk("UPROBE: sem_wait tgid=%u pid=%u\n", tgid, pid);
//   return 0;
// }

// Userspace semaphore wait return
// SEC("uretprobe/libc.so.6:sem_wait")
// int BPF_PROG(uretprobe_sem_wait, void *unused) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   bpf_printk("URETPROBE: sem_wait tgid=%u pid=%u\n", tgid, pid);
//   return 0;
// }

// This is the probe for the starting of disk IO
SEC("tracepoint/block/block_rq_issue")
int trace_block_rq_issue(struct trace_event_raw_block_rq *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
  if (!allowed_tgid(tgid))
    return 0;

  u32 pid = (u32)id;

  // The key is a composition, it is not that strong but it should be fine
  u64 key = ((u64)ctx->dev << 32) | ctx->sector;
  bpf_map_update_elem(&disk_io_pid_map, &key, &id, BPF_ANY);

  return enter_event(pid, DISK_IO);
}

// TODO: For IO the problem is that IO can also be done asynchronously. I
// think one approach is to actually look if the scheduler is scheduling out the
// thread while IO is happening. That would be a strong indication that it
// is synchronous IO and not asynchronous. To be thought about in the future.
//
// This is the probe for the completion of disk IO
// For the IO completion we need to do a workaround. The problem is that the
// process that completes the IO instructions is not necessarily the same as
// one that issued it. This means that we need to keep track of device and
// sector instruction data so that we can find again which process issued the
// IO instructions.
SEC("tracepoint/block/block_rq_complete")
int trace_block_rq_complete(struct trace_event_raw_block_rq_completion *ctx) {

  u64 key = ((u64)ctx->dev << 32) | ctx->sector;
  u32 *pid_p = bpf_map_lookup_elem(&disk_io_pid_map, &key);

  // The pid was not in the map, so it was not allowed
  if (!pid_p)
    return 0;

  u32 pid = *pid_p;

  exit_event(pid, DISK_IO);
  bpf_map_delete_elem(&disk_io_pid_map, &key);
  return 0;
}

// These are probes for all system calls.
// SEC("tracepoint/syscalls/sys_enter_read")
// int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   bpf_printk("tracepoint: sys_enter_read tgid=%u pid=%u\n", tgid, pid);
//   return 0;
// }
// SEC("tracepoint/syscalls/sys_exit_read")
// int trace_read_exit(struct trace_event_raw_sys_exit *ctx) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   bpf_printk("tracepoint: sys_exit_read tgid=%u pid=%u\n", tgid, pid);
//   return 0;
// }

// TODO:
// the plan is as follows first we will count the cache miss rate so for this we
// need to know how much of the cache references are successful and how much of
// them miss with this rate we can estimate the number of stall cycles due to
// these memory misses memory cache misses using this number of stalled cycles
// can estimate the fraction of the cycles since the last measurements that were
// stalled. using this fraction we can then estimate the time lost in a
// performance block due to memory contention note that the stalled cycles
// should only be looking at the scheduled in time because cache misses when
// another event happens is already accounted for. it might be necessary to
// somehow interpolate the values because the frequency of the performance event
// is different than that of the other events so it might be necessary to
// interpolate values considering the already known timestamps.
//
// nr_cycles_per_miss = 100
// nr_stalled_cycles = nr_misses * <nr_cycles_per_miss>
// stalled_cycle_fraction = nr_stalled_cycles / cycles
//
//
// What about:
// extra_cycles = (CPI_benchmark - CPI_baseline) × nr_instruction
// extra_time   = extra_cycles / clock_frequency
SEC("perf_event")
int sample_cycles(struct bpf_perf_event_data *ctx) {
  u64 *valp;
  static const u64 zero;
  u64 id;
  u32 tgid;
  u32 pid;

  id = bpf_get_current_pid_tgid();
  tgid = id >> 32;
  pid = (u32)id;

  if (!allowed_tgid(tgid))
    return 0;

  u64 period = ctx->sample_period;
  // bpf_printk("perf_event: sample_cycles tgid=%u, pid=%u, period=%llu\n",
  // tgid, pid, period);

  return 0;
}

// SEC("perf_event")
// int sample_instructions(struct bpf_perf_event_data *ctx) {
//   u64 *valp;
//   static const u64 zero;
//   u64 id;
//   u32 tgid;
//   u32 pid;

//   id = bpf_get_current_pid_tgid();
//   tgid = id >> 32;
//   pid = (u32)id;

//   if (!allowed_tgid(tgid))
//     return 0;

//   u64 period = ctx->sample_period;
//   bpf_printk("perf_event: sample_instructions tgid=%u, pid=%u,
//   period=%llu\n", tgid, pid, period);

//   return 0;
// }

SEC("perf_event")
int sample_cache_misses(struct bpf_perf_event_data *ctx) {
  u64 *valp;
  static const u64 zero;
  u64 id;
  u32 tgid;
  u32 pid;

  id = bpf_get_current_pid_tgid();
  tgid = id >> 32;
  pid = (u32)id;

  if (!allowed_tgid(tgid))
    return 0;

  u64 period = ctx->sample_period;
  // bpf_printk("perf_event: sample_cache_misses tgid=%u, pid=%u,
  // period=%llu\n", tgid, pid, period);

  return 0;
}

// SEC("perf_event")
// int sample_cache_ref(struct bpf_perf_event_data *ctx) {
//   u64 *valp;
//   static const u64 zero;
//   u64 id;
//   u32 tgid;
//   u32 pid;

//   id = bpf_get_current_pid_tgid();
//   tgid = id >> 32;
//   pid = (u32)id;

//   if (!allowed_tgid(tgid))
//     return 0;

//   u64 period = ctx->sample_period;
//   bpf_printk("perf_event: sample_cache_ref tgid=%u, pid=%u, period=%llu\n",
//              tgid, pid, period);

//   return 0;
// }
