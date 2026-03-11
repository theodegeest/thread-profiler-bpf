// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "thread-profiler.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile unsigned long long granularity_ns = 1e8;
const volatile bool filter_by_tgid = false;
const volatile pid_t filter_tgid;

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, pid_t);
  __type(value, struct internal_thread_info);
} thread_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, u64);
  __type(value, pid_t);
} disk_io_pid_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static bool allowed_tgid(pid_t tgid) {
  if (filter_by_tgid && tgid != filter_tgid)
    return false;
  return true;
}

static bool allowed_task(struct task_struct *task) {
  u32 tgid = BPF_CORE_READ(task, tgid);

  return allowed_tgid(tgid);
}

// static void print_state_stack(struct internal_thread_info *info_p) {
//   bpf_printk("depth=%d [%s,%s,%s,%s,%s]", info_p->state_depth,
//              thread_state_name[info_p->state_stack[0]],
//              thread_state_name[info_p->state_stack[1]],
//              thread_state_name[info_p->state_stack[2]],
//              thread_state_name[info_p->state_stack[3]],
//              thread_state_name[info_p->state_stack[4]]);
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

static u64 start_of_nth_block(u64 start_time, u64 n) {
  return start_time + n * granularity_ns;
}

static int create_new_thread_info(struct internal_thread_info *info_p,
                                  pid_t pid, thread_state_t initial_state,
                                  u64 current_time) {
  info_p->thread_creation_ts = current_time;
  info_p->block_index = 0;
  info_p->block_start_ts = current_time;
  // info_p->first_block_event_ts = current_time;
  info_p->last_event_ts = current_time;
  info_p->offcpu_time_ns = 0;
  info_p->mutex_time_ns = 0;
  info_p->futex_time_ns = 0;
  info_p->disk_io_time_ns = 0;
  // info_p->state = initial_state;
  state_stack_push(info_p, initial_state);

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
  profile_block_p->block_end_time_ns = info_p->last_event_ts;
  // profile_block_p->first_event_time_ns = info_p->first_block_event_ts;
  // profile_block_p->last_event_time_ns = info_p->last_event_ts;
  profile_block_p->offcpu_time_ns = info_p->offcpu_time_ns;
  profile_block_p->mutex_time_ns = info_p->mutex_time_ns;
  profile_block_p->futex_time_ns = info_p->futex_time_ns;
  profile_block_p->disk_io_time_ns = info_p->disk_io_time_ns;
  // profile_block_p->end_state = info_p->state;

  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(profile_block_p, 0);
  return 0;
}

// TODO: maybe remove last event on current time?
// TODO: start_of_block -> start_of_nth_block
static int bump_block(struct internal_thread_info *info_p,
                      u64 current_block_index, u64 current_time_ts) {
  info_p->block_index = current_block_index;
  info_p->block_start_ts =
      start_of_block(current_time_ts, info_p->thread_creation_ts);
  // info_p->first_block_event_ts = current_time_ts;
  info_p->last_event_ts = info_p->block_start_ts;
  info_p->offcpu_time_ns = 0;
  info_p->mutex_time_ns = 0;
  info_p->futex_time_ns = 0;
  info_p->disk_io_time_ns = 0;
  return 0;
}

static int make_next_block(struct internal_thread_info *info_p) {
  info_p->block_index++;
  info_p->block_start_ts =
      start_of_nth_block(info_p->thread_creation_ts, info_p->block_index);
  info_p->last_event_ts = info_p->block_start_ts;
  info_p->offcpu_time_ns = 0;
  info_p->mutex_time_ns = 0;
  info_p->futex_time_ns = 0;
  info_p->disk_io_time_ns = 0;
  return 0;
}

// static int update_component(struct internal_thread_info *info_p,
//                             u64 current_time) {
//   thread_state_t state = state_stack_peek(info_p);
//   s64 delta;
//   switch (state) {
//   case ERROR_STATE:
//     bpf_printk("update_component: ERROR_STATE");
//     break;
//   case SCHEDULED_OUT:
//     bpf_printk("update_component: SCHEDULED_OUT");
//     break;
//   case SCHEDULED_IN:
//     bpf_printk("update_component: SCHEDULED_IN");
//     delta =
//         (s64)(info_p->block_start_ts + granularity_ns -
//         info_p->last_event_ts);
//     break;
//   }
//   return 0;
// }

static int handle_sched_switch(void *ctx, bool preempt,
                               struct task_struct *prev,
                               struct task_struct *next) {
  s64 delta;
  pid_t pid, tgid;
  u64 current_time, current_block_index;
  thread_state_t state;
  u64 block_end;

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
    info_p = bpf_map_lookup_elem(&thread_map, &pid);
    if (!info_p) {
      // There was no thread info, create new
      bpf_printk("handle_sched_switch: no prev thread info (%d)\n", pid);
      create_new_thread_info(&info, pid, THREAD_CREATE, current_time);

      info_p = bpf_map_lookup_elem(&thread_map, &pid);
      if (!info_p) {
        bpf_printk(
            "handle_sched_switch: Could not create thread info for prev (%d)\n",
            pid);
        return 0;
      }
    }

    state = state_stack_peek(info_p);
    if (state == MUTEX_WAIT || state == FUTEX || state == DISK_IO) {
      // The top of the state stack is an event where we ignore schedule out
      thread_state_t s = state < THREAD_STATE_NAME_COUNT ? state : ERROR_STATE;
      bpf_printk("handle_sched_switch: prev skip (%d) %s", pid,
                 thread_state_name[s]);
      goto skip_prev;
    }

    if (state == SCHEDULED_OUT) {
      bpf_printk("handle_sched_switch: WARNING prev schedule out but it has "
                 "state SCHEDULED_OUT (%d)",
                 pid);
    }

    // bpf_printk("handle_sched_switch: prev thread info (%d)\n", pid);

    current_block_index =
        get_block_index(current_time, info_p->thread_creation_ts);
    // bpf_printk("handle_sched_switch: current_block_index (%lld)\n",
    //            current_block_index);

    if (current_block_index > info_p->block_index) {
      // The last event was in a previous block. We need to update the
      // components and submit this block to the user space

      info_p->last_event_ts = info_p->block_start_ts + granularity_ns;
      submit_current_block(pid, info_p);
      make_next_block(info_p);
      if (current_block_index > info_p->block_index) {
        // There was at least one granularity_ns in between, submit a block of
        // that size NOTE: We do not add any components (all 0)
        info_p->last_event_ts =
            start_of_nth_block(info_p->thread_creation_ts, current_block_index);
        submit_current_block(pid, info_p);
        bump_block(info_p, current_block_index, current_time);
      }
    }

    info_p->last_event_ts = current_time;
    // info_p->state = SCHEDULED_OUT;
    // if (state == SCHEDULED_IN)
    //   state_stack_pop(info_p);
    state_stack_push(info_p, SCHEDULED_OUT);
  }

skip_prev:

  // Handle the task that is just scheduled in

  pid = BPF_CORE_READ(next, pid);
  tgid = BPF_CORE_READ(next, tgid);

  // The newly scheduled thread is the idle thread
  if (!pid || !allowed_task(next))
    return 0;

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

  state = state_stack_peek(info_p);
  if (state == MUTEX_WAIT || state == FUTEX || state == DISK_IO) {
    // The top of the state stack is an event where we ignore schedule in
    thread_state_t s = state < THREAD_STATE_NAME_COUNT ? state : ERROR_STATE;
    bpf_printk("handle_sched_switch: next skip (%d) %s", pid,
               thread_state_name[s]);
    goto cleanup;
  }

  if (state == SCHEDULED_IN) {
    bpf_printk("handle_sched_switch: WARNING next schedule in but it has "
               "state SCHEDULED_IN (%d)",
               pid);
  }

  if (state == SCHEDULED_OUT) {
    // Good, this is normal schedule out and back in
    state_stack_pop(info_p);
  }

  // if (info_p->state == MUTEX_WAIT) {
  //   // This context switch happens during the futex wait call in a mutex
  //   wait.
  //   // It is only temporarily scheduled in and will probably be scheduled out
  //   // again inside the same lock. Do not count this as any scheduling out,
  //   the
  //   // lock is still not acquired.
  //   goto cleanup;
  // } else if (info_p->state == DISK_IO) {
  //   goto cleanup;
  // } else if (info_p->state == FUTEX) {
  //   goto cleanup;
  // }

  // bpf_printk(
  //     "handle_sched_switch [%d] pid (%d, %d) was scheduled out for %lld
  //     ns\n", bpf_get_smp_processor_id(), pid, tgid, delta);

  current_block_index =
      get_block_index(current_time, info_p->thread_creation_ts);

  if (current_block_index > info_p->block_index) {
    // The last event was in a previous block
    // We need to submit this block to the user space

    // switch (state) {
    // case ERROR_STATE:
    //   bpf_printk("handle_sched_switch: next previous block ERROR_STATE");
    //   break;
    // case SCHEDULED_OUT:
    //   bpf_printk("handle_sched_switch: next previous block SCHEDULED_OUT");
    //   break;
    // case SCHEDULED_IN:
    //   bpf_printk("handle_sched_switch: next previous block SCHEDULED_IN");

    //   u64 block_end = info_p->block_start_ts + granularity_ns;
    //   info_p->offcpu_time_ns += block_end - info_p->last_event_ts;
    //   info_p->last_event_ts = block_end;
    //   delta = (s64)(info_p->block_start_ts + granularity_ns -
    //                 info_p->last_event_ts);
    //   if (delta < 0) {
    //     bpf_printk(
    //         "handle_sched_switch: next delta previous block negative (%d)\n",
    //         pid);
    //     goto cleanup;
    //   }
    //   break;
    // }

    block_end = info_p->block_start_ts + granularity_ns;
    info_p->offcpu_time_ns += block_end - info_p->last_event_ts;
    info_p->last_event_ts = block_end;
    submit_current_block(pid, info_p);
    make_next_block(info_p);
    if (current_block_index > info_p->block_index) {
      // There was at least one granularity_ns in between, submit a block of
      // that size NOTE: We do not add any components (all 0)

      block_end =
          start_of_nth_block(info_p->thread_creation_ts, current_block_index);
      info_p->offcpu_time_ns += block_end - info_p->block_start_ts;
      info_p->last_event_ts = block_end;
      submit_current_block(pid, info_p);
      bump_block(info_p, current_block_index, current_time);
    }

    // delta =
    //     (s64)(info_p->block_start_ts + granularity_ns -
    //     info_p->last_event_ts);
    // if (delta < 0) {
    //   bpf_printk(
    //       "handle_sched_switch: next delta previous block negative (%d)\n",
    //       pid);
    //   goto cleanup;
    // }

    // if (delta > granularity_ns) {
    //   bpf_printk("handle_sched_switch: WARNING (%d) delta of previous block
    //   is "
    //              "higher than granularity_ns\n",
    //              pid);
    // }

    // info_p->offcpu_time_ns += delta;
    // info_p->last_event_ts = info_p->block_start_ts + granularity_ns;
    // info_p->state = SCHEDULED_OUT;
    // submit_current_block(pid, info_p);
    // bump_block(info_p, current_block_index, current_time);
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
  // info_p->state = SCHEDULED_IN;
  // state_stack_push(info_p, SCHEDULED_IN);

cleanup:
  return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev,
             struct task_struct *next) {
  return handle_sched_switch(ctx, preempt, prev, next);
}

// Thread creation
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx) {
  pid_t pid, tgid;
  struct internal_thread_info *info_p, info = {};

  tgid = ctx->parent_pid;
  if (!allowed_tgid(tgid)) {
    return 0;
  }

  pid = ctx->child_pid;

  // bpf_printk("fork parent=%d child=%d\n", ctx->parent_pid, ctx->child_pid);

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

// Thread destruction
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

  // bpf_printk("exit: pid=%d, comm = %s \n", pid, comm);

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

    u64 block_end = info_p->block_start_ts + granularity_ns;
    delta = block_end - info_p->last_event_ts;
    switch (state) {
    case SCHEDULED_OUT:
      info_p->offcpu_time_ns += delta;
      break;
    case MUTEX_WAIT:
      info_p->mutex_time_ns += delta;
      break;
    case FUTEX:
      info_p->futex_time_ns += delta;
      break;
    case DISK_IO:
      info_p->disk_io_time_ns += delta;
      break;
    default:
      break;
    }
    info_p->last_event_ts = block_end;
    submit_current_block(pid, info_p);
    make_next_block(info_p);
    if (current_block_index > info_p->block_index) {
      // There was at least one granularity_ns in between, submit a block of
      // that size NOTE: We do not add any components (all 0)

      block_end =
          start_of_nth_block(info_p->thread_creation_ts, current_block_index);
      delta = block_end - info_p->block_start_ts;
      switch (state) {
      case SCHEDULED_OUT:
        info_p->offcpu_time_ns += delta;
        break;
      case MUTEX_WAIT:
        info_p->mutex_time_ns += delta;
        break;
      case FUTEX:
        info_p->futex_time_ns += delta;
        break;
      case DISK_IO:
        info_p->disk_io_time_ns += delta;
        break;
      default:
        break;
      }
      info_p->last_event_ts = block_end;
      submit_current_block(pid, info_p);
      bump_block(info_p, current_block_index, current_time_ts);
    }

    // submit_current_block(pid, info_p);
    // bump_block(info_p, current_block_index, current_time_ts);
  }

  // if (info_p->state == SCHEDULED_OUT) {
  //   // The thread was killed while it was scheduled out
  //   // This means that we must get to know how long it was waiting
  //   // This will make it possible to find the load imbalance.
  // }

  // bpf_printk("exit (%d) FOUND in map, start = %lld, delta %lld ns, n = %ld, "
  //            "block_start_ts = %lld\n",
  //            pid, info_p->thread_creation_ts, delta, current_block_index,
  //            start_of_block(current_time_ts, info_p->thread_creation_ts));

  delta = current_time_ts - info_p->last_event_ts;
  switch (state) {
  case SCHEDULED_OUT:
    info_p->offcpu_time_ns += delta;
    break;
  case MUTEX_WAIT:
    info_p->mutex_time_ns += delta;
    break;
  case FUTEX:
    info_p->futex_time_ns += delta;
    break;
  case DISK_IO:
    info_p->disk_io_time_ns += delta;
    break;
  default:
    break;
  }
  info_p->last_event_ts = current_time_ts;
  submit_current_block(pid, info_p);

cleanup:
  bpf_map_delete_elem(&thread_map, &pid);
  return 0;
}

// TODO: The idea here will be that we want to 1 be able to mark a thread saying
// I have started this type of event, for example a mutex lock. Then, when
// another event triggers, it looks at the mark. If the mark tells it that it
// was doing a mutex, then it can calculate how long that mutex took for at
// least a partial result for that mutex. Then, it can continue on the
// computation by marking itself to the current event, which can be a futex, for
// example. When this event ends, it can calculate the futex length.
// To encode this stack-like behavior, we could make a mark, for example, futex.
// Then, another one, futex-in-mutex. So That we can differentiate between a
// futex call that we cannot classify yet, and a futex call inside a mutex.
//
// So maybe we need to change the API so that we have a marking step and an
// actual computation for the delta from what was already marked. I am unsure if
// this can be a single function or that it needs to be split up in two.
// One way to do this is with a single function and if it is SCHEDULED_IN we
// don't do anything with the previous delta.
//
// I see two ways maybe a switch case or maybe like the trick with the index
// because we can use enums that are numbers to reference in an array so that
// might also be a way to get the offset in the struct

// static int enter_event(pid_t pid, thread_state_t new_block_state,
//                        thread_state_t new_state) {
//   struct internal_thread_info *info_p, info = {};

//   u64 current_time, current_block_index;

//   current_time = bpf_ktime_get_ns();

//   info_p = bpf_map_lookup_elem(&thread_map, &pid);
//   if (!info_p) {
//     // There was no thread info, create new
//     bpf_printk("enter_event: no prev thread info (%d)\n", pid);
//     create_new_thread_info(&info, pid, new_block_state, current_time);

//     info_p = bpf_map_lookup_elem(&thread_map, &pid);
//     if (!info_p) {
//       bpf_printk("enter_event: Could not create thread info for "
//                  "prev (%d)\n",
//                  pid);
//       return 0;
//     }
//   }

//   current_block_index =
//       get_block_index(current_time, info_p->thread_creation_ts);

//   if (current_block_index > info_p->block_index) {
//     // The last event was in a previous block
//     // We need to submit this block to the user space
//     submit_current_block(pid, info_p);
//     bump_block(info_p, current_block_index, current_time);
//   }

//   info_p->last_event_ts = current_time;
//   info_p->state = new_state;
//   return 0;
// }

// static int exit_event(pid_t pid, size_t field_offset,
//                       thread_state_t new_block_state,
//                       thread_state_t new_state) {
//   struct internal_thread_info *info_p, info = {};

//   s64 delta;

//   u64 current_time, current_block_index;

//   u64 *field_ptr;

//   current_time = bpf_ktime_get_ns();

//   info_p = bpf_map_lookup_elem(&thread_map, &pid);
//   if (!info_p) {
//     // This thread was not yet encountered
//     create_new_thread_info(&info, pid, new_block_state, current_time);
//     info_p = bpf_map_lookup_elem(&thread_map, &pid);
//     if (!info_p) {
//       bpf_printk("exit_event: Could not create thread info for (%d)\n", pid);
//       return 0;
//     }
//   }

//   current_block_index =
//       get_block_index(current_time, info_p->thread_creation_ts);

//   if (current_block_index > info_p->block_index) {
//     // The last event was in a previous block
//     // We need to submit this block to the user space
//     delta =
//         (s64)(info_p->block_start_ts + granularity_ns -
//         info_p->last_event_ts);
//     if (delta < 0) {
//       bpf_printk("exit_event: delta previous block negative (%d)\n", pid);
//       goto cleanup;
//     }

//     if (delta > granularity_ns) {
//       bpf_printk("exit_event: WARNING (%d) delta of previous "
//                  "block is higher than granularity_ns\n",
//                  pid);
//     }

//     field_ptr = (u64 *)((char *)info_p + field_offset);
//     *field_ptr += delta;
//     info_p->last_event_ts = info_p->block_start_ts + granularity_ns;
//     info_p->state = new_block_state;
//     submit_current_block(pid, info_p);
//     bump_block(info_p, current_block_index, current_time);
//   }

//   delta = (s64)(current_time - info_p->last_event_ts);
//   if (delta < 0) {
//     bpf_printk("exit_event: delta current block negative (%d)\n", pid);
//     goto cleanup;
//   }

//   if (delta > granularity_ns) {
//     bpf_printk("exit_event: WARNING (%d) delta of current block is "
//                "higher than granularity_ns\n",
//                pid);
//   }

//   info_p->last_event_ts = current_time;

//   field_ptr = (u64 *)((char *)info_p + field_offset);
//   *field_ptr += delta;
//   info_p->state = new_state;

// cleanup:
//   return 0;
// }

// Userspace mutex lock call
// SEC("uprobe/libc.so.6:__pthread_mutex_lock")
// int BPF_PROG(uprobe_pthread_mutex_lock, void *unused) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   return enter_event(pid, SCHEDULED_IN, MUTEX_WAIT);
// }

// Userspace mutex lock return
// SEC("uretprobe/libc.so.6:__pthread_mutex_lock")
// int BPF_PROG(uretprobe_pthread_mutex_lock, void *unused) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   size_t offset = offsetof(struct internal_thread_info, mutex_wait_time_ns);
//   return exit_event(pid, offset, MUTEX_WAIT, SCHEDULED_IN);
// }

// This is only the read system call
// SEC("tracepoint/syscalls/sys_enter_futex")
// int trace_enter_futex(struct trace_event_raw_sys_enter *ctx) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   // TODO: use this
//   switch (state) {
//   case ERROR_STATE:
//     bpf_printk("handle_sched_switch: prev previous block ERROR_STATE");
//     break;
//   case SCHEDULED_OUT:
//     bpf_printk("handle_sched_switch: prev previous block SCHEDULED_OUT");
//     break;
//   case MUTEX_WAIT:
//     bpf_printk("handle_sched_switch: prev previous block MUTEX_WAIT");
//     u64 block_end = info_p->block_start_ts + granularity_ns;
//     info_p->mutex_time_ns += block_end - info_p->last_event_ts;
//     info_p->last_event_ts = block_end;
//     submit_current_block(pid, info_p);

//     if (current_block_index > info_p->block_index + 1) {
//       // The current event happend more than one granularity_ns from the
//       // last event

//       info_p->block_index += 1;
//       info_p->block_start_ts = block_end;
//       info_p->last_event_ts =
//           start_of_block(current_time, info_p->thread_creation_ts);
//       info_p->offcpu_time_ns = 0;
//       info_p->mutex_time_ns = info_p->last_event_ts - info_p->block_start_ts;
//       info_p->futex_time_ns = 0;
//       info_p->disk_io_time_ns = 0;
//       submit_current_block(pid, info_p);

//       bump_block(info_p, current_block_index, current_time);
//       info_p->mutex_time_ns += current_time - info_p->block_start_ts;
//       state_stack_push(info_p, SCHEDULED_OUT);
//     }
//     break;
//   default:
//     bpf_printk("handle_sched_switch: prev previous block %s",
//                thread_state_name[state]);

//     state_stack_push(info_p, SCHEDULED_OUT);
//     break;
//   }

//   bpf_printk("tracepoint: sys_enter_futex tgid=%u pid=%u\n", tgid, pid);
//   return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_futex")
// int trace_exit_futex(struct trace_event_raw_sys_exit *ctx) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   bpf_printk("tracepoint: sys_exit_futex tgid=%u pid=%u\n", tgid, pid);
//   return 0;
// }

// Userspace barrier wait call
// SEC("uprobe/libc.so.6:pthread_barrier_wait")
// int BPF_PROG(uprobe_pthread_barrier_wait, void *unused) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;
//   u32 pid = (u32)id;

//   // bpf_printk("UPROBE: pthread_barrier_wait tgid=%u pid=%u\n", tgid, pid);
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

//   // bpf_printk("URETPROBE: pthread_barrier_wait tgid=%u pid=%u\n", tgid,
//   pid); return 0;
// }

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

// Userspace semaphore wait call
// SEC("uprobe/libc.so.6:sem_wait")
// int BPF_PROG(uprobe_sem_wait, void *unused) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   // bpf_printk("UPROBE: sem_wait tgid=%u pid=%u\n", tgid, pid);
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

//   // bpf_printk("URETPROBE: sem_wait tgid=%u pid=%u\n", tgid, pid);
//   return 0;
// }

// This is only the read system call
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

// SEC("tracepoint/block/block_rq_issue")
// int trace_block_rq_issue(struct trace_event_raw_block_rq *ctx) {
//   u64 id = bpf_get_current_pid_tgid();
//   u32 tgid = id >> 32;
//   if (!allowed_tgid(tgid))
//     return 0;

//   u32 pid = (u32)id;

//   // The key is a composition, it is not that strong but it should be fine
//   u64 key = ((u64)ctx->dev << 32) | ctx->sector;
//   bpf_map_update_elem(&disk_io_pid_map, &key, &id, BPF_ANY);

//   // bpf_printk("TRACEPOINT: block_rq_issue tgid=%u pid=%u, dev=%u,
//   // sector=%ull\n",
//   //            tgid, pid, ctx->dev, ctx->sector);
//   return enter_event(pid, SCHEDULED_IN, DISK_IO);
// }

// For the IO completion we need to do a workaround. The problem is that the
// process that completes the IO instructions is not necessarily the same as
// one that issued it. This means that we need to keep track of device and
// sector instruction data so that we can find again which process issued the
// IO instructions.
// TODO: For IO the problem is that IO can also be done asynchronously. I
// think one approach is to actually look if the scheduler is scheduling out the
// thread while IO is happening. That would be a strong indication that it
// is synchronous IO and not asynchronous. To be thought about in the future.
// SEC("tracepoint/block/block_rq_complete")
// int trace_block_rq_complete(struct trace_event_raw_block_rq_completion *ctx)
// {

//   u64 key = ((u64)ctx->dev << 32) | ctx->sector;
//   u32 *pid_p = bpf_map_lookup_elem(&disk_io_pid_map, &key);

//   // The pid was not in the map, so it was not allowed
//   if (!pid_p)
//     return 0;

//   u32 pid = *pid_p;

//   // bpf_printk("TRACEPOINT: block_rq_complete pid=%u, dev=%u,
//   sector=%ull\n",
//   // pid,
//   //            ctx->dev, ctx->sector);
//   size_t offset = offsetof(struct internal_thread_info, disk_io_time_ns);
//   exit_event(pid, offset, DISK_IO, SCHEDULED_IN);
//   bpf_map_delete_elem(&disk_io_pid_map, &key);
//   return 0;
// }
