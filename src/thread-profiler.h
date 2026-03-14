/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __THREAD_PROFILER_H
#define __THREAD_PROFILER_H

#define MAX_CPU_NR	128
#define PERF_EVENT_NR 3
#define TASK_COMM_LEN 16
#define MAX_PID_NR 30
#define MAX_TID_NR 30

// TODO: Rename state -> mark
// These are the states that the state machines keep track of
typedef enum thread_state {
  ERROR_STATE = 0,
  SCHEDULED_OUT = 1,
  SCHEDULED_IN = 2,
  MUTEX = 3,
  FUTEX = 4,
  DISK_IO = 5,
  THREAD_CREATE = 6,
  THREAD_EXIT = 7,
} thread_state_t;

// This is an array that makes it possible to print the states to stdout.
static const char *const thread_state_name[] = {
    "ERROR_STATE", "SCHEDULED_OUT", "SCHEDULED_IN",  "MUTEX",
    "FUTEX",       "DISK_IO",       "THREAD_CREATE", "THREAD_EXIT"};

#define THREAD_STATE_NAME_COUNT                                                \
  (sizeof(thread_state_name) / sizeof(thread_state_name[0]))

struct profile_block {
  int tid;
  unsigned long long block_index;
  unsigned long long block_start_time_ns;
  unsigned long long block_end_time_ns;
  unsigned long long offcpu_time_ns;
  unsigned long long mutex_time_ns;
  unsigned long long futex_time_ns;
  unsigned long long disk_io_time_ns;
};

#define STATE_STACK_MAX_DEPTH 5
struct internal_thread_info {
  unsigned long long thread_creation_ts;
  unsigned long long block_index;
  unsigned long long block_start_ts;
  unsigned long long last_event_ts;
  unsigned long long offcpu_time_ns;
  unsigned long long mutex_time_ns;
  unsigned long long futex_time_ns;
  unsigned long long disk_io_time_ns;
  thread_state_t state_stack[STATE_STACK_MAX_DEPTH];
  unsigned int state_depth;
};

// static inline thread_state_t
// state_stack_peek(struct internal_thread_info *info_p) {
//   if (!info_p)
//     return ERROR_STATE;
//   if (info_p->state_depth == 0)
//     return ERROR_STATE;

//   unsigned int idx = info_p->state_depth - 1;
//   switch (idx) {
//   case 0:
//     return info_p->state_stack[0];
//   case 1:
//     return info_p->state_stack[1];
//   case 2:
//     return info_p->state_stack[2];
//   case 3:
//     return info_p->state_stack[3];
//   case 4:
//     return info_p->state_stack[4];
//   default:
//     return ERROR_STATE;
//   }
// }

static inline thread_state_t
state_stack_peek(struct internal_thread_info *info_p) {
  if (!info_p)
    return ERROR_STATE;
  if (info_p->state_depth == 0)
    return ERROR_STATE;
  unsigned int idx = info_p->state_depth - 1;
  if (idx < STATE_STACK_MAX_DEPTH)
    return info_p->state_stack[idx];
  return ERROR_STATE;
}

// static inline thread_state_t
// state_stack_pop(struct internal_thread_info *info_p) {
//   if (!info_p)
//     return ERROR_STATE;
//   if (info_p->state_depth == 0)
//     return ERROR_STATE;

//   /* decrement depth and return the value at the resulting index */
//   unsigned int new_depth = info_p->state_depth - 1;
//   thread_state_t ret;
//   switch (new_depth) {
//   case 0:
//     ret = info_p->state_stack[0];
//     break;
//   case 1:
//     ret = info_p->state_stack[1];
//     break;
//   case 2:
//     ret = info_p->state_stack[2];
//     break;
//   case 3:
//     ret = info_p->state_stack[3];
//     break;
//   case 4:
//     ret = info_p->state_stack[4];
//     break;
//   default:
//     return ERROR_STATE;
//   }
//   // store the new depth only after reading the value (verifier likes this)
//   info_p->state_depth = new_depth; return ret;
// }

static inline thread_state_t
state_stack_pop(struct internal_thread_info *info_p) {
  if (!info_p)
    return ERROR_STATE;
  if (info_p->state_depth == 0)
    return ERROR_STATE;
  info_p->state_depth--;
  unsigned int idx = info_p->state_depth;
  if (idx < STATE_STACK_MAX_DEPTH)
    return info_p->state_stack[idx];
  return ERROR_STATE;
}

// static inline int state_stack_push(struct internal_thread_info *info_p,
//                                    thread_state_t state) {
//   if (!info_p)
//     return 0;
//   /* reject if already full */
//   if (info_p->state_depth >= STATE_STACK_MAX_DEPTH)
//     return 0;

//   unsigned int idx = info_p->state_depth;
//   switch (idx) {
//   case 0:
//     info_p->state_stack[0] = state;
//     break;
//   case 1:
//     info_p->state_stack[1] = state;
//     break;
//   case 2:
//     info_p->state_stack[2] = state;
//     break;
//   case 3:
//     info_p->state_stack[3] = state;
//     break;
//   case 4:
//     info_p->state_stack[4] = state;
//     break;
//   default:
//     return 0;
//   }
//   info_p->state_depth = idx + 1;
//   return 1;
// }

static inline int state_stack_push(struct internal_thread_info *info_p,
                                   thread_state_t state) {
  if (!info_p)
    return 0;

  unsigned int idx = info_p->state_depth;

  if (idx >= STATE_STACK_MAX_DEPTH)
    return 0;

  // NOTE: The switch statement can be resumed with the following line. It is
  // just an assignment of the state at the current index. However, the verifier
  // of eBPF is not able to prove that the index in the array is valid. That
  // is why a switch statement is needed here. Do not remove it.
  //
  // info_p->state_stack[idx] = state;
  switch (idx) {
  case 0:
    info_p->state_stack[0] = state;
    break;
  case 1:
    info_p->state_stack[1] = state;
    break;
  case 2:
    info_p->state_stack[2] = state;
    break;
  case 3:
    info_p->state_stack[3] = state;
    break;
  case 4:
    info_p->state_stack[4] = state;
    break;
  default:
    return 0;
  }
  info_p->state_depth++;
  return 1;
}

#endif /* __THREAD_PROFILER_H */
