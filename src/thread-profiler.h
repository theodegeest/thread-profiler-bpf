/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __THREAD_PROFILER_H
#define __THREAD_PROFILER_H

#define TASK_COMM_LEN 16
#define MAX_PID_NR 30
#define MAX_TID_NR 30

typedef enum thread_state {
  ERROR_STATE = 0,
  SCHEDULED_OUT = 1,
  SCHEDULED_IN = 2,
  MUTEX_WAIT = 3,
  FUTEX = 4,
  DISK_IO = 5,
  THREAD_CREATE = 6,
  THREAD_EXIT = 7,
} thread_state_t;

static const char *const thread_state_name[] = {
    "ERROR_STATE", "SCHEDULED_OUT", "SCHEDULED_IN",  "MUTEX_WAIT",
    "FUTEX",       "DISK_IO",       "THREAD_CREATE", "THREAD_EXIT"};

#define THREAD_STATE_NAME_COUNT                                                \
  (sizeof(thread_state_name) / sizeof(thread_state_name[0]))

#define STATE_STACK_MAX_DEPTH 5
struct internal_thread_info {
  unsigned long long thread_creation_ts;
  unsigned long long block_index;
  unsigned long long block_start_ts;
  // unsigned long long block_end_ts;
  // unsigned long long first_block_event_ts;
  unsigned long long last_event_ts;
  unsigned long long offcpu_time_ns;
  unsigned long long mutex_time_ns;
  unsigned long long futex_time_ns;
  unsigned long long disk_io_time_ns;
  thread_state_t state_stack[STATE_STACK_MAX_DEPTH];
  unsigned int state_depth;
};

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

static inline int state_stack_push(struct internal_thread_info *info_p,
                                   thread_state_t state) {
  if (!info_p)
    return 0;
  if (info_p->state_depth < STATE_STACK_MAX_DEPTH) {
    unsigned int idx = info_p->state_depth;
    info_p->state_stack[idx] = state;
    info_p->state_depth++;
    return 1;
  }
  return 0;
}

// static thread_state_t state_stack_peek(struct internal_thread_info *info_p) {
//   unsigned int depth = info_p->state_depth;
//   if (depth >= 0 && depth < STATE_STACK_MAX_DEPTH) {
//     return info_p->state_stack[depth];
//   } else {
//     return ERROR_STATE;
//   }
// }

// static thread_state_t state_stack_pop(struct internal_thread_info *info_p) {
//   if (info_p->state_depth > 0) {
//     return info_p->state_stack[info_p->state_depth--];
//   } else {
//     return ERROR_STATE;
//   }
// }

// static int state_stack_push(struct internal_thread_info *info_p,
//                             thread_state_t state) {
//   if (info_p->state_depth < STATE_STACK_MAX_DEPTH - 1) {
//     info_p->state_stack[++(info_p->state_depth)] = state;
//     return 1;
//   } else {
//     return 0;
//   }
// }

struct profile_block {
  int tid;
  unsigned long long block_index;
  unsigned long long block_start_time_ns;
  unsigned long long block_end_time_ns;
  // unsigned long long first_event_time_ns;
  // unsigned long long last_event_time_ns;
  unsigned long long offcpu_time_ns;
  unsigned long long mutex_time_ns;
  unsigned long long futex_time_ns;
  unsigned long long disk_io_time_ns;
  // thread_state_t end_state;
};

#endif /* __THREAD_PROFILER_H */
