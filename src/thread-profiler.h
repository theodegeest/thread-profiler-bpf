/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __THREAD_PROFILER_H
#define __THREAD_PROFILER_H

#define TASK_COMM_LEN 16
#define MAX_PID_NR 30
#define MAX_TID_NR 30

typedef enum thread_state {
  SCHEDULED_OUT = 0,
  SCHEDULED_IN = 1,
  THREAD_CREATE = 2,
  THREAD_EXIT = 3,
} thread_state_t;

const char *thread_state_name[] = {"SCHEDULED_OUT", "SCHEDULED_IN",
                                   "THREAD_CREATE", "THREAD_EXIT"};

struct internal_thread_info {
  unsigned long long thread_creation_ts;
  unsigned long long block_index;
  unsigned long long block_start_ts;
  unsigned long long first_block_event_ts;
  unsigned long long last_event_ts;
  unsigned long long offcpu_time_ns;
  thread_state_t state;
};

struct profile_block {
  int tid;
  unsigned long long block_index;
  unsigned long long block_start_time_ns;
  unsigned long long first_event_time_ns;
  unsigned long long last_event_time_ns;
  unsigned long long offcpu_time_ns;
  thread_state_t end_state;
};

#endif /* __THREAD_PROFILER_H */
