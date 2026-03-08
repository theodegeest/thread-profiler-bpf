/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __PENSIEVE_H
#define __PENSIEVE_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
  int pid;
  int ppid;
  unsigned exit_code;
  unsigned long long duration_ns;
  char comm[TASK_COMM_LEN];
  char filename[MAX_FILENAME_LEN];
  bool exit_event;
};

typedef enum thread_state {
  SCHEDULED_OUT = 0,
  SCHEDULED_IN = 1,
  THREAD_CREATE = 2,
  THREAD_EXIT = 3,
} thread_state_t;

const char *thread_state_name[] = {"SCHEDULED_OUT", "SCHEDULED_IN",
                                   "THREAD_CREATE", "THREAD_EXIT"};

struct profile_block {
  int pid;
  unsigned long long block_index;
  unsigned long long block_start_time_ns;
  unsigned long long first_event_time_ns;
  unsigned long long last_event_time_ns;
  unsigned long long offcpu_time_ns;
  thread_state_t end_state;
};

#endif /* __PENSIEVE_H */
