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

struct profile_block {
  int tid;
  unsigned long long start_time_ns;
  int offcpu_component;
};

#endif /* __PENSIEVE_H */
