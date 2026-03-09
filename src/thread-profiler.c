// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>

#include "thread-profiler.h"
#include "thread-profiler.skel.h"
#include "trace_helpers.h"

static struct env {
  unsigned long long granularity_ns;
  pid_t pids[MAX_PID_NR];
  pid_t tids[MAX_TID_NR];
} env = {.granularity_ns = 1e8};

const char *argp_program_version = "thread_profiler 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
    "Perform per thread event profiling.\n"
    "\n"
    "USAGE: thread-profiler [--help] [-p PID] [-t TID]"
    "EXAMPLES:\n"
    "    thread-profiler             # profile all threads until Ctrl-C\n"
    "    thread-profiler -p 185,175,165 # only profile threads for PID "
    "185,175,165\n"
    "    thread-profiler -t 188,120,134 # only profile threads 188,120,134\n";

static const struct argp_option opts[] = {
    {"pid", 'p', "PID", 0, "Profile these PIDs only, comma-separated list", 0},
    {"tid", 't', "TID", 0, "Profile these TIDs only, comma-separated list", 0},
    {"granularity", 'g', "GRANULARITY-NS", 0,
     "Size of granularity for profile blocks in ns"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
  int ret;
  switch (key) {
  case 'g':
    errno = 0;
    long number = strtol(arg, NULL, 10);
    if (errno || number <= 0) {
      fprintf(stderr, "Invalid duration: %s\n", arg);
      argp_usage(state);
    } else {
      env.granularity_ns = (unsigned long long)number;
    }
    break;
  case 'p':
    ret = split_convert(strdup(arg), ",", env.pids, sizeof(env.pids),
                        sizeof(pid_t), str_to_int);
    if (ret) {
      if (ret == -ENOBUFS)
        fprintf(stderr, "the number of pid is too big, please "
                        "increase MAX_PID_NR's value and recompile\n");
      else
        fprintf(stderr, "invalid PID: %s\n", arg);

      argp_usage(state);
    }
    break;
  case 't':
    ret = split_convert(strdup(arg), ",", env.tids, sizeof(env.tids),
                        sizeof(pid_t), str_to_int);
    if (ret) {
      if (ret == -ENOBUFS)
        fprintf(stderr, "the number of tid is too big, please "
                        "increase MAX_TID_NR's value and recompile\n");
      else
        fprintf(stderr, "invalid TID: %s\n", arg);

      argp_usage(state);
    }
    break;
  case ARGP_KEY_ARG:
    argp_usage(state);
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_WARN)
    return vfprintf(stderr, format, args);
  return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

static void print_profile_block(struct profile_block *profile_block_p) {
  printf("%d %llu %llu %llu %llu %llu %s\n", profile_block_p->tid,
         profile_block_p->block_index, profile_block_p->block_start_time_ns,
         profile_block_p->first_event_time_ns,
         profile_block_p->last_event_time_ns, profile_block_p->offcpu_time_ns,
         thread_state_name[profile_block_p->end_state]);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  struct profile_block *profile_block_p = data;
  print_profile_block(profile_block_p);
  return 0;
}

uint64_t get_current_time_ns() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(int argc, char **argv) {
  struct ring_buffer *rb = NULL;
  struct thread_profiler_bpf *skel;
  int pids_fd, tids_fd, err, i;
  __u8 val = 0;

  /* Parse command line arguments */
  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err)
    return err;

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Cleaner handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* Load and verify BPF application */
  skel = thread_profiler_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /* Parameterize BPF code with minimum duration parameter */
  skel->rodata->granularity_ns = env.granularity_ns;

  /* User space PID and TID correspond to TGID and PID in the kernel,
   * respectively */
  if (env.pids[0])
    skel->rodata->filter_by_tgid = true;
  if (env.tids[0])
    skel->rodata->filter_by_pid = true;

  /* Load & verify BPF programs */
  err = thread_profiler_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  if (env.pids[0]) {
    /* User pids_fd points to the tgids map in the BPF program */
    pids_fd = bpf_map__fd(skel->maps.tgids);
    for (i = 0; i < MAX_PID_NR && env.pids[i]; i++) {
      if (bpf_map_update_elem(pids_fd, &(env.pids[i]), &val, BPF_ANY) != 0) {
        fprintf(stderr, "failed to init pids map: %s\n", strerror(errno));
        goto cleanup;
      }
    }
  }
  if (env.tids[0]) {
    /* User tids_fd points to the pids map in the BPF program */
    tids_fd = bpf_map__fd(skel->maps.pids);
    for (i = 0; i < MAX_TID_NR && env.tids[i]; i++) {
      if (bpf_map_update_elem(tids_fd, &(env.tids[i]), &val, BPF_ANY) != 0) {
        fprintf(stderr, "failed to init tids map: %s\n", strerror(errno));
        goto cleanup;
      }
    }
  }

  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  /* Attach tracepoints */
  err = thread_profiler_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  // TODO: Look into this
  // {
  //   /* after loading the bpf object (obj) and finding the program */
  //   struct bpf_program *prog =
  //       bpf_object__find_program_by_name(skel->obj,
  //       "uprobe_pthread_cond_wait");
  //   if (!prog) /* handle error */
  //     ;

  //   LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
  //   // uprobe_opts.func_name =
  //   //     "pthread_cond_wait";      // ask libbpf to resolve the symbol name
  //   uprobe_opts.retprobe = false; // false = entry, true = return

  //   // To get offsets use this command
  //   // No clue if this will be needed
  //   // nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep pthread_cond_wait
  //   // 000000000009b5e0 T pthread_cond_wait@@GLIBC_2.3.2
  //   // 0000000000099c80 T pthread_cond_wait@GLIBC_2.2.5
  //   //
  //   struct bpf_link *link = bpf_program__attach_uprobe_opts(
  //       prog, -1 /* all pids */, "/lib/x86_64-linux-gnu/libc.so.6",
  //       0x09b5e0 /* offset ignored when func_name used */, &uprobe_opts);

  //   // struct bpf_link *link = bpf_program__attach_uprobe_opts(
  //   //     prog, -1 /* all pids */, "/lib/x86_64-linux-gnu/libc.so.6",
  //   //     0x099c80 /* offset ignored when func_name used */, &uprobe_opts);
  //   if (!link) {
  //     fprintf(stderr, "attach UPROBE pthread_cond_wait failed: %s\n",
  //             strerror(errno));
  //     goto cleanup;
  //   }
  // }

  /* Process events */
  printf("%s %s %s %s %s %s %s\n", "TID", "BLOCK_INDEX", "BLOCK_START_TIME",
         "FIRST_EVENT_TIME", "LAST_EVENT_TIME", "OFFCPU_TIME", "END_STATE");
  fflush(stdout);
  while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }
  int map_fd = bpf_map__fd(skel->maps.thread_map);

  pid_t key, next_key;
  struct internal_thread_info value;

  /* get first key */
  if (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
    // There is at least one key
    while (1) {
      key = next_key;

      if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
        printf("%d %llu %llu %llu %llu %llu %s %lu\n", key, value.block_index,
               value.block_start_ts, value.first_block_event_ts,
               value.last_event_ts, value.offcpu_time_ns,
               thread_state_name[value.state], get_current_time_ns());
      }

      if (bpf_map_get_next_key(map_fd, &key, &next_key) != 0)
        break;
    }
  }

  fflush(stdout);

cleanup:
  /* Clean up */
  ring_buffer__free(rb);
  thread_profiler_bpf__destroy(skel);

  return err < 0 ? -err : 0;
}
