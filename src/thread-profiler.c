// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <asm/unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "thread-profiler.h"
#include "thread-profiler.skel.h"
#include "trace_helpers.h"

static struct env {
  unsigned long long granularity_ns;
  pid_t pid;
  int freq;
} env = {.granularity_ns = 1e8, .freq = 99};

const char *argp_program_version = "thread_profiler 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
    "Perform per thread event profiling.\n"
    "\n"
    "USAGE: thread-profiler [--help] [-p PID] [-t TID]"
    "EXAMPLES:\n"
    "    thread-profiler             # profile all threads until Ctrl-C\n"
    "    thread-profiler -p 185 # only profile threads for PID 185\n"
    "    thread-profiler -f 199 # sample perf events at 199HZ (default 88Hz)\n";

static const struct argp_option opts[] = {
    {"pid", 'p', "PID", 0, "Profile this PID only", 0},
    {"granularity", 'g', "GRANULARITY-NS", 0,
     "Size of granularity for profile blocks in ns"},
    {"frequency", 'f', "FREQUENCY", 0, "Sample with a certain frequency", 0},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
  long number;
  switch (key) {
  case 'g':
    errno = 0;
    number = strtol(arg, NULL, 10);
    if (errno || number <= 0) {
      fprintf(stderr, "Invalid duration: %s\n", arg);
      argp_usage(state);
    } else {
      env.granularity_ns = (unsigned long long)number;
    }
    break;
  case 'p':
    errno = 0;
    number = strtol(arg, NULL, 10);
    if (errno || number <= 0) {
      fprintf(stderr, "Invalid PID: %s\n", arg);
      argp_usage(state);
    } else {
      env.pid = (unsigned long long)number;
    }
    break;
  case 'f':
    errno = 0;
    env.freq = strtol(arg, NULL, 10);
    if (errno || env.freq <= 0) {
      fprintf(stderr, "Invalid freq (in HZ): %s\n", arg);
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

static int open_and_attach_perf_event(int freq,
                                      struct thread_profiler_bpf *skel,
                                      struct bpf_link *links[], int leader_fd,
                                      enum perf_hw_id event, int cpu,
                                      struct bpf_program *prog,
                                      int perf_event_id) {
  int fd;

  struct perf_event_attr attr = {
      .type = PERF_TYPE_HARDWARE,
      .freq = 1,
      .sample_freq = freq,
      .config = event,
  };
  attr.size = sizeof(attr);
  // Create group
  fd = syscall(__NR_perf_event_open, &attr, -1, cpu, leader_fd, 0);
  if (fd < 0) {
    /* Ignore CPU that is offline */
    if (errno == ENODEV)
      return -1;
    fprintf(stderr, "failed to init perf sampling: %s\n", strerror(errno));
    return -1;
  }
  links[cpu * PERF_EVENT_NR + perf_event_id] =
      bpf_program__attach_perf_event(prog, fd);
  if (!links[cpu * PERF_EVENT_NR + perf_event_id]) {
    fprintf(stderr, "failed to attach perf event on cpu: %d\n", cpu);
    close(fd);
    return -1;
  }
  return fd;
}

static int nr_cpus;

static int open_and_attach_perf_events(int freq,
                                       struct thread_profiler_bpf *skel,
                                       struct bpf_link *links[]) {
  int i, fd, leader_fd;

  for (i = 0; i < nr_cpus; i++) {
    leader_fd = open_and_attach_perf_event(freq, skel, links, -1,
                                           PERF_COUNT_HW_CPU_CYCLES, i,
                                           skel->progs.sample_cycles, 0);
    if (leader_fd < 0)
      return 1;

    // fd = open_and_attach_perf_event(freq, skel, links, -1,
    //                                 PERF_COUNT_HW_INSTRUCTIONS, i,
    //                                 skel->progs.sample_instructions, 1);
    // if (fd < 0)
    //   return 1;

    fd = open_and_attach_perf_event(freq, skel, links, -1,
                                    PERF_COUNT_HW_CACHE_MISSES, i,
                                    skel->progs.sample_cache_misses, 1);
    if (fd < 0)
      return 1;

    // fd = open_and_attach_perf_event(freq, skel, links, -1,
    //                                 PERF_COUNT_HW_CACHE_REFERENCES, i,
    //                                 skel->progs.sample_cache_ref, 3);
    // if (fd < 0)
    //   return 1;
  }

  return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_WARN)
    return vfprintf(stderr, format, args);
  return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

static void print_profile_block(struct profile_block *profile_block_p) {
  printf("%d %llu %llu %llu %llu %llu %llu %llu\n", profile_block_p->tid,
         profile_block_p->block_index, profile_block_p->block_start_time_ns,
         profile_block_p->block_end_time_ns, profile_block_p->offcpu_time_ns,
         profile_block_p->mutex_time_ns, profile_block_p->futex_time_ns,
         profile_block_p->disk_io_time_ns);
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
  struct bpf_link *links[MAX_CPU_NR * PERF_EVENT_NR] = {};
  int err, i;

  /* Parse command line arguments */
  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err)
    return err;

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Cleaner handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  nr_cpus = libbpf_num_possible_cpus();
  if (nr_cpus < 0) {
    fprintf(stderr, "failed to get # of possible cpus: '%s'!\n",
            strerror(-nr_cpus));
    return 1;
  }
  if (nr_cpus > MAX_CPU_NR) {
    fprintf(stderr, "the number of cpu cores is too big, please "
                    "increase MAX_CPU_NR's value and recompile");
    return 1;
  }

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
  if (env.pid) {
    skel->rodata->filter_by_tgid = true;
    skel->rodata->filter_tgid = env.pid;
  }

  /* Load & verify BPF programs */
  err = thread_profiler_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  // err = open_and_attach_perf_events(env.freq, skel, links);
  // if (err) {
  //   fprintf(stderr, "Failed to attach perf events\n");
  //   goto cleanup;
  // }

  /* Attach tracepoints */
  err = thread_profiler_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  // TODO: Look into this
  // I haven't found a clean way to be able to attach a probe on the conditional
  // variable. The problem is that libc exports multiple symbols for this
  // function. So the normal way to define the uprobe in the kernel side does
  // not work. The only working alternative that I have found is by manually
  // finding the offsets in the shared library object. As this is not a robust
  // way to attach a uprobe, I still need to look at alternatives. This way
  // makes it possible to attach to conditional variables on one machine, but
  // it does not guarantee that it works on any machine. Or even worse, on the
  // same machine but after an update.
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
  printf("%s %s %s %s %s %s %s %s\n", "TID", "BLOCK_INDEX", "BLOCK_START_TIME",
         "BLOCK_END_TIME", "OFFCPU_TIME", "MUTEX", "FUTEX", "DISK_IO");
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

      // TODO: Add the delta from cutoff to a component
      if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
        printf("%d %llu %llu %llu %llu %llu %llu %llu %lu\n", key,
               value.block_index, value.block_start_ts, value.last_event_ts,
               value.offcpu_time_ns, value.mutex_time_ns, value.futex_time_ns,
               value.disk_io_time_ns, get_current_time_ns());
      }

      if (bpf_map_get_next_key(map_fd, &key, &next_key) != 0)
        break;
    }
  }

  fflush(stdout);

cleanup:
  /* Clean up */
  ring_buffer__free(rb);
  for (i = 0; i < nr_cpus * PERF_EVENT_NR; i++)
    bpf_link__destroy(links[i]);
  thread_profiler_bpf__destroy(skel);

  return err < 0 ? -err : 0;
}
