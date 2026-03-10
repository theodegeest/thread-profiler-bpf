# TODO list

- when unscheduling look at state

 `TASK_RUNNING`          runnable or currently running if scheduled out: cause preemption
 `TASK_INTERRUPTIBLE`    sleeping (can be woken by signal) sleep, futex, yield
 `TASK_UNINTERRUPTIBLE`  waiting for I/O / lock (lock? maybe lookup)
 `TASK_STOPPED`          stopped by signal
 `TASK_DEAD`             exiting

- IO
  sys_enter_read (userspace read)
  block_rq_issue (start an io)
  block_rq_complete (io is complete?)
  sched_switch (maybe schedule back? before or after complete?)

- yield?
  tracepoint/syscalls/sys_enter_sched_yield

- sleep?
  tracepoint/syscalls/sys_enter_nanosleep

- add synchronisation metric (contention?)
- add syscall metric
- add memory metric (LLC?)
- Make user side request latest data when closing (to reduce information loss on last profile block)
