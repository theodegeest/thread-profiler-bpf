# TODO list

- when unscheduling look at state

 `TASK_RUNNING`          runnable or currently running if scheduled out: cause preemption
 `TASK_INTERRUPTIBLE`    sleeping (can be woken by signal) sleep, futex, yield
 `TASK_UNINTERRUPTIBLE`  waiting for I/O / lock (lock? maybe lookup)
 `TASK_STOPPED`          stopped by signal
 `TASK_DEAD`             exiting

- IO: Currently the thread profiler is assuming that any IO operation is done synchronously.
      It might be needed to use the scheduler information to reduce the actual IO time to the off-CPU time during the IO call.
      This makes it possible to distinguish between asynchronous IO and synchronous IO.

- yield?
  tracepoint/syscalls/sys_enter_sched_yield

- sleep?
  tracepoint/syscalls/sys_enter_nanosleep

- add synchronisation metric (contention?)
- add syscall metric
- add memory metric (LLC?)
- add barrier metric
- add semaphore metric
- add conditional variable metric (WARN multiple exported symbols in libc)
