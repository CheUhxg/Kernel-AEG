// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// File autogenerated by genseccomp.py from Android U - edit at your peril!!

const struct sock_filter arm_app_filter[] = {
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 0, 0, 146),
BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 240, 144, 0), //futex
BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 54, 143, 0), //ioctl
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 199, 71, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 85, 35, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 45, 17, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 26, 9, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 19, 5, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 10, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 8, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 7, 136, 135), //restart_syscall|exit|fork|read|write|open|close
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 9, 135, 134), //creat
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 13, 134, 133), //unlink|execve|chdir
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 24, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 21, 132, 131), //lseek|getpid
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 25, 131, 130), //getuid
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 36, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 33, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 27, 128, 127), //ptrace
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 34, 127, 126), //access
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 41, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 40, 125, 124), //sync|kill|rename|mkdir
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 44, 124, 123), //dup|pipe|times
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 63, 9, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 57, 5, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 55, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 52, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 46, 119, 118), //brk
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 53, 118, 117), //umount2
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 56, 117, 116), //fcntl
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 60, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 58, 115, 114), //setpgid
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 61, 114, 113), //umask
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 75, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 66, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 65, 111, 110), //dup2|getppid
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 68, 110, 109), //setsid|sigaction
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 77, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 76, 108, 107), //setrlimit
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 79, 107, 106), //getrusage|gettimeofday
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 125, 17, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 114, 9, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 96, 5, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 94, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 91, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 86, 101, 100), //readlink
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 93, 100, 99), //munmap|truncate
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 95, 99, 98), //fchmod
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 104, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 98, 97, 96), //getpriority|setpriority
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 107, 96, 95), //setitimer|getitimer|stat
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 118, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 116, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 115, 93, 92), //wait4
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 117, 92, 91), //sysinfo
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 122, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 121, 90, 89), //fsync|sigreturn|clone
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 123, 89, 88), //uname
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 168, 9, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 140, 5, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 136, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 131, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 126, 84, 83), //mprotect
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 134, 83, 82), //quotactl|getpgid|fchdir
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 137, 82, 81), //personality
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 150, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 149, 80, 79), //_llseek|getdents|_newselect|flock|msync|readv|writev|getsid|fdatasync
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 164, 79, 78), //mlock|munlock|mlockall|munlockall|sched_setparam|sched_getparam|sched_setscheduler|sched_getscheduler|sched_yield|sched_get_priority_max|sched_get_priority_min|sched_rr_get_interval|nanosleep|mremap
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 183, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 172, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 169, 76, 75), //poll
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 182, 75, 74), //prctl|rt_sigreturn|rt_sigaction|rt_sigprocmask|rt_sigpending|rt_sigtimedwait|rt_sigqueueinfo|rt_sigsuspend|pread64|pwrite64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 190, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 188, 73, 72), //getcwd|capget|capset|sigaltstack|sendfile
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 198, 72, 71), //vfork|ugetrlimit|mmap2|truncate64|ftruncate64|stat64|lstat64|fstat64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 327, 35, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 256, 17, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 219, 9, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 211, 5, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 207, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 205, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 203, 65, 64), //getuid32|getgid32|geteuid32|getegid32
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 206, 64, 63), //getgroups32
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 210, 63, 62), //fchown32|setresuid32|getresuid32
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 217, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 212, 61, 60), //getresgid32
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 218, 60, 59), //getdents64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 241, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 224, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 222, 57, 56), //mincore|madvise|fcntl64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 240, 56, 55), //gettid|readahead|setxattr|lsetxattr|fsetxattr|getxattr|lgetxattr|fgetxattr|listxattr|llistxattr|flistxattr|removexattr|lremovexattr|fremovexattr|tkill|sendfile64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 250, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 249, 54, 53), //sched_setaffinity|sched_getaffinity|io_setup|io_destroy|io_getevents|io_submit|io_cancel|exit_group
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 254, 53, 52), //epoll_create|epoll_ctl|epoll_wait|remap_file_pages
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 290, 9, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 280, 5, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 270, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 263, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 262, 48, 47), //set_tid_address|timer_create|timer_settime|timer_gettime|timer_getoverrun|timer_delete
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 269, 47, 46), //clock_gettime|clock_getres|clock_nanosleep|statfs64|fstatfs64|tgkill
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 271, 46, 45), //arm_fadvise64_64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 286, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 285, 44, 43), //waitid|socket|bind|connect|listen
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 289, 43, 42), //getsockname|getpeername|socketpair
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 316, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 292, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 291, 40, 39), //sendto
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 298, 39, 38), //recvfrom|shutdown|setsockopt|getsockopt|sendmsg|recvmsg
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 322, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 319, 37, 36), //inotify_init|inotify_add_watch|inotify_rm_watch
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 326, 36, 35), //openat|mkdirat|mknodat|fchownat
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 403, 17, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 369, 9, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 348, 5, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 345, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 340, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 339, 30, 29), //fstatat64|unlinkat|renameat|linkat|symlinkat|readlinkat|fchmodat|faccessat|pselect6|ppoll|unshare|set_robust_list
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 344, 29, 28), //splice|sync_file_range2|tee|vmsplice
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 347, 28, 27), //getcpu|epoll_pwait
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 350, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 349, 26, 25), //utimensat
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 367, 25, 24), //timerfd_create|eventfd|fallocate|timerfd_settime|timerfd_gettime|signalfd4|eventfd2|epoll_create1|dup3|pipe2|inotify_init1|preadv|pwritev|rt_tgsigqueueinfo|perf_event_open|recvmmsg|accept4
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 380, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 373, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 370, 22, 21), //prlimit64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 378, 21, 20), //syncfs|sendmmsg|setns|process_vm_readv|process_vm_writev
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 397, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 394, 19, 18), //sched_setattr|sched_getattr|renameat2|seccomp|getrandom|memfd_create|bpf|execveat|userfaultfd|membarrier|mlock2|copy_file_range|preadv2|pwritev2
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 398, 18, 17), //statx
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 438, 9, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 434, 5, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 420, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 417, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 415, 13, 12), //clock_gettime64|clock_settime64|clock_adjtime64|clock_getres_time64|clock_nanosleep_time64|timer_gettime64|timer_settime64|timerfd_gettime64|timerfd_settime64|utimensat_time64|pselect6_time64|ppoll_time64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 418, 12, 11), //recvmmsg_time64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 425, 11, 10), //semtimedop_time64|rt_sigtimedwait_time64|futex_time64|sched_rr_get_interval_time64|pidfd_send_signal
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 436, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 435, 9, 8), //pidfd_open
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 437, 8, 7), //close_range
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 983042, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 440, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 439, 5, 4), //pidfd_getfd
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 441, 4, 3), //process_madvise
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 983045, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 983043, 2, 1), //__ARM_NR_cacheflush
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 983046, 1, 0), //__ARM_NR_set_tls
BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
};

#define arm_app_filter_size (sizeof(arm_app_filter) / sizeof(struct sock_filter))