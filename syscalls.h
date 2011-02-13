#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "processes.h"
#include <sys/user.h>

void initSyscallHooks();

typedef void (*hookPtr)(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &hookSyscall);
//typedef void (*hookPtr)(processInfo *pi, user_regs_struct &regs);

hookPtr getPreHook(int syscall);
hookPtr getFakedHook(int syscall);
hookPtr getPostHook(int syscall);

#endif
