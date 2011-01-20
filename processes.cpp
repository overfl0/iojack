#include <stdio.h>
#include <stdlib.h>      // exit()
#include <sys/ptrace.h>
#include <errno.h>

#include "processes.h"
#include "sshijack.h"

// Memory access
unsigned long processInfo::getValue(unsigned long addr)
{
	unsigned long retval = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
	if(retval == (unsigned long)-1 && errno != 0)
	{
		perror("ptrace read");
		printf("errno: %d\n", errno);
	}
	//throw "Exception!!!";
	return retval;
}

long processInfo::writeLong(unsigned long addr, unsigned long value)
{
	long retval = ptrace(PTRACE_POKEDATA, pid, addr, value);
	if(retval == -1)
	{
		char tmp[100];
		sprintf(tmp, "ptrace write at addr 0x%lx", addr);
		perror(tmp);
	}
	else
		dprintf("Write OK!\n");
	return retval;
}

int processInfo::writeChar(unsigned long addr, unsigned char value)
{
	//TODO: Check retval + errno!
	unsigned long origVal = getValue(addr);
	unsigned char *p = (unsigned char *)&origVal;
	*p = value;
	writeLong(addr, origVal);
	
	return -1; // In case I forget about the TODO
}

// Remaining methods

static void printPtraceError(int error)
{
	switch(error)
	{
		case EBUSY: printf("EBUSY\n"); break;
		case EFAULT: printf("EFAULT\n"); break;
		case EIO: printf("EIO\n"); break;
		case EINVAL: printf("EINVAL\n"); break;
		case EPERM: printf("EPERM\n"); break;
		case ESRCH: printf("ESRCH\n"); break;
		default: printf("Reason: Other\n");
	}
}

void processInfo::detachProcess()
{
	printf("Detaching %d... ", pid);
	int retval = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if(retval == -1)
	{
		printf("Failed! ");
		printPtraceError(errno);
		perror("Detach failed");
	}
	else
	{
		printf("OK!\n");
	}
}

void processInfo::stopAtSyscall(int signal)
{
	if(ptrace(PTRACE_SYSCALL, pid, NULL, signal) == -1)
	{
		printPtraceError(errno);
		perrorexit("PTRACE_SYSCALL");
	}
}
