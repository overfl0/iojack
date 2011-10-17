#include <stdio.h>
#include <stdlib.h>      // exit()
#include <sys/ptrace.h>
#include <errno.h>

#include "processes.h"
#include "iojack.h"

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

// FIXME: Needs testing
void processInfo::readMemcpy(void *dest, unsigned long remoteAddr, unsigned int n)
{
	unsigned long *udest = (unsigned long *)dest;
	dprintf("readMemcpy(dest=%lx, remoteAddr=%lx, uint n=%u\n", (unsigned long)dest, remoteAddr, n);
	for(; n >= sizeof(unsigned long); n -= sizeof(unsigned long))
	{
		//dprintf("%u\n", n);
		unsigned long retval = ptrace(PTRACE_PEEKDATA, pid, remoteAddr, 0);
		if(retval == (unsigned long)-1 && errno != 0)
		{
			perror("readMemcpy - ptrace read");
			return;
		}
		
		*udest++ = retval;
		remoteAddr += sizeof(unsigned long);
	}
	
	if(n > 0)
	{
		unsigned long retval = ptrace(PTRACE_PEEKDATA, pid, remoteAddr, 0);
		if(retval == (unsigned long)-1 && errno != 0)
		{
			perror("readMemcpy - ptrace read2");
			return;
		}
		
		char *c = (char *)&retval;
		for(unsigned int i = 0; i < n; i++)
		{
			//dprintf("%d\n", i);
			((char *)udest)[i] = c[i];
		}
	}
	
}

// FIXME: Needs testing
void processInfo::writeMemcpy(unsigned long remoteAddr, void *src, unsigned int n)
{
	unsigned long *usrc = (unsigned long *)src;
	dprintf("writeMemcpy(remoteAddr=%lx, src=%lx, uint n=%u\n", remoteAddr, (unsigned long)src, n);
	
	for(; n >= sizeof(unsigned long); n -= sizeof(unsigned long))
	{
		long retval = ptrace(PTRACE_POKEDATA, pid, remoteAddr, *usrc);
		if(retval == -1)
		{
			perror("writeMemcpy - ptrace write 1");
			return;
		}
		
		usrc++;
		remoteAddr += sizeof(unsigned long);
	}
	
	if(n > 0)
	{
		// Read the whole ulong into memory
		unsigned long remoteData = ptrace(PTRACE_PEEKDATA, pid, remoteAddr, 0);
		if(remoteData == (unsigned long)-1 && errno != 0)
		{
			perror("writeMemcpy - ptrace read");
			return;
		}
		
		// Modify only the requested bits
		char *c = (char *)&remoteData;
		for(unsigned int i = 0; i < n; i++)
		{
			//dprintf("%d\n", i);
			c[i] = ((char *)usrc)[i];
		}
		
		// Write it back
		long retval = ptrace(PTRACE_POKEDATA, pid, remoteAddr, remoteData);
		if(retval == -1)
		{
			perror("writeMemcpy - ptrace write 2");
			return;
		}
	}
	
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
