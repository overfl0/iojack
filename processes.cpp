#include <stdio.h>
#include <sys/ptrace.h>
#include <errno.h>

#include "processes.h"
#include "sshijack.h"

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
