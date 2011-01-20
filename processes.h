#ifndef PROCESSES_H
#define PROCESSES_H

#include <sys/types.h>

class processInfo
{
	public:
	processInfo(pid_t newPid)
	{
		pid = newPid;
		inSyscall = 0;
		fakingSyscall = -1;
		
		sigstopToDetach = 0;
		sigstopToRestartSyscall = 0;
		sigstopNewChild = 0;
	}

	pid_t pid;
	int inSyscall;
	int fakingSyscall;
	
	int sigstopToDetach;
	int sigstopToRestartSyscall;
	int sigstopNewChild;
	
	unsigned long getValue(unsigned long addr);
	long writeLong(unsigned long addr, unsigned long value);
	int writeChar(unsigned long addr, unsigned char value);
	
	void detachProcess();
	void stopAtSyscall(int signal = 0);
};

#endif
