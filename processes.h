#ifndef PROCESSES_H
#define PROCESSES_H

#include <sys/types.h>
#include <set>
#include <sys/user.h> // user_regs_struct
#include <string.h> // memset

class processInfo
{
	public: // We have nothing to hide, don't we? :)
	processInfo(pid_t newPid)
	{
		pid = newPid;
		inSyscall = 0;
		fakingSyscall = -1;
		
		sigstopToDetach = 0;
		sigstopToRestartSyscall = 0;
		sigstopNewChild = 0;
		
		stdin.insert(0);
		stdout.insert(1);
		stderr.insert(2);
		
		//orig_regs = 0;
		memset(&orig_regs, 0, sizeof(user_regs_struct));
	}

	pid_t pid;
	int inSyscall;
	int fakingSyscall;
	
	int sigstopToDetach;
	int sigstopToRestartSyscall;
	int sigstopNewChild;
	
	user_regs_struct orig_regs;
	
	// TODO: Implement a more efficient container
	std::set<int> stdin, stdout, stderr;
	inline bool isStdin(int fd) { return stdin.find(fd) != stdin.end(); };
	inline bool isStdout(int fd) { return stdout.find(fd) != stdout.end(); };
	inline bool isStderr(int fd) { return stderr.find(fd) != stderr.end(); };
	
	unsigned long getValue(unsigned long addr);
	long writeLong(unsigned long addr, unsigned long value);
	int writeChar(unsigned long addr, unsigned char value);
	void readMemcpy(void *dest, unsigned long remoteAddr, unsigned int n);
	void writeMemcpy(unsigned long remoteAddr, void *src, unsigned int n);
	
	void detachProcess();
	void stopAtSyscall(int signal = 0);
};

#endif
