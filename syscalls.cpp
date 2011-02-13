#include <stdio.h>
#include "syscalls.h"
#include "sshijack.h"
#include "buffer.h"
#include <vector>
#include <stdexcept> // out_of_range exception
#include <sys/syscall.h>

using namespace std;

vector<hookPtr> preSyscall;
vector<hookPtr> fakedSyscall;
vector<hookPtr> postSyscall;

inline void addHook(vector<hookPtr> &v, int syscall, hookPtr ptr)
{
	if(syscall < 0)
		return; // Fail silently. Who told you to hook negative syscalls? 
	
	if(v.size() <= (unsigned int)syscall)
	{
		v.resize(syscall + 1, NULL);
	}
	v[syscall] = ptr;
}

inline hookPtr getHook(vector<hookPtr> &v, int syscall)
{
	if(syscall < 0 || v.size() <= (unsigned int)syscall)
		return NULL;
	return v[syscall];
	/* This version, while pretty, REALLY sucks performance-wise!
	try
	{
		return v.at(syscall);
	} catch(std::out_of_range e)
	{
		return NULL;
	}*/
}

hookPtr getPreHook(int syscall)
{
	return getHook(preSyscall, syscall);
}

hookPtr getFakedHook(int syscall)
{
	return getHook(fakedSyscall, syscall);
}

hookPtr getPostHook(int syscall)
{
	return getHook(postSyscall, syscall);
}

buffer inputBuffer;

// ============= HOOKS =============
void preReadHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &fakeSyscall)
{
	if(inputBuffer.lockedSize() && regs.ARG1 == 0)
	{
		dprintf("Syscall: 0x%lx\tfd: 0x%lx\tbuf: 0x%lx\tcount: 0x%lx\n", regs.ORIG_RAX, regs.ARG1, regs.ARG2, regs.ARG3);
		fakeSyscall = 1;
	}
}

void fakedReadHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &unused)
{
	//ssize_t read(int fd, void *buf, size_t count);
	//eax read(ebx fd, ecx *buf, edx count);
	unsigned int len = inputBuffer.lockedSize();
	if(regs.ARG3 < len)
		len = regs.ARG3;
	
	inputBuffer.lock();
	for(unsigned int i = 0; i < len; i++)
	{
		char c = inputBuffer.get();
		pi->writeChar(regs.ARG2 + i, c);
	}
	inputBuffer.unlock();
	regs.RAX = len;
	
	saveRegs = 1;
}

void preWriteHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &fakeSyscall)
{
	// ssize_t write(int fd, const void *buf, size_t count);
	//ssize_t retval = write(regs.ARG1, regs.ARG2, regs.ARG3);
	//write(stdout, regs.ARG2, regs.ARG3);
	dprintf("Got a write syscall!\n");
	dprintf("fd = %d\n", (int)regs.ARG1);
	if(regs.ARG1 == 1 /*stdout*/ || regs.ARG1 == 2 /*stderr*/ )
	{
		for(unsigned int i = 0; i < regs.ARG3; i++)
		{
			unsigned long c = pi->getValue(regs.ARG2 + i);
			dprintf("Wrote letter: ");
			printf("%c", (int)c);
			dprintf("\n");
		}
		fflush(stdout);
	}
	
	//return retval;
}

// ======== END OF HOOKS ===========

void initSyscallHooks()
{
	addHook(preSyscall, SYS_write, preWriteHook);
	addHook(preSyscall, SYS_read, preReadHook);
	addHook(fakedSyscall, SYS_read, fakedReadHook);
}
