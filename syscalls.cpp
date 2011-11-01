#include <stdio.h>
#include "syscalls.h"
#include "iojack.h"
#include "buffer.h"
#include <vector>
#include <sys/syscall.h>
#include <sys/select.h>
#include <poll.h>
#include <fcntl.h>

using namespace std;

vector<hookPtr> preSyscall;
vector<hookPtr> fakedSyscall;
vector<hookPtr> postSyscall;

inline void setHook(vector<hookPtr> &v, int syscall, hookPtr ptr)
{
	if(syscall < 0)
		return; // Fail silently. Who told you to hook negative syscalls? 
	
	if(v.size() <= (unsigned int)syscall)
	{
		v.resize(syscall + 1, NULL);
	}
	v[syscall] = ptr;
}

void setPreHook(int syscall, hookPtr ptr)
{
	setHook(preSyscall, syscall, ptr);
}

void setFakedHook(int syscall, hookPtr ptr)
{
	setHook(fakedSyscall, syscall, ptr);
}

void setPostHook(int syscall, hookPtr ptr)
{
	setHook(postSyscall, syscall, ptr);
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
	if(inputBuffer.lockedSize() && pi->isStdin(regs.ARG1))
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
	if(pi->isStdout(regs.ARG1) || pi->isStderr(regs.ARG1))
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
	if(regs.ARG2 && inputBuffer.lockedSize() && pi->stdin.size())
	{
		pi->readMemcpy(&inSet, regs.ARG2, sizeof(fd_set));
		foreach(pi->stdin, it)
			if(FD_ISSET(*it, &inSet))
			{
				fakeSyscall = 1;
				return;
			}
	}
	
}

void fakeSelectHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &unused)
{
	regs.RAX = 0;
	
	// readfds
	if(regs.ARG2 && inputBuffer.lockedSize() && pi->stdin.size())
	{
		fd_set readSet;
		pi->readMemcpy(&readSet, regs.ARG2, sizeof(fd_set));
		// Get the file descriptor
		int fd = 0;
		foreach(pi->stdin, it)
			if(FD_ISSET(*it, &readSet))
				fd = *it;
		//FD_ZERO(&readSet);
		for(unsigned int i = 0; i < regs.ARG1; i++)
			FD_CLR(i, &readSet);
		FD_SET(fd, &readSet);
		pi->writeMemcpy(regs.ARG2, &readSet, sizeof(fd_set));
		
		regs.RAX += 1;
	}
	
	// writefds
	if(regs.ARG3)
	{
		fd_set writeSet;
		pi->readMemcpy(&writeSet, regs.ARG3, sizeof(fd_set));
		//FD_ZERO(&writeSet);
		for(unsigned int i = 0; i < regs.ARG1; i++)
			FD_CLR(i, &writeSet);
		pi->writeMemcpy(regs.ARG3, &writeSet, sizeof(fd_set));
	}
	
	// exceptfds
	if(regs.ARG4
		&& regs.ARG4 != (unsigned long)-1 // Nano temporary workaround
		)
	{
		fd_set exceptSet;
		pi->readMemcpy(&exceptSet, regs.ARG4, sizeof(fd_set));
		//FD_ZERO(&exceptSet);
		for(unsigned int i = 0; i < regs.ARG1; i++)
			FD_CLR(i, &exceptSet);
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
	if(regs.ARG2 && inputBuffer.lockedSize() && pi->stdin.size())
	{
		pollfd fds[regs.ARG2];
		pi->readMemcpy(&fds, regs.ARG1, regs.ARG2 * sizeof(pollfd));
		
		for(unsigned int i = 0; i < regs.ARG2; i++)
		{
			if(pi->isStdin(fds[i].fd) && (fds[i].events & POLLIN))
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
			fds[i].revents = 0;
			
			if(pi->isStdin(fds[i].fd) && (fds[i].events & POLLIN))
			{
				fds[i].revents = POLLIN;
				regs.RAX += 1;
				// Maybe force all other revents to 0 now that we've found one valid stdin fd?
			}
		}
		
		pi->writeMemcpy(regs.ARG1, &fds, regs.ARG2 * sizeof(pollfd));
	}
	
	saveRegs = 1;
}

void postCloseHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &unused)
{
	//printf("[%d] Got close(%lu) syscall! (returned: %d)\n", pi->pid, pi->orig_regs.ARG1, (int)regs.RAX);
	if((int)regs.RAX != 0)
		return;

	pi->closeFileDescriptor(pi->orig_regs.ARG1);
}

void postDupHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &unused)
{
	//printf("[%d] Got dup(%lu) syscall! (returned: %d)\n", pi->pid, pi->orig_regs.ARG1, (int)regs.RAX);
	if((int)regs.RAX == -1)
		return;

	//TODO: check the man for FD_CLOEXEC
	pi->duplicateFileDescriptor(pi->orig_regs.ARG1, regs.RAX);
}

void postDup2Hook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &unused)
{
	//printf("[%d] Got dup2(%lu, %lu) syscall! (returned: %d)\n", pi->pid, pi->orig_regs.ARG1, pi->orig_regs.ARG2, (int)regs.RAX);
	if((int)regs.RAX == -1)
		return;

	if(pi->orig_regs.ARG1 == pi->orig_regs.ARG2)
		return; // Do nothing as per the man page

	pi->closeFileDescriptor(pi->orig_regs.ARG2);

	//TODO: check the man for FD_CLOEXEC
	pi->duplicateFileDescriptor(pi->orig_regs.ARG1, pi->orig_regs.ARG2);
}

void postDup3Hook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &unused)
{
	//printf("[%d] Got dup3(%lu, %lu, %lu) syscall! (returned: %d)\n", pi->pid, pi->orig_regs.ARG1, pi->orig_regs.ARG2, pi->orig_regs.ARG3, (int)regs.RAX);
	if((int)regs.RAX == -1)
		return;

	pi->closeFileDescriptor(pi->orig_regs.ARG2);
	pi->duplicateFileDescriptor(pi->orig_regs.ARG1, pi->orig_regs.ARG2);

	if(pi->orig_regs.ARG3 & FD_CLOEXEC)
	{
		// TODO: Do something
	}
}

void postFcntlHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &unused)
{
	//printf("[%d] Got fcntl(%lu, %lu, %lu) syscall! (returned: %d)\n", pi->pid, pi->orig_regs.ARG1, pi->orig_regs.ARG2, pi->orig_regs.ARG3, (int)regs.RAX);
	if((int)regs.RAX == -1)
		return;

	if(pi->orig_regs.ARG2 == F_DUPFD || pi->orig_regs.ARG2 == F_DUPFD_CLOEXEC)
	{
		pi->duplicateFileDescriptor(pi->orig_regs.ARG1, (int)regs.RAX);
	}
}

//int open(const char *pathname, int flags, mode_t mode);
//int creat(const char *pathname, mode_t mode);
void postOpenHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &unused)
{
	//printf("[%d] Got open(%lx, %lu, %lu) syscall! (returned: %d)\n", pi->pid, pi->orig_regs.ARG1, pi->orig_regs.ARG2, pi->orig_regs.ARG3, (int)regs.RAX);
	if((int)regs.RAX < 0)
		return;

	#define MAX_FILE_LEN 100
	char fileName[MAX_FILE_LEN + 1];
	pi->readStrncpy(fileName, pi->orig_regs.ARG1, MAX_FILE_LEN);
	fileName[MAX_FILE_LEN] = '\0';
	#undef MAX_FILE_LEN

	//printf("[%d] open(%s) = %d\n", pi->pid, fileName, (int)regs.RAX);

	// Check if opening a terminal
	if(!strncmp(fileName, "/dev/pts/", strlen("/dev/pts/"))
	|| !strncmp(fileName, "/dev/tty",  strlen("/dev/tty")))
	{
		if((pi->orig_regs.ARG2 & 3) == O_RDONLY || (pi->orig_regs.ARG2 & 3) == O_RDWR)
		{
			pi->stdin.insert(regs.RAX);
		}

		if((pi->orig_regs.ARG2 & 3) == O_WRONLY || (pi->orig_regs.ARG2 & 3) == O_RDWR)
		{
			pi->stdout.insert(regs.RAX);
			pi->stderr.insert(regs.RAX);
		}
	}
}

// ======== END OF HOOKS ===========

//void prePollHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &fakeSyscall)
//void fakePollHook(processInfo *pi, user_regs_struct &regs, int &saveRegs, int &unused)

void initSyscallHooks()
{
	setPreHook  (SYS_write,  preWriteHook);
	setPreHook  (SYS_read,   preReadHook);
	setFakedHook(SYS_read,   fakedReadHook);
	setPreHook  (SYS_select, preSelectHook);
	setFakedHook(SYS_select, fakeSelectHook);
	setPreHook  (SYS_poll,   prePollHook);
	setFakedHook(SYS_poll,   fakePollHook);
	setPostHook (SYS_close,  postCloseHook);
	setPostHook (SYS_dup,    postDupHook);
	setPostHook (SYS_dup2,   postDup2Hook);
	setPostHook (SYS_dup3,   postDup3Hook);
	setPostHook (SYS_fcntl,  postFcntlHook);
	setPostHook (SYS_open,   postOpenHook);
}
