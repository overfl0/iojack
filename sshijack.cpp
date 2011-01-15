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

#include "sshijack.h"
#include "terminal.h"

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
public:
	void add(char c) {data.push(c);}
	void add(const char *s)
	{
		for(const char *p = s; *p; p++)
			data.push(*p);
	}
	int size() { return data.size(); }
	unsigned char get()
	{
		unsigned char c = data.front();
		data.pop();
		return c;
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
		printf("Write OK!\n");
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

inline int wejscie(int status)
{
	if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
		return 1;
	else
		return 0;
}

class processInfo
{
	public:
	processInfo(pid_t newPid)
	{
		pid = newPid;
		inSyscall = 0;
		fakingSyscall = -1;
	}

	pid_t pid;
	int inSyscall;
	int fakingSyscall;
};

typedef map<pid_t, processInfo*> processes_t;
processes_t processes;


// ============= HOOKS =============
void readHook(pid_t pid, user_regs_struct &regs)
{
	//ssize_t read(int fd, void *buf, size_t count);
	//eax read(ebx fd, ecx *buf, edx count);
	unsigned int len = inputBuffer.size();
	if(regs.ARG3 < len)
		len = regs.ARG3;
	
	for(unsigned int i = 0; i < len; i++)
	{
		char c = inputBuffer.get();
		writeChar(regs.ARG2 + i, c, pid);
	}
	regs.RAX = len;
}

void writeHook(pid_t pid, user_regs_struct &regs)
{
	// ssize_t write(int fd, const void *buf, size_t count);
	//ssize_t retval = write(regs.ARG1, regs.ARG2, regs.ARG3);
	//write(stdout, regs.ARG2, regs.ARG3);
	printf("fd = %d\n", (int)regs.ARG1);
	if(regs.ARG1 == 1 /*stdout*/ || regs.ARG1 == 2 /*stderr*/ )
	{
		for(unsigned int i = 0; i < regs.ARG3; i++)
		{
			unsigned long c = getValue(regs.ARG2 + i, pid);
			printf("Wrote letter: %c\n", (int)c);
		}
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
		printf("Entering syscall: 0x%lx\n", regs->ORIG_RAX);
		if(inputBuffer.size() && regs->ORIG_RAX == SYS_read)
		{
			printf("Syscall: 0x%lx\tfd: 0x%lx\tbuf: 0x%lx\tcount: 0x%lx\n", regs->ORIG_RAX, regs->ARG1, regs->ARG2, regs->ARG3);

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
			printf("Got a write syscall!\n");
			writeHook(pi->pid, *regs);
		}
		
		
		pi->inSyscall = 1;
	}
	else // Exiting from a syscall
	{
		printf("Exiting syscall: 0x%lx\n", regs->ORIG_RAX);
		if(pi->fakingSyscall != -1)
		{
			if(regs->ORIG_RAX != (unsigned int)-1)
				printf("OMG! :O\n");
			printf("Trying to write something.\n");
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
	{
		processInfo *pi = it->second;
		printf("Trying send SIGSTOP to pid %d... ", pi->pid);
		
		// If we're in the middle of faking a system call, we can't detach from this pid
		if(pi->inSyscall && pi->fakingSyscall != -1)
		{
			printf("faking system call. Aborted.\n");
			it++;
			continue;
		}
		
		// TODO: something along the lines of pi->sentSigStop = 1
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
	setSignalHandlers();

	//inputBuffer.add("To jest test\n");
	inputBuffer.add("To jest test");

	if(argc < 2)
		pexit("Usage: %s <pid>\n", argv[0]);

	int firstPid = atoi(argv[1]);
	if(firstPid <= 1)
		pexit("Can't get correct pid from arguments\n");

	printf("Attaching to pid: %d\n", firstPid);
	if(ptrace(PTRACE_ATTACH, firstPid, NULL, NULL) == -1)
		perrorexit("PTRACE_ATTACH");

	processes[firstPid] = new processInfo(firstPid);

	/*if(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) == -1)
		perrorexit("PTRACE_SETOPTIONS"); */

	int status;
	// Should be checked
	firstPid = wait(&status);
	if(WIFEXITED(status))
	{
		printf("Process %d exited\n", firstPid);
		return 0;
	}
	
	initTerminal();
	
	// We are interested only in syscalls
	if(ptrace(PTRACE_SYSCALL, firstPid, NULL, NULL) == -1)
		perrorexit("PTRACE_SYSCALL");
	
	//=========================================================================
	while(1)
	{
		// Check if we have something to read from stdin
		int inputChar = getTerminalChar();
		if(inputChar != -1)
		{
			inputBuffer.add(inputChar);
		}
		// Wait for a syscall to be called
		int pidReceived = wait(&status);
		//printf("After wait\n");
		// FIXME: || WIFSIGNALED?
		while(pidReceived != -1)
		{
			if(WIFEXITED(status))
			{
				printf("Process %d exited\n", pidReceived);
				processes.erase(pidReceived);
			
				// If no more traced processes, then exit
				if(processes.empty())
				{
					// Got a better idea to break out of TWO while loops at once?
					goto noMoreProcesses;
				}
			} else if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP /*&& pi->sentSigStop? */)
			{
				printf("******WIFSTOPPED!******\n");
				if(wantToExit)
				{
					// That's our chance! :)
					printf("A pid stopped while we wanted to quit. Trying to detach now...\n");
					detachProcess(pidReceived);
					processes.erase(pidReceived);
					// If no more traced processes, then exit
					if(processes.empty())
					{
						// Got a better idea to break out of TWO while loops at once?
						goto noMoreProcesses;
					}
				}
				else
					break;
			} else
				break;
			
			// Wait for another event
			//printf("Before wait2\n");
			pidReceived = wait(&status);
			//printf("After wait2\n");
		}
		
		//temporary:
        // I don't even remember why I wrote that here ;-)
		if(pidReceived == -1 && errno == EINTR)
		{
			if(wantToExit)
            {
				printf("Got and error and want to exit. Things may become unstable now...\n");
				tryDetachFromProcesses();
            }

			//if no more pids to trace:
			if(processes.empty())
				break;
			
			continue;
		}
		
		processes_t::iterator it = processes.find(pidReceived);
		if(it == processes.end())
			// On purpose. This may be a bug that should not get unnoticed!
			pexit("Unexpected pid %d received by wait call\n", pidReceived);
		
		processInfo *pi = it->second;
		struct user_regs_struct regs;
		// TODO: check retval
		ptrace((__ptrace_request)PTRACE_GETREGS, pi->pid, 0, &regs);
		
		int saveRegs = 0;
		processSyscall(pi, &regs, &saveRegs);
		if(saveRegs)
		{
			// TODO: check retval
			ptrace((__ptrace_request)PTRACE_SETREGS, pi->pid, 0, &regs);
		}
		
		//if(inputBuffer.size() == 0)
		//	wantToExit = 1;
		
		
		if(wantToExit && pi->inSyscall == 0 && pi->fakingSyscall != -1)
		{
			detachProcess(pi->pid);
			processes.erase(pi->pid);
		}
		
		//if no more pids to trace:
		if(processes.empty())
			goto noMoreProcesses; // Use goto to be consistent with previous calls
		
		// We are interested only in syscalls
		if(ptrace(PTRACE_SYSCALL, pi->pid, NULL, NULL) == -1)
			perrorexit("PTRACE_SYSCALL");
	}
	// Yes, dear purists, that's a label. Kill me!
	noMoreProcesses:
	
	uninitTerminal();
	
	return 0;
}

