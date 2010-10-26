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

void ex_program(int sig);

#include "sshijack.h"

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
	//Check retval + errno!
	unsigned long origVal = getValue(addr, tracepid);
	unsigned char *p = (unsigned char *)&origVal;
	*p = value;
	writeLong(addr, origVal, tracepid);
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
		inSyscall = -2;
	}

	pid_t pid;
	int inSyscall;
};

typedef map<pid_t, processInfo*> processes_t;
processes_t processes;


// ============= HOOKS =============
void readHook(pid_t pid, user_regs_struct &regs)
{
	//ssize_t read(int fd, void *buf, size_t count);
	//eax read(ebx fd, ecx *buf, edx count);
	int len = inputBuffer.size();
	if(regs.ARG3 < len)
		len = regs.ARG3;
	
	for(int i = 0; i < len; i++)
	{
		char c = inputBuffer.get();
		writeChar(regs.ARG2 + i, c, pid);
	}
	regs.RAX = len;
}

int canExit;

// ======== END OF HOOKS ===========

void processSyscall(processInfo *pi, user_regs_struct *regs, int *saveRegs)
{
	printf("__RAX: %ld (orig: %ld)\n", regs->RAX, regs->ORIG_RAX);

	if(inputBuffer.size() && (regs->ORIG_RAX == SYS_read || regs->ORIG_RAX == -1))
	{
		printf("Syscall: 0x%lx\tArg1: 0x%lx\tArg2: 0x%lx\tArg3: 0x%lx\t", regs->ORIG_RAX, regs->ARG1, regs->ARG2, regs->ARG3);
		if(pi->inSyscall == -2)
		{//TODO: check whether fd == 0 (input)
			// First ptrace trap. We are about to run a syscall.
			// Remember it and change it to a nonexisting one
			// Then wait for ptrace to stop execution again after
			// running it.
			pi->inSyscall = regs->ORIG_RAX;

			// This syscall can't exist :)
			regs->ORIG_RAX = -1;
			regs->RAX = -1;
			
			*saveRegs = 1;
		}
		else
		{
			// Second ptrace trap. We just finished running our
			// nonexisting syscall. Now is the moment to inject the
			// "correct" return values, etc...
			switch(pi->inSyscall)
			{
			case SYS_read: readHook(pi->pid, *regs); break;
				
			}

			*saveRegs = 1;
			pi->inSyscall = -2;
		}
	
	}
}

int main(int argc, char *argv[])
{
	(void) signal(SIGINT, ex_program);

	inputBuffer.add("To jest test\n");
	/*int*/ canExit = 0;
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
	if(WIFEXITED(status)){
		printf("Process exited\n");
		return 0;
	}
	
	// We are interested only in syscalls
	if(ptrace(PTRACE_SYSCALL, firstPid, NULL, NULL) == -1)
		perrorexit("PTRACE_SYSCALL");
	
	while(1)
	{
		int pidReceived = wait(&status);
		if(WIFEXITED(status)){
			printf("Process exited\n");
			//TODO: if no more process traced, then exit
			return 0;
		}
		
		processes_t::iterator it = processes.find(pidReceived);
		if(it == processes.end())
			pexit("Unexpected pid %d received by wait call\n", pidReceived);
		
		processInfo *pi = it->second;
		struct user_regs_struct regs;
		// TODO: check retval
		ptrace((__ptrace_request)PTRACE_GETREGS, it->second->pid, 0, &regs);
		
		int saveRegs = 0;
		processSyscall(pi, &regs, &saveRegs);
		if(saveRegs)
		{
			// TODO: check retval
			ptrace((__ptrace_request)PTRACE_SETREGS, it->second->pid, 0, &regs);
		}
		
		//if(inputBuffer.size() == 0)
		//	canExit = 1;
		
		if(canExit)
			break;
		
		// We are interested only in syscalls
		if(ptrace(PTRACE_SYSCALL, it->second->pid, NULL, NULL) == -1)
			perrorexit("PTRACE_SYSCALL");
	}
	// TODO: check retval
	ptrace(PTRACE_DETACH, firstPid, NULL, NULL);
	
	// TODO: Clean the processes map (delete pointers)
	
	return 0;
}

void ex_program(int sig)
{
    printf("Wake up call ... !!! - Caught signal: %d ... !!\n", sig);
    (void) signal(SIGINT, SIG_DFL);

    //ptrace(PTRACE_DETACH, pid, NULL, NULL);
    //exit(0);
    canExit = 1;
}