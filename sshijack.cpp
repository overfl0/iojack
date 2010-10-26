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
	regs.rax = len;
}

int canExit;

// ======== END OF HOOKS ===========
int main(int argc, char *argv[])
{
	(void) signal(SIGINT, ex_program);

	inputBuffer.add("To jest test\n");
	/*int*/ canExit = 0;
	if(argc < 2)
		pexit("Usage: %s <pid>\n", argv[0]);

	int pid = atoi(argv[1]);
	if(pid <= 1)
		pexit("Can't get correct pid from arguments\n");

	printf("Attaching to pid: %d\n", pid);
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
		perrorexit("PTRACE_ATTACH");

	/*if(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) == -1)
		perrorexit("PTRACE_SETOPTIONS"); */

	int status;
	pid = wait(&status);
	if(WIFEXITED(status)){
		printf("Process exited\n");
		return 0;
	}
	
	int inSyscall = -2;
	while(1)
	{	
		// We are interested only in syscalls
		if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
			perrorexit("PTRACE_SYSCALL");
		
		wait(&status);
		if(WIFEXITED(status)){
			printf("Process exited\n");
			return 0;
		}
		
		
		struct user_regs_struct regs;
		// TODO: check retval
		ptrace((__ptrace_request)PTRACE_GETREGS, pid, 0, &regs);
		printf("__RAX: %ld (orig: %ld)\n", regs.rax, regs.orig_rax);
		/*printf("Status: %x\n", status);*/
		if(inputBuffer.size() && (regs.orig_rax == SYS_read || regs.orig_rax == -1))
		{
			
			
			/*
			int tbl[100];
			printf("EIP: %x\tESP: %x\tEBP: %x\tEAX: %x\tEBX: %x\tECX: %x\tEDX: %x\n", regs.eip, regs.esp, regs.ebp, regs.eax, regs.ebx, regs.ecx, regs.edx);
			printf("EAX_orig: %x\n", regs.orig_eax);
			for(int i = 0; i < 10; i++)
			{
				tbl[i] = getValue(regs.eip + 4*i, pid);
				printf("%08x ", tbl[i]);
			}
			printf("\n");
			*/
			printf("Syscall: 0x%lx\tArg1: 0x%lx\tArg2: 0x%lx\tArg3: 0x%lx\t", regs.orig_rax, regs.ARG1, regs.ARG2, regs.ARG3);
			if(inSyscall == -2)
			{//TODO: check whether fd == 0 (input)
				// First ptrace trap. We are about to run a syscall.
				// Remember it and change it to a nonexisting one
				// Then wait for ptrace to stop execution again after
				// running it.
				inSyscall = regs.orig_rax;
				//printf("RIP: %lx\tRSP: %lx\tRBP: %lx\tRAX: %lx\tRBX: %lx\tRCX: %lx\tRDX: %lx\n", regs.rip, regs.rsp, regs.rbp, regs.rax, regs.rbx, regs.rcx, regs.rdx);
				//printf("RDI: %lx\tRSI: %lx\tRDX: %lx\tRCX: %lx\n", regs.rdi, regs.rsi, regs.rdx, regs.rcx);
				// This syscall can't exist :)
				regs.orig_rax = -1;
				regs.rax = -1;
				
				// TODO: check retval
				ptrace((__ptrace_request)PTRACE_SETREGS, pid, 0, &regs);
			}
			else
			{
				// Second ptrace trap. We just finished running our
				// nonexisting syscall. Now is the moment to inject the
				// "correct" return values, etc...
				switch(inSyscall)
				{
				case SYS_read: readHook(pid, regs); break;
					
				}
				// TODO: check retval
				ptrace((__ptrace_request)PTRACE_SETREGS, pid, 0, &regs);
				inSyscall = -2;
			}
		
		}
		
		//if(inputBuffer.size() == 0)
		//	canExit = 1;
		
		if(canExit)
			break;
	}
	// TODO: check retval
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	
	
	
	
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