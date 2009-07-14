#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/user.h>
#include <asm/ptrace.h>

inline unsigned int getValue(unsigned int addr, int tracepid)
{
	unsigned int retval = ptrace(PTRACE_PEEKDATA,tracepid,addr,0);
	return retval;
		//if(retval == (unsigned int)-1 && errno != 0)
		//	throw "Exception!!!";
}

inline int writeLong(unsigned int addr, unsigned long value, int tracepid)
{
	int retval = ptrace(PTRACE_POKEDATA,tracepid,addr, value);
	/*	if(retval == -1)
		perror("ptrace write");
	else
		printf("Write OK!");*/
	return retval;
}

inline int writeChar(unsigned int addr, unsigned char value, int tracepid)
{
	//Check retval + errno!
	unsigned int origVal = getValue(addr, tracepid);
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

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("Usage: %s <pid>\n", argv[0]);
		return 1;
	}
	int pid = atoi(argv[1]);
	if(pid <= 1)
	{
		printf("Can't get correct pid from arguments\n");
		return 1;
	}
	
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
	{
		perror("PTRACE_ATTACH");
		return 1;
	}
	
	/*if(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) == -1)
	{
		perror("PTRACE_SETOPTIONS");
		return 1;
	}
	*/
	int status;
	wait(&status);
	if(WIFEXITED(status)){
		printf("Process exited\n");
		return 0;
	}
	
	int inSyscall = 0;
	
	while(1)
	{	
		// We are interested only in syscalls
		if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
		{
			perror("PTRACE_SYSCALL");
			return 1;
		}
		
		wait(&status);
		if(WIFEXITED(status)){
			printf("Process exited\n");
			return 0;
		}
		
		
		struct user_regs_struct regs;
		// TODO: check retval
		ptrace((__ptrace_request)PTRACE_GETREGS, pid, 0, &regs);
		/*printf("__EAX: %d (orig: %d)\n", regs.eax, regs.orig_eax);
		printf("Status: %x\n", status);*/
		if(regs.orig_eax == SYS_read || regs.orig_eax == -1/*wyjscie == 1*/)
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
			
			if(inSyscall == 0)
			{
				// First ptrace trap. We are about to run a syscall.
				// Remember it and change it to a nonexisting one
				// Then wait for ptrace to stop execution again after
				// running it.
				inSyscall = regs.orig_eax;
				
				// This syscall can't exist :)
				regs.orig_eax = -1;
				regs.eax = -1;
				
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
				case SYS_read:
					writeChar(regs.ecx, 'x', pid);
					//regs.orig_eax = -1;
					regs.eax = 1;
					break;
					
				}
				// TODO: check retval
				ptrace((__ptrace_request)PTRACE_SETREGS, pid, 0, &regs);
				inSyscall = 0;
			}
		
		}
		
	}
	// TODO: check retval
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	
	
	
	
	return 0;
}
