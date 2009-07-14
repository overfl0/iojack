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
	if(retval == -1)
		perror("ptrace write");
	else
		printf("Write OK!");
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
	
	
	//long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
	
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
	
	int wyjscie = 0;
	
	while(1)
	{	
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
		ptrace((__ptrace_request)PTRACE_GETREGS, pid, 0, &regs);
		printf("__EAX: %d (orig: %d)\n", regs.eax, regs.orig_eax);
		printf("Status: %x\n", status);
		if(regs.orig_eax == SYS_read || regs.orig_eax == -1/*wyjscie == 1*/)
		{
			
			
			int fd, buf, count;
			int tbl[100];
			printf("EIP: %x\tESP: %x\tEBP: %x\tEAX: %x\tEBX: %x\tECX: %x\tEDX: %x\n", regs.eip, regs.esp, regs.ebp, regs.eax, regs.ebx, regs.ecx, regs.edx);
			printf("EAX_orig: %x\n", regs.orig_eax);
			for(int i = 0; i < 10; i++)
			{
				tbl[i] = getValue(regs.eip + 4*i, pid);
				printf("%08x ", tbl[i]);
			}
			printf("\n");
			
			if(wyjscie == 0)
			{
				printf("======== Run 1 ========\n");
				regs.orig_eax = -1;
				regs.eax = -1;
				
				ptrace((__ptrace_request)PTRACE_SETREGS, pid, 0, &regs);
				wyjscie = 1;
			}
			else if(wyjscie == 1)
			{
				printf("======== Run 2 ========\n");
				writeChar(regs.ecx, 'x', pid);
				//regs.orig_eax = -1;
				regs.eax = 1;
				
				ptrace((__ptrace_request)PTRACE_SETREGS, pid, 0, &regs);
				wyjscie = 0;
			}
			else printf("*********  Blad w ifach!!!  *********\n");
			
			
			
			printf("End\n");	
		}
		
	}
	
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	
	
	
	
	return 0;
}
