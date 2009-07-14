#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/user.h>
#include <asm/ptrace.h>
#include <queue>

using namespace std;

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


// ============= HOOKS =============
void readHook(int pid, user_regs_struct &regs)
{
	//ssize_t read(int fd, void *buf, size_t count);
	//eax read(ebx fd, ecx *buf, edx count);
	
	int len = inputBuffer.size();
	if(regs.edx < len)
		len = regs.edx;
	
	for(int i = 0; i < len; i++)
		writeChar(regs.ecx + i, inputBuffer.get(), pid);
	regs.eax = len;
}


// ======== END OF HOOKS ===========
int main(int argc, char *argv[])
{
	inputBuffer.add("To jest test");
	int canExit = 0;
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
		if(inputBuffer.size() && (regs.orig_eax == SYS_read || regs.orig_eax == -1))
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
			{//TODO: check whether fd == 0 (input)
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
				case SYS_read: readHook(pid, regs); break;
					
				}
				// TODO: check retval
				ptrace((__ptrace_request)PTRACE_SETREGS, pid, 0, &regs);
				inSyscall = 0;
			}
		
		}
		
		if(inputBuffer.size() == 0)
			canExit = 1;
		
		if(canExit)
			break;
	}
	// TODO: check retval
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	
	
	
	
	return 0;
}
