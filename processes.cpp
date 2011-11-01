#include <stdio.h>
#include <stdlib.h>      // exit()
#include <sys/ptrace.h>
#include <errno.h>

#include <sys/types.h> // opendir
#include <dirent.h>

#include "processes.h"
#include "iojack.h"

// Memory access
unsigned long processInfo::getValue(unsigned long addr)
{
	unsigned long retval = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
	if(retval == (unsigned long)-1 && errno != 0)
	{
		perror("ptrace read");
		printf("errno: %d\n", errno);
	}
	//throw "Exception!!!";
	return retval;
}

long processInfo::writeLong(unsigned long addr, unsigned long value)
{
	long retval = ptrace(PTRACE_POKEDATA, pid, addr, value);
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

int processInfo::writeChar(unsigned long addr, unsigned char value)
{
	//TODO: Check retval + errno!
	unsigned long origVal = getValue(addr);
	unsigned char *p = (unsigned char *)&origVal;
	*p = value;
	writeLong(addr, origVal);
	
	return -1; // In case I forget about the TODO
}

// FIXME: Needs testing
void processInfo::readMemcpy(void *dest, unsigned long remoteAddr, unsigned int n)
{
	unsigned long *udest = (unsigned long *)dest;
	dprintf("readMemcpy(dest=%lx, remoteAddr=%lx, uint n=%u\n", (unsigned long)dest, remoteAddr, n);
	for(; n >= sizeof(unsigned long); n -= sizeof(unsigned long))
	{
		//dprintf("%u\n", n);
		unsigned long retval = ptrace(PTRACE_PEEKDATA, pid, remoteAddr, 0);
		if(retval == (unsigned long)-1 && errno != 0)
		{
			perror("readMemcpy - ptrace read");
			return;
		}
		
		*udest++ = retval;
		remoteAddr += sizeof(unsigned long);
	}
	
	if(n > 0)
	{
		unsigned long retval = ptrace(PTRACE_PEEKDATA, pid, remoteAddr, 0);
		if(retval == (unsigned long)-1 && errno != 0)
		{
			perror("readMemcpy - ptrace read2");
			return;
		}
		
		char *c = (char *)&retval;
		for(unsigned int i = 0; i < n; i++)
		{
			//dprintf("%d\n", i);
			((char *)udest)[i] = c[i];
		}
	}
	
}

// FIXME: Needs testing
void processInfo::writeMemcpy(unsigned long remoteAddr, void *src, unsigned int n)
{
	unsigned long *usrc = (unsigned long *)src;
	dprintf("writeMemcpy(remoteAddr=%lx, src=%lx, uint n=%u\n", remoteAddr, (unsigned long)src, n);
	
	for(; n >= sizeof(unsigned long); n -= sizeof(unsigned long))
	{
		long retval = ptrace(PTRACE_POKEDATA, pid, remoteAddr, *usrc);
		if(retval == -1)
		{
			perror("writeMemcpy - ptrace write 1");
			return;
		}
		
		usrc++;
		remoteAddr += sizeof(unsigned long);
	}
	
	if(n > 0)
	{
		// Read the whole ulong into memory
		unsigned long remoteData = ptrace(PTRACE_PEEKDATA, pid, remoteAddr, 0);
		if(remoteData == (unsigned long)-1 && errno != 0)
		{
			perror("writeMemcpy - ptrace read");
			return;
		}
		
		// Modify only the requested bits
		char *c = (char *)&remoteData;
		for(unsigned int i = 0; i < n; i++)
		{
			//dprintf("%d\n", i);
			c[i] = ((char *)usrc)[i];
		}
		
		// Write it back
		long retval = ptrace(PTRACE_POKEDATA, pid, remoteAddr, remoteData);
		if(retval == -1)
		{
			perror("writeMemcpy - ptrace write 2");
			return;
		}
	}
	
}

char *processInfo::readStrncpy(char *dest, unsigned long remoteAddr, unsigned int n)
{
	unsigned int i = 0;
	while(i < n)
	{
		//printf("Reading at %lx...\n", remoteAddr + i);
		unsigned long retval = ptrace(PTRACE_PEEKDATA, pid, remoteAddr + i, 0);
		if(retval == (unsigned long)-1 && errno != 0)
		{
			perror("readMemcpy - ptrace read");
			goto end; //FIXME: throw an exception or sumtin'
		}

		for(unsigned int j = 0; j < sizeof(unsigned long); j++, i++)
		{
			if(i >= n)
				goto end;

			*dest = ((char *)&retval)[j];
			if(*dest++ == '\0')
				goto end;
		}
	}

	end:
	for(;i < n; i++)
		*dest++ = '\0';

	return dest;
}

// Remaining methods

void processInfo::closeFileDescriptor(unsigned int fd)
{
	if(isStdin(fd))
		stdin.erase(fd);

	if(isStdout(fd))
		stdout.erase(fd);

	if(isStderr(fd))
		stderr.erase(fd);
}

void processInfo::duplicateFileDescriptor(unsigned int oldfd, unsigned int newfd)
{
	//printf("[%d] Duplicating descriptor: %u -> %u\n", pid, oldfd, newfd);
	if(isStdin(oldfd))
		stdin.insert(newfd);

	if(isStdout(oldfd))
		stdout.insert(newfd);

	if(isStderr(oldfd))
		stderr.insert(newfd);
}

static void printPtraceError(int error)
{
	switch(error)
	{
		case EBUSY: printf("EBUSY\n"); break;
		case EFAULT: printf("EFAULT\n"); break;
		case EIO: printf("EIO\n"); break;
		case EINVAL: printf("EINVAL\n"); break;
		case EPERM: printf("EPERM\n"); break;
		case ESRCH: printf("ESRCH\n"); break;
		default: printf("Reason: Other\n");
	}
}

void processInfo::detachProcess()
{
	printf("Detaching %d... ", pid);
	int retval = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if(retval == -1)
	{
		printf("Failed! ");
		printPtraceError(errno);
		perror("Detach failed");
	}
	else
	{
		printf("OK!\n");
	}
}

void processInfo::stopAtSyscall(int signal)
{
	if(ptrace(PTRACE_SYSCALL, pid, NULL, signal) == -1)
	{
		printPtraceError(errno);
		perrorexit("PTRACE_SYSCALL");
	}
}

void processInfo::guessFds()
{
	// TODO: perform error checking!
	char path[100];
	snprintf(path, 100, "/proc/%d/fd/", pid);

	DIR *dp;
	struct dirent *ep;
	if((dp = opendir(path)) != NULL)
	{
		while((ep = readdir(dp)))
		{
			//printf("[%d] %s (inode: %ld)\n", pid, ep->d_name, (long)ep->d_ino);
			if(ep->d_type == DT_LNK)
			{
				char fdpath[1025];
				snprintf(fdpath, 1025, "%s/%s", path, ep->d_name);

				//struct stat retstat, retlstat;
				//stat(fdpath, &retstat);
				//lstat(fdpath, &retlstat);
				//printf("st_dev:\t%d\t%d\n", retstat.st_dev, retlstat.st_dev);
				//printf("st_ino:\t%d\t%d\n", (int)retstat.st_ino, (int)retlstat.st_ino);
				//printf("st_rdev:\t%d\t%d\n", (int)retstat.st_rdev, (int)retlstat.st_rdev);

				char linkName[101];
				int retval = readlink(fdpath, linkName, 100);
				linkName[100] = '\0';
				if(retval >= 0)
				{
					linkName[retval] = '\0';
					//printf("[%d] -> %s\n", pid, linkName);
					if(!strncmp(linkName, "/dev/pts/", strlen("/dev/pts/"))
					|| !strncmp(linkName, "/dev/tty",  strlen("/dev/tty")))
					{
						//printf("[%d] This fd points to stdin/out/err\n", pid);
						int fd = atoi(ep->d_name);
						printf("[%d] Adding fd %d to watched streams\n", pid, fd);

						// Add this fd to all the streams. This should do the trick
						// until we find a more reliable way find which fd is which stream
						stdin.insert(fd);
						stdout.insert(fd);
						stderr.insert(fd);
					}

				} else {
					printf("[%d] Readlink on %s failed!\n", pid, fdpath);
				}

			}
		}

		closedir(dp);
	}
	else
		perror ("Couldn't open the /proc/... directory");
}
