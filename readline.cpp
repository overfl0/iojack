#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main()
{
    char tmp[101];
    tmp[0] = 0; tmp[1] = 0; tmp[2] = 0; tmp[3] = 0; tmp[4] = 0; tmp[5] = 0; tmp[6] = 0; tmp[7] = 0; 
    printf("Pid: %d\n", getpid());
    
    printf("Reading 100 bytes to: 0x%lx\n", (long)tmp);
    int retval = read(0, tmp, 100);
    if(retval >= 0)
    {
	tmp[retval] = '\0';
	printf("Read %d bytes: %s\n", retval, tmp);
    } else {
	perror("read()");
    }

    return 0;
}