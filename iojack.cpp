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

#include "iojack.h"
#include "terminal.h"
#include "syscallToStr.h"
#include "buffer.h"
#include "processes.h"
#include "syscalls.h"

void displayUsage(char *programName)
{
    printf("Usage: %s [-ha] <pid>\n", programName);
    printf("\tOptions:\n"
           "\t\t-a\tUse ANSI cursor sequences right after connecting\n");
}

settings_t globalSettings;
static const char *optString = "had";

int getArgs(int argc, char **argv)
{
    int opt;
    while((opt = getopt(argc, argv, optString)) != -1)
    {
        switch(opt)
        {
            /*case 'p':
                globalArgs.langCode = optarg;
                break;
            */
            case 'a':
                globalSettings.sendANSI = 1;
                break;

            case 'd':
                globalSettings.hideOutput = 1;
                break;

            case 'h':
                displayUsage(argv[0]);
                exit(0);

            case '?':
                displayUsage(argv[0]);
                exit(1);
        }
    }

    if(argc <= optind)
    {
        displayUsage(argv[0]);
        exit(1);
    }

    int firstPid = atoi(argv[optind]);
    if(firstPid <= 1)
        pexit("Can't get correct pid from arguments\n");

    return firstPid;
}

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

extern buffer inputBuffer;

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

void tmpDump(processInfo *pi, user_regs_struct *regs)
{
    unsigned long arr[2];
    arr[0] = pi->getValue(regs->rip - sizeof(long));
    arr[1] = pi->getValue(regs->rip);

    printf("%lX: ", regs->rip - sizeof(long));
    for(unsigned int i = 1; i <= sizeof(long) * 2; i++)
    {
        printf("\\x%02X", ((unsigned char *)arr)[i-1]);
        if(i % 2 == 0) printf(" ");
    }
    printf("\n");
}

void processSyscall(processInfo *pi, user_regs_struct *regs, int *saveRegs)
{
    // regs->ORIG_RAX - Syscall number
    //printf("__RAX: %ld (orig: %ld)\n", regs->RAX, regs->ORIG_RAX);
    // We're either in a syscall or not
    if(!pi->inSyscall)
    {
        // I read somewhere that rax should == -38 now but I should confirm that
        // Tip: everything seems to suggest that it's the value of -ENOSYS
        // ("this system call doesn't exist")
        dprintf("[%d] Entering syscall: %s (%ld), rax = %ld\n",
                pi->pid, syscallToStr(regs->ORIG_RAX), regs->ORIG_RAX, regs->RAX);
        //dprintf("RIP: %lx\n", regs->rip);
        //tmpDump(pi, regs);
        pi->orig_regs = *regs; // Backup everything
        hookPtr fun = getPreHook(regs->ORIG_RAX);
        if(fun)
        {
            // Run a hooked function
            int fakeSyscall = 0;
            fun(pi, *regs, *saveRegs, fakeSyscall);

            if(fakeSyscall)
            {
                pi->fakingSyscall = regs->ORIG_RAX;

                // This syscall can't exist :)
                regs->ORIG_RAX = (unsigned int)-1;
                regs->RAX = -1;

                *saveRegs = 1;
            }
        }

        pi->inSyscall = 1;
    }
    else // Exiting a syscall
    {
        dprintf("[%d] Exiting syscall:  %s (%ld)   with code %ld\n", pi->pid, syscallToStr(regs->ORIG_RAX), regs->ORIG_RAX, regs->RAX);
        //dprintf("RIP: %lx\n", regs->rip);

        int unused;
        if(pi->fakingSyscall != -1)
        {
            if(regs->ORIG_RAX != (unsigned int)-1)
                printf("[%d] OMG! :O, regs->ORIG_RAX == %ld\n", pi->pid, regs->ORIG_RAX);

            // Second ptrace trap. We just finished running our
            // nonexisting syscall. Now is the moment to inject the
            // "correct" return values, etc...
            hookPtr fun = getFakedHook(pi->fakingSyscall);
            if(fun)
                fun(pi, *regs, *saveRegs, unused);
            else
            {
                // Should not happen!
                printf("[%d] Can't find function handling fake %s! (%d).\n", pi->pid, syscallToStr(pi->fakingSyscall), pi->fakingSyscall);
                exit(1);
            }

            regs->ORIG_RAX = pi->fakingSyscall;
            pi->fakingSyscall = -1;
        }

        hookPtr postFun = getPostHook(pi->orig_regs.ORIG_RAX);
        if(postFun)
            postFun(pi, *regs, *saveRegs, unused);

        pi->inSyscall = 0;
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
    int firstPid = getArgs(argc, argv);

    setSignalHandlers();
    initSyscallHooks();

    printf("Attaching to pid: %d\n", firstPid);
    if(ptrace(PTRACE_ATTACH, firstPid, NULL, NULL) == -1)
    {
        if(errno == EPERM)
        {
            pexit("Could not attach to process due to lack of permissions\n"
                  "If you're on ubuntu, you may try the following as root:\n"
                  "echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\n");
        }
        else
            perrorexit("PTRACE_ATTACH");
    }

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
    if(retval)
        perrorexit("Reading input thread");

    processes[firstPid] = new processInfo(firstPid);
    processes[firstPid]->guessFds();

    // We are interested only in syscalls
    processes[firstPid]->stopAtSyscall();

    unsigned char applicationSequences[] = {0x1b, 0x5b, 0x3f, 0x31, 0x68};
    if(!globalSettings.sendANSI)
        printf("%s", applicationSequences);

    //=========================================================================
    while(!processes.empty())
    {
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
            //pexit("Unexpected pid %d received by wait call\n", pidReceived);

            // Too bad that this may happen on clone() and fork() calls :(
            // Ugly workaround
            // FIXME TODO FIXME TODO This is WAY too ugly to be kept unchanged
            processes[pidReceived] = new processInfo(pidReceived);
            it = processes.find(pidReceived);
            it->second->sigstopNewChild = 1;
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
                pi->detachProcess();
                processes.erase(pidReceived);
                continue;
            }

            if(pi->sigstopToRestartSyscall)
            {
                dprintf("Restarting tracing of pid %d\n", pi->pid);
                pi->sigstopToRestartSyscall = 0;

                pi->stopAtSyscall();
                continue;
            }

            if(pi->sigstopNewChild)
            {
                pi->sigstopNewChild = 0;
                dprintf("[%d] The new child has stopped.\n", pi->pid);

                if(ptrace(PTRACE_SETOPTIONS, pi->pid, NULL,
                   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC
                   /*| PTRACE_O_TRACESYSGOOD ? */) == -1)
                    perrorexit("PTRACE_SETOPTIONS");

                pi->stopAtSyscall();
                continue;
            }
        }

        // If it's not our signal, forward it to the program and continue the loop
        if(WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP)
        {
            dprintf("Pid %d stopped with signal: %d\n", pi->pid, WSTOPSIG(status));

            pi->stopAtSyscall(WSTOPSIG(status));
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
            printf("[%d] A new process forked/vforked/cloned: %lu\n", pi->pid, newPid);

            processInfo *newPi = new processInfo(newPid);
            newPi->sigstopNewChild = 1;
            // Copy file descriptors from the parent
            //FIXME: Race condition with pi->pid calling close() before we get here
            newPi->stdin = pi->stdin;
            newPi->stdout = pi->stdout;
            newPi->stderr = pi->stderr;
            processes[newPid] = newPi;

            pi->stopAtSyscall();

            continue;
        }
        if(event == PTRACE_EVENT_EXEC)
        {
            // TODO: We probably need to close some fds here (FD_CLOEXEC)
            dprintf("###################################################################\n");
            dprintf("Wykryto exec!\n");
            dprintf("###################################################################\n");
            pi->stopAtSyscall();

            continue;
        }

        //=Handle syscalls and registers=======================================
        struct user_regs_struct regs;
        if(ptrace((__ptrace_request)PTRACE_GETREGS, pi->pid, 0, &regs) == -1)
            perrorexit("PTRACE_GETREGS");

        int saveRegs = 0;
        processSyscall(pi, &regs, &saveRegs);
        if(saveRegs)
        {
            if(ptrace((__ptrace_request)PTRACE_SETREGS, pi->pid, 0, &regs) == -1)
                perrorexit("PTRACE_SETREGS");
        }
        //=====================================================================

        if(wantToExit && pi->inSyscall == 0 && pi->fakingSyscall != -1)
        {
            pi->detachProcess();
            processes.erase(pi->pid);
            continue;
        }

        // We are interested only in syscalls
        pi->stopAtSyscall();
    }

    wantToExit = 1;
    pthread_join(pollStdinThread, NULL);

    return 0;
}

