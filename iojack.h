#ifndef SSHIJACK_H
#define SSHIJACK_H

#if defined(__i386__) || defined(M_IX86) /* x86 arch */
//#warning x86 architecture detected
#warning *** x86 architecture is not regularly tested. Use at your own risk ***

#define ARG1 ebx
#define ARG2 ecx
#define ARG3 edx
#define ARG4 esi
#define ARG5 edi
#define ARG6 ebp

// This should not break anything
#define RAX eax
#define ORIG_RAX orig_eax

#elif defined(__amd64__) || defined(_M_X64) /* x86_64 arch */
//#warning x86_64 architecture detected

#define ARG1 rdi
#define ARG2 rsi
#define ARG3 rdx
#define ARG4 rcx
#define ARG5 r8
#define ARG6 r9
//Note to self: Kernel-kernel calls use rdi, rsi, rdx, r10, r8, r9

#define RAX rax
#define RIP rip
#define ORIG_RAX orig_rax

#elif defined(__arm__) && defined(__ARMEL__)
//#warning armel architecture detected

#define ARG1 ARM_r0
#define ARG2 ARM_r1
#define ARG3 ARM_r2
#define ARG4 ARM_r3
#define ARG5 ARM_r4
#define ARG6 ARM_r5

#define CALL_NBR ARM_r7

#define RAX ARM_r0
#define RIP ARM_ip
#define ORIG_RAX ARM_ORIG_r0

#define user_regs_struct pt_regs

#else
#error "Can't recognize processor architecture!"
#endif

#define pexit(x...)\
do \
{\
    printf(x);\
    exit(1);\
} while(0)

#define perrorexit(x)\
do \
{\
    perror(x);\
    exit(1);\
} while(0)


using namespace std;

#define foreach(iterable, iterator)                                   \
    for(__typeof__((iterable).begin()) iterator = (iterable).begin(); \
        iterator != (iterable).end();                                 \
        iterator++)

//#define DEBUG
#ifdef DEBUG
#define dprintf(x...) printf(x)
#else
#define dprintf(x...)
#endif

class settings_t
{
public:
    char sendANSI;

    settings_t(): sendANSI(0) {};
};
extern settings_t globalSettings;

#endif
