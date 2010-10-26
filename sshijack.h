#if defined(__i386__) || defined(M_IX86) /* x86 arch */
//#warning x86 architecture detected

#define ARG1 ebx
#define ARG2 ecx
#define ARG3 edx
#define ARG4 esi
#define ARG5 edi
#define ARG6 ebp

#elif defined(__amd64__) || defined(_M_X64) /* x86_64 arch */
//#warning x86_64 architecture detected

#define ARG1 rdi
#define ARG2 rsi
#define ARG3 rdx
#define ARG4 rcx
#define ARG5 r8
#define ARG6 r9
//Note to self: Kernel-kernel calls use rdi, rsi, rdx, r10, r8, r9

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
