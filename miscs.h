#ifndef MISC_FUNCTIONS_DSCAO__
#define MISC_FUNCTIONS_DSCAO__

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#define unlikely(x)  __builtin_expect((x), 0)
#define likely(x)  __builtin_expect((x), 1)

static inline int lock_try(volatile int *lock)
{
	int retv;

	__asm__ __volatile__(	"movl $1, %%eax\n\t"
				"xchgl %%eax, (%0)\n\t"
				:"=r"(lock), "=a"(retv)
				:"0"(lock)
			);
	return retv;
}

void dump_stack(void);

#define ENOMEM	12
#define ENOSPACE	112

enum LOGLVL {LERR = 5, LWARN = 4, LINFO = 1, LABORT = 9};

static inline unsigned int swap32(unsigned int x)
{
	union {
		unsigned int v;
		unsigned char b[4];
	} u;
	u.v = x;
	return (u.b[0] << 24)|(u.b[1] << 16)|(u.b[2] << 8)|u.b[3];
}

int miscs_init(const char *logfile);
void miscs_exit(void);
void logmsg(int level, const char *fmt, ...);
int llog(const char *fmt, ...);

void *check_pointer(void *ptr);

unsigned long time_elapsed(const struct timespec *tm0,
		const struct timespec *tm1);

static inline int align8(int len)
{
	return (((len - 1) >> 3) + 1) << 3;
}

#endif /* MISC_FUNCTIONS_DSCAO__ */
