#ifndef MISC_FUNCTIONS_DSCAO__
#define MISC_FUNCTIONS_DSCAO__

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#define unlikely(x)  __builtin_expect((x), 0)
#define likely(x)  __builtin_expect((x), 1)

static inline int lock_try(volatile int *lock)
{
	int retv = 1;

	__asm__ __volatile__(	"movl $1, %%eax\n\t"
				"xchgl %%eax, (%0)\n\t"
				:"=r"(lock), "="(retv)
				:"0"(lock)
			);
	return retv;
}

static int elog(const char *format, ...)
{
	va_list va;
	int len;
	time_t curtm;
	char *datime;

	curtm = time(NULL);
	datime = ctime(&curtm);
	datime[strlen(datime)-1] = 0;
	fprintf(stderr, "%s ", datime);
	va_start(va, format);
	len = vfprintf(stderr, format, va);
	va_end(va);
	return len;
}

static inline unsigned long
time_elapsed(const struct timespec *tm0, const struct timespec *tm1)
{
	long usec;
	time_t sec;

	usec = tm1->tv_nsec - tm0->tv_nsec;
	sec = tm1->tv_sec - tm0->tv_sec;
	if (usec < 0) {
		usec += 1000000000;
		sec--;
	}
	if (sec < 0)
		return 0;
	else
		return (sec * 1000) + usec / 1000000;
}

static inline int align8(int len)
{
	return (((len - 1) >> 3) + 1) << 3;
}

#endif /* MISC_FUNCTIONS_DSCAO__ */
