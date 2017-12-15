#ifndef MISC_FUNCTIONS_DSCAO__
#define MISC_FUNCTIONS_DSCAO__

#include <stdio.h>
#include <stdarg.h>
#include <execinfo.h>
#include <time.h>
#include <sys/time.h>

#undef unlikely
#undef likely
#define unlikely(x)  __builtin_expect((x), 0)
#define likely(x)  __builtin_expect((x), 1)

#define STACK_DEPTH   32
static void *trace_buffer[STACK_DEPTH];
static inline void dump_stack(void)
{
        int depth;

        depth = backtrace(trace_buffer, STACK_DEPTH);
        backtrace_symbols_fd(trace_buffer, depth, fileno(stderr));
}

static inline int errlog(const char *fmt, ...)
{
	va_list ap;
	int retv;

	va_start(ap, fmt);
	retv = vfprintf(stderr, fmt, ap);
	va_end(ap);

	return retv;
}

static inline int outlog(FILE *outf, const char *fmt, ...)
{
	va_list ap;
	int retv;

	va_start(ap, fmt);
	retv = vfprintf(outf, fmt, ap);
	va_end(ap);

	return retv;
}

static inline long time_interval(const struct timespec *a,
                                          const struct timespec *b)
{
        long sec;
        long msec, nsec;

        msec = 0;
        sec = (int)(b->tv_sec - a->tv_sec);
        nsec = b->tv_nsec - a->tv_nsec;
        if (nsec < 0) {
                sec--;
                nsec += 1000000000l;
        }
        msec = sec * 1000000 + nsec / 1000;
        return msec;
}

#define KB	1024
#define MB      1048576

static inline void random_seed(unsigned short xsubi[3])
{
	FILE *inf;
        inf = fopen("/dev/urandom", "rb");
        fread(xsubi, sizeof(unsigned short), 3, inf);
        fclose(inf);
}
static inline void get_datetime(char *buf, int len)
{
	char date[48];
	struct timeval curtime;
	struct tm ltime;

        gettimeofday(&curtime, NULL);
        localtime_r(&curtime.tv_sec, &ltime);
        strftime(date, sizeof(date), "%F %T", &ltime);
	snprintf(buf, len, "%s.%6.6d", date, (int)curtime.tv_usec);
}
#endif /* MISC_FUNCTIONS_DSCAO__ */
