#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>
#include <time.h>
#include <sched.h>
#include "miscs.h"

#define STACK_DEPTH	64

struct trace_buf {
	void *trace[STACK_DEPTH];
	volatile int lock;
};

static struct trace_buf tbuf = {.lock = 0};
static const char *nomem = "Out of Memory!\n";

void dump_stack(void)
{
	int depth, locked = 1;

	do {
		while (tbuf.lock != 0)
			sched_yield();
		locked = lock_try(&tbuf.lock);
	} while (locked != 0);

	depth = backtrace(tbuf.trace, STACK_DEPTH);
	backtrace_symbols_fd(tbuf.trace, depth, fileno(stderr));
	tbuf.lock = 0;
}

void logmsg(int level, const char *fmt, ...)
{
	va_list ap;

	switch(level) {
		case LINFO:
			fprintf(stderr, "Info: ");
			break;
		case LERR:
			fprintf(stderr, "Error: ");
			break;
		case LABORT:
			fprintf(stderr, "Aborting: ");
			break;
	};

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	if (unlikely(level == LABORT)) {
		dump_stack();
		abort();
	}
}

void *check_pointer(void *ptr)
{
	if (unlikely(!ptr))
		logmsg(LABORT, nomem);
	return ptr;
}

unsigned long time_elapsed(const struct timespec *tm0,
		const struct timespec *tm1)
{
	unsigned long tv_sec;
	long tv_nsec;

	tv_sec = tm1->tv_sec - tm0->tv_sec;
	tv_nsec = tm1->tv_nsec - tm0->tv_nsec;
	if (tv_nsec < 0) {
		tv_sec--;
		tv_nsec += 1000000000ul;
	}
	return tv_sec * 1000 + (tv_nsec / 1000000);
}
