#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sched.h>
#include <stdarg.h>
#include "dhcp.h"

static volatile int global_exit = 0;

void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
}

static int elog(const char *format, ...)
{
	va_list va;
	int len;

	va_start(va, format);
	len = vfprintf(stderr, format, va);
	va_end(va);
	return len;
}

static int poll_init(struct pollfd *pfd, int port)
{
	int sockd, retv;
	char pstr[16];
	struct addrinfo hints, *res;

	retv = 0;
	snprintf(pstr, sizeof(pstr), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	while ((retv = getaddrinfo(NULL, pstr, &hints, &res)) == EAI_AGAIN)
		sched_yield();
	if (retv != 0) {
		elog("getaddrinfo failed: %s\n", gai_strerror(retv));
		goto exit_10;
	}

	sockd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockd == -1) {
		elog("Cannot create socket: %s\n", strerror(errno));
		retv = errno;
		goto exit_20;
	}
	pfd->fd = sockd;
	pfd->revents = 0;
	pfd->events = POLLIN;
	if (bind(sockd, res->ai_addr, res->ai_addrlen) == -1) {
		elog("Cannot bind socket: %s\n", strerror(errno));
		retv = errno;
		goto exit_30;
	}
	freeaddrinfo(res);
	return retv;

exit_30:
	close(pfd->fd);
exit_20:
	freeaddrinfo(res);
exit_10:
	return retv;
}

static int packet_process(int sockd, struct dhcp_data *dhdat, FILE *fout)
{
	int len, buflen = dhdat->maxlen;
	struct sockaddr_in srcaddr;
	socklen_t socklen;
	char *buf = (char *)&dhdat->pkt;
	time_t ctm;

	dhdat->len = 0;
	socklen = sizeof(srcaddr);
	memset(&srcaddr, 0, socklen);
	len = recvfrom(sockd, buf, buflen, 0, (struct sockaddr *)&srcaddr,
			&socklen);
	if (len <= 0) {
		elog("recvfrom failed: %s\n", strerror(errno));
		return len;
	}
	if (fout)
		fwrite(buf, 1, len, fout);
	dhdat->len = len;
	ctm = time(NULL);
	dhcp_echo_packet(dhdat, ctm);
	return len;
}

int main(int argc, char *argv[])
{
	int retv, sockd, sysret;
	struct pollfd fds[2];
	struct sigaction sigact;
	struct dhcp_data *dhdat;

	memset(fds, 0, sizeof(fds));
	retv = 0;

	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = sig_handler;
	if (sigaction(SIGTERM, &sigact, NULL) == -1 ||
			sigaction(SIGINT, &sigact, NULL) == -1)
		elog("Signal Handler Cannot be setup: %s\n",
				strerror(errno));

	dhdat = malloc(2048);
	if (!dhdat) {
		fprintf(stderr, "Out of Memory!\n");
		return 100;
	}
	dhdat->maxlen = 2048 - offsetof(struct dhcp_data, pkt);

	retv = poll_init(fds, 67);
	if (retv != 0)
		goto exit_10;
	retv = poll_init(fds+1, 4011);
	if (retv != 0)
		goto exit_20;


	global_exit = 0;
	do {
		sysret = poll(fds, 2, 1000);
		if (sysret == -1 && errno != EINTR) {
			elog("poll failed: %s\n", strerror(errno));
			retv = 600;
			goto exit_30;
		} else if ((sysret == -1 && errno == EINTR) || sysret == 0)
			continue;
		
		if (fds[0].revents) {
			sockd = fds[0].fd;
			fds[0].revents = 0;
			elog("Receive a DHCP message at port 67.");
			packet_process(sockd, dhdat, NULL);
		}
		if (fds[1].revents) {
			sockd = fds[1].fd;
			fds[1].revents = 0;
			elog("Receive a DHCP message at port 4011.");
			packet_process(sockd, dhdat, NULL);
		}

	} while (global_exit == 0);

exit_30:
	close(fds[1].fd);
exit_20:
	close(fds[0].fd);
exit_10:
	free(dhdat);
	return retv;
}
