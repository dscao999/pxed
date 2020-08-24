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
#include <assert.h>
#include "miscs.h"
#include "dhcp.h"

static volatile int global_exit = 0;

void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
}

static int poll_init(struct pollfd *pfd, int port)
{
	int sockd, retv, broadcast, sysret;
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
		logmsg(LERR, "getaddrinfo failed: %s\n", gai_strerror(retv));
		goto exit_10;
	}

	sockd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockd == -1) {
		logmsg(LERR, "Cannot create socket: %s\n", strerror(errno));
		retv = errno;
		goto exit_20;
	}
	if (port == 67) {
		broadcast = 1;
		sysret = setsockopt(sockd, SOL_SOCKET, SO_BROADCAST,
				&broadcast, 4);
		if (sysret == -1) {
			logmsg(LERR, "Cannot enable socket to broadcast: %s",
					strerror(errno));
			retv = errno;
			goto exit_30;
		}
	}
	pfd->fd = sockd;
	pfd->revents = 0;
	pfd->events = POLLIN;
	if (bind(sockd, res->ai_addr, res->ai_addrlen) == -1) {
		logmsg(LERR, "Cannot bind socket: %s\n", strerror(errno));
		retv = errno;
		goto exit_30;
	}
	freeaddrinfo(res);
	return retv;

exit_30:
	close(sockd);
exit_20:
	freeaddrinfo(res);
exit_10:
	return retv;
}

static const unsigned char svrip[] = {192, 168, 1, 105};

static int pxe_offer(int sockd, const struct sockaddr_in *peer,
		struct dhcp_data *dhdat)
{
	struct dhcp_packet *dhcp;
	struct dhcp_option *opt;
	const struct dhcp_option *c_opt;
	int len = 0, maxlen = 1000;
	unsigned char uuid[17];
	int uid_code = DHCP_CUUID;
	
	dhcp = &dhdat->dhpkt;
	c_opt = dhcp_option_search(dhdat, DHCP_CUUID);
	if (!c_opt)
		c_opt = dhcp_option_search(dhdat, DHCP_CMUID);
	memset(uuid, 0, sizeof(uuid));
	if (unlikely(!c_opt))
		logmsg(LERR, "No UUID Info in DHCP PXE request.");
	else {
		assert(c_opt->len == 17);
		memcpy(uuid, c_opt->val, c_opt->len);
		uid_code = c_opt->code;
	}
	c_opt = dhcp_option_search(dhdat, DHCP_MAXLEN);
	if (unlikely(!c_opt))
		logmsg(LERR, "PXE DHCP discover has no max packet size.");
	else
		maxlen = (c_opt->val[0] << 8) | c_opt->val[1];

	dhcp->header.op = DHCP_REP;
	dhcp->header.secs = 0;
	memset(&dhcp->header.ciaddr, 0, 16);

	opt = dhcp->options;
	opt->code = DHCP_MSGTYPE;
	opt->len = 1;
	opt->val[0] = DHCP_OFFER;
	len += sizeof(struct dhcp_option) + opt->len;

	opt = dhcp_option_next(opt);
	opt->code = DHCP_SVRID;
	opt->len = 4;
	opt->val[0] = svrip[0];
	opt->val[1] = svrip[1];
	opt->val[2] = svrip[2];
	opt->val[3] = svrip[3];
	len += sizeof(struct dhcp_option) + opt->len;

	opt = dhcp_option_next(opt);
	opt->code = uid_code;
	opt->len = 17;
	memcpy(opt->val, uuid, opt->len);
	len += sizeof(struct dhcp_option) + opt->len;

	opt = dhcp_option_next(opt);
	opt->code = DHCP_CLASS;
	opt->len = 9;
	memcpy(opt->val, "PXEClient", 9);
	len += sizeof(struct dhcp_option) + opt->len;

	opt = dhcp_option_next(opt);
	opt->code = DHCP_MAXLEN;
	opt->len = 2;
	opt->val[0] = (maxlen >> 8) & 0x0ff;
	opt->val[1] = maxlen & 0x0ff;
	len += sizeof(struct dhcp_option) + opt->len;

	opt = dhcp_option_next(opt);
	opt->code = DHCP_END;
	len += 1;

	dhdat->len = sizeof(struct dhcp_head) + len;
	len = sendto(sockd, dhcp, dhdat->len, 0, (const struct sockaddr *)peer,
			sizeof(struct sockaddr_in));
	if (unlikely(len != dhdat->len))
		logmsg(LERR, "PXE Offer, sendto failed: %s", strerror(errno));
	return len;
}

static int packet_process(int sockd, struct dhcp_data *dhdat, FILE *fout,
		int verbose)
{
	int len, buflen = dhdat->maxlen;
	struct sockaddr_in srcaddr;
	socklen_t socklen;
	char *buf = (char *)&dhdat->dhpkt;

	dhdat->len = 0;
	socklen = sizeof(srcaddr);
	memset(&srcaddr, 0, socklen);
	len = recvfrom(sockd, buf, buflen, 0, (struct sockaddr *)&srcaddr,
			&socklen);
	if (len <= 0) {
		logmsg(LERR, "recvfrom failed: %s\n", strerror(errno));
		return len;
	}
	if (fout)
		fwrite(buf, 1, len, fout);
	dhdat->len = len;
	if (verbose)
		dhcp_echo_packet(dhdat);
	if (!dhcp_pxe(dhdat))
		return len;

	printf("Preparing a PXE offer...\n");
	len = pxe_offer(sockd, &srcaddr, dhdat);
	return len;
}

int main(int argc, char *argv[])
{
	int retv, sockd, sysret;
	struct pollfd fds[3];
	struct sigaction sigact;
	struct dhcp_data *dhdat;

	memset(fds, 0, sizeof(fds));
	retv = 0;

	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = sig_handler;
	if (sigaction(SIGTERM, &sigact, NULL) == -1 ||
			sigaction(SIGINT, &sigact, NULL) == -1)
		logmsg(LERR, "Signal Handler Cannot be setup: %s\n",
				strerror(errno));

	dhdat = malloc(2048);
	check_pointer(dhdat);
	dhdat->maxlen = 2048 - offsetof(struct dhcp_data, dhpkt);

	retv = poll_init(fds, 67);
	if (retv != 0)
		goto exit_10;
	retv = poll_init(fds+1, 68);
	if (retv != 0)
		goto exit_20;
	retv = poll_init(fds+2, 4011);
	if (retv != 0)
		goto exit_30;


	global_exit = 0;
	do {
		sysret = poll(fds, 3, 1000);
		if (sysret == -1 && errno != EINTR) {
			logmsg(LERR, "poll failed: %s\n", strerror(errno));
			retv = 600;
			goto exit_40;
		} else if ((sysret == -1 && errno == EINTR) || sysret == 0)
			continue;
		
		if (fds[0].revents) {
			sockd = fds[0].fd;
			logmsg(LINFO, "Receive a DHCP message at port 67.");
		}
		if (fds[1].revents) {
			sockd = fds[1].fd;
			logmsg(LINFO, "Receive a DHCP message at port 68.");
		}
		if (fds[2].revents) {
			sockd = fds[2].fd;
			logmsg(LINFO, "Receive a DHCP message at port 4011.");
		}
		packet_process(sockd, dhdat, NULL, 1);

		fds[0].revents = 0;
		fds[1].revents = 0;
		fds[2].revents = 0;
	} while (global_exit == 0);

exit_40:
	close(fds[2].fd);
exit_30:
	close(fds[1].fd);
exit_20:
	close(fds[0].fd);
exit_10:
	free(dhdat);
	return retv;
}
