#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sched.h>
#include <assert.h>
#include "miscs.h"
#include "dhcp.h"

static volatile int global_exit = 0;

#define PXE_DISC_SET	0x06

void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
}

struct g_param {
	const char *conf;
	const char *iface;
	int verbose;
};

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
static const char PXE_PROMPT1[] = "PXE Investigation 1";
static const char PXE_PROMPT[] = "PXE Research";

static int makeup_vendor_pxe(struct dhcp_option *opt, int lenrem)
{
	int vlen;
	struct dhcp_option *vopt;

	opt->code = DHCP_VENDOR;
	vopt = (struct dhcp_option *)opt->val;

	vlen = 0;
	vopt->code = PXE_DISCTL;
	vopt->len = 1;
	vopt->val[0] = PXE_DISC_SET;
	vlen += sizeof(struct dhcp_option) + vopt->len;

	vopt = dhcp_option_next(vopt);
	vopt->code = PXE_BOOTSVR;
	vopt->val[0] = 0x30;
	vopt->val[1] = 1;
	vopt->val[2] = 1;

	vopt->val[3] = 192;
	vopt->val[4] = 168;
	vopt->val[5] = 1;
	vopt->val[6] = 105;

	vopt->len = 7;
	vlen += sizeof(struct dhcp_option) + vopt->len;

	vopt = dhcp_option_next(vopt);
	vopt->code = PXE_BOOTMENU;
	vopt->val[0] = 0x30;
	vopt->val[1] = 1;
	vopt->val[2] = strlen(PXE_PROMPT1) + 1;
	strcpy((char *)(vopt->val+3), PXE_PROMPT1);
	vopt->len = vopt->val[2] + 3;
	vlen += sizeof(struct dhcp_option) + vopt->len;

	vopt = dhcp_option_next(vopt);
	vopt->code = PXE_BOOTPROMPT;
	vopt->val[0] = 50;
	strcpy((char *)(vopt->val+1), PXE_PROMPT);
	vopt->len = strlen(PXE_PROMPT) + 2;
	vlen += sizeof(struct dhcp_option) + vopt->len;

	vopt = dhcp_option_next(vopt);
	vopt->code = PXE_END;

	opt->len = vlen + 1;
	assert(opt->len + sizeof(struct dhcp_option) < lenrem);
	return sizeof(struct dhcp_option) + opt->len;
}

static int pxe_ack(int sockd, struct dhcp_data *dhdat,
		struct sockaddr_in *peer)
{
	logmsg(LINFO, "I will do a pxe ack.");
	dhdat->dhpkt.header.op = DHCP_REP;
	return 0;
}
static int pxe_offer(int sockd, struct dhcp_data *dhdat,
		struct sockaddr_in *peer)
{
	struct dhcp_packet *dhcp;
	struct dhcp_option *opt;
	const struct dhcp_option *c_opt;
	int optlen = 0, maxlen = 1024, lenrem, len;
	unsigned char uuid[17];
	
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
	}
	c_opt = dhcp_option_search(dhdat, DHCP_MAXLEN);
	if (unlikely(!c_opt))
		logmsg(LERR, "PXE DHCP discover has no max packet size.");
	else
		maxlen = (c_opt->val[0] << 8) | c_opt->val[1];

	dhcp->header.op = DHCP_REP;
	dhcp->header.secs = 0;
	memset(&dhcp->header.ciaddr, 0, 16);

	optlen = 0;
	opt = dhcp->options;
	opt->code = DHCP_MSGTYPE;
	opt->len = 1;
	opt->val[0] = DHCP_OFFER;
	optlen += sizeof(struct dhcp_option) + opt->len;

	opt = dhcp_option_next(opt);
	opt->code = DHCP_SVRID;
	opt->len = 4;
	opt->val[0] = svrip[0];
	opt->val[1] = svrip[1];
	opt->val[2] = svrip[2];
	opt->val[3] = svrip[3];
	optlen += sizeof(struct dhcp_option) + opt->len;

	opt = dhcp_option_next(opt);
	opt->code = DHCP_CMUID;
	opt->len = 17;
	memcpy(opt->val, uuid, opt->len);
	optlen += sizeof(struct dhcp_option) + opt->len;

	opt = dhcp_option_next(opt);
	opt->code = DHCP_CLASS;
	opt->len = 9;
	memcpy(opt->val, "PXEClient", 9);
	optlen += sizeof(struct dhcp_option) + opt->len;

	lenrem = maxlen - sizeof(struct dhcp_head) - optlen;
	opt = dhcp_option_next(opt);
	makeup_vendor_pxe(opt, lenrem);
	optlen += sizeof(struct dhcp_option) + opt->len;

	opt = dhcp_option_next(opt);
	opt->code = DHCP_END;
	optlen += 1;

	if (peer->sin_addr.s_addr == 0)
		inet_pton(AF_INET, "255.255.255.255", &peer->sin_addr);
	dhdat->len = sizeof(struct dhcp_head) + optlen;
	len = sendto(sockd, dhcp, dhdat->len, 0,
			(const struct sockaddr *)peer,
			sizeof(struct sockaddr_in));
	if (unlikely(len != dhdat->len))
		logmsg(LERR, "PXE Offer, sendto failed: %s", strerror(errno));
	return len;
}

static int packet_process(int sockd, struct dhcp_data *dhdat, int verbose)
{
	int len, buflen = dhdat->maxlen;
	struct sockaddr_in srcaddr;
	socklen_t socklen;
	char *buf = (char *)&dhdat->dhpkt;
	const struct dhcp_option *opt;

	dhdat->len = 0;
	socklen = sizeof(srcaddr);
	memset(&srcaddr, 0, socklen);
	len = recvfrom(sockd, buf, buflen, 0, (struct sockaddr *)&srcaddr,
			&socklen);
	if (len <= 0) {
		logmsg(LERR, "recvfrom failed: %s\n", strerror(errno));
		return len;
	}
	dhdat->len = len;
	if (!dhcp_pxe(dhdat))
		return len;
	if (verbose)
		dhcp_echo_packet(dhdat);

	opt = dhcp_option_search(dhdat, DHCP_MSGTYPE);
	if (!opt)
		logmsg(LERR, "No DHCP Message type specified.");
	else if (opt->val[0] == DHCP_DISCOVER) {
		len = pxe_offer(sockd, dhdat, &srcaddr);
		if (verbose)
			dhcp_echo_packet(dhdat);
	} else if (opt->val[0] == DHCP_REQUEST) {
		opt = dhcp_option_search(dhdat, DHCP_SVRID);
		if (opt && memcmp(opt->val+1, svrip, opt->len) == 0) {
			len = pxe_ack(sockd, dhdat, &srcaddr);
			if (verbose)
				dhcp_echo_packet(dhdat);
		}
	} else
		logmsg(LINFO, "Received a message type: %hhu ignored",
				opt->val[0]);
	return len;
}

static void gparam_init(int argc, char *argv[], struct g_param *gp)
{
	int fin = 0, opt;
	extern char *optarg;
	extern int opterr, optopt;

	gp->conf = "/etc/default/pxed.conf";
	gp->iface = NULL;
	gp->verbose = 0;
	do {
		opt = getopt(argc, argv, ":c:i:v");
		switch(opt) {
		case -1:
			fin = 1;
			break;
		case '?':
			logmsg(LERR, "Unknown option: %c", (char)optopt);
			break;
		case ':':
			logmsg(LERR, "Missing argument for %c", (char)optopt);
			break;
		case 'c':
			gp->conf = optarg;
			break;
		case 'i':
			gp->iface = optarg;
			break;
		case 'v':
			gp->verbose = 1;
			break;
		default:
			assert(0);
		}
	} while (fin == 0);
}

int main(int argc, char *argv[])
{
	int retv, sockd, sysret;
	struct pollfd fds[2];
	struct sigaction sigact;
	struct dhcp_data *dhdat;
	static struct g_param gp;

	gparam_init(argc, argv, &gp);

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
	retv = poll_init(fds+1, 4011);
	if (retv != 0)
		goto exit_20;


	global_exit = 0;
	do {
		sysret = poll(fds, sizeof(fds) / sizeof(struct pollfd), 1000);
		if (sysret == -1 && errno != EINTR) {
			logmsg(LERR, "poll failed: %s\n", strerror(errno));
			retv = 600;
			goto exit_30;
		} else if ((sysret == -1 && errno == EINTR) || sysret == 0)
			continue;
		
		if (fds[0].revents) {
			sockd = fds[0].fd;
			logmsg(LINFO, "Receive a DHCP message at port 67.");
		}
		if (fds[1].revents) {
			sockd = fds[1].fd;
			logmsg(LINFO, "Receive a DHCP message at port 4011.");
		}
		packet_process(sockd, dhdat, gp.verbose);

		fds[0].revents = 0;
		fds[1].revents = 0;
	} while (global_exit == 0);

exit_30:
	close(fds[1].fd);
exit_20:
	close(fds[0].fd);
exit_10:
	free(dhdat);
	return retv;
}
