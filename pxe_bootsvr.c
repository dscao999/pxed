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
#include <assert.h>
#include <arpa/inet.h>
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

static int poll_init(struct pollfd *pfd, int port, const char *iface)
{
	int sockd, retv, brd;
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
		retv = -retv;
		goto exit_10;
	}

	sockd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockd == -1) {
		elog("Cannot create socket: %s\n", strerror(errno));
		retv = -errno;
		goto exit_20;
	}
	if (port == 67) {
		brd = 1;
		retv = setsockopt(sockd, SOL_SOCKET, SO_BROADCAST, &brd, 4);
		if (retv == -1) {
			elog("Cannot set to broadcast: %s\n", strerror(errno));
			retv = -errno;
			goto exit_30;
		}
	}
	if (iface) {
		retv = setsockopt(sockd, SOL_SOCKET, SO_BINDTODEVICE, iface,
				sizeof(char *));
		if (retv == -1) {
			elog("Cannot bind socket to device %s: %s\n", iface,
					strerror(errno));
			retv = -errno;
			goto exit_30;
		}
	}
	pfd->fd = sockd;
	pfd->revents = 0;
	pfd->events = POLLIN;
	if (bind(sockd, res->ai_addr, res->ai_addrlen) == -1) {
		elog("Cannot bind socket: %s\n", strerror(errno));
		retv = -errno;
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

struct pxe_client {
	uint8_t uuid[16];
	uint16_t arch;
	uint16_t maxlen;
};

static const char *bootfile = "/pxelinux.0";
static int check_packet(int sockd, const struct sockaddr_in *src,
		const struct dhcp_data *dhdat, FILE *flog)
{
	int retv = 0, venlen, optlen;
	struct pxe_client pxec;
	const struct dhcp_option *opt, *vopt;
	struct dhcp_option *mopt, *sopt;
	struct dhcp_data *offer;
	struct dhcp_packet *pkt;
	struct in_addr svraddr;
	uint16_t svrtyp, layer;

	opt = dhcp_option_search(dhdat, DHCP_CUUID);
	if (!opt) {
		opt = dhcp_option_search(dhdat, DHCP_CMUID);
		if (!opt) {
			elog("No UUID in PXE discover.\n");
			return retv;
		}
	}
	memcpy(pxec.uuid, opt->val+1, sizeof(pxec.uuid));
	opt = dhcp_option_search(dhdat, DHCP_CLARCH);
	if (!opt) {
		elog("No client architecture type in PXE discover.\n");
		return retv;
	}
	pxec.arch = (opt->val[0] << 8) | opt->val[1];
	opt = dhcp_option_search(dhdat, DHCP_MAXLEN);
	if (!opt) {
		pxec.maxlen = 1024;
	} else
		pxec.maxlen = (opt->val[0] << 8) | opt->val[1];
	opt = dhcp_option_search(dhdat, DHCP_VENDOR);
	if (!opt) {
		elog("No Vendor option in pxe request/inform.\n");
		return retv;
	}
	vopt = (const struct dhcp_option *)opt->val;
	if (vopt->code != PXE_BOOTITEM) {
		elog("No PXE Boot Item in pxe request/inform.\n");
		return retv;
	}
	svrtyp = (vopt->val[0] << 8) | vopt->val[1];
	layer = (vopt->val[2] << 8) | vopt->val[3];
	printf("Received a PXE Boot Server Request. Server Type: %04X, Layer: %04x\n", svrtyp, layer);

	offer = malloc(pxec.maxlen);
	offer->maxlen = pxec.maxlen;
	offer->len = 0;
	pkt = &offer->pkt;
	memcpy(&pkt->header, &dhdat->pkt.header, sizeof(struct dhcp_head));
	pkt->header.op = DHCP_REP;
	strcpy(pkt->header.sname, "192.168.98.9");
	strcpy(pkt->header.bootfile, bootfile);

	mopt = pkt->options;
	mopt->code = DHCP_MSGTYPE;
	mopt->len = 1;
	mopt->val[0] = DHCP_ACK;
	mopt = dhcp_option_next(mopt);
	mopt->code = DHCP_SVRID;
	mopt->len = 4;
	retv = inet_pton(AF_INET, "192.168.98.9", &svraddr);
	if (retv != 1)
		elog("Warning: inet_pton failed.\n");
	memcpy(&pkt->header.siaddr, &svraddr, 4);
	memcpy(mopt->val, &svraddr, mopt->len);
	mopt = dhcp_option_next(mopt);
	mopt->code = DHCP_CMUID;
	mopt->len = 17;
	mopt->val[0] = 0;
	memcpy(mopt->val+1, pxec.uuid, sizeof(pxec.uuid));
	mopt = dhcp_option_next(mopt);
	mopt->code = DHCP_CLASS;
	mopt->len = 9;
	memcpy(mopt->val, "PXEClient", mopt->len);
	mopt = dhcp_option_next(mopt);
	mopt->code = DHCP_SVRNAME;
	mopt->len = 12;
	memcpy(mopt->val, "192.168.98.9", mopt->len);
	mopt = dhcp_option_next(mopt);
	mopt->code = DHCP_BOOTFILE;
	mopt->len = strlen(bootfile);
	memcpy(mopt->val, bootfile, mopt->len);

	mopt = dhcp_option_next(mopt);
	mopt->code = DHCP_VENDOR;

	venlen = 0;
	sopt = (struct dhcp_option *)mopt->val;
	sopt->code = PXE_BOOTITEM;
	sopt->len = 4;
	sopt->val[0] = svrtyp >> 8;
	sopt->val[1] = svrtyp & 0x0ff;
	sopt->val[2] = layer >> 8;
	sopt->val[3] = layer & 0x0ff;
	sopt = dhcp_option_next(sopt);
	sopt->code = PXE_END;
	venlen = 7;
	mopt->len = venlen;

	mopt = dhcp_option_next(mopt);
	mopt->code = DHCP_END;
	optlen = &mopt->code - (uint8_t *)pkt->options + 1;
	offer->len = sizeof(struct dhcp_head) + optlen;
	if (flog) {
		fwrite(&offer->len, sizeof(offer->len), 1, flog);
		fwrite(pkt, 1, offer->len, flog);
	}
	
	retv = sendto(sockd, pkt, offer->len, 0, src, sizeof(struct sockaddr_in));
	if (retv == -1)
		elog("Failed to send offer: %s\n", strerror(errno));
	dhcp_echo_packet(offer);
	free(offer);
	return retv;
}

static int packet_process(int sockd, struct dhcp_data *dhdat, FILE *fout)
{
	int len, buflen = dhdat->maxlen;
	struct sockaddr_in srcaddr;
	socklen_t socklen;
	char *buf = (char *)&dhdat->pkt;
	const struct dhcp_option *copt;

	dhdat->len = 0;
	socklen = sizeof(srcaddr);
	memset(&srcaddr, 0, socklen);
	len = recvfrom(sockd, buf, buflen, 0, (struct sockaddr *)&srcaddr,
			&socklen);
	if (len <= 0) {
		elog("recvfrom failed: %s\n", strerror(errno));
		return len;
	}
	dhdat->len = len;
	if (!dhcp_pxe(dhdat)) {
		elog("Not a PXE discover packet, Ignored.\n");
		return 0;
	}
	copt = dhcp_option_search(dhdat, DHCP_MSGTYPE);
	if (!copt || (copt->val[0] != DHCP_REQUEST &&
				copt->val[0] != DHCP_INFORM)) {
		elog("Not a PXE Boot Server request/inform, Ignored.\n");
		return 0;
	}

	if (socklen > sizeof(srcaddr))
		elog("Warning: address size too large %d\n", socklen);

	if (fout) {
		fwrite(&len, sizeof(len), 1, fout);
		fwrite(buf, 1, len, fout);
	}
	len = check_packet(sockd, &srcaddr, dhdat, NULL);
	return len;
}

int main(int argc, char *argv[])
{
	int retv, sockd, sysret;
	struct pollfd pfd;
	struct sigaction sigact;
	struct dhcp_data *dhdat;
	const char *iface;

	iface = NULL;
	if (argc > 1)
		iface = argv[1];

	memset(&pfd, 0, sizeof(pfd));
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

	retv = poll_init(&pfd, 4011, iface);
	if (retv != 0)
		goto exit_10;

	global_exit = 0;
	do {
		sysret = poll(&pfd, 1, 1000);
		if (sysret == -1 && errno != EINTR) {
			elog("poll failed: %s\n", strerror(errno));
			retv = 600;
			goto exit_30;
		} else if ((sysret == -1 && errno == EINTR) || sysret == 0)
			continue;
		
		if (pfd.revents) {
			sockd = pfd.fd;
			pfd.revents = 0;
			packet_process(sockd, dhdat, NULL);
		}
	} while (global_exit == 0);

exit_30:
	close(pfd.fd);
exit_10:
	free(dhdat);
	return retv;
}