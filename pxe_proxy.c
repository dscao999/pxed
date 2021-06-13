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
#include <time.h>
#include <signal.h>
#include <sched.h>
#include <stdarg.h>
#include <assert.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "dhcp.h"
#include "pxed_config.h"

static volatile int global_exit = 0;

void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
}

struct server_info {
	const struct boot_option *boot_option;
	struct in_addr sin_addr;
	int sockd;
	int verbose;
	FILE *flog;
};

static int elog(const char *format, ...)
{
	va_list va;
	int len;
	time_t curtm;
	char *datime;

	curtm = time(NULL);
	datime = ctime(&curtm);
	datime[strlen(datime)] = 0;
	fprintf(stderr, "%s ", datime);
	va_start(va, format);
	len = vfprintf(stderr, format, va);
	va_end(va);
	return len;
}

static int get_nicaddr(int sockd, const char *iface, struct in_addr *addr)
{
	struct ifreq req;
	int sysret;
	struct sockaddr_in *ipv4_addr;

	strncpy(req.ifr_name, iface, IFNAMSIZ);
	sysret = ioctl(sockd, SIOCGIFADDR, &req);
	if (sysret == -1) {
		elog("ioctl failed: %s\n", strerror(errno));
		return sysret;
	}
	ipv4_addr = (struct sockaddr_in *)&req.ifr_addr;
	*addr = ipv4_addr->sin_addr;
	return sysret;
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
	retv = setsockopt(sockd, SOL_SOCKET, SO_BINDTODEVICE, iface,
			sizeof(char *));
	if (retv == -1) {
		elog("Cannot bind socket to device %s: %s\n", iface,
				strerror(errno));
		retv = -errno;
		goto exit_30;
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

static int check_packet(int sockd, const struct sockaddr_in *src,
		const struct dhcp_data *dhdat, FILE *flog)
{
	int retv = 0, venlen, sublen, optlen;
	struct pxe_client pxec;
	const struct dhcp_option *opt;
	struct dhcp_option *mopt, *sopt;
	struct dhcp_data *offer;
	struct dhcp_packet *pkt;
	struct in_addr svraddr;

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
		elog("No maximum length in PXE discover.\n");
		pxec.maxlen = 1024;
	} else
		pxec.maxlen = (opt->val[0] << 8) | opt->val[1];

	offer = malloc(pxec.maxlen);
	offer->maxlen = pxec.maxlen;
	offer->len = 0;
	pkt = &offer->pkt;
	memcpy(&pkt->header, &dhdat->pkt.header, sizeof(struct dhcp_head));
	pkt->header.op = DHCP_REP;
	mopt = pkt->options;
	mopt->code = DHCP_MSGTYPE;
	mopt->len = 1;
	mopt->val[0] = DHCP_OFFER;
	mopt = dhcp_option_next(mopt);
	mopt->code = DHCP_SVRID;
	mopt->len = 4;
	retv = inet_pton(AF_INET, "192.168.98.9", &svraddr);
	if (retv != 1)
		elog("Warning: inet_pton failed.\n");
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
	mopt->code = DHCP_VENDOR;

	venlen = 0;
	sopt = (struct dhcp_option *)mopt->val;
	sopt->code = PXE_DISCTL;
	sopt->len = 1;
	sopt->val[0] = 7;
	venlen += 3;
	sopt = dhcp_option_next(sopt);
	sopt->code = PXE_BOOTSVR;
	sublen = 0;
	sopt->val[0] = 0x0;
	sopt->val[1] = 0x1;
	sopt->val[2] = 1;
	memcpy(sopt->val+3, &svraddr, 4);
	sublen += 7;
	sopt->len = sublen;
	venlen += sublen + 2;
	sopt = dhcp_option_next(sopt);
	sopt->code = PXE_BOOTMENU;
	sublen = 0;
	sopt->val[0] = 0;
	sopt->val[1] = 1;
	sopt->val[2] = 9;
	memcpy(sopt->val+3, "LIOS v2.1", 9);
	sublen += 12;
	sopt->len = sublen;
	venlen += sublen + 2;
	sopt = dhcp_option_next(sopt);
	sopt->code = PXE_BOOTPROMPT;
	sublen = 0;
	sopt->val[0] = 60;
	memcpy(sopt->val+1, "LIOS PXE Server", 15);
	sublen += 16;
	sopt->len = sublen;
	venlen += sublen + 2;
	sopt = dhcp_option_next(sopt);
	sopt->code = PXE_END;
	venlen += 1;
	assert(venlen == &sopt->code - mopt->val + 1);
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
	return retv;
}

static int packet_process(struct server_info *sinfo, struct dhcp_data *dhdat)
{
	int len, buflen = dhdat->maxlen;
	struct sockaddr_in srcaddr;
	socklen_t socklen;
	char *buf = (char *)&dhdat->pkt;
	const struct dhcp_option *copt;

	dhdat->len = 0;
	socklen = sizeof(srcaddr);
	memset(&srcaddr, 0, socklen);
	len = recvfrom(sinfo->sockd, buf, buflen, 0,
			(struct sockaddr *)&srcaddr, &socklen);
	if (len <= 0) {
		elog("recvfrom failed: %s\n", strerror(errno));
		return len;
	}
	dhdat->len = len;
	if (!dhcp_pxe(dhdat)) {
		if (sinfo->verbose)
			elog("Not a PXE discover packet, Ignored.\n");
		return 0;
	}
	copt = dhcp_option_search(dhdat, DHCP_MSGTYPE);
	if (!copt || copt->val[0] != DHCP_DISCOVER) {
		if (sinfo->verbose)
			elog("Not a DHCP discover request, Ignored.\n");
		return 0;
	}

	if (socklen > sizeof(srcaddr))
		elog("Warning: address size too large %d\n", socklen);

	if (sinfo->flog) {
		fwrite(&len, sizeof(int), 1, sinfo->flog);
		fwrite(buf, 1, len, sinfo->flog);
	}
	inet_pton(AF_INET, "255.255.255.255", &srcaddr.sin_addr);
	len = check_packet(sinfo->sockd, &srcaddr, dhdat, NULL);
	return len;
}

static int get_first_nic(char *buf)
{
	DIR *dir;
	int retv = 0, found;
	struct dirent *ent;
	static const char *netdir = "/sys/class/net";

	dir = opendir(netdir);
	if (!dir) {
		elog("Cannot open directory %s: %s\n", netdir,
				strerror(errno));
		return retv;
	}
	errno = 0;
	found = 0;
	ent = readdir(dir);
	while (ent) {
		if ((ent->d_type & DT_LNK) == 0)
			goto next_nic;
		if (strcmp(ent->d_name, "lo") == 0)
			goto next_nic;
		strcpy(buf, ent->d_name);
		found = 1;
		break;
next_nic:
		ent = readdir(dir);
	}
	if (found == 0)
		elog("No NIC is found.\n");
	else
		printf("Info: Bind to NIC \'%s\'\n", buf);
	return found;
}


int main(int argc, char *argv[])
{
	int retv, sysret, fin, c;
	struct pollfd pfd;
	struct sigaction sigact;
	struct dhcp_data *dhdat;
	const char *iface = NULL, *config = NULL;
	static char ifname[32];
	extern char *optarg;
	extern int opterr, optopt;
	struct server_info sinfo;

	sinfo.verbose = 0;
	sinfo.flog = NULL;
	opterr = 0;
	fin = 0;
	do {
		c = getopt(argc, argv, ":i:c:");
		switch(c) {
		case '?':
			elog("Unknown option: %c\n", (char)optopt);
			break;
		case ':':
			elog("Missing argument for %c\n", (char)optopt);
			break;
		case -1:
			fin = 1;
			break;
		case 'i':
			iface = optarg;
			break;
		case 'c':
			config = optarg;
			break;
		case 'v':
			sinfo.verbose = 1;
			break;
		default:
			elog("Internal Logic error in processing options.\n");
			assert(0);
		}
	} while (fin == 0);

	if (!iface) {
		retv = get_first_nic(ifname);
		if (retv == 1)
			iface = ifname;
		else {
			elog("No NIC port.\n");
			return 3;
		}
	}
	if (!config)
		config = "/etc/pxed.conf";
	retv = pxed_config(config);
	if (retv != 0) {
		elog("Cannot parse configuration file: %s\n", config);
		return 1;
	}

	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = sig_handler;
	if (sigaction(SIGTERM, &sigact, NULL) == -1 ||
			sigaction(SIGINT, &sigact, NULL) == -1)
		elog("Signal Handler Cannot be setup: %s\n",
				strerror(errno));

	dhdat = malloc(2048);
	if (!dhdat) {
		elog("Out of Memory!\n");
		return 100;
	}
	dhdat->maxlen = 2048 - offsetof(struct dhcp_data, pkt);

	retv = poll_init(&pfd, 67, iface);
	if (retv != 0)
		goto exit_10;

	sinfo.sockd = pfd.fd;
	sinfo.boot_option = bopt;
	retv = get_nicaddr(pfd.fd, iface, &sinfo.sin_addr);
	if (retv != 0) {
		elog("Cannot get IP address of %s.\n", iface);
		goto exit_20;
	}

	global_exit = 0;
	do {
		sysret = poll(&pfd, 1, 1000);
		if (sysret == -1 && errno != EINTR) {
			elog("poll failed: %s\n", strerror(errno));
			retv = 10;
			goto exit_20;
		} else if ((sysret == -1 && errno == EINTR) || sysret == 0)
			continue;
		
		if (pfd.revents) {
			pfd.revents = 0;
			packet_process(&sinfo, dhdat);
		}
	} while (global_exit == 0);

exit_20:
	close(pfd.fd);
exit_10:
	free(dhdat);
	return retv;
}
