#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>
#include <net/if.h>
#include "miscs.h"
#include "dhcp.h"
#include "net_utils.h"
#include "pxed_config.h"

static volatile int global_exit = 0;

void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
}

struct server_info {
	const struct boot_option *boot_option;
	FILE *flog;
	char ipaddr[32];
	struct in_addr sin_addr;
	int verbose;
};
struct pxe_client {
	uint8_t uuid[16];
	uint16_t arch;
	uint16_t maxlen;
};

static int offer_pxe(const struct server_info *sinf, int sockd,
		const struct sockaddr_in *src, const struct dhcp_data *dhdat)
{
	int retv = 0, venlen, sublen, optlen;
	struct pxe_client pxec;
	const struct dhcp_option *opt;
	struct dhcp_option *mopt, *sopt;
	struct dhcp_data *offer;
	struct dhcp_packet *pkt;
	time_t ctm;

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
	memcpy(mopt->val, &sinf->sin_addr, mopt->len);
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
	int i, count, len;
	const struct boot_item *vitems[8];
	count = 0;
	for (i = 0; i < sinf->boot_option->n_bitems && count < 8; i++) {
		if (sinf->boot_option->bitems[i].clarch == pxec.arch)
			vitems[count++] = &sinf->boot_option->bitems[i];
	}
	if (count == 0) {
		elog("No support for arch: %04X in %d supported items.\n",
				pxec.arch, sinf->boot_option->n_bitems);
		retv = -4;
		goto exit_10;
	}
	sopt->len = count * 7;
	sublen = 0;
	for (i = 0; i < count; i++) {
		sopt->val[sublen+0] = vitems[i]->index >> 8;
		sopt->val[sublen+1] = vitems[i]->index & 0x0ff;
		sopt->val[sublen+2] = 1;
		memcpy(sopt->val+3+sublen, &sinf->sin_addr, 4);
		sublen += 7;
	}
	venlen += sublen + 2;
	sopt = dhcp_option_next(sopt);
	sopt->code = PXE_BOOTMENU;
	sublen = 0;
	for (i = 0; i < count; i++) {
		sopt->val[sublen+0] = vitems[i]->index >> 8;
		sopt->val[sublen+1] = vitems[i]->index & 0x0ff;
		len = strlen(vitems[i]->desc);
		sopt->val[sublen+2] = len;
		memcpy(sopt->val+sublen+3, vitems[i]->desc, len);
		sublen += 3 + len;
	}
	sopt->len = sublen;
	venlen += sublen + 2;

	sopt = dhcp_option_next(sopt);
	sopt->code = PXE_BOOTPROMPT;
	sublen = strlen(sinf->boot_option->prompt);
	sopt->val[0] = sinf->boot_option->timeout;
	memcpy(sopt->val+1, sinf->boot_option->prompt, sublen);
	sopt->len = sublen + 1;
	venlen += sopt->len + 2;
	sopt = dhcp_option_next(sopt);
	sopt->code = PXE_END;
	venlen += 1;
	assert(venlen == &sopt->code - mopt->val + 1);

	mopt->len = venlen;
	mopt = dhcp_option_next(mopt);
	mopt->code = DHCP_END;
	optlen = &mopt->code - (uint8_t *)pkt->options + 1;
	offer->len = sizeof(struct dhcp_head) + optlen;

	ctm= time(NULL);
	if (sinf->flog) {
		fwrite(&ctm, sizeof(ctm), 1, sinf->flog);
		fwrite(&offer->len, sizeof(offer->len), 1, sinf->flog);
		fwrite(pkt, 1, offer->len, sinf->flog);
	}
	if (sinf->verbose)
		dhcp_echo_packet(offer, ctm);
	
	retv = sendto(sockd, pkt, offer->len, 0,
			src, sizeof(struct sockaddr_in));
	if (retv == -1)
		elog("Failed to send offer: %s\n", strerror(errno));

exit_10:
	free(offer);
	return retv;
}

static int discover_packet_process(const struct server_info *sinf, int sockd,
		struct dhcp_data *dhdat)
{
	int len, buflen = dhdat->maxlen;
	struct sockaddr_in srcaddr;
	socklen_t socklen;
	char *buf = (char *)&dhdat->pkt;
	const struct dhcp_option *copt;
	time_t ctm;

	dhdat->len = 0;
	socklen = sizeof(srcaddr);
	memset(&srcaddr, 0, socklen);
	len = recvfrom(sockd, buf, buflen, 0,
			(struct sockaddr *)&srcaddr, &socklen);
	if (len <= 0) {
		elog("recvfrom failed: %s\n", strerror(errno));
		return len;
	}
	dhdat->len = len;
	if (!dhcp_pxe(dhdat)) {
		if (sinf->verbose)
			elog("Not a PXE discover packet, Ignored.\n");
		return 0;
	}
	copt = dhcp_option_search(dhdat, DHCP_MSGTYPE);
	if (!copt || copt->val[0] != DHCP_DISCOVER) {
		if (sinf->verbose)
			elog("Not a PXE discover request, Ignored.\n");
		return 0;
	}

	if (socklen > sizeof(srcaddr))
		elog("Warning: address size too large %d\n", socklen);
	ctm= time(NULL);
	if (sinf->flog) {
		fwrite(&ctm, sizeof(ctm), 1, sinf->flog);
		fwrite(&dhdat->len, sizeof(dhdat->len), 1, sinf->flog);
		fwrite(buf, 1, dhdat->len, sinf->flog);
	}
	if (sinf->verbose)
		dhcp_echo_packet(dhdat, ctm);
	if (srcaddr.sin_addr.s_addr == 0)
		inet_pton(AF_INET, "255.255.255.255", &srcaddr.sin_addr);
	len = offer_pxe(sinf, sockd, &srcaddr, dhdat);
	return len;
}

struct thread_param {
	const struct server_info *sinf;
	struct pollfd pfd;
	int retcode;
};

void * get_pxe_discover(void *data)
{
	struct thread_param *arg = data;
	struct dhcp_data *dhdat;
	int sysret;

	dhdat = malloc(2048);
	if (!dhdat) {
		elog("Out of Memory!\n");
		arg->retcode = 100;
		return NULL;
	}
	dhdat->maxlen = 2048 - offsetof(struct dhcp_data, pkt);

	do {
		sysret = poll(&arg->pfd, 1, 1000);
		if (sysret == -1 && errno != EINTR) {
			elog("poll failed: %s\n", strerror(errno));
			global_exit = 1;
			continue;
		} else if ((sysret == -1 && errno == EINTR) || sysret == 0)
			continue;
		if (arg->pfd.revents == 0)
			continue;

		arg->pfd.revents = 0;
		discover_packet_process(arg->sinf, arg->pfd.fd, dhdat);
	} while (global_exit == 0);

	free(dhdat);
	return NULL;
}

static int ack_pxe(const struct server_info *sinf, int sockd,
		const struct sockaddr_in *src, const struct dhcp_data *dhdat)
{
	int retv = 0, venlen, optlen;
	struct pxe_client pxec;
	const struct dhcp_option *opt, *vopt;
	struct dhcp_option *mopt, *sopt;
	struct dhcp_data *offer;
	struct dhcp_packet *pkt;
	uint16_t svrtyp, layer;
	time_t ctm;

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

	int i;
	const struct boot_item *myitem = sinf->boot_option->bitems;
	for (i = 0; i < sinf->boot_option->n_bitems; i++, myitem++)
		if (myitem->index == svrtyp)
			break;
	if (i == sinf->boot_option->n_bitems) {
		if (sinf->verbose)
			elog("Not a request to me.\n");
		return retv;
	}
	if (myitem->clarch != pxec.arch) {
		elog("Logic Error, arch: %d not supported.\n", pxec.arch);
		return retv;
	}

	offer = malloc(pxec.maxlen);
	offer->maxlen = pxec.maxlen;
	offer->len = 0;
	pkt = &offer->pkt;
	memcpy(&pkt->header, &dhdat->pkt.header, sizeof(struct dhcp_head));
	pkt->header.op = DHCP_REP;
	memcpy(&pkt->header.siaddr, &sinf->sin_addr, 4);
	strcpy(pkt->header.sname, sinf->ipaddr);
	strcpy(pkt->header.bootfile, myitem->bootfile);

	mopt = pkt->options;
	mopt->code = DHCP_MSGTYPE;
	mopt->len = 1;
	mopt->val[0] = DHCP_ACK;
	mopt = dhcp_option_next(mopt);
	mopt->code = DHCP_SVRID;
	mopt->len = 4;
	memcpy(mopt->val, &sinf->sin_addr, mopt->len);
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
	mopt->len = strlen(sinf->ipaddr);
	memcpy(mopt->val, sinf->ipaddr, mopt->len);
	mopt = dhcp_option_next(mopt);
	mopt->code = DHCP_BOOTFILE;
	mopt->len = strlen(myitem->bootfile);
	memcpy(mopt->val, myitem->bootfile, mopt->len);

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
	ctm= time(NULL);
	if (sinf->flog) {
		fwrite(&ctm, sizeof(ctm), 1, sinf->flog);
		fwrite(&offer->len, sizeof(offer->len), 1, sinf->flog);
		fwrite(pkt, 1, offer->len, sinf->flog);
	}
	if (sinf->verbose)
		dhcp_echo_packet(offer, ctm);
	retv = sendto(sockd, pkt, offer->len, 0, src, sizeof(struct sockaddr_in));
	if (retv == -1)
		elog("Failed to send offer: %s\n", strerror(errno));
	free(offer);
	return retv;
}

static int request_packet_process(const struct server_info *sinf, int sockd,
		struct dhcp_data *dhdat)
{
	int len, buflen = dhdat->maxlen;
	struct sockaddr_in srcaddr;
	socklen_t socklen;
	char *buf = (char *)&dhdat->pkt;
	const struct dhcp_option *copt;
	int retv = 0;
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
	dhdat->len = len;
	if (!dhcp_pxe(dhdat)) {
		if (sinf->verbose)
			elog("Not a PXE packet, Ignored.\n");
		return retv;
	}
	copt = dhcp_option_search(dhdat, DHCP_MSGTYPE);
	if (!copt || (copt->val[0] != DHCP_REQUEST &&
				copt->val[0] != DHCP_INFORM)) {
		if (sinf->verbose)
			elog("Not PXE Boot Server request/inform, Ignored.\n");
		return retv;
	}

	if (socklen > sizeof(srcaddr))
		elog("Warning: address size too large %d\n", socklen);

	ctm= time(NULL);
	if (sinf->flog) {
		fwrite(&ctm, sizeof(ctm), 1, sinf->flog);
		fwrite(&dhdat->len, sizeof(dhdat->len), 1, sinf->flog);
		fwrite(buf, 1, dhdat->len, sinf->flog);
	}
	if (sinf->verbose)
		dhcp_echo_packet(dhdat, ctm);
	len = ack_pxe(sinf, sockd, &srcaddr, dhdat);
	return len;
}
void * get_pxe_request(void *data)
{
	struct thread_param *arg = data;
	struct dhcp_data *dhdat;
	int sysret;

	dhdat = malloc(2048);
	if (!dhdat) {
		elog("Out of Memory!\n");
		arg->retcode = 100;
		return NULL;
	}
	dhdat->maxlen = 2048 - offsetof(struct dhcp_data, pkt);

	do {
		sysret = poll(&arg->pfd, 1, 1000);
		if (sysret == -1 && errno != EINTR) {
			elog("poll failed: %s\n", strerror(errno));
			global_exit = 1;
			continue;
		} else if ((sysret == -1 && errno == EINTR) || sysret == 0)
			continue;
		if (arg->pfd.revents == 0)
			continue;

		arg->pfd.revents = 0;
		sysret = request_packet_process(arg->sinf, arg->pfd.fd, dhdat);
		
	} while (global_exit == 0);

	free(dhdat);
	return NULL;
}

int main(int argc, char *argv[])
{
	int retv, fin, c;
	struct sigaction sigact;
	const char *iface = NULL, *config = NULL;
	static char ifname[32];
	extern char *optarg;
	extern int opterr, optopt;
	struct server_info sinfo;
	struct thread_param parm[2];
	pthread_t th67, th4011;
	static const struct timespec itv = {.tv_sec = 1, .tv_nsec = 0};

	sinfo.verbose = 0;
	sinfo.flog = NULL;
	opterr = 0;
	fin = 0;
	do {
		c = getopt(argc, argv, ":i:vc:");
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
	retv = pxed_config(config, sinfo.verbose);
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

	sinfo.boot_option = bopt;
	if (strlen(bopt->logfile) > 0) {
		sinfo.flog = fopen(bopt->logfile, "w");
		if (!sinfo.flog)
			elog("Warning! Cannot open log file %s: %s\n",
					bopt->logfile, strerror(errno));
	}
	
	parm[0].pfd.fd = -1;
	parm[1].pfd.fd = -1;
	retv = poll_init(&parm[0].pfd, 67, iface);
	if (retv != 0)
		goto exit_10;
	retv = poll_init(&parm[1].pfd, 4011, iface);
	if (retv != 0)
		goto exit_10;

	retv = get_nicaddr(parm[0].pfd.fd, iface, &sinfo.sin_addr);
	if (retv != 0) {
		elog("Cannot get IP address of %s.\n", iface);
		goto exit_10;
	}
	if (!inet_ntop(AF_INET, &sinfo.sin_addr, sinfo.ipaddr,
				sizeof(sinfo.ipaddr))) {
		elog("Cannot convert network address to string.\n");
		retv = 8;
		goto exit_10;
	}
	printf("Monitoring NIC: %s, IP: %s\n", iface, sinfo.ipaddr);

	parm[0].sinf = &sinfo;
	parm[0].retcode = 0;
	parm[1].sinf = &sinfo;
	parm[1].retcode = 0;
	retv = pthread_create(&th67, NULL, get_pxe_discover, parm);
	if (retv) {
		elog("Cannot create thread: %s\n", strerror(retv));
		goto exit_10;
	}
	retv = pthread_create(&th4011, NULL, get_pxe_request, parm+1);
	if (retv) {
		elog("Cannot create thread: %s\n", strerror(retv));
		pthread_kill(th67, SIGTERM);
		pthread_join(th67, NULL);
		goto exit_10;
	}

	do
		nanosleep(&itv, NULL);
	while (global_exit == 0);

	pthread_join(th67, NULL);
	pthread_join(th4011, NULL);


exit_10:
	if (parm[0].pfd.fd > 0)
		close(parm[0].pfd.fd);
	if (parm[1].pfd.fd > 0)
		close(parm[1].pfd.fd);
	if (sinfo.flog)
		fclose(sinfo.flog);
	return retv;
}
