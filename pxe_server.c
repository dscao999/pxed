#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <assert.h>
#include "misc.h"
#include "dhcp.h"
#include "pxe_util.h"

#define MAX_CLIENTS	0x100
#define MAX_CLIENTS_MASK 0x0ff

static const char *default_config = "/etc/pxed.conf";
static struct logspec {
	int verbose;
	FILE *logf;
	char *logfile;
} loginfo;

extern pxe_config_t *pconf_g;

typedef struct dhcp_pool {
	char buffer[MAX_CLIENTS*PACKET_LEN];
	dhcp_buff_t  items[MAX_CLIENTS];
	int head;
} dhcp_pool_t;

void pool_init(dhcp_pool_t *pool)
{
	int i;
	char *curbuf;

	pool->head = 0;
	curbuf = pool->buffer;
	for (i = 0; i < MAX_CLIENTS; i++) {
		pool->items[i].packet = (dhcp_packet_t *) curbuf;
		curbuf += PACKET_LEN;
		pool->items[i].maxlen = PACKET_LEN;
	}
}
static inline dhcp_buff_t *dhcp_pool_next(dhcp_pool_t *pool)
{
	dhcp_buff_t *packet_buff;

	packet_buff = pool->items + pool->head;
	pool->head = (pool->head + 1) & MAX_CLIENTS_MASK;
	dhcp_buff_init(packet_buff);
	return packet_buff;
}

static volatile int stop_processing = 0;
static volatile int reconfig = 0;
void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		stop_processing = 1;
}
void sig_hup_handler(int sig)
{
	if (sig == SIGHUP) {
		reconfig = 1;
		stop_processing = 1;
	}
}

static int sock_init(int port, const char *iface)
{
	int sockd, retv, broadcast;
	struct addrinfo hints, *res;
	char pstr[16];

	snprintf(pstr, sizeof(pstr), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	while ((retv = getaddrinfo(NULL, pstr, &hints, &res)) == EAI_AGAIN)
		;
	if (retv != 0) {
		errlog("getaddrinfo failed: %s\n", gai_strerror(retv));
		retv = -250;
		goto z_exit;
	}

	sockd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockd == -1) {
		errlog("Cannot create socket: %s\n", strerror(errno));
		retv = -204;
		goto y_exit;
	}
	broadcast = 1;
        retv = setsockopt(sockd, SOL_SOCKET, SO_BROADCAST, &broadcast, 4);
	if (retv == -1) {
		errlog("Cannot set socket to broadcast: %s\n",
			strerror(errno));
		retv = -278;
		goto y_exit;
	}
	if (iface) {
		if (setsockopt(sockd, SOL_SOCKET, SO_BINDTODEVICE, iface,
		sizeof(char*)) < 0)
			errlog("Cannot bind socket to device eth0\n");
	}
 
	if (bind(sockd, res->ai_addr, res->ai_addrlen) == -1) {
		errlog("Cannot bind socket: %s\n", strerror(errno));
		retv = -208;
		goto x_exit;
	}

	freeaddrinfo(res);
	return sockd;

x_exit:
	close(sockd);
y_exit:
	freeaddrinfo(res);
z_exit:
	return retv;
}

static int fds_init(struct pollfd fds[2], int num, const char *iface)
{
	int retv;


	retv = 0;
	fds[0].fd = -1;
	fds[1].fd = -1;
	fds[0].revents = 0;
	fds[1].revents = 0;

	fds[0].fd = sock_init(4011, iface);
	if (fds[0].fd < 0) {
		retv = fds[0].fd;
		goto z_exit;
	}
	fds[0].events = POLLIN;

	if (num == 1)
		return retv;

	fds[1].fd = sock_init(67, iface);
	if (fds[1].fd < 0) {
		retv = fds[1].fd;
		goto y_exit;
	}
	fds[1].events = POLLIN;

	return retv;

y_exit:
	close(fds[0].fd);
z_exit:
	return retv;
}

static inline void fds_exit(const struct pollfd fds[2])
{
	if (fds[0].fd > 0) close(fds[0].fd);
	if (fds[1].fd > 0) close(fds[1].fd);
}

static int pxe_prepare_ack(dhcp_buff_t *buff, int nic)
{
	int retv, svrseq, i, clarch, len;
	dhcp_packet_t *pkt;
	dhcp_option_t *option, *vendopt;
	const dhcp_option_t *bootopt, *oparch;
	macip_addr_t *macip;
	bootserv_t *bsvr;
	uint8 uuid[16];
	noalign16_t seq;
	pxe_config_t *pconf = pconf_g;

	assert(nic < pconf->nics);

	retv = 0;
	if (!dhcp_get_uuid(buff, uuid)) {
		errlog("Cannot get uuid!\n");
		goto z_exit;
	}

	clarch = -1;
	oparch = dhcp_option_search(buff, DHCLARCH);
	if (oparch) {
		seq.pad[0] = oparch->vals[0];
		seq.pad[1] = oparch->vals[1];
		clarch = ntohs(seq.val);
	}

	macip = pconf->macips + nic;
	pkt = buff->packet;
	pkt->op = 2;
	pkt->ciaddr = 0;
	pkt->yiaddr = 0;
	pkt->siaddr = macip->ipaddr.s_addr;


	svrseq = -1;
	seq.val = -1;
	bootopt = dhcp_vendopt_search(buff, PXEBOOTITEM);
	if (bootopt) {
		seq.pad[0] = bootopt->vals[0];
		seq.pad[1] = bootopt->vals[1];
		svrseq = ntohs(seq.val);
	}
	bsvr = pconf->bootsvrs;

	if (svrseq != -1 && svrseq != 0) {
		for (i = 0; i < pconf->svrs; i++) {
			if (bsvr->seq == svrseq)
				break;
			bsvr++;
		}
		if (i == pconf->svrs) {
			errlog("Server seq: %d not present!\n", svrseq);
			retv = -1;
			goto z_exit;
		}
	}

	option = (dhcp_option_t *)pkt->options;
	option->code = DHSVRID;
	option->len = 4;
	memcpy(option->vals, &macip->ipaddr, 4);

	option = dhcp_option_next(option);
        option->code = DHCMUID;
        option->len = 17;
        option->vals[0] = 0;
	memcpy(option->vals+1, uuid, 16);

	option = dhcp_option_next(option);
	option->code = DHMSGTYPE;
	option->len = 1;
	if (svrseq != 0)
		option->vals[0] = 5;
	else
		option->vals[0] = 6;

	option = dhcp_option_next(option);
	option->code = DHCLASS;
	option->len = 9;
	memcpy(option->vals, "PXEClient", 9);

	option = dhcp_option_next(option);
	if (svrseq > 0) {
		option->code = DHSVRNAME;
		inet_ntop(AF_INET, &macip->ipaddr, (char *)option->vals, INET_ADDRSTRLEN);
		option->len = strlen((char *)option->vals);
			
		option = dhcp_option_next(option);
		option->code = DHBOOTFILE;
		option->len = bsvr->blen+1;
		memcpy(option->vals, bsvr->bfile, bsvr->blen);
		option->vals[bsvr->blen] = 0;
		
		option = dhcp_option_next(option);
		vendopt = option;
		vendopt->code = DHVENDOR;
		option = (dhcp_option_t *)vendopt->vals;
		option->code = PXEBOOTITEM;
		option->len = 4;
		option->vals[0] = seq.pad[0];
		option->vals[1] = seq.pad[1];
		option->vals[2] = 0;
		option->vals[3] = 0;
		option = dhcp_option_next(option);
		option->code = PXEEND;
		vendopt->len = (void *)option - (void *)vendopt->vals + 1;
		option = dhcp_option_next(vendopt);
	} else {
		len = (void *)option - (void *)pkt;
		pxe_vendor_setup(option, buff->maxlen - len, clarch);
		option = dhcp_option_next(option);
	}
	option->code = DHEND;

	buff->len = (void *)option - (void *)pkt + 1;
	retv = buff->len;

z_exit:
	return retv;
}

static int pxe_prepare_offer(dhcp_buff_t *buff, int nic)
{
	int retv, len, clarch;
	dhcp_packet_t *pkt;
	dhcp_option_t *option;
	const dhcp_option_t *oparch;
	macip_addr_t *macip;
	uint8 uuid[16];
	noalign16_t sval;
	pxe_config_t *pconf = pconf_g;

	assert(nic < pconf->nics);

	retv = 0;
	if (!dhcp_get_uuid(buff, uuid)) {
		errlog("Cannot get uuid!\n");
		goto z_exit;
	}

        clarch = -1;
        oparch = dhcp_option_search(buff, DHCLARCH);
        if (oparch) {
                sval.pad[0] = oparch->vals[0];
                sval.pad[1] = oparch->vals[1];
                clarch = ntohs(sval.val);
        }

	pkt = buff->packet;
	pkt->op = 2;
	pkt->ciaddr = 0;
	pkt->yiaddr = 0;
	pkt->siaddr = 0;

	macip = pconf->macips + nic;
	option = (dhcp_option_t *)pkt->options;
	option->code = DHSVRID;
	option->len = 4;
	memcpy(option->vals, &macip->ipaddr, 4);

	option = dhcp_option_next(option);
        option->code = DHCMUID;
        option->len = 17;
        option->vals[0] = 0;
	memcpy(option->vals+1, uuid, 16);

	option = dhcp_option_next(option);
	buff->len = (void *)option - (void *)pkt;
	len = pxe_offer_make((uint8 *)option, buff->maxlen - buff->len, clarch);
	buff->len += len;

	retv = buff->len;

z_exit:
	return retv;
}

int process_packet(int sock, dhcp_buff_t *buff)
{
	int retv, num, clarch, maxlen;
	const dhcp_option_t *option;
	noalign16_t sval;
	struct sockaddr_in srcaddr;
	socklen_t socklen;
	pxe_config_t *pconf = pconf_g;

	retv = 0;
	socklen = sizeof(srcaddr);
	memset(&srcaddr, 0, socklen);
	buff->len = recvfrom(sock, buff->packet, buff->maxlen, 0,
			(struct sockaddr *)&srcaddr, &socklen);
	if (buff->len <= 0) {
		errlog("recvfrom failed: %s\n", strerror(errno));
		retv = -8;
		goto z_exit;
	}
	
	if (loginfo.verbose)
		dhcp_dump_packet(buff, loginfo.logf);
	
	if (!dhcp_pxe_request(buff)) {
		retv = -1;
		if (loginfo.verbose)
			errlog("Not a PXE Boot Request!\n");
		goto z_exit;
	}

	option = dhcp_option_search(buff, DHMAXLEN);
	if (option) {
		sval.pad[0] = option->vals[0];
		sval.pad[1] = option->vals[1];
		maxlen = ntohs(sval.val);
		if (buff->maxlen < maxlen)
			errlog("Warning: max request length too big: %d\n",
				maxlen);
	}
	clarch = -1;
	option = dhcp_option_search(buff, DHCLARCH);
	if (option) {
		sval.pad[0] = option->vals[0];
		sval.pad[1] = option->vals[1];
		clarch = ntohs(sval.val);
	}
	if (clarch == -1) {
		retv = -11;
		if (loginfo.verbose)
			errlog("Unsupported client arch: %d\n", clarch);
		goto z_exit;
	}
	if (loginfo.verbose)
		errlog("Client Architecture: %d\n", clarch);

	option = dhcp_option_search(buff, DHMSGTYPE);
	if (!option) {
		retv = -10;
		if (loginfo.verbose)
			errlog("No Message Type!\n");
		goto z_exit;
	}
	switch(option->vals[0]) {
	case 1: /* A Discover Packet */
		if (pxe_prepare_offer(buff, 0) <= 0) {
			errlog("Offer cannot be prepared\n");
			retv = -2;
			goto z_exit;
		}
		srcaddr.sin_addr = pconf->bcast;
		break;
	case 3: /* A Request Packet */
		if (pxe_prepare_ack(buff, 0) <= 0) {
			errlog("Acknolowedge cannot be prepared\n");
			retv = -3;
			goto z_exit;
		}
		if (srcaddr.sin_addr.s_addr == 0)
			srcaddr.sin_addr = pconf->bcast;
		break;
	case 8:
	default:
		errlog("An invalid message type!\n");
		retv = -4;
		goto z_exit;
	}

	num = sendto(sock, buff->packet, buff->len, 0,
			&srcaddr, sizeof(srcaddr));
	if (num == -1) {
		errlog("sendto failed: %s\n", strerror(errno));
		retv = -12;
	} else if (num != buff->len)
		errlog("sendto not complete!\n");

	if (loginfo.verbose)
		dhcp_dump_packet(buff, loginfo.logf);
z_exit:
	return retv;
}

int main(int argc, char *argv[])
{
	int retv, sysret, opt, stoparg;;
	extern int opterr, optopt, optind;
	extern char *optarg;
	const char *config_f;
	struct pollfd fds[2];
	dhcp_pool_t *pool;
	dhcp_buff_t *buff;
	struct sigaction sigact;
	int numsocks, foreground;
	char *iface;
	pxe_config_t *pconf;

	retv = 0;

	foreground = 0;
	iface = NULL;
	stoparg = 0;
	opterr = 0;
	config_f = NULL;
	do {
		opt = getopt(argc, argv, ":c:i:vD");
		switch(opt) {
		case -1:
			stoparg = 1;
			break;
		case '?':
			errlog("Unknown option: %c\n", optopt);
			break;
		case ':':
			errlog("Missing argument for: %c\n", optopt);
			break;
		case 'c':
			config_f = optarg;
			break;
		case 'v':
			loginfo.verbose = 1;
			break;
		case 'D':
			foreground=1;
			break;
		case 'i':
			iface = optarg;
			break;
		default:
			assert(0);
		}
	} while (!stoparg);
	if (!config_f)
		config_f = default_config;
	if (!foreground)
		daemon(0, 0);

	sigact.sa_handler = sig_handler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	if (sigaction(SIGTERM, &sigact, NULL) == -1 ||
		sigaction(SIGINT, &sigact, NULL) == -1)
		errlog("Signal Handler Cannot be setup\n");
	sigact.sa_handler = sig_hup_handler;
	if (sigaction(SIGHUP, &sigact, NULL) == -1)
		errlog("Signal Handler Cannot be setup\n");

	pool = mmap(NULL, sizeof(dhcp_pool_t), PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (unlikely(pool == MAP_FAILED)) {
		retv = 10000;
		errlog("Cannot reserve pool space: %s\n", strerror(errno));
		goto z_exit;
	}
	pool_init(pool);

	do {
		reconfig = 0;
		numsocks = 2;
		pxe_data_init();
		pconf = pconf_g;
		if (pxe_server_init(config_f, iface) < 0) {
			retv = 4;
			errlog("Cannot initialize server!\n");
			goto x_exit;
		}
		loginfo.logfile = pconf->logfile;
		loginfo.logf = fopen(loginfo.logfile, "wb");
		if (loginfo.logf == NULL) {
			loginfo.verbose = 0;
			errlog("Cannot open log file: %s\n", loginfo.logfile);
		}
		if (pconf->m67 == 0)
			numsocks = 1;
		if ((retv = fds_init(fds, numsocks, iface)) < 0) {
			errlog("Failed to initialize sockets!\n");
			retv = -retv;
			goto x_exit;
		}
		stop_processing = 0;
		do {
			sysret = poll(fds, numsocks, 1000);
			if (sysret == -1 && errno != EINTR) {
				errlog("poll failed: %s\n", strerror(errno));
				retv = 600;
				goto z_exit;
			} else if (sysret == -1 && errno == EINTR)
				errlog("\n");
			else if (sysret == 0)
				continue;
			
			if (fds[0].revents) {	
				buff = dhcp_pool_next(pool);
				process_packet(fds[0].fd, buff);
				fds[0].revents = 0;
			}
			if (fds[1].revents) {	
				buff = dhcp_pool_next(pool);
				process_packet(fds[1].fd, buff);
				fds[1].revents = 0;
			}
			fds[0].revents = 0;
			fds[1].revents = 0;
		} while (!stop_processing);
		fds_exit(fds);
		if (loginfo.logf)
			fclose(loginfo.logf);
	} while (reconfig);

x_exit:
	munmap(pool, sizeof(dhcp_pool_t));
z_exit:
	return retv;
}
