#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <assert.h>
#include "misc.h"
#include "dhcp.h"
#include "pxe_util.h"

#define SERVER_DISPLAY "DSCAO PXE Server V0001"

extern FILE *yyin;
extern void yyrewind(void);
extern int yyparse(void);
static pxe_config_t pxe_conf;
pxe_config_t *pconf_g;
int conferr;

void pxe_data_init(void)
{
	pconf_g = &pxe_conf;
	memset(pconf_g, 0, sizeof(pxe_config_t));
	pconf_g->m67 = 1;
}

int pxe_server_init(const char *cfg_file, const char *iface)
{
	int retv, num;
	struct ifaddrs *ifap, *curifa;
	struct sockaddr_in *sockaddr;
	struct ifreq ioreq;
	int sockd, i;
	char dates[48];
	const char *stype;
	pxe_config_t *pconf = pconf_g;

	retv = 0;

	yyrewind();
	yyin = fopen(cfg_file, "rb");
	if (!yyin) {
		errlog("Cannot open configuration: %s\n", strerror(errno));
		retv = -2000;
		goto z_exit;
	}
	conferr = 0;
	num = yyparse();
	fclose(yyin);
	if (conferr || num) {
		errlog("Cannot parse configuation file: %s\n", cfg_file);
		retv = -2004;
		goto z_exit;
	} else {
		get_datetime(dates, sizeof(dates));
		errlog("%s=====Number of boot items: %d=====\n", dates, pconf->svrs);
		for (i = 0; i < pconf->svrs; i++) {
			switch(pconf->bootsvrs[i].type) {
			case X86_64_EFI:
				stype = "X86_64 EFI";
				break;
			case X86_64_BIOS:
				stype = "X86_64 BIOS";
				;
			case I386_BIOS:
				stype = "I386 BIOS";
				break;
			case I386_EFI:
				stype = "I386 EFI";
				break;
			case IA64_EFI:
				stype = "IA64 EFI";
				break;
			default:
				stype = "Unknown Type";
				break;
			}
			errlog("Type: %12s, BFile: %s, Desc: %s\n",
				stype,
				pconf->bootsvrs[i].bfile,
				pconf->bootsvrs[i].desc);
		}
	}

	sockd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sockd == -1) {
		errlog("Cannot create ip socket: %s\n", strerror(errno));
		retv = -520;
		goto z_exit;
	}
	num = getifaddrs(&ifap);
	if (num == -1) {
		errlog("Cannot get local address: %s\n", strerror(errno));
		retv = -516;
		goto y_exit;
	}
	num = 0;
	curifa = ifap;
	while (curifa && num < MAXNICS) {
		if (!(curifa->ifa_flags & IFF_UP) || !(curifa->ifa_addr)
			|| curifa->ifa_flags & IFF_LOOPBACK
			|| curifa->ifa_addr->sa_family != AF_INET
			|| curifa->ifa_flags & IFF_POINTOPOINT
			|| (iface && strcmp(iface, curifa->ifa_name) != 0)) {
			curifa = curifa->ifa_next;
			continue;
		}

		sockaddr = (struct sockaddr_in *)curifa->ifa_addr;
		pconf->macips[num].ipaddr = sockaddr->sin_addr;
		sockaddr = (struct sockaddr_in *)curifa->ifa_ifu.ifu_broadaddr;
		pconf->macips[num].bcast = sockaddr->sin_addr;
		strcpy(ioreq.ifr_name, curifa->ifa_name);
		if (ioctl(sockd, SIOCGIFHWADDR, &ioreq) == -1) {
			errlog("Cannot get mac address: %s\n", strerror(errno));
			retv = -540;
			goto x_exit;
		}
		memcpy(pconf->macips[num].macaddr, ioreq.ifr_hwaddr.sa_data, 6);

		curifa = curifa->ifa_next;
		num += 1;
	}
	if (num == 0) {
		retv = -600;
		errlog("No suitable nic port found.\n");
		goto x_exit;
	}
	pconf->nics = num;

	if (pconf->plen == 0) {
		strcpy(pconf->prompt, SERVER_DISPLAY);
		pconf->plen = strlen(pconf->prompt);
	}

	inet_pton(AF_INET, "255.255.255.255", &pconf->bcast);

x_exit:
	freeifaddrs(ifap);
y_exit:
	close(sockd);
z_exit:
	return retv;
}

int pxe_vendor_setup(dhcp_option_t *opt, int maxlen, int clarch)
{
	const pxe_config_t *pconf = pconf_g;
	int i, j, offset, matched;
	dhcp_option_t *option;
	const bootserv_t *bserv;
	const macip_addr_t *nicaddr;
	union {
		uint16 seq;
		uint8 s[2];
	} seq;

        opt->code = DHVENDOR;
	option = (dhcp_option_t *)opt->vals;

	option->code = PXEDISCTL;
	option->len = 1;
	option->vals[0] = 7;

	bserv = pconf->bootsvrs;
	option = dhcp_option_next(option);
	offset = 0;
	option->code = PXEBOOTSVR;
	matched = 0;
	for (i = 0; i < pconf->svrs; i++, bserv++) {
		if (bserv->type != clarch)
			continue;
		seq.seq = htons(bserv->seq);
		option->vals[offset] = seq.s[0];
		option->vals[offset+1] = seq.s[1];
		option->vals[offset+2] = pconf->nics;
		offset += 3;
		nicaddr = pconf->macips;
		for (j = 0; j < pconf->nics; j++) {
			memcpy(option->vals+offset, &nicaddr->ipaddr, 4);
			offset += 4;
			nicaddr++;
		}
		matched++;
	}
	option->len = offset;
	if (!matched)
		errlog("Client Type %d not supported!\n", clarch);

	option = dhcp_option_next(option);
	offset = 0;
	option->code = PXEBOOTMENU;
	bserv = pconf->bootsvrs;
	for (i = 0; i < pconf->svrs; i++, bserv++) {
		if (bserv->type != clarch)
			continue;
		seq.seq = htons(bserv->seq);
		option->vals[offset] = seq.s[0];
		option->vals[offset+1] = seq.s[1];
		option->vals[offset+2] = bserv->dlen+1;
		offset += 3;
		memcpy(option->vals+offset, bserv->desc, bserv->dlen);
		offset += bserv->dlen;
		option->vals[offset++] = 0;
		matched--;
	}
	assert(matched == 0);
	option->len = offset;

	option = dhcp_option_next(option);
	option->code = PXEBOOTPROMPT;
	option->vals[0] = pconf->timeout;
	memcpy(option->vals+1, pconf->prompt, pconf->plen);
	option->len = pconf->plen + 1;

	option = dhcp_option_next(option);
	option->code = PXEEND;

	opt->len = (uint8 *)option - opt->vals + 1;
	return opt->len;
}

int pxe_offer_make(uint8 *buff, int maxlen, int clarch)
{
	int len;
	dhcp_option_t *option;

	option = (dhcp_option_t *)buff;
        option->code = DHMSGTYPE;
        option->len = 1;
        option->vals[0] = 2;

	option = dhcp_option_next(option);
        option->code = DHCLASS;
        option->len = 9;
        memcpy(option->vals, "PXEClient", 9);

        option = dhcp_option_next(option);
	len = (uint8 *)option - buff;
        pxe_vendor_setup(option, maxlen - len, clarch);
	
	option = dhcp_option_next(option);
	option->code = DHEND;

	len = (uint8 *)option - buff + 1;
	return len;
}
