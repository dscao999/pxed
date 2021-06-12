#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include "dhcp.h"

static const uint8_t dhcp_cookie[] = {99, 130, 83, 99};
static const char PXE_ID[] = "PXEClient";

int dhcp_valid(const struct dhcp_data *dhdat)
{
	if (dhdat->len < sizeof(struct dhcp_packet))
		return 0;
	return memcmp(dhdat->pkt.header.magic_cookie, dhcp_cookie, 4) == 0;
}

int dhcp_pxe(const struct dhcp_data *dhdat)
{
	const struct dhcp_option *cls;
	int retv = 0;

	retv = dhcp_valid(dhdat);
	if (!retv)
		return retv;
	retv = 0;
	cls = dhcp_option_search(dhdat, DHCP_CLASS);
	if (cls && cls->len == 32)
		retv = memcmp(cls->val, PXE_ID, sizeof(PXE_ID) - 1) == 0;
	return retv;
}

const struct dhcp_option *
dhcp_option_search(const struct dhcp_data *dhdat, int opt)
{
	const struct dhcp_option *option;;
	const struct dhcp_packet *pkt = &dhdat->pkt;
	int len = dhdat->len;

	option = dhdat->pkt.options;
	do {
		if (option->code == opt)
			break;
		option = dhcp_option_cnext(option);
	} while (option != NULL && ((char *)option - (char *)pkt) < len);
	if (option && ((char *)option - (char *)pkt) >= len)
		option = NULL;

	return option;
} 

static int llog(const char *format, ...)
{
	va_list ap;
	int len;

	va_start(ap, format);
	len = vprintf(format, ap);
	va_end(ap);
	return len;
}

static inline void dhcp_echo_ip(const unsigned int ip)
{
	llog("%d.%d.%d.%d", ip & 0x0ff, (ip >> 8) & 0x0ff,
			(ip >> 16) & 0x0ff, (ip >> 24) & 0x0ff);
}

static inline void dhcp_echo_chaddr(const uint8_t chaddr[16])
{
	int i;
	const uint8_t *ch;

	llog("DHCP chaddr:");
	for (i = 0, ch = chaddr; i < 16; i++, ch++)
		llog(" %02hhX", *ch);
	llog("\n");
}

static int dhcp_echo_head(const struct dhcp_packet *dhpkt)
{
	const struct dhcp_head *hdr = &dhpkt->header;

	if (hdr->op == DHCP_REQ)
		llog("A Boot Request Packet.\n");
	else if (hdr->op == DHCP_REP)
		llog("A Boot Reply Packet.\n");
	llog("OP: %02hhX HType: %02hhX HLen: 3%hhd Hoops: %2hhd\n",
			hdr->op, hdr->htype, hdr->hlen, hdr->hops);
	llog("XID: %08X\n", hdr->xid);
	llog("Secs: %hd, Flags: %hX\n", hdr->secs, hdr->flags);
	llog("Client IP: ");
	dhcp_echo_ip(hdr->ciaddr);
	llog(" Your IP: ");
	dhcp_echo_ip(hdr->yiaddr);
	llog(" Server IP: ");
	dhcp_echo_ip(hdr->siaddr);
	llog(" Gate Way: ");
	dhcp_echo_ip(hdr->giaddr);
	llog("\n");

	dhcp_echo_chaddr(hdr->chaddr);
	llog("Bootstrap Server: %s\n", hdr->sname);
	llog("  Bootstrap File: %s\n", hdr->bootfile);

	llog("Cookie: %hhu.%hhu.%hhu.%hhu\n", hdr->magic_cookie[0],
			hdr->magic_cookie[1], hdr->magic_cookie[2],
			hdr->magic_cookie[3]);
	return sizeof(struct dhcp_head);
}

static inline int dhcp_opt2str(char *buf, int maxlen,
		const uint8_t *str, int len)
{
	int mlen;

	mlen = maxlen - 1 < len ? maxlen - 1 : len;
	if (mlen < len)
		fprintf(stderr, "Option string size too big: %d - %d\n", maxlen, len);
	memcpy(buf, str, mlen);
	*(buf+mlen) = 0;
	return mlen;
}

static int dhcp_echo_pxe_option(const struct dhcp_option *opt)
{
	int len, i, idx, numips, bid, desclen, maxlen;
	char *buf;

	maxlen = 128;
	buf = malloc(maxlen);
	len = 0;
	switch(opt->code) {
	case PXE_END:
		llog("PXE Option Ends(%hhu).\n", opt->code);
		len = 1;
		break;
	case DHCP_PAD:
		len = 1;
		break;
	case PXE_DISCTL:
		llog("Discovery Control(%hhu): %02hhX\n", opt->code,
				opt->val[0]);
		break;
	case PXE_BOOTSVR:
		llog("PXE Boot Servers:\n");
		idx = 0;
		do {
			bid = ((unsigned int)opt->val[idx] << 8) | opt->val[idx+1];
			llog("\t\tBoot ID: %04X\n", bid);
			idx += 2;
			numips = opt->val[idx];
			for (i = 0; i < numips; i++) {
				llog("\t\t\t%hhu.%hhu.%hhu.%hhu\n",
						opt->val[idx+1],
						opt->val[idx+2],
						opt->val[idx+3],
						opt->val[idx+4]);
				idx += 4;
			}
		} while (++idx < opt->len);
		break;
	case PXE_BOOTMENU:
		llog("PXE Boot Menu:\n");
		idx = 0;
		do {
			bid = ((unsigned int)opt->val[idx] << 8)|opt->val[idx+1];
			llog("\t\tBoot ID: %04X", bid);
			idx += 2;
			desclen = opt->val[idx];
			maxlen = dhcp_opt2str(buf, maxlen, opt->val+idx+1, desclen);
			llog(" Menu: %s\n", buf);
			idx += desclen + 1;
		} while (idx < opt->len);
		break;
	case PXE_BOOTPROMPT:
		llog("PXE Boot Prompt, Timeout: %hhd", opt->val[0]);
		maxlen = dhcp_opt2str(buf, maxlen, opt->val+1, opt->len - 1);
		llog(" Prompt: %s\n", buf);
		break;
	default:
		llog("Option: %u, Length: %u, Vals:", opt->code,
				opt->len);
		for (i = 0; i < opt->len; i++)
			llog(" %02hhX", opt->val[i]);
		llog("\n");
		break;
	}

	if (len == 0)
		len = opt->len + sizeof(struct dhcp_option) - 1;
	free(buf);
	return len;
}

static int dhcp_echo_option(const struct dhcp_option *opt)
{
	int len, venlen, i, maxlen;
	char *buf;
	unsigned int arch;
	const struct dhcp_option *inn;

	maxlen = 128;
	buf = malloc(maxlen);

	len = 0;
	switch(opt->code) {
	case DHCP_PAD:
		len = 1;
		break;
	case DHCP_NETMASK:
		assert(opt->len == 4);
		llog("Subnet Mask: %hhu.%hhu.%hhu.%hhu\n", opt->val[0],
				opt->val[1], opt->val[2], opt->val[3]);
		break;
	case DHCP_CLNAME:
		maxlen = dhcp_opt2str(buf, maxlen, opt->val, opt->len);
		llog("Client Host Name: %s\n", buf);
		break;
	case DHCP_VENDOR:
		inn = (const struct dhcp_option *)opt->val;
		llog("Vendor Options: \n");
		venlen = 0;
		while (inn) {
			llog("\t");
			venlen += dhcp_echo_pxe_option(inn);
			inn = dhcp_option_cnext(inn);
		}
		assert(opt->len == venlen);
		break;
	case DHCP_LTIME:
		llog("DHCP Lease Time: %u\n", (opt->val[0] << 24) |
				(opt->val[1] << 16) | (opt->val[2] << 8) |
				opt->val[3]);
		break;
	case DHCP_MSGTYPE:
		llog("Message Type: ");
		switch(opt->val[0]) {
		case DHCP_DISCOVER:
			llog("DHCP Discover");
			break;
		case DHCP_OFFER:
			llog("DHCP Offer");
			break;
		case DHCP_REQUEST:
			llog("DHCP Request");
			break;
		case DHCP_DECLINE:
			llog("DHCP Decline");
			break;
		case DHCP_ACK:
			llog("DHCP Ack");
			break;
		case DHCP_NACK:
			llog("DHCP No Ack");
			break;
		case DHCP_RELEASE:
			llog("DHCP Release");
			break;
		case DHCP_INFORM:
			llog("DHCP Inform");
			break;
		default:
			llog("Unknown");
			break;
		}
		llog("\n");
		break;
	case DHCP_SVRID:
		llog("Server ID: %hhu.%hhu.%hhu.%hhu\n", opt->val[0],
				opt->val[1], opt->val[2], opt->val[3]);
		break;
	case DHCP_MAXLEN:
		llog("Max DHCP Message Length: %u\n",
				(int)((opt->val[0] << 8) | opt->val[1]));
		break;
	case DHCP_CLASS:
		maxlen = dhcp_opt2str(buf, maxlen, opt->val, opt->len);
		llog("Class ID: %s\n", buf);
		break;
	case DHCP_CMUID:
	case DHCP_CUUID:
		llog("Client UUID: code->%hhu type->%hhu",
				opt->code, opt->val[0]);
		for (i = 1; i < 17; i++)
			llog(" %02hhX", opt->val[i]);
		llog("\n");
		break;
	case DHCP_CLARCH:
		arch = (opt->val[0] << 8) | opt->val[1];
		llog("Client Arch: %u\n", arch);
		break;
	case DHCP_END:
		len = 1;
		llog("DHCP Message End(%hhu).\n", opt->code);
		break;
	case DHCP_SVRNAME:
		llog("Option Server Name: ");
		maxlen = dhcp_opt2str(buf, maxlen, opt->val, opt->len);
		llog("%s\n", buf);
		break;
	case DHCP_BOOTFILE:
		llog("Option Boot File: ");
		maxlen = dhcp_opt2str(buf, maxlen, opt->val, opt->len);
		llog("%s\n", buf);
		break;
	default:
		llog("Option: %u, Length: %u, Vals:", opt->code,
				opt->len);
		for (i = 0; i < opt->len; i++)
			llog(" %02hhX", opt->val[i]);
		llog("\n");
		break;
	}
	free(buf);
	if (len == 0)
		len = opt->len + sizeof(struct dhcp_option) - 1;
	return len;
}

int dhcp_echo_packet(const struct dhcp_data *dhdat)
{
	const struct dhcp_packet *dhcp;
	const struct dhcp_option *opt;
	struct timespec ctm;
	int len;

	dhcp = &dhdat->pkt;
	clock_gettime(CLOCK_MONOTONIC_COARSE, &ctm);
	llog("======================Time Stamp:%09lu.%03lu", ctm.tv_sec, ctm.tv_nsec / 1000000);
	llog("======================\n");
	if (!dhcp_valid(dhdat)) {
		printf("Not a valid DHCP packet!\n");
		return dhdat->len;
	}

	len = dhcp_echo_head(dhcp);
	if (dhdat->len == sizeof(struct dhcp_packet))
		return dhdat->len;
	opt = dhcp->options;
	while (opt) {
		len += dhcp_echo_option(opt);
		opt = dhcp_option_cnext(opt);
	}
	return len;
}
