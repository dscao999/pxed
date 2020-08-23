#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include "miscs.h"
#include "dhcp.h"

static const uint8 dhcp_cookie[] = {99, 130, 83, 99};
static const char PXE_ID[] = "PXEClient";

int dhcp_valid(const struct dhcp_data *dhdat)
{
	if (dhdat->len < sizeof(struct dhcp_packet))
		return 0;
	return memcmp(dhdat->dhpkt.header.magic_cookie, dhcp_cookie, 4) == 0;
}

int dhcp_pxe(const struct dhcp_data *dhdat)
{
	const struct dhcp_option *cls;
	int retv = 0;

	cls = dhcp_option_search(dhdat, DHCP_CLASS);
	if (cls && cls->len == 32)
		retv = memcmp(cls->val, PXE_ID, sizeof(PXE_ID)) == 0;
	return retv;
}

const struct dhcp_option *
dhcp_option_search(const struct dhcp_data *dhdat, int opt)
{
	const struct dhcp_option *option;;
	const struct dhcp_packet *dhpkt = &dhdat->dhpkt;
	int found, len = dhdat->len;

	found = 0;
	option = dhdat->dhpkt.options;
	do {
		if (option->code == opt) {
			found = 1;
			break;
		}
		option = dhcp_option_cnext(option);
	} while (option != NULL && ((void *)option - (void *)dhpkt < len));
	if (!found)
		option = NULL;

	return option;
} 

static int llog(const char *fmt, ...)
{
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vprintf(fmt, ap);
	va_end(ap);
	return len+1;
}

static inline int dhcp_echo_ip(const unsigned int ip)
{
	return llog("%d.%d.%d.%d", ip & 0x0ff, (ip >> 8) & 0x0ff,
			(ip >> 16) & 0x0ff, (ip >> 24) & 0x0ff);
}

static int dhcp_echo_chaddr(const uint8 chaddr[16])
{
	int len, i;
	const uint8 *ch;

	len = llog("DHCP chaddr:");
	for (i = 0, ch = chaddr; i < 16; i++, ch++)
		len += llog(" %02hhX", *ch);
	len += llog("\n");
	return len;
}

static int dhcp_echo_sname(const char sname[64])
{
	int len, i;
	const char *ch;

	len = llog("Server Name: ");
	for (i = 0, ch = sname; i < 64 && *ch != 0; i++, ch++)
		len += llog("%c", *ch);
	len += llog("\n");
	return len;
}

static int dhcp_echo_bfile(const char bfile[128])
{
	int len, i;
	const char *ch;

	len = llog("Boot File: ");
	for (i = 0, ch = bfile; i < 128 && *ch != 0; i++, ch++)
		len += llog("%c", *ch);
	len += llog("\n");
	return len;
}

static void dhcp_echo_head(const struct dhcp_packet *dhpkt)
{
	const struct dhcp_head *hdr = &dhpkt->header;

	if (hdr->op == 1)
		llog("Boot Request Packet:\n");
	else if (hdr->op == 2)
		llog("Boot Reply Packet:\n");
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
	dhcp_echo_sname(hdr->sname);
	dhcp_echo_bfile(hdr->bootfile);

	llog("Cookie: %hhu.%hhu.%hhu.%hhu\n", hdr->magic_cookie[0],
			hdr->magic_cookie[1], hdr->magic_cookie[2],
			hdr->magic_cookie[3]);
}

static inline char *dhcp_opt2str(const struct dhcp_option *opt)
{
	char *buf;

	buf = malloc(opt->len + 1);
	memcpy(buf, opt->val, opt->len);
	*(buf+opt->len) = 0;
	return buf;
}

static int dhcp_echo_option(const struct dhcp_option *opt)
{
	int len, i;
	char *buf;
	unsigned short arch;
	const struct dhcp_option *inn;

	len = 0;
	switch(opt->code) {
	case 0:
		break;
	case 1:
		assert(opt->len == 4);
		len = llog("Subnet Mask: %hhu.%hhu.%hhu.%hhu\n", opt->val[0],
				opt->val[1], opt->val[2], opt->val[3]);
		break;
	case 12:
		buf = dhcp_opt2str(opt);
		len = llog("Client Host Name: %s\n", buf);
		free(buf);
		break;
	case 43:
		inn = (const struct dhcp_option *)opt->val;
		len = llog("Vendor Options: \n");
		while (inn) {
			llog("\t");
			len += dhcp_echo_option(inn);
			inn = dhcp_option_cnext(inn);
		}
		break;
	case 51:
		len = llog("DHCP Lease Time: %u\n", (opt->val[0] << 24) |
				(opt->val[1] << 16) | (opt->val[2] << 8) |
				opt->val[3]);
		break;
	case 53:
		len = llog("Message Type: ");
		switch(opt->val[0]) {
		case 1:
			len += llog("DHCP Discover");
			break;
		case 2:
			len += llog("DHCP Offer");
			break;
		case 3:
			len += llog("DHCP Request");
			break;
		case 4:
			len += llog("DHCP Decline");
			break;
		case 5:
			len += llog("DHCP Ack");
			break;
		case 6:
			len += llog("DHCP No Ack");
			break;
		case 7:
			len += llog("DHCP Release");
			break;
		case 8:
			len += llog("DHCP Inform");
			break;
		default:
			len += llog("Unknown");
			break;
		}
		llog("\n");
		break;
	case 54:
		len = llog("Server ID: %hhu.%hhu.%hhu.%hhu\n", opt->val[0],
				opt->val[1], opt->val[2], opt->val[3]);
		break;
	case 57:
		len = llog("Max DHCP Message Length: %u\n",
				(int)((opt->val[0] << 8) | opt->val[1]));
		break;
	case 60:
		buf = dhcp_opt2str(opt);
		len = llog("Class ID: %s\n", buf);
		free(buf);
		break;
	case 97:
	case 61:
		buf = dhcp_opt2str(opt);
		len = llog("Client UUID: %s\n", buf+1);
		free(buf);
		break;
	case 93:
		arch = (opt->val[0] << 8) | opt->val[1];
		len = llog("Client Arch: %u\n", arch);
		break;
	case 255:
		len = llog("DHCP Message End: %u\n", opt->code);
		break;
	default:
		len = llog("Option: %u, Length: %u, Vals:", opt->code,
				opt->len);
		for (i = 0; i < opt->len; i++)
			len += llog(" %02hhX", opt->val[i]);
		len += llog("\n");
		break;
	}
	return len;
}

void dhcp_echo_packet(const struct dhcp_data *dhdat)
{
	const struct dhcp_packet *dhcp;
	const struct dhcp_option *opt;

	dhcp = &dhdat->dhpkt;
	if (!dhcp_valid(dhdat)) {
		printf("Not a valid DHCP packet!\n");
		return;
	}

	dhcp_echo_head(dhcp);
	if (dhdat->len == sizeof(struct dhcp_packet))
		return;
	opt = dhcp->options;
	while (opt) {
		dhcp_echo_option(opt);
		opt = dhcp_option_cnext(opt);
	}
}
