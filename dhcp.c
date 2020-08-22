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
	return len;
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

static int dhcp_echo_option(const struct dhcp_option *opt)
{
	int len, i;
	char *buf;

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
		buf = malloc(opt->len + 1);
		memcpy(buf, opt->val, opt->len);
		*(buf+opt->len) = 0;
		len = llog("Client Host Name: %s\n", buf);
		free(buf);
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
/*

	option = dhcp_option_search(dhcp_buff, DHCLASS);
	if (!option || option->len < 9 || 
		memcmp(option->vals, "PXEClient", 9) != 0) {
		outlog(outf, "Not a PXE boot packet!\n");
		dhcp_dump_macaddr(dhcp, outf);
		return;
	}
	get_datetime(date, sizeof(date));
	outlog(outf, "\n%s: ", date);
	if (dhcp->op == 1)
		outlog(outf, "Boot Request Packet");
	else if (dhcp->op == 2)
		outlog(outf, "Boot Reply Packet");
	else
		outlog(outf, "A Unknown Packet");
	outlog(outf, " length: %d\n", len);

	option = (dhcp_option_t *)dhcp->options;
	pos = ((void *)option - (void *)dhcp);
	while (option->code != DHEND && pos < len) {
		dump_option(option, 1, outf);
		option = dhcp_option_next(option);
		pos = ((void *)option - (void *)dhcp);
	}

	option = dhcp_pxe_request(dhcp_buff);
	if (option) {
		if (option->vals[0] == 1)
			outlog(outf, "A PXE discover packet!\n");
		else if (option->vals[0] == 3)
			outlog(outf, "A PXE request packet!\n");
		option = dhcp_option_search(dhcp_buff, DHCLASS);
		memcpy(string, (const char *)option->vals, option->len);
		string[option->len] = 0;
		outlog(outf, "PXE Mark: %s\n", string);
	}
}*/
