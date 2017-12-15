#ifndef DHCP_DSCAO__
#define DHCP_DSCAO__
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include "misc.h"

#define PACKET_LEN      1536

enum dh_options {DHPAD = 0, DHCLASS = 60, DHSVRNAME = 66, DHBOOTFILE = 67,
	DHVENDOR = 43, DHMSGTYPE = 53, DHSVRID = 54, DHMAXLEN = 57, DHCUUID = 61,
	DHCLARCH = 93, DHCMUID = 97, DHEND = 255 };
enum dhpxe_options {PXEDISCTL = 6, PXEBOOTSVR = 8, PXEBOOTMENU = 9,
	PXEBOOTPROMPT = 10, PXEBOOTITEM = 71, PXEEND = 255};

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

typedef union noalign16 {
	uint8 pad[2];
	uint16 val;
} noalign16_t;

typedef struct dhcp_packet {
	uint8 op;
	uint8 htype;
	uint8 hlen;
	uint8 hops;
	uint32 xid;
	uint16 secs;
	uint16 flags;
	uint32 ciaddr;
	uint32 yiaddr;
	uint32 siaddr;
	uint32 giaddr;
	uint8 chaddr[16];
	char   sname[64];
	char   bootfile[128];
	uint8 magic_cookie[4];
	uint8 options[1];
} dhcp_packet_t;
typedef struct dhcp_option {
	uint8 code;
	uint8 len;
	uint8 vals[5];
} dhcp_option_t;

static inline dhcp_option_t *dhcp_option_next(const dhcp_option_t *option)
{
	dhcp_option_t *retp;

	retp = NULL;
	if (option->code == 0)
		retp = (dhcp_option_t *) (&option->code + 1);
	else if (option->code != 255)
		retp = (dhcp_option_t *)(option->vals + option->len);
	return retp;
}

typedef struct dhcp_buff {
        dhcp_packet_t *packet;
        int len, maxlen;
} dhcp_buff_t;

static inline void dhcp_buff_init(dhcp_buff_t *buf)
{
	buf->len = 0;
	buf->maxlen = PACKET_LEN;
}
const dhcp_option_t *dhcp_option_search(const dhcp_buff_t *dhcp, int opt);
const dhcp_option_t *dhcp_vendopt_search(const dhcp_buff_t *dhcp, int opt);
const dhcp_option_t *dhcp_pxe_request(const dhcp_buff_t *dhcp);
int dhcp_get_uuid(const dhcp_buff_t *buff, uint8 uuid[16]);

void dhcp_dump_macaddr(const dhcp_packet_t *packet, FILE *outf);
void dhcp_dump_packet(const dhcp_buff_t *dhcp, FILE *outf);
static inline void dhcp_dump_raw_packet(const dhcp_buff_t *dhcp,
		const char *fname)
{
	FILE *outf;

	outf = fopen(fname, "wb");
	if (outf) {
		errlog("Raw Packet dump length: %d\n", dhcp->len);
		fwrite(dhcp->packet, 1, dhcp->len, outf);
	}
	fclose(outf);
}

static inline int dhcp_valid_packet(const dhcp_packet_t *dhcp)
{
	int retv;

	retv = 0;
	if (dhcp->magic_cookie[0] == 99 &&
	    dhcp->magic_cookie[1] == 130 &&
	    dhcp->magic_cookie[2] == 83 &&
	    dhcp->magic_cookie[3] == 99) retv = 1;
	return retv;
}

#endif /* DHCP_DSCAO__ */
