#ifndef DHCP_DSCAO__
#define DHCP_DSCAO__
#include <stdint.h>
#include <time.h>

#define DHCP_REQ	1
#define DHCP_REP	2

#define DHCP_DISCOVER	1
#define DHCP_OFFER	2
#define DHCP_REQUEST	3
#define DHCP_DECLINE	4
#define DHCP_ACK	5
#define DHCP_NACK	6
#define DHCP_RELEASE	7
#define DHCP_INFORM	8

enum dhcp_code {DHCP_PAD = 0, DHCP_NETMASK = 1, DHCP_CLNAME = 12,
	DHCP_VENDOR = 43, DHCP_LTIME = 51, DHCP_MSGTYPE = 53, DHCP_SVRID = 54,
	DHCP_MAXLEN = 57, DHCP_CLASS = 60, DHCP_CUUID = 61, DHCP_SVRNAME = 66,
	DHCP_BOOTFILE = 67, DHCP_CLARCH = 93, DHCP_CMUID = 97, DHCP_END = 255 };
enum pxe_code {PXE_DISCTL = 6, PXE_BOOTSVR = 8, PXE_BOOTMENU = 9,
	PXE_BOOTPROMPT = 10, PXE_BOOTITEM = 71, PXE_END = 255};

struct dhcp_head {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	char sname[64];
	char bootfile[128];
	uint8_t magic_cookie[4];
};

struct __attribute__((aligned(1))) dhcp_option {
	uint8_t code;
	uint8_t len;
	uint8_t val[1];
};

struct __attribute__((aligned(8))) dhcp_packet {
	struct dhcp_head header;
	struct dhcp_option options[1];
};

struct dhcp_data {
	uint16_t len;
	uint16_t maxlen;
	struct dhcp_packet pkt;
};

int dhcp_valid(const struct dhcp_data *dhdat);
int dhcp_pxe(const struct dhcp_data *dhdat);

static inline
const struct dhcp_option *dhcp_option_cnext(const struct dhcp_option *option)
{
	const struct dhcp_option *cnext = NULL;

	if (option->code == DHCP_PAD)
		cnext = (const struct dhcp_option *)((const char *)option + 1);
	else if (option->code == DHCP_END)
		cnext = NULL;
	else
		cnext = (const struct dhcp_option *)((const char *)(option + 1)
				+ option->len - 1);
	return cnext;
}

static inline
struct dhcp_option *dhcp_option_next(struct dhcp_option *option)
{
	struct dhcp_option *next = NULL;

	if (option->code == DHCP_PAD)
		next = (struct dhcp_option *)((char *)option + 1);
	else if (option->code == DHCP_END)
		next = NULL;
	else
		next = (struct dhcp_option *)((char *)(option + 1) +
				option->len - 1);
	return next;
}

const struct dhcp_option *
dhcp_option_search(const struct dhcp_data *dhdat, int opt);
int dhcp_echo_packet(const struct dhcp_data *dhdat, time_t ctm);

#endif /* DHCP_DSCAO__ */
