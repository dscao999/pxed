#ifndef DHCP_DSCAO__
#define DHCP_DSCAO__

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

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

struct dhcp_head {
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
	char sname[64];
	char bootfile[128];
	uint8 magic_cookie[4];
};

struct __attribute__((aligned(1))) dhcp_option {
	uint8 code;
	uint8 len;
	uint8 val[0];
};

struct __attribute__((aligned(8))) dhcp_packet {
	struct dhcp_head header;
	struct dhcp_option options[0];
};

struct dhcp_data {
	unsigned short len;
	unsigned short maxlen;
	unsigned short pad[2];
	struct dhcp_packet dhpkt;
};

int dhcp_valid(const struct dhcp_data *dhdat);
int dhcp_pxe(const struct dhcp_data *dhdat);

static inline
const struct dhcp_option *dhcp_option_cnext(const struct dhcp_option *option)
{
	const struct dhcp_option *cnext = NULL;

	if (option->code == DHCP_PAD)
		cnext = (const void *)option + 1;
	else if (option->code == DHCP_END)
		cnext = NULL;
	else
		cnext = (const void *)(option + 1) + option->len;
	return cnext;
}

static inline
struct dhcp_option *dhcp_option_next(struct dhcp_option *option)
{
	struct dhcp_option *next = NULL;

	if (option->code == DHCP_PAD)
		next = (void *)option + 1;
	else if (option->code == DHCP_END)
		next = NULL;
	else
		next = (void *)(option + 1) + option->len;
	return next;
}

const struct dhcp_option *
dhcp_option_search(const struct dhcp_data *dhdat, int opt);
void dhcp_echo_packet(const struct dhcp_data *dhdat);

#endif /* DHCP_DSCAO__ */
