#ifndef PXE_UTIL_DSCAO__
#define PXE_UTIL_DSCAO__
#include <arpa/inet.h>
#include "dhcp.h"

#define MAXPATH         128
#define MAXSTRING       32
#define MAXNICS         8
#define MAXSVRS         8

enum client_type_t {
	X86_64_EFI = 7,
	X86_64_BIOS = 200,
	IA64_EFI = 2,
        I386_BIOS = 0,
        I386_EFI = 9
};

typedef struct macip_addr {
        unsigned char macaddr[6];
        struct in_addr ipaddr, bcast;
} macip_addr_t;
typedef struct bootserv {
        int type, seq;
        int dlen, blen;
        char desc[MAXSTRING];
        char bfile[MAXPATH];
} bootserv_t;

typedef struct pxe_config {
        struct in_addr bcast;
        int nics, svrs, m67;
        macip_addr_t macips[MAXNICS];
        bootserv_t bootsvrs[MAXSVRS];
        int timeout;
        int plen;
        char prompt[MAXSTRING];
	char logfile[256];
} pxe_config_t;

typedef struct pxe_buff {
	uint8 *buff;
	int len, maxlen;
	int vendor_offset, vendor_len;
} pxe_buff_t;

int pxe_vendor_setup(dhcp_option_t *opt, int maxlen, int clarch);

void pxe_data_init(void);
int pxe_server_init(const char *cfg_file, const char *iface);
int pxe_offer_make(uint8 *buff, int maxlen, int clarch);

#endif /* PXE_UTIL_DSCAO__ */
