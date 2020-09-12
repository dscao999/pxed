#ifndef PXED_CONFIG_DSCAO__
#define PXED_CONFIG_DSCAO__

#define MAX_PATH	128
#define MAX_PHRASE	64
#define MAX_NUM_ITEMS 32

enum client_arch {
        X86_BIOS = 0,
	NEC_PC98 = 1,
	IA64_EFI = 2,
	ALPHA_DEC = 3,
	X86_ARC = 4,
	INTEL_LEAN = 5,
	X86_EFI = 6,
        X86_64_EFI = 7,
	XSCALE_EFI = 8,
	EFI_BC = 9
};

struct boot_item {
	char desc[MAX_PHRASE];
	char bootfile[MAX_PATH];
	enum client_arch clarch;
	unsigned short svrtyp;
};

struct boot_option {
	unsigned int bvip;
        unsigned short timeout;
        char prompt[MAX_PHRASE];
	struct boot_item bitems[MAX_NUM_ITEMS];
};

extern const struct boot_option *bopt;

int pxed_config(const char *confname);

#endif /* PXED_CONFIG_DSCAO__ */
