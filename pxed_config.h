#ifndef PXED_CONFIG_DSCAO__
#define PXED_CONFIG_DSCAO__

#define MAX_NUM_ITEMS 32

enum client_arch {
	X86_64_EFI = 9,
	IA64_EFI = 2,
        I386_BIOS = 0,
        ARM_EFI = 7,
	AARCH64_EFI = 8
};

struct boot_item {
	enum client_arch clarch;
	char desc[64];
	char bootfile[128];
};

struct boot_serv {
        int tmout;
        char prompt[32];
	char logfile[128];
	struct boot_item bitems[MAX_NUM_ITEMS];
};

extern const struct boot_serv *bserv;

#endif /* PXED_CONFIG_DSCAO__ */
