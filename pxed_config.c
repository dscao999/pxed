#include "pxe_config.h"

static struct boot_serv bootsvr;
const struct boot_serv *bsvr;

int pxe_config(const char *conf)
{
	bsvr = &bootsvr;
}
