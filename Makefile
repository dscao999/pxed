
ifeq ($(ARCH),ARM)
	CC := arm-elf-linux-gnueabi-gcc
endif

.PHONEY:	all clean release

CFLAGS = -Wall -D_GNU_SOURCE -g
LDFLAGS = -g

all:	pxed retv

pxed:	pxe_server.o pxe_util.o dhcp.o pxe_config.tab.o lex.yy.o
	$(LINK.o) $^ -o $@

retv:	retrieve.o dhcp.o
	$(LINK.o) $^ -o $@

pxe_server.o:	pxe_util.h dhcp.h misc.h
pxe_util.o:	pxe_util.h dhcp.h misc.h
dhcp.o:		dhcp.h misc.h
lex.yy.o:	pxe_config.tab.h

lex.yy.c:	pxe_config.lex
	flex	pxe_config.lex

pxe_config.tab.c pxe_config.tab.h: pxe_config.y
	bison -d pxe_config.y

clean:
	rm -f pxed retv *.o
	rm -f pxe_config.tab.c lex.yy.c

release:	CFLAGS += -DNDEBUG -O2

release:	LDFLAGS += -O2

release:	all