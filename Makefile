
ifeq ($(ARCH),ARM)
	CC := arm-elf-linux-gnueabi-gcc
endif

.PHONEY:	all clean release

CFLAGS = -W -Wall -D_GNU_SOURCE -g
LDFLAGS = -g

all:	pxed retv pxem conftx

conftx: conf_test.o  pxed_config.tab.o lex.yy.o miscs.o
	$(LINK.o) $^ -o $@

pxem:	pxe_monitor.o dhcp.o miscs.o
	$(LINK.o) $^ -o $@

pxed:	pxed.o dhcp.o miscs.o
	$(LINK.o) $^ -o $@

retv:	retrieve.o dhcp.o
	$(LINK.o) $^ -o $@

lex.yy.o: lex.yy.c pxed_config.tab.h

lex.yy.c: pxed_config.lex
	flex	pxed_config.lex

pxed_config.tab.c pxed_config.tab.h: pxed_config.y
	bison -d pxed_config.y

clean:
	rm -f pxed conftx pxem retv *.o
	rm -f pxed_config.tab.c lex.yy.c pxed_config.tab.h

release:	CFLAGS += -DNDEBUG -O2

release:	LDFLAGS += -O2

release:	all
