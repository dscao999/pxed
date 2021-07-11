
ifeq ($(ARCH),ARM)
	CC := arm-elf-linux-gnueabi-gcc
endif

.PHONEY:	all clean release

CFLAGS = -pedantic -W -Wall -D_GNU_SOURCE -g -pthread
LDFLAGS = -g -pthread

#all:	pxed retv pxem conftx
all:	pxem pxe_proxy pxe_boot retrv

srcs = $(wildcard *.c)
deps = $(srcs:.c=.d)

conftx: conf_test.o  pxed_config.tab.o lex.yy.o miscs.o
	$(LINK.o) $^ -o $@

pxem:	pxe_monitor.o dhcp.o
	$(LINK.o) $^ -o $@

pxe_proxy: pxe_proxy.o dhcp.o pxed_config.tab.o lex.yy.o net_utils.o
	$(LINK.o) $^ -o $@

retrv:	retrieve.o dhcp.o
	$(LINK.o) $^ -o $@

lex.yy.c: pxed_config.lex
	flex	pxed_config.lex

pxed_config.tab.c pxed_config.tab.h: pxed_config.y
	bison -d -v pxed_config.y

clean:
	rm -f *.d
	rm -f pxed conftx pxem retv *.o pxe_proxy
	rm -f pxed_config.tab.c lex.yy.c pxed_config.tab.h

release:	CFLAGS += -DNDEBUG -O2

release:	LDFLAGS += -O2

release:	all

%.o: %.c
	$(COMPILE.c) -MMD -MP -c $< -o $@

-include $(deps)
