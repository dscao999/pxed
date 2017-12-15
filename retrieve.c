#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "misc.h"
#include "dhcp.h"

static inline int retrieve_packet (char *packet, FILE *flog)
{
        uint32_t len;
        int pktlen, bytes;
        if (flog == NULL) return 0;
        fread (&len, sizeof (len), 1, flog);
        if (feof (flog)) return 0;
        pktlen = ntohl (len);
        bytes = fread (packet, 1, pktlen, flog);
        if (bytes != pktlen) {
                errlog("Corrupted log!\n");
                bytes = -1;
        }
        return bytes;
}

static char buffer[1600];

int main(int argc, char *argv[])
{
	int retv, num;
	char *logfile;
	FILE *inf;
	dhcp_buff_t pkt;

	retv = 0;
	if (argc > 1) logfile = argv[1];
	else {
		errlog("Usage: retv logfile\n");
		retv = 4;
		goto z_exit;
	}
	pkt.maxlen = sizeof(buffer);
	pkt.packet = (dhcp_packet_t *)buffer;
	
	inf = fopen(logfile, "rb");
	if (!inf) {
		errlog("Cannot open %s: %s\n", logfile, strerror(errno));
		retv = 8;
		goto z_exit;
	}

	while ((num = retrieve_packet((char *)pkt.packet, inf)) > 0) {
		pkt.len = num;
		dhcp_dump_packet(&pkt, stdout);
	}

	fclose(inf);
z_exit:
	return retv;
}
