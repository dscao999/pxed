#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include "miscs.h"
#include "dhcp.h"

static char buffer[1600];

int main(int argc, char *argv[])
{
	int retv, bytes;
	char *logfile;
	FILE *inf;
	struct dhcp_data *dhdat;
	time_t ctm;

	retv = 0;
	if (argc > 1)
		logfile = argv[1];
	else {
		elog("Usage: %s logfile\n", argv[0]);
		retv = 4;
		goto z_exit;
	}
	dhdat = (struct dhcp_data *)buffer;
	dhdat->maxlen = sizeof(buffer) - 4;
	
	inf = fopen(logfile, "rb");
	if (!inf) {
		elog("Cannot open %s: %s\n", logfile, strerror(errno));
		retv = 8;
		goto z_exit;
	}

	fread(&ctm, sizeof(ctm), 1, inf);
	while (!feof(inf)) {
		fread(&dhdat->len, sizeof(dhdat->len), 1, inf);
	        bytes = fread(&dhdat->pkt, 1, dhdat->len, inf);
		if (bytes != dhdat->len) {
			elog("Corrutped PXE packet log.\n");
			break;
		}
		dhcp_echo_packet(dhdat, ctm);
		fread(&ctm, sizeof(ctm), 1, inf);
	}

	fclose(inf);
z_exit:
	return retv;
}
