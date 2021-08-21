#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <string.h>
#include <netdb.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include "miscs.h"
#include "net_utils.h"

int get_first_nic(char *buf)
{
	DIR *dir;
	int retv = 0, found, sysret, len, numb, type;
	struct dirent *ent;
	char nic_syspath[128], typbuf[16];
	struct stat mst;
	static const char *netdir = "/sys/class/net";
	FILE *fin;

	dir = opendir(netdir);
	if (!dir) {
		elog("Cannot open directory %s: %s\n", netdir,
				strerror(errno));
		return retv;
	}
	errno = 0;
	found = 0;
	ent = readdir(dir);
	while (ent) {
		if ((ent->d_type & DT_LNK) == 0)
			goto next_nic;
		if (strcmp(ent->d_name, "lo") == 0)
			goto next_nic;
		strcpy(nic_syspath, netdir);
		strcat(nic_syspath, "/");
		strcat(nic_syspath, ent->d_name);
		len = strlen(nic_syspath);
		strcpy(nic_syspath+len, "/wireless");
		sysret = stat(nic_syspath, &mst);
		if (sysret == 0)
			goto next_nic;
		strcpy(nic_syspath+len, "/type");
		fin = fopen(nic_syspath, "r");
		if (!fin)
			goto next_nic;
		numb = fread(typbuf, 1, sizeof(typbuf), fin);
		fclose(fin);
		if (numb < 0)
			goto next_nic;
		typbuf[numb] = 0;
		type = atoi(typbuf);
		if (type != 1)
			goto next_nic;

		strcpy(buf, ent->d_name);
		found = 1;
		break;
next_nic:
		ent = readdir(dir);
	}
	if (found == 0)
		elog("No NIC is found.\n");
	else
		printf("Info: Bind to NIC \'%s\'\n", buf);
	return found;
}

int get_nicaddr(int sockd, const char *iface, struct in_addr *addr)
{
	struct ifreq req;
	int sysret;
	struct sockaddr_in *ipv4_addr;

	strncpy(req.ifr_name, iface, IFNAMSIZ);
	sysret = ioctl(sockd, SIOCGIFADDR, &req);
	if (sysret == -1) {
		elog("ioctl failed for %s: %s\n", iface, strerror(errno));
		return sysret;
	}
	ipv4_addr = (struct sockaddr_in *)&req.ifr_addr;
	*addr = ipv4_addr->sin_addr;
	return sysret;
}

int poll_init(struct pollfd *pfd, int port, const char *iface)
{
	int sockd, retv, brd;
	char pstr[16];
	struct addrinfo hints, *res;
	static const struct timespec itv = {.tv_sec = 0, .tv_nsec = 100000000};

	retv = 0;
	snprintf(pstr, sizeof(pstr), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	while ((retv = getaddrinfo(NULL, pstr, &hints, &res)) == EAI_AGAIN)
		nanosleep(&itv, NULL);
	if (retv != 0) {
		elog("getaddrinfo failed: %s\n", gai_strerror(retv));
		retv = -11;
		goto exit_10;
	}

	sockd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockd == -1) {
		elog("Cannot create socket: %s\n", strerror(errno));
		retv = -12;
		goto exit_20;
	}
	if (port == 67) {
		brd = 1;
		retv = setsockopt(sockd, SOL_SOCKET, SO_BROADCAST, &brd, 4);
		if (retv == -1) {
			elog("Cannot set to broadcast: %s\n", strerror(errno));
			retv = -13;
			goto exit_30;
		}
	}
	retv = setsockopt(sockd, SOL_SOCKET, SO_BINDTODEVICE, iface,
			strlen(iface)+1);
	if (retv == -1) {
		elog("Cannot bind socket to device %s: %s\n", iface,
				strerror(errno));
		retv = -14;
		goto exit_30;
	}

	pfd->fd = sockd;
	pfd->revents = 0;
	pfd->events = POLLIN;
	if (bind(sockd, res->ai_addr, res->ai_addrlen) == -1) {
		elog("Cannot bind socket: %s\n", strerror(errno));
		retv = -errno;
		goto exit_30;
	}
	freeaddrinfo(res);
	return retv;

exit_30:
	close(pfd->fd);
exit_20:
	freeaddrinfo(res);
exit_10:
	return retv;
}
