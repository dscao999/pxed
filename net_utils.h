#ifndef NET_UTILS_DSCAO__
#define NET_UTILS_DSCAO__
#include <arpa/inet.h>
#include <poll.h>

int get_first_nic(char *buf);
int get_nicaddr(int sockd, const char *iface, struct in_addr *addr);
int poll_init(struct pollfd *pfd, int port, const char *iface);

#endif /* NET_UTILS_DSCAO__ */
