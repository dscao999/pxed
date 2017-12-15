#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "dhcp.h"

void dhcp_dump_macaddr(const dhcp_packet_t *packet, FILE *outf)
{
	int i;

	outlog(outf, "mac address: ");
	for (i = 0; i < packet->hlen - 1; i++)
		outlog(outf, "%X:", packet->chaddr[i]);
	outlog(outf, "%X\n", packet->chaddr[i]);
}

static void dump_option(const dhcp_option_t *opt, int verbose, FILE *outf)
{
        int i;
	const uint8 *bytes;
	const dhcp_option_t *vendor_opts;

	if (opt->code == 0) return;

        outlog(outf, "option: %d, len: %d\n", opt->code, opt->len);
        if (verbose && opt->len) {
		if(opt->code != 43) {
	                outlog(outf, "   option bytes: ");
			for (i = 0; i < opt->len; i++) {
				outlog(outf, "%x ", opt->vals[i]);
				if ((i+1) % 25 == 0) outlog(outf, "\n      ");
			}
			if (i % 25 != 0) outlog(outf, "\n");
		} else {
			outlog(outf, "begin vendor options: \n", outf);
			bytes = opt->vals;
			vendor_opts = (dhcp_option_t *)bytes;
			do {
				dump_option(vendor_opts, verbose, outf);
				bytes = vendor_opts->vals + vendor_opts->len;
				vendor_opts = (dhcp_option_t *)bytes;
			} while (vendor_opts->code != 255 &&
				 bytes < opt->vals + opt->len);
			outlog(outf, "end vendor options\n");
		}
			
        }

}

const dhcp_option_t *dhcp_option_search(const dhcp_buff_t *dhcp, int opt)
{
	const dhcp_option_t *option;;
	int found;

	found = 0;
	option = (const dhcp_option_t *)dhcp->packet->options;
	do {
		if (option->code == opt) {
			found = 1;
			break;
		}
		option = dhcp_option_next(option);
	} while ((void *)option - (void *)dhcp->packet < dhcp->len
			&& option->code != 255);
	if (!found) option = NULL;

	return option;
} 

const dhcp_option_t *dhcp_vendopt_search(const dhcp_buff_t *buff, int opt)
{
	const dhcp_option_t *option, *vopt;
	int found = 0;

	option = NULL;
	vopt = dhcp_option_search(buff, DHVENDOR);
	if (!vopt) goto z_exit;

	option = (dhcp_option_t *)vopt->vals;
	do {
		if (option->code == opt) {
			found = 1;
			break;
		}
		option = dhcp_option_next(option);
	} while ((void *)option - (void *)vopt->vals < vopt->len &&
		option->code != 255);
	if (!found) option = NULL;

z_exit:
	return option;
}

int dhcp_get_uuid(const dhcp_buff_t *buff, uint8 uuid[16])
{
	int retv;
	const dhcp_option_t *option;

	retv = 0;
	option = dhcp_option_search(buff, DHCMUID);
	if (option && option->vals[0] == 0) {
		retv = 1;
		memcpy(uuid, option->vals+1, 16);
	}
	return retv;
}
		
const dhcp_option_t *dhcp_pxe_request(const dhcp_buff_t *dhcp)
{
	const dhcp_option_t *option, *retopt;

	retopt = NULL;
	if (!dhcp_valid_packet(dhcp->packet) ||
		dhcp->packet->op != 1) goto z_exit;
	retopt = dhcp_option_search(dhcp, DHMSGTYPE);
	if (retopt->vals[0] != 1 && retopt->vals[0] != 3) {
		retopt = NULL;
		goto z_exit;
	}
	option = dhcp_option_search(dhcp, DHCLASS);
	if (!option || option->len < 9 ||
		memcmp(option->vals, "PXEClient", 9) != 0)
		retopt = NULL;

z_exit:
	return retopt;
}

void dhcp_dump_packet(const dhcp_buff_t *dhcp_buff, FILE *outf)
{
	const dhcp_option_t *option;
	const dhcp_packet_t *dhcp;
	char string[48];
	int pos, len;
	char date[48];

	len = dhcp_buff->len;
	dhcp = dhcp_buff->packet;
	if (!dhcp_valid_packet(dhcp)) {
		outlog(outf, "Not a valid DHCP packet!\n");
		dhcp_dump_macaddr(dhcp, outf);
		return;
	}
	option = dhcp_option_search(dhcp_buff, DHCLASS);
	if (!option || option->len < 9 || 
		memcmp(option->vals, "PXEClient", 9) != 0) {
		outlog(outf, "Not a PXE boot packet!\n");
		dhcp_dump_macaddr(dhcp, outf);
		return;
	}
	get_datetime(date, sizeof(date));
	outlog(outf, "\n%s: ", date);
	if (dhcp->op == 1)
		outlog(outf, "Boot Request Packet");
	else if (dhcp->op == 2)
		outlog(outf, "Boot Reply Packet");
	else
		outlog(outf, "A Unknown Packet");
	outlog(outf, " length: %d\n", len);

	option = (dhcp_option_t *)dhcp->options;
	pos = ((void *)option - (void *)dhcp);
	while (option->code != DHEND && pos < len) {
		dump_option(option, 1, outf);
		option = dhcp_option_next(option);
		pos = ((void *)option - (void *)dhcp);
	}

	option = dhcp_pxe_request(dhcp_buff);
	if (option) {
		if (option->vals[0] == 1)
			outlog(outf, "A PXE discover packet!\n");
		else if (option->vals[0] == 3)
			outlog(outf, "A PXE request packet!\n");
		option = dhcp_option_search(dhcp_buff, DHCLASS);
		memcpy(string, (const char *)option->vals, option->len);
		string[option->len] = 0;
		outlog(outf, "PXE Mark: %s\n", string);
	}
}
