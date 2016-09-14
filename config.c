#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <stdarg.h>     /* va_list, va_start, va_arg, va_end */
#include <string.h>
#include <ctype.h>
#include <getopt.h>

#include <rte_ip.h>

#include "config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

static config_t config;
static config_t *conf = &config;

/* default parameters */
static config_t config = {
	.test = FIXRATE,

	.stats_interval = 3,
	.duration = 0,
	.pps = 0,
	.pts = 0,
	.step = 1,
	.save_latencies = 0,

	.num_ports = 2,
	.num_tx_queues = 1,
	.num_rx_queues = 1,
	.burst_size = 32,

	.packet_size = 64,
	.dst_macs_are_set = 0,
	.ipv6 = 0,
	.arp_delay = 0,

	.src_ip4 = {IPv4_NS(172, 16, 0, 1), IPv4_NS(172, 16, 1, 1)},
	.dst_ip4 = {IPv4_NS(172, 16, 0, 2), IPv4_NS(172, 16, 1, 2)},
	.src_ip6 = {
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
	.dst_ip6 = {
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb},
	.udp_port = 1024,

};

config_t *get_config(void)
{
	return &config;
}

static void print_usage(void)
{
	printf("Documentation is available at https://wiki.cisco.com/display/VPP/lw-pktgn+documentation\n");
}

#define die(err, ...) { \
	printf(err, ##__VA_ARGS__); \
	printf("\nUse --help for syntax\nExiting !\n\n"); \
	exit(-1);}

/* verify if *value contains numeric value */
static int verify_int(char *value)
{
	int x = 0;
	int len = strlen(value);

	while(x < len) {
		if(!isdigit(*(value+x)))
			die("invalid numeric value %s !", value);
		++x;
	}

	return atoi(value);
}

/* verify if *value contains numeric value */
static uint64_t verify_uint64(char *value)
{
	int x = 0;
	int len = strlen(value);
	char * pEnd;

	while(x < len) {
		if(!isdigit(*(value+x)))
			die("invalid numeric value %s !", value);
		++x;
	}

	return (uint64_t)strtoull(value, &pEnd, 10);
}

/* parse MAC addrs separated with "," and store it into config.dst_mac */
static int parse_macs(char *str)
{
	uint8_t *bytes = (uint8_t *)&config.dst_mac[0];
	int values[6 * 2];
	int i;

	if (sscanf(str, "%x:%x:%x:%x:%x:%x,%x:%x:%x:%x:%x:%x",
					  &values[0], &values[1], &values[2],
					  &values[3], &values[4], &values[5],
					  &values[6], &values[7], &values[8],
					  &values[9], &values[10], &values[11]) == 12)
	{
		/* convert to uint8_t */
		for (i = 0; i < 12; ++i)
			bytes[i] = (uint8_t) values[i];

		return 0;
	}
	return 1;
}

/* parse ipv4 or ipv6 ip addr separated with "," if src_dst == 1 ips are stored into config.src_ip*
 * oitherwise into config.dst_ip*
 */
typedef enum {SOURCE, DESTINATION} srcdst;
static int parse_ips(char *str, srcdst src_dst)
{
	struct addrinfo hint, *res = NULL;
	int ret, is_ipv4;
	char *separator = strchr(str,',');

	if (separator == NULL)
		return 1;

	*separator = 0;

	memset(&hint, '\0', sizeof hint);
	hint.ai_family = PF_UNSPEC;
	hint.ai_flags = AI_NUMERICHOST;

	ret = getaddrinfo(str, NULL, &hint, &res);
	if (ret)
		return 1;

	is_ipv4 = (res->ai_family == AF_INET) ? 1 : 0;
	freeaddrinfo(res);

	if (src_dst == SOURCE) { // source IP addr
		if (is_ipv4) {
			if (!inet_pton(AF_INET, str, (struct in_addr *)&config.src_ip4[0]))
				return 1;
			if (!inet_pton(AF_INET, separator+1, (struct in_addr *)&config.src_ip4[1]))
				return 1;
		} else {
			if (!inet_pton(AF_INET6, str, &config.src_ip6))
				return 1;
			if (!inet_pton(AF_INET6, separator+1, &config.src_ip6[16]))
				return 1;
		}

	} else { // destination IP addr
		if (is_ipv4) {
			if (!inet_pton(AF_INET, str, (struct in_addr *)&config.dst_ip4[0]))
				return 1;
			if (!inet_pton(AF_INET, separator+1, (struct in_addr *)&config.dst_ip4[1]))
				return 1;
		} else {
			if (!inet_pton(AF_INET6, str, &config.dst_ip6))
				return 1;
			if (!inet_pton(AF_INET6, separator+1, &config.dst_ip6[16]))
				return 1;
		}

	}
	return 0;
}

#define TMPSIZE 64
/* parse ports separated with "," */
static int parse_port(char *str)
{
	if (!strncmp(str, "random", 6)) {
		config.udp_port = PORT_RANDOM;
	} else if (str[0] == '+') {
		if (sscanf(str+1, "%i", &config.udp_port) != 1)
			return 1;
		config.udp_port |= PORT_INCREMENT;
	} else
		if (sscanf(str, "%i", &config.udp_port) != 1)
			return 1;
		else
			config.udp_port &= 0xffff;

	return 0;
}

#define dbg(str, ...) printf("CONFIG: "); printf(str, ##__VA_ARGS__);

/* TODO: check if configuration is valid. */
static void validate_configuration(void)
{
	if ((config.ipv6) && (config.packet_size < 78)) {
		printf("Warning: ipv6 enabled, increasing packetsize to 78 bytes\n");
		config.packet_size = 78;
	}
}

int parse_cmdline(int argc, char **argv)
{
	int c;

	enum {HELP, TEST, STATS_INTERVAL, DURATION, PPS, RATE, PTS, NUM_PORTS, NUM_TX_QUEUES,
		NUM_RX_QUEUES, BURST_SIZE, PACKET_SIZE, IPV6, ARP_DELAY, SRC_IP_LIST, DST_IP_LIST,
		UDP_PORT, DST_MAC_LIST, MIN_RATE, MAX_RATE, DROP_RATIO, STEP, SAVE_LATENCIES};

	while (1)
	{
		int option_index = 0;
		static struct option long_options[] = {
		{"help",          no_argument,       0, HELP},
		{"test",          required_argument, 0, TEST},
		{"stats-interval",required_argument, 0, STATS_INTERVAL},
		{"duration",      required_argument, 0, DURATION},
		{"pps",           required_argument, 0, PPS},
		{"rate",          required_argument, 0, RATE},
		{"pts",           required_argument, 0, PTS},
		{"save-latencies",no_argument,       0, SAVE_LATENCIES},

		{"num-ports",     required_argument, 0, NUM_PORTS},
		{"num-tx-queues", required_argument, 0, NUM_TX_QUEUES},
		{"num-rx-queues", required_argument, 0, NUM_RX_QUEUES},
		{"burst-size",    required_argument, 0, BURST_SIZE},

		{"min-rate",      required_argument, 0, MIN_RATE},
		{"max-rate",      required_argument, 0, MAX_RATE},
		{"drop-ratio",    required_argument, 0, DROP_RATIO},
		{"step",          required_argument, 0, STEP},

		{"packet-size",   required_argument, 0, PACKET_SIZE},
		{"ipv6",          no_argument,       0, IPV6},
		{"arp-delay",     required_argument, 0, ARP_DELAY},
		{"src-ip-list",   required_argument, 0, SRC_IP_LIST},
		{"dst-ip-list",   required_argument, 0, DST_IP_LIST},
		{"udp-port",      required_argument, 0, UDP_PORT},
		{"dst-mac-list",  required_argument, 0, DST_MAC_LIST},

		{0, 0, 0, 0}};

		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {

		case HELP:
		default:
			print_usage();
			exit(0);
			break;

		case TEST:
			if (!strcmp(optarg, "binsearch"))
				config.test = BINSEARCH;
			else if (!strcmp(optarg, "delay"))
				config.test = DELAY;
			else if (!strcmp(optarg, "fixrate"))
				config.test = FIXRATE;
			else if (!strcmp(optarg, "linsearch"))
				config.test = LINSEARCH;
			else
				die("Unknown test \"%s\"", optarg);
			break;
			
		case STATS_INTERVAL:
			config.stats_interval = verify_int(optarg);
			break;

		case DURATION:
			config.duration = verify_int(optarg);
			break;

		case PPS:
			config.pps = verify_uint64(optarg);
			break;

		case RATE:
			config.pps = rate_to_pps(verify_uint64(optarg));
			break;

		case PTS:
			config.pts = verify_uint64(optarg);
			break;

		case NUM_PORTS:
			config.num_ports = verify_int(optarg);
			break;

		case NUM_TX_QUEUES:
			config.num_tx_queues = verify_int(optarg);
			break;

		case NUM_RX_QUEUES:
			config.num_rx_queues = verify_int(optarg);
			break;

		case PACKET_SIZE:
			config.packet_size = verify_int(optarg);
			break;

		case DST_MAC_LIST:
			if (parse_macs(optarg))
				die("parameters for --dst-mac-list are invalid (\"%s\")", optarg);
			config.dst_macs_are_set = 1;
			break;

		case SRC_IP_LIST:
			if (parse_ips(optarg, SOURCE))
				die("parameters for --src-ip-list are invalid (\"%s\")", optarg);
			break;

		case DST_IP_LIST:
			if (parse_ips(optarg, DESTINATION))
				die("parameters for --dst-ip-list are invalid (\"%s\")", optarg);
			break;

		case UDP_PORT:
			if (parse_port(optarg))
				die("parameters for --udp-port are invalid (\"%s\")", optarg);
			break;

		case STEP:
			config.step = verify_uint64(optarg);
			break;

		case MIN_RATE:
			config.min_rate = verify_uint64(optarg);
			break;

		case MAX_RATE:
			config.max_rate = verify_uint64(optarg);
			break;

		case DROP_RATIO:
			sscanf(optarg, "%f", &config.drop_ratio);
			break;

		case IPV6:
			config.ipv6 = 1;
			break;

		case ARP_DELAY:
			config.arp_delay = verify_int(optarg);
			break;

		case BURST_SIZE:
			config.burst_size = verify_int(optarg);
			if (config.burst_size > 64) {
				printf("Decreasing burst size to 64 !\n");
				config.burst_size = 64;
			}
			break;

		case SAVE_LATENCIES:
			config.save_latencies = 1;
			break;
		}
	}
	validate_configuration();
	return 0;
}
