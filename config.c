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

	.num_ports = 2,
	.num_tx_queues = 1,
	.num_rx_queues = 1,
	.burst_size = 32,

	.packet_size = 64,
	.dst_macs_are_set = 0,
	.ipv6 = 0,

	.src_ip4 = {IPv4(172, 16, 0, 1), IPv4(172, 16, 1, 1)},
	.dst_ip4 = {IPv4(172, 16, 0, 2), IPv4(172, 16, 1, 2)},
	.src_port = 1024,
	.dst_port = 2048,

};

config_t *get_config(void)
{
	return &config;
}

static void print_usage(void)
{
	printf("usage:\ncsit-pktgen [dpdk-args] -- [pktgen args]\n\n"
		   "  --help - this help\n"
		   "  --stats-interval [n] - wait [n] seconds between printing statistics\n"
		   "  --duration n - stop after n seconds\n"
		   "  --pps [n] - transmit [n] packets per seconds\n"
		   "  --pts [n] - quit after transmitting [n] packets (on all directions)\n"
		   "\n"
		   "  --ipv6 - use ipv6 instead of ipv4\n"
		   "  --packet-size [n] - packet size in [n] bytes including header\n"
		   "  --src-ips [a,b] - source IP addr\n"
		   "  --dst-ips [a,b] - destination IP addr\n"
		   "  --udp-ports [a,b] - udp ports used for communication\n"
		   "  --dst-macs [a,b] - set MAC addrs for ethernet ports\n"
		   "\n"
		   "  --num-ports - number of physical ethernet port used\n"
		   "  --num-tx-queues - number of transmit processing threads\n"
		   "  --num-rx-queues - number of receive processing threads\n"
		   "\n"
		);
}

#define die(err, ...) { \
	printf(err, ##__VA_ARGS__); \
	printf("\nUse --help for syntax\nExiting !\n\n"); \
	exit(-1);}

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

static int parse_ips(char *str, int src_dst)
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

	if (src_dst == 1) { // source IP addr
		if (is_ipv4) {
			if (!inet_pton(AF_INET, str, (struct in_addr *)&config.src_ip4[0]))
				return 1;
			if (!inet_pton(AF_INET, separator+1, (struct in_addr *)&config.src_ip4[1]))
				return 1;
			config.src_ip4[0] = ntohl(config.src_ip4[0]);
			config.src_ip4[1] = ntohl(config.src_ip4[1]);
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
			config.dst_ip4[0] = ntohl(config.dst_ip4[0]);
			config.dst_ip4[1] = ntohl(config.dst_ip4[1]);
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
static int parse_ports(char *str)
{
	char port1[TMPSIZE], port2[TMPSIZE];

	if (strlen(str) > TMPSIZE)
		return 1;

	if (sscanf(str, "%[^,],%s", port1, port2) != 2)
		return 1;

	if (!strncmp(port1, "random", 6)) {
		config.src_port = PORT_RANDOM;
	} else if (port1[0] == '+') {
		if (sscanf(port1+1, "%i", &config.src_port) != 1)
			return 1;
		config.src_port |= PORT_INCREMENT;
	} else
		if (sscanf(port1, "%i", &config.src_port) != 1)
		return 1;
	else
		config.src_port &= 0xffff;

	if (!strncmp(port2, "random", 6)) {
		config.dst_port = PORT_RANDOM;
	} else if (port2[0] == '+') {
		if (sscanf(port2+1, "%i", &config.dst_port) != 1)
			return 1;
		config.dst_port |= PORT_INCREMENT;
	} else
		if (sscanf(port2, "%i", &config.dst_port) != 1)
		return 1;
	else
		config.dst_port &= 0xffff;

	return 0;
}

#define dbg(str, ...) printf("CONFIG: "); printf(str, ##__VA_ARGS__);

static void validate_configuration(void)
{

}

int parse_cmdline(int argc, char **argv)
{
	int c;

	enum {HELP, TEST, STATS_INTERVAL, DURATION, PPS, RATE, PTS, NUM_PORTS, NUM_TX_QUEUES,
		NUM_RX_QUEUES, BURST_SIZE, PACKET_SIZE, IPV6, SRC_IPS, DST_IPS, UDP_PORTS, DST_MACS,
		MIN_RATE, MAX_RATE, DROP, STEP};

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

		{"num-ports",     required_argument, 0, NUM_PORTS},
		{"num-tx-queues", required_argument, 0, NUM_TX_QUEUES},
		{"num-rx-queues", required_argument, 0, NUM_RX_QUEUES},
		{"burst-size",    required_argument, 0, BURST_SIZE},

		{"min-rate",      required_argument, 0, MIN_RATE},
		{"max-rate",      required_argument, 0, MAX_RATE},
		{"drop",          required_argument, 0, DROP},
		{"step",          required_argument, 0, STEP},

		{"packet-size",   required_argument, 0, PACKET_SIZE},
		{"ipv6",          no_argument,       0, IPV6},
		{"src-ips",       required_argument, 0, SRC_IPS},
		{"dst-ips",       required_argument, 0, DST_IPS},
		{"udp-ports",     required_argument, 0, UDP_PORTS},
		{"dst-macs",      required_argument, 0, DST_MACS},

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
			config.pps = verify_int(optarg);
			break;

		case RATE:
			config.pps = rate_to_pps(verify_int(optarg));
			break;

		case PTS:
			config.pts = verify_int(optarg);
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

		case DST_MACS:
			if (parse_macs(optarg))
				die("parameters for --dst-macs are invalid (\"%s\")", optarg);
			config.dst_macs_are_set = 1;
			break;

		case SRC_IPS:
			if (parse_ips(optarg, 1))
				die("parameters for --src-ips are invalid (\"%s\")", optarg);
			break;

		case DST_IPS:
			if (parse_ips(optarg, 2))
				die("parameters for --dst-ips are invalid (\"%s\")", optarg);
			break;

		case UDP_PORTS:
			if (parse_ports(optarg))
				die("parameters for --dst-ips are invalid (\"%s\")", optarg);
			break;

		case STEP:
			config.step = verify_int(optarg);
			break;

		case MIN_RATE:
			config.min_rate = verify_uint64(optarg);
			break;

		case MAX_RATE:
			config.max_rate = verify_uint64(optarg);
			break;

		case DROP:
			config.drop = verify_uint64(optarg);
			break;

		case IPV6:
			config.ipv6 = 1;
			break;

		case BURST_SIZE:
			config.burst_size = verify_int(optarg);
			if (config.burst_size > 64) {
				printf("Decreasing burst size to 64 !\n");
				config.burst_size = 64;
			}
			break;
		}
	}
	validate_configuration();
	return 0;
}
