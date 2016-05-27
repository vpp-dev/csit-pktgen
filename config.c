#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <stdarg.h>     /* va_list, va_start, va_arg, va_end */
#include <string.h>
#include <ctype.h>
#include <getopt.h>

#include "config.h"

static config_t conf;

/* default parameters */
static config_t conf = {
	.stats_interval = 3,
	.duration = 0,
	.pps = 0,
	.pts = 0,

	.num_ports = 2,
	.num_tx_queues = 1,
	.num_rx_queues = 1,

	.packet_size = 64,
	.macs_are_set = 0,
};

config_t *get_config(void)
{
	return &conf;
}

static void print_usage(void)
{
	printf("usage:\ncsit-pktgen [dpdk-args] -- [pktgen args]\n\n"
		   "  --help - this help\n"
		   "  --stats-interval n - wait n seconds between printing statistics\n"
		   "  --duration n - stop after n seconds\n"
		   "  --pps n - transmit n packets per seconds\n"
		   "  --pts n - quit after transmitting n packets (on all directions)\n"
		   "\n"
		   "  --src-ips - source IP addr\n"
		   "  --dst-ips - destination IP addr\n"
		   "  --dst-macs - mac addr\n"
		   "  --packet-size - packet size in bytes including header\n"
		   "  --dst-macs - set MAC addrs for ethernet ports\n"
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

static int parse_macs(char *str)
{
	uint8_t *bytes = (uint8_t *)&conf.mac[0];
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

		conf.macs_are_set = 1;
		return 0;
	}
	return 1;
}

int parse_cmdline(int argc, char **argv)
{
	int c;

	enum {HELP, STATS_INTERVAL, DURATION, PPS, PTS, NUM_PORTS, NUM_TX_QUEUES, NUM_RX_QUEUES,
		  PACKET_SIZE, SRC_IPS, DST_IPS, DST_MACS};

	while (1)
	{
		int option_index = 0;
		static struct option long_options[] = {
		{"help",          no_argument,       0, HELP},
		{"stats-interval",required_argument, 0, STATS_INTERVAL},
		{"duration",      required_argument, 0, DURATION},
		{"pps",           required_argument, 0, PPS},
		{"pts",           required_argument, 0, PTS},

		{"num-ports",     required_argument, 0, NUM_PORTS},
		{"num-tx-queues", required_argument, 0, NUM_TX_QUEUES},
		{"num-rx-queues", required_argument, 0, NUM_RX_QUEUES},

		{"packet-size",   required_argument, 0, PACKET_SIZE},
		{"src-ips",       required_argument, 0, SRC_IPS},
		{"dst-ips",       required_argument, 0, DST_IPS},
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

		case STATS_INTERVAL:
			conf.stats_interval = verify_int(optarg);
			break;

		case DURATION:
			conf.duration = verify_int(optarg);
			break;

		case PPS:
			conf.pps = verify_int(optarg);
			break;

		case PTS:
			conf.pts = verify_int(optarg);
			break;

		case NUM_PORTS:
			conf.num_ports = verify_int(optarg);
			break;

		case NUM_TX_QUEUES:
			conf.num_tx_queues = verify_int(optarg);
			break;

		case NUM_RX_QUEUES:
			conf.num_rx_queues = verify_int(optarg);
			break;

		case PACKET_SIZE:
			conf.packet_size = verify_int(optarg);
			break;

		case DST_MACS:
			if (parse_macs(optarg))
				die("parameters for --dst-macs are invalid (\"%s\")", optarg);
			break;

		case SRC_IPS:
//			conf.src_ips[0] = inet_addr(optarg);
			break;
		}
	}

	return 0;
}
