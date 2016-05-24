#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <getopt.h>

#include "config.h"

static config_t conf;

/* default parameters */
static config_t conf = {
	.stats_interval = 3,
	.duration = 0,

	.num_ports = 2,
	.num_tx_queues = 1,
	.num_rx_queues = 1,

	.packet_size = 64,
};

config_t *get_config()
{
	return &conf;
}

static void print_usage(void)
{
	printf("usage:\ncsit-pktgen [dpdk-args] -- [pktgen args]\n\n"
		   "  --help - this help\n"
		   "  --stats_interval n - wait n seconds between printing statistics\n"
		   "  --duration n - stop after n seconds\n"
		   "\n"
		   "  --src-ips - source IP addr\n"
		   "  --dst-ips - destination IP addr\n"
		   "  --dst-macs - mac addr\n"
		   "  --packet_size - packet size in bytes including header\n"
		   "\n"
		   "  --num_ports - number of physical ethernet port used\n"
		   "  --num_tx_queues - number of transmit processing threads\n"
		   "  --num_rx_queues - number of receive processing threads\n"
		   "\n"
		);
}

int parse_cmdline(int argc, char **argv)
{
	int c;

	enum {HELP, STATS_INTERVAL, DURATION, NUM_PORTS, NUM_TX_QUEUES, NUM_RX_QUEUES,
		  PACKET_SIZE, SRC_IPS, DST_IPS, DST_MACS};

	while (1)
	{
		int option_index = 0;
		static struct option long_options[] = {
		{"help",          no_argument,       0, HELP},
		{"stats_interval",required_argument, 0, STATS_INTERVAL},
		{"duration",      required_argument, 0, DURATION},

		{"num_ports",     required_argument, 0, NUM_PORTS},
		{"num_tx_queues", required_argument, 0, NUM_TX_QUEUES},
		{"num_rx_queues", required_argument, 0, NUM_RX_QUEUES},

		{"packet_size",   required_argument, 0, PACKET_SIZE},
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
			conf.stats_interval = atoi(optarg);
			break;

		case DURATION:
			conf.duration = atoi(optarg);
			break;

		case NUM_PORTS:
			conf.num_ports = atoi(optarg);
			break;

		case NUM_TX_QUEUES:
			conf.num_tx_queues = atoi(optarg);
			break;

		case NUM_RX_QUEUES:
			conf.num_rx_queues = atoi(optarg);
			break;

		case PACKET_SIZE:
			conf.packet_size = atoi(optarg);
			break;

		case SRC_IPS:
//			conf.src_ips[0] = inet_addr(optarg);
			break;
		}
	}
	return 0;
}
