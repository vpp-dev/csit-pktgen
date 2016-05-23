#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <getopt.h>

#include "config.h"

static config_t conf;

static config_t conf = {
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
	printf("csit_pktgen command line options:\n\n"
		   " --help: this help\n"
		   " --num_ports: number of physical ethernet port used\n"
		   " --num_tx_queues: number of transmit processing threads\n"
		   " --num_rx_queues: number of receive processing threads\n"
		   " --packet_size: packet size in bytes including header\n"
		   "\n"
		);
}

int parse_cmdline(int argc, char **argv)
{
	int c;

	while (1)
	{
		int option_index = 0;
		static struct option long_options[] = {
		{"help",          no_argument,       0, 0},
		{"num_ports",     required_argument, 0, 1},
		{"num_tx_queues", required_argument, 0, 2},
		{"num_rx_queues", required_argument, 0, 3},
		{"packet_size",   required_argument, 0, 4},
		{0, 0, 0, 0}};

		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {

		case 0:
			print_usage();
			exit(0);
			break;

		case 1:
			conf.num_ports = atoi(optarg);
			break;

		case 2:
			conf.num_tx_queues = atoi(optarg);
			break;

		case 3:
			conf.num_rx_queues = atoi(optarg);
			break;

		case 4:
			conf.packet_size = atoi(optarg);
			break;

		default:
			printf("Getopt returned character code 0%o ??\n", c);
		}
	}
	return 0;
}
