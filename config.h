#ifndef __CONFIG__H__
#define __CONFIG__H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct {
	unsigned char mac[6];
} mac_t;

typedef struct {
	int stats_interval;
	int duration; /* run time duration in sec */
	int pps; /* number of transmitted packets per sec, 0 == no delay between packets */
	int pts; /* quit after transmitting pts packets */

	int num_ports;
	int num_tx_queues;
	int num_rx_queues;

	int packet_size;
} config_t;

int parse_cmdline(int argc, char **argv);

config_t *get_config(void); /* configuration struct */

#endif //__CONFIG__H__
