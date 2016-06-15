#ifndef __CONFIG__H__
#define __CONFIG__H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PREAMBLE_SOF_GAP 20

#define PORT_INCREMENT (1<<16)
#define PORT_RANDOM (1<<17)

#define rate_to_pps(x) ((x)/8/conf->packet_size)
#define pps_to_rate(x) ((x)*8*conf->packet_size)

/* csit-pktgen run mode */
enum {BINSEARCH, DELAY, FIXRATE, LINSEARCH};

typedef struct {
	unsigned char mac[6];
} mac_t;


typedef struct {
	int test;  /* [binsearch|delay|fixrate|linsearch] */

	int stats_interval;
	int duration; /* run time duration in sec */
	uint64_t pps;  /* number of transmitted packets per sec, 0 == no delay between packets */
	int pts; /* quit after transmitting pts packets */

	int num_ports;
	int num_tx_queues;
    int num_rx_queues;

	int step;
	uint64_t min_rate;
	uint64_t cur_rate;
	uint64_t max_rate;
	int drop;

	int packet_size;
	int dst_macs_are_set;
	int ipv6;
	mac_t src_mac[2];
	mac_t dst_mac[2];

	uint32_t src_ip4[2];
	uint32_t dst_ip4[2];
	uint8_t  src_ip6[32];
	uint8_t  dst_ip6[32];
	uint32_t src_port; /* bits 0-15=port, bit16=increment, bit17=random */
	uint32_t dst_port;

} config_t;

int parse_cmdline(int argc, char **argv);

config_t *get_config(void); /* configuration struct */

#endif //__CONFIG__H__
