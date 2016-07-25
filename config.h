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
#define IPv4_NS(a,b,c,d) ((uint32_t)(((d) & 0xff) << 24) | \
			(((c) & 0xff) << 16) | \
			(((b) & 0xff) << 8)  | \
			((a) & 0xff))

/* csit-pktgen run mode */
enum {BINSEARCH, DELAY, FIXRATE, LINSEARCH};

#define MAX_PKT_BURST        64

typedef struct {
	unsigned char mac[6];
} mac_t;


typedef struct {
	int test;  /* [binsearch|delay|fixrate|linsearch] */

	int stats_interval;
	int duration; /* run time duration in sec */
	uint64_t pps;  /* number of transmitted packets per sec, 0 == no delay between packets */
	uint64_t pts; /* quit after transmitting pts packets */

	unsigned int num_ports;
	unsigned int num_tx_queues;
	unsigned int num_rx_queues;
	unsigned int burst_size;

	uint64_t step;
	uint64_t min_rate;
	uint64_t cur_rate;
	uint64_t max_rate;
	uint64_t step_min;
	uint64_t step_max;
	float drop_ratio;

	int packet_size;
	int dst_macs_are_set;
	int ipv6;
	int arp_delay; /* delay in seconds after sending ARP packet */
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
