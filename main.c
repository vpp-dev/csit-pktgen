#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include "immintrin.h"

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_arp.h>

#include "barrier.h"
#include "config.h"

#define MEMPOOL_CACHE_SIZE   256
/* packet magic number to identify our packets */
#define PKT_MAGIC_ID 0xAA55DEADCAFE55AA
/* time to flush network buffers in seconds */
#define FLUSH_BUFFER_TIME 2

config_t *conf = NULL;

#define TICKS_TO_NSEC(x) ((x) * 1000 / ticks_per_usec)
uint64_t ticks_per_sec;
int ticks_per_usec;
int should_quit = 0;
volatile unsigned int rx_should_stop = 0; /* >0 to stop all rx threads */
volatile unsigned int tx_should_stop = 0; /* >0 to stop all rx threads */
volatile unsigned int tx_threads_stopped = 0; /* number of stopped tx threads */
struct timespec started, actual;

worker_barrier_t *b;
static struct rte_mempool * pktmbuf_pool;


static void __attribute__ ((unused))
hexdump(uint8_t buffer[], int len)
{
#define HEXDUMP_LINE_LEN	16
	int i;
	char s[HEXDUMP_LINE_LEN+1];
	bzero(s, HEXDUMP_LINE_LEN+1);

	for(i=0; i < len; i++) {
		if (!(i%HEXDUMP_LINE_LEN)) {
			if (s[0])
				printf("[%s]",s);
			printf("\n%05x: ", i);
			bzero(s, HEXDUMP_LINE_LEN);
		}
		s[i%HEXDUMP_LINE_LEN]=isprint(buffer[i])?buffer[i]:'.';
		printf("%02x ", buffer[i]);
	}
	while(i++%HEXDUMP_LINE_LEN)
		printf("   ");

	printf("[%s]\n", s);
}

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload enabled */
		.hw_vlan_filter = 0,
		.hw_vlan_strip  = 0,
		.hw_vlan_extend = 0,
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 1, /**< CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_UDP | ETH_RSS_IP | ETH_RSS_TCP /*ETH_RSS_IP*/,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

typedef enum {
	THREAD_RX=1,
	THREAD_TX=2
} thread_type_t;

typedef struct {
	/* stats */
	uint64_t num_tx_pkts;
	uint64_t num_tx_octets;

	uint64_t num_rx_pkts;
	uint64_t num_rx_octets;
	uint64_t num_rx_dropped;

	uint64_t latency_sum;
	uint64_t latency_min; /* total latency */
	uint64_t latency_max;
} counters;

typedef struct {
	char cacheline0[0] __attribute__((aligned(2*64)));
	int port;
	int queue;
	thread_type_t type;
	int lcore_id;

	/* packet data */
	uint16_t pkt_len;
	uint64_t pkts_to_transmit; /* stop tx thread after this number is reached */
	struct ether_addr src_mac;
	struct ether_addr dst_mac;
	uint32_t src_ip4;
	uint32_t dst_ip4;
	uint32_t src_ip6[16];
	uint32_t dst_ip6[16];
	uint32_t src_port;
	uint32_t dst_port;
	uint64_t delay; /* delay between packets, calculated at thread start from pps */
	uint64_t pts; /* number of packets to send by this thread */

	counters counters;

} per_thread_data_t;

typedef struct {
	uint64_t magic_id;
	uint64_t tsc; // time stamp counter
} packet_payload;

counters runtime_cnt = {0};

/* Shows DPDK error on stdout. Called from RX func. */
static inline void dump_dpdk_error(uint64_t flags)
{
	printf("received packet with DPDK errors: ");

	if (flags & PKT_RX_L4_CKSUM_BAD)
		printf("L4 cksum of RX pkt. is not OK.\n");
	if (flags & PKT_RX_IP_CKSUM_BAD)
		printf("IP cksum of RX pkt. is not OK.\n");
	if (flags & PKT_RX_EIP_CKSUM_BAD)
		printf("External IP header checksum error.\n");

	printf("\n");
}

static void print_configuration(void)
{
	char temp1[64];
	char temp2[64];
	char port_str[32];

	printf("Current configuration:\n");
	printf("======================\n");
	printf("selected test: ");
	switch(conf->test)
	{
		case BINSEARCH:
			printf("binary search");
			break;

		case DELAY:
			printf("delay between packets");
			break;

		case FIXRATE:
			printf("fixed rate");
			break;

		case LINSEARCH:
			printf("linear search");
			break;
	}
	printf(", status is printed in %is interval, test duration: %is.\n", conf->stats_interval, conf->duration);
	printf("packet size: %i, IP version: %s\n", conf->packet_size, conf->ipv6 ? "IPv6" : "IPv4");
	printf("PPS: %lu, PTS: %lu, ports: %i, tx_queues: %i, rx_queues: %i, burst_size: %i\n",
		   conf->pps, conf->pts, conf->num_ports, conf->num_tx_queues, conf->num_rx_queues, conf->burst_size);

	printf("MAC info:\n");
	ether_format_addr(temp1, sizeof(temp1),(const struct ether_addr *)&conf->src_mac[0]);
	ether_format_addr(temp2, sizeof(temp2),(const struct ether_addr *)&conf->dst_mac[0]);
	printf("%s -> %s\n", temp1, temp2);
	ether_format_addr(temp1, sizeof(temp1),(const struct ether_addr *)&conf->src_mac[1]);
	ether_format_addr(temp2, sizeof(temp2),(const struct ether_addr *)&conf->dst_mac[1]);
	printf("%s -> %s\n", temp1, temp2);

	if (conf->udp_port & PORT_INCREMENT)
		sprintf(port_str, "%i[incremented]", conf->udp_port & 0xffff);
	else if (conf->udp_port & PORT_RANDOM)
		sprintf(port_str, "[RANDOM]");
	else
		sprintf(port_str, "%i", conf->udp_port & 0xffff);

	printf("IP info:\n");
	if (conf->ipv6)
	{
		printf("%s:%s -> %s:%s\n",
			inet_ntop(AF_INET6, (void *)&conf->src_ip6[0], temp1, sizeof(temp1)), port_str,
			inet_ntop(AF_INET6, (void *)&conf->dst_ip6[0], temp2, sizeof(temp2)), port_str);
		printf("%s:%s -> %s:%s\n",
			inet_ntop(AF_INET6, (void *)&conf->src_ip6[1], temp1, sizeof(temp1)), port_str,
			inet_ntop(AF_INET6, (void *)&conf->dst_ip6[1], temp2, sizeof(temp2)), port_str);
		} else {
		printf("%s:%s -> %s:%s\n",
			inet_ntop(AF_INET, (void *)&conf->src_ip4[0], temp1, sizeof(temp1)), port_str,
			inet_ntop(AF_INET, (void *)&conf->dst_ip4[0], temp2, sizeof(temp2)), port_str);
		printf("%s:%s -> %s:%s\n",
			inet_ntop(AF_INET, (void *)&conf->src_ip4[1], temp1, sizeof(temp1)), port_str,
			inet_ntop(AF_INET, (void *)&conf->dst_ip4[1], temp2, sizeof(temp2)), port_str);
	}

	printf("======================\n");
}

/* Calculates ipv4 hdr checksum and ipv4,6 UDP checksum. */
static inline void
calculate_checksum(struct rte_mbuf *pkt)
{
	struct ether_hdr * eth;
	struct ipv4_hdr * ip4;
	struct ipv6_hdr * ip6;
	struct udp_hdr * udp;

	eth = rte_pktmbuf_mtod_offset(pkt, struct ether_hdr *, 0);

	if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4))
	{
		ip4 = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, sizeof(*eth));
		udp = rte_pktmbuf_mtod_offset(pkt, struct udp_hdr *, sizeof(*eth)+sizeof(*ip4));
		ip4->hdr_checksum = rte_ipv4_cksum(ip4);
		udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip4, udp);
	}

	if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6))
	{
		ip6 = rte_pktmbuf_mtod_offset(pkt, struct ipv6_hdr *, sizeof(*eth));
		udp = rte_pktmbuf_mtod_offset(pkt, struct udp_hdr *, sizeof(*eth)+sizeof(*ip6));
		udp->dgram_cksum = rte_ipv6_udptcp_cksum(ip6, udp);
	}
}

/* Fills ethernet, ipv4 and UDP header in packet. Returns pointer to UDP payload. */
static inline void *
craft_packet_ipv4(per_thread_data_t * ptd, struct rte_mbuf *pkt)
{
	struct ether_hdr * eth;
	struct ipv4_hdr * ip4;
	struct udp_hdr * udp;
	eth = rte_pktmbuf_mtod_offset(pkt, struct ether_hdr *, 0);
	ip4 = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, sizeof(*eth));
	udp = rte_pktmbuf_mtod_offset(pkt, struct udp_hdr *, sizeof(*eth)+sizeof(*ip4));

	/* Metadata */
	pkt->next = 0;
	pkt->nb_segs = 1;
	rte_pktmbuf_data_len (pkt) = ptd->pkt_len;
	rte_pktmbuf_pkt_len (pkt) = ptd->pkt_len;

	/* Ethernet */
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	ether_addr_copy(&ptd->src_mac, &eth->s_addr);
	ether_addr_copy(&ptd->dst_mac, &eth->d_addr);

	/* IPv4 */
	ip4->version_ihl     = 0x45;
	ip4->type_of_service = 0;
	ip4->fragment_offset = 0;
	ip4->time_to_live    = 64;
	ip4->next_proto_id   = 17 /* UDP */;
	ip4->packet_id       = 0;
	ip4->total_length    = rte_cpu_to_be_16(ptd->pkt_len - sizeof(*eth));
	ip4->src_addr        = ptd->src_ip4;
	ip4->dst_addr        = ptd->dst_ip4;
	ip4->hdr_checksum    = 0;

	/* UDP */
	switch(ptd->src_port & 0xffff0000) {
	case PORT_RANDOM:
		udp->src_port = rand() & 0xffff; // FIXME rand (is up to 32768)!
		break;
	case PORT_INCREMENT:
		if ((ptd->counters.num_tx_pkts % (conf->udp_port & 0xffff)) == 0) {
			ptd->src_port++;
			ptd->src_port = (ptd->src_port & 0xffff) + PORT_INCREMENT;
		}
		// no break here
	default:
		udp->src_port = rte_cpu_to_be_16(ptd->src_port);
	}

	switch(ptd->dst_port & 0xffff0000) {
	case PORT_RANDOM:
		udp->dst_port = rand() & 0xffff; // FIXME rand (is up to 32768)!
		break;
	case PORT_INCREMENT:
		if ((ptd->counters.num_tx_pkts % (conf->udp_port & 0xffff)) == 0) {
			ptd->dst_port++;
			ptd->dst_port = (ptd->dst_port & 0xffff) + PORT_INCREMENT;
		}
		// no break here
	default:
		udp->dst_port = rte_cpu_to_be_16(ptd->dst_port);
	}

	udp->dgram_len = rte_cpu_to_be_16(ptd->pkt_len - sizeof(*eth) - sizeof(*ip4));
	udp->dgram_cksum = 0;

	return (udp+1);
}

/* Fills ethernet, ipv6 and UDP header in packet. Returns pointer to UDP payload. */
static inline void *
craft_packet_ipv6(per_thread_data_t * ptd, struct rte_mbuf *pkt)
{
	struct ether_hdr * eth;
	struct ipv6_hdr * ip6;
	struct udp_hdr * udp;
	eth = rte_pktmbuf_mtod_offset(pkt, struct ether_hdr *, 0);
	ip6 = rte_pktmbuf_mtod_offset(pkt, struct ipv6_hdr *, sizeof(*eth));
	udp = rte_pktmbuf_mtod_offset(pkt, struct udp_hdr *, sizeof(*eth)+sizeof(*ip6));

	/* Metadata */
	pkt->next = 0;
	pkt->nb_segs = 1;
	rte_pktmbuf_data_len (pkt) = ptd->pkt_len;
	rte_pktmbuf_pkt_len (pkt) = ptd->pkt_len;

	/* Ethernet */
	ether_addr_copy(&ptd->src_mac, &eth->s_addr);
	ether_addr_copy(&ptd->dst_mac, &eth->d_addr);
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);

	/* IPv6 */
	ip6->proto = IPPROTO_UDP;
	ip6->vtc_flow = rte_cpu_to_be_32(0x60000000);
	ip6->hop_limits = 64;
	ip6->payload_len = rte_cpu_to_be_16(ptd->pkt_len - sizeof(*eth) - sizeof(*ip6));
	memcpy(ip6->src_addr, ptd->src_ip6, 16);
	memcpy(ip6->dst_addr, ptd->dst_ip6, 16);

	/* UDP */
	switch(ptd->src_port & 0xffff0000) {
	case PORT_RANDOM:
		udp->src_port = rand() & 0xffff; // FIXME rand (is up to 32768)!
		break;
	case PORT_INCREMENT:
		if ((ptd->counters.num_tx_pkts % (conf->udp_port & 0xffff)) == 0) {
			ptd->src_port++;
			ptd->src_port = (ptd->src_port & 0xffff) + PORT_INCREMENT;
		}
		// no break here
	default:
		udp->src_port = rte_cpu_to_be_16(ptd->src_port);
	}

	switch(ptd->dst_port & 0xffff0000) {
	case PORT_RANDOM:
		udp->dst_port = rand() & 0xffff; // FIXME rand (is up to 32768)!
		break;
	case PORT_INCREMENT:
		if ((ptd->counters.num_tx_pkts % (conf->udp_port & 0xffff)) == 0) {
			ptd->dst_port++;
			ptd->dst_port = (ptd->dst_port & 0xffff) + PORT_INCREMENT;
		}
		// no break here
	default:
		udp->dst_port = rte_cpu_to_be_16(ptd->dst_port);
	}
	udp->dgram_len = rte_cpu_to_be_16(ptd->pkt_len - sizeof(*eth) - sizeof(*ip6));
	udp->dgram_cksum = 0;

	return (udp+1);
}

/* Prepares ARP packet. */
static inline void prepare_arp(config_t *conf, struct rte_mbuf *pkt, uint16_t arp_opcode, int port)
{
	struct ether_hdr * eth;
	struct arp_hdr * arp;
	eth = rte_pktmbuf_mtod_offset(pkt, struct ether_hdr *, 0);
	arp = rte_pktmbuf_mtod_offset(pkt, struct arp_hdr *, sizeof(*eth));

	/* Metadata */
	pkt->next = 0;
	pkt->nb_segs = 1;
	rte_pktmbuf_data_len(pkt) = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	rte_pktmbuf_pkt_len(pkt)  = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);

	/* Ethernet */
	ether_addr_copy((const struct ether_addr *)&conf->src_mac[port], &eth->s_addr);
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

	/* arp */
	arp->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
	arp->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	arp->arp_hln = ETHER_ADDR_LEN;
	arp->arp_pln = sizeof(uint32_t);

	if (arp_opcode == ARP_OP_REQUEST) {
		arp->arp_op = rte_cpu_to_be_16(ARP_OP_REQUEST);
		arp->arp_data.arp_sip = conf->src_ip4[port];
		arp->arp_data.arp_tip = conf->dst_ip4[port];
		memset(&eth->d_addr, 0xff, 6);
		memset(&arp->arp_data.arp_tha, 0, 6);
		ether_addr_copy((const struct ether_addr *)&conf->src_mac[port], &arp->arp_data.arp_sha);
	}

	if (arp_opcode == ARP_OP_REPLY) {
		arp->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
		// (port==0)?1:0
		ether_addr_copy((const struct ether_addr *)&conf->src_mac[port], &eth->s_addr);
		ether_addr_copy((const struct ether_addr *)&conf->src_mac[(port==0)?1:0], &eth->d_addr);
		ether_addr_copy((const struct ether_addr *)&conf->src_mac[port], &arp->arp_data.arp_sha);
		ether_addr_copy((const struct ether_addr *)&conf->src_mac[(port==0)?1:0], &arp->arp_data.arp_tha);

		arp->arp_data.arp_sip = conf->dst_ip4[(port==0)?1:0];
		arp->arp_data.arp_tip = conf->src_ip4[(port==0)?1:0];
	}
}

/* Prepares ARP packet. */
static inline void prepare_soladv(config_t *conf, struct rte_mbuf *pkt, int port, int icmp_type)
{
	struct ether_hdr * eth;
	struct ipv6_hdr * ip6;
	struct icmp * icmpv6;

	eth = rte_pktmbuf_mtod_offset(pkt, struct ether_hdr *, 0);
	ip6 = rte_pktmbuf_mtod_offset(pkt, struct ipv6_hdr *, sizeof(*eth));
	icmpv6 = rte_pktmbuf_mtod_offset(pkt, struct icmp *, sizeof(*eth) + sizeof(*ip6));

	/* Metadata */
	pkt->next = 0;
	pkt->nb_segs = 1;
	rte_pktmbuf_data_len(pkt) = sizeof(*eth) + sizeof(*ip6) + sizeof(*icmpv6);
	rte_pktmbuf_pkt_len(pkt)  = sizeof(*eth) + sizeof(*ip6) + sizeof(*icmpv6);

	if (icmp_type == NEIGHBOR_SOLICITATION)
	{
		/* Ethernet */
		eth->d_addr.addr_bytes[0] = 0x33;
		eth->d_addr.addr_bytes[1] = 0x33;
		eth->d_addr.addr_bytes[2] = 0xff;
		eth->d_addr.addr_bytes[3] = (uint8_t)conf->dst_ip6[port*16+13];
		eth->d_addr.addr_bytes[4] = (uint8_t)conf->dst_ip6[port*16+14];
		eth->d_addr.addr_bytes[5] = (uint8_t)conf->dst_ip6[port*16+15];
		ether_addr_copy((const struct ether_addr *)&conf->src_mac[port], &eth->s_addr);
		eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);

		/* IPv6 */
		ip6->proto = IPPROTO_ICMPV6;
		ip6->vtc_flow = rte_cpu_to_be_32(0x60000000);
		ip6->hop_limits = 0xff;
		ip6->payload_len = rte_cpu_to_be_16(sizeof(*icmpv6));
		memcpy(&ip6->src_addr, (const void *)&conf->src_ip6[port*16], 16);
		memcpy(&ip6->dst_addr, (const void *)&conf->dst_ip6[port*16], 16);

		/* Icmpv6 */
		icmpv6->icmp_type = NEIGHBOR_SOLICITATION;
		icmpv6->icmp_code = 0;
		icmpv6->reserved = 0;
		icmpv6->option_type = 1;
		icmpv6->option_length = 1;
		ether_addr_copy((const struct ether_addr *)&conf->src_mac[port],
						(struct ether_addr *)&icmpv6->option_ll_addr);
		icmpv6->icmp_cksum = 0;
		icmpv6->icmp_cksum = rte_ipv6_udptcp_cksum(ip6, icmpv6);
	}
	else if (icmp_type == NEIGHBOR_ADVERTISEMENT)
	{
		/* RESPONSE TO SOLICITATION */

		/* Ethernet */
		ether_addr_copy(&eth->s_addr, &eth->d_addr);
 		ether_addr_copy((const struct ether_addr *)&conf->src_mac[port], &eth->s_addr);
		eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);

		port = ~port & 1;

		/* IPv6 */
		ip6->proto = IPPROTO_ICMPV6;
		ip6->vtc_flow = rte_cpu_to_be_32(0x60000000);
		ip6->hop_limits = 0xff;
		ip6->payload_len = rte_cpu_to_be_16(sizeof(*icmpv6));
		memcpy(&ip6->src_addr, (const void *)&conf->dst_ip6[port*16], 16);
		memcpy(&ip6->dst_addr, (const void *)&conf->src_ip6[port*16], 16);

		port = ~port & 1;

		/* Icmpv6 */
		icmpv6->icmp_type = NEIGHBOR_ADVERTISEMENT;
		icmpv6->icmp_code = 0;
		icmpv6->reserved = rte_cpu_to_be_32(0x60000000);
		icmpv6->option_type = 1;
		icmpv6->option_length = 1;
		ether_addr_copy((const struct ether_addr *)&conf->src_mac[port],
						(struct ether_addr *)&icmpv6->option_ll_addr);
		icmpv6->icmp_cksum = 0;
		icmpv6->icmp_cksum = rte_ipv6_udptcp_cksum(ip6, icmpv6);
	}
}

/* Sends 2 ARP requests */
static inline void send_arp(config_t *conf)
{
	struct rte_mbuf *pkt;
	uint16_t ret = 0;

 	pkt = rte_pktmbuf_alloc(pktmbuf_pool);
	prepare_arp(conf, pkt, ARP_OP_REQUEST, 0);
	ret += rte_eth_tx_burst(0, 0, &pkt, 1);  /* request from port 0 */

	pkt = rte_pktmbuf_alloc(pktmbuf_pool);
	prepare_arp(conf, pkt, ARP_OP_REQUEST, 1);
	ret += rte_eth_tx_burst(1, 0, &pkt, 1);  /* request from port 1 */

	if (ret != 2) {
		printf("Unable to send ARP packets !!\n");
		abort();
	}
}

static inline void send_solicitation(config_t *conf)
{
	struct rte_mbuf *pkt;
	uint16_t ret = 0;

	pkt = rte_pktmbuf_alloc(pktmbuf_pool);
	prepare_soladv(conf, pkt, 0, NEIGHBOR_SOLICITATION);
	ret += rte_eth_tx_burst(0, 0, &pkt, 1);  /* request from port 0 */

	pkt = rte_pktmbuf_alloc(pktmbuf_pool);
	prepare_soladv(conf, pkt, 1, NEIGHBOR_SOLICITATION);
	ret += rte_eth_tx_burst(1, 0, &pkt, 1);  /* request from port 0 */

	if (ret != 2) {
		printf("Unable to send Neighbor Solicitation packets !!\n");
		abort();
	}
}
/* Main transmit function */
static int lcore_tx_main(__attribute__((unused)) void *arg)
{
	int i;
	unsigned lcore_id;
	per_thread_data_t * ptd = (per_thread_data_t *) arg;
	uint64_t tsc, last_run_tsc = 0;
	packet_payload *payload;
	struct rte_mbuf *pkts[MAX_PKT_BURST];
	int pkts_in_round = conf->burst_size;
	int pkts_sent;
	int pts_present = 0; /* was "packets to send" set ? */

	lcore_id = rte_lcore_id();
	printf("Handling port %u TX queue %u on core %u\n", ptd->port, ptd->queue, lcore_id);

	if (ptd->src_port & PORT_INCREMENT) /* start from zero*/
		ptd->src_port &= 0xffff0000;
	if (ptd->dst_port & PORT_INCREMENT) /* start from zero*/
		ptd->dst_port &= 0xffff0000;

	while(!tx_should_stop) {
		worker_barrier_check(b);
		tsc = rte_rdtsc();

		/* Is number of "packets to send" set ? */
		if(unlikely(ptd->pts)) {
			pts_present = 1;
			pkts_in_round = (ptd->pts > (uint64_t)conf->burst_size) ? conf->burst_size : ptd->pts;
		}

		/* Is "delay between packets" set ? */
		if(unlikely(ptd->delay)) {
			if (tsc < (last_run_tsc + ptd->delay * pkts_in_round))
				continue;
		}
		last_run_tsc = tsc;

		for (i=0; i<pkts_in_round; i++) {
			pkts[i] = rte_pktmbuf_alloc(pktmbuf_pool); /* allocate packet memory */
			if (pkts[i] == NULL)
			{
				printf("Cannot allocate mbuf !\n");
				abort();
			}

			if (!conf->ipv6) /* fill headers */
				payload = craft_packet_ipv4(ptd, pkts[i]);
			else
				payload = craft_packet_ipv6(ptd, pkts[i]);

			payload->magic_id = PKT_MAGIC_ID;
			payload->tsc = tsc; /* put tsc into payload and recalculate checksum */
			calculate_checksum(pkts[i]);
		}

		pkts_sent = rte_eth_tx_burst(ptd->port, ptd->queue, pkts, pkts_in_round);
		ptd->counters.num_tx_pkts += pkts_sent;
		ptd->counters.num_tx_octets += ptd->pkt_len * pkts_sent;

		if (pkts_sent != pkts_in_round)
		{
			for (i=pkts_sent; i<pkts_in_round; i++)
				rte_pktmbuf_free(pkts[i]);
		}

		/* Was all "packets to send" sent ? If yes, stop thread. */
		if(unlikely(pts_present)) {
			ptd->pts -= pkts_sent;
			if (!ptd->pts) {
				__sync_fetch_and_add(&tx_threads_stopped,  1);
				break;
			}
		}
	}

	/* this was the last thread - send ALARM signal to the main thread */
	if (tx_threads_stopped == conf->num_tx_queues * conf->num_ports) {
		kill(0, SIGALRM);
	}
	__sync_fetch_and_add(b->num_workers, -1);
	return 0;
}

/* Main receive function */
static int
lcore_rx_main(__attribute__((unused)) void *arg)
{
	int nb_rx = 0;
	int i;
	unsigned lcore_id;
	uint64_t latency;
	uint16_t *eth_type;
	struct rte_mbuf *pkts[MAX_PKT_BURST];
	packet_payload *payload;
	per_thread_data_t * ptd = (per_thread_data_t *) arg;
	struct ipv4_hdr *ip4;
 	struct ipv6_hdr *ip6;
	struct udp_hdr * udp;
	struct arp_hdr * arp;
	struct icmp * icmpv6;
	FILE * fp;
	char filename[64];

	if (conf->save_latencies) {
		sprintf(filename, "port_%u_queue_%u_core_%u.txt", ptd->port, ptd->queue, lcore_id);
		fp = fopen (filename, "w+");
	}

	lcore_id = rte_lcore_id();
	printf("Handling port %u RX queue %u on core %u\n", ptd->port, ptd->queue, lcore_id);

	while(!rx_should_stop) {
		worker_barrier_check(b);

		nb_rx = rte_eth_rx_burst(ptd->port, ptd->queue, pkts, MAX_PKT_BURST);
		uint64_t tsc2 = rte_rdtsc();

		if (!nb_rx)
			continue;

		for (i = 0; i < nb_rx; i++) {
			eth_type = rte_pktmbuf_mtod_offset(pkts[i], uint16_t *, 12);

			/* handle ARP */
			if (unlikely(rte_be_to_cpu_16(*eth_type) == ETHER_TYPE_ARP)) {
				arp = rte_pktmbuf_mtod_offset(pkts[i], struct arp_hdr *, sizeof(struct ether_hdr));

				if (arp->arp_op == rte_cpu_to_be_16(ARP_OP_REPLY)) {

					if (arp->arp_data.arp_sip == conf->dst_ip4[0])
						ether_addr_copy(&arp->arp_data.arp_sha, (struct ether_addr *)&conf->dst_mac[0]);

					if (arp->arp_data.arp_sip == conf->dst_ip4[1])
						ether_addr_copy(&arp->arp_data.arp_sha, (struct ether_addr *)&conf->dst_mac[1]);

					rte_pktmbuf_free(pkts[i]);
					ptd->counters.num_rx_dropped++;
					continue;
				} else if (arp->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST)) {

					if (arp->arp_data.arp_tip == ptd->dst_ip4) {
						prepare_arp(conf, pkts[i], ARP_OP_REPLY, ptd->port);
						rte_eth_tx_burst(ptd->port, 0, &pkts[i], 1);
						continue;
					}

					rte_pktmbuf_free(pkts[i]);
					ptd->counters.num_rx_dropped++;
					continue;
				}

			/* handle IPv6 */
			} else if (rte_be_to_cpu_16(*eth_type) == ETHER_TYPE_IPv6) {
				if (!conf->ipv6) { /* We are using IPv4, drop IPv6 packet */
					rte_pktmbuf_free(pkts[i]);
					ptd->counters.num_rx_dropped++;
					continue;
				}
				ip6 = rte_pktmbuf_mtod_offset(pkts[i], struct ipv6_hdr *, sizeof(struct ether_hdr));
				udp = rte_pktmbuf_mtod_offset(pkts[i], struct udp_hdr *, sizeof(struct ether_hdr)+sizeof(*ip6));
				icmpv6 = rte_pktmbuf_mtod_offset(pkts[i], struct icmp *, sizeof(struct ether_hdr)+sizeof(*ip6));
				payload = rte_pktmbuf_mtod_offset(pkts[i], packet_payload *,
					sizeof(struct ether_hdr)+sizeof(*ip6)+sizeof(*udp));

				/* handle Network solicitation request */
				if (unlikely(ip6->proto == IPPROTO_ICMPV6)) {
					if (icmpv6->icmp_type == NEIGHBOR_SOLICITATION) {
						prepare_soladv(conf, pkts[i], ptd->port, NEIGHBOR_ADVERTISEMENT);
						rte_eth_tx_burst(ptd->port, 0, &pkts[i], 1);

					} else if (icmpv6->icmp_type == NEIGHBOR_ADVERTISEMENT) {

						if (!memcmp(&ip6->src_addr, &conf->dst_ip6[0], 16))
							ether_addr_copy((struct ether_addr *)&icmpv6->option_ll_addr,
											(struct ether_addr *)&conf->dst_mac[0]);

						if (!memcmp(&ip6->src_addr, &conf->dst_ip6[16], 16))
							ether_addr_copy((struct ether_addr *)&icmpv6->option_ll_addr,
											(struct ether_addr *)&conf->dst_mac[1]);

						rte_pktmbuf_free(pkts[i]);
						ptd->counters.num_rx_dropped++;
						continue;
					}
				}

				/* Is it our packet ? check addr && dst ports */
				if ((!memcmp(ip6->src_addr, ptd->src_ip6, 16)) || (!memcmp(ip6->dst_addr, ptd->dst_ip6, 16))) {
					ptd->counters.num_rx_dropped++;
					continue;
				}

				if(unlikely((conf->udp_port & (PORT_RANDOM|PORT_INCREMENT)) == 0)) {
						if (rte_be_to_cpu_16(udp->dst_port) != ptd->dst_port) {
						ptd->counters.num_rx_dropped++;
						continue;
					}
				}

				/* Set payload to UDP payload */
				payload = (packet_payload *)rte_pktmbuf_mtod_offset(pkts[i], uint64_t *,
					sizeof(struct ether_hdr)+sizeof(*ip6)+sizeof(*udp));
				if (payload->magic_id != PKT_MAGIC_ID) {
					printf("Bad magic number !\n"); fflush(stdout);
					rte_pktmbuf_free(pkts[i]);
					ptd->counters.num_rx_dropped++;
					continue;
				}

				/* handle IPv4 */
			} else if (rte_be_to_cpu_16(*eth_type) == ETHER_TYPE_IPv4) {
				if (conf->ipv6) { /* We are using IPv6, drop IPv4 packet */
					rte_pktmbuf_free(pkts[i]);
					ptd->counters.num_rx_dropped++;
					continue;
				}
				ip4 = rte_pktmbuf_mtod_offset(pkts[i], struct ipv4_hdr *, sizeof(struct ether_hdr));
				udp = rte_pktmbuf_mtod_offset(pkts[i], struct udp_hdr *, sizeof(struct ether_hdr)+sizeof(*ip4));
				payload = (packet_payload *)rte_pktmbuf_mtod_offset(pkts[i], uint64_t *,
					sizeof(struct ether_hdr)+sizeof(*ip4)+sizeof(*udp));

				/* Is it our packet ? check addr && dst ports */
				if ((ip4->src_addr != ptd->src_ip4) || (ip4->dst_addr != ptd->dst_ip4)) {
					ptd->counters.num_rx_dropped++;
					continue;
				}

				if(unlikely((conf->udp_port & (PORT_RANDOM|PORT_INCREMENT)) == 0)) {
					if (rte_be_to_cpu_16(udp->dst_port) != ptd->dst_port) {
						ptd->counters.num_rx_dropped++;
						continue;
					}
				}

				/* Set payload to UDP payload */
				if (payload->magic_id != PKT_MAGIC_ID) {
					printf("Bad magic number !\n"); fflush(stdout);
					rte_pktmbuf_free(pkts[i]);
					ptd->counters.num_rx_dropped++;
					continue;
				}
			} else {
				/* this was not IP packet, free memory && continue*/
// 				printf("UNKNOWN PACKET !\n"); fflush(stdout);
// 				hexdump(rte_pktmbuf_mtod_offset(pkts[i], void *, 0), pkts[i]->pkt_len);
				rte_pktmbuf_free(pkts[i]);
				ptd->counters.num_rx_dropped++;
				continue;
			}

			//printf("port %u queue %u tx_timestamp %lu rx_timestamp %lu delte %lu (%lu ns)\n",
			//       ptd->port, ptd->queue, *tsc1, tsc2, tsc2-*tsc1, TICKS_TO_NSEC(tsc2-*tsc1));
			//hexdump(rte_pktmbuf_mtod_offset(pkts[i], void *, 0), pkts[i]->pkt_len);
			latency = tsc2 - payload->tsc;
			if (payload->tsc > tsc2) {
				printf("Received invalid TSC! TSC@send: 0x%lx, TSC@recv: 0x%lx\n", payload->tsc, tsc2);
				hexdump(rte_pktmbuf_mtod_offset(pkts[i], void *, 0), pkts[i]->pkt_len);
				latency = 0;
			}
			if (conf->save_latencies)
				fprintf(fp, "%lu\n", TICKS_TO_NSEC(latency));

			/* set min/max and sum latency */
			ptd->counters.latency_sum += latency;
			if (latency < ptd->counters.latency_min)
				ptd->counters.latency_min = latency;
			if (latency > ptd->counters.latency_max)
				ptd->counters.latency_max = latency;

			/* Was there any DPDK error ? */
			if (unlikely(pkts[i]->ol_flags &
				(PKT_RX_L4_CKSUM_BAD | PKT_RX_IP_CKSUM_BAD | PKT_RX_EIP_CKSUM_BAD)))
				dump_dpdk_error(pkts[i]->ol_flags);

			/* Inc counters && free memory */
			ptd->counters.num_rx_pkts++;
			ptd->counters.num_rx_octets += pkts[i]->pkt_len;
			rte_pktmbuf_free(pkts[i]);
		}
	}
	__sync_fetch_and_add(b->num_workers, -1);
	if (conf->save_latencies)
		fclose(fp);
	return 0;
}

enum { QUIT_CTRL_C=1, QUIT_ALARM };
static void signal_stop(__attribute__((unused)) int signal)
{
	/* CTRL+C keypress from terminal handler */
	printf("\nSIGSTOP received, exitting...\n");
	should_quit = QUIT_CTRL_C;
}

static void signal_alarm(__attribute__((unused)) int signal)
{
	/* SIGALRM handler. SIGALRM is sent from last running RX thread */
	should_quit = QUIT_ALARM;
}

/* Calculate time diff. Used for latency calculation. */
static uint64_t clock_diff(struct timespec start, struct timespec end)
{
	struct timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp.tv_sec*1000+temp.tv_nsec/1000000;
}

/* Start DPDK RX/TX threads */
static per_thread_data_t * launch_threads(per_thread_data_t * ptd, thread_type_t rxtx)
{
	int lcore_id;
	unsigned int p, q, d;
	int num_threads = conf->num_ports * (conf->num_rx_queues + conf->num_tx_queues);

	if (ptd)
		free(ptd);

	/* Allocate cache-alligned per thread data */
	ptd = aligned_alloc(64, num_threads * sizeof(per_thread_data_t));
	memset(ptd, 0, num_threads * sizeof(per_thread_data_t));

	p = q = d = 0;

	clock_gettime(CLOCK_MONOTONIC, &started);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		unsigned int threads_per_port = conf->num_tx_queues + conf->num_rx_queues;
		int i = p * threads_per_port + q;
		if (p == conf->num_ports)
			continue;

		ptd[i].port = p;
		ptd[i].lcore_id = lcore_id;

		if (q < conf->num_tx_queues) {
			if (rxtx & THREAD_TX) {

				/* prepare TX threads */
				if (conf->pps)
					ptd[i].delay = ticks_per_sec / (conf->pps / conf->num_tx_queues);
				ptd[i].pts = conf->pts / conf->num_tx_queues;
				ptd[i].queue = q;
				ptd[i].type = THREAD_TX;
				if (p == 0) {
					rte_memcpy(&ptd[i].src_mac, (const void *)&conf->src_mac[0], 6);
					rte_memcpy(&ptd[i].dst_mac, (const void *)&conf->dst_mac[0], 6);
				} else {
					rte_memcpy(&ptd[i].src_mac, (const void *)&conf->src_mac[1], 6);
					rte_memcpy(&ptd[i].dst_mac, (const void *)&conf->dst_mac[1], 6);
				}
				ptd[i].src_ip4 = conf->src_ip4[p];
				ptd[i].dst_ip4 = conf->dst_ip4[p];
				memcpy(ptd[i].src_ip6, &conf->src_ip6[p*16], 16);
				memcpy(ptd[i].dst_ip6, &conf->dst_ip6[p*16], 16);

				ptd[i].src_port = conf->udp_port+q;
				ptd[i].dst_port = conf->udp_port;
				ptd[i].pkt_len = conf->packet_size;

				/* and launch it */
				__sync_fetch_and_add(b->num_workers,  1);
				rte_eal_remote_launch(lcore_tx_main, &ptd[i], lcore_id);
			}
		} else {
			if (rxtx & THREAD_RX) {

				/* prepare RX threads */
				ptd[i].queue = q - conf->num_tx_queues;
				ptd[i].type = THREAD_RX;
				ptd[i].src_ip4 = conf->src_ip4[(p==1)?0:1];
				ptd[i].dst_ip4 = conf->dst_ip4[(p==1)?0:1];
				ptd[i].dst_port = conf->udp_port;

				ptd[i].counters.latency_min = 0xffffffffffffffff;
				ptd[i].counters.latency_max = 0;

				/* and launch it */
				__sync_fetch_and_add(b->num_workers,  1);
				rte_eal_remote_launch(lcore_rx_main, &ptd[i], lcore_id);
			}
		}

		q++;
		if (q == threads_per_port) {
			q = 0;
			p++;
		}
	}

	/* If test duration was set, set up alarm. Alarm callback will shut down pktgen */
	if (conf->duration)
		alarm(conf->duration);

	return ptd;
}

typedef enum {RATE_START, RATE_UP, RATE_DOWN} updown;
static void binsrch_get_pps(updown direction)
{
	switch(direction)
	{
		case RATE_START:
			conf->cur_rate = (conf->max_rate - conf->min_rate) / 2;
			conf->binsrch_step = conf->cur_rate;
			break;

		case RATE_UP:
			conf->min_rate = conf->cur_rate + 1;
			conf->binsrch_step = (conf->max_rate - conf->min_rate) / 2;
			conf->cur_rate += conf->binsrch_step;
			break;

		case RATE_DOWN:
			conf->max_rate = conf->cur_rate - 1;
			conf->binsrch_step = (conf->max_rate - conf->min_rate) / 2;
			conf->cur_rate -= conf->binsrch_step;
			break;
	}

	conf->pps = rate_to_pps(conf->cur_rate);
	return;
}

static void linsrch_get_pps(updown direction)
{
	switch(direction)
	{
		case RATE_START:
			conf->cur_rate = conf->max_rate;
			break;

		case RATE_DOWN:
			conf->cur_rate -= conf->step;
			break;

		case RATE_UP: /* unused here */
			conf->cur_rate = 0;
			break;
	}

	conf->pps = rate_to_pps(conf->cur_rate);
	return;
}

/* Sum stats from per thread data */
static void calculate_runtime_counters(counters *runtime_cnt, per_thread_data_t * ptd, int num_threads)
{
	int q;

	for (q = 0; q < num_threads; q++) {
		runtime_cnt->num_tx_octets += ptd[q].counters.num_tx_octets;
		runtime_cnt->num_tx_pkts   += ptd[q].counters.num_tx_pkts;
		runtime_cnt->num_rx_octets += ptd[q].counters.num_rx_octets;
		runtime_cnt->num_rx_pkts   += ptd[q].counters.num_rx_pkts;
		runtime_cnt->num_rx_dropped+= ptd[q].counters.num_rx_dropped;

		if (ptd[q].type == THREAD_RX) {
			runtime_cnt->latency_sum   += ptd[q].counters.latency_sum;
			if (ptd[q].counters.latency_min < runtime_cnt->latency_min)
				runtime_cnt->latency_min = ptd[q].counters.latency_min;
			if (ptd[q].counters.latency_max > runtime_cnt->latency_max)
				runtime_cnt->latency_max = ptd[q].counters.latency_max;
		}

		/* clear stats */
		memset((void *)&ptd[q].counters, 0, sizeof(counters));

		/* set min interval to maximum */
		ptd[q].counters.latency_min = 0xffffffffffffffff;

	}

	if (runtime_cnt->num_tx_pkts < runtime_cnt->num_rx_pkts) {
		printf("Warning: received(%lu) more packets than sent(%lu)\n",
			   runtime_cnt->num_rx_pkts, runtime_cnt->num_tx_pkts);
		runtime_cnt->num_rx_pkts = runtime_cnt->num_tx_pkts;
	}
}

/* Dump per thread stats to stdout */
static void dump_ptd_stats(per_thread_data_t * ptd, int num_threads)
{
	int q;

	printf("\n========== run time %lu sec ==========\n", clock_diff(started, actual)/1000);

	for (q = 0; q < num_threads; q++) {

		if (ptd[q].type != THREAD_RX)
		{
			printf("Port %u queue %u tx pkts        : %15lu (%lu pps) [%lu kbit/s]\n",
				   ptd[q].port, ptd[q].queue,
		  ptd[q].counters.num_tx_pkts,
		  ptd[q].counters.num_tx_pkts / conf->stats_interval,
		  ptd[q].counters.num_tx_octets * 8 / (conf->stats_interval*1000));

		} else {
			if (ptd[q].counters.num_rx_pkts) {
				printf("Port %u queue %u rx pkts        : %15lu (%lu pps) [%lu kbit/s], %lu dropped\n",
					   ptd[q].port, ptd[q].queue,
		   ptd[q].counters.num_rx_pkts,
		   ptd[q].counters.num_rx_pkts / conf->stats_interval,
		   ptd[q].counters.num_rx_octets * 8 / (conf->stats_interval*1000),
		   ptd[q].counters.num_rx_dropped);

				printf("Port %u queue %u avg latency    : min/avg/max: (%lu ns)/(%lu ns)/(%lu ns)\n",
					   ptd[q].port, ptd[q].queue,
		   TICKS_TO_NSEC(ptd[q].counters.latency_min),
					   TICKS_TO_NSEC(ptd[q].counters.latency_sum/ptd[q].counters.num_rx_pkts),
					   TICKS_TO_NSEC(ptd[q].counters.latency_max));

			} else {
				printf("Port %u queue %u rx pkts        : No packets received\n",
					   ptd[q].port, ptd[q].queue);
			}
		}
	}
}

/* Dump final stats to stdout */
static void dump_final_stats(counters *ctr, uint64_t time_diff)
{
	if (!time_diff) {
		printf("Time diff is less than 1 ms, no stats are calculated\n");
		return;
	}

	printf("%lu packets transmitted, %lu received, lost %lu (%f%% packet loss), dropped %lu, time %lu ms\n",
		ctr->num_tx_pkts, ctr->num_rx_pkts,
		ctr->num_tx_pkts - ctr->num_rx_pkts,
		(float)((ctr->num_tx_pkts - ctr->num_rx_pkts) * 100 / (float)ctr->num_tx_pkts),
		ctr->num_rx_dropped,
		time_diff);

	printf("Average TX throughput %lu kbit/s, TX pps: %lu\n",
		   ((ctr->num_tx_octets) * 8 / time_diff),
		   (ctr->num_tx_pkts * 1000) / time_diff);

	printf("Average RX throughput %lu kbit/s, RX pps: %lu, latency min/avg/max %lu/%lu/%lu ns\n",
		   ((ctr->num_rx_octets) * 8 / time_diff),
		   (ctr->num_rx_pkts * 1000) / time_diff,
		   TICKS_TO_NSEC(ctr->latency_min),
		   TICKS_TO_NSEC(ctr->latency_sum / ctr->num_tx_pkts),
		   TICKS_TO_NSEC(ctr->latency_max));
}

int main(int argc, char **argv)
{
	int ret;
	int socketid = 0;
	struct rte_eth_txconf *txconf;
	struct rte_eth_dev_info dev_info;
	unsigned int p, q;
	int i;
	per_thread_data_t * ptd = NULL, * interval_copy;
	int num_threads;
	uint64_t lost, last_valid_pps=0;
	float lostpercent=0;

	/* check if "--" is present on command line. ("--" is separator for DPDK and pktgen
	 * cmdline arguments) csit-pktgen [dpdk-args] -- [pktgen args]
	 */
	for (i=0; i<argc; i++)
		if ((!strncmp(argv[i], "--", 2)) && (strlen(argv[i]) == 2))
			break;

	parse_cmdline(argc-i, &argv[i]); /* parameters after "--" are for pktgen */

	ret = rte_eal_init(i, argv); /* first parameter set is for dpdk, separated with "--" */
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot init EAL\n");

	/* get pointer to config struct */
	conf = get_config();

	/* get NIC MACs */
	rte_eth_macaddr_get (0, (void *)&conf->src_mac[0]);
	rte_eth_macaddr_get (1, (void *)&conf->src_mac[1]);

	signal(SIGINT, signal_stop);
	signal(SIGALRM, signal_alarm);

	ticks_per_sec = rte_get_tsc_hz();
	ticks_per_usec = ticks_per_sec/1000000;
	num_threads = conf->num_ports * (conf->num_rx_queues + conf->num_tx_queues);

	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool0", 32768,
										   MEMPOOL_CACHE_SIZE, 0,
										   RTE_MBUF_DEFAULT_BUF_SIZE, 0);

	if (pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	if (rte_eth_dev_count() !=  conf->num_ports)
		rte_exit(EXIT_FAILURE, "Please whitelist only %u device\n",
				 conf->num_ports);

	for (p = 0; p < conf->num_ports; p++) {

		ret = rte_eth_dev_configure(p, conf->num_rx_queues, conf->num_tx_queues, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_configure:"
								" err=%d, port=%d\n", ret, p);

		for (q = 0; q < conf->num_rx_queues; q++) {
			ret = rte_eth_rx_queue_setup(p, q, 512, socketid, NULL, pktmbuf_pool);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,"rte_eth_rx_queue_setup:"
									" err=%d, port=%d queue=%d\n", ret, p, q);
		}

		/* Setup TX queue */
		rte_eth_dev_info_get(p, &dev_info);
		txconf = &dev_info.default_txconf;
		for (q = 0; q < conf->num_tx_queues; q++) {
			ret = rte_eth_tx_queue_setup(p, q, 512, socketid, txconf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:"
									" err=%d, port=%d queue %d\n", ret, p, q);
		}

		rte_eth_promiscuous_enable(p);

		ret = rte_eth_dev_start(p);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d,"
								" port=%d\n", ret, p);
	}

	/* init barier for synchronizing threads */
	b = worker_barrier_init();

	/* send ARP first */
	ptd = launch_threads(ptd, THREAD_RX);

	if (conf->arp_delay) {
		printf("Waiting %i seconds before %s...\n", conf->arp_delay,
			   conf->ipv6 ? "Network Solicitation" : "ARP");

		sleep(conf->arp_delay);
		if (conf->ipv6)
			send_solicitation(conf);
		else
			send_arp(conf);

		printf("Waiting %i seconds after %s...\n", conf->arp_delay,
			   conf->ipv6 ? "Network Solicitation" : "ARP");
		sleep(conf->arp_delay);
	}

	rx_should_stop = 1; // stop RX threads
	rte_eal_mp_wait_lcore(); // check and mark all lcores as finished
	rx_should_stop = 0;

	/* init binary or linear search */
	switch(conf->test) {
		case BINSEARCH:
			binsrch_get_pps(RATE_START);
			printf("BINARY search: starting with: %lu bps (%lu pps) step: %lu\n",
				   pps_to_rate(conf->pps), conf->pps, conf->binsrch_step);
			break;

		case LINSEARCH:
			linsrch_get_pps(RATE_START);
			printf("LINEAR search: starting with: %lu bps (%lu pps)\n",
				   pps_to_rate(conf->pps), conf->pps);
			break;
	}

	interval_copy = aligned_alloc(64, num_threads * sizeof(per_thread_data_t));
	ptd = launch_threads(ptd, THREAD_RX|THREAD_TX);

	runtime_cnt.latency_min = 0xffffffffffffffff;

	print_configuration();

	while (1) {
		sleep(conf->stats_interval);

		if (should_quit) {
			if (should_quit == QUIT_CTRL_C)
				break;

			if (conf->test == BINSEARCH) {
				tx_should_stop = 1; // stop TX
				clock_gettime(CLOCK_MONOTONIC, &actual);
				sleep(FLUSH_BUFFER_TIME); // time to flush network card buffers
				rx_should_stop = 1;
				rte_eal_mp_wait_lcore(); // check and mark all lcores as finished
				should_quit = 0;
				tx_should_stop = rx_should_stop = 0;
				clear_barrier(b);
				calculate_runtime_counters(&runtime_cnt, ptd, num_threads);
				printf("\n");
				uint64_t time_diff = clock_diff(started, actual);

				lost = runtime_cnt.num_tx_pkts - runtime_cnt.num_rx_pkts;
				lostpercent = ((float)lost*100) / (float)runtime_cnt.num_tx_pkts;
				printf("BINARY search: finished test with rate: %lu bps (%lu pps), lost %lu (%f %%)\n",
					   pps_to_rate(conf->pps), conf->pps, lost, lostpercent);
				printf("BINARY search: sent (%lu packets [%lu pps]), received (%lu packets [%lu pps]) time: (%lu ms)\n",
						runtime_cnt.num_tx_pkts, runtime_cnt.num_tx_pkts * 1000 / time_diff,
						runtime_cnt.num_rx_pkts, runtime_cnt.num_rx_pkts * 1000 / time_diff,
						time_diff);

				if (lostpercent < conf->drop_ratio)
				{
					/* packetloss is bellow drop %, increase rate */
					last_valid_pps = conf->pps;
					binsrch_get_pps(RATE_UP);
					if (conf->binsrch_step > conf->step)
						printf("BINARY search: increasing rate to %lu bps (%lu pps) step: %lu\n",
						   pps_to_rate(conf->pps), conf->pps, conf->binsrch_step);
				}

				if (lostpercent > conf->drop_ratio)
				{
					/* packetloss is above drop %, decrease rate */
					binsrch_get_pps(RATE_DOWN);
					if (conf->binsrch_step > conf->step)
						printf("BINARY search: decreasing rate to %lu bps (%lu pps) step: %lu\n",
						   pps_to_rate(conf->pps), conf->pps, conf->binsrch_step);
				}

				if (conf->binsrch_step <= conf->step)
				{
					printf("BINARY search: current step (%lu) is bellow defined step (%lu), exitting...\n",
						   conf->binsrch_step, conf->step);

					if (lostpercent > (uint64_t)conf->drop_ratio)
						conf->pps = last_valid_pps;

					if (conf->pps)
						printf("BINARY search: found rate %lu bps (%lu pps)\n",
							   pps_to_rate(conf->pps), conf->pps);
					else
						printf("BINARY search: Rate not found !\n");
					exit(0);
				}

				memset(&runtime_cnt, 0, sizeof(counters));
				runtime_cnt.latency_min = 0xffffffffffffffff;
				ptd = launch_threads(ptd, THREAD_RX|THREAD_TX); // relaunch again
				continue;
			}

			if (conf->test == LINSEARCH) {
				/* linear search is starting at maxrate and decreases speed by step */
				tx_should_stop = 1; // stop TX
				clock_gettime(CLOCK_MONOTONIC, &actual);
				sleep(FLUSH_BUFFER_TIME); // time to flush network card buffers
				rx_should_stop = 1;
				rte_eal_mp_wait_lcore(); // check and mark all lcores as finished
				should_quit = 0;
				tx_should_stop = rx_should_stop = 0;
				clear_barrier(b);
				calculate_runtime_counters(&runtime_cnt, ptd, num_threads);
				printf("\n");
				uint64_t time_diff = clock_diff(started, actual);

				lost = runtime_cnt.num_tx_pkts - runtime_cnt.num_rx_pkts;
				lostpercent = ((float)lost*100) / (float)runtime_cnt.num_tx_pkts;
				printf("LINEAR search: finished test with rate: %lu bps (%lu pps), lost %lu (%f %%)\n",
					   pps_to_rate(conf->pps), conf->pps, lost, lostpercent);
				printf("LINEAR search: sent (%lu packets [%lu pps]), received (%lu packets [%lu pps]) time: (%lu ms)\n",
						runtime_cnt.num_tx_pkts, runtime_cnt.num_tx_pkts * 1000 / time_diff,
						runtime_cnt.num_rx_pkts, runtime_cnt.num_rx_pkts * 1000 / time_diff,
						time_diff);

				if (lostpercent > conf->drop_ratio)
				{
					/* packetloss is above drop , decrease rate */
					linsrch_get_pps(RATE_DOWN);
					printf("LINEAR search: Decreasing rate to %lu bps (%lu pps)\n", pps_to_rate(conf->pps), conf->pps);
				} else
				{
					printf("LINEAR search: Found rate %lu bps (%lu pps)\n", pps_to_rate(conf->pps), conf->pps);
					exit(0);
				}

				if (conf->cur_rate <= conf->min_rate) {
					printf("LINEAR search: Rate not found !\n");
					exit(0);
				}

				memset(&runtime_cnt, 0, sizeof(counters));
				runtime_cnt.latency_min = 0xffffffffffffffff; /* set maximum latency */
				ptd = launch_threads(ptd, THREAD_RX|THREAD_TX); // relaunch again
				continue;
			}

			if (conf->test == FIXRATE)
				break;
		}

		worker_barrier_sync(b);
		memcpy(interval_copy, ptd, num_threads * sizeof(per_thread_data_t));
		calculate_runtime_counters(&runtime_cnt, ptd, num_threads);
		worker_barrier_release(b);

		clock_gettime(CLOCK_MONOTONIC, &actual);
		dump_ptd_stats(interval_copy, num_threads);
	}

	/* fixrate test ends here */
	printf("Stopping Tx threads and waiting for Rx threads to finish\n");
	tx_should_stop = 1;
	clock_gettime(CLOCK_MONOTONIC, &actual);
	sleep(FLUSH_BUFFER_TIME);
	rx_should_stop = 1;
	rte_eal_mp_wait_lcore();

	calculate_runtime_counters(&runtime_cnt, ptd, num_threads);
	dump_final_stats(&runtime_cnt, clock_diff(started, actual));

	return 0;
}
