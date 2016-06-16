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

#include "barrier.h"
#include "config.h"

#define MEMPOOL_CACHE_SIZE   256

config_t *conf = NULL;

#define TICKS_TO_NSEC(x) ((x) * 1000 / ticks_per_usec)
uint64_t ticks_per_sec;
int ticks_per_usec;
int should_quit = 0;
volatile int rx_should_stop = 0; /* >0 to stop all rx threads */
volatile int tx_should_stop = 0; /* >0 to stop all rx threads */
volatile int tx_threads_stopped = 0; /* number of stopped tx threads */
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
	THREAD_RX,
	THREAD_TX
} thread_type_t;

typedef struct {
	/* stats */
	uint64_t num_tx_pkts;
	uint64_t num_tx_octets;

	uint64_t num_rx_pkts;
	uint64_t num_rx_octets;

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
	uint64_t delay; /* delay between packets, calculated ad thread start frpm pps */
	uint64_t pts; /* number of packets to send by this thread */

	counters counters;

} per_thread_data_t;

typedef struct {
	uint64_t tsc; // time stamp counter
} packet_payload;

counters runtime_cnt = {0};

static inline void dump_dpdk_error(uint64_t flags)
{
	printf("received packet with DPDK errors: ");
	__asm__("int $3");
	if (flags & PKT_RX_L4_CKSUM_BAD)
		printf("L4 cksum of RX pkt. is not OK.\n");
	if (flags & PKT_RX_IP_CKSUM_BAD)
		printf("IP cksum of RX pkt. is not OK.\n");
	if (flags & PKT_RX_EIP_CKSUM_BAD)
		printf("External IP header checksum error.\n");
	if (flags & PKT_RX_OVERSIZE)
		printf("Num of desc of an RX pkt oversize.\n");
	if (flags & PKT_RX_HBUF_OVERFLOW)
		printf("Header buffer overflow.\n");
	if (flags & PKT_RX_RECIP_ERR)
		printf("Hardware processing error.\n");
	if (flags & PKT_RX_MAC_ERR)
		printf("MAC error.\n");
	if (flags & PKT_RX_IEEE1588_PTP)
		printf("RX IEEE1588 L2 Ethernet PT Packet.\n");
	if (flags & PKT_RX_IEEE1588_TMST)
		printf("RX IEEE1588 L2/L4 timestamped packet.\n");
	if (flags & PKT_RX_FDIR_ID)
		printf("FD id reported if FDIR match.\n");
	if (flags & PKT_RX_FDIR_FLX)
		printf("Flexible bytes reported if FDIR match.\n");
	if (flags & PKT_RX_QINQ_PKT)
		printf(") RX packet with double VLAN stripped.\n");
	printf("\n");
}

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
	ip4->src_addr        = rte_cpu_to_be_32(ptd->src_ip4);
	ip4->dst_addr        = rte_cpu_to_be_32(ptd->dst_ip4);
	ip4->hdr_checksum    = 0;

	/* UDP */
	switch(ptd->src_port & 0xffff0000) {
	case PORT_RANDOM:
		udp->src_port = rand() & 0xffff; // FIXME rand (is up to 32768)!
		break;
	case PORT_INCREMENT:
		if ((ptd->counters.num_tx_pkts % (conf->src_port & 0xffff)) == 0) {
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
		if ((ptd->counters.num_tx_pkts % (conf->dst_port & 0xffff)) == 0) {
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
		if ((ptd->counters.num_tx_pkts % (conf->src_port & 0xffff)) == 0) {
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
		if ((ptd->counters.num_tx_pkts % (conf->dst_port & 0xffff)) == 0) {
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

static int
lcore_tx_main(__attribute__((unused)) void *arg)
{
	int i;
	unsigned lcore_id;
	per_thread_data_t * ptd = (per_thread_data_t *) arg;
	uint64_t tsc, last_run_tsc = 0;
	packet_payload *payload;
	struct rte_mbuf *pkts[MAX_PKT_BURST];
	int pkts_in_round = conf->burst_size;
	int pkts_sent;
	int pts_present = 0;

	lcore_id = rte_lcore_id();
	printf("Handling port %u TX queue %u on core %u\n", ptd->port, ptd->queue, lcore_id);

	if (ptd->src_port & PORT_INCREMENT) /* start from zero*/
		ptd->src_port &= 0xffff0000;
	if (ptd->dst_port & PORT_INCREMENT) /* start from zero*/
		ptd->dst_port &= 0xffff0000;

	while(!tx_should_stop) {
		worker_barrier_check(b);
		tsc = rte_rdtsc_precise();

		if(unlikely(ptd->pts)) {
			pts_present = 1;
			pkts_in_round = (ptd->pts > (uint64_t)conf->burst_size) ? conf->burst_size : ptd->pts;
		}

		if(unlikely(ptd->delay)) {
			pkts_in_round = 1;
			if (tsc < (last_run_tsc + ptd->delay))
				continue;
		}
		last_run_tsc = tsc;

		for (i=0; i<pkts_in_round; i++) {
			pkts[i] = rte_pktmbuf_alloc(pktmbuf_pool);

			if (!conf->ipv6)
				payload = craft_packet_ipv4(ptd, pkts[i]);
			else
				payload = craft_packet_ipv6(ptd, pkts[i]);

			payload->tsc = rte_rdtsc_precise();
			calculate_checksum(pkts[i]);
		}

		pkts_sent = rte_eth_tx_burst(ptd->port, ptd->queue, pkts, pkts_in_round);
		ptd->counters.num_tx_pkts += pkts_sent;
		ptd->counters.num_tx_octets += ptd->pkt_len * pkts_sent;

		for (i=0; i<pkts_in_round; i++)
			rte_pktmbuf_free(pkts[i]);

		if(unlikely(pts_present)) {
			ptd->pts -= pkts_sent;
			if (!ptd->pts) {
				__sync_fetch_and_add(&tx_threads_stopped,  1);
				break;
			}
		}
	}
	if (tx_threads_stopped == conf->num_tx_queues * conf->num_ports) { /* this was the last thread */
		kill(0, SIGALRM);
	}
	__sync_fetch_and_add(b->num_workers, -1);
	return 0;
}

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

	lcore_id = rte_lcore_id();
	printf("Handling port %u RX queue %u on core %u\n", ptd->port, ptd->queue, lcore_id);

	while(!rx_should_stop) {
		worker_barrier_check(b);

		nb_rx = rte_eth_rx_burst(ptd->port, ptd->queue, pkts, conf->burst_size);
		uint64_t tsc2 = rte_rdtsc_precise();
		if (!nb_rx)
			continue;

		ptd->counters.num_rx_pkts += nb_rx;

		for (i = 0; i < nb_rx; i++) {
			eth_type = (uint16_t *)rte_pktmbuf_mtod_offset(pkts[i], uint64_t *, 12);
			if (rte_be_to_cpu_16(*eth_type) == ETHER_TYPE_IPv6)
				payload = (packet_payload *)rte_pktmbuf_mtod_offset(pkts[i], uint64_t *,
					sizeof(struct ether_hdr)+sizeof(struct ipv6_hdr)+sizeof(struct udp_hdr));
			else
				payload = (packet_payload *)rte_pktmbuf_mtod_offset(pkts[i], uint64_t *,
					sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)+sizeof(struct udp_hdr));

			//printf("port %u queue %u tx_timestamp %lu rx_timestamp %lu delte %lu (%lu ns)\n",
			//       ptd->port, ptd->queue, *tsc1, tsc2, tsc2-*tsc1, TICKS_TO_NSEC(tsc2-*tsc1));
			//hexdump(rte_pktmbuf_mtod_offset(pkts[i], void *, 0), pkts[i]->pkt_len);
			latency = tsc2-payload->tsc;

			ptd->counters.latency_sum += latency;
			if (latency < ptd->counters.latency_min)
				ptd->counters.latency_min = latency;
			if (latency > ptd->counters.latency_max)
				ptd->counters.latency_max = latency;

			if (unlikely(pkts[i]->ol_flags & 0xFFFFFFFFFFFFFFF8)) /* mask lowest 3 bits */
				dump_dpdk_error(pkts[i]->ol_flags);

			ptd->counters.num_rx_octets += pkts[i]->pkt_len;
			rte_pktmbuf_free(pkts[i]);
		}
	}
	__sync_fetch_and_add(b->num_workers, -1);
	return 0;
}

enum { QUIT_CTRL_C=1, QUIT_ALARM };
static void signal_stop(__attribute__((unused)) int signal)
{
	printf("\nSIGSTOP received, exitting...\n");
	should_quit = QUIT_CTRL_C;
}

static void signal_alarm(__attribute__((unused)) int signal)
{
	should_quit = QUIT_ALARM;
}

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

static per_thread_data_t * launch_threads(per_thread_data_t * ptd)
{
	int lcore_id;
	int p, q, d;
	int num_threads = conf->num_ports * (conf->num_rx_queues + conf->num_tx_queues);

	if (ptd)
		free(ptd);

	ptd = aligned_alloc(64, num_threads * sizeof(per_thread_data_t));
	memset(ptd, 0, num_threads * sizeof(per_thread_data_t));

	p = q = d = 0;

	clock_gettime(CLOCK_MONOTONIC, &started);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		int threads_per_port = conf->num_tx_queues + conf->num_rx_queues;
		int i = p * threads_per_port + q;
		if (p == conf->num_ports)
			continue;

		ptd[i].port = p;
		ptd[i].lcore_id = lcore_id;

		if (q < conf->num_tx_queues) {
			if (conf->pps)
				ptd[i].delay = ticks_per_sec / (conf->pps / conf->num_tx_queues);
			ptd[i].pts = conf->pts / conf->num_tx_queues;
			ptd[i].queue = q;
			ptd[i].type = THREAD_TX;
			if (p == 0) {
				rte_memcpy(&ptd[i].src_mac, (const void *)&conf->src_mac[0], 6);
				rte_memcpy(&ptd[i].dst_mac, (const void *)&conf->dst_mac[1], 6);
			} else {
				rte_memcpy(&ptd[i].src_mac, (const void *)&conf->src_mac[1], 6);
				rte_memcpy(&ptd[i].dst_mac, (const void *)&conf->dst_mac[0], 6);
			}
			ptd[i].src_ip4 = conf->src_ip4[p];
			ptd[i].dst_ip4 = conf->dst_ip4[p];
			memcpy(ptd[i].src_ip6, &conf->src_ip6[p*16], 16);
			memcpy(ptd[i].dst_ip6, &conf->dst_ip6[p*16], 16);

			ptd[i].src_port = conf->src_port+q;
			ptd[i].dst_port = conf->dst_port+q;
			ptd[i].pkt_len = conf->packet_size;

			__sync_fetch_and_add(b->num_workers,  1);
			rte_eal_remote_launch(lcore_tx_main, &ptd[i], lcore_id);
		} else {
			ptd[i].queue = q - conf->num_tx_queues;
			ptd[i].type = THREAD_RX;
			ptd[i].counters.latency_min = 0xffffffffffffffff;
			ptd[i].counters.latency_max = 0;
			__sync_fetch_and_add(b->num_workers,  1);
			rte_eal_remote_launch(lcore_rx_main, &ptd[i], lcore_id);
		}

		q++;
		if (q == threads_per_port) {
			q = 0;
			p++;
		}
	}

	if (conf->duration)
		alarm(conf->duration);

	return ptd;
}

typedef enum {RATE_START, RATE_UP, RATE_DOWN} updown;
static uint64_t binsrch_get_next_pps(updown direction)
{
	uint64_t interval;
	uint64_t rate;

	switch(direction)
	{
		case RATE_START:
			interval = conf->max_rate - conf->min_rate;
			rate = conf->min_rate + interval / 2;
			printf("Linerate %lu Mbit/s (%lu pps).\n", rate/1000000, rate_to_pps(rate));
			break;

		case RATE_UP:
			conf->min_rate = conf->cur_rate;
			interval = conf->max_rate - conf->min_rate;
			rate = conf->min_rate + interval / 2;
			break;

		case RATE_DOWN:
			conf->max_rate = conf->cur_rate;
			interval = conf->max_rate - conf->min_rate;
			rate = conf->min_rate + interval / 2;
			break;
	}

	conf->cur_rate = rate;
	return rate_to_pps(rate);
}

static void calculate_runtime_counters(counters *runtime_cnt, per_thread_data_t * ptd, int num_threads)
{
	int q;

	for (q = 0; q < num_threads; q++) {
		runtime_cnt->num_tx_octets += ptd[q].counters.num_tx_octets;
		runtime_cnt->num_tx_pkts   += ptd[q].counters.num_tx_pkts;
		runtime_cnt->num_rx_octets += ptd[q].counters.num_rx_octets;
		runtime_cnt->num_rx_pkts   += ptd[q].counters.num_rx_pkts;

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
}

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
				printf("Port %u queue %u rx pkts        : %15lu (%lu pps) [%lu kbit/s]\n",
					   ptd[q].port, ptd[q].queue,
		   ptd[q].counters.num_rx_pkts,
		   ptd[q].counters.num_rx_pkts / conf->stats_interval,
		   ptd[q].counters.num_rx_octets * 8 / (conf->stats_interval*1000));

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

static void dump_final_stats(counters *ctr, uint64_t time_diff)
{
	printf("%lu packets transmitted, %lu received, lost %lu (%i%% packet loss), time %lu ms\n",
		ctr->num_tx_pkts, ctr->num_rx_pkts,
		ctr->num_tx_pkts - ctr->num_rx_pkts,
		(int)((ctr->num_tx_pkts - ctr->num_rx_pkts) * 100 / ctr->num_tx_pkts),
		time_diff);

	printf("Average throughput %lu kbit/s, latency min/avg/max %lu/%lu/%lu ns\n",
		((ctr->num_tx_octets) * 8 / time_diff),
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
	int p, q, i;
	per_thread_data_t * ptd = NULL, * interval_copy;
	int num_threads;
	uint64_t packetloss, old_pps=0;

	for (i=0; i<argc; i++)
		if ((!strncmp(argv[i], "--", 2)) && (strlen(argv[i]) == 2))
			break;

	parse_cmdline(argc-i, &argv[i]); /* parameters after "--" are for pktgen */

	ret = rte_eal_init(i, argv); /* first parameter set is for dpdk, separated with "--" */
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot init EAL\n");

	conf = get_config();

	rte_eth_macaddr_get (0, (void *)&conf->src_mac[0]);
	rte_eth_macaddr_get (1, (void *)&conf->src_mac[1]);

	if (!conf->dst_macs_are_set) {
		rte_eth_macaddr_get (0, (void *)&conf->src_mac[1]);
		rte_eth_macaddr_get (1, (void *)&conf->src_mac[0]);
	}

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

	b = worker_barrier_init();
	if (conf->test == BINSEARCH) {
		conf->pps = binsrch_get_next_pps(RATE_START);
	}

	interval_copy = aligned_alloc(64, num_threads * sizeof(per_thread_data_t));
	ptd = launch_threads(ptd);

	runtime_cnt.latency_min = 0xffffffffffffffff;

	while (1) {
		sleep(conf->stats_interval);

		if (should_quit) {
			if (should_quit == QUIT_CTRL_C)
				break;

			if (conf->test == BINSEARCH) {
				tx_should_stop = 1; // stop TX
				clock_gettime(CLOCK_MONOTONIC, &actual);
				sleep(1); // time to flush network card buffers
				rx_should_stop = 1;
				rte_eal_mp_wait_lcore(); // check and mark all lcores as finished
				should_quit = 0;
				tx_should_stop = rx_should_stop = 0;
				clear_barrier(b);
				calculate_runtime_counters(&runtime_cnt, ptd, num_threads);
				printf("\n");
				dump_final_stats(&runtime_cnt, clock_diff(started, actual));

				packetloss = runtime_cnt.num_tx_pkts - runtime_cnt.num_rx_pkts;
				if (packetloss < (uint64_t)conf->drop)
				{
					conf->pps = binsrch_get_next_pps(RATE_UP);
					printf("Increasing rate to %lu bps (%lu pps)\n", pps_to_rate(conf->pps), conf->pps);
				}

				if (packetloss > (uint64_t)conf->drop)
				{
					conf->pps = binsrch_get_next_pps(RATE_DOWN);
					printf("Decreasing rate to %lu bps (%lu pps)\n", pps_to_rate(conf->pps), conf->pps);
				}

				if (old_pps == conf->pps)
				{
					printf("Found rate %lu bps (%lu pps)\n", pps_to_rate(conf->pps), conf->pps);
					exit(0);
				}

				memset(&runtime_cnt, 0, sizeof(counters));
				runtime_cnt.latency_min = 0xffffffffffffffff;
				old_pps = conf->pps;
				ptd = launch_threads(ptd); // relaunch again
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

	printf("Stopping Tx threads and waiting for Rx threads to finish\n");
	tx_should_stop = 1;
	clock_gettime(CLOCK_MONOTONIC, &actual);
	sleep(1);
	rx_should_stop = 1;
	rte_eal_mp_wait_lcore();

	calculate_runtime_counters(&runtime_cnt, ptd, num_threads);
	dump_final_stats(&runtime_cnt, clock_diff(started, actual));

	return 0;
}
