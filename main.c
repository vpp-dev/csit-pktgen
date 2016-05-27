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
#define MAX_PKT_BURST        32

config_t *conf = NULL;

#define TICKS_TO_NSEC(x) ((x) * 1000 / ticks_per_usec)
int ticks_per_usec = 1700;
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

static uint8_t broadcast_addr[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

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
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t pps; /* packets per second */
	uint32_t pts; /* number of packets to send by this thread */

	/* stats */
	uint64_t num_tx_pkts;
	uint64_t old_tx_pkts;
	uint64_t num_tx_octets;
	uint64_t num_rx_pkts;
	uint64_t old_rx_pkts;
	uint64_t num_rx_octets;
	uint64_t last_tsc;

	uint64_t latency_sum;
	uint64_t latency_min; /* total latency */
	uint64_t latency_max;
	uint64_t latency_min_interval; /* per interval latency */
	uint64_t latency_max_interval;
} per_thread_data_t;

static inline void *
craft_packet(per_thread_data_t * ptd, struct rte_mbuf *pkt)
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
	ip4->total_length   = rte_cpu_to_be_16(ptd->pkt_len - sizeof(*eth));
	ip4->src_addr = rte_cpu_to_be_32(ptd->src_ip4);
	ip4->dst_addr = rte_cpu_to_be_32(ptd->dst_ip4);
	ip4->hdr_checksum = rte_ipv4_cksum(ip4);

	/* UDP */
	udp->src_port = rte_cpu_to_be_16(ptd->src_port);
	udp->dst_port = rte_cpu_to_be_16(ptd->dst_port);
	udp->dgram_len = rte_cpu_to_be_16(ptd->pkt_len - sizeof(*eth) - sizeof(*ip4));
	udp->dgram_cksum = 0;

	return (udp+1);
}

static int
lcore_tx_main(__attribute__((unused)) void *arg)
{
	unsigned lcore_id;
	per_thread_data_t * ptd = (per_thread_data_t *) arg;
	uint64_t tsc, last_run_tsc = 0;
	struct rte_mbuf *pkt = NULL;

	lcore_id = rte_lcore_id();
	printf("Handling port %u TX queue %u on core %u\n", ptd->port, ptd->queue, lcore_id);

	while(!tx_should_stop) {
		worker_barrier_check(b);
		tsc = ptd->last_tsc = rte_rdtsc_precise();

		if(unlikely(ptd->pps))
			if (tsc < last_run_tsc + (1000000 / ptd->pps) * ticks_per_usec)
				continue;

		if (likely(pkt == NULL)) {
			pkt = rte_pktmbuf_alloc(pktmbuf_pool);
			if (unlikely(pkt == NULL))
				continue;
		}

		last_run_tsc = tsc;

		uint64_t  * payload = craft_packet(ptd, pkt);
		//hexdump(rte_pktmbuf_mtod_offset(pkt, void *, 0), ptd->pkt_len);
		*payload = rte_rdtsc_precise();

		if (likely(rte_eth_tx_burst(ptd->port, ptd->queue, &pkt, 1))) { /* packet was sent */
			ptd->num_tx_pkts ++;
			ptd->num_tx_octets += ptd->pkt_len;
			pkt = NULL;
		}

		if(unlikely(ptd->pts)) {
			if (ptd->pts == ptd->num_tx_pkts) {
				if (pkt)
					rte_pktmbuf_free(pkt);
				__sync_fetch_and_add(&tx_threads_stopped,  1);
				break;
			}
		}
	}

	if (tx_threads_stopped == conf->num_tx_queues * conf->num_ports) { /* this was the last thread */
		kill(0, SIGALRM);
	}

	return 0;
}

static int
lcore_rx_main(__attribute__((unused)) void *arg)
{
	int nb_rx = 0;
	int i;
	unsigned lcore_id;
	uint64_t latency;
	struct rte_mbuf *pkts[MAX_PKT_BURST];
	per_thread_data_t * ptd = (per_thread_data_t *) arg;

	lcore_id = rte_lcore_id();
	printf("Handling port %u RX queue %u on core %u\n", ptd->port, ptd->queue, lcore_id);

	ptd->latency_min_interval = 0xffffffffffffffff;
	ptd->latency_max_interval = 0;

	while(!rx_should_stop) {
		worker_barrier_check(b);
		ptd->last_tsc = rte_rdtsc_precise();
		nb_rx = rte_eth_rx_burst(ptd->port, ptd->queue, pkts, MAX_PKT_BURST);
		uint64_t *tsc1, tsc2 = rte_rdtsc_precise();
		if (!nb_rx)
			continue;

		ptd->num_rx_pkts += nb_rx;

		for (i = 0; i < nb_rx; i++) {
			tsc1 = rte_pktmbuf_mtod_offset(pkts[i], uint64_t *, 14+20+8);
			//printf("port %u queue %u tx_timestamp %lu rx_timestamp %lu delte %lu (%lu ns)\n",
			//       ptd->port, ptd->queue, *tsc1, tsc2, tsc2-*tsc1, TICKS_TO_NSEC(tsc2-*tsc1));
			//hexdump(rte_pktmbuf_mtod_offset(pkts[i], void *, 0), pkts[i]->pkt_len);
			latency = tsc2-*tsc1;

			ptd->latency_sum += latency;
			if (latency < ptd->latency_min_interval)
				ptd->latency_min_interval = latency;
			if (latency > ptd->latency_max_interval)
				ptd->latency_max_interval = latency;

			rte_pktmbuf_free(pkts[i]);
		}
	}

	return 0;
}

static void signal_stop(__attribute__((unused)) int signal)
{
	printf("\nSIGSTOP received, exitting...\n");
	should_quit = 1;
}

static void signal_alarm(__attribute__((unused)) int signal)
{
	should_quit = 1;
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

int main(int argc, char **argv)
{
	int ret;
	int socketid = 0;
	int lcore_id;
	struct rte_eth_txconf *txconf;
	struct rte_eth_dev_info dev_info;
	int p, q, d, i;
	per_thread_data_t * ptd, * ptd_copy;
	int num_threads;

	for (i=0; i<argc; i++)
		if (!strncmp(argv[i], "--", 2))
			break;

	parse_cmdline(argc-i, &argv[i]); /* parameters after "--" are for pktgen */

	ret = rte_eal_init(i, argv); /* first parameter set is for dpdk, separated with "--" */
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot init EAL\n");

	conf = get_config();
	num_threads = conf->num_ports * (conf->num_rx_queues + conf->num_tx_queues);

	signal(SIGINT, signal_stop);
	signal(SIGALRM, signal_alarm);

	ticks_per_usec = rte_get_tsc_hz()/1000000;

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

	b = worker_barrier_init(num_threads);

	ptd = aligned_alloc(64, num_threads * sizeof(per_thread_data_t));
	ptd_copy = aligned_alloc(64, num_threads * sizeof(per_thread_data_t));
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
			ptd[i].pps = conf->pps / conf->num_tx_queues;
			ptd[i].pts = conf->pts / conf->num_tx_queues;
			ptd[i].queue = q;
			ptd[i].type = THREAD_TX;
			rte_eth_macaddr_get (p, &ptd[i].src_mac);
			rte_memcpy(&ptd[i].dst_mac, broadcast_addr, 6);
			ptd[i].src_ip4 = IPv4(172, 16, p+1, 2);
			ptd[i].dst_ip4 = IPv4(172, 16, p+1, 1);
			ptd[i].src_port = 1024 + p*16 + q;
			ptd[i].dst_port = 2048 + p*16 + q;
			ptd[i].pkt_len = conf->packet_size;
			rte_eal_remote_launch(lcore_tx_main, &ptd[i], lcore_id);
		} else {
			ptd[i].queue = q - conf->num_tx_queues;
			ptd[i].type = THREAD_RX;
			ptd[i].latency_min = 0xffffffffffffffff;
			ptd[i].latency_max = 0;
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

	while (!should_quit) {
		uint64_t tot_rx_pkts = 0;
		uint64_t tot_rx_pps = 0;
		uint64_t tot_tx_pkts = 0;
		uint64_t tot_tx_pps = 0;
		uint64_t min_tsc = ~0;
		uint64_t max_tsc = 0;
		uint64_t pps;

		sleep(conf->stats_interval);

		if (should_quit)
			break;

		worker_barrier_sync(b);
		memcpy(ptd_copy, ptd, num_threads * sizeof(per_thread_data_t));

		for (q = 0; q < num_threads; q++) {
			/* save old values */
			ptd[q].old_tx_pkts = ptd[q].num_tx_pkts;
			ptd[q].old_rx_pkts = ptd[q].num_rx_pkts;

			/* calculate max/min latency per life */
			if (ptd[q].latency_min_interval < ptd[q].latency_min)
				ptd[q].latency_min = ptd[q].latency_min_interval;
			if (ptd[q].latency_max_interval > ptd[q].latency_max)
				ptd[q].latency_max = ptd[q].latency_max_interval;
			ptd[q].latency_min_interval = 0xffffffffffffffff;
			ptd[q].latency_max_interval = 0;
		}

		worker_barrier_release(b);
		clock_gettime(CLOCK_MONOTONIC, &actual);

		printf("\n========== run time %lu sec ==========\n", clock_diff(started, actual)/1000);
		printf("%-30s: %lu ticks (%lu ns)\n", "Barrier duration",
			   worker_barrier_last_duration(b),
			   TICKS_TO_NSEC(worker_barrier_last_duration(b)));

		for (q = 0; q < num_threads; q++) {
			if (ptd_copy[q].last_tsc < min_tsc)
				min_tsc = ptd_copy[q].last_tsc;

			if (ptd_copy[q].last_tsc > max_tsc)
				max_tsc = ptd_copy[q].last_tsc;
		}

		printf("%-30s: %lu ticks (%lu ns)\n", "TSC drift",
			   max_tsc - min_tsc, TICKS_TO_NSEC(max_tsc - min_tsc));

		for (q = 0; q < num_threads; q++) {

			if (ptd_copy[q].type != THREAD_RX) {
				pps = ptd_copy[q].num_tx_pkts - ptd_copy[q].old_tx_pkts;
				printf("Port %u queue %u tx pkts        : %15lu (%lu pps) [%lu kbit/s]\n",
					   ptd_copy[q].port, ptd_copy[q].queue,
					   ptd_copy[q].num_tx_pkts,
					   pps / conf->stats_interval,
					   pps * conf->packet_size * 8 / (conf->stats_interval*1000));
				tot_tx_pkts += ptd_copy[q].num_tx_pkts;
				tot_tx_pps += ptd_copy[q].num_tx_pkts - ptd_copy[q].old_tx_pkts;

			} else {
				if (ptd_copy[q].num_rx_pkts) {
					pps = ptd_copy[q].num_rx_pkts - ptd_copy[q].old_rx_pkts;
					printf("Port %u queue %u rx pkts        : %15lu (%lu pps) [%lu kbit/s]\n",
						   ptd_copy[q].port, ptd_copy[q].queue,
						   ptd_copy[q].num_rx_pkts,
						   pps / conf->stats_interval,
						   pps * conf->packet_size * 8 / (conf->stats_interval*1000));

					printf("Port %u queue %u avg latency    : %15lu (%lu ns), max: (%lu ns), min: (%lu ns)\n",
						   ptd_copy[q].port, ptd_copy[q].queue,
						   ptd_copy[q].latency_sum/ptd_copy[q].num_rx_pkts,
						   TICKS_TO_NSEC(ptd_copy[q].latency_sum/ptd_copy[q].num_rx_pkts),
						   TICKS_TO_NSEC(ptd_copy[q].latency_max_interval),
						   TICKS_TO_NSEC(ptd_copy[q].latency_min_interval));

					tot_rx_pkts += ptd_copy[q].num_rx_pkts;
					tot_rx_pps += ptd_copy[q].num_rx_pkts - ptd_copy[q].old_rx_pkts;
				} else {
					printf("Port %u queue %u rx pkts        : No packets received\n",
						   ptd_copy[q].port, ptd_copy[q].queue);
				}
			}
		}
		printf("%-30s: %15lu (%lu pps)\n", "Total Tx pkts", tot_tx_pkts, tot_tx_pps);
		printf("%-30s: %15lu (%lu pps)\n", "Total Rx pkts", tot_rx_pkts, tot_rx_pps);
	}

	printf("Stopping Tx threads and waiting for Rx threads to finish\n");
	tx_should_stop = 1;
	clock_gettime(CLOCK_MONOTONIC, &actual);
	usleep(100000);
	rx_should_stop = 1;
	rte_eal_mp_wait_lcore();

	uint64_t tot_rx_pkts = 0;
	uint64_t tot_tx_pkts = 0;
	uint64_t latency_avg = 0;
	uint64_t latency_min = 0xffffffffffffffff;
	uint64_t latency_max = 0;
	uint64_t time_diff = clock_diff(started, actual);

	for (q = 0; q < num_threads; q++) {
		if (ptd[q].type != THREAD_RX) {
			tot_tx_pkts += ptd[q].num_tx_pkts;

		} else {
			tot_rx_pkts += ptd[q].num_rx_pkts;
			if (likely(ptd[q].num_rx_pkts))
				latency_avg += ptd[q].latency_sum/ptd[q].num_rx_pkts;

			if (ptd[q].latency_min_interval < ptd[q].latency_min)
				ptd[q].latency_min = ptd[q].latency_min_interval;
			if (ptd[q].latency_max_interval > ptd[q].latency_max)
				ptd[q].latency_max = ptd[q].latency_max_interval;

			if (latency_min > ptd[q].latency_min)
				latency_min = ptd[q].latency_min;
			if (latency_max < ptd[q].latency_max)
				latency_max = ptd[q].latency_max;
		}
	}
	printf("--- pktgen traffic statistics ---\n");
	printf("%lu packets transmitted, %lu received, lost %lu (%i%% packet loss), time %lu ms\n",
		   tot_tx_pkts, tot_rx_pkts,
		   tot_tx_pkts - tot_rx_pkts,
		   (int)((tot_tx_pkts - tot_rx_pkts) * 100 / tot_tx_pkts),
		   time_diff);

	printf("Average throughput %lu kbit/s, latency min/avg/max %lu/%lu/%lu ns\n",
		   ((tot_tx_pkts + tot_rx_pkts) * conf->packet_size * 8 / time_diff),
		   TICKS_TO_NSEC(latency_min),
		   TICKS_TO_NSEC(latency_avg/(conf->num_ports * conf->num_rx_queues)),
		   TICKS_TO_NSEC(latency_max));

	return 0;
}
