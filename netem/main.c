#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <netinet/in.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

static volatile bool force_quit;

#define RTE_LOGTYPE_NETEM RTE_LOGTYPE_USER1

#define MAX_PKT_BURST     32
#define BURST_TX_DRAIN_US 100
#define MEMPOOL_CACHE_SIZE 256
#define RX_DESC_DEFAULT   1024
#define TX_DESC_DEFAULT   1024
#define NB_PORTS          2
#define NUM_PQ            10
#define DELAY_QUEUE_SIZE  2048  /* per PQ, per lcore */

static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

static struct rte_ether_addr netem_ports_eth_addr[NB_PORTS];
static struct rte_eth_dev_tx_buffer *tx_buffer[NB_PORTS];

static struct rte_eth_conf port_conf = {
	.txmode = { .mq_mode = RTE_ETH_MQ_TX_NONE },
};

struct rte_mempool *netem_pktmbuf_pool = NULL;

struct __rte_cache_aligned netem_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
	uint64_t duplicated;
	uint64_t delayed;
};
struct netem_port_statistics port_statistics[NB_PORTS];

static uint64_t timer_period = 1;

/*
 * Profile Queue (PQ) configuration.
 * drop_n: drop this many out of every 10 packets (0 = no drop).
 * dup_n:  send an extra copy for this many out of every 10 packets.
 * delay_us: hold each packet for this many microseconds before forwarding.
 *
 * Classification (first match wins):
 *  PQ 0 – ICMP
 *  PQ 1 – TCP dst 80   (HTTP)
 *  PQ 2 – TCP dst 443  (HTTPS)
 *  PQ 3 – TCP dst 22   (SSH)
 *  PQ 4 – UDP dst 53   (DNS)
 *  PQ 5 – UDP dst 123  (NTP)
 *  PQ 6 – src IP in 10.0.0.0/24
 *  PQ 7 – src IP in 192.168.0.0/24
 *  PQ 8 – TCP dst port < 1024 (other well-known)
 *  PQ 9 – everything else (default)
 */
struct pq_config {
	const char *name;
	uint32_t    drop_n;
	uint32_t    dup_n;
	uint64_t    delay_us;
};

static const struct pq_config pq_configs[NUM_PQ] = {
	[0] = { "ICMP",             2, 0, 0    },
	[1] = { "HTTP(80)",         0, 2, 0    },
	[2] = { "HTTPS(443)",       0, 0, 1000 },
	[3] = { "SSH(22)",          1, 0, 100  },
	[4] = { "DNS(53)",          0, 0, 500  },
	[5] = { "NTP(123)",         1, 0, 0    },
	[6] = { "src 10.0.0.0/24",  0, 3, 0   },
	[7] = { "src 192.168.0/24", 3, 0, 0   },
	[8] = { "TCP<1024",         0, 0, 2000 },
	[9] = { "default",          0, 0, 0   },
};

/* Entry in a per-PQ delay ring */
struct delay_entry {
	struct rte_mbuf *m;
	uint64_t         release_tsc;
};

/*
 * Per-lcore, per-PQ state.  Each lcore owns its own copy exclusively —
 * no sharing, no locks needed.
 */
struct pq_state {
	uint64_t         pkt_count;
	struct delay_entry delay_q[DELAY_QUEUE_SIZE];
	uint32_t         dq_head;
	uint32_t         dq_tail;
	uint32_t         dq_count;
} __rte_cache_aligned;

struct lcore_state {
	struct pq_state pqs[NUM_PQ];
} __rte_cache_aligned;

static struct lcore_state lcore_states[RTE_MAX_LCORE];

/* ------------------------------------------------------------------ */

static void
print_stats(void)
{
	const char clr[]     = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
	printf("%s%s", clr, topLeft);

	uint64_t ttx = 0, trx = 0, tdrop = 0, tdup = 0, tdelay = 0;
	printf("\nPort statistics ====================================");
	for (unsigned p = 0; p < NB_PORTS; p++) {
		printf("\n  Port %u: rx=%-10"PRIu64" tx=%-10"PRIu64
		       " drop=%-8"PRIu64" dup=%-8"PRIu64" delay=%-8"PRIu64,
		       p,
		       port_statistics[p].rx,
		       port_statistics[p].tx,
		       port_statistics[p].dropped,
		       port_statistics[p].duplicated,
		       port_statistics[p].delayed);
		ttx    += port_statistics[p].tx;
		trx    += port_statistics[p].rx;
		tdrop  += port_statistics[p].dropped;
		tdup   += port_statistics[p].duplicated;
		tdelay += port_statistics[p].delayed;
	}
	printf("\n  Total : rx=%-10"PRIu64" tx=%-10"PRIu64
	       " drop=%-8"PRIu64" dup=%-8"PRIu64" delay=%-8"PRIu64,
	       trx, ttx, tdrop, tdup, tdelay);

	printf("\nProfile Queue config ================================");
	for (int pq = 0; pq < NUM_PQ; pq++)
		printf("\n  PQ%d [%-18s] drop=%u/10  dup=%u/10  delay=%"PRIu64"us",
		       pq, pq_configs[pq].name,
		       pq_configs[pq].drop_n,
		       pq_configs[pq].dup_n,
		       pq_configs[pq].delay_us);
	printf("\n====================================================\n");
	fflush(stdout);
}

/* ------------------------------------------------------------------ */

/*
 * Classify an incoming packet into one of the 10 PQs.
 * Returns PQ index 0-9.  Non-IPv4 → PQ 9.
 */
static uint16_t
classify_packet(struct rte_mbuf *m)
{
	if (unlikely(rte_pktmbuf_data_len(m) < sizeof(struct rte_ether_hdr)))
		return 9;

	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	if (rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_IPV4)
		return 9;

	uint32_t data_len = rte_pktmbuf_data_len(m);
	if (unlikely(data_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)))
		return 9;

	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
	uint8_t  proto  = ip->next_proto_id;
	uint32_t src_ip = rte_be_to_cpu_32(ip->src_addr);
	uint32_t ihl    = (ip->version_ihl & 0x0f) * 4;

	/* PQ 0: ICMP */
	if (proto == IPPROTO_ICMP)
		return 0;

	/* PQ 6: src 10.0.0.0/24 */
	if ((src_ip >> 8) == (0x0A000000 >> 8))
		return 6;

	/* PQ 7: src 192.168.0.0/24 */
	if ((src_ip >> 8) == (0xC0A80000 >> 8))
		return 7;

	uint8_t *l4 = (uint8_t *)ip + ihl;

	if (proto == IPPROTO_TCP) {
		if (unlikely(data_len < sizeof(struct rte_ether_hdr) + ihl +
		                        sizeof(struct rte_tcp_hdr)))
			return 9;
		uint16_t dport = rte_be_to_cpu_16(((struct rte_tcp_hdr *)l4)->dst_port);
		if (dport == 80)   return 1;
		if (dport == 443)  return 2;
		if (dport == 22)   return 3;
		if (dport < 1024)  return 8;
		return 9;
	}

	if (proto == IPPROTO_UDP) {
		if (unlikely(data_len < sizeof(struct rte_ether_hdr) + ihl +
		                        sizeof(struct rte_udp_hdr)))
			return 9;
		uint16_t dport = rte_be_to_cpu_16(((struct rte_udp_hdr *)l4)->dst_port);
		if (dport == 53)  return 4;
		if (dport == 123) return 5;
		return 9;
	}

	return 9;
}

/* ------------------------------------------------------------------ */

static inline void
delay_enqueue(struct pq_state *pqs, struct rte_mbuf *m, uint64_t release_tsc)
{
	if (unlikely(pqs->dq_count >= DELAY_QUEUE_SIZE)) {
		rte_pktmbuf_free(m);
		return;
	}
	pqs->delay_q[pqs->dq_tail].m           = m;
	pqs->delay_q[pqs->dq_tail].release_tsc = release_tsc;
	pqs->dq_tail = (pqs->dq_tail + 1) % DELAY_QUEUE_SIZE;
	pqs->dq_count++;
}

/*
 * Release all delay-queue entries whose deadline has passed.
 * Within a single PQ, entries are always chronologically ordered
 * (same delay_us applied to a monotonically increasing cur_tsc),
 * so we can break on the first unexpired entry.
 */
static void
flush_delay_queues(struct lcore_state *ls, uint16_t tx_port_id, uint64_t cur_tsc)
{
	for (int pq = 0; pq < NUM_PQ; pq++) {
		struct pq_state *pqs = &ls->pqs[pq];
		while (pqs->dq_count > 0) {
			if (pqs->delay_q[pqs->dq_head].release_tsc > cur_tsc)
				break;
			struct rte_mbuf *m = pqs->delay_q[pqs->dq_head].m;
			pqs->dq_head = (pqs->dq_head + 1) % DELAY_QUEUE_SIZE;
			pqs->dq_count--;
			int sent = rte_eth_tx_buffer(tx_port_id, 0,
			                             tx_buffer[tx_port_id], m);
			if (sent)
				port_statistics[tx_port_id].tx += sent;
		}
	}
}

/* ------------------------------------------------------------------ */

static inline void
forward_mbuf(struct rte_mbuf *m, uint16_t pq_id,
             uint16_t rx_port_id, uint16_t tx_port_id,
             struct lcore_state *ls, uint64_t cur_tsc,
             uint64_t tsc_per_us)
{
	const struct pq_config *cfg = &pq_configs[pq_id];
	struct pq_state        *pqs = &ls->pqs[pq_id];
	uint64_t count = pqs->pkt_count++;

	/* Drop */
	if (cfg->drop_n > 0 && (count % 10) < cfg->drop_n) {
		rte_pktmbuf_free(m);
		port_statistics[rx_port_id].dropped++;
		return;
	}

	/* Duplicate: enqueue a copy ahead of the original */
	if (cfg->dup_n > 0 && (count % 10) < cfg->dup_n) {
		struct rte_mbuf *clone = rte_pktmbuf_copy(m, netem_pktmbuf_pool,
		                                           0, UINT32_MAX);
		if (likely(clone != NULL)) {
			if (cfg->delay_us > 0)
				delay_enqueue(pqs, clone,
				              cur_tsc + cfg->delay_us * tsc_per_us);
			else {
				int sent = rte_eth_tx_buffer(tx_port_id, 0,
				                             tx_buffer[tx_port_id], clone);
				if (sent)
					port_statistics[tx_port_id].tx += sent;
			}
			port_statistics[rx_port_id].duplicated++;
		}
	}

	/* Delay or forward immediately */
	if (cfg->delay_us > 0) {
		delay_enqueue(pqs, m, cur_tsc + cfg->delay_us * tsc_per_us);
		port_statistics[rx_port_id].delayed++;
	} else {
		int sent = rte_eth_tx_buffer(tx_port_id, 0, tx_buffer[tx_port_id], m);
		if (sent)
			port_statistics[tx_port_id].tx += sent;
	}
}

/* ------------------------------------------------------------------ */

static void
netem_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned lcore_id = rte_lcore_id();

	/* lcore 0 → rx port 0 → tx port 1; lcore 1 → rx port 1 → tx port 0 */
	uint16_t rx_port_id = (uint16_t)lcore_id;
	uint16_t tx_port_id = rx_port_id ^ 1;

	struct lcore_state *ls = &lcore_states[lcore_id];
	memset(ls, 0, sizeof(*ls));

	uint64_t tsc_hz      = rte_get_tsc_hz();
	uint64_t tsc_per_us  = tsc_hz / 1000000;
	const uint64_t drain_tsc = (tsc_hz + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	uint64_t prev_tsc  = 0;
	uint64_t timer_tsc = 0;

	printf("lcore %u: rx port %u → tx port %u\n",
	       lcore_id, rx_port_id, tx_port_id);
	RTE_LOG(INFO, NETEM, "entering main loop on lcore %u\n", lcore_id);

	while (!force_quit) {
		uint64_t cur_tsc = rte_rdtsc();

		/* Release any delay-queue packets whose time has come */
		flush_delay_queues(ls, tx_port_id, cur_tsc);

		/* Periodic TX drain + stats */
		if (unlikely(cur_tsc - prev_tsc > drain_tsc)) {
			int sent = rte_eth_tx_buffer_flush(tx_port_id, 0,
			                                   tx_buffer[tx_port_id]);
			if (sent)
				port_statistics[tx_port_id].tx += sent;

			if (timer_period > 0) {
				timer_tsc += cur_tsc - prev_tsc;
				if (unlikely(timer_tsc >= timer_period)) {
					if (lcore_id == rte_get_main_lcore()) {
						print_stats();
						timer_tsc = 0;
					}
				}
			}
			prev_tsc = cur_tsc;
		}

		/* RX burst */
		unsigned nb_rx = rte_eth_rx_burst(rx_port_id, 0,
		                                  pkts_burst, MAX_PKT_BURST);
		if (unlikely(nb_rx == 0))
			continue;

		port_statistics[rx_port_id].rx += nb_rx;

		for (unsigned i = 0; i < nb_rx; i++) {
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i], void *));
			uint16_t pq_id = classify_packet(pkts_burst[i]);
			forward_mbuf(pkts_burst[i], pq_id,
			             rx_port_id, tx_port_id,
			             ls, cur_tsc, tsc_per_us);
		}
	}
}

static int
netem_launch_one_lcore(__rte_unused void *dummy)
{
	netem_main_loop();
	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	int      ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid;
	unsigned lcore_id;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);

	timer_period *= rte_get_timer_hz();

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports\n");

	unsigned nb_mbufs = RTE_MAX(
		nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST + 2 * MEMPOOL_CACHE_SIZE),
		8192U);
	/* Extra headroom for delay queues and duplication clones */
	nb_mbufs += NB_PORTS * NUM_PQ * DELAY_QUEUE_SIZE * 2;

	netem_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (netem_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf   rxq_conf;
		struct rte_eth_txconf   txq_conf;
		struct rte_eth_conf     local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		nb_ports_available++;
		printf("Initializing port %u... ", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
			         "Error during getting device (port %u) info: %s\n",
			         portid, strerror(-ret));

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			         "Cannot configure device: err=%d, port=%u\n", ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			         "Cannot adjust descriptors: err=%d, port=%u\n", ret, portid);

		ret = rte_eth_macaddr_get(portid, &netem_ports_eth_addr[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			         "Cannot get MAC address: err=%d, port=%u\n", ret, portid);

		rxq_conf          = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
		                             rte_eth_dev_socket_id(portid),
		                             &rxq_conf, netem_pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			         "rte_eth_rx_queue_setup: err=%d, port=%u\n", ret, portid);

		txq_conf          = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
		                             rte_eth_dev_socket_id(portid), &txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			         "rte_eth_tx_queue_setup: err=%d, port=%u\n", ret, portid);

		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
			RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
			rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE,
			         "Cannot allocate tx_buffer for port %u\n", portid);

		rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
			rte_eth_tx_buffer_count_callback,
			&port_statistics[portid].dropped);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			         "Cannot set tx error callback for port %u\n", portid);

		ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);
		if (ret < 0)
			printf("Port %u: failed to disable ptype parsing\n", portid);

		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			         "rte_eth_dev_start: err=%d, port=%u\n", ret, portid);

		printf("Port %u, MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n\n",
		       portid,
		       RTE_ETHER_ADDR_BYTES(&netem_ports_eth_addr[portid]));

		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (!nb_ports_available)
		rte_exit(EXIT_FAILURE, "No ports available\n");

	ret = 0;
	rte_eal_mp_remote_launch(netem_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	rte_eal_cleanup();
	printf("Bye...\n");
	return ret;
}
