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

#include "netem.h"
#include "http.h"

/* general stuff */
#define MAX_PKT_BURST       32
#define BURST_TX_DRAIN_US   100
#define MEMPOOL_CACHE_SIZE  256
#define RX_DESC_DEFAULT     1024
#define TX_DESC_DEFAULT     1024
#define STATS_INTERVAL_SEC  1

/* drop/dup ratios are N out of this */

/* IP protocol numbers */
#define PROTO_ICMP  1
#define PROTO_TCP   6
#define PROTO_UDP   17

/* the two IP ranges we match on, in host byte order */
#define NET_10_0_0      0x0A000000
#define NET_192_168_0   0xC0A80000

/* /24 check: throw away last octet, compare the rest */
#define IP_IN_SLASH24(ip, net24)   (((ip) >> 8) == ((net24) >> 8))

/* packets under this size go to PQ 8 */
#define SMALL_PKT_BYTES  128

/* --------------------------------------------------------------- */
/* header pointer macros                                            */
/* --------------------------------------------------------------- */

#define PKT_ETH(m)   rte_pktmbuf_mtod((m), struct rte_ether_hdr *)
#define PKT_IP(m)    ((struct rte_ipv4_hdr *)(PKT_ETH(m) + 1))

/* IP header length from the IHL field (lower nibble * 4) */
#define IP_HDR_LEN(ip)   (((ip)->version_ihl & 0x0f) << 2)

/* TCP header length from the data offset field (upper nibble * 4) */
#define TCP_HDR_LEN(tcp) (((tcp)->data_off >> 4) << 2)

/* skip past the L4 header to get to payload */
#define TCP_PAYLOAD(l4)  ((uint8_t *)(l4) + TCP_HDR_LEN((struct rte_tcp_hdr *)(l4)))
#define UDP_PAYLOAD(l4)  ((uint8_t *)(l4) + sizeof(struct rte_udp_hdr))

/* how many payload bytes we actually have (guard against underflow) */
#define TCP_PAYLOAD_LEN(l4, l4_len) \
    ((l4_len) > TCP_HDR_LEN((struct rte_tcp_hdr *)(l4)) \
        ? (l4_len) - TCP_HDR_LEN((struct rte_tcp_hdr *)(l4)) : 0)
#define UDP_PAYLOAD_LEN(l4_len) \
    ((l4_len) > sizeof(struct rte_udp_hdr) \
        ? (l4_len) - (uint32_t)sizeof(struct rte_udp_hdr) : 0)

/* check total IP length from the header field */
#define IS_SMALL_PKT(ip) \
    (rte_be_to_cpu_16((ip)->total_length) < SMALL_PKT_BYTES)

/* --------------------------------------------------------------- */
/* payload pattern matching                                         */
/* --------------------------------------------------------------- */

#define PAYLOAD_STARTS_WITH(buf, buflen, pat, n) \
    ((buflen) >= (n) && memcmp((buf), (pat), (n)) == 0)

/* HTTP — method verbs or response prefix */
#define IS_HTTP(buf, len) (                             \
    PAYLOAD_STARTS_WITH(buf, len, "GET ",     4) ||    \
    PAYLOAD_STARTS_WITH(buf, len, "POST ",    5) ||    \
    PAYLOAD_STARTS_WITH(buf, len, "HTTP/",    5) ||    \
    PAYLOAD_STARTS_WITH(buf, len, "HEAD ",    5) ||    \
    PAYLOAD_STARTS_WITH(buf, len, "PUT ",     4) ||    \
    PAYLOAD_STARTS_WITH(buf, len, "DELETE ",  7) ||    \
    PAYLOAD_STARTS_WITH(buf, len, "OPTIONS ", 8) )

/*
 * TLS — content type 0x14-0x17, major version 0x03, minor 0x00-0x04
 * same header for ssl3, tls1.0, 1.1, 1.2, 1.3
 */
#define IS_TLS(buf, len) (                      \
    (len) >= 3                               && \
    (buf)[0] >= 0x14 && (buf)[0] <= 0x17    && \
    (buf)[1] == 0x03                         && \
    (buf)[2] <= 0x04 )

/* SSH — RFC says both sides must start with "SSH-" */
#define IS_SSH(buf, len) \
    PAYLOAD_STARTS_WITH(buf, len, "SSH-", 4)

/*
 * DNS — 12 byte header, bits 14-11 of byte 2 are opcode
 * opcode 0 = standard query/response, covers basically all real DNS
 */
#define DNS_OPCODE(buf)  (((buf)[2] >> 3) & 0x0f)
#define IS_DNS(buf, len) \
    ((len) >= 12 && DNS_OPCODE(buf) == 0)

/*
 * NTP — 48 bytes minimum, first byte: LI(7-6) VN(5-3) Mode(2-0)
 * version 3 or 4, mode 1-5
 */
#define NTP_VERSION(b)   (((b) >> 3) & 0x07)
#define NTP_MODE(b)      ((b) & 0x07)
#define IS_NTP(buf, len) (                          \
    (len) >= 48                                  && \
    NTP_VERSION((buf)[0]) >= 3                   && \
    NTP_VERSION((buf)[0]) <= 4                   && \
    NTP_MODE((buf)[0])    >= 1                   && \
    NTP_MODE((buf)[0])    <= 5 )

/* --------------------------------------------------------------- */
/* drop / dup helpers                                               */
/* --------------------------------------------------------------- */

#define SHOULD_DROP(count, drop_n) \
    ((drop_n) > 0 && ((count) % PACKETS_PER_GROUP) < (drop_n))

#define SHOULD_DUP(count, dup_n) \
    ((dup_n) > 0 && ((count) % PACKETS_PER_GROUP) < (dup_n))

/* --------------------------------------------------------------- */
/* delay ring helpers                                               */
/* --------------------------------------------------------------- */

#define RING_NEXT(idx, size)  (((idx) + 1) % (size))
#define TSC_PER_US(hz)        ((hz) / 1000000ULL)
#define RELEASE_TSC(now, us, tsc_per_us) \
    ((now) + (uint64_t)(us) * (tsc_per_us))

/* --------------------------------------------------------------- */
/* globals (extern'd in netem.h so http.c can read/write them)     */
/* --------------------------------------------------------------- */

static volatile bool force_quit;

#define RTE_LOGTYPE_NETEM RTE_LOGTYPE_USER1

static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

static struct rte_ether_addr netem_ports_eth_addr[NB_PORTS];
static struct rte_eth_dev_tx_buffer *tx_buffer[NB_PORTS];

static struct rte_eth_conf port_conf = {
	.txmode = { .mq_mode = RTE_ETH_MQ_TX_NONE },
};

struct rte_mempool *netem_pktmbuf_pool = NULL;

struct netem_port_statistics port_statistics[NB_PORTS];

static uint64_t timer_period = STATS_INTERVAL_SEC;

/* the 10 profile queues — not const so the HTTP thread can update them */
struct pq_config pq_configs[NUM_PQ] = {
	[0] = { "proto=ICMP",          .drop_n = 2, .dup_n = 0, .delay_us = 0    },
	[1] = { "payload=HTTP",        .drop_n = 0, .dup_n = 2, .delay_us = 0    },
	[2] = { "payload=TLS",         .drop_n = 0, .dup_n = 0, .delay_us = 1000 },
	[3] = { "payload=SSH",         .drop_n = 1, .dup_n = 0, .delay_us = 100  },
	[4] = { "payload=DNS",         .drop_n = 0, .dup_n = 0, .delay_us = 500  },
	[5] = { "payload=NTP",         .drop_n = 1, .dup_n = 0, .delay_us = 0    },
	[6] = { "src=10.0.0.0/24",     .drop_n = 0, .dup_n = 3, .delay_us = 0   },
	[7] = { "src=192.168.0.0/24",  .drop_n = 3, .dup_n = 0, .delay_us = 0   },
	[8] = { "size<128B",           .drop_n = 0, .dup_n = 0, .delay_us = 2000 },
	[9] = { "default",             .drop_n = 0, .dup_n = 0, .delay_us = 0   },
};

struct lcore_state  lcore_states[RTE_MAX_LCORE];
struct pq_agg_stats pq_agg[NUM_PQ];  /* updated in print_stats, read by HTTP thread */

/* --------------------------------------------------------------- */
/* stats printout + pq_agg update                                   */
/* --------------------------------------------------------------- */

static void
print_stats(void)
{
	/* update aggregated PQ stats so the dashboard has fresh data */
	for (int pq = 0; pq < NUM_PQ; pq++) {
		uint64_t total = 0;
		uint32_t depth = 0;
		unsigned lcore;
		RTE_LCORE_FOREACH(lcore) {
			total += lcore_states[lcore].pqs[pq].pkt_count;
			depth += lcore_states[lcore].pqs[pq].dq_count;
		}
		pq_agg[pq].pkt_count = total;
		pq_agg[pq].dq_count  = depth;
	}

	const char clr[]     = { 27, '[', '2', 'J', '\0' };
	const char topleft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
	printf("%s%s", clr, topleft);

	uint64_t ttx = 0, trx = 0, tdrop = 0, tdup = 0, tdelay = 0;
	printf("\nPort statistics ====================================");
	for (unsigned p = 0; p < NB_PORTS; p++) {
		printf("\n  Port %u | rx=%-10"PRIu64" tx=%-10"PRIu64
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
	printf("\n  Total  | rx=%-10"PRIu64" tx=%-10"PRIu64
	       " drop=%-8"PRIu64" dup=%-8"PRIu64" delay=%-8"PRIu64,
	       trx, ttx, tdrop, tdup, tdelay);

	printf("\n\nProfile Queue config ================================");
	for (int pq = 0; pq < NUM_PQ; pq++) {
		printf("\n  PQ%d [%-18s] drop=%u/10  dup=%u/10  delay=%"PRIu64"us  pkts=%"PRIu64,
		       pq,
		       pq_configs[pq].name,
		       pq_configs[pq].drop_n,
		       pq_configs[pq].dup_n,
		       pq_configs[pq].delay_us,
		       pq_agg[pq].pkt_count);
	}
	printf("\n====================================================\n");
	printf("  Dashboard: http://localhost:%d\n", HTTP_PORT);
	fflush(stdout);
}

/* --------------------------------------------------------------- */
/* packet classification                                            */
/* --------------------------------------------------------------- */

/*
 * look inside the packet and decide which of the 10 queues it belongs to
 * we do actual payload inspection instead of just checking port numbers
 * because port numbers are unreliable (anyone can run anything on any port)
 *
 * order: ICMP → IP prefix → TCP payload → UDP payload → size → default
 */
static uint16_t
classify_packet(struct rte_mbuf *m)
{
	uint32_t data_len = rte_pktmbuf_data_len(m);

	if (unlikely(data_len < sizeof(struct rte_ether_hdr) +
	                         sizeof(struct rte_ipv4_hdr)))
		return 9;

	struct rte_ether_hdr *eth = PKT_ETH(m);
	if (rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_IPV4)
		return 9;

	struct rte_ipv4_hdr *ip = PKT_IP(m);
	uint8_t  proto          = ip->next_proto_id;
	uint32_t src_ip         = rte_be_to_cpu_32(ip->src_addr);
	uint32_t ip_hdr_len     = IP_HDR_LEN(ip);

	if (proto == PROTO_ICMP)                   return 0;
	if (IP_IN_SLASH24(src_ip, NET_10_0_0))     return 6;
	if (IP_IN_SLASH24(src_ip, NET_192_168_0))  return 7;

	uint32_t l4_offset = sizeof(struct rte_ether_hdr) + ip_hdr_len;
	if (unlikely(data_len <= l4_offset))
		return 9;

	uint8_t *l4     = (uint8_t *)ip + ip_hdr_len;
	uint32_t l4_len = data_len - l4_offset;

	if (proto == PROTO_TCP) {
		if (unlikely(l4_len < sizeof(struct rte_tcp_hdr))) return 9;
		uint8_t *payload     = TCP_PAYLOAD(l4);
		uint32_t payload_len = TCP_PAYLOAD_LEN(l4, l4_len);
		if (IS_HTTP(payload, payload_len)) return 1;
		if (IS_TLS(payload, payload_len))  return 2;
		if (IS_SSH(payload, payload_len))  return 3;
		if (IS_SMALL_PKT(ip))              return 8;
		return 9;
	}

	if (proto == PROTO_UDP) {
		if (unlikely(l4_len < sizeof(struct rte_udp_hdr))) return 9;
		uint8_t *payload     = UDP_PAYLOAD(l4);
		uint32_t payload_len = UDP_PAYLOAD_LEN(l4_len);
		if (IS_DNS(payload, payload_len))  return 4;
		if (IS_NTP(payload, payload_len))  return 5;
		if (IS_SMALL_PKT(ip))              return 8;
		return 9;
	}

	if (IS_SMALL_PKT(ip)) return 8;
	return 9;
}

/* --------------------------------------------------------------- */
/* delay ring                                                       */
/* --------------------------------------------------------------- */

static inline void
delay_enqueue(struct pq_state *pqs, struct rte_mbuf *m, uint64_t release_tsc)
{
	if (unlikely(pqs->dq_count >= DELAY_QUEUE_SIZE)) {
		rte_pktmbuf_free(m); /* ring full, drop rather than crash */
		return;
	}
	pqs->delay_q[pqs->dq_tail].m           = m;
	pqs->delay_q[pqs->dq_tail].release_tsc = release_tsc;
	pqs->dq_tail  = RING_NEXT(pqs->dq_tail, DELAY_QUEUE_SIZE);
	pqs->dq_count++;
}

/*
 * release packets whose timer has expired
 * within one PQ, release_tsc is monotonically increasing so we
 * can break on the first packet that isn't ready yet
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
			pqs->dq_head  = RING_NEXT(pqs->dq_head, DELAY_QUEUE_SIZE);
			pqs->dq_count--;
			int sent = rte_eth_tx_buffer(tx_port_id, 0,
			                             tx_buffer[tx_port_id], m);
			if (sent)
				port_statistics[tx_port_id].tx += sent;
		}
	}
}

/* --------------------------------------------------------------- */
/* per-packet processing                                            */
/* --------------------------------------------------------------- */

static void
process_packet(struct rte_mbuf *m,
               uint16_t rx_port_id, uint16_t tx_port_id,
               struct lcore_state *ls,
               uint64_t cur_tsc, uint64_t tsc_per_us)
{
	uint16_t pq_id              = classify_packet(m);
	const struct pq_config *cfg = &pq_configs[pq_id];
	struct pq_state        *pqs = &ls->pqs[pq_id];
	uint64_t count              = pqs->pkt_count++;

	/* drop */
	if (SHOULD_DROP(count, cfg->drop_n)) {
		rte_pktmbuf_free(m);
		port_statistics[rx_port_id].dropped++;
		return;
	}

	/* duplicate — clone goes through same delay as original */
	if (SHOULD_DUP(count, cfg->dup_n)) {
		struct rte_mbuf *clone = rte_pktmbuf_copy(m, netem_pktmbuf_pool,
		                                           0, UINT32_MAX);
		if (likely(clone != NULL)) {
			if (cfg->delay_us > 0)
				delay_enqueue(pqs, clone,
				              RELEASE_TSC(cur_tsc, cfg->delay_us, tsc_per_us));
			else {
				int sent = rte_eth_tx_buffer(tx_port_id, 0,
				                             tx_buffer[tx_port_id], clone);
				if (sent)
					port_statistics[tx_port_id].tx += sent;
			}
			port_statistics[rx_port_id].duplicated++;
		}
	}

	/* delay or send immediately */
	if (cfg->delay_us > 0) {
		delay_enqueue(pqs, m, RELEASE_TSC(cur_tsc, cfg->delay_us, tsc_per_us));
		port_statistics[rx_port_id].delayed++;
	} else {
		int sent = rte_eth_tx_buffer(tx_port_id, 0, tx_buffer[tx_port_id], m);
		if (sent)
			port_statistics[tx_port_id].tx += sent;
	}
}

/* --------------------------------------------------------------- */
/* main loop — one per lcore                                        */
/* --------------------------------------------------------------- */

static void
netem_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned lcore_id = rte_lcore_id();

	/* lcore 0 -> rx port 0 -> tx port 1, lcore 1 -> rx port 1 -> tx port 0 */
	uint16_t rx_port_id = (uint16_t)lcore_id;
	uint16_t tx_port_id = rx_port_id ^ 1;

	/* each lcore owns its own state, nothing shared between lcores */
	struct lcore_state *ls = &lcore_states[lcore_id];
	memset(ls, 0, sizeof(*ls));

	uint64_t tsc_hz     = rte_get_tsc_hz();
	uint64_t tsc_per_us = TSC_PER_US(tsc_hz);
	const uint64_t drain_tsc = (tsc_hz + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	uint64_t prev_tsc  = 0;
	uint64_t timer_tsc = 0;

	printf("lcore %u started: rx=port%u  tx=port%u\n",
	       lcore_id, rx_port_id, tx_port_id);
	RTE_LOG(INFO, NETEM, "entering main loop on lcore %u\n", lcore_id);

	while (!force_quit) {
		uint64_t cur_tsc = rte_rdtsc();

		/* check delay waiting rooms every iteration for good timing precision */
		flush_delay_queues(ls, tx_port_id, cur_tsc);

		/* every 100us: flush TX buffer, maybe print stats */
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

		unsigned nb_rx = rte_eth_rx_burst(rx_port_id, 0,
		                                  pkts_burst, MAX_PKT_BURST);
		if (unlikely(nb_rx == 0))
			continue;

		port_statistics[rx_port_id].rx += nb_rx;

		for (unsigned i = 0; i < nb_rx; i++) {
			/* tell CPU to start loading next packet's data into cache now */
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i], void *));
			process_packet(pkts_burst[i],
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

/* --------------------------------------------------------------- */
/* startup                                                          */
/* --------------------------------------------------------------- */

int
main(int argc, char **argv)
{
	int      ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid;
	unsigned lcore_id;

	/* DPDK init — sets up memory, grabs CPU cores, opens the NICs */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);

	/* convert seconds to TSC ticks */
	timer_period *= rte_get_timer_hz();

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports found\n");

	/* pre-allocate all packet buffers — never malloc during processing */
	unsigned nb_mbufs = RTE_MAX(
		nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST + 2 * MEMPOOL_CACHE_SIZE),
		8192U);
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
			         "Error getting device info (port %u): %s\n",
			         portid, strerror(-ret));

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			         "Cannot configure port %u: err=%d\n", portid, ret);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			         "Cannot adjust descriptors port %u: err=%d\n", portid, ret);

		ret = rte_eth_macaddr_get(portid, &netem_ports_eth_addr[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			         "Cannot get MAC port %u: err=%d\n", portid, ret);

		rxq_conf          = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
		                             rte_eth_dev_socket_id(portid),
		                             &rxq_conf, netem_pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			         "rx_queue_setup err=%d port=%u\n", ret, portid);

		txq_conf          = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
		                             rte_eth_dev_socket_id(portid), &txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			         "tx_queue_setup err=%d port=%u\n", ret, portid);

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
			         "rte_eth_dev_start err=%d port=%u\n", ret, portid);

		printf("Port %u, MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n\n",
		       portid,
		       RTE_ETHER_ADDR_BYTES(&netem_ports_eth_addr[portid]));

		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (!nb_ports_available)
		rte_exit(EXIT_FAILURE, "No ports available\n");

	/* start the web dashboard before launching packet processing */
	http_server_start(HTTP_PORT);

	/* start the main loop on both lcores simultaneously */
	ret = 0;
	rte_eal_mp_remote_launch(netem_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	http_server_stop();

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
