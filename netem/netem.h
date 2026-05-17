#ifndef NETEM_H
#define NETEM_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_common.h>
#include <rte_mbuf.h>

/* shared constants */
#define NUM_PQ            10
#define NB_PORTS          2
#define DELAY_QUEUE_SIZE  2048
#define PACKETS_PER_GROUP 10
#define HTTP_PORT         9000

/* per-port counters */
struct __rte_cache_aligned netem_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
	uint64_t duplicated;
	uint64_t delayed;
};

/* profile queue config — not const so the HTTP thread can update it live */
struct pq_config {
	const char *name;
	uint32_t    drop_n;
	uint32_t    dup_n;
	uint64_t    delay_us;
};

/* one slot in a PQ delay ring */
struct delay_entry {
	struct rte_mbuf *m;
	uint64_t         release_tsc;
};

/* per-lcore per-PQ state — each lcore owns its own, no sharing */
struct pq_state {
	uint64_t           pkt_count;
	struct delay_entry delay_q[DELAY_QUEUE_SIZE];
	uint32_t           dq_head;
	uint32_t           dq_tail;
	uint32_t           dq_count;
} __rte_cache_aligned;

/* per-lcore state */
struct lcore_state {
	struct pq_state pqs[NUM_PQ];
} __rte_cache_aligned;

/*
 * aggregated per-PQ stats, updated once per second by the main lcore
 * and read by the HTTP thread for the dashboard — no lock needed, display only
 */
struct pq_agg_stats {
	uint64_t pkt_count;
	uint32_t dq_count;
};

/* globals defined in main.c, used by http.c */
extern struct netem_port_statistics port_statistics[NB_PORTS];
extern struct pq_config             pq_configs[NUM_PQ];
extern struct lcore_state           lcore_states[RTE_MAX_LCORE];
extern struct pq_agg_stats          pq_agg[NUM_PQ];

#endif /* NETEM_H */
