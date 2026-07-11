#ifndef STATS_H
#define STATS_H

#include <rte_common.h>
#include <rte_lcore.h>

#include "hyperdpi.h"

/* One slot per lcore. Each lcore only ever writes its own slot (no locks,
 * no atomics needed) -- the stats thread only reads and aggregates, per
 * the "lock-free per-core counters" requirement in the spec. */
struct core_stats {
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t http_packets;
	uint64_t https_packets;
	uint64_t non_dpi_packets;
	uint64_t forwarded_packets;
	uint64_t dropped_packets;
	uint64_t tx_packets;
} __rte_cache_aligned;

extern struct core_stats stats_table[RTE_MAX_LCORE];

void stats_init(void);

static inline void stats_add_rx(unsigned lcore_id, uint64_t packets, uint64_t bytes)
{
	stats_table[lcore_id].rx_packets += packets;
	stats_table[lcore_id].rx_bytes += bytes;
}

static inline void stats_count_classified(unsigned lcore_id, enum traffic_type type)
{
	switch (type) {
	case TRAFFIC_HTTP:
		stats_table[lcore_id].http_packets++;
		break;
	case TRAFFIC_HTTPS:
		stats_table[lcore_id].https_packets++;
		break;
	default:
		stats_table[lcore_id].non_dpi_packets++;
		break;
	}
}

static inline void stats_count_forwarded(unsigned lcore_id)
{
	stats_table[lcore_id].forwarded_packets++;
}

static inline void stats_count_dropped(unsigned lcore_id)
{
	stats_table[lcore_id].dropped_packets++;
}

static inline void stats_add_tx(unsigned lcore_id, uint64_t packets)
{
	stats_table[lcore_id].tx_packets += packets;
}

/* Args for stats_thread_main(), built in main() once num_workers/lcores are
 * known. worker_lcores[i] lets the stats thread index stats_table[] for
 * worker i directly (needed for the per-worker PPS load-balancing signal --
 * see parser_bucket_rebalance() in parser.h). rebalance_enabled lets a run
 * disable rebalancing (-B flag) while keeping bucket-based steering, to
 * capture a "before" baseline for verification. */
struct stats_thread_args {
	unsigned num_workers;
	unsigned worker_lcores[MAX_WORKERS];
	bool rebalance_enabled;
};

/* lcore entry point: launched via rte_eal_remote_launch() with a
 * `struct stats_thread_args *` as arg. Prints an aggregated snapshot plus a
 * per-worker PPS breakdown to the console every 1s until force_quit is set,
 * and (if rebalance_enabled) periodically rebalances idle hash buckets away
 * from the most-loaded worker. */
int stats_thread_main(void *arg);

#endif /* STATS_H */
