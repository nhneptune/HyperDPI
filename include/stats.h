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

/* lcore entry point: launched via rte_eal_remote_launch(), prints an
 * aggregated snapshot to the console every 1s until force_quit is set. */
int stats_thread_main(void *arg);

#endif /* STATS_H */
