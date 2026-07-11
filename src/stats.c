#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include <rte_cycles.h>
#include <rte_lcore.h>

#include "stats.h"
#include "parser.h"

/*
 * Load-aware rebalancing thresholds (RSS++-inspired, Phase 1 -- see
 * version_01.md for the full design writeup and parser.c for the bucket
 * mechanism this drives).
 */
#define REBALANCE_IMBALANCE_RATIO 1.25   /* trigger when max worker PPS > 1.25x average */
#define REBALANCE_MIN_AVG_PPS     100.0  /* floor to avoid noisy churn near-idle */
#define BUCKET_IDLE_THRESHOLD_MS  200    /* deliberately shorter than flow_table's ~1.5s
					   * idle timeout -- accepted Phase 1 trade-off,
					   * see version_01.md */

struct core_stats stats_table[RTE_MAX_LCORE];

void stats_init(void)
{
	memset(stats_table, 0, sizeof(stats_table));
}

static void aggregate(struct core_stats *out)
{
	memset(out, 0, sizeof(*out));

	unsigned lcore_id;
	RTE_LCORE_FOREACH(lcore_id) {
		const struct core_stats *s = &stats_table[lcore_id];
		out->rx_packets += s->rx_packets;
		out->rx_bytes += s->rx_bytes;
		out->http_packets += s->http_packets;
		out->https_packets += s->https_packets;
		out->non_dpi_packets += s->non_dpi_packets;
		out->forwarded_packets += s->forwarded_packets;
		out->dropped_packets += s->dropped_packets;
		out->tx_packets += s->tx_packets;
	}
}

/* Per-worker "packets processed" = http+https+non_dpi classified by that
 * worker (stats_count_classified() is only ever called from
 * worker_thread_main(), so this is a pure per-worker work signal with no
 * cross-contamination from RX/TX/Stats lcores). Used both for the printed
 * "Per-worker PPS" line and as the rebalance decision's load metric. */
static uint64_t worker_processed(unsigned lcore_id)
{
	const struct core_stats *s = &stats_table[lcore_id];
	return s->http_packets + s->https_packets + s->non_dpi_packets;
}

int stats_thread_main(void *arg)
{
	struct stats_thread_args *a = arg;

	struct core_stats prev, cur;
	aggregate(&prev);

	uint64_t worker_prev[MAX_WORKERS];
	for (unsigned i = 0; i < a->num_workers; i++)
		worker_prev[i] = worker_processed(a->worker_lcores[i]);

	const uint64_t hz = rte_get_timer_hz();
	const uint64_t idle_threshold_cycles = hz * BUCKET_IDLE_THRESHOLD_MS / 1000;
	uint64_t last_tsc = rte_get_timer_cycles();

	printf("[Stats] thread started on lcore %u\n", rte_lcore_id());

	while (!force_quit) {
		/* Sleep in short slices so shutdown reacts within ~100ms instead
		 * of blocking a full second. */
		for (int i = 0; i < 10 && !force_quit; i++)
			usleep(100000);
		if (force_quit)
			break;

		uint64_t now_tsc = rte_get_timer_cycles();
		double elapsed_s = (double)(now_tsc - last_tsc) / (double)hz;
		last_tsc = now_tsc;

		aggregate(&cur);

		uint64_t d_packets = cur.rx_packets - prev.rx_packets;
		uint64_t d_bytes = cur.rx_bytes - prev.rx_bytes;
		double pps = elapsed_s > 0 ? (double)d_packets / elapsed_s : 0;
		double mbps = elapsed_s > 0 ? (double)d_bytes * 8.0 / elapsed_s / 1e6 : 0;

		printf("--------------------------------------------------------------------\n");
		printf("Throughput: %.2f Mbps | PPS: %.0f | Total RX packets: %" PRIu64 "\n",
		       mbps, pps, cur.rx_packets);
		printf("HTTP: %" PRIu64 " | HTTPS: %" PRIu64 " | Non-DPI: %" PRIu64 "\n",
		       cur.http_packets, cur.https_packets, cur.non_dpi_packets);
		printf("Forwarded: %" PRIu64 " | Dropped: %" PRIu64 " | TX sent: %" PRIu64 "\n",
		       cur.forwarded_packets, cur.dropped_packets, cur.tx_packets);

		double worker_pps[MAX_WORKERS];
		double sum_pps = 0, max_pps = 0;
		unsigned max_idx = 0, min_idx = 0;

		printf("Per-worker PPS:");
		for (unsigned i = 0; i < a->num_workers; i++) {
			uint64_t cur_processed = worker_processed(a->worker_lcores[i]);
			uint64_t d_processed = cur_processed - worker_prev[i];
			worker_pps[i] = elapsed_s > 0 ? (double)d_processed / elapsed_s : 0;
			worker_prev[i] = cur_processed;

			printf(" W%u=%.0f", i, worker_pps[i]);
			sum_pps += worker_pps[i];
			if (worker_pps[i] > max_pps) {
				max_pps = worker_pps[i];
				max_idx = i;
			}
			if (worker_pps[i] < worker_pps[min_idx])
				min_idx = i;
		}
		printf("\n");

		unsigned bucket_counts[MAX_WORKERS];
		parser_bucket_get_distribution(a->num_workers, bucket_counts);
		printf("Bucket distribution:");
		for (unsigned i = 0; i < a->num_workers; i++)
			printf(" W%u=%u", i, bucket_counts[i]);
		printf("\n");
		fflush(stdout);

		if (a->rebalance_enabled && a->num_workers > 1) {
			double avg_pps = sum_pps / a->num_workers;
			if (avg_pps >= REBALANCE_MIN_AVG_PPS &&
			    max_pps > avg_pps * REBALANCE_IMBALANCE_RATIO && max_idx != min_idx) {
				unsigned moved = parser_bucket_rebalance(
					max_idx, min_idx, now_tsc, idle_threshold_cycles);
				if (moved > 0)
					printf("[Stats] rebalance: moved %u bucket(s) worker %u -> worker %u (avg=%.0f max=%.0f)\n",
					       moved, max_idx, min_idx, avg_pps, max_pps);
			}
		}

		prev = cur;
	}

	printf("[Stats] thread exiting on lcore %u\n", rte_lcore_id());
	return 0;
}
