#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include <rte_cycles.h>
#include <rte_lcore.h>

#include "stats.h"

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

int stats_thread_main(void *arg)
{
	(void)arg;

	struct core_stats prev, cur;
	aggregate(&prev);

	const uint64_t hz = rte_get_timer_hz();
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
		fflush(stdout);

		prev = cur;
	}

	printf("[Stats] thread exiting on lcore %u\n", rte_lcore_id());
	return 0;
}
