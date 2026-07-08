#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_cycles.h>

#include "hyperdpi.h"
#include "parser.h"
#include "dpi_engine.h"
#include "stats.h"

volatile bool force_quit;

#define DEFAULT_PATTERNS_FILE "config/patterns.txt"
#define DEFAULT_NUM_WORKERS   2
#define MBUF_POOL_CACHE       MBUF_POOL_CACHE_SIZE

struct rx_thread_args {
	uint16_t port_id;
	struct rte_ring **worker_rings;
	unsigned num_workers;
};

struct worker_thread_args {
	unsigned worker_id;
	struct rte_ring *in_ring;
	struct rte_ring *tx_ring;
	uint64_t flow_timeout_cycles;
};

struct tx_thread_args {
	uint16_t port_id;
	struct rte_ring *tx_ring;
};

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n[Main] signal %d received, shutting down...\n", signum);
		force_quit = true;
	}
}

/*
 * RX Thread (spec 4.2.A): pure polling, no parsing beyond the minimal
 * 5-tuple steering hash needed to keep each flow's packets on the same
 * worker (required for per-flow reassembly to work).
 */
static int rx_thread_main(void *arg)
{
	struct rx_thread_args *a = arg;
	unsigned lcore_id = rte_lcore_id();
	struct rte_mbuf *bufs[BURST_SIZE];
	struct rte_mbuf *dest[MAX_WORKERS][BURST_SIZE];
	uint16_t dest_n[MAX_WORKERS];

	printf("[RX] started on lcore %u\n", lcore_id);

	while (!force_quit) {
		uint16_t nb_rx = rte_eth_rx_burst(a->port_id, 0, bufs, BURST_SIZE);
		if (nb_rx == 0)
			continue;

		uint64_t rx_bytes = 0;
		memset(dest_n, 0, sizeof(dest_n));

		for (uint16_t i = 0; i < nb_rx; i++) {
			rx_bytes += rte_pktmbuf_pkt_len(bufs[i]);
			uint32_t h = parser_flow_rss_hash(bufs[i]);
			unsigned w = h % a->num_workers;
			dest[w][dest_n[w]++] = bufs[i];
		}

		stats_add_rx(lcore_id, nb_rx, rx_bytes);

		for (unsigned w = 0; w < a->num_workers; w++) {
			if (dest_n[w] == 0)
				continue;
			uint16_t sent = rte_ring_enqueue_burst(a->worker_rings[w],
								(void **)dest[w], dest_n[w], NULL);
			for (uint16_t j = sent; j < dest_n[w]; j++) {
				/* worker ring full: drop rather than leak the mbuf */
				stats_count_dropped(lcore_id);
				rte_pktmbuf_free(dest[w][j]);
			}
		}
	}

	printf("[RX] exiting on lcore %u\n", lcore_id);
	return 0;
}

/*
 * Worker Thread (spec 4.2.B / 5.1 / 5.2 / 5.3): L2-L4 parse+filter, per-flow
 * reassembly, Hyperscan DPI scan, FORWARD/DROP decision.
 */
static int worker_thread_main(void *arg)
{
	struct worker_thread_args *a = arg;
	unsigned lcore_id = rte_lcore_id();
	struct rte_mbuf *bufs[BURST_SIZE];
	struct rte_mbuf *fwd[BURST_SIZE];

	hs_scratch_t *scratch = NULL;
	if (dpi_engine_alloc_scratch(&scratch) != 0) {
		fprintf(stderr, "[Worker %u] failed to allocate Hyperscan scratch\n",
			a->worker_id);
		return -1;
	}

	struct flow_table *ft = parser_flow_table_create(a->flow_timeout_cycles);
	if (!ft) {
		fprintf(stderr, "[Worker %u] failed to create flow table\n", a->worker_id);
		dpi_engine_free_scratch(scratch);
		return -1;
	}

	printf("[Worker %u] started on lcore %u\n", a->worker_id, lcore_id);

	while (!force_quit) {
		uint16_t n = rte_ring_dequeue_burst(a->in_ring, (void **)bufs, BURST_SIZE, NULL);
		if (n == 0)
			continue;

		uint16_t fwd_n = 0;

		for (uint16_t i = 0; i < n; i++) {
			struct rte_mbuf *pkt = bufs[i];
			struct l2l4_result l2l4;

			if (!parser_parse_l2_l4(pkt, &l2l4)) {
				stats_count_classified(lcore_id, TRAFFIC_NON_DPI);
				stats_count_dropped(lcore_id);
				rte_pktmbuf_free(pkt);
				continue;
			}

			stats_count_classified(lcore_id, l2l4.type);

			const char *scan_str = NULL;
			uint16_t scan_len = 0;
			enum packet_action cached_action = ACTION_FORWARD;
			enum packet_action action;

			enum reassembly_status rs = parser_flow_update(ft, &l2l4, &scan_str,
									&scan_len, &cached_action);
			switch (rs) {
			case REASSEMBLY_CACHED:
				action = cached_action;
				break;
			case REASSEMBLY_READY:
				action = dpi_engine_scan(scratch, l2l4.type, scan_str, scan_len);
				parser_flow_cache_verdict(ft, &l2l4.key, action);
				printf("[Worker %u] %s %s -> %s\n", a->worker_id,
				       action == ACTION_DROP ? "MATCH   " : "NO MATCH",
				       scan_str, action == ACTION_DROP ? "DROP" : "FORWARD");
				break;
			case REASSEMBLY_PENDING:
			case REASSEMBLY_GIVE_UP:
			default:
				/* fail-open: forward while waiting for more segments, or
				 * after giving up once the reassembly cap is hit */
				action = ACTION_FORWARD;
				break;
			}

			if (action == ACTION_DROP) {
				stats_count_dropped(lcore_id);
				rte_pktmbuf_free(pkt);
			} else {
				fwd[fwd_n++] = pkt;
			}
		}

		if (fwd_n > 0) {
			uint16_t sent = rte_ring_enqueue_burst(a->tx_ring, (void **)fwd, fwd_n,
								NULL);
			for (uint16_t j = 0; j < sent; j++)
				stats_count_forwarded(lcore_id);
			for (uint16_t j = sent; j < fwd_n; j++) {
				/* tx ring full: drop rather than leak the mbuf */
				stats_count_dropped(lcore_id);
				rte_pktmbuf_free(fwd[j]);
			}
		}
	}

	parser_flow_table_free(ft);
	dpi_engine_free_scratch(scratch);
	printf("[Worker %u] exiting on lcore %u\n", a->worker_id, lcore_id);
	return 0;
}

/* TX Thread (spec 4.2.C): gathers up to a full burst per dequeue, then a
 * single rte_eth_tx_burst() call to minimize driver interaction. */
static int tx_thread_main(void *arg)
{
	struct tx_thread_args *a = arg;
	unsigned lcore_id = rte_lcore_id();
	struct rte_mbuf *bufs[BURST_SIZE];

	printf("[TX] started on lcore %u\n", lcore_id);

	while (!force_quit) {
		uint16_t n = rte_ring_dequeue_burst(a->tx_ring, (void **)bufs, BURST_SIZE, NULL);
		if (n == 0)
			continue;

		uint16_t sent = rte_eth_tx_burst(a->port_id, 0, bufs, n);
		stats_add_tx(lcore_id, sent);
		for (uint16_t i = sent; i < n; i++)
			rte_pktmbuf_free(bufs[i]); /* NIC tx queue full: free rather than leak */
	}

	printf("[TX] exiting on lcore %u\n", lcore_id);
	return 0;
}

static void usage(const char *prgname)
{
	fprintf(stderr,
		"Usage: %s [EAL options] -- [-p patterns_file] [-w num_workers(2-%d)]\n",
		prgname, MAX_WORKERS);
}

int main(int argc, char **argv)
{
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "EAL init failed\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	const char *patterns_file = DEFAULT_PATTERNS_FILE;
	unsigned num_workers = DEFAULT_NUM_WORKERS;

	int opt;
	optind = 1;
	while ((opt = getopt(argc, argv, "p:w:h")) != -1) {
		switch (opt) {
		case 'p':
			patterns_file = optarg;
			break;
		case 'w':
			num_workers = (unsigned)atoi(optarg);
			break;
		case 'h':
		default:
			usage(argv[0]);
			rte_exit(EXIT_FAILURE, "invalid arguments\n");
		}
	}
	if (num_workers < 2 || num_workers > MAX_WORKERS)
		rte_exit(EXIT_FAILURE, "num_workers must be between 2 and %d\n", MAX_WORKERS);

	stats_init();

	if (dpi_engine_load_rules(patterns_file) != 0)
		rte_exit(EXIT_FAILURE, "failed to load DPI rules from %s\n", patterns_file);

	if (rte_eth_dev_count_avail() == 0)
		rte_exit(EXIT_FAILURE,
			 "no ethernet ports available -- pass --vdev=net_pcap0,rx_pcap=...\n");

	uint16_t port_id = APP_PORT_ID;

	unsigned needed_lcores = 1 /* rx */ + num_workers + 1 /* tx */ + 1 /* stats */;
	if (rte_lcore_count() < needed_lcores + 1)
		rte_exit(EXIT_FAILURE,
			 "need %u worker lcores plus the main lcore (pass -l/-c EAL args); have %u\n",
			 needed_lcores, rte_lcore_count());

	unsigned lcores[needed_lcores];
	unsigned nlcores = 0;
	unsigned lcore_id;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (nlcores >= needed_lcores)
			break;
		lcores[nlcores++] = lcore_id;
	}

	unsigned rx_lcore = lcores[0];
	unsigned worker_lcores[MAX_WORKERS];
	for (unsigned i = 0; i < num_workers; i++)
		worker_lcores[i] = lcores[1 + i];
	unsigned tx_lcore = lcores[1 + num_workers];
	unsigned stats_lcore = lcores[2 + num_workers];

	unsigned nb_mbufs = RX_RING_SIZE + num_workers * WORKER_RING_SIZE + TX_RING_SIZE +
			     needed_lcores * MBUF_POOL_CACHE;

	struct rte_mempool *mbuf_pool =
		rte_pktmbuf_pool_create("MBUF_POOL", nb_mbufs, MBUF_POOL_CACHE, 0,
					 MBUF_DATA_SIZE, (int)rte_socket_id());
	if (!mbuf_pool)
		rte_exit(EXIT_FAILURE, "failed to create mbuf pool: %s\n", rte_strerror(rte_errno));

	struct rte_eth_conf port_conf;
	memset(&port_conf, 0, sizeof(port_conf));

	if (rte_eth_dev_configure(port_id, 1, 1, &port_conf) < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_dev_configure failed\n");

	if (rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE, rte_socket_id(), NULL, mbuf_pool) < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup failed\n");

	if (rte_eth_tx_queue_setup(port_id, 0, TX_RING_SIZE, rte_socket_id(), NULL) < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup failed\n");

	if (rte_eth_dev_start(port_id) < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start failed\n");

	struct rte_ring *worker_rings[MAX_WORKERS];
	for (unsigned i = 0; i < num_workers; i++) {
		char name[RTE_RING_NAMESIZE];
		snprintf(name, sizeof(name), "worker_ring_%u", i);
		worker_rings[i] = rte_ring_create(name, WORKER_RING_SIZE, (int)rte_socket_id(),
						   RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (!worker_rings[i])
			rte_exit(EXIT_FAILURE, "failed to create %s\n", name);
	}

	struct rte_ring *tx_ring = rte_ring_create("tx_ring", TX_RING_SIZE, (int)rte_socket_id(),
						    RING_F_SC_DEQ);
	if (!tx_ring)
		rte_exit(EXIT_FAILURE, "failed to create tx_ring\n");

	uint64_t flow_timeout_cycles = rte_get_timer_hz() * 3 / 2; /* ~1.5s idle timeout */

	struct rx_thread_args rx_args = {
		.port_id = port_id,
		.worker_rings = worker_rings,
		.num_workers = num_workers,
	};
	rte_eal_remote_launch(rx_thread_main, &rx_args, rx_lcore);

	struct worker_thread_args worker_args[MAX_WORKERS];
	for (unsigned i = 0; i < num_workers; i++) {
		worker_args[i].worker_id = i;
		worker_args[i].in_ring = worker_rings[i];
		worker_args[i].tx_ring = tx_ring;
		worker_args[i].flow_timeout_cycles = flow_timeout_cycles;
		rte_eal_remote_launch(worker_thread_main, &worker_args[i], worker_lcores[i]);
	}

	struct tx_thread_args tx_args = {.port_id = port_id, .tx_ring = tx_ring};
	rte_eal_remote_launch(tx_thread_main, &tx_args, tx_lcore);

	rte_eal_remote_launch(stats_thread_main, NULL, stats_lcore);

	printf("[Main] HyperDPI running with %u worker(s). Press Ctrl+C to stop.\n", num_workers);

	rte_eal_mp_wait_lcore();

	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);

	for (unsigned i = 0; i < num_workers; i++)
		rte_ring_free(worker_rings[i]);
	rte_ring_free(tx_ring);

	dpi_engine_free_rules();
	rte_eal_cleanup();

	return 0;
}
