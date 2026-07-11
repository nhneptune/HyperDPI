/*
 * Standalone, deterministic test of the bucket-rebalancing mechanism in
 * parser.c (parser_bucket_table_init / parser_bucket_select_worker /
 * parser_bucket_rebalance / parser_bucket_get_distribution).
 *
 * Why this exists: reproducing a real "idle bucket while another worker is
 * overloaded" scenario end-to-end through the full DPDK pipeline requires
 * the pcap replay loop period to exceed BUCKET_IDLE_THRESHOLD_MS (200ms).
 * Empirically this application processes on the order of 10M+ packets/sec
 * even against file-replayed traffic (see version_01.md), so a big enough
 * fixture to make one infinite_rx loop take >=200ms needs several million
 * packets in memory at once (net_pcap's infinite_rx requires nb_mbufs >=
 * packet count in the file) -- multiple GB, beyond this dev environment's
 * budget. This test instead calls the bucket functions directly with
 * controlled synthetic timestamps, which is the appropriate way to verify
 * timing-dependent logic without needing to out-run the hardware.
 *
 * No DPDK EAL/hugepages/root needed: the four bucket functions touch only
 * plain static arrays, no rte_malloc/rte_hash/mbuf APIs.
 *
 * Build:   cc -Iinclude -include rte_config.h $(pkg-config --cflags libdpdk) \
 *              scripts/test_bucket_rebalance.c src/parser.c \
 *              $(pkg-config --libs libdpdk libhs) -o /tmp/test_bucket_rebalance
 * Run:     /tmp/test_bucket_rebalance
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parser.h"

volatile bool force_quit; /* referenced via hyperdpi.h by other TUs; unused here */

static int failures;

#define CHECK(cond, msg)                                                                         \
	do {                                                                                       \
		if (!(cond)) {                                                                    \
			printf("FAIL: %s\n", msg);                                               \
			failures++;                                                              \
		} else {                                                                          \
			printf("PASS: %s\n", msg);                                               \
		}                                                                                 \
	} while (0)

#define TEST_NUM_BUCKETS 256 /* mirrors PARSER_NUM_BUCKETS, private to parser.c */

static void touch_all_buckets(uint64_t at_tsc)
{
	for (uint32_t b = 0; b < TEST_NUM_BUCKETS; b++)
		parser_bucket_select_worker(b, at_tsc); /* hash == bucket index here */
}

int main(void)
{
	unsigned counts[MAX_WORKERS];
	const uint64_t HZ = 2000000000ULL; /* pretend 2 GHz TSC for readable ms math */
	const uint64_t idle_threshold = HZ / 5; /* 200ms, matches BUCKET_IDLE_THRESHOLD_MS */

	/* --- Test 1: init gives an even, deterministic split --- */
	parser_bucket_table_init(2);
	parser_bucket_get_distribution(2, counts);
	CHECK(counts[0] == TEST_NUM_BUCKETS / 2 && counts[1] == TEST_NUM_BUCKETS / 2,
	      "init(2 workers) splits 256 buckets 128/128");

	/* --- Test 2: selecting a worker stamps activity and returns the
	 * bucket's current owner --- */
	uint64_t t0 = 1000 * HZ;
	unsigned w = parser_bucket_select_worker(0 /* hash -> bucket 0 */, t0);
	CHECK(w == 0, "hash 0 (bucket 0) initially maps to worker 0");

	/* --- Test 3: every bucket freshly touched -> none move, even when
	 * asked to rebalance worker 0 -> worker 1. This is the core safety
	 * invariant (never touch a live flow's bucket). --- */
	parser_bucket_table_init(2);
	touch_all_buckets(t0);
	unsigned moved = parser_bucket_rebalance(0, 1, t0 + 1 /* 1 cycle later */, idle_threshold);
	parser_bucket_get_distribution(2, counts);
	CHECK(moved == 0 && counts[0] == TEST_NUM_BUCKETS / 2,
	      "all-buckets-active: rebalance moves nothing");

	/* --- Test 4: everything active except bucket 0, which goes idle for
	 * longer than the threshold -- only bucket 0 should move. --- */
	uint64_t t1 = t0 + idle_threshold + HZ / 100; /* threshold + 5ms margin */
	touch_all_buckets(t1);                        /* refresh every bucket except... */
	parser_bucket_select_worker(0, t0);            /* ...bucket 0, left stale at t0 */
	moved = parser_bucket_rebalance(0, 1, t1, idle_threshold);
	parser_bucket_get_distribution(2, counts);
	CHECK(moved == 1 && counts[1] == TEST_NUM_BUCKETS / 2 + 1,
	      "the one bucket idle > threshold moves overloaded -> underloaded worker");

	/* --- Test 5: PARSER_MAX_BUCKETS_PER_PASS caps how many move in one
	 * call (anti-oscillation). Nothing touched since init -> every
	 * worker-0 bucket looks idle relative to a far-future now_tsc; confirm
	 * the pass is capped at 8 rather than moving all 128 at once. --- */
	parser_bucket_table_init(2);
	uint64_t t2 = 5000 * HZ;
	moved = parser_bucket_rebalance(0, 1, t2, idle_threshold);
	CHECK(moved == 8, "a single rebalance pass moves at most 8 buckets (anti-oscillation)");

	/* --- Test 6: the underflow-bug regression check. This is the exact
	 * scenario the code review caught: the Stats thread takes a now_tsc
	 * snapshot, then (by the time it calls rebalance) the RX thread may
	 * have already stamped a *newer* timestamp on a bucket than that
	 * snapshot (last_seen > now_tsc). If the idle check did
	 * `now_tsc - last_seen` without guarding against that, the unsigned
	 * subtraction underflows to a huge number and wrongly looks "idle
	 * enough" -- silently reassigning an actively-hot bucket and breaking
	 * the flow-affinity invariant. --- */
	parser_bucket_table_init(2);
	uint64_t t_base = 9000 * HZ;
	touch_all_buckets(t_base);
	uint64_t stale_now_tsc = t_base - HZ / 10; /* 100ms "in the past" vs. every last_seen */
	moved = parser_bucket_rebalance(0, 1, stale_now_tsc, idle_threshold);
	parser_bucket_get_distribution(2, counts);
	CHECK(moved == 0 && counts[0] == TEST_NUM_BUCKETS / 2,
	      "last_seen > now_tsc (stale snapshot) does not underflow into a false idle move");

	printf("\n%d check(s) failed.\n", failures);
	return failures == 0 ? 0 : 1;
}
