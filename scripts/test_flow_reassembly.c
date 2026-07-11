/*
 * Standalone, deterministic test of the sequence-aware TCP reassembly /
 * overlap-resolution logic in parser.c (Ptacek & Newsham 1998 insertion/
 * evasion hardening -- see version_02.md for the full design writeup).
 *
 * Calls parser_flow_update() directly with synthetic struct l2l4_result
 * values (no real packets/mbufs needed -- the function only reads type,
 * key, payload, payload_len, seq). Needs a minimal working EAL (parser_
 * flow_table_create() uses rte_hash_create()/rte_zmalloc()) but NOT real
 * hugepages/root: `--no-huge -m 128` gives a working heap without either.
 *
 * Build: cc -O0 -g -Iinclude -include rte_config.h $(pkg-config --cflags libdpdk libhs) \
 *           scripts/test_flow_reassembly.c src/parser.c \
 *           $(pkg-config --libs libdpdk libhs) -o /tmp/test_flow_reassembly
 * Run:   /tmp/test_flow_reassembly --no-huge -m 128 --no-pci
 */
#include <stdio.h>
#include <string.h>

#include <rte_eal.h>

#include "parser.h"

/* Note: hyperdpi.h declares `extern volatile bool force_quit;`, but
 * src/parser.c never references it, so this link unit (parser.c +
 * this file) needs no definition for it. */

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

static struct flow_key make_key(uint16_t sport)
{
	struct flow_key k;
	memset(&k, 0, sizeof(k));
	k.src_ip = 0x0a000001;
	k.dst_ip = 0x0a000002;
	k.src_port = sport;
	k.dst_port = 80;
	k.proto = 6; /* IPPROTO_TCP */
	return k;
}

/* Feeds one segment and returns the reassembly_status. On READY, copies the
 * extracted string into out_buf (caller-owned) so it survives past the next
 * call (out_str otherwise points into the flow's own scan_buf, which a
 * later call could overwrite). */
static enum reassembly_status feed(struct flow_table *ft, uint16_t sport, uint32_t seq,
				    const char *payload, uint16_t len, char *out_buf,
				    size_t out_buf_sz)
{
	struct l2l4_result l2l4;
	memset(&l2l4, 0, sizeof(l2l4));
	l2l4.type = TRAFFIC_HTTP;
	l2l4.key = make_key(sport);
	l2l4.payload = payload;
	l2l4.payload_len = len;
	l2l4.seq = seq;

	const char *out_str = NULL;
	uint16_t out_len = 0;
	enum packet_action cached_action;
	bool no_sni = false;
	enum reassembly_status st =
		parser_flow_update(ft, &l2l4, &out_str, &out_len, &cached_action, &no_sni);

	if (st == REASSEMBLY_READY && out_buf) {
		size_t n = out_len < out_buf_sz - 1 ? out_len : out_buf_sz - 1;
		memcpy(out_buf, out_str, n);
		out_buf[n] = '\0';
	}
	return st;
}

int main(int argc, char **argv)
{
	int ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		fprintf(stderr, "rte_eal_init failed -- run with e.g. --no-huge -m 128 --no-pci\n");
		return 1;
	}

	uint64_t timeout_cycles = rte_get_timer_hz() * 3 / 2;
	char extracted[512];

	const char req1[] = "GET / HTTP/1.1\r\nHost: one.example\r\n\r\n";
	const char req2[] = "GET / HTTP/1.1\r\nHost: two.example\r\n\r\n"; /* same length as req1 */

	/* --- Test 1: baseline in-order, single segment --- */
	{
		struct flow_table *ft = parser_flow_table_create(timeout_cycles);
		enum reassembly_status st =
			feed(ft, 100, 1001, req1, (uint16_t)strlen(req1), extracted, sizeof(extracted));
		CHECK(st == REASSEMBLY_READY && strstr(extracted, "one.example") != NULL,
		      "in-order single segment -> READY with correct host");
		parser_flow_table_free(ft);
	}

	/* --- Test 2: out-of-order, second half arrives before first half --- */
	{
		struct flow_table *ft = parser_flow_table_create(timeout_cycles);
		size_t mid = strlen(req1) / 2;
		enum reassembly_status st1 =
			feed(ft, 101, 1001 + (uint32_t)mid, req1 + mid,
			     (uint16_t)(strlen(req1) - mid), extracted, sizeof(extracted));
		CHECK(st1 == REASSEMBLY_PENDING,
		      "out-of-order: second half alone is not enough (PENDING)");
		enum reassembly_status st2 =
			feed(ft, 101, 1001, req1, (uint16_t)mid, extracted, sizeof(extracted));
		CHECK(st2 == REASSEMBLY_READY && strstr(extracted, "one.example") != NULL,
		      "out-of-order: first half completes the flow, correct host extracted");
		parser_flow_table_free(ft);
	}

	/* --- Test 3: overlap, first-wins -- two full, equal-length, same-offset
	 * segments; the first one processed determines the outcome even though
	 * it alone would already be enough to extract a verdict. --- */
	{
		struct flow_table *ft = parser_flow_table_create(timeout_cycles);
		CHECK(strlen(req1) == strlen(req2), "test fixture: req1/req2 must be equal length");
		enum reassembly_status st1 =
			feed(ft, 102, 1001, req1, (uint16_t)strlen(req1), extracted, sizeof(extracted));
		CHECK(st1 == REASSEMBLY_READY && strstr(extracted, "one.example") != NULL,
		      "overlap: first full segment (one.example) -> READY immediately");
		/* Flow already has a cached verdict at this point (READY triggers
		 * caching in the real worker loop, but this harness calls
		 * parser_flow_update() directly without also calling
		 * parser_flow_cache_verdict() -- so feeding segment B here still
		 * exercises the buffer-level first-wins guarantee, independent of
		 * verdict caching). */
		enum reassembly_status st2 =
			feed(ft, 102, 1001, req2, (uint16_t)strlen(req2), extracted, sizeof(extracted));
		CHECK(st2 == REASSEMBLY_READY && strstr(extracted, "one.example") != NULL &&
			      strstr(extracted, "two.example") == NULL,
		      "overlap: second same-range segment (two.example) does not overwrite -- "
		      "still one.example");
		parser_flow_table_free(ft);
	}

	/* --- Test 4: overlap where completion requires BOTH segments (first-wins
	 * on the overlapping region, but a non-overlapping tail from the second
	 * segment is still needed) -- split req1 so segment A only carries a
	 * partial, ambiguous prefix and segment B (overlapping A's tail, then
	 * extending further) supplies the rest under a DIFFERENT hostname. This
	 * is the scenario QA flagged as not yet covered: first-wins must hold
	 * even when a later, differently-completing segment arrives before a
	 * verdict exists. */
	{
		struct flow_table *ft = parser_flow_table_create(timeout_cycles);
		size_t split = strlen("GET / HTTP/1.1\r\nHost: one"); /* mid-hostname */

		enum reassembly_status st1 = feed(ft, 103, 1001, req1, (uint16_t)split, extracted,
						   sizeof(extracted));
		CHECK(st1 == REASSEMBLY_PENDING, "overlap/multi-segment: partial prefix -> PENDING");

		/* Segment B starts at the SAME offset as segment A (seq=1001) but
		 * carries the *other* full request -- its first `split` bytes
		 * overlap A's already-filled bytes (must not overwrite them) and
		 * its tail extends past what A alone provided. */
		enum reassembly_status st2 =
			feed(ft, 103, 1001, req2, (uint16_t)strlen(req2), extracted, sizeof(extracted));
		CHECK(st2 == REASSEMBLY_READY, "overlap/multi-segment: completes once tail arrives");
		CHECK(strstr(extracted, "one.example") != NULL &&
			      strstr(extracted, "two.example") == NULL,
		      "overlap/multi-segment: first-wins held even though completion needed "
		      "bytes from the second (differently-hostnamed) segment");
		parser_flow_table_free(ft);
	}

	/* --- Test 5: give-up when the buffer fills without ever finding a match --- */
	{
		struct flow_table *ft = parser_flow_table_create(timeout_cycles);
		char junk[4096];
		memset(junk, 'A', sizeof(junk));
		enum reassembly_status st =
			feed(ft, 104, 1001, junk, sizeof(junk), extracted, sizeof(extracted));
		CHECK(st == REASSEMBLY_GIVE_UP, "buffer fills with no match -> GIVE_UP");
		parser_flow_table_free(ft);
	}

	printf("\n%d check(s) failed.\n", failures);
	rte_eal_cleanup();
	return failures == 0 ? 0 : 1;
}
