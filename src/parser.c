#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <netinet/in.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_cycles.h>

#include "parser.h"

#define FLOW_TABLE_CAPACITY       1024
#define FLOW_BUF_CAP              4096 /* last byte reserved for NUL terminator */
#define FLOW_SCAN_BUF_CAP         512
#define FLOW_EXPIRY_SCAN_INTERVAL 256  /* sweep the table every N parser_flow_update() calls */

/*
 * Adversarial-resilient TCP reassembly (Ptacek & Newsham 1998 insertion/
 * evasion; see version_02.md for the full writeup). `buf` is indexed by
 * stream offset relative to `first_seq`, not by arrival order, so segments
 * are placed correctly regardless of arrival order. `filled[]` tracks which
 * offsets have been written; overlap resolution is "first wins" -- an
 * offset already filled (by whatever segment was processed earliest) is
 * never overwritten by a later-processed segment covering the same
 * position. `contig_len` (the gap-free prefix length from offset 0) is what
 * try_extract_http()/try_extract_tls_sni() scan -- both require a
 * contiguous, correctly-ordered prefix. `hwm` is the highest offset+1 ever
 * written (>= contig_len, since out-of-order segments can fill positions
 * past a gap); it bounds how much of `buf`/`filled` must move when an
 * earlier-sequence segment arrives and the buffer needs to shift right.
 */
struct flow_state {
	char buf[FLOW_BUF_CAP];
	uint8_t filled[FLOW_BUF_CAP];
	uint16_t contig_len;
	uint16_t hwm;
	uint32_t first_seq;
	bool first_seq_set;
	char scan_buf[FLOW_SCAN_BUF_CAP];
	enum traffic_type type;
	uint64_t last_seen_tsc;
	bool verdict_cached;
	enum packet_action cached_action;
	bool no_sni_cached; /* verdict_cached was set via REASSEMBLY_NO_SNI, not a real DPI
			     * scan -- lets parser_flow_update() report *out_no_sni accurately
			     * on every subsequent REASSEMBLY_CACHED packet of this flow, not
			     * just the first (see parser.h). */
};

struct flow_table {
	struct rte_hash *h;
	struct flow_state *states;
	uint64_t timeout_cycles;
	uint64_t call_count;
};

/*
 * Shared L2-L4 field extraction, used both for the RX-side steering hash
 * (cheap, best-effort) and the worker's validating parse. Returns false if
 * the packet is not IPv4/TCP with dst port 80/443 -- callers that need a
 * drop decision (parser_parse_l2_l4) treat false as "drop"; the RX hash
 * path just falls back to 0 in that case, which is still correct (packets
 * that will be dropped anyway don't need flow affinity).
 */
static bool extract_headers(struct rte_mbuf *pkt, struct flow_key *key, enum traffic_type *type,
			     const char **payload, uint16_t *payload_len, uint32_t *seq)
{
	uint16_t data_len = rte_pktmbuf_data_len(pkt);
	const uint8_t *base = rte_pktmbuf_mtod(pkt, const uint8_t *);

	if (data_len < sizeof(struct rte_ether_hdr))
		return false;

	const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)base;
	if (rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_IPV4)
		return false;

	uint16_t l3_off = sizeof(struct rte_ether_hdr);
	if (data_len < l3_off + sizeof(struct rte_ipv4_hdr))
		return false;

	const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(base + l3_off);
	uint8_t ihl = (ip->version_ihl & 0x0f) * 4;
	if (ihl < sizeof(struct rte_ipv4_hdr) || data_len < l3_off + ihl)
		return false;

	uint8_t proto = ip->next_proto_id;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return false;

	key->src_ip = ip->src_addr;
	key->dst_ip = ip->dst_addr;
	key->proto = proto;

	uint16_t l4_off = l3_off + ihl;
	uint16_t src_port, dst_port, data_off;

	if (proto == IPPROTO_TCP) {
		if (data_len < l4_off + sizeof(struct rte_tcp_hdr))
			return false;
		const struct rte_tcp_hdr *tcp = (const struct rte_tcp_hdr *)(base + l4_off);
		src_port = rte_be_to_cpu_16(tcp->src_port);
		dst_port = rte_be_to_cpu_16(tcp->dst_port);
		uint8_t doff = (tcp->data_off >> 4) * 4;
		if (doff < sizeof(struct rte_tcp_hdr))
			return false;
		data_off = l4_off + doff;
		if (seq)
			*seq = rte_be_to_cpu_32(tcp->sent_seq);
	} else {
		if (data_len < l4_off + sizeof(struct rte_udp_hdr))
			return false;
		const struct rte_udp_hdr *udp = (const struct rte_udp_hdr *)(base + l4_off);
		src_port = rte_be_to_cpu_16(udp->src_port);
		dst_port = rte_be_to_cpu_16(udp->dst_port);
		data_off = l4_off + sizeof(struct rte_udp_hdr);
	}

	key->src_port = src_port;
	key->dst_port = dst_port;

	if (proto != IPPROTO_TCP)
		return false; /* HTTP/HTTPS DPI only applies to TCP */

	if (dst_port == HTTP_PORT)
		*type = TRAFFIC_HTTP;
	else if (dst_port == HTTPS_PORT)
		*type = TRAFFIC_HTTPS;
	else
		return false;

	if (data_off > data_len)
		return false;

	if (payload) {
		*payload = (const char *)(base + data_off);
		*payload_len = data_len - data_off;
	}
	return true;
}

uint32_t parser_flow_rss_hash(struct rte_mbuf *pkt)
{
	struct flow_key key;
	enum traffic_type type;
	const char *payload;
	uint16_t payload_len;

	memset(&key, 0, sizeof(key));
	if (!extract_headers(pkt, &key, &type, &payload, &payload_len, NULL))
		return 0;

	return rte_jhash(&key, sizeof(key), 0);
}

bool parser_parse_l2_l4(struct rte_mbuf *pkt, struct l2l4_result *out)
{
	return extract_headers(pkt, &out->key, &out->type, &out->payload, &out->payload_len,
				&out->seq);
}

#define PARSER_NUM_BUCKETS          256 /* power of two: bucket = hash & (N-1) */
#define PARSER_MAX_BUCKETS_PER_PASS   8 /* cap moved per rebalance call -- anti-oscillation */

/*
 * bucket_worker[]: written only by the Stats thread (parser_bucket_rebalance),
 * read only by the RX thread (parser_bucket_select_worker). Single-writer/
 * single-reader, no locks needed -- same lock-free pattern as stats_table[]
 * (see stats.h). x86 TSO guarantees no torn reads for these word-sized
 * elements; a reader occasionally seeing a reassignment a few packets late
 * is harmless since buckets are only ever moved once idle.
 *
 * bucket_last_seen_tsc[]: written only by the RX thread (every packet),
 * read only by the Stats thread's idle scan. Same pattern, opposite
 * direction.
 *
 * Note: traffic that isn't IPv4/TCP-UDP or not dst port 80/443 always
 * hashes to bucket 0 (parser_flow_rss_hash()'s fallback). That keeps
 * bucket 0 almost permanently "hot" so it will rarely be reassigned --
 * harmless, since that traffic is dropped at the L2-L4 stage in the
 * worker regardless of which one it lands on.
 */
static uint8_t bucket_worker[PARSER_NUM_BUCKETS];
static uint64_t bucket_last_seen_tsc[PARSER_NUM_BUCKETS];

void parser_bucket_table_init(unsigned num_workers)
{
	for (unsigned b = 0; b < PARSER_NUM_BUCKETS; b++)
		bucket_worker[b] = (uint8_t)(b % num_workers);
	memset(bucket_last_seen_tsc, 0, sizeof(bucket_last_seen_tsc));
}

unsigned parser_bucket_select_worker(uint32_t hash, uint64_t now_tsc)
{
	uint32_t bucket = hash & (PARSER_NUM_BUCKETS - 1);
	bucket_last_seen_tsc[bucket] = now_tsc;
	return bucket_worker[bucket];
}

unsigned parser_bucket_rebalance(unsigned overloaded_worker, unsigned underloaded_worker,
				  uint64_t now_tsc, uint64_t idle_threshold_cycles)
{
	unsigned moved = 0;

	for (uint32_t b = 0; b < PARSER_NUM_BUCKETS && moved < PARSER_MAX_BUCKETS_PER_PASS; b++) {
		if (bucket_worker[b] != overloaded_worker)
			continue;

		uint64_t last = bucket_last_seen_tsc[b];
		/* now_tsc is a snapshot the caller took before this call; the RX
		 * thread may have stamped a newer timestamp on this bucket since
		 * then (last >= now_tsc). Treat that as "still active" explicitly
		 * -- without this check, now_tsc - last would underflow (both are
		 * uint64_t) and wrongly look like a huge idle duration, letting an
		 * actively-hot bucket be reassigned. */
		if (last >= now_tsc || now_tsc - last <= idle_threshold_cycles)
			continue; /* still active recently -- do not touch */

		bucket_worker[b] = (uint8_t)underloaded_worker;
		moved++;
	}

	return moved;
}

void parser_bucket_get_distribution(unsigned num_workers, unsigned *counts_out)
{
	memset(counts_out, 0, sizeof(*counts_out) * num_workers);
	for (uint32_t b = 0; b < PARSER_NUM_BUCKETS; b++) {
		unsigned w = bucket_worker[b];
		if (w < num_workers)
			counts_out[w]++;
	}
}

/* Case-insensitive substring search over a NUL-terminated buffer. */
static char *find_ci(const char *hay, const char *needle)
{
	size_t needle_len = strlen(needle);

	for (const char *p = hay; *p; p++) {
		if (strncasecmp(p, needle, needle_len) == 0)
			return (char *)p;
	}
	return NULL;
}

static const char *const http_methods[] = {
	"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ",
};

/*
 * Spec 5.2: for HTTP, find the method keyword at the start of the payload
 * and extract the URL + Host header. Returns false while the request line
 * or Host header hasn't fully arrived yet (caller keeps buffering).
 */
static bool try_extract_http(struct flow_state *st, const char **out_str, uint16_t *out_len)
{
	st->buf[st->contig_len] = '\0';
	const char *buf = st->buf;

	bool method_ok = false;
	for (size_t i = 0; i < RTE_DIM(http_methods); i++) {
		if (strncmp(buf, http_methods[i], strlen(http_methods[i])) == 0) {
			method_ok = true;
			break;
		}
	}
	if (!method_ok)
		return false;

	const char *sp1 = strchr(buf, ' ');
	if (!sp1)
		return false;
	const char *sp2 = strchr(sp1 + 1, ' ');
	if (!sp2)
		return false; /* request line not fully received yet */
	uint16_t uri_len = (uint16_t)(sp2 - (sp1 + 1));

	const char *host_hdr = find_ci(buf, "\r\nHost:");
	if (!host_hdr)
		return false; /* Host header not seen yet */

	const char *host_val = host_hdr + strlen("\r\nHost:");
	while (*host_val == ' ')
		host_val++;
	const char *host_end = strstr(host_val, "\r\n");
	if (!host_end)
		return false; /* Host header line not fully received yet */
	uint16_t host_len = (uint16_t)(host_end - host_val);

	if (snprintf(st->scan_buf, sizeof(st->scan_buf), "http://%.*s%.*s", host_len, host_val,
		     uri_len, sp1 + 1) < 0)
		return false;

	*out_str = st->scan_buf;
	*out_len = (uint16_t)strnlen(st->scan_buf, sizeof(st->scan_buf));
	return true;
}

#define TLS_NEED(n)                                                                              \
	do {                                                                                       \
		if ((uint32_t)offset + (n) > st->contig_len)                                        \
			return TLS_SNI_PENDING;                                                   \
	} while (0)

/* Tri-state result of a single try_extract_tls_sni() call. Distinguishes
 * "wait for more data" from "definitively no SNI in this ClientHello" --
 * the old bool return conflated the two, which meant an ECH-shaped
 * ClientHello (structurally complete, no server_name extension by design)
 * was indistinguishable from a genuinely still-buffering one until either
 * the 4KB reassembly window filled or the flow idled out. See
 * REASSEMBLY_NO_SNI in parser.h and version_03.md. */
enum tls_sni_result {
	TLS_SNI_PENDING,     /* not enough data buffered yet -- also the safe fallback for
			      * every early structural mismatch (wrong record/handshake type,
			      * non-hostname name_type): with out-of-order reassembly, offset 0
			      * of the anchored buffer can transiently hold the wrong bytes
			      * before an earlier segment arrives and shifts things into
			      * place, so a single early mismatch is never trusted as
			      * definitive -- only returned by TLS_NEED() and by every
			      * `return` in try_extract_tls_sni() except the final one below */
	TLS_SNI_NOT_PRESENT, /* returned from exactly one place: the extensions list was
			      * walked start-to-finish (every ext_len consumed exactly up to
			      * ext_end) without ever seeing ext_type 0x0000. Reaching that
			      * point requires every preceding length-prefixed field to have
			      * parsed self-consistently, which is the trustworthy signal --
			      * an out-of-order/incomplete buffer overwhelmingly fails one of
			      * the earlier checks first (see TLS_SNI_PENDING above) */
	TLS_SNI_FOUND,
};

/*
 * Spec 5.2: for HTTPS, intercept the TLS ClientHello and parse its
 * extensions to pull out the SNI hostname. Handles the case where the
 * ClientHello is split across several reassembled TCP segments by bounds
 * checking every field read against st->contig_len and returning
 * TLS_SNI_PENDING ("wait for more data") whenever a field isn't fully
 * present yet.
 *
 * Simplification: assumes the ClientHello fits within a single TLS record
 * (true for the vast majority of real-world traffic); a ClientHello
 * fragmented across multiple TLS records is out of scope for this project.
 */
static enum tls_sni_result try_extract_tls_sni(struct flow_state *st, const char **out_str,
						 uint16_t *out_len)
{
	const uint8_t *buf = (const uint8_t *)st->buf;
	uint16_t offset = 0;

	TLS_NEED(5); /* record header: type(1) + version(2) + length(2) */
	if (buf[0] != 0x16)
		/* NOT a terminal TLS_SNI_NOT_PRESENT: with out-of-order reassembly,
		 * offset 0 of the anchored buffer can transiently hold the wrong
		 * bytes before an earlier-sequence segment arrives and shifts
		 * things into place (parser_flow_update()'s memmove path). Treating
		 * this single-byte mismatch as definitive let one out-of-order
		 * segment poison the verdict before reassembly completed -- caught
		 * by re-running pcap/adversarial.pcap's out-of-order scenario
		 * during this feature's own regression pass. Fall back to PENDING,
		 * same as before this change; the generic buffer-fill/timeout
		 * give-up path below still applies as the safety net. */
		return TLS_SNI_PENDING;
	offset = 5;

	TLS_NEED(4); /* handshake header: type(1) + length(3) */
	if (buf[offset] != 0x01)
		return TLS_SNI_PENDING; /* same out-of-order risk as buf[0] above */
	offset += 4;

	TLS_NEED(2 + 32 + 1); /* client_version(2) + random(32) + session_id_len(1) */
	offset += 2 + 32;
	uint8_t session_id_len = buf[offset];
	offset += 1;
	TLS_NEED(session_id_len);
	offset += session_id_len;

	TLS_NEED(2);
	uint16_t cipher_len = (uint16_t)((buf[offset] << 8) | buf[offset + 1]);
	offset += 2;
	TLS_NEED(cipher_len);
	offset += cipher_len;

	TLS_NEED(1);
	uint8_t comp_len = buf[offset];
	offset += 1;
	TLS_NEED(comp_len);
	offset += comp_len;

	TLS_NEED(2);
	uint16_t ext_total_len = (uint16_t)((buf[offset] << 8) | buf[offset + 1]);
	offset += 2;
	uint32_t ext_end = (uint32_t)offset + ext_total_len;
	TLS_NEED(ext_total_len);

	while ((uint32_t)offset + 4 <= ext_end) {
		TLS_NEED(4);
		uint16_t ext_type = (uint16_t)((buf[offset] << 8) | buf[offset + 1]);
		uint16_t ext_len = (uint16_t)((buf[offset + 2] << 8) | buf[offset + 3]);
		offset += 4;
		TLS_NEED(ext_len);
		/* A declared ext_len that overruns the extensions block itself
		 * (offset+ext_len > ext_end) is malformed relative to ext_total_len
		 * -- without this check the loop's own bound check below would
		 * silently fail on the next iteration and fall through to the
		 * "exhausted, no server_name found" TLS_SNI_NOT_PRESENT return,
		 * even though bytes past ext_end (possibly a real server_name
		 * extension) were never actually examined. Treat it as PENDING
		 * (not trustworthy) rather than a clean structural termination. */
		if ((uint32_t)offset + ext_len > ext_end)
			return TLS_SNI_PENDING;

		if (ext_type == 0x0000) { /* server_name extension */
			uint16_t p = offset;
			if ((uint32_t)p + 2 > st->contig_len)
				return TLS_SNI_PENDING;
			p += 2; /* server_name_list length */
			if ((uint32_t)p + 3 > st->contig_len)
				return TLS_SNI_PENDING;
			uint8_t name_type = buf[p];
			uint16_t name_len = (uint16_t)((buf[p + 1] << 8) | buf[p + 2]);
			p += 3;
			if (name_type != 0x00)
				return TLS_SNI_PENDING; /* same out-of-order caution as buf[0] above */
			if ((uint32_t)p + name_len > st->contig_len)
				return TLS_SNI_PENDING;

			if (snprintf(st->scan_buf, sizeof(st->scan_buf), "HOST://%.*s", name_len,
				     (const char *)&buf[p]) < 0)
				return TLS_SNI_PENDING;

			*out_str = st->scan_buf;
			*out_len = (uint16_t)strnlen(st->scan_buf, sizeof(st->scan_buf));
			return TLS_SNI_FOUND;
		}

		offset += ext_len;
	}

	return TLS_SNI_NOT_PRESENT; /* extensions fully present but no server_name found */
}

struct flow_table *parser_flow_table_create(uint64_t timeout_cycles)
{
	static uint32_t table_seq;
	char name[RTE_HASH_NAMESIZE];

	struct flow_table *ft = rte_zmalloc("flow_table", sizeof(*ft), 0);
	if (!ft)
		return NULL;

	snprintf(name, sizeof(name), "flow_hash_%u",
		 __atomic_fetch_add(&table_seq, 1, __ATOMIC_RELAXED));

	struct rte_hash_parameters params = {
		.name = name,
		.entries = FLOW_TABLE_CAPACITY,
		.key_len = sizeof(struct flow_key),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = (int)rte_socket_id(),
	};

	ft->h = rte_hash_create(&params);
	if (!ft->h) {
		rte_free(ft);
		return NULL;
	}

	ft->states = rte_zmalloc("flow_states", sizeof(struct flow_state) * FLOW_TABLE_CAPACITY,
				  RTE_CACHE_LINE_SIZE);
	if (!ft->states) {
		rte_hash_free(ft->h);
		rte_free(ft);
		return NULL;
	}

	ft->timeout_cycles = timeout_cycles;
	return ft;
}

void parser_flow_table_free(struct flow_table *ft)
{
	if (!ft)
		return;
	rte_free(ft->states);
	rte_hash_free(ft->h);
	rte_free(ft);
}

/*
 * Lazily sweeps the whole table for idle flows. Deleting while iterating is
 * a known DPDK caveat (an entry can be skipped in a given pass) -- harmless
 * here since any missed entry is simply picked up on the next sweep.
 */
static void flow_table_expire(struct flow_table *ft)
{
	uint32_t next = 0;
	const void *key;
	void *data;
	int32_t idx;
	uint64_t now = rte_get_timer_cycles();

	while ((idx = rte_hash_iterate(ft->h, &key, &data, &next)) >= 0) {
		struct flow_state *st = &ft->states[idx];
		if (now - st->last_seen_tsc > ft->timeout_cycles)
			rte_hash_del_key(ft->h, key);
	}
}

enum reassembly_status parser_flow_update(struct flow_table *ft, const struct l2l4_result *l2l4,
					   const char **out_str, uint16_t *out_len,
					   enum packet_action *out_cached_action, bool *out_no_sni)
{
	*out_no_sni = false;

	ft->call_count++;
	if (ft->call_count % FLOW_EXPIRY_SCAN_INTERVAL == 0)
		flow_table_expire(ft);

	int32_t idx = rte_hash_lookup(ft->h, &l2l4->key);
	struct flow_state *st;

	if (idx < 0) {
		idx = rte_hash_add_key(ft->h, &l2l4->key);
		if (idx < 0)
			return REASSEMBLY_GIVE_UP; /* table full: fail open, can't track this flow */
		st = &ft->states[idx];
		memset(st, 0, sizeof(*st));
		st->type = l2l4->type;
	} else {
		st = &ft->states[idx];
	}

	st->last_seen_tsc = rte_get_timer_cycles();

	if (st->verdict_cached) {
		*out_cached_action = st->cached_action;
		*out_no_sni = st->no_sni_cached;
		return REASSEMBLY_CACHED;
	}

	/*
	 * Zero-payload packets (SYN, pure ACK, FIN) reach here too --
	 * extract_headers() doesn't filter on TCP flags. They must neither
	 * anchor first_seq nor perturb reassembly state: anchoring on a SYN
	 * (whose seq is one less than the first real data byte) would offset
	 * every subsequent placement by 1 and permanently stall contig_len at
	 * 0, silently fail-opening every flow.
	 */
	if (l2l4->payload_len > 0) {
		if (!st->first_seq_set) {
			st->first_seq = l2l4->seq;
			st->first_seq_set = true;
		}

		/* Serial-number arithmetic: negative means this segment starts
		 * before everything seen so far and the buffer must shift right
		 * to make room at the front. Safe without full 32-bit wraparound
		 * handling because the reassembly window is capped at FLOW_BUF_CAP
		 * -- anything that far away is rejected by the bounds checks below
		 * regardless of the true wraparound distance. */
		int32_t diff = (int32_t)(l2l4->seq - st->first_seq);

		if (diff < 0) {
			uint32_t shift = (uint32_t)(-diff);
			/* Compare in uint32_t before any narrowing cast -- shift can
			 * be huge (malformed/adversarial seq), and truncating it to
			 * uint16_t first could wrap into a small value that wrongly
			 * passes this check, causing an out-of-bounds memmove. */
			if (shift <= (uint32_t)(FLOW_BUF_CAP - 1) &&
			    (uint32_t)st->hwm + shift <= (uint32_t)(FLOW_BUF_CAP - 1)) {
				memmove(st->buf + shift, st->buf, st->hwm);
				memmove(st->filled + shift, st->filled, st->hwm);
				memset(st->filled, 0, shift);
				st->hwm += (uint16_t)shift;
				st->first_seq = l2l4->seq;
				diff = 0;
				/* The offset mapping just changed for every existing
				 * byte, so the old contig_len no longer means "gap-free
				 * from 0" at its old value -- it must be re-derived from
				 * offset 0. Resuming from the stale value below would let
				 * the recompute loop skip straight into the relocated
				 * (still gap-free-looking) old data and miss a genuine
				 * new gap left behind by this shift, e.g. when the
				 * triggering segment is shorter than the shift distance. */
				st->contig_len = 0;
			}
			/* else: shift doesn't fit in the window -- drop this
			 * segment's contribution, keep existing state, keep waiting. */
		}

		if (diff >= 0) {
			uint32_t rel_offset = (uint32_t)diff;
			if (rel_offset < (uint32_t)(FLOW_BUF_CAP - 1)) {
				uint32_t write_end = rel_offset + l2l4->payload_len;
				if (write_end > (uint32_t)(FLOW_BUF_CAP - 1))
					write_end = FLOW_BUF_CAP - 1; /* clip to window */

				for (uint32_t off = rel_offset; off < write_end; off++) {
					if (!st->filled[off]) { /* first wins */
						st->buf[off] = l2l4->payload[off - rel_offset];
						st->filled[off] = 1;
					}
				}
				if (write_end > st->hwm)
					st->hwm = (uint16_t)write_end;
				while (st->contig_len < st->hwm && st->filled[st->contig_len])
					st->contig_len++;
			}
			/* else: segment lands entirely beyond the reassembly window.
			 * Deliberately NOT a give-up: a single out-of-window segment
			 * doesn't mean the header is unparseable, and giving up
			 * immediately would let an attacker force this flow fail-open
			 * with one bogus far-ahead segment -- a new evasion primitive
			 * this feature would otherwise be closing. */
		}
	}

	if (l2l4->type == TRAFFIC_HTTP) {
		if (try_extract_http(st, out_str, out_len))
			return REASSEMBLY_READY;
	} else {
		enum tls_sni_result r = try_extract_tls_sni(st, out_str, out_len);
		if (r == TLS_SNI_FOUND)
			return REASSEMBLY_READY;
		if (r == TLS_SNI_NOT_PRESENT) {
			/* Immediate, not gated by contig_len -- an ECH-shaped
			 * ClientHello (or any other definitively SNI-less case) is
			 * typically far smaller than FLOW_BUF_CAP, so waiting for
			 * the generic give-up check below would leave it PENDING
			 * (silently fail-open) until the ~1.5s idle sweep instead
			 * of surfacing it now. See REASSEMBLY_NO_SNI, version_03.md. */
			st->no_sni_cached = true;
			*out_no_sni = true;
			return REASSEMBLY_NO_SNI;
		}
		/* TLS_SNI_PENDING falls through to the generic pending/give-up
		 * check below, same as before. */
	}

	/* Genuine give-up: the contiguous prefix filled the whole window
	 * without finding a match. If contig_len is stuck behind a persistent
	 * gap instead, the flow just idles until flow_table_expire's ~1.5s
	 * sweep reaps it -- same fail-open outcome as today, just later. */
	if (st->contig_len >= FLOW_BUF_CAP - 1)
		return REASSEMBLY_GIVE_UP;

	return REASSEMBLY_PENDING;
}

enum fallback_verdict parser_flow_classify_fallback(const struct flow_features *features)
{
	(void)features;
	return FALLBACK_UNKNOWN; /* not implemented -- see parser.h for the design intent */
}

void parser_flow_cache_verdict(struct flow_table *ft, const struct flow_key *key,
				enum packet_action action)
{
	int32_t idx = rte_hash_lookup(ft->h, key);
	if (idx < 0)
		return; /* flow was evicted between scan and cache -- next packet just re-scans */

	struct flow_state *st = &ft->states[idx];
	st->verdict_cached = true;
	st->cached_action = action;
	st->contig_len = 0; /* reassembly buffer no longer needed */
	/* hwm/filled[]/first_seq/first_seq_set are deliberately left stale --
	 * verdict_cached short-circuits parser_flow_update() before any
	 * placement code runs, and a slot reused by a later flow always gets a
	 * full memset(st, 0, sizeof(*st)) on creation, so nothing ever reads
	 * these fields again in a meaningful state. */
}
