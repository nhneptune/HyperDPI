#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_mbuf.h>

#include "hyperdpi.h"

/* 5-tuple identifying a flow. Used both by the RX-side steering hash
 * (parser_flow_rss_hash) and by the per-worker reassembly table
 * (parser_flow_update), so packets of one flow always land on the worker
 * that owns that flow's reassembly state. */
struct flow_key {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  proto;
} __rte_packed;

/* Cheap best-effort 5-tuple hash for RX-side flow steering only (selects
 * which worker ring a packet is enqueued to). This is the one piece of
 * header inspection the RX thread performs -- deliberately minimal (fixed
 * struct field reads, no validation, no drop decisions) so line-rate is
 * preserved; it plays the same role real NIC RSS hashing would. Full,
 * validating parsing happens in parser_parse_l2_l4() inside the worker.
 * Falls back to 0 for anything not IPv4/TCP/UDP -- those packets get
 * dropped at the L2-L4 stage in the worker anyway, so which ring they
 * land on does not affect correctness. */
uint32_t parser_flow_rss_hash(struct rte_mbuf *pkt);

/* Result of the full L2->L4 parse + classification done in the worker. */
struct l2l4_result {
	enum traffic_type type; /* TRAFFIC_HTTP or TRAFFIC_HTTPS (never NON_DPI here) */
	struct flow_key key;
	const char *payload;
	uint16_t payload_len;
};

/* Validating L2->L4 parse per spec 5.1: ether_type must be IPv4, next_proto
 * must be TCP/UDP, dst port must be 80/443. Returns false (packet must be
 * dropped immediately) if any check fails. */
bool parser_parse_l2_l4(struct rte_mbuf *pkt, struct l2l4_result *out);

/* Opaque per-worker flow reassembly table. */
struct flow_table;

struct flow_table *parser_flow_table_create(uint64_t timeout_cycles);
void parser_flow_table_free(struct flow_table *ft);

enum reassembly_status {
	REASSEMBLY_PENDING, /* not enough data yet: caller fail-opens (FORWARD), no scan */
	REASSEMBLY_READY,   /* out_str/out_len filled: caller should dpi_engine_scan() then
			     * call parser_flow_cache_verdict() with the result */
	REASSEMBLY_CACHED,  /* flow already has a verdict from a prior scan: out_cached_action set */
	REASSEMBLY_GIVE_UP, /* buffer cap hit without finding Host/SNI: caller fail-opens (FORWARD) */
};

/* Feeds l2l4->payload into the reassembly buffer for l2l4->key (creating a
 * new flow entry if needed), opportunistically expiring flows idle longer
 * than the table's timeout, and reports what the caller should do next. */
enum reassembly_status parser_flow_update(struct flow_table *ft, const struct l2l4_result *l2l4,
					   const char **out_str, uint16_t *out_len,
					   enum packet_action *out_cached_action);

/* Records the verdict from dpi_engine_scan() for this flow so subsequent
 * packets skip re-scanning and reuse the cached action directly. */
void parser_flow_cache_verdict(struct flow_table *ft, const struct flow_key *key,
				enum packet_action action);

#endif /* PARSER_H */
