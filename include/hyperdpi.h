#ifndef HYPERDPI_H
#define HYPERDPI_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_common.h>

#define MAX_WORKERS         4
#define BURST_SIZE          32
#define RX_RING_SIZE         1024
#define WORKER_RING_SIZE      1024
#define TX_RING_SIZE          1024
#define MBUF_POOL_CACHE_SIZE  256
#define MBUF_DATA_SIZE        RTE_MBUF_DEFAULT_BUF_SIZE

#define APP_PORT_ID           0

/* Ports we inspect at L7; anything else is dropped at the parser stage. */
#define HTTP_PORT             80
#define HTTPS_PORT            443

/* Traffic classification used across parser/dpi_engine/stats. */
enum traffic_type {
	TRAFFIC_NON_DPI = 0, /* dropped before reaching L7 (not IPv4/TCP-UDP/80-443) */
	TRAFFIC_HTTP,
	TRAFFIC_HTTPS,
};

enum packet_action {
	ACTION_FORWARD = 0,
	ACTION_DROP,
};

/* Global shutdown flag, set by the SIGINT/SIGTERM handler in main.c.
 * All thread loops must poll this every iteration since infinite_rx=1
 * on the pcap vdev means rte_eth_rx_burst() never naturally returns 0
 * at EOF. */
extern volatile bool force_quit;

#endif /* HYPERDPI_H */
