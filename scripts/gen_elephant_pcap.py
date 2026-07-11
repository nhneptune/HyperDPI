#!/usr/bin/env python3
"""Builds a synthetic traffic mix for verifying load-aware RX bucket
rebalancing: one "elephant" flow (many packets, one 5-tuple) interleaved
with many "mouse" flows (few packets each, distinct 5-tuples). Reuses the
flow-building helpers from gen_pcap.py.

Usage:
  python3 scripts/gen_elephant_pcap.py [--out pcap/elephant.pcap]
                                        [--mice 50] [--elephant-gap 500000]

--elephant-gap controls how many filler packets are written between each
pair of mouse flows. This needs calibrating against the target machine's
RX-thread processing rate so that each gap takes noticeably longer,
wall-clock, than BUCKET_IDLE_THRESHOLD_MS (200ms in src/stats.c) when
replayed -- otherwise buckets never go idle and rebalancing never
triggers. See version_01.md for the calibration procedure.
"""

import argparse

from scapy.all import Ether, IP, TCP, Raw
from scapy.utils import PcapWriter

from gen_pcap import MAC_CLIENT, MAC_SERVER, build_http_request, tcp_flow

ELEPHANT_SRC_IP = "10.99.0.1"
ELEPHANT_DST_IP = "93.184.216.99"
ELEPHANT_SPORT = 50000


def build_filler_bytes(seq):
	"""One raw HTTP-port TCP data packet for the elephant flow's filler
	traffic, pre-serialized once and then written many times verbatim.
	Content doesn't matter -- the elephant flow's verdict is already
	cached (REASSEMBLY_CACHED) by the time filler packets are sent, so
	they never reach try_extract_http()/hs_scan(); they only need to
	pass L2-L4 classification (IPv4/TCP/dst port 80) to count as
	HTTP-classified work for whichever worker owns the elephant's
	bucket."""
	pkt = (Ether(src=MAC_CLIENT, dst=MAC_SERVER) /
	       IP(src=ELEPHANT_SRC_IP, dst=ELEPHANT_DST_IP) /
	       TCP(sport=ELEPHANT_SPORT, dport=80, flags="PA", seq=seq, ack=5001) /
	       Raw(load=b"x"))
	return bytes(pkt)


def main():
	ap = argparse.ArgumentParser(description=__doc__)
	ap.add_argument("--out", default="pcap/elephant.pcap")
	ap.add_argument("--mice", type=int, default=50, help="number of distinct mouse flows")
	ap.add_argument("--elephant-gap", type=int, default=500_000,
			 help="elephant filler packets written between each pair of mouse flows")
	args = ap.parse_args()

	filler_bytes = build_filler_bytes(seq=2000)
	total_mouse_pkts = 0
	num_gaps = max(args.mice, 1)  # always emit at least one gap, even with --mice 0

	with PcapWriter(args.out, append=False, sync=False) as writer:
		# Elephant flow: real handshake + one real HTTP request so its
		# verdict gets cached quickly, then everything else is filler.
		elephant_start = tcp_flow(ELEPHANT_SRC_IP, ELEPHANT_DST_IP, ELEPHANT_SPORT, 80,
					   [build_http_request("elephant-flow.example", "/")])
		for pkt in elephant_start:
			writer.write(pkt)

		for m in range(num_gaps):
			if m < args.mice:
				mouse = tcp_flow(f"10.50.{m // 250}.{m % 250}", "93.184.216.50",
						  41000 + m, 80,
						  [build_http_request(f"mouse-{m}.example", "/")])
				for pkt in mouse:
					writer.write(pkt)
				total_mouse_pkts += len(mouse)

			for _ in range(args.elephant_gap):
				writer.write(filler_bytes)

	total = len(elephant_start) + total_mouse_pkts + num_gaps * args.elephant_gap
	print(f"wrote {total} packets to {args.out} "
	      f"({args.mice} mouse flows, elephant-gap={args.elephant_gap})")


if __name__ == "__main__":
	main()
