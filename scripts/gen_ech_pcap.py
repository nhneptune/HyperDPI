#!/usr/bin/env python3
"""Builds pcap/ech.pcap: scenarios exercising the REASSEMBLY_NO_SNI path in
parser.c (see version_03.md for the full design writeup -- "Is Encrypted
ClientHello a Challenge for Traffic Classification?", IEEE 2022).

A separate fixture from pcap/traffic.pcap and pcap/adversarial.pcap on
purpose: those files' exact packet/counter totals are asserted elsewhere
(qa regression checks, version_01.md, version_02.md, README.md); adding
scenarios there would churn all of those.

Scenarios:

1. Single-segment ECH-shaped ClientHello (no server_name extension):
   expected REASSEMBLY_NO_SNI on the first data packet -> FORWARD,
   informational log line printed exactly once (verdict cached
   immediately, so a follow-up empty-payload ACK on the same flow must
   NOT re-trigger the LOG line). The counter, however, increments for
   BOTH packets (the triggering ClientHello and the follow-up ACK): it
   tracks every uninspected packet of a no-SNI flow, not just the one
   that produced the verdict (see *out_no_sni in parser_flow_update(),
   include/stats.h) -- this scenario contributes +2.

2. ECH-shaped ClientHello split across two TCP segments, in sequence
   order: the first half alone must stay PENDING (not prematurely
   NO_SNI/GIVE_UP -- this is the regression case for the tri-state fix in
   try_extract_tls_sni()); the second half completes it -> NO_SNI. Only
   the second (completing) segment is ever counted -- the first stayed
   genuinely PENDING, not no-SNI. Contributes +1.

3. Decoy-before-real (documented, accepted limitation -- see version_03.md
   "Known limitation: caching race"): a complete, self-contained ECH-shaped
   decoy ClientHello (no SNI) is placed at a TCP sequence position AFTER a
   real DROP-listed ClientHello (bad-gambling.net) but is emitted FIRST in
   arrival order. Because it is the first packet processed for the flow, it
   anchors the reassembly buffer's origin and completes/caches a FORWARD
   verdict before the real, earlier-sequence ClientHello ever arrives --
   the cached-verdict short-circuit in parser_flow_update() means the real
   segment is never even placed into the buffer, and instead takes the
   cheap REASSEMBLY_CACHED path (still counted, since the cached verdict
   is a no-SNI one). Expected: FORWARD (NOT DROP) for both packets of this
   flow. Contributes +2 (decoy + real_ch, both counted). This is a
   deliberate extension of the same "first wins" trade-off already
   documented and accepted for pcap/adversarial.pcap scenario 2
   (version_02.md) -- not a new bug, and not something this feature
   claims to close.

Total expected TLS_ECH_OR_NO_SNI counter across all 3 scenarios: 2+1+2 = 5
(verified against the real pipeline -- see version_03.md).
"""

from scapy.all import Ether, IP, TCP, wrpcap

from gen_pcap import (MAC_CLIENT, MAC_SERVER, build_client_hello, build_client_hello_ech,
		       tcp_flow_with_seqs)


def main():
	packets = []

	# Scenario 1: single-segment ECH ClientHello -> NO_SNI once, cached after.
	ech1 = build_client_hello_ech()
	packets += tcp_flow_with_seqs("10.0.2.1", "93.184.216.20", 42001, 443, [(0, ech1)])
	# Follow-up empty-payload ACK on the same flow -- must take the cached
	# path, not re-trigger the NO_SNI log line (but IS still counted, since
	# it's still an uninspected packet of a no-SNI flow -- see docstring).
	packets.append(Ether(src=MAC_CLIENT, dst=MAC_SERVER) / IP(src="10.0.2.1", dst="93.184.216.20") /
			TCP(sport=42001, dport=443, flags="A", seq=1001 + len(ech1), ack=5001))

	# Scenario 2: ECH ClientHello split across two in-order segments.
	ech2 = build_client_hello_ech()
	mid = len(ech2) // 2
	packets += tcp_flow_with_seqs("10.0.2.2", "93.184.216.21", 42002, 443,
				       [(0, ech2[:mid]), (mid, ech2[mid:])])

	# Scenario 3: decoy-before-real -- documented, accepted limitation.
	real_ch = build_client_hello("bad-gambling.net")
	decoy_ch = build_client_hello_ech()
	decoy_offset = len(real_ch) + 1000  # arbitrary gap, no byte overlap with real_ch
	packets += tcp_flow_with_seqs("10.0.2.3", "93.184.216.22", 42003, 443,
				       [(decoy_offset, decoy_ch), (0, real_ch)])

	wrpcap("pcap/ech.pcap", packets)
	print(f"wrote {len(packets)} packets to pcap/ech.pcap")
	print("Expected: scenario 1 NO_SNI (FORWARD, one log line, counter +2), "
	      "scenario 2 NO_SNI once completed (FORWARD, counter +1), "
	      "scenario 3 FORWARD (NOT DROP -- accepted limitation, counter +2). "
	      "Total TLS_ECH_OR_NO_SNI counter: 5.")


if __name__ == "__main__":
	main()
