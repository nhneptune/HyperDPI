#!/usr/bin/env python3
"""Builds pcap/adversarial.pcap: TCP segment overlap and out-of-order
arrival scenarios, to exercise the sequence-aware reassembly / "first
wins" overlap resolution in parser.c (see version_02.md for the full
design writeup -- Ptacek & Newsham 1998 insertion/evasion; PYROLYSE,
arXiv:2504.21618).

A separate fixture from pcap/traffic.pcap on purpose: that file's exact
packet/counter totals are asserted in several places already (qa
regression checks, version_01.md, README.md); adding scenarios there
would churn all of those.

Scenarios (all built with tcp_flow_with_seqs(), segments emitted in LIST
order which may differ from sequence-number order):

1. Overlap, malicious-first: two same-length HTTP requests at the same
   sequence offset, malware.com's request processed first. Expected:
   DROP -- "first wins" means the later, benign-looking overlap can't
   erase the already-recorded malicious Host.
2. Overlap, benign-first: same construction, order reversed. Expected:
   FORWARD -- the accepted Ptacek-Newsham-style limitation: whichever
   segment a real destination host (or here, HyperDPI) processes first
   determines the outcome, and no single policy is evasion-proof without
   knowing the real destination's own reassembly behavior.
3. Out-of-order: a DROP-listed TLS SNI's ClientHello split into two
   segments, second half emitted before the first half. Expected: DROP,
   identical to the in-order case -- a correctness property (reassembly
   must not depend on arrival order), not an evasion-resistance claim.
"""

from scapy.all import wrpcap

from gen_pcap import build_client_hello, build_http_request, tcp_flow_with_seqs


def main():
	packets = []

	# Scenario 1: overlap, malicious segment processed first -> DROP expected.
	mal = build_http_request("malware.com", "/evil")
	benign = build_http_request("example.com", "/evil")
	assert len(mal) == len(benign), "overlap scenarios require equal-length payloads"
	packets.extend(tcp_flow_with_seqs("10.0.1.1", "93.184.216.10", 41001, 80,
					   [(0, mal), (0, benign)]))

	# Scenario 2: overlap, benign segment processed first -> FORWARD expected
	# (documented limitation, not a bug -- see module docstring).
	packets.extend(tcp_flow_with_seqs("10.0.1.2", "93.184.216.11", 41002, 80,
					   [(0, benign), (0, mal)]))

	# Scenario 3: out-of-order arrival of a split, DROP-listed TLS ClientHello
	# -> DROP expected, same as if the segments had arrived in order.
	ch = build_client_hello("bad-gambling.net")
	mid = len(ch) // 2
	packets.extend(tcp_flow_with_seqs("10.0.1.3", "93.184.216.12", 41003, 443,
					   [(mid, ch[mid:]), (0, ch[:mid])]))

	wrpcap("pcap/adversarial.pcap", packets)
	print(f"wrote {len(packets)} packets to pcap/adversarial.pcap")
	print("Expected verdicts: scenario 1 DROP, scenario 2 FORWARD, scenario 3 DROP")


if __name__ == "__main__":
	main()
