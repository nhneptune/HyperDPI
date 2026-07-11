#!/usr/bin/env python3
"""Builds pcap/traffic.pcap covering the 3 mandatory scenarios from the spec
(HTTP DROP, HTTPS/SNI DROP, FORWARD) plus one extra case where a TLS
ClientHello is split across two TCP segments, to exercise the flow
reassembly path in parser.c."""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

MAC_CLIENT = "02:00:00:00:00:01"
MAC_SERVER = "02:00:00:00:00:02"


def build_http_request(host, path="/"):
	req = (f"GET {path} HTTP/1.1\r\n"
	       f"Host: {host}\r\n"
	       f"User-Agent: HyperDPI-Test\r\n"
	       f"Connection: close\r\n\r\n")
	return req.encode()


def build_client_hello(hostname):
	hostname_b = hostname.encode()
	server_name_entry = bytes([0x00]) + len(hostname_b).to_bytes(2, "big") + hostname_b
	server_name_list = len(server_name_entry).to_bytes(2, "big") + server_name_entry
	ext_server_name = (0x0000).to_bytes(2, "big") + len(server_name_list).to_bytes(2, "big") + server_name_list
	extensions_block = len(ext_server_name).to_bytes(2, "big") + ext_server_name

	client_version = bytes([0x03, 0x03])
	random_bytes = bytes(range(32))
	session_id = bytes([0x00])
	cipher_suites = (2).to_bytes(2, "big") + bytes([0x00, 0x2f])
	compression = bytes([0x01, 0x00])

	body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_block
	handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
	record = bytes([0x16, 0x03, 0x01]) + len(handshake).to_bytes(2, "big") + handshake
	return record


def build_client_hello_ech(public_name="cover.example"):
	"""An ECH-shaped ClientHello: structurally a valid TLS ClientHello (record
	type 0x16, handshake type 0x01, all length-prefixed fields internally
	consistent), but its extensions list omits ext_type 0x0000 (server_name)
	entirely -- matching how a real ECH ClientHello looks to a passive
	parser (the true SNI is encrypted inside the ECH extension payload; the
	outer ClientHello typically carries no plaintext server_name extension
	at all). Includes a placeholder ext_type 0xfe0d (encrypted_client_hello)
	extension -- not a real RFC 9180 HPKE payload, just self-consistent
	length-prefixed bytes, enough for the extension-walk in
	try_extract_tls_sni() to parse it as complete. See version_03.md."""
	public_name_b = public_name.encode()
	# Placeholder ECH extension body: config_id(1) + cipher_suite(4) +
	# enc_len(2)+enc(8, dummy) + payload_len(2)+payload (dummy, includes
	# public_name so the fixture is at least recognizable in a hex dump).
	enc = bytes(range(8))
	payload = public_name_b
	ech_body = (bytes([0xAB]) + bytes([0x00, 0x01, 0x00, 0x01]) +
		    len(enc).to_bytes(2, "big") + enc +
		    len(payload).to_bytes(2, "big") + payload)
	ext_ech = (0xfe0d).to_bytes(2, "big") + len(ech_body).to_bytes(2, "big") + ech_body

	# A second, unrelated extension (ALPN) so the extensions list isn't
	# trivially just one entry -- exercises the extension-walk loop.
	alpn_proto = b"\x02h2"
	alpn_list = len(alpn_proto).to_bytes(2, "big") + alpn_proto
	ext_alpn = (0x0010).to_bytes(2, "big") + len(alpn_list).to_bytes(2, "big") + alpn_list

	extensions_block = ext_alpn + ext_ech

	client_version = bytes([0x03, 0x03])
	random_bytes = bytes(range(32))
	session_id = bytes([0x00])
	cipher_suites = (2).to_bytes(2, "big") + bytes([0x00, 0x2f])
	compression = bytes([0x01, 0x00])
	ext_total = len(extensions_block).to_bytes(2, "big")

	body = (client_version + random_bytes + session_id + cipher_suites + compression +
		ext_total + extensions_block)
	handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
	record = bytes([0x16, 0x03, 0x01]) + len(handshake).to_bytes(2, "big") + handshake
	return record


def tcp_handshake(src_ip, dst_ip, sport, dport, init_seq=1000):
	"""SYN/SYN-ACK/ACK preamble shared by tcp_flow() and
	tcp_flow_with_seqs(). Returns (packets, next_client_seq) where
	next_client_seq is the sequence number of the first real data byte
	(init_seq + 1 -- the SYN itself consumes one sequence number)."""
	pkts = []
	seq = init_seq

	pkts.append(Ether(src=MAC_CLIENT, dst=MAC_SERVER) / IP(src=src_ip, dst=dst_ip) /
		    TCP(sport=sport, dport=dport, flags="S", seq=seq))
	seq += 1
	pkts.append(Ether(src=MAC_SERVER, dst=MAC_CLIENT) / IP(src=dst_ip, dst=src_ip) /
		    TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=seq))
	pkts.append(Ether(src=MAC_CLIENT, dst=MAC_SERVER) / IP(src=src_ip, dst=dst_ip) /
		    TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=5001))

	return pkts, seq


def tcp_flow(src_ip, dst_ip, sport, dport, segments):
	"""One packet per TCP segment (plus a minimal SYN/SYN-ACK/ACK handshake
	so the capture looks like a real connection), sequence numbers
	incrementing correctly across segments."""
	pkts, seq = tcp_handshake(src_ip, dst_ip, sport, dport)

	for seg in segments:
		pkts.append(Ether(src=MAC_CLIENT, dst=MAC_SERVER) / IP(src=src_ip, dst=dst_ip) /
			    TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=5001) / Raw(load=seg))
		seq += len(seg)

	return pkts


def tcp_flow_with_seqs(src_ip, dst_ip, sport, dport, seq_segments, base_seq=1000):
	"""Additive -- does not replace tcp_flow(). `seq_segments` is a list of
	(seq_offset, payload) tuples, seq_offset relative to the first real
	data byte (base_seq+1, after the SYN's phantom byte), emitted in LIST
	ORDER -- which may differ from sequence-number order. Lets callers
	build arbitrary overlap/out-of-order adversarial scenarios (see
	scripts/gen_adversarial_pcap.py)."""
	pkts, first_data_seq = tcp_handshake(src_ip, dst_ip, sport, dport, init_seq=base_seq)

	for seq_offset, payload in seq_segments:
		pkts.append(Ether(src=MAC_CLIENT, dst=MAC_SERVER) / IP(src=src_ip, dst=dst_ip) /
			    TCP(sport=sport, dport=dport, flags="PA",
				seq=first_data_seq + seq_offset, ack=5001) / Raw(load=payload))

	return pkts


def main():
	packets = []

	# Scenario 1: HTTP DROP -- Host matches "http://malware.com.*" (DROP rule)
	packets += tcp_flow("10.0.0.1", "93.184.216.1", 40001, 80,
			     [build_http_request("malware.com", "/evil")])

	# Scenario 2: HTTPS DROP -- SNI matches "HOST://bad-gambling.net.*" (DROP rule),
	# ClientHello fits in a single TCP segment
	packets += tcp_flow("10.0.0.2", "93.184.216.2", 40002, 443,
			     [build_client_hello("bad-gambling.net")])

	# Scenario 3: FORWARD -- no rule matches (default allow)
	packets += tcp_flow("10.0.0.3", "93.184.216.3", 40003, 80,
			     [build_http_request("example.com", "/")])

	# Scenario 4 (extra): same DROP-listed SNI as scenario 2, but the
	# ClientHello is split across two TCP segments to exercise reassembly.
	ch = build_client_hello("bad-gambling.net")
	mid = len(ch) // 2
	packets += tcp_flow("10.0.0.5", "93.184.216.5", 40005, 443,
			     [ch[:mid], ch[mid:]])

	wrpcap("pcap/traffic.pcap", packets)
	print(f"wrote {len(packets)} packets to pcap/traffic.pcap")


if __name__ == "__main__":
	main()
