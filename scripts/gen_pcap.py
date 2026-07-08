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


def tcp_flow(src_ip, dst_ip, sport, dport, segments):
	"""One packet per TCP segment (plus a minimal SYN/SYN-ACK/ACK handshake
	so the capture looks like a real connection), sequence numbers
	incrementing correctly across segments."""
	pkts = []
	seq = 1000

	pkts.append(Ether(src=MAC_CLIENT, dst=MAC_SERVER) / IP(src=src_ip, dst=dst_ip) /
		    TCP(sport=sport, dport=dport, flags="S", seq=seq))
	seq += 1
	pkts.append(Ether(src=MAC_SERVER, dst=MAC_CLIENT) / IP(src=dst_ip, dst=src_ip) /
		    TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=seq))
	pkts.append(Ether(src=MAC_CLIENT, dst=MAC_SERVER) / IP(src=src_ip, dst=dst_ip) /
		    TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=5001))

	for seg in segments:
		pkts.append(Ether(src=MAC_CLIENT, dst=MAC_SERVER) / IP(src=src_ip, dst=dst_ip) /
			    TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=5001) / Raw(load=seg))
		seq += len(seg)

	return pkts


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
