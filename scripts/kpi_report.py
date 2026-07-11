#!/usr/bin/env python3
"""Parses a HyperDPI stdout log (and optionally an RSS-sampling log) and
prints a KPI summary table suitable for screenshotting against the spec's
targets (throughput, PPS, memory stability)."""

import re
import sys

THROUGHPUT_MIN, THROUGHPUT_MAX = 400.0, 1000.0
PPS_MIN, PPS_MAX = 100_000, 500_000

STATS_RE = re.compile(
	r"Throughput:\s*([\d.]+)\s*Mbps\s*\|\s*PPS:\s*(\d+)\s*\|\s*Total RX packets:\s*(\d+)")
COUNTS_RE = re.compile(r"HTTP:\s*(\d+)\s*\|\s*HTTPS:\s*(\d+)\s*\|\s*Non-DPI:\s*(\d+)")
ACTIONS_RE = re.compile(r"Forwarded:\s*(\d+)\s*\|\s*Dropped:\s*(\d+)\s*\|\s*TX sent:\s*(\d+)")
RSS_RE = re.compile(r"RSS=(\d+)")


def main():
	if len(sys.argv) < 2:
		print(f"Usage: {sys.argv[0]} <hyperdpi_log_file> [rss_log_file]")
		sys.exit(1)

	log_path = sys.argv[1]
	rss_path = sys.argv[2] if len(sys.argv) > 2 else None

	samples = []
	last_counts = None
	last_actions = None
	saw_clean_exit = False

	with open(log_path) as f:
		for line in f:
			m = STATS_RE.search(line)
			if m:
				samples.append((float(m.group(1)), int(m.group(2)), int(m.group(3))))
				continue
			m = COUNTS_RE.search(line)
			if m:
				last_counts = tuple(int(x) for x in m.groups())
				continue
			m = ACTIONS_RE.search(line)
			if m:
				last_actions = tuple(int(x) for x in m.groups())
				continue
			if "exiting on lcore" in line:
				saw_clean_exit = True

	if not samples:
		print("No stats snapshots found in log -- did the program run long enough "
		      "(Stats thread prints every 1s)?")
		sys.exit(1)

	throughputs = [s[0] for s in samples]
	ppss = [s[1] for s in samples]
	duration_s = len(samples)  # one snapshot per second

	print("=" * 72)
	print("HyperDPI KPI Report")
	print("=" * 72)
	print(f"Log file             : {log_path}")
	print(f"Stats snapshots       : {len(samples)}  (~{duration_s}s of runtime, "
	      f"~{duration_s / 60:.1f} min)")
	print("-" * 72)
	print(f"{'Metric':<28}{'Min':>12}{'Avg':>12}{'Max':>12}")
	print(f"{'Throughput (Mbps)':<28}{min(throughputs):>12.2f}"
	      f"{sum(throughputs) / len(throughputs):>12.2f}{max(throughputs):>12.2f}")
	print(f"{'PPS':<28}{min(ppss):>12.0f}{sum(ppss) / len(ppss):>12.0f}{max(ppss):>12.0f}")
	print("-" * 72)
	print(f"KPI target Throughput : {THROUGHPUT_MIN}-{THROUGHPUT_MAX} Mbps -> "
	      f"{'PASS' if max(throughputs) >= THROUGHPUT_MIN else 'FAIL (below min)'}")
	print(f"KPI target PPS        : {PPS_MIN:,}-{PPS_MAX:,} -> "
	      f"{'PASS' if max(ppss) >= PPS_MIN else 'FAIL (below min)'}")
	print("-" * 72)

	if last_counts:
		http, https, non_dpi = last_counts
		print(f"Final classification  : HTTP={http:,}  HTTPS={https:,}  Non-DPI={non_dpi:,}")
	if last_actions:
		fwd, drop, tx = last_actions
		print(f"Final actions          : Forwarded={fwd:,}  Dropped={drop:,}  TX sent={tx:,}")
	print(f"Total RX (last sample): {samples[-1][2]:,}")
	print("-" * 72)
	shutdown_msg = "YES" if saw_clean_exit else 'NO (no "exiting on lcore" lines found)'
	print(f"Clean shutdown seen   : {shutdown_msg}")

	if rss_path:
		rss_values = []
		with open(rss_path) as f:
			for line in f:
				m = RSS_RE.search(line)
				if m:
					rss_values.append(int(m.group(1)))
		if rss_values:
			first, last = rss_values[0], rss_values[-1]
			delta = last - first
			stable = abs(delta) < max(first * 0.05, 1024)  # within 5% or 1MB
			print("-" * 72)
			print(f"Memory (RSS) samples   : {len(rss_values)}")
			print(f"First RSS / Last RSS   : {first:,} KB / {last:,} KB (delta {delta:+,} KB)")
			print(f"Memory stability        : {'PASS (stable)' if stable else 'CHECK (drifted)'}")
		else:
			print("No RSS samples found in rss log.")
	print("=" * 72)


if __name__ == "__main__":
	main()
