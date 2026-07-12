#!/usr/bin/env python3
"""Benchmarks HyperDPI's steady-state Throughput/PPS/CPU% across worker
counts (-w 2/3/4), for report_template.md §III.3. Method matches what that
section already prescribes: infinite_rx=1 (no tx_pcap), wait for every
worker's "started on lcore" line, run a warm-up period before sampling to
skip the startup transient, get Throughput/PPS from stats_thread_main's
printed lines (same regex as kpi_report.py), get CPU% externally via two
/proc/<pid>/stat reads (utime+stime, cols 14+15) using `pgrep -x hyperdpi`
for the PID (not `pgrep -f` -- see CLAUDE.md's documented gotcha: that also
matches the wrapping sudo/stdbuf processes).

Must run from the repo root (writes to logs/, assets/, and reads
pcap/traffic.pcap / config/patterns.txt via relative paths). Needs sudo
(prompts interactively unless SUDO_PASSWORD is set in the environment) and
DPDK hugepages already configured (see CLAUDE.md).

Usage:
  python3 scripts/bench_workers.py                    # full run (60s warmup, 30s sample)
  python3 scripts/bench_workers.py --warmup 5 --sample 5   # fast smoke test
  python3 scripts/bench_workers.py --plot-only         # regenerate charts from an existing summary
"""

import argparse
import getpass
import json
import os
import re
import shlex
import subprocess
import sys
import time

from kpi_report import STATS_RE

WORKERS = [2, 3, 4]
CLK_TCK = os.sysconf("SC_CLK_TCK")
STARTED_RE = re.compile(r"\[Worker (\d+)\] started on lcore")
EXITING_RE = re.compile(r"exiting on lcore")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sudo_run(cmd, password, check=True):
	"""Runs `cmd` (a list) under sudo -S, feeding the password on stdin."""
	full = ["sudo", "-S", "-p", ""] + cmd
	return subprocess.run(full, input=password + "\n", text=True, capture_output=True,
			       check=check, cwd=REPO_ROOT)


def wait_for(predicate, timeout_s, interval_s=0.5):
	deadline = time.monotonic() + timeout_s
	while time.monotonic() < deadline:
		if predicate():
			return True
		time.sleep(interval_s)
	return predicate()


def hyperdpi_pid():
	r = subprocess.run(["pgrep", "-x", "hyperdpi"], capture_output=True, text=True)
	pids = [int(p) for p in r.stdout.split()]
	if len(pids) > 1:
		raise RuntimeError(f"multiple hyperdpi processes found ({pids}) -- a previous run "
				    f"was not cleaned up; kill them manually before re-running")
	return pids[0] if pids else None


def build_eal_lcore_args(total_lcores):
	"""Prefers plain -l when enough distinct CPUs actually exist; only falls
	back to --lcores oversubscription (per CLAUDE.md's documented pattern)
	when the box doesn't have total_lcores physical CPUs. Hardcoding the
	oversubscription affinity set to a fixed range would both throttle CPU%
	measurements on boxes with more CPUs available and fail outright on a
	box with fewer than 4 (CPU count on this dev VM is documented to vary
	across resizes)."""
	nproc = os.cpu_count() or 1
	if nproc >= total_lcores:
		return f"-l 0-{total_lcores - 1}"
	return f"--lcores '(0-{total_lcores - 1})@(0-{nproc - 1})'"


def read_utime_stime(pid):
	with open(f"/proc/{pid}/stat") as f:
		fields = f.read().split()
	# fields[1] is "(comm)" which may itself contain spaces -- utime/stime are
	# always the 14th/15th whitespace-separated fields counting from the end
	# of the ")"-terminated comm field, so split on ")" instead of relying on
	# a fixed field index.
	line = " ".join(fields)
	after_comm = line.split(")", 1)[1].split()
	utime, stime = int(after_comm[11]), int(after_comm[12])  # utime=14th,stime=15th overall
	return utime + stime


def sample_cpu_percent(pid, duration_s):
	"""Takes 1s-interval utime+stime readings for duration_s seconds and
	returns the average CPU% across all consecutive-pair intervals."""
	readings = []
	t_prev = time.monotonic()
	ticks_prev = read_utime_stime(pid)
	readings_count = max(1, duration_s)
	for _ in range(readings_count):
		time.sleep(1)
		t_now = time.monotonic()
		ticks_now = read_utime_stime(pid)
		dt = t_now - t_prev
		d_ticks = ticks_now - ticks_prev
		pct = (d_ticks / CLK_TCK) / dt * 100 if dt > 0 else 0.0
		readings.append(pct)
		t_prev, ticks_prev = t_now, ticks_now
	return sum(readings) / len(readings) if readings else 0.0


def run_one(worker_count, warmup_s, sample_s, password):
	existing = hyperdpi_pid()
	if existing is not None:
		raise RuntimeError(f"W={worker_count}: a hyperdpi process (pid {existing}) is already "
				    f"running before this benchmark could start -- investigate/kill "
				    f"it manually first")

	total_lcores = worker_count + 4
	eal_args = build_eal_lcore_args(total_lcores)
	log_path = os.path.join(REPO_ROOT, "logs", f"bench_w{worker_count}.log")
	os.makedirs(os.path.dirname(log_path), exist_ok=True)

	# stdbuf -oL -eL: matches the launch pattern already established in
	# README.md/version_01.md -- without it, hyperdpi's stdout is fully
	# buffered (not a TTY), so the "started on lcore"/"exiting on lcore"
	# lines this script polls for would only appear once something else
	# happens to flush (relying on the target binary's own internal flush
	# cadence rather than guaranteeing line-buffered output ourselves).
	launch_cmd = (
		f"nohup stdbuf -oL -eL ./hyperdpi {eal_args} -n 4 "
		f"--vdev=net_pcap0,rx_pcap=pcap/traffic.pcap,infinite_rx=1 "
		f"-- -p config/patterns.txt -w {worker_count} "
		f"> {shlex.quote(log_path)} 2>&1 &"
	)

	def all_workers_started():
		if not os.path.exists(log_path):
			return False
		with open(log_path) as f:
			seen = {int(m.group(1)) for m in STARTED_RE.finditer(f.read())}
		return len(seen) >= worker_count

	def exited_cleanly():
		if not os.path.exists(log_path):
			return False
		with open(log_path) as f:
			text = f.read()
		return len(EXITING_RE.findall(text)) >= (worker_count + 3)

	print(f"[bench] W={worker_count}: launching ({eal_args}) -> {log_path}")
	launch_result = sudo_run(["bash", "-c", launch_cmd], password, check=False)
	if launch_result.returncode != 0:
		raise RuntimeError(f"W={worker_count}: failed to launch hyperdpi: "
				    f"{(launch_result.stderr or launch_result.stdout).strip()}")

	# From here on a real process may be running -- guarantee we always try
	# to stop it, even if something below raises (e.g. startup timeout,
	# missing pid, a crash mid-sample). Without this, a failed run leaks an
	# infinite_rx=1 hyperdpi process that never exits on its own, silently
	# corrupting every subsequent worker-count's measurements (either via
	# hyperdpi_pid()'s multi-pid detection aborting them, or worse, a stale
	# fd still writing into an old log file).
	cpu_avg = None
	try:
		if not wait_for(all_workers_started, timeout_s=60):
			raise RuntimeError(f"W={worker_count}: workers did not all start within "
					    f"60s -- check {log_path}")
		print(f"[bench] W={worker_count}: all {worker_count} workers started, "
		      f"warming up {warmup_s}s")
		time.sleep(warmup_s)

		pid = hyperdpi_pid()
		if pid is None:
			raise RuntimeError(f"W={worker_count}: hyperdpi process not found after warmup")

		print(f"[bench] W={worker_count}: sampling CPU% for {sample_s}s (pid {pid})")
		cpu_avg = sample_cpu_percent(pid, sample_s)
	finally:
		print(f"[bench] W={worker_count}: stopping")
		sudo_run(["bash", "-c", "kill -TERM $(pgrep -x hyperdpi) 2>/dev/null"], password,
			  check=False)
		clean = wait_for(exited_cleanly, timeout_s=15)
		gone = wait_for(lambda: hyperdpi_pid() is None, timeout_s=10)
		if not gone:
			print(f"[bench] W={worker_count}: WARNING -- hyperdpi still running after "
			      f"SIGTERM+10s wait, sending SIGKILL", file=sys.stderr)
			sudo_run(["bash", "-c", "kill -KILL $(pgrep -x hyperdpi) 2>/dev/null"],
				  password, check=False)
			wait_for(lambda: hyperdpi_pid() is None, timeout_s=10)
		if not clean:
			print(f"[bench] W={worker_count}: WARNING -- did not observe a full clean "
			      f"shutdown in {log_path}", file=sys.stderr)

	with open(log_path) as f:
		samples = [(float(m.group(1)), int(m.group(2))) for m in STATS_RE.finditer(f.read())]
	if len(samples) <= warmup_s:
		raise RuntimeError(f"W={worker_count}: only {len(samples)} stats samples captured, "
				    f"not enough to skip a {warmup_s}s warm-up window")
	# Index-based slice: assumes ~1 stats sample/sec starting near process
	# launch (Stats thread prints every 1s, see src/stats.c) rather than
	# correlating by wall-clock timestamp -- approximate, not exact, but the
	# default 60s/30s windows leave ample margin for the small jitter this
	# can introduce (Stats thread sleeps in 100ms slices, not a precise 1Hz
	# timer).
	steady = samples[warmup_s:warmup_s + sample_s]
	if not steady:
		raise RuntimeError(f"W={worker_count}: steady-state window produced 0 samples "
				    f"(--sample must be >= 1)")

	throughputs = [s[0] for s in steady]
	ppss = [s[1] for s in steady]
	return {
		"workers": worker_count,
		"throughput_min": min(throughputs),
		"throughput_avg": sum(throughputs) / len(throughputs),
		"throughput_max": max(throughputs),
		"pps_min": min(ppss),
		"pps_avg": sum(ppss) / len(ppss),
		"pps_max": max(ppss),
		"cpu_avg": cpu_avg,
		"clean_shutdown": clean,
	}


def plot_summary(summary, outdir):
	import matplotlib
	matplotlib.use("Agg")
	import matplotlib.pyplot as plt

	os.makedirs(outdir, exist_ok=True)
	BLUE = "#2a78d6"
	TEXT_PRIMARY = "#0b0b0b"
	TEXT_SECONDARY = "#52514e"
	SURFACE = "#fcfcfb"

	workers = [s["workers"] for s in summary]
	charts = [
		("throughput_avg", "Throughput trung bình (Mbps)", "bench_throughput.png", "{:.0f}"),
		("pps_avg", "PPS trung bình", "bench_pps.png", "{:,.0f}"),
		("cpu_avg", "CPU trung bình (%)", "bench_cpu.png", "{:.0f}%"),
	]

	for key, title, filename, fmt in charts:
		values = [s[key] for s in summary]
		fig, ax = plt.subplots(figsize=(5, 3.5), dpi=150, facecolor=SURFACE)
		ax.set_facecolor(SURFACE)
		bars = ax.bar([str(w) for w in workers], values, color=BLUE, width=0.5,
			      edgecolor="none", zorder=3)
		for spine in ("top", "right", "left"):
			ax.spines[spine].set_visible(False)
		ax.spines["bottom"].set_color(TEXT_SECONDARY)
		ax.tick_params(colors=TEXT_SECONDARY)
		ax.yaxis.grid(True, color="#e5e4df", zorder=0)
		ax.set_axisbelow(True)
		ax.set_xlabel("Số Worker (-w)", color=TEXT_SECONDARY)
		ax.set_title(title, color=TEXT_PRIMARY, fontsize=11, pad=12)
		ymax = max(values) if values else 1
		ax.set_ylim(0, ymax * 1.18 if ymax > 0 else 1)
		for bar, v in zip(bars, values):
			ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + ymax * 0.03,
				fmt.format(v), ha="center", va="bottom", color=TEXT_PRIMARY, fontsize=9)
		fig.tight_layout()
		out_path = os.path.join(outdir, filename)
		fig.savefig(out_path)
		plt.close(fig)
		print(f"[bench] wrote {out_path}")


def main():
	ap = argparse.ArgumentParser()
	ap.add_argument("--warmup", type=int, default=60, help="warm-up seconds before sampling")
	ap.add_argument("--sample", type=int, default=30, help="steady-state sampling window seconds")
	ap.add_argument("--plot-only", action="store_true",
			 help="skip running, just regenerate charts from logs/bench_summary.json")
	args = ap.parse_args()
	if args.warmup < 0 or args.sample < 1:
		ap.error("--warmup must be >= 0 and --sample must be >= 1")

	summary_path = os.path.join(REPO_ROOT, "logs", "bench_summary.json")

	if args.plot_only:
		with open(summary_path) as f:
			summary = json.load(f)
	else:
		password = os.environ.get("SUDO_PASSWORD")
		if password is None:
			password = getpass.getpass("sudo password: ")
		summary = []
		for w in WORKERS:
			try:
				result = run_one(w, args.warmup, args.sample, password)
			except Exception as e:
				print(f"[bench] W={w}: FAILED -- {e}", file=sys.stderr)
				continue
			summary.append(result)
			print(f"[bench] W={w}: throughput avg={result['throughput_avg']:.0f} Mbps, "
			      f"pps avg={result['pps_avg']:.0f}, cpu avg={result['cpu_avg']:.1f}%, "
			      f"clean_shutdown={result['clean_shutdown']}")
			# Persist after every successful run, not just at the end -- a
			# later worker count failing shouldn't discard already-collected
			# results.
			with open(summary_path, "w") as f:
				json.dump(summary, f, indent=2)
			print(f"[bench] wrote {summary_path} (after W={w})")

		if not summary:
			print("[bench] no successful runs -- nothing to summarize/plot", file=sys.stderr)
			sys.exit(1)

	print()
	print(f"{'Worker':<8}{'Thr min':>10}{'Thr avg':>10}{'Thr max':>10}"
	      f"{'PPS min':>12}{'PPS avg':>12}{'PPS max':>12}{'CPU avg%':>10}")
	for s in summary:
		print(f"{s['workers']:<8}{s['throughput_min']:>10.0f}{s['throughput_avg']:>10.0f}"
		      f"{s['throughput_max']:>10.0f}{s['pps_min']:>12.0f}{s['pps_avg']:>12.0f}"
		      f"{s['pps_max']:>12.0f}{s['cpu_avg']:>10.1f}")

	plot_summary(summary, os.path.join(REPO_ROOT, "assets"))


if __name__ == "__main__":
	main()
