#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import shutil
import argparse

CGROUP_PATH = "/sys/fs/cgroup/mycontainer"

# ---------------- Cgroup Setup ----------------
def cleanup_cgroup():
    """Remove cgroup after container stops."""
    try:
        if os.path.exists(CGROUP_PATH):
            shutil.rmtree(CGROUP_PATH)
            print(f"Cleaned up cgroup {CGROUP_PATH}")
    except Exception as e:
        print(f"Error cleaning up cgroup: {e}")

def setup_cgroup(cpu_max="100000 100000", memory_max="100M"):
    """Create and configure cgroup with CPU and memory limits."""
    try:
        os.makedirs(CGROUP_PATH, exist_ok=True)

        # CPU quota
        with open(f"{CGROUP_PATH}/cpu.max", "w") as f:
            f.write(cpu_max)

        # Memory limit
        with open(f"{CGROUP_PATH}/memory.max", "w") as f:
            f.write(memory_max)

        print(f"Cgroup {CGROUP_PATH} setup with CPU={cpu_max}, Memory={memory_max}")
    except Exception as e:
        print(f"Error setting up cgroup: {e}")

def add_to_cgroup(pid):
    """Add process to cgroup."""
    try:
        with open(f"{CGROUP_PATH}/cgroup.procs", "w") as f:
            f.write(str(pid))
        print(f"Added PID {pid} to {CGROUP_PATH}")
    except Exception as e:
        print(f"Error adding process to cgroup: {e}")

# ---------------- Telemetry with CPU% & Memory% ----------------
def read_stats():
    """
    Return current CPU and memory stats as a dict:
    - cpu_usage_usec: CPU time used in microseconds
    - memory_bytes: current memory usage
    - memory_percent: % of memory limit used
    """
    try:
        # Memory
        with open(f"{CGROUP_PATH}/memory.current") as f:
            mem_usage = int(f.read())
        with open(f"{CGROUP_PATH}/memory.max") as f:
            mem_limit_str = f.read().strip()
            if mem_limit_str.endswith("M"):
                mem_limit = int(mem_limit_str[:-1]) * 1024 * 1024
            elif mem_limit_str.endswith("G"):
                mem_limit = int(mem_limit_str[:-1]) * 1024 * 1024 * 1024
            else:
                mem_limit = int(mem_limit_str)
        mem_percent = (mem_usage / mem_limit) * 100 if mem_limit > 0 else 0

        # CPU
        with open(f"{CGROUP_PATH}/cpu.stat") as f:
            lines = f.readlines()
            usage_usec = 0
            for line in lines:
                if line.startswith("usage_usec"):
                    usage_usec = int(line.strip().split()[1])

        return {"cpu_usage_usec": usage_usec, "memory_bytes": mem_usage, "memory_percent": mem_percent}
    except Exception as e:
        print(f"Error reading stats: {e}")
        return {"cpu_usage_usec": 0, "memory_bytes": 0, "memory_percent": 0}

def telemetry_loop(interval=2, memory_scale_threshold=80, scale_to="200M"):
    """
    Monitor cgroup usage and dynamically scale memory.
    interval: seconds between measurements
    memory_scale_threshold: memory usage threshold in MB
    scale_to: memory limit after scaling
    """
    print(f"\n[Telemetry] Monitoring every {interval}s... (Press Ctrl+C to stop)")
    prev_cpu_usage = None
    try:
        while True:
            stats = read_stats()
            mem_mb = stats["memory_bytes"] / (1024*1024)
            mem_pct = stats["memory_percent"]

            # Compute CPU % of 1 core
            cpu_pct = 0
            if prev_cpu_usage is not None:
                cpu_delta_usec = stats["cpu_usage_usec"] - prev_cpu_usage
                cpu_pct = (cpu_delta_usec / (interval * 1_000_000)) * 100
            prev_cpu_usage = stats["cpu_usage_usec"]

            print(f"CPU Usage: {cpu_pct:.2f}% | Memory: {mem_mb:.2f} MB ({mem_pct:.1f}%)", end="\r")

            # Dynamic memory scaling
            if mem_mb > memory_scale_threshold:
                with open(f"{CGROUP_PATH}/memory.max", "w") as f:
                    f.write(scale_to)
                print(f"\n[Scaling] Memory scaled to {scale_to}")

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nTelemetry loop stopped.")

# ---------------- Container Runner ----------------
def run_container(command, interval=2):
    """Run process inside namespaces and apply cgroup limits."""
    setup_cgroup()
    proc = subprocess.Popen([
        "unshare",
        "--fork", "--pid", "--mount-proc",
        "--uts", "--mount", "--net",
        "bash", "-c", f"hostname container && {command}"
    ])

    add_to_cgroup(proc.pid)
    telemetry_loop(interval)
    proc.wait()
    cleanup_cgroup()

# ---------------- CLI Tool ----------------
def cli_stats(interval=2):
    """Standalone CLI to print current usage."""
    print(f"Showing live cgroup stats every {interval}s (Press Ctrl+C to exit)")
    prev_cpu_usage = None
    try:
        while True:
            stats = read_stats()
            mem_mb = stats["memory_bytes"] / (1024*1024)
            mem_pct = stats["memory_percent"]

            cpu_pct = 0
            if prev_cpu_usage is not None:
                cpu_delta_usec = stats["cpu_usage_usec"] - prev_cpu_usage
                cpu_pct = (cpu_delta_usec / (interval * 1_000_000)) * 100
            prev_cpu_usage = stats["cpu_usage_usec"]

            print(f"CPU Usage: {cpu_pct:.2f}% | Memory: {mem_mb:.2f} MB ({mem_pct:.1f}%)", end="\r")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nExiting CLI stats.")

# ---------------- Main ----------------
def main():
    parser = argparse.ArgumentParser(description="Container runtime with telemetry")
    parser.add_argument("command", nargs="*", help="Command to run inside container")
    parser.add_argument("--demo", action="store_true", help="Run demo stress-ng workload")
    parser.add_argument("--interval", type=int, default=2, help="Telemetry interval in seconds")
    parser.add_argument("--stats", action="store_true", help="Run standalone telemetry CLI")
    args = parser.parse_args()

    if args.stats:
        cli_stats(interval=args.interval)
        return

    if args.demo:
        run_container("stress-ng --cpu 1 --vm 1 --vm-bytes 50M --timeout 20", interval=args.interval)
    elif args.command:
        run_container(" ".join(args.command), interval=args.interval)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
