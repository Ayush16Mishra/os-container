#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import shutil
CGROUP_PATH = "/sys/fs/cgroup/mycontainer"

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

        # Set CPU quota (period=100000, quota=100000 → 100% of 1 core)
        with open(f"{CGROUP_PATH}/cpu.max", "w") as f:
            f.write(cpu_max)

        # Set memory limit
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

def telemetry_loop():
    """Monitor usage and dynamically scale resources."""
    print("\n[Telemetry Loop] Monitoring...")
    while True:
        try:
            # Read CPU stats
            with open(f"{CGROUP_PATH}/cpu.stat") as f:
                cpu_stats = f.read()

            # Read memory usage
            with open(f"{CGROUP_PATH}/memory.current") as f:
                mem_usage = int(f.read())

            print(f"CPU: {cpu_stats.strip()} | Memory: {mem_usage / (1024*1024):.2f} MB")

            # Dynamic scaling: if memory > 80 MB, increase limit
            if mem_usage > 80 * 1024 * 1024:
                with open(f"{CGROUP_PATH}/memory.max", "w") as f:
                    f.write("200M")
                print("Scaled memory to 200M")

            time.sleep(2)
        except KeyboardInterrupt:
            print("Telemetry loop stopped.")
            break

def run_container(command):
    """Run process inside namespaces and apply cgroup limits."""
    setup_cgroup()

    # Launch container process
    proc = subprocess.Popen([
        "unshare",
        "--fork", "--pid", "--mount-proc",
        "--uts", "--mount", "--net",
        "bash", "-c", f"hostname container && {command}"
    ])

    # Attach to cgroup
    add_to_cgroup(proc.pid)

    # Start telemetry
    telemetry_loop()

    proc.wait()
    cleanup_cgroup()

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 container.py <command>")
        print("  python3 container.py --demo")
        sys.exit(1)

    if sys.argv[1] == "--demo":
        run_container("stress-ng --cpu 1 --vm 1 --vm-bytes 50M --timeout 20")
    else:
        command = " ".join(sys.argv[1:])
        run_container(command)

if __name__ == "__main__":
    main()
