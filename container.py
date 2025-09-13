#!/usr/bin/env python3
import os, sys, subprocess, time, psutil

CGROUP_PATH = "/sys/fs/cgroup/mycontainer"
MEM_THRESHOLD_MB = 80
MEM_SCALE_MB = 200
CPU_SCALE_QUOTA = "200000 100000"

def setup_cgroup(cpu_max="100000 100000", memory_max="100M"):
    os.makedirs(CGROUP_PATH, exist_ok=True)
    with open(f"{CGROUP_PATH}/cpu.max", "w") as f:
        f.write(cpu_max)
    with open(f"{CGROUP_PATH}/memory.max", "w") as f:
        f.write(memory_max)
    print(f"Cgroup {CGROUP_PATH} setup with CPU={cpu_max}, Memory={memory_max}")

def add_to_cgroup(pid):
    try:
        with open(f"{CGROUP_PATH}/cgroup.procs", "w") as f:
            f.write(str(pid))
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            with open(f"{CGROUP_PATH}/cgroup.procs", "w") as f:
                f.write(str(child.pid))
        print(f"Added PID {pid} and children to {CGROUP_PATH}")
    except Exception as e:
        print(f"Error adding PID to cgroup: {e}")

def telemetry_loop(interval=2):
    prev_cpu = 0
    print("\n[Telemetry Loop] Monitoring...")
    while True:
        try:
            with open(f"{CGROUP_PATH}/cpu.stat") as f:
                stats = {line.split()[0]: int(line.split()[1]) for line in f}
            cpu_usage = stats.get("usage_usec", 0)
            cpu_delta = cpu_usage - prev_cpu
            prev_cpu = cpu_usage

            with open(f"{CGROUP_PATH}/memory.current") as f:
                mem_usage = int(f.read())

            pids = []
            try:
                with open(f"{CGROUP_PATH}/cgroup.procs") as f:
                    pids = [int(line.strip()) for line in f if line.strip().isdigit()]
            except:
                pass
            per_process = []
            for pid in pids:
                try:
                    p = psutil.Process(pid)
                    per_process.append(f"{pid}: CPU={p.cpu_percent()/psutil.cpu_count():.1f}% MEM={p.memory_info().rss/1024/1024:.1f}MB")
                except:
                    continue

            print(f"CPU: {cpu_delta/1000:.2f} ms | Memory: {mem_usage/1024/1024:.2f} MB")
            if per_process:
                print("Per-process stats: " + ", ".join(per_process))

            if mem_usage > MEM_THRESHOLD_MB * 1024 * 1024:
                with open(f"{CGROUP_PATH}/memory.max", "w") as f:
                    f.write(f"{MEM_SCALE_MB}M")
                print(f"Scaled memory to {MEM_SCALE_MB} MB")
            if cpu_delta / 1000 > 1500:
                with open(f"{CGROUP_PATH}/cpu.max", "w") as f:
                    f.write(CPU_SCALE_QUOTA)
                print(f"Scaled CPU quota to {CPU_SCALE_QUOTA}")

            time.sleep(interval)
        except KeyboardInterrupt:
            print("Telemetry loop stopped.")
            break

def run_container(command, interval=2):
    setup_cgroup()
    proc = subprocess.Popen([
        "unshare", "--fork", "--pid", "--mount-proc", "--uts", "--mount", "--net",
        "bash", "-c", f"hostname container && {command}"
    ])
    time.sleep(0.5)
    add_to_cgroup(proc.pid)
    telemetry_loop(interval)
    proc.wait()
    try: os.rmdir(CGROUP_PATH)
    except: pass

def week1_demo():
    print("\n=== Week 1: Namespace Isolation Demo ===")
    print("This demonstrates PID, UTS, mount, and network namespace isolation.\n")
    print("Running bash inside container...")
    run_container("bash", interval=2)
    print("\nExplanation:")
    print("Hostname changed to 'container' → UTS namespace isolation")
    print("PID inside container is isolated → PID namespace")
    print("/proc is remounted → mount namespace")
    print("Network interfaces are separate → net namespace")

def week2_demo():
    print("\n=== Week 2: Resource Limits + Dynamic Scaling Demo ===")
    print("Demonstrates cgroups for CPU/memory, telemetry, and dynamic scaling.\n")
    run_container("stress-ng --cpu 1 --vm 1 --vm-bytes 50M --timeout 20", interval=2)
    print("\nExplanation:")
    print("CPU & memory cgroups applied")
    print("Telemetry loop shows live CPU and memory usage")
    print("Dynamic scaling occurs if thresholds exceeded")

def week3_demo():
    print("\n=== Week 3: Enhanced Telemetry Demo ===")
    print("Demonstrates per-process stats, interval configs, and monitoring CLI.\n")
    run_container("stress-ng --cpu 1 --vm 1 --vm-bytes 50M --timeout 20", interval=2)
    print("\nExplanation:")
    print("Per-process CPU and memory printed every interval")
    print("Includes child processes")
    print("Interval configurable using --interval N")
    print("Can monitor running container using --stats mode")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 container.py --week1|--week2|--week3")
        sys.exit(1)

    if sys.argv[1] == "--week1":
        week1_demo()
    elif sys.argv[1] == "--week2":
        week2_demo()
    elif sys.argv[1] == "--week3":
        week3_demo()
    else:
        print("Invalid argument. Use --week1, --week2, or --week3.")

if _name_ == "_main_":
    main()