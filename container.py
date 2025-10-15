#!/usr/bin/env python3
"""
container_runtime.py
---------------------
Mini container runtime using Linux namespaces + cgroups v2.

Implements:
- Container isolation (PID, UTS, Mount, Network namespaces)
- Per-container cgroups for CPU/memory limits
- Dynamic scaling policies (CPU/memory)
- YAML configuration & structured JSON logging
- Optional shared/isolated network modes
- Metrics recorded to CSV
- Basic curses dashboard (fallback to console)
- Graceful cleanup, zombie reaping, and demo runner

Usage examples:
---------------
sudo ./container_runtime.py run --cmd "python3 myscript.py" --mem 200M --cpu "200000 100000"
sudo ./container_runtime.py list
sudo ./container_runtime.py kill --id <cid>
sudo ./container_runtime.py dashboard
sudo ./container_runtime.py demo
"""

import os, sys, time, json, yaml, csv, signal, subprocess, threading, logging, shutil, uuid
from pathlib import Path
from collections import defaultdict

try:
    import psutil
except ImportError:
    psutil = None
try:
    import curses
    HAS_CURSES = True
except ImportError:
    HAS_CURSES = False

LOG = logging.getLogger("runtime")
LOG.setLevel(logging.INFO)
LOG.addHandler(logging.StreamHandler(sys.stdout))

# ---------------------------
# Config & Globals
# ---------------------------
DEFAULT_CONFIG = {
    "thresholds": {
        "mem_up_mb": 200,
        "mem_down_mb": 100,
        "mem_trigger_up_mb": 80,
        "mem_trigger_down_mb": 40,
        "cpu_up_ms": 1500,
        "cpu_down_ms": 500,
        "cpu_scale_up": "200000 100000",
        "cpu_scale_down": "100000 100000",
    },
    "general": {
        "telemetry_interval": 2,
        "cooldown_secs": 5,
        "record_metrics": True,
        "metrics_dir": "/tmp/container_metrics",
        "cgroup_base": "/sys/fs/cgroup",
    }
}

containers = {}
containers_lock = threading.Lock()

# ---------------------------
# Helpers
# ---------------------------
def structured_log(event, cid=None, **kwargs):
    payload = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": event}
    if cid: payload["cid"] = cid
    payload.update(kwargs)
    LOG.info(json.dumps(payload))

def ensure_dir(p): os.makedirs(p, exist_ok=True)

def cgroup_path(cid, cfg): return os.path.join(cfg["general"]["cgroup_base"], f"mycontainer-{cid}")

def load_config(path="config.yaml"):
    cfg = DEFAULT_CONFIG.copy()
    if Path(path).exists():
        try:
            with open(path) as f:
                user = yaml.safe_load(f) or {}
            cfg["thresholds"].update(user.get("thresholds", {}))
            cfg["general"].update(user.get("general", {}))
            structured_log("config_loaded", path=path)
        except Exception as e:
            structured_log("config_error", error=str(e))
    else:
        structured_log("config_default", msg="using defaults")
    return cfg

# ---------------------------
# CGROUPS
# ---------------------------
def setup_cgroup(cid, cfg, cpu="100000 100000", mem="100M"):
    path = cgroup_path(cid, cfg)
    ensure_dir(path)
    try:
        with open(os.path.join(path, "cpu.max"), "w") as f: f.write(cpu)
        with open(os.path.join(path, "memory.max"), "w") as f: f.write(mem)
        structured_log("cgroup_created", cid, cpu=cpu, mem=mem)
    except Exception as e:
        structured_log("cgroup_error", cid, error=str(e))
    return path

def add_pid_to_cgroup(cid, pid, cfg):
    try:
        path = cgroup_path(cid, cfg)
        with open(os.path.join(path, "cgroup.procs"), "w") as f: f.write(str(pid))
        if psutil:
            for ch in psutil.Process(pid).children(recursive=True):
                with open(os.path.join(path, "cgroup.procs"), "w") as f: f.write(str(ch.pid))
    except Exception as e:
        structured_log("cgroup_add_error", cid, error=str(e))

def remove_cgroup(path, cid):
    try:
        if os.path.exists(path): shutil.rmtree(path)
    except Exception as e:
        structured_log("cgroup_remove_error", cid, error=str(e))

# ---------------------------
# TELEMETRY
# ---------------------------
def read_stats(path):
    cpu, mem = 0, 0
    try:
        with open(os.path.join(path, "cpu.stat")) as f:
            for line in f:
                k, v = line.split()
                if k == "usage_usec": cpu = int(v)
        with open(os.path.join(path, "memory.current")) as f:
            mem = int(f.read().strip())
    except: pass
    return cpu, mem

def telemetry(cid, cfg):
    t = cfg["general"]["telemetry_interval"]
    thresh, path = cfg["thresholds"], cgroup_path(cid, cfg)
    prev_cpu, peak_cpu, peak_mem = None, 0, 0
    cooldown = cfg["general"]["cooldown_secs"]
    last_scale = 0
    metrics_dir = cfg["general"]["metrics_dir"]
    ensure_dir(metrics_dir)
    file = os.path.join(metrics_dir, f"{cid}.csv")

    with open(file, "w", newline="") as f:
        csv.writer(f).writerow(["time", "cpu_ms", "mem_mb", "cpu.max", "mem.max"])

    while True:
        with containers_lock:
            info = containers.get(cid)
            if not info or info["stop_event"].is_set():
                break
        cpu, mem = read_stats(path)
        delta = 0 if prev_cpu is None else max(0, cpu - prev_cpu)
        prev_cpu = cpu
        cpu_ms = delta / 1000.0
        mem_mb = mem / (1024 * 1024)
        peak_cpu, peak_mem = max(peak_cpu, cpu_ms), max(peak_mem, mem_mb)

        structured_log("telemetry", cid, cpu_ms=cpu_ms, mem_mb=mem_mb)
        with open(file, "a", newline="") as f:
            csv.writer(f).writerow([time.strftime("%H:%M:%S"), f"{cpu_ms:.3f}", f"{mem_mb:.3f}"])

        now = time.time()
        if now - last_scale >= cooldown:
            try:
                if mem_mb > thresh["mem_trigger_up_mb"]:
                    with open(os.path.join(path, "memory.max"), "w") as f: f.write(f"{thresh['mem_up_mb']}M")
                elif mem_mb < thresh["mem_trigger_down_mb"]:
                    with open(os.path.join(path, "memory.max"), "w") as f: f.write(f"{thresh['mem_down_mb']}M")
                if cpu_ms > thresh["cpu_up_ms"]:
                    with open(os.path.join(path, "cpu.max"), "w") as f: f.write(thresh["cpu_scale_up"])
                elif cpu_ms < thresh["cpu_down_ms"]:
                    with open(os.path.join(path, "cpu.max"), "w") as f: f.write(thresh["cpu_scale_down"])
                last_scale = now
            except: pass
        time.sleep(t)
    containers[cid]["peaks"] = (peak_cpu, peak_mem)
    structured_log("telemetry_end", cid, peak_cpu=peak_cpu, peak_mem=peak_mem)

# ---------------------------
# LIFECYCLE
# ---------------------------
def run_container(cmd, cfg, cpu, mem, net_mode):
    cid = uuid.uuid4().hex[:6]
    cpath = setup_cgroup(cid, cfg, cpu, mem)
    stop_event = threading.Event()
    net_flag = [] if net_mode == "shared" else ["--net"]
    unshare = ["unshare", "--fork", "--pid", "--mount-proc", "--uts", "--mount"] + net_flag + \
               ["bash", "-c", f"hostname {cid} && {cmd}"]

    try:
        proc = subprocess.Popen(unshare)    
    except Exception as e:
        structured_log("launch_error", cid, error=str(e))
        return None

    add_pid_to_cgroup(cid, proc.pid, cfg)
    entry = {"pid": proc, "cmd": cmd, "start_time": time.time(), "stop_event": stop_event,
             "cgroup": cpath, "peaks": (0, 0)}
    with containers_lock:
        containers[cid] = entry

    threading.Thread(target=telemetry, args=(cid, cfg), daemon=True).start()
    structured_log("started", cid, pid=proc.pid, net=net_mode)
    return cid

def list_containers():
    print(f"{'CID':8} {'PID':6} {'STATUS':9} {'UPTIME':8} {'CPUms':8} {'MEMMB':8} CMD")
    with containers_lock:
        for cid, i in containers.items():
            status = "running" if i["pid"].poll() is None else "stopped"
            up = int(time.time() - i["start_time"])
            pc, pm = i["peaks"]
            print(f"{cid:8} {i['pid'].pid:<6} {status:<9} {up:<8} {pc:<8.1f} {pm:<8.1f} {i['cmd']}")

def kill_container(cid):
    with containers_lock:
        info = containers.get(cid)
        if not info: print("No such container"); return
    info["stop_event"].set()
    try:
        if info["pid"].poll() is None:
            info["pid"].terminate(); info["pid"].wait(timeout=3)
    except: info["pid"].kill()
    remove_cgroup(info["cgroup"], cid)
    with containers_lock: del containers[cid]
    structured_log("killed", cid)

# ---------------------------
# DASHBOARD
# ---------------------------
def dashboard(cfg):
    def _draw(stdscr):
        curses.curs_set(0)
        while True:
            stdscr.erase()
            stdscr.addstr(0, 0, "Mini Container Dashboard (q to quit)")
            r = 2
            with containers_lock:
                for cid, i in containers.items():
                    status = "running" if i["pid"].poll() is None else "stopped"
                    pc, pm = i["peaks"]
                    stdscr.addstr(r, 0, f"{cid} | {status} | CPU:{pc:.2f} | MEM:{pm:.2f} | {i['cmd']}")
                    r += 1
            stdscr.refresh()
            if stdscr.getch() == ord("q"): break
            time.sleep(cfg["general"]["telemetry_interval"])
    if HAS_CURSES:
        curses.wrapper(_draw)
    else:
        while True:
            os.system("clear")
            list_containers()
            print("\n(q) to quit")
            if input().strip().lower() == "q": break

# ---------------------------
# DEMO
# ---------------------------
def demo(cfg):
    structured_log("demo_start")
    cmds = [
        "stress-ng --cpu 1 --timeout 5",
        "stress-ng --vm 1 --vm-bytes 100M --timeout 5"
    ]
    ids = [run_container(c, cfg, "100000 100000", "100M", "isolated") for c in cmds]
    time.sleep(8)
    list_containers()
    for cid in ids:
        if cid: kill_container(cid)
    structured_log("demo_done")

# ---------------------------
# MAIN
# ---------------------------
import argparse
def main():
    cfg = load_config()
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="action")

    r = sub.add_parser("run"); r.add_argument("--cmd", required=True)
    r.add_argument("--cpu", default="100000 100000"); r.add_argument("--mem", default="100M")
    r.add_argument("--net", choices=["shared", "isolated"], default="isolated")

    sub.add_parser("list")
    k = sub.add_parser("kill"); k.add_argument("--id", required=True)
    sub.add_parser("dashboard")
    sub.add_parser("demo")

    args = p.parse_args()
    if args.action == "run":
        cid = run_container(args.cmd, cfg, args.cpu, args.mem, args.net)
        print(f"Started {cid}")
    elif args.action == "list":
        list_containers()
    elif args.action == "kill":
        kill_container(args.id)
    elif args.action == "dashboard":
        dashboard(cfg)
    elif args.action == "demo":
        demo(cfg)
    else:
        p.print_help()

if _name_ == "_main_":
    def _sig(signum, frame):
        structured_log("signal_exit", sig=signum)
        for c in list(containers.keys()): kill_container(c)
        sys.exit(0)
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)
    main()