#!/usr/bin/env python3
"""
container_runtime.py -- controller + client for mini container runtime

Usage:
  # Start controller/daemon (one terminal)
  sudo python3 container_runtime.py serve

  # In other terminals, send commands to the controller:
  sudo python3 container_runtime.py run --cmd "sleep 30" --mem 100M --cpu "100000 100000"
  sudo python3 container_runtime.py list
  sudo python3 container_runtime.py kill --id <cid>
  sudo python3 container_runtime.py dashboard
  sudo python3 container_runtime.py demo

Notes:
- Requires root to use namespaces and write to /sys/fs/cgroup.
- Socket: /tmp/container_runtime.sock
- State file: /tmp/containers_state.json
"""

import os, sys, time, json, yaml, csv, signal, subprocess, threading, logging, shutil, uuid, socket, errno
from pathlib import Path
from collections import defaultdict

try:
    import psutil
except Exception:
    psutil = None

try:
    import curses
    HAS_CURSES = True
except Exception:
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
        "default_priority": 5,
    }
}

containers = {}
containers_lock = threading.Lock()
CONTAINER_STATE_FILE = "/tmp/containers_state.json"
SOCKET_PATH = "/tmp/container_runtime.sock"

# ---------------------------
# Helpers
# ---------------------------

CONTAINERS_ROOT = "/tmp/mycontainers"   # base directory for per-container fs

BRIDGE_NAME = "osbridge0"
BRIDGE_SUBNET = "10.10.0.0/24"
BRIDGE_GW = "10.10.0.1"
_next_veth_idx = 1


def set_container_priority(cid, priority, cfg):
    # map priority 1..10 -> cpu.weight 1..10000 (linear)
    weight = max(1, min(10000, int((priority / 10.0) * 10000)))
    path = cgroup_path(cid, cfg)
    try:
        with open(os.path.join(path, "cpu.weight"), "w") as f:
            f.write(str(weight))
        structured_log("set_priority", cid=cid, priority=priority, weight=weight)
    except Exception as e:
        structured_log("priority_error", cid=cid, error=str(e))

def ensure_bridge():
    try:
        # create bridge if not exists
        out = subprocess.run(["ip", "link", "show", BRIDGE_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if out.returncode != 0:
            subprocess.check_call(["ip", "link", "add", "name", BRIDGE_NAME, "type", "bridge"])
            subprocess.check_call(["ip", "addr", "add", BRIDGE_GW + "/24", "dev", BRIDGE_NAME])
            subprocess.check_call(["ip", "link", "set", BRIDGE_NAME, "up"])
            structured_log("bridge_created", bridge=BRIDGE_NAME)
    except Exception as e:
        structured_log("bridge_error", error=str(e))

def setup_veth_for_container(cid, pid, ip_addr=None):
    """
    Create veth pair and attach to bridge; move peer to container netns and configure IP.
    pid: pid of container (the process in netns)
    ip_addr: string like "10.10.0.5"
    Returns host_veth name and container iface name.
    """
    host_if = f"vethh{cid[:6]}"
    cont_if = f"vethc{cid[:6]}"  # will rename to eth0 inside container
    try:
        ensure_bridge()

        # --- Wait for container's network namespace to exist ---
        for _ in range(10):
            if os.path.exists(f"/proc/{pid}/ns/net"):
                break
            time.sleep(0.05)
        else:
            raise RuntimeError(f"netns for pid {pid} not ready")

        # --- Create veth pair ---
        subprocess.check_call(["ip", "link", "add", host_if, "type", "veth", "peer", "name", cont_if])

        # --- Attach host side to bridge ---
        subprocess.check_call(["ip", "link", "set", host_if, "master", BRIDGE_NAME])
        subprocess.check_call(["ip", "link", "set", host_if, "up"])

        # --- Move container side into container's netns ---
        subprocess.check_call(["ip", "link", "set", cont_if, "netns", str(pid)])

        # --- Configure inside netns ---
        if ip_addr is None:
            ip_addr = f"10.10.0.{int(cid[:2], 16) % 250 + 2}"
        nsenter = ["nsenter", "-t", str(pid), "-n"]
        subprocess.check_call(nsenter + ["ip", "link", "set", cont_if, "name", "eth0"])
        subprocess.check_call(nsenter + ["ip", "addr", "add", ip_addr + "/24", "dev", "eth0"])
        subprocess.check_call(nsenter + ["ip", "link", "set", "eth0", "up"])
        subprocess.check_call(nsenter + ["ip", "route", "add", "default", "via", BRIDGE_GW])

        structured_log("veth_setup", cid=cid, host_if=host_if, container_ip=ip_addr)
        return host_if, "eth0"

    except Exception as e:
        structured_log("veth_error", cid=cid, error=str(e))
        try:
            subprocess.call(["ip", "link", "del", host_if])
        except Exception:
            pass
        return None, None

def teardown_veth(host_if):
    try:
        subprocess.call(["ip", "link", "del", host_if])
    except Exception as e:
        structured_log("veth_teardown_err", ifname=host_if, error=str(e))


def ensure_container_dirs():
    ensure_dir(CONTAINERS_ROOT)

def prepare_overlay_root(cid, base_root="/usr/share/container-base", cfg=None):
    """
    Create overlay dirs and mount overlay to /tmp/mycontainers/<cid>/rootfs.
    base_root: path to a base read-only root filesystem (you should create a small rootfs or use minimal distro files)
    Returns mountpoint path or None on error.
    """
    ensure_container_dirs()
    base_root = str(base_root)
    root_base = os.path.join(CONTAINERS_ROOT, cid)
    upper = os.path.join(root_base, "upper")
    work = os.path.join(root_base, "work")
    merged = os.path.join(root_base, "rootfs")

    for d in (upper, work, merged):
        ensure_dir(d)

    # ensure base exists
    if not os.path.exists(base_root):
        # fallback: use a minimal bind of host root (dangerous) — better to prepare a base image beforehand
        structured_log("overlay_error", cid=cid, error=f"base_root_missing:{base_root}")
        return None

    opts = f"lowerdir={base_root},upperdir={upper},workdir={work}"
    try:
        subprocess.check_call(["mount", "-t", "overlay", "overlay", "-o", opts, merged])
        structured_log("overlay_mounted", cid=cid, merged=merged)
        return merged
    except subprocess.CalledProcessError as e:
        structured_log("overlay_mount_fail", cid=cid, error=str(e))
        return None

def teardown_overlay_root(cid):
    root_base = os.path.join(CONTAINERS_ROOT, cid)
    merged = os.path.join(root_base, "rootfs")
    try:
        if os.path.ismount(merged):
            subprocess.call(["umount", "-l", merged])
    except Exception as e:
        structured_log("overlay_umount_error", cid=cid, error=str(e))
    try:
        shutil.rmtree(root_base, ignore_errors=True)
    except Exception:
        pass

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
# Persistent state
# ---------------------------
def save_state():
    try:
        with containers_lock:
            out = {}
            for cid, c in containers.items():
                # store only minimal data
                pid = c["proc"].pid if hasattr(c["proc"], "pid") else (c["proc"].pid if isinstance(c["proc"], subprocess.Popen) else None)
                out[cid] = {
                    "pid": pid,
                    "cmd": c["cmd"],
                    "start_time": c.get("start_time", time.time()),
                    "cgroup": c.get("cgroup")
                }
            with open(CONTAINER_STATE_FILE, "w") as f:
                json.dump(out, f)
    except Exception as e:
        structured_log("state_save_error", error=str(e))

def load_state(cfg):
    # Attempt to reattach to running pids saved in state file (best-effort)
    if not os.path.exists(CONTAINER_STATE_FILE):
        return
    try:
        with open(CONTAINER_STATE_FILE) as f:
            data = json.load(f)
        for cid, info in data.items():
            pid = info.get("pid")
            if pid is None: continue
            try:
                if psutil:
                    proc = psutil.Process(pid)
                    # reattach
                    with containers_lock:
                        if cid not in containers:
                            containers[cid] = {
                                "proc": proc,
                                "cmd": info.get("cmd"),
                                "start_time": info.get("start_time", time.time()),
                                "stop_event": threading.Event(),
                                "cgroup": info.get("cgroup"),
                                "peaks": (0, 0)
                            }
                            # start telemetry for reattached container
                            threading.Thread(target=telemetry, args=(cid, cfg), daemon=True).start()
                            threading.Thread(target=monitor_container, args=(cid, proc, cfg), daemon=True).start()
                else:
                    # Without psutil, try os.kill 0 to check existence
                    os.kill(pid, 0)
                    with containers_lock:
                        if cid not in containers:
                            containers[cid] = {
                                "proc": subprocess.Popen(["/bin/true"]),  # placeholder
                                "cmd": info.get("cmd"),
                                "start_time": info.get("start_time", time.time()),
                                "stop_event": threading.Event(),
                                "cgroup": info.get("cgroup"),
                                "peaks": (0, 0)
                            }
                            threading.Thread(target=telemetry, args=(cid, cfg), daemon=True).start()
                            threading.Thread(target=monitor_container, args=(cid, proc, cfg), daemon=True).start()
            except Exception:
                # process not present
                continue
        structured_log("state_loaded", file=CONTAINER_STATE_FILE)
    except Exception as e:
        structured_log("state_load_error", error=str(e))

# ---------------------------
# CGROUPS
# ---------------------------

def monitor_container(cid, proc, cfg):
    """
    Waits for the container to exit naturally, then cleans it up.
    """
    proc.wait()  # block until process exits
    structured_log("container_exit", cid=cid)
    cleanup_container(cid, cfg)


def cleanup_container(cid, cfg):
    """
    Stops telemetry, removes cgroups, and deletes container from memory.
    """
    with containers_lock:
        info = containers.get(cid)
        if not info:
            return

        # Stop telemetry
        if info.get("stop_event"):
            info["stop_event"].set()

        # Remove cgroup
        try:
            remove_cgroup(info.get("cgroup"), cid)
        except Exception as e:
            structured_log("cleanup_error", cid=cid, error=str(e))
        # Teardown networking
        try:
            host_if = f"vethh{cid[:6]}"
            teardown_veth(host_if)
        except Exception as e:
            structured_log("veth_teardown_error", cid=cid, error=str(e))

        # Remove from containers dict
        containers.pop(cid, None)
    save_state()
    structured_log("cleaned", cid=cid)


def setup_cgroup(cid, cfg, cpu="100000 100000", mem="100M"):
    path = cgroup_path(cid, cfg)
    ensure_dir(path)
    try:
        with open(os.path.join(path, "cpu.max"), "w") as f: f.write(cpu)
        with open(os.path.join(path, "memory.max"), "w") as f: f.write(mem)
        structured_log("cgroup_created", cid=cid, cpu=cpu, mem=mem)
    except Exception as e:
        structured_log("cgroup_error", cid=cid, error=str(e))
    return path

def add_pid_to_cgroup(cid, pid, cfg):
    try:
        path = cgroup_path(cid, cfg)
        with open(os.path.join(path, "cgroup.procs"), "w") as f: f.write(str(pid))
        if psutil:
            for ch in psutil.Process(pid).children(recursive=True):
                try:
                    with open(os.path.join(path, "cgroup.procs"), "w") as f: f.write(str(ch.pid))
                except: pass
    except Exception as e:
        structured_log("cgroup_add_error", cid=cid, error=str(e))

def remove_cgroup(path, cid):
    try:
        if os.path.exists(path):
            # remove files and directories bottom-up, skip cgroup.events (often not removable)
            for root, dirs, files in os.walk(path, topdown=False):
                for fn in files:
                    fp = os.path.join(root, fn)
                    try:
                        # skip cgroup.events / other special files
                        if os.path.basename(fp) in ("cgroup.events",):
                            continue
                        os.unlink(fp)
                    except Exception:
                        pass
                for d in dirs:
                    try:
                        os.rmdir(os.path.join(root, d))
                    except Exception:
                        pass
            try:
                os.rmdir(path)
            except Exception:
                pass
    except Exception as e:
        structured_log("cgroup_remove_error", cid=cid, error=str(e))

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
    except Exception:
        pass
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

    # create header if missing
    if not os.path.exists(file):
        try:
            with open(file, "w", newline="") as f:
                csv.writer(f).writerow(["time", "cpu_ms", "mem_mb", "cpu.max", "mem.max"])
        except Exception:
            pass

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

        structured_log("telemetry", cid=cid, cpu_ms=cpu_ms, mem_mb=mem_mb)
        try:
            with open(file, "a", newline="") as f:
                csv.writer(f).writerow([time.strftime("%H:%M:%S"), f"{cpu_ms:.3f}", f"{mem_mb:.3f}"])
        except Exception:
            pass

        now = time.time()
        if now - last_scale >= cooldown:
            try:
                if mem_mb > thresh["mem_trigger_up_mb"]:
                    with open(os.path.join(path, "memory.max"), "w") as f: f.write(f"{thresh['mem_up_mb']}M")
                    structured_log("scale_mem_up", cid=cid, new=f"{thresh['mem_up_mb']}M")
                elif mem_mb < thresh["mem_trigger_down_mb"]:
                    with open(os.path.join(path, "memory.max"), "w") as f: f.write(f"{thresh['mem_down_mb']}M")
                    structured_log("scale_mem_down", cid=cid, new=f"{thresh['mem_down_mb']}M")
                if cpu_ms > thresh["cpu_up_ms"]:
                    with open(os.path.join(path, "cpu.max"), "w") as f: f.write(thresh["cpu_scale_up"])
                    structured_log("scale_cpu_up", cid=cid, new=thresh["cpu_scale_up"])
                elif cpu_ms < thresh["cpu_down_ms"]:
                    with open(os.path.join(path, "cpu.max"), "w") as f: f.write(thresh["cpu_scale_down"])
                    structured_log("scale_cpu_down", cid=cid, new=thresh["cpu_scale_down"])
                last_scale = now
            except Exception:
                pass
        time.sleep(t)
    with containers_lock:
        if cid in containers:
            containers[cid]["peaks"] = (peak_cpu, peak_mem)
    structured_log("telemetry_end", cid=cid, peak_cpu=peak_cpu, peak_mem=peak_mem)

# ---------------------------
# LIFECYCLE
# ---------------------------
def run_container(cmd, cfg, cpu, mem, net_mode):
    """
    Run a containerized process with cgroup isolation and optional OverlayFS root.
    """
    cid = uuid.uuid4().hex[:6]
    cpath = setup_cgroup(cid, cfg, cpu, mem)
    stop_event = threading.Event()
    net_flag = [] if net_mode == "shared" else ["--net"]

    # ---------- OverlayFS setup ----------
    overlay_root = None
    base_root = cfg.get("general", {}).get("base_root", "/usr/share/container-base")
    use_overlay = cfg.get("general", {}).get("use_overlay", True)

    if use_overlay:
        try:
            overlay_root = prepare_overlay_root(cid, base_root, cfg)
        except Exception as e:
            structured_log("overlay_init_error", cid=cid, error=str(e))
            overlay_root = None

    # ---------- Build the command to run ----------
    if overlay_root:
        # mount proc inside the overlay root and chroot into it
        inner_cmd = (
            f"mount --make-rprivate / && "
            f"mount -t proc proc /proc || true; "
            f"chroot {overlay_root} /bin/bash -lc 'hostname {cid} && exec {cmd}'"
        )
    else:
        # fallback: no overlay, normal execution
        inner_cmd = f"hostname {cid} && exec {cmd}"

    unshare = [
        "unshare",
        "--fork",
        "--pid",
        "--mount-proc",
        "--uts",
        "--mount"
    ] + net_flag + ["bash", "-c", inner_cmd]

    # ---------- Launch container process ----------
    try:
        proc = subprocess.Popen(unshare)
    except Exception as e:
        structured_log("launch_error", cid=cid, error=str(e))
        return None

    # slight pause to let the unshared process initialize
    time.sleep(0.15)

    # ---------- Cgroup setup ----------
    try:
        add_pid_to_cgroup(cid, proc.pid, cfg)
    except Exception:
        pass
        # ---------- Networking setup ----------
    if net_mode == "isolated":
        try:
            setup_veth_for_container(cid, proc.pid)
        except Exception as e:
            structured_log("veth_setup_fail", cid=cid, error=str(e))


    # ---------- Track container ----------
    entry = {
        "proc": proc,
        "cmd": cmd,
        "start_time": time.time(),
        "stop_event": stop_event,
        "cgroup": cpath,
        "peaks": (0, 0),
        "cid": cid,
        "overlay_root": overlay_root,
    }

    with containers_lock:
        containers[cid] = entry

    # ---------- Background threads ----------
    threading.Thread(target=telemetry, args=(cid, cfg), daemon=True).start()
    threading.Thread(target=monitor_container, args=(cid, proc, cfg), daemon=True).start()
    save_state()
    structured_log("started", cid=cid, pid=proc.pid, net=net_mode, overlay=bool(overlay_root))
    return cid


def list_containers(cfg):
    # print table
    print(f"{'CID':8} {'PID':6} {'STATUS':9} {'UPTIME':8} {'CPUms':8} {'MEMMB':8} CMD")
    with containers_lock:
        for cid, i in list(containers.items()):
            try:
                proc = i["proc"]
                # get pid: if psutil Process object
                pid = proc.pid if hasattr(proc, "pid") else (proc.pid if isinstance(proc, subprocess.Popen) else "N/A")
                alive = True
                if psutil and hasattr(proc, "is_running"):
                    alive = proc.is_running()
                else:
                    # fallback: check poll for Popen
                    try:
                        if isinstance(proc, subprocess.Popen):
                            alive = proc.poll() is None
                    except Exception:
                        pass
                status = "running" if alive else "stopped"
                up = int(time.time() - i["start_time"])
                pc, pm = i.get("peaks", (0,0))
                print(f"{cid:8} {str(pid):6} {status:<9} {up:<8} {pc:<8.1f} {pm:<8.1f} {i['cmd']}")
            except Exception:
                continue

def kill_container(cfg, cid):
    with containers_lock:
        info = containers.get(cid)
        if not info:
            print("No such container")
            return False
        proc = info["proc"]
        # signal telemetry / monitor to stop
        if info.get("stop_event"):
            info["stop_event"].set()

    # terminate the container process
    try:
        if psutil and isinstance(proc, psutil.Process):
            for ch in proc.children(recursive=True):
                try:
                    ch.terminate()
                except: pass
            try:
                proc.terminate()
            except: pass
        else:
            if isinstance(proc, subprocess.Popen):
                try:
                    if proc.poll() is None:
                        proc.terminate()
                        proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except: pass
    except Exception:
        pass

    # unified cleanup for cgroups and dict removal
    cleanup_container(cid, cfg)

    structured_log("killed", cid=cid)
    return True

# ---------------------------
# DASHBOARD
# ---------------------------

def dashboard_loop(cfg):
    metrics_dir = cfg["general"].get("metrics_dir", "/tmp/container_metrics")

    def _draw(stdscr):
        curses.curs_set(0)
        while True:
            stdscr.erase()
            stdscr.addstr(0, 0, "Mini Container Dashboard (q to quit)")
            r = 2

            # --- 1. Display containers tracked in-memory ---
            try:
                from container import containers, containers_lock  # ensure import works
                with containers_lock:
                    for cid, i in containers.items():
                        proc = i["proc"]
                        status = "running" if (not isinstance(proc, subprocess.Popen) or proc.poll() is None) else "stopped"
                        pc, pm = i.get("peaks", (0, 0))
                        stdscr.addstr(r, 0, f"{cid} | {status} | CPU:{pc:.2f} | MEM:{pm:.2f} | {i['cmd']}")
                        r += 1
            except:
                pass

            # --- 2. Display containers from telemetry CSVs ---
            if os.path.exists(metrics_dir):
                csv_files = [f for f in os.listdir(metrics_dir) if f.endswith(".csv")]
                for csv_file in csv_files:
                    cid = csv_file.replace(".csv", "")
                    # Skip already displayed containers
                    if 'containers' in locals() and cid in containers:
                        continue
                    cpu_ms, mem_mb, cmd = 0.0, 0.0, ""
                    path = os.path.join(metrics_dir, csv_file)
                    try:
                        with open(path) as f:
                            reader = csv.DictReader(f)
                            last_row = None
                            for last_row in reader:
                                pass
                            if last_row:
                                cpu_ms = float(last_row.get("cpu_ms", 0))
                                mem_mb = float(last_row.get("mem_mb", 0))
                                cmd = last_row.get("cmd", "")
                    except Exception as e:
                        cmd = f"Error reading CSV: {e}"
                        stdscr.addstr(r, 0, f"{cid} | stopped | CPU:{cpu_ms:.2f} | MEM:{mem_mb:.2f} | {cmd}")
                    r += 1

            stdscr.refresh()
            ch = stdscr.getch()
            if ch == ord("q"):
                break
            time.sleep(cfg["general"].get("telemetry_interval", 2))

    if 'curses' in globals() and curses:
        curses.wrapper(_draw)
    else:
        while True:
            os.system("clear")
            try:
                from container import containers, containers_lock
                with containers_lock:
                    for cid, i in containers.items():
                        proc = i["proc"]
                        status = "running" if (not isinstance(proc, subprocess.Popen) or proc.poll() is None) else "stopped"
                        pc, pm = i.get("peaks", (0, 0))
                        print(f"{cid} | {status} | CPU:{pc:.2f} | MEM:{pm:.2f} | {i['cmd']}")
            except:
                print("No live containers tracked in-memory.")

            # Show containers from CSVs
            if os.path.exists(metrics_dir):
                csv_files = [f for f in os.listdir(metrics_dir) if f.endswith(".csv")]
                for csv_file in csv_files:
                    cid = csv_file.replace(".csv", "")
                    if 'containers' in locals() and cid in containers:
                        continue
                    cpu_ms, mem_mb, cmd = 0.0, 0.0, ""
                    path = os.path.join(metrics_dir, csv_file)
                    try:
                        with open(path) as f:
                            reader = csv.DictReader(f)
                            last_row = None
                            for last_row in reader:
                                pass
                            if last_row:
                                cpu_ms = float(last_row.get("cpu_ms", 0))
                                mem_mb = float(last_row.get("mem_mb", 0))
                                cmd = last_row.get("cmd", "")
                    except:
                        pass
                    print(f"{cid} | stopped | CPU:{cpu_ms:.2f} | MEM:{mem_mb:.2f} | {cmd}")

            print("\n(q) to quit")
            if input().strip().lower() == "q":
                break
            time.sleep(cfg["general"].get("telemetry_interval", 2))
# ---------------------------
# DEMO
# ---------------------------
def demo_flow(cfg):
    structured_log("demo_start")
    cmds = [
        "stress-ng --cpu 1 --timeout 5",
        "stress-ng --vm 1 --vm-bytes 100M --timeout 5"
    ]
    ids = []
    for c in cmds:
        cid = run_container(c, cfg, "100000 100000", "100M", "isolated")
        if cid: ids.append(cid)
    time.sleep(8)
    list_containers(cfg)
    for cid in ids:
        kill_container(cfg, cid)
    structured_log("demo_done")

# ---------------------------
# Simple UNIX socket controller
# ---------------------------
def start_controller(cfg):
    # remove stale socket
    try:
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
    except Exception:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(5)
    structured_log("controller_started", socket=SOCKET_PATH)

    # load persistent state and reattach
    load_state(cfg)

    def handle_client(conn):
        try:
            raw = conn.recv(65536)
            if not raw:
                conn.close(); return
            req = json.loads(raw.decode())
            action = req.get("action")
            resp = {"ok": True}
            if action == "run":
                cmd = req.get("cmd")
                cpu = req.get("cpu", "100000 100000")
                mem = req.get("mem", "100M")
                net = req.get("net", "isolated")
                cid = run_container(cmd, cfg, cpu, mem, net)
                resp["cid"] = cid
            elif action == "list":
                # return minimal listing
                out = []
                with containers_lock:
                    for cid, i in containers.items():
                        pid = i["proc"].pid if hasattr(i["proc"], "pid") else None
                        alive = True
                        try:
                            if psutil and hasattr(i["proc"], "is_running"):
                                alive = i["proc"].is_running()
                            else:
                                if isinstance(i["proc"], subprocess.Popen):
                                    alive = i["proc"].poll() is None
                        except:
                            alive = False
                        up = int(time.time() - i.get("start_time", time.time()))
                        pc, pm = i.get("peaks", (0,0))
                        out.append({"cid": cid, "pid": pid, "status": "running" if alive else "stopped",
                                    "uptime": up, "cpu_ms": pc, "mem_mb": pm, "cmd": i.get("cmd")})
                resp["list"] = out
            elif action == "kill":
                cid = req.get("cid")
                ok = kill_container(cfg, cid)
                resp["ok"] = ok
            elif action == "dashboard":
                # not used by socket; controller will simply signal client to open local dashboard
                resp["msg"] = "dashboard"
            elif action == "demo":
                threading.Thread(target=demo_flow, args=(cfg,), daemon=True).start()
                resp["msg"] = "demo_started"
            else:
                resp = {"ok": False, "error": "unknown action"}
        except Exception as e:
            resp = {"ok": False, "error": str(e)}
        try:
            conn.sendall(json.dumps(resp).encode())
        except Exception:
            pass
        conn.close()

    try:
        while True:
            conn, _ = server.accept()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        server.close()
    finally:
        try:
            if os.path.exists(SOCKET_PATH):
                os.unlink(SOCKET_PATH)
        except Exception:
            pass

# ---------------------------
# Client helper to talk to controller
# ---------------------------
def send_to_controller(payload):
    if not os.path.exists(SOCKET_PATH):
        return {"ok": False, "error": "controller_not_running"}
    try:
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(SOCKET_PATH)
        c.sendall(json.dumps(payload).encode())
        resp = c.recv(65536)
        c.close()
        return json.loads(resp.decode())
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---------------------------
# MAIN / CLI
# ---------------------------
import argparse
def main():
    cfg = load_config()
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="action")

    serve = sub.add_parser("serve")
    r = sub.add_parser("run"); r.add_argument("--cmd", required=True)
    r.add_argument("--cpu", default="100000 100000"); r.add_argument("--mem", default="100M")
    r.add_argument("--net", choices=["shared", "isolated"], default="isolated")

    sub.add_parser("list")
    k = sub.add_parser("kill"); k.add_argument("--id", required=True)
    sub.add_parser("dashboard")
    sub.add_parser("demo")

    args = p.parse_args()

    if args.action == "serve":
        try:
            start_controller(cfg)
        except Exception as e:
            structured_log("serve_error", error=str(e))
    elif args.action == "run":
        # client -> send to controller if running, otherwise run in-process
        payload = {"action": "run", "cmd": args.cmd, "cpu": args.cpu, "mem": args.mem, "net": args.net}
        resp = send_to_controller(payload)
        if resp.get("ok"):
            if resp.get("cid"):
                print(f"Started {resp.get('cid')}")
            else:
                print("Started (controller accepted)")
        else:
            if resp.get("error") == "controller_not_running":
                # fallback: run directly (in-process)
                cid = run_container(args.cmd, cfg, args.cpu, args.mem, args.net)
                print(f"Started {cid} (local)")
            else:
                print("Error:", resp)
    elif args.action == "list":
        resp = send_to_controller({"action": "list"})
        if resp.get("ok"):
            rows = resp.get("list", [])
            print(f"{'CID':8} {'PID':6} {'STATUS':9} {'UPTIME':8} {'CPUms':8} {'MEMMB':8} CMD")
            for r in rows:
                print(f"{r['cid']:8} {str(r['pid']):6} {r['status']:<9} {r['uptime']:<8} {r['cpu_ms']:<8.1f} {r['mem_mb']:<8.1f} {r['cmd']}")
        else:
            if resp.get("error") == "controller_not_running":
                print("Controller not running. Start it with: sudo python3 container_runtime.py serve")
            else:
                print("Error:", resp)
    elif args.action == "kill":
        resp = send_to_controller({"action": "kill", "cid": args.id})
        if resp.get("ok"):
            print("Killed", args.id)
        else:
            # fallback try local
            ok = kill_container(cfg, args.id)
            if ok: print("Killed (local)", args.id)
            else: print("No such container")
    elif args.action == "dashboard":
        # prefer to show local dashboard (client telling user to run dashboard in controller terminal)
        resp = send_to_controller({"action": "dashboard"})
        if resp.get("ok"):
            # open local dashboard reading directly from state (best-effort)
            dashboard_loop(cfg)
        else:
            if resp.get("error") == "controller_not_running":
                print("Controller not running. Start it with: sudo python3 container_runtime.py serve")
            else:
                print("Error:", resp)
    elif args.action == "demo":
        resp = send_to_controller({"action": "demo"})
        if resp.get("ok"):
            print("Demo started")
        else:
            if resp.get("error") == "controller_not_running":
                print("Controller not running. Running demo locally.")
                demo_flow(cfg)
            else:
                print("Error:", resp)
    else:
        p.print_help()

if _name_ == "_main_":
    def _sig(signum, frame):
        structured_log("signal_exit", sig=signum)
        # try to kill all tracked containers cleanly
        with containers_lock:
            for c in list(containers.keys()):
                try:
                    kill_container(load_config(), c)
                except: pass
        try:
            if os.path.exists(SOCKET_PATH):
                os.unlink(SOCKET_PATH)
        except: pass
        sys.exit(0)
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)
    main()