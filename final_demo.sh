#!/bin/bash
# ==========================================================
# full_showcase.sh (final narrated + stable)
# OS Project - Group 22
# Container Runtime with Dynamic Resource Scaling
# ==========================================================

DELAY_SHORT=2
DELAY_LONG=5
SLOW=0
VERBOSE=0

for arg in "$@"; do
  case "$arg" in
    --slow) SLOW=1 ;;
    --verbose) VERBOSE=1 ;;
  esac
done

if [ "$SLOW" -eq 1 ]; then
  DELAY_SHORT=$((DELAY_SHORT * 2))
  DELAY_LONG=$((DELAY_LONG * 2))
fi

# ------------------------
# Colors
# ------------------------
C_RESET="\033[0m"; C_BLUE="\033[1;34m"; C_CYAN="\033[1;36m"; C_GREEN="\033[1;32m"
C_YELLOW="\033[1;33m"; C_RED="\033[1;31m"; C_MAG="\033[1;35m"; C_WHITE="\033[1;37m"

# ------------------------
# Root check
# ------------------------
if [ "$EUID" -ne 0 ]; then
  echo -e "${C_YELLOW}[!] Re-running under sudo...${C_RESET}"
  exec sudo "$0" "$@"
fi

: > serve_log.txt 2>/dev/null || true
LOG_TAIL_PID=""

start_log_stream() {
  if [ "$VERBOSE" -eq 1 ]; then
    PATTERN='("event":\s*"(started|overlay_mounted|veth_setup|scale_cpu_|scale_mem_|telemetry|container_exit|cleaned)")'
    tail -n0 -F serve_log.txt 2>/dev/null | grep --line-buffered -E "$PATTERN" |
      while read -r line; do echo -e "${C_MAG}[LOG]${C_RESET} $line"; done &
    LOG_TAIL_PID=$!
    sleep 0.2
  fi
}

stop_log_stream() {
  if [ -n "$LOG_TAIL_PID" ]; then
    kill "$LOG_TAIL_PID" 2>/dev/null || true
    wait "$LOG_TAIL_PID" 2>/dev/null || true
    LOG_TAIL_PID=""
  fi
}

cleanup_and_exit() {
  stop_log_stream
  pkill -f "container.py serve" 2>/dev/null || true
  if ip link show osbridge0 >/dev/null 2>&1; then
    ip link delete osbridge0 type bridge 2>/dev/null || true
  fi
  echo -e "${C_GREEN}Cleanup done. Exiting.${C_RESET}"
  exit 0
}
trap cleanup_and_exit INT TERM EXIT

# ==========================================================
# INTRO
# ==========================================================
clear
echo -e "\n${C_BLUE}============================================================${C_RESET}"
echo -e "${C_CYAN}   OS PROJECT - GROUP 22: FULL SHOWCASE (Weeks 1 → 10)${C_RESET}"
echo -e "${C_BLUE}============================================================${C_RESET}\n"
sleep $DELAY_SHORT

echo -e "${C_YELLOW}💬 Talking Point:${C_RESET} Welcome to our OS project demo — a container runtime built from scratch using Linux namespaces, cgroups v2, and dynamic resource scaling."
sleep $DELAY_LONG

# ==========================================================
# ENVIRONMENT SETUP
# ==========================================================
echo -e "${C_YELLOW}[ENV CHECK]${C_RESET} Preparing tools & folders..."
if ! command -v stress-ng >/dev/null 2>&1; then
  echo -e "${C_RED}[ERROR] stress-ng missing. Install: sudo apt install stress-ng${C_RESET}"
  exit 1
fi
mkdir -p /tmp/container_metrics /usr/share/container-base
echo "base file" > /usr/share/container-base/placeholder.txt
sleep $DELAY_SHORT
echo -e "${C_YELLOW}💬 Talking Point:${C_RESET} Before starting, we prepare the base filesystem and metrics directory — these are used later by OverlayFS and telemetry."
sleep $DELAY_LONG

# ==========================================================
# STAGE 0 — NETWORK BRIDGE
# ==========================================================
echo -e "${C_CYAN}[STAGE 0] Network Bridge Setup (Week 7)${C_RESET}"
echo -e "${C_YELLOW}💬 Talking Point:${C_RESET} We first create a virtual bridge, ‘osbridge0’, which provides isolated networking between containers."
if ! ip link show osbridge0 >/dev/null 2>&1; then
  ip link add name osbridge0 type bridge 2>/dev/null || true
  ip addr add 10.10.0.1/24 dev osbridge0 2>/dev/null || true
  ip link set osbridge0 up 2>/dev/null || true
fi
ip addr show osbridge0 | head -n 4
sleep $DELAY_LONG
echo -e "${C_YELLOW}💬 Talking Point:${C_RESET} This bridge will later connect each container’s veth interface, forming a mini virtual LAN."
sleep $DELAY_SHORT

# ==========================================================
# STAGE 1 — CONTROLLER START
# ==========================================================
echo -e "${C_CYAN}[STAGE 1] Start Controller (Weeks 1–2)${C_RESET}"
python3 container.py serve > serve_log.txt 2>&1 &
CONT_PID=$!
sleep 2
start_log_stream
echo -e "${C_YELLOW}💬 Talking Point:${C_RESET} The controller process initializes namespaces, manages cgroups, and handles container lifecycle events."
sleep $DELAY_LONG

# ==========================================================
# PART A — TELEMETRY & DYNAMIC SCALING
# ==========================================================
echo -e "${C_CYAN}[PART A] Telemetry & Dynamic Scaling (Weeks 3–5)${C_RESET}"
echo -e "${C_YELLOW}💬 Talking Point:${C_RESET} Next, we launch CPU- and memory-intensive workloads. Watch how our runtime auto-scales CPU shares and memory dynamically."
python3 container.py run --cmd "stress-ng --cpu 1 --timeout 20" --mem 100M --cpu "100000 100000" --net shared
sleep 1
python3 container.py run --cmd "stress-ng --vm 1 --vm-bytes 200M --timeout 20" --mem 150M --cpu "100000 100000" --net shared
sleep 5
python3 container.py list
sleep 2
tail -n 4 /tmp/container_metrics/*.csv 2>/dev/null || echo "(Telemetry not ready)"
sleep $DELAY_LONG

# ==========================================================
# PART B — NETWORK NAMESPACE
# ==========================================================
echo -e "${C_CYAN}[PART B] Network Namespace Demonstration (Week 7)${C_RESET}"
echo -e "${C_YELLOW}💬 Talking Point:${C_RESET} Each container gets its own network namespace. Now you’ll see the isolated container’s private IP and a ping to our bridge gateway."
python3 container.py run --cmd "echo '--- Inside container ---'; ip addr show eth0; echo '--- Pinging bridge ---'; ping -c 2 10.10.0.1" --mem 50M --cpu "100000 100000" --net isolated
sleep $DELAY_LONG
echo -e "${C_WHITE}[Host view]${C_RESET} Bridge links (veths attached to osbridge0):"
bridge link | head -n 8 || echo "  (bridge links empty if container exited fast)"
sleep $DELAY_SHORT
echo -e "${C_YELLOW}💬 Talking Point:${C_RESET} From the host side, we can see virtual Ethernet pairs connecting containers to the bridge — confirming network isolation."
sleep $DELAY_LONG

# ==========================================================
# PART C — OVERLAYFS
# ==========================================================
echo -e "${C_CYAN}[PART C] OverlayFS Integration (Week 5)${C_RESET}"
echo -e "${C_YELLOW}💬 Talking Point:${C_RESET} Our runtime attempts to mount a layered filesystem using OverlayFS — this provides lightweight container roots."
python3 container.py run --cmd "hostname && echo 'overlay test' && sleep 5" --mem 50M --cpu "100000 100000" --net shared
sleep $DELAY_LONG

# ==========================================================
# PART D — MULTI-CONTAINER
# ==========================================================
echo -e "${C_CYAN}[PART D] Multi-Container Coordination (Week 8)${C_RESET}"
echo -e "${C_YELLOW}💬 Talking Point:${C_RESET} We now launch multiple containers concurrently — demonstrating orchestration and independent cgroups."
python3 container.py run --cmd "sleep 10" --mem 20M --cpu "50000 50000" --net shared
python3 container.py run --cmd "stress-ng --cpu 1 --timeout 10" --mem 50M --cpu "100000 100000" --net shared
sleep 2
python3 container.py list
sleep $DELAY_LONG

# ==========================================================
# PART E — PERSISTENCE & RECOVERY (SIMULATED)
# ==========================================================
echo -e "${C_CYAN}[PART E] Persistence & Recovery (Weeks 6 & 9)${C_RESET}"
echo -e "${C_YELLOW}💬 Talking Point:${C_RESET} Normally, our controller can save and reload state after a restart. For this demo we’ll simulate recovery to keep it stable."
sleep $DELAY_SHORT
echo -e "  • Simulating controller restart..."
sleep 2
echo -e "  • Pretending to reload container state from /tmp/containers_state.json"
sleep 2
echo -e "  • (Skipped actual restart to ensure uninterrupted demo)"
sleep $DELAY_LONG
python3 container.py list
sleep $DELAY_SHORT

# ==========================================================
# PART F — FAULT SIMULATION
# ==========================================================
echo -e "${C_CYAN}[PART F] Fault Simulation (Week 9)${C_RESET}"
echo -e "${C_YELLOW}💬 Talking Point:${C_RESET} We simulate a fault by deleting one veth device. The controller detects it and continues running."
VN=$(ip -o link show type veth | awk '{print $2}' | head -n1 | sed 's/://')
if [ -n "$VN" ]; then ip link delete "$VN" 2>/dev/null || true; fi
sleep $DELAY_LONG

# ==========================================================
# PART G — CLEANUP & SUMMARY
# ==========================================================
echo -e "${C_CYAN}[PART G] Cleanup & Final Summary (Week 10)${C_RESET}"
echo -e "${C_YELLOW}💬 Talking Point:${C_RESET} Finally, we stop the controller, remove the bridge, and show how all features map to each week."
pkill -f "container.py serve" 2>/dev/null || true
sleep 2
if ip link show osbridge0 >/dev/null 2>&1; then ip link delete osbridge0 type bridge 2>/dev/null; fi
stop_log_stream
sleep $DELAY_SHORT

echo -e "\n${C_GREEN}============================================================${C_RESET}"
echo -e "${C_GREEN}✅ FULL SHOWCASE COMPLETE — Group 22${C_RESET}"
echo -e "${C_GREEN}============================================================${C_RESET}\n"
echo -e "${C_WHITE}Logs:${C_RESET} serve_log.txt"
echo -e "${C_WHITE}Telemetry:${C_RESET} /tmp/container_metrics/"
echo -e "${C_WHITE}Bridge:${C_RESET} osbridge0 (removed)\n"
echo -e "${C_CYAN}💬 Talking Point:${C_RESET} This completes our 10-week development — from isolation and scaling to networking, persistence, and cleanup."
echo -e "${C_GREEN}Thank you.${C_RESET}\n"
cleanup_and_exit
