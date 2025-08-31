#!/usr/bin/env python3
import os
import sys
import subprocess

def run_container(command):
    """Run a command inside isolated namespaces (PID, UTS, Mount, Net)."""
    try:
        subprocess.run([
            "unshare",
            "--fork", "--pid", "--mount-proc",
            "--uts", "--mount", "--net",
            "bash", "-c", f"hostname container && {command}"
        ])
    except Exception as e:
        print(f"Error running container: {e}")

def demo():
    print("=== DEMO: Container Foundations (Isolation Proof) ===\n")

    # Show host PID
    print("[1] Host process info:")
    print("Host PID:", os.getpid())

    # Inside container
    print("\n[2] Running inside new PID namespace...")
    run_container("echo 'Container PID:' $$ && hostname")

    print("\nExplanation:")
    print(" - On the host, your Python process has a large PID (not 1).")
    print(" - Inside the container, the first process becomes PID 1.")
    print("   This proves the process namespace is isolated.")
    print(" - Hostname also changes to 'container' inside the UTS namespace.")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 container.py <command>")
        print("  python3 container.py --demo   (run validation demo)")
        sys.exit(1)

    if sys.argv[1] == "--demo":
        demo()
    else:
        command = " ".join(sys.argv[1:])
        run_container(command)

if _name_ == "_main_":
    main()