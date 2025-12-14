#!/usr/bin/env python3
"""
OpenEASD Development Runner - Starts both API server and worker.

Usage:
    python run_dev.py                    # Start both API and worker
    python run_dev.py --port 8080        # Start on custom port
    python run_dev.py --workers 3        # Start with multiple workers

Press Ctrl+C to stop all processes.
"""

import argparse
import signal
import subprocess
import sys
import time
from typing import List


class DevRunner:
    """Manages API server and worker processes."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8000, num_workers: int = 1):
        self.host = host
        self.port = port
        self.num_workers = num_workers
        self.processes: List[subprocess.Popen] = []
        self.running = False

    def start(self):
        """Start all processes."""
        self.running = True

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

        print("=" * 60)
        print("OpenEASD Development Server")
        print("=" * 60)
        print(f"API Server: http://{self.host}:{self.port}")
        print(f"API Docs:   http://localhost:{self.port}/docs")
        print(f"Workers:    {self.num_workers}")
        print("=" * 60)
        print("Press Ctrl+C to stop all processes")
        print("=" * 60)
        print()

        # Start API server
        self._start_api_server()

        # Give API server time to start
        time.sleep(1)

        # Start worker(s)
        for i in range(self.num_workers):
            self._start_worker(i + 1)

        # Wait for processes
        self._monitor_processes()

    def _start_api_server(self):
        """Start the API server process."""
        print("[API] Starting API server...")
        cmd = [
            sys.executable, "-m", "uvicorn",
            "src.api.main:app",
            "--host", self.host,
            "--port", str(self.port),
            "--reload"
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        self.processes.append(proc)
        print(f"[API] Started (PID: {proc.pid})")

    def _start_worker(self, worker_id: int):
        """Start a worker process."""
        print(f"[Worker-{worker_id}] Starting worker...")
        cmd = [sys.executable, "-m", "workers.scan_worker"]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        self.processes.append(proc)
        print(f"[Worker-{worker_id}] Started (PID: {proc.pid})")

    def _monitor_processes(self):
        """Monitor running processes and print output."""
        import select

        while self.running:
            # Check if any process has died
            for i, proc in enumerate(self.processes):
                if proc.poll() is not None:
                    print(f"\n[Process] Process {proc.pid} exited with code {proc.returncode}")
                    if self.running:
                        self._shutdown()
                    return

            # Read output from processes (non-blocking)
            for proc in self.processes:
                if proc.stdout:
                    try:
                        # Use select for non-blocking read on Unix
                        import os
                        import fcntl
                        fd = proc.stdout.fileno()
                        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

                        line = proc.stdout.readline()
                        if line:
                            # Determine which process this is
                            if proc == self.processes[0]:
                                prefix = "[API]"
                            else:
                                worker_num = self.processes.index(proc)
                                prefix = f"[Worker-{worker_num}]"
                            print(f"{prefix} {line.rstrip()}")
                    except (BlockingIOError, IOError):
                        pass

            time.sleep(0.1)

    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signal."""
        print("\n\nShutting down...")
        self._shutdown()

    def _shutdown(self):
        """Stop all processes."""
        self.running = False

        for proc in self.processes:
            if proc.poll() is None:
                print(f"[Shutdown] Terminating process {proc.pid}...")
                proc.terminate()

        # Wait for processes to terminate
        for proc in self.processes:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print(f"[Shutdown] Force killing process {proc.pid}...")
                proc.kill()

        print("[Shutdown] All processes stopped")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="OpenEASD Development Runner - Start API server and workers"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind API server (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for API server (default: 8000)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)"
    )

    args = parser.parse_args()

    runner = DevRunner(
        host=args.host,
        port=args.port,
        num_workers=args.workers
    )
    runner.start()


if __name__ == "__main__":
    main()
