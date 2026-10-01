#!/usr/bin/env python3
"""
PID_cys: Master Entrypoint
Launches the FastAPI backend and Interactive Cybersecurity Dashboard.
"""
import sys
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn


def print_banner(host: str, port: int):
    banner = f"""
=============================================================================
  ██████╗ ██╗██████╗         ██████╗██╗   ██╗███████╗
  ██╔══██╗██║██╔══██╗       ██╔════╝╚██╗ ██╔╝██╔════╝
  ██████╔╝██║██║  ██║       ██║      ╚████╔╝ ███████╗
  ██╔═══╝ ██║██║  ██║       ██║       ╚██╔╝  ╚════██║
  ██║     ██║██████╔╝███████╗╚██████╗  ██║   ███████║
  ╚═╝     ╚═╝╚═════╝ ╚══════╝ ╚═════╝  ╚═╝   ╚══════╝
  HYBRID PROMPT INJECTION DETECTION FIREWALL v1.0
=============================================================================
  🟢 Status:           OPERATIONAL & LISTENING
  🌐 Web Dashboard:    http://{host}:{port}/
  📡 REST API Docs:    http://{host}:{port}/docs
  ⚡ Core Layers:      L1 (Aho-Corasick) | L2 (20k TF-IDF ML) | L3 (Semantic Guard)
=============================================================================
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(description="Start PID_cys Firewall & Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable hot reload")

    args = parser.parse_args()

    print_banner(args.host, args.port)
    uvicorn.run("src.api.server:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
