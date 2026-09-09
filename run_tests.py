#!/usr/bin/env python3
"""
AZZAZEL run_tests.py — Ejecutor oficial de la suite de pruebas (CI / Test Runner).
"""
import os
import sys
import time
from pathlib import Path

# Bootstrap sys.path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest

GREEN = "\033[92m"
CYAN = "\033[96m"
RED = "\033[91m"
AMBER = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"


def main() -> int:
    print(f"\n{GREEN}{BOLD}╔═════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{GREEN}{BOLD}║         AZZAZEL VPN v1.0 — SUITE DE INTEGRACIÓN CONTINUA (CI)       ║{RESET}")
    print(f"{GREEN}{BOLD}╚═════════════════════════════════════════════════════════════════════╝{RESET}\n")

    t0 = time.time()
    pytest_args = ["tests/", "-v", "--tb=short"] + sys.argv[1:]
    exit_code = pytest.main(pytest_args)
    duration = time.time() - t0

    print(f"\n{CYAN}───────────────────────────────────────────────────────────────────────{RESET}")
    if exit_code == 0:
        print(f"{GREEN}{BOLD}  ✔ TODAS LAS PRUEBAS PASARON EXITOSAMENTE en {duration:.2f}s{RESET}")
        print(f"{GREEN}    Baterías verificadas: Core, Crypto, Proxy NTLM, VPN Tunnel, Bridge,{RESET}")
        print(f"{GREEN}    SSH Shell, SSH Port Forwarding, Scanner, Firewall DSL y REST API.{RESET}")
    else:
        print(f"{RED}{BOLD}  ✗ ALGUNAS PRUEBAS FALLARON (código de salida: {exit_code}) en {duration:.2f}s{RESET}")
    print(f"{CYAN}───────────────────────────────────────────────────────────────────────{RESET}\n")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
