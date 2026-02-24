#!/usr/bin/env bash
set -euo pipefail
python3 -m py_compile routeguard_core.py routeguard_cli.py routeguard_gui.py
echo 'Syntax OK'
python3 routeguard_cli.py --help >/dev/null
python3 routeguard_cli.py status >/dev/null || true
echo 'CLI smoke OK'
