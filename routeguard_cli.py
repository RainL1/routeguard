#!/usr/bin/env python3
"""Command-line interface for RouteGuard Auto Suite.

This module exposes an argparse-based CLI for generating configuration from a
WireGuard file, launching the protection/monitoring runner, printing status,
and cleaning up nftables rules.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from routeguard_core import (
    RouteGuardError,
    RouteGuardRunner,
    build_generated_config_from_wg,
    check_dependencies,
    default_logger,
    ensure_root_if_needed,
    process_alive,
    read_state,
    remove_nft_rules,
    status_summary,
)


def eprint(msg: str) -> None:
    """Print a message to stderr and flush immediately."""
    print(msg, file=sys.stderr, flush=True)


def parse_args() -> argparse.Namespace:
    """Build and parse CLI arguments for all supported subcommands."""
    p = argparse.ArgumentParser(prog='routeguard-cli', description='Auto-configuring RouteGuard (CLI) for WireGuard configs')
    sub = p.add_subparsers(dest='cmd', required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--wg-config', required=True, help='Path to WireGuard .conf')
    common.add_argument('--iface', help='Override VPN interface name (default: infer from file name)')
    common.add_argument('--mode', choices=['monitor', 'protect', 'off'], default='monitor')
    common.add_argument('--interval', type=int, default=5)
    common.add_argument('--no-allow-lan', action='store_true')
    common.add_argument('--no-allow-dhcp', action='store_true')

    rp = sub.add_parser('run', parents=[common], help='Run RouteGuard in foreground using generated config')
    rp.add_argument('--up-vpn', action='store_true', help='Run wg-quick up <iface> before starting')
    rp.add_argument('--down-vpn-on-exit', action='store_true')
    rp.add_argument('--no-cleanup', action='store_true', help='Do not remove nft rules on exit')
    rp.add_argument('--save-generated-config', help='Save generated JSON config to file')
    rp.add_argument('--print-generated', action='store_true')

    pp = sub.add_parser('print-config', parents=[common], help='Print generated RouteGuard config and exit')
    pp.add_argument('--save', help='Save generated config to file')

    sub.add_parser('status', help='Show status')
    sub.add_parser('cleanup', help='Remove nft rules only')
    sub.add_parser('stop', help='Signal running instance (if known) and remove nft rules')
    return p.parse_args()


def make_cfg(ns: argparse.Namespace):
    return build_generated_config_from_wg(
        ns.wg_config,
        mode=ns.mode,
        vpn_iface=ns.iface,
        allow_lan=not ns.no_allow_lan,
        allow_dhcp=not ns.no_allow_dhcp,
        poll_interval_sec=ns.interval,
    )


def cmd_run(ns: argparse.Namespace) -> int:
    ensure_root_if_needed(ns.mode)
    missing = check_dependencies()
    if missing:
        raise RouteGuardError('Missing dependencies: ' + ', '.join(missing))
    cfg = make_cfg(ns)
    if ns.print_generated:
        print(cfg.to_json())
    if ns.save_generated_config:
        Path(ns.save_generated_config).write_text(cfg.to_json() + '\n', encoding='utf-8')
        default_logger(f'Saved generated config to {ns.save_generated_config}')
    runner = RouteGuardRunner(cfg, logger=default_logger, auto_up_vpn=ns.up_vpn, auto_down_vpn_on_exit=ns.down_vpn_on_exit, cleanup_nft_on_exit=not ns.no_cleanup)
    return runner.run()


def cmd_print(ns: argparse.Namespace) -> int:
    cfg = make_cfg(ns)
    print(cfg.to_json())
    if ns.save:
        Path(ns.save).write_text(cfg.to_json() + '\n', encoding='utf-8')
        default_logger(f'Saved generated config to {ns.save}')
    return 0


def cmd_status() -> int:
    st = status_summary()
    print(json.dumps(st, indent=2, ensure_ascii=False))
    state = st.get('state') or {}
    pid = state.get('pid')
    if pid is not None:
        print(f'Process PID {pid} alive: {process_alive(int(pid))}')
    return 0


def cmd_cleanup() -> int:
    ensure_root_if_needed('protect')
    remove_nft_rules()
    return 0


def cmd_stop() -> int:
    ensure_root_if_needed('protect')
    state = read_state()
    if state and 'pid' in state:
        pid = int(state['pid'])
        try:
            os.kill(pid, 15)
            default_logger(f'Sent SIGTERM to RouteGuard PID {pid}')
        except ProcessLookupError:
            default_logger(f'PID {pid} is not running.')
        except PermissionError:
            default_logger(f'No permission to signal PID {pid}.')
    else:
        default_logger('No RouteGuard state file found.')
    remove_nft_rules()
    return 0


def main() -> int:
    """CLI entry point. Returns process exit code."""
    try:
        ns = parse_args()
        if ns.cmd == 'run':
            return cmd_run(ns)
        if ns.cmd == 'print-config':
            return cmd_print(ns)
        if ns.cmd == 'status':
            return cmd_status()
        if ns.cmd == 'cleanup':
            return cmd_cleanup()
        if ns.cmd == 'stop':
            return cmd_stop()
        raise RouteGuardError(f'Unknown command: {ns.cmd}')
    except KeyboardInterrupt:
        return 130
    except RouteGuardError as e:
        eprint('ERROR: ' + str(e))
        return 1
    except Exception as e:
        eprint('UNEXPECTED ERROR: ' + str(e))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
