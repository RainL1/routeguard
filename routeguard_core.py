#!/usr/bin/env python3
"""
RouteGuard Auto Suite core.
Protects against TunnelVision-like VPN bypass by applying nftables kill-switch rules
derived automatically from a WireGuard config and monitoring route table changes.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import signal
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

ROUTEGUARD_TABLE_FAMILY = "inet"
ROUTEGUARD_TABLE_NAME = "routeguard"
DEFAULT_INTERVAL = 5
PRIVATE_V4_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
PRIVATE_V6_CIDR = "fc00::/7"
LINK_LOCAL_V6 = ["fe80::/10", "ff00::/8"]
STATE_PATHS = [Path("/run/routeguard-auto/state.json"), Path("/tmp/routeguard-auto-state.json")]


class RouteGuardError(RuntimeError):
    """Base runtime exception used by RouteGuard core operations."""
    pass


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def default_logger(msg: str) -> None:
    print(f"[{timestamp()}] {msg}", flush=True)


@dataclass
class EndpointRule:
    ip: str
    port: int
    proto: str = "udp"


@dataclass
class GeneratedConfig:
    mode: str
    vpn_iface: str
    poll_interval_sec: int = DEFAULT_INTERVAL
    allow_lan: bool = True
    allow_dhcp: bool = True
    vpn_endpoints: List[EndpointRule] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["vpn_endpoints"] = [asdict(e) for e in (self.vpn_endpoints or [])]
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


def run_cmd(args: List[str], *, check: bool = True, capture_output: bool = True, text: bool = True, input_data: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, capture_output=capture_output, text=text, input=input_data)


def command_exists(cmd: str) -> bool:
    from shutil import which
    return which(cmd) is not None


def parse_wireguard_config(path: str) -> dict:
    """Parse a WireGuard .conf file and return interface/peer sections."""
    p = Path(path)
    if not p.exists():
        raise RouteGuardError(f"WireGuard config not found: {path}")
    interface: Dict[str, str] = {}
    peers: List[Dict[str, str]] = []
    current_section: Optional[str] = None
    current_peer: Optional[Dict[str, str]] = None
    for raw_line in p.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or line.startswith(';'):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1].strip().lower()
            if section == 'interface':
                current_section = 'interface'; current_peer = None
            elif section == 'peer':
                current_section = 'peer'; current_peer = {}; peers.append(current_peer)
            else:
                current_section = None; current_peer = None
            continue
        if '=' not in line:
            continue
        key, value = [x.strip() for x in line.split('=', 1)]
        if current_section == 'interface':
            interface[key] = value
        elif current_section == 'peer' and current_peer is not None:
            current_peer[key] = value
    if not peers:
        raise RouteGuardError('No [Peer] section found in WireGuard config.')
    return {'interface': interface, 'peers': peers}


def infer_iface_name_from_wg_path(path: str) -> str:
    name = Path(path).name
    return name[:-5] if name.endswith('.conf') else name


def parse_endpoint(endpoint: str) -> Tuple[str, int]:
    endpoint = endpoint.strip()
    if endpoint.startswith('['):
        m = re.match(r'^\[(.+)\]:(\d+)$', endpoint)
        if not m:
            raise RouteGuardError(f'Invalid endpoint format: {endpoint}')
        return m.group(1), int(m.group(2))
    if endpoint.count(':') == 1:
        host, port = endpoint.rsplit(':', 1)
        if not port.isdigit():
            raise RouteGuardError(f'Invalid endpoint port: {endpoint}')
        return host, int(port)
    raise RouteGuardError(f'Unsupported endpoint format: {endpoint}')


def resolve_host_ips(host: str) -> List[str]:
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            return [host]
        except OSError:
            pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_UDP)
    except socket.gaierror as e:
        raise RouteGuardError(f"Cannot resolve endpoint host '{host}': {e}") from e
    ips: List[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise RouteGuardError(f'No IPs resolved for {host}')
    return ips


def build_generated_config_from_wg(wg_config_path: str, *, mode: str='monitor', vpn_iface: Optional[str]=None, allow_lan: bool=True, allow_dhcp: bool=True, poll_interval_sec: int=DEFAULT_INTERVAL) -> GeneratedConfig:
    """Create a normalized RouteGuard configuration from a WireGuard config file."""
    data = parse_wireguard_config(wg_config_path)
    iface_name = vpn_iface or infer_iface_name_from_wg_path(wg_config_path)
    endpoints: List[EndpointRule] = []
    seen = set()
    for peer in data['peers']:
        ep = peer.get('Endpoint')
        if not ep:
            continue
        host, port = parse_endpoint(ep)
        for ip in resolve_host_ips(host):
            key = (ip, int(port), 'udp')
            if key not in seen:
                seen.add(key)
                endpoints.append(EndpointRule(ip=ip, port=int(port), proto='udp'))
    if not endpoints:
        raise RouteGuardError('No Peer Endpoint found in WireGuard config.')
    return GeneratedConfig(mode=mode, vpn_iface=iface_name, poll_interval_sec=max(1, int(poll_interval_sec)), allow_lan=allow_lan, allow_dhcp=allow_dhcp, vpn_endpoints=endpoints)


def interface_exists(iface: str) -> bool:
    return run_cmd(['ip', 'link', 'show', iface], check=False).returncode == 0


def build_nft_script(cfg: GeneratedConfig) -> str:
    """Build an nftables script implementing a RouteGuard output kill-switch."""
    iface = cfg.vpn_iface.replace('"', '')
    lines = [
        f'table {ROUTEGUARD_TABLE_FAMILY} {ROUTEGUARD_TABLE_NAME} {{',
        '  chain rg_output {',
        '    type filter hook output priority filter; policy accept;',
        '    oifname "lo" accept',
        f'    oifname "{iface}" accept',
        f"    ip6 daddr {{ {', '.join(LINK_LOCAL_V6)} }} accept",
    ]
    if cfg.allow_dhcp:
        lines += ['    udp sport 68 udp dport 67 accept', '    udp sport 546 udp dport 547 accept']
    if cfg.allow_lan:
        lines += [f"    ip daddr {{ {', '.join(PRIVATE_V4_CIDRS)} }} accept", f'    ip6 daddr {PRIVATE_V6_CIDR} accept']
    for ep in (cfg.vpn_endpoints or []):
        fam = 'ip6' if ':' in ep.ip else 'ip'
        proto = ep.proto.lower()
        lines.append(f'    {fam} daddr {ep.ip} {proto} dport {int(ep.port)} accept')
    lines += [f'    oifname != "{iface}" drop', '  }', '}']
    return '\n'.join(lines) + '\n'


def routeguard_table_exists() -> bool:
    return run_cmd(['nft', 'list', 'table', ROUTEGUARD_TABLE_FAMILY, ROUTEGUARD_TABLE_NAME], check=False).returncode == 0 if command_exists('nft') else False


def apply_nft_rules(cfg: GeneratedConfig, logger: Callable[[str], None]=default_logger) -> None:
    """Apply RouteGuard nftables rules for the provided generated config."""
    if not command_exists('nft'):
        raise RouteGuardError('nft command not found. Install nftables.')
    # Remove previous ruleset safely (ignored if table is absent).
    remove_nft_rules(logger=lambda _msg: None)
    script = build_nft_script(cfg)
    cp = run_cmd(['nft', '-f', '-'], check=False, input_data=script)
    if cp.returncode != 0:
        err = (cp.stderr or cp.stdout or '').strip()
        raise RouteGuardError(f'nft failed to apply rules: {err or "unknown error"}')
    if not routeguard_table_exists():
        raise RouteGuardError('Failed to apply nft rules (table inet routeguard missing).')
    logger(f"Applied nftables rules for iface '{cfg.vpn_iface}' ({len(cfg.vpn_endpoints or [])} endpoint rule(s)).")


def remove_nft_rules(logger: Callable[[str], None]=default_logger) -> None:
    """Remove the RouteGuard nftables table if it exists."""
    if not command_exists('nft'):
        return
    cp = run_cmd(['nft', 'delete', 'table', ROUTEGUARD_TABLE_FAMILY, ROUTEGUARD_TABLE_NAME], check=False)
    if cp.returncode == 0:
        logger('Removed nftables table inet routeguard.')
    else:
        logger('nftables table inet routeguard was not present (nothing to remove).')


def ip_json_routes(ipv6: bool=False) -> List[dict]:
    args = ['ip', '-j']
    if ipv6:
        args.append('-6')
    args += ['route', 'show', 'table', 'main']
    cp = run_cmd(args, check=False)
    if cp.returncode != 0:
        return []
    try:
        data = json.loads(cp.stdout or '[]')
        return data if isinstance(data, list) else []
    except Exception:
        return []


def suspicious_routes(routes: List[dict], vpn_iface: str, ipv6: bool=False) -> List[str]:
    """Detect split-default routes routed via a non-VPN interface."""
    targets = {'::/1', '8000::/1'} if ipv6 else {'0.0.0.0/1', '128.0.0.0/1'}
    out: List[str] = []
    for r in routes:
        dst = r.get('dst')
        dev = r.get('dev') or r.get('oif') or ''
        if dst in targets and dev and dev != vpn_iface:
            out.append(f"{dst} via dev={dev} gateway={r.get('gateway', '-')}")
    return out


def check_dependencies(require_tk: bool=False) -> List[str]:
    missing = [cmd for cmd in ('ip', 'nft') if not command_exists(cmd)]
    if require_tk:
        try:
            import tkinter  # noqa: F401
        except Exception:
            missing.append('python-tk')
    return missing


def wg_quick_up(iface: str, logger: Callable[[str], None]=default_logger) -> None:
    if not command_exists('wg-quick'):
        raise RouteGuardError('wg-quick not found. Install wireguard-tools.')
    cp = run_cmd(['wg-quick', 'up', iface], check=False)
    out = (cp.stdout or '') + (cp.stderr or '')
    if cp.returncode != 0 and 'already exists' not in out and 'already up' not in out:
        raise RouteGuardError(f'wg-quick up {iface} failed:\n{out.strip()}')
    logger(f"WireGuard interface '{iface}' is up (or already up).")


def wg_quick_down(iface: str, logger: Callable[[str], None]=default_logger) -> None:
    if not command_exists('wg-quick'):
        return
    cp = run_cmd(['wg-quick', 'down', iface], check=False)
    out = (cp.stdout or '') + (cp.stderr or '')
    if cp.returncode == 0:
        logger(f"WireGuard interface '{iface}' is down.")
    else:
        logger(f"wg-quick down {iface}: {out.strip() or 'no action'}")


def _state_path() -> Path:
    for p in STATE_PATHS:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            return p
        except Exception:
            continue
    return Path('/tmp/routeguard-auto-state.json')


def write_state(cfg: GeneratedConfig, extra: Optional[dict]=None) -> Path:
    p = _state_path()
    payload = {'pid': os.getpid(), 'started_at': timestamp(), 'config': cfg.to_dict()}
    if extra:
        payload.update(extra)
    p.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return p


def read_state() -> Optional[dict]:
    for p in STATE_PATHS:
        if p.exists():
            try:
                return json.loads(p.read_text(encoding='utf-8'))
            except Exception:
                return None
    return None


def remove_state() -> None:
    for p in STATE_PATHS:
        try:
            p.unlink()
        except Exception:
            pass


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


class RouteGuardRunner:
    """Foreground runner that manages lifecycle, monitoring, and cleanup."""

    def __init__(self, cfg: GeneratedConfig, *, logger: Callable[[str], None]=default_logger, auto_up_vpn: bool=False, auto_down_vpn_on_exit: bool=False, cleanup_nft_on_exit: bool=True):
        self.cfg = cfg
        self.logger = logger
        self.auto_up_vpn = auto_up_vpn
        self.auto_down_vpn_on_exit = auto_down_vpn_on_exit
        self.cleanup_nft_on_exit = cleanup_nft_on_exit
        self.stop_event = threading.Event()
        self._signal_installed = False

    def request_stop(self) -> None:
        self.stop_event.set()

    def _install_signals(self) -> None:
        if threading.current_thread() is not threading.main_thread() or self._signal_installed:
            return
        def _handler(signum, frame):
            self.logger(f'Signal {signum} received, stopping...')
            self.stop_event.set()
        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)
        self._signal_installed = True

    def _wait_for_iface(self, timeout_sec: int=10) -> None:
        t0 = time.time()
        while time.time() - t0 < timeout_sec:
            if interface_exists(self.cfg.vpn_iface):
                return
            time.sleep(0.5)
        raise RouteGuardError(f"VPN interface '{self.cfg.vpn_iface}' not found.")

    def run(self) -> int:
        """Run the monitoring/protection loop until stop is requested."""
        self._install_signals()
        self.logger(f"RouteGuard starting: mode={self.cfg.mode}, iface={self.cfg.vpn_iface}, interval={self.cfg.poll_interval_sec}s")
        self.logger('Endpoints: ' + ', '.join([f"{e.ip}:{e.port}/{e.proto}" for e in (self.cfg.vpn_endpoints or [])]))
        try:
            if self.auto_up_vpn:
                wg_quick_up(self.cfg.vpn_iface, self.logger)
            if self.cfg.mode == 'protect':
                self._wait_for_iface()
                apply_nft_rules(self.cfg, self.logger)
            elif self.cfg.mode == 'monitor':
                self.logger('Monitor mode: no nftables blocking rules will be applied.')
            elif self.cfg.mode == 'off':
                remove_nft_rules(self.logger)
                self.logger('Off mode: exiting.')
                return 0
            else:
                raise RouteGuardError(f'Unknown mode: {self.cfg.mode}')
            statep = write_state(self.cfg)
            self.logger(f'State file: {statep}')
            warned = set()
            while not self.stop_event.is_set():
                if self.cfg.mode == 'protect' and not routeguard_table_exists():
                    self.logger('WARNING: nft table missing, re-applying rules.')
                    apply_nft_rules(self.cfg, self.logger)
                current = set(suspicious_routes(ip_json_routes(False), self.cfg.vpn_iface, False) + suspicious_routes(ip_json_routes(True), self.cfg.vpn_iface, True))
                for msg in sorted(current - warned):
                    self.logger('ALERT suspicious route detected: ' + msg)
                warned = current
                for _ in range(max(1, int(self.cfg.poll_interval_sec * 10))):
                    if self.stop_event.is_set():
                        break
                    time.sleep(0.1)
            self.logger('Stopping RouteGuard...')
            return 0
        finally:
            try:
                if self.cleanup_nft_on_exit and self.cfg.mode == 'protect':
                    remove_nft_rules(self.logger)
            finally:
                if self.auto_down_vpn_on_exit:
                    try:
                        wg_quick_down(self.cfg.vpn_iface, self.logger)
                    except Exception as e:
                        self.logger(f'WARNING wg-quick down failed: {e}')
                remove_state()


def ensure_root_if_needed(mode: str) -> None:
    if mode in ('protect', 'monitor', 'off') and os.geteuid() != 0:
        raise RouteGuardError('Please run as root (sudo).')


def status_summary() -> dict:
    """Return a compact runtime status summary used by CLI/GUI."""
    return {'routeguard_nft_table_present': routeguard_table_exists(), 'state': read_state()}
