"""
CresCent RAM Forensics Toolkit v4.0 - Network Map

Builds a deduplicated map of all network connections grouped by process,
identifies external IPs, attempts reverse DNS, and exports results.
"""

import ipaddress
import json
import logging
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from utils.json_converter import load_json_by_pattern


def _gv(item, *keys):
    # Exact match first
    for k in keys:
        if k in item:
            return item[k]
    # Case-insensitive fallback (Vol2/Vol3 column name variations)
    lower_map = {str(k).lower(): k for k in item}
    for k in keys:
        lk = str(k).lower()
        if lk in lower_map:
            return item[lower_map[lk]]
    return None


# Kept for any external imports that still reference the prefix list.
# Prefer _is_private_ip() below for new code — it handles 172.16/12 etc.
PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "0.0.0.0", "::", "*", "0:0")


def _is_private_ip(ip: str) -> bool:
    """True if the IP is private / loopback / link-local / CGNAT / placeholder.

    Uses the ipaddress module so RFC1918 172.16.0.0/12, link-local
    169.254.0.0/16, and CGNAT 100.64.0.0/10 are all correctly classified —
    something a simple string-prefix check misses. Falls back to placeholder
    string matches for wildcard tokens that Volatility emits ('*', '0:0', '::').
    """
    if not ip or ip in ("*", "0:0", "::", ""):
        return True
    # Strip brackets and any trailing port that slipped through.
    bare = ip.strip().strip("[]").split("%", 1)[0]  # also strip IPv6 zone id
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        # Not parseable — assume private to avoid leaking malformed garbage
        # into the "external IPs" list.
        return True
    if (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
        return True
    # CGNAT (RFC 6598) — 100.64.0.0/10. Python's is_private does NOT cover
    # this range because IANA classifies it as 'Shared Address Space',
    # but for forensic external-vs-internal triage we treat it as internal:
    # CGNAT addresses are never reachable from the public internet directly,
    # so a host talking to one is almost certainly on the same ISP NAT.
    if isinstance(addr, ipaddress.IPv4Address):
        if addr in ipaddress.IPv4Network("100.64.0.0/10"):
            return True
    return False


class NetworkMap:
    """Build a network connection map from Volatility JSON output."""

    def __init__(self, logger: logging.Logger, dns_timeout: float = 2.0):
        self.log = logger
        self.dns_timeout = dns_timeout
        self._connections: List[Dict[str, str]] = []
        self._external_ips: Set[str] = set()
        self._dns_cache: Dict[str, str] = {}

    def load(self, output_dir: Path) -> int:
        """Load network data from json/ directory.

        Returns:
            Number of connections loaded.
        """
        jd = output_dir / "json"
        if not jd.is_dir():
            return 0

        # Load process names for PID mapping
        pid_names: Dict[str, str] = {}
        for p in load_json_by_pattern(jd, "pslist"):
            pid = str(_gv(p, "PID", "pid", "Pid") or "")
            name = str(_gv(p, "ImageFileName", "Name", "Process", "name", "COMM", "Comm") or "")
            if pid:
                pid_names[pid] = name

        self._connections.clear()
        self._external_ips.clear()

        def _add(pid, proc_name, local, lport, remote, rport, proto, state):
            conn = {
                "pid": pid, "process": proc_name,
                "local": f"{local}:{lport}", "remote": f"{remote}:{rport}",
                "proto": proto, "state": state,
            }
            self._connections.append(conn)
            remote_ip = remote.split(":")[0].strip() if remote else ""
            if remote_ip and not _is_private_ip(remote_ip):
                self._external_ips.add(remote_ip)

        # Windows + generic sources
        for pat in ("netscan", "netstat", "connscan", "connections",
                     "sockscan", "sockets"):
            for n in load_json_by_pattern(jd, pat):
                pid = str(_gv(n, "PID", "pid", "Pid", "Owner Pid") or "")
                owner = _gv(n, "Owner", "owner", "Process") or ""
                _add(
                    pid, pid_names.get(pid, str(owner)),
                    str(_gv(n, "LocalAddr", "Local Address", "LocalAddress", "Local IP", "Local") or ""),
                    str(_gv(n, "LocalPort", "Local Port") or ""),
                    str(_gv(n, "ForeignAddr", "Foreign Address", "RemoteAddr",
                             "Remote IP", "Remote", "Foreign") or ""),
                    str(_gv(n, "ForeignPort", "Foreign Port", "RemotePort", "Remote Port") or ""),
                    str(_gv(n, "Proto", "Protocol", "proto", "Type") or "TCP"),
                    str(_gv(n, "State", "state") or ""),
                )

        # Linux Vol3 sockstat — Source/Destination Addr/Port field names
        for n in load_json_by_pattern(jd, "sockstat"):
            pid = str(_gv(n, "PID", "pid") or "")
            process = str(_gv(n, "Process", "process", "Name", "name") or "")
            _add(
                pid, pid_names.get(pid, process),
                str(_gv(n, "Source Addr", "Source Address", "SrcAddr", "LocalAddr") or ""),
                str(_gv(n, "Source Port", "SrcPort", "LocalPort") or ""),
                str(_gv(n, "Destination Addr", "Destination Address",
                        "DstAddr", "ForeignAddr") or ""),
                str(_gv(n, "Destination Port", "DstPort", "ForeignPort") or ""),
                str(_gv(n, "Socket Type", "Type", "Proto", "proto") or "SOCK"),
                str(_gv(n, "State", "state") or ""),
            )

        # Linux lsof socket entries (Vol3 fields: Path, Type, Process, PID)
        for entry in load_json_by_pattern(jd, "lsof"):
            path_field = str(_gv(entry, "Path", "Name", "name", "FILE") or "")
            file_type = str(_gv(entry, "Type", "type") or "")
            if not (file_type.upper() in ("SOCK", "IPV4", "IPV6")
                    or "->" in path_field):
                continue
            pid = str(_gv(entry, "PID", "pid") or "")
            proc = str(_gv(entry, "Process", "COMMAND", "Command", "name") or "")
            remote = path_field.split("->")[1].strip() if "->" in path_field else ""
            _add(pid, pid_names.get(pid, proc), "", "", remote, "", file_type, "")

        self.log.info("Network map: %d connections, %d external IPs",
                      len(self._connections), len(self._external_ips))
        return len(self._connections)

    def resolve_dns(self) -> Dict[str, str]:
        """Attempt reverse DNS on all external IPs.

        Returns:
            Dict of IP -> hostname (or 'N/A' if resolution fails).
        """
        self.log.info("Resolving %d external IPs...", len(self._external_ips))
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.dns_timeout)

        for ip in sorted(self._external_ips):
            if ip in self._dns_cache:
                continue
            try:
                host, _, _ = socket.gethostbyaddr(ip)
                self._dns_cache[ip] = host
                self.log.info("  %s -> %s", ip, host)
            except (socket.herror, socket.gaierror, socket.timeout, OSError):
                self._dns_cache[ip] = "N/A"

        socket.setdefaulttimeout(old_timeout)
        return dict(self._dns_cache)

    def get_by_process(self) -> Dict[str, List[Dict]]:
        """Group connections by process.

        Returns:
            Dict of 'PID:name' -> list of connection dicts.
        """
        grouped: Dict[str, List[Dict]] = {}
        for c in self._connections:
            key = f"{c['pid']}:{c['process']}"
            grouped.setdefault(key, []).append(c)
        return dict(sorted(grouped.items()))

    def get_external_only(self) -> List[Dict[str, str]]:
        """Return only connections with external (non-private) remote IPs.

        Returns:
            Filtered connection list.
        """
        result = []
        for c in self._connections:
            remote_ip = c["remote"].split(":")[0].strip()
            if remote_ip and not _is_private_ip(remote_ip):
                result.append(c)
        return result

    def write_report(self, output_dir: Path, do_dns: bool = True) -> Path:
        """Write network map report (TXT + JSON).

        Args:
            output_dir: Output directory.
            do_dns: Attempt reverse DNS resolution.

        Returns:
            Path to the TXT report.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if do_dns and self._external_ips:
            self.resolve_dns()

        txt_path = output_dir / "network_map.txt"
        json_dir = output_dir / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        json_path = json_dir / "network_map.json"

        # TXT report
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  NETWORK MAP\n")
            f.write(f"  Total connections: {len(self._connections)}\n")
            f.write(f"  External IPs: {len(self._external_ips)}\n")
            f.write("=" * 80 + "\n\n")

            # External IPs with DNS
            f.write("--- EXTERNAL IPs ---\n\n")
            if self._external_ips:
                for ip in sorted(self._external_ips):
                    host = self._dns_cache.get(ip, "")
                    dns_str = f" -> {host}" if host and host != "N/A" else ""
                    f.write(f"  {ip}{dns_str}\n")
            else:
                f.write("  None\n")
            f.write("\n")

            # By process
            f.write("--- CONNECTIONS BY PROCESS ---\n\n")
            grouped = self.get_by_process()
            for proc_key, conns in grouped.items():
                ext_count = sum(1 for c in conns
                                if not _is_private_ip(c["remote"].split(":")[0]))
                f.write(f"  [{proc_key}] ({len(conns)} conn, {ext_count} external)\n")
                for c in conns:
                    remote_ip = c["remote"].split(":")[0].strip()
                    dns = self._dns_cache.get(remote_ip, "")
                    dns_str = f" ({dns})" if dns and dns != "N/A" else ""
                    f.write(f"    {c['proto']:5s} {c['local']:25s} -> "
                            f"{c['remote']}{dns_str} [{c['state']}]\n")
                f.write("\n")

            # External connections summary
            f.write("--- EXTERNAL CONNECTIONS ---\n\n")
            ext = self.get_external_only()
            if ext:
                for c in ext:
                    remote_ip = c["remote"].split(":")[0].strip()
                    dns = self._dns_cache.get(remote_ip, "")
                    dns_str = f" ({dns})" if dns and dns != "N/A" else ""
                    f.write(f"  [{c['pid']}] {c['process']:20s} "
                            f"{c['remote']}{dns_str} [{c['state']}]\n")
            else:
                f.write("  None\n")
            f.write("\n" + "=" * 80 + "\n")

        # JSON report
        report = {
            "total_connections": len(self._connections),
            "external_ips": {ip: self._dns_cache.get(ip, "N/A")
                             for ip in sorted(self._external_ips)},
            "connections": self._connections,
            "by_process": {k: v for k, v in self.get_by_process().items()},
        }
        json_path.write_text(json.dumps(report, indent=2, default=str),
                             encoding="utf-8")

        self.log.info("Network map: %s, %s", txt_path, json_path)
        return txt_path

    @property
    def external_ips(self) -> Set[str]:
        return self._external_ips

    @property
    def connections(self) -> List[Dict[str, str]]:
        return self._connections
