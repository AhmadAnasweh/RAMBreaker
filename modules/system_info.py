"""
CresCent RAM Forensics Toolkit v4.0 - System Info Extractor

Extracts key system information from memory:
  - Hostname / Workstation name
  - Username(s) / logged-in users
  - IP address(es)
  - OS version / build
  - Domain name
  - Last boot time

Sources:
  1. Vol3 windows.info.Info JSON (OS version, build)
  2. Vol3 windows.registry.hivelist (registry hives)
  3. Vol3 windows.envars.Envars (COMPUTERNAME, USERNAME, USERDOMAIN)
  4. Vol3 windows.getsids.GetSIDs (user SIDs → usernames)
  5. Vol3 windows.netstat/netscan (local IP addresses)
  6. Strings scan for hostname/IP patterns (fallback)
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

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


class SystemInfo:
    """Extract system identification info from memory forensics data."""

    def __init__(self, logger: logging.Logger):
        self.log = logger
        self._info: Dict[str, Any] = {
            "hostname": "",
            "domain": "",
            "os_version": "",
            "os_build": "",
            "architecture": "",
            "boot_time": "",
            "usernames": [],
            "ip_addresses": [],
            "mac_addresses": [],
        }

    def load(self, output_dir: Path) -> Dict[str, Any]:
        """Load system info from all available sources.

        Args:
            output_dir: Base analysis output directory with json/ subfolder.

        Returns:
            Dict with system information.
        """
        od = Path(output_dir)
        jd = od / "json"

        self._info = {
            "hostname": "",
            "domain": "",
            "os_version": "",
            "os_build": "",
            "architecture": "",
            "boot_time": "",
            "usernames": [],
            "ip_addresses": [],
            "mac_addresses": [],
        }

        if jd.is_dir():
            self._from_windows_info(jd)   # no-op on Linux (file not found)
            self._from_envars(jd)         # works for both: same Variable/Value schema
            self._from_getsids(jd)        # no-op on Linux
            self._from_hashdump(jd)       # Windows usernames from hashdump
            self._from_file_paths(jd)     # users from \Users\ /home/ /Users/ paths (any mode)
            self._from_registry_hostname(jd)  # Windows hostname from registry printkey
            self._from_network(jd)        # now covers sockstat (Linux) too
            self._from_linux_pslist(jd)   # boot time + arch from PID 1 (no-op on Windows)
            self._from_linux_kernel(jd)   # kernel version from linux_resolver (no-op on Windows)

        # Fallback: scan SUMMARY.txt
        summary = od / "SUMMARY.txt"
        if summary.exists():
            self._from_summary(summary)

        # Fallback: scan strings for hostname/IP
        for sf in ("strings_ascii.txt", "strings.txt"):
            sp = od / sf
            if sp.exists() and not self._info["hostname"]:
                self._from_strings(sp)
                break

        # Deduplicate
        self._info["usernames"] = sorted(set(self._info["usernames"]))
        self._info["ip_addresses"] = sorted(set(self._info["ip_addresses"]))
        self._info["mac_addresses"] = sorted(set(self._info["mac_addresses"]))

        self.log.info("System Info: hostname=%s, users=%d, IPs=%d",
                      self._info["hostname"] or "unknown",
                      len(self._info["usernames"]),
                      len(self._info["ip_addresses"]))
        return self._info

    def _from_windows_info(self, jd: Path):
        """Extract from windows.info.Info JSON."""
        # Use "windows_info" pattern to avoid matching system_info.json first
        # (load_json_by_pattern returns on first hit, alphabetically s < w)
        items = load_json_by_pattern(jd, "windows_info")
        if not items:
            items = load_json_by_pattern(jd, "windows.info")
        for item in items:
            # Vol3 windows.info outputs key-value pairs
            key = str(_gv(item, "Variable", "variable", "Key", "key") or "")
            val = str(_gv(item, "Value", "value") or "")

            if not key and not val:
                # Sometimes it's flat fields
                for k, v in item.items():
                    if "NTBuildLab" in k:
                        self._info["os_build"] = str(v)
                    elif "NTMajorVersion" in str(k):
                        self._info["os_version"] = f"Windows NT {v}"
                    elif "Is64Bit" in k:
                        self._info["architecture"] = "x64" if v else "x86"
                    elif "SystemTime" in k:
                        self._info["boot_time"] = str(v)
                continue

            key_lower = key.lower()
            if "ntbuildlab" in key_lower:
                self._info["os_build"] = val
            elif "ntmajorversion" in key_lower or "major" in key_lower:
                if val and not self._info["os_version"]:
                    self._info["os_version"] = f"Windows NT {val}"
            elif "is64bit" in key_lower:
                self._info["architecture"] = "x64" if val.lower() in ("true", "1", "yes") else "x86"
            elif "systemtime" in key_lower:
                self._info["boot_time"] = val
            elif "machine" in key_lower or "processor" in key_lower:
                if "64" in val:
                    self._info["architecture"] = "x64"

    def _from_envars(self, jd: Path):
        """Extract from envars JSON (Windows and Linux both use 'Variable'/'Value')."""
        _skip_users = {"system", "local service", "network service", "defaultuser0",
                       "root", "nobody", "daemon"}
        for item in load_json_by_pattern(jd, "envars"):
            var = str(_gv(item, "Variable", "variable", "Name", "name") or "").upper()
            val = str(_gv(item, "Value", "value") or "").strip()

            if not var or not val:
                continue

            # --- Hostname ---
            if var in ("COMPUTERNAME", "HOSTNAME") and not self._info["hostname"]:
                self._info["hostname"] = val
                self.log.debug("Hostname from envars: %s", val)

            # --- Users (Windows: USERNAME; Linux: USER, LOGNAME) ---
            elif var in ("USERNAME", "USER", "LOGNAME"):
                if val.lower() not in _skip_users:
                    self._info["usernames"].append(val)

            # --- Domain (Windows only) ---
            elif var == "USERDOMAIN" and not self._info["domain"]:
                self._info["domain"] = val
            elif var == "USERDOMAIN_ROAMINGPROFILE" and not self._info["domain"]:
                self._info["domain"] = val
            elif var == "LOGONSERVER" and not self._info["domain"]:
                self._info["domain"] = val.replace("\\\\", "")

            # --- OS version (Windows: OS; Linux: PRETTY_NAME, DISTRIB_DESCRIPTION) ---
            elif var in ("OS", "PRETTY_NAME", "DISTRIB_DESCRIPTION") and not self._info["os_version"]:
                self._info["os_version"] = val

            # --- Architecture (Windows: PROCESSOR_ARCHITECTURE; Linux: HOSTTYPE, MACHTYPE) ---
            elif var in ("PROCESSOR_ARCHITECTURE", "HOSTTYPE", "MACHTYPE"):
                if "64" in val or "x86_64" in val or "aarch64" in val:
                    self._info["architecture"] = "x64"
                elif "86" in val:
                    self._info["architecture"] = "x86"

    def _from_getsids(self, jd: Path):
        """Extract usernames from windows.getsids.GetSIDs JSON."""
        seen_sids = set()
        for item in load_json_by_pattern(jd, "getsids"):
            sid = str(_gv(item, "SID", "sid") or "")
            name = str(_gv(item, "Name", "name") or "")

            if not sid or sid in seen_sids:
                continue
            seen_sids.add(sid)

            # User SIDs end with -1001, -1002, etc. (RID >= 1000)
            parts = sid.split("-")
            if len(parts) >= 4:
                try:
                    rid = int(parts[-1])
                    if rid >= 1000 and name:
                        # Extract username from "DOMAIN\User" format
                        if "\\" in name:
                            domain, user = name.rsplit("\\", 1)
                            self._info["usernames"].append(user)
                            if not self._info["domain"]:
                                self._info["domain"] = domain
                        else:
                            self._info["usernames"].append(name)
                except ValueError:
                    pass

    def _from_hashdump(self, jd: Path):
        """Windows usernames from hashdump (User:RID:LM:NT).

        A valid entry has a NUMERIC RID; this filters out Vol2 banner/error lines
        (e.g. '*** Failed to import ...') that the text parser can leave in the JSON.
        """
        _skip = {"guest", "defaultaccount", "wdagutilityaccount", ""}
        for item in load_json_by_pattern(jd, "hashdump"):
            user = str(_gv(item, "User", "user", "Username", "username") or "").strip()
            rid = str(_gv(item, "RID", "rid") or "").strip()
            if not user or not rid:
                parts = str(_gv(item, "raw") or "").split(":")
                if len(parts) >= 4 and parts[1].strip().isdigit():
                    user, rid = parts[0].strip(), parts[1].strip()
                else:
                    continue
            if (not rid.isdigit() or user.lower() in _skip
                    or user.startswith("$")
                    or not re.match(r'^[A-Za-z0-9._$ -]{1,32}$', user)):
                continue
            self._info["usernames"].append(user)

    # Home-dir path segments that are NOT real user accounts.
    _PATH_SKIP_USERS = {
        "all users", "default", "default user", "public", "shared", "guest",
        ".", "..", "desktop.ini", "localservice", "network service",
        "networkservice", "local service", "systemprofile", "root", "nobody",
    }

    def _from_file_paths(self, jd: Path):
        """Derive usernames from home-directory paths in file listings.

        Works in ANY mode (fast/plugins included) because it uses the file-listing
        plugins that are always present: Windows filescan (\\Users\\<name>\\),
        Linux pagecache/lsof (/home/<name>/), macOS list_files (/Users/<name>/).
        """
        rx = [re.compile(r'[\\/]Users[\\/]([^\\/]+)[\\/]', re.IGNORECASE),  # Win + macOS
              re.compile(r'/home/([^/]+)/', re.IGNORECASE)]                  # Linux
        found: Set[str] = set()
        for jpat in ("filescan", "pagecache", "lsof", "list_files", "mac_file"):
            for item in load_json_by_pattern(jd, jpat):
                p = str(_gv(item, "Name", "name", "Path", "path", "FilePath",
                            "File Path", "file_path") or "")
                if not p:
                    continue
                for r in rx:
                    m = r.search(p)
                    if m:
                        u = m.group(1).strip()
                        if u and u.lower() not in self._PATH_SKIP_USERS and 0 < len(u) <= 40:
                            found.add(u)
        for u in sorted(found):
            self._info["usernames"].append(u)

    def _from_registry_hostname(self, jd: Path):
        """Windows hostname from a registry ComputerName value in printkey output."""
        if self._info["hostname"]:
            return
        for jpat in ("printkey", "registry"):
            for item in load_json_by_pattern(jd, jpat):
                name = str(_gv(item, "Value Name", "ValName", "Name", "name") or "")
                if name.lower() in ("computername", "activecomputername", "hostname"):
                    data = str(_gv(item, "Data", "ValData", "Value", "value") or "").strip()
                    data = data.strip("\x00").strip()
                    if data:
                        self._info["hostname"] = data
                        self.log.debug("Hostname from registry ComputerName: %s", data)
                        return

    def _from_network(self, jd: Path):
        """Extract IP addresses from network plugins (Windows and Linux)."""
        _skip_ips = {"0.0.0.0", "*", "::", "127.0.0.1", "127.0.0.53", ""}
        # Windows: netscan/netstat/connscan; Linux: sockstat/lsof
        for pat in ("netscan", "netstat", "connscan", "connections", "sockstat", "lsof"):
            for item in load_json_by_pattern(jd, pat):
                # Windows / Linux sockstat / macOS mac.netstat field names
                local = str(_gv(item, "LocalAddr", "Local Address", "LocalAddress",
                                "Local IP", "Source Addr", "Source") or "")
                if not local or local in _skip_ips:
                    continue
                # Strip port (Windows: "1.2.3.4:80"; Linux sockstat: "1.2.3.4")
                ip = local.rsplit(":", 1)[0].strip().strip("[]")
                if ip and ip not in _skip_ips and not ip.startswith("127."):
                    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
                        self._info["ip_addresses"].append(ip)

    def _from_linux_kernel(self, jd: Path):
        """Read kernel version written by linux_resolver.resolve_symbols()."""
        kf = jd / "linux_kernel.json"
        if not kf.exists():
            return
        try:
            data = json.loads(kf.read_text(encoding="utf-8"))
            kv = data.get("kernel_version", "")
            os_t = data.get("os_type", "linux")
            if kv and not self._info["os_version"]:
                if os_t == "mac":
                    self._info["os_version"] = f"Darwin {kv}"
                    # Extract full banner for display if available
                    banner = data.get("banner", "")
                    if banner and not self._info["os_build"]:
                        self._info["os_build"] = banner
                else:
                    self._info["os_version"] = f"Linux {kv}"
                self.log.debug("OS version from linux_kernel.json: %s", kv)
        except Exception:
            pass

    def _from_linux_pslist(self, jd: Path):
        """Extract boot time and architecture from linux.pslist.PsList."""
        for item in load_json_by_pattern(jd, "pslist"):
            # PID 1 (init/systemd) creation time ≈ system boot time
            if str(_gv(item, "PID", "pid") or "") == "1":
                ct = str(_gv(item, "CREATION TIME", "CreateTime",
                             "creation_time", "Start Time") or "")
                if ct and not self._info["boot_time"]:
                    self._info["boot_time"] = ct
            # Infer x64 from large virtual offsets
            if not self._info["architecture"]:
                offset = _gv(item, "OFFSET (V)", "Offset", "offset")
                try:
                    if int(offset) > 2 ** 32:
                        self._info["architecture"] = "x64"
                except (TypeError, ValueError):
                    pass

    def _from_summary(self, summary_path: Path):
        """Extract profile info from SUMMARY.txt."""
        try:
            content = summary_path.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                if "Profile:" in line:
                    profile = line.split(":", 1)[1].strip()
                    if profile and profile != "N/A":
                        # Extract Windows version from profile name
                        if not self._info["os_version"]:
                            self._info["os_version"] = profile
        except Exception:
            pass

    def _from_strings(self, strings_path: Path):
        """Fallback: scan strings for hostname and IP patterns."""
        try:
            # Only read first 50MB for speed
            with open(strings_path, "r", encoding="utf-8", errors="ignore") as f:
                chunk = f.read(50 * 1024 * 1024)

            # Look for COMPUTERNAME in registry-style strings
            for m in re.finditer(r'COMPUTERNAME[=\x00\s]+([A-Z0-9\-]{2,15})', chunk):
                name = m.group(1).strip()
                if name and name != "COMPUTERNAME":
                    self._info["hostname"] = name
                    self.log.debug("Hostname from strings: %s", name)
                    break

        except Exception as e:
            self.log.debug("Strings scan error: %s", e)

    def write_report(self, output_dir: Path) -> Path:
        """Write system info to TXT and JSON.

        Returns:
            Path to TXT report.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        txt_path = output_dir / "system_info.txt"
        json_dir = output_dir / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        json_path = json_dir / "system_info.json"

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write("  SYSTEM INFORMATION\n")
            f.write("=" * 60 + "\n\n")

            f.write(f"  Hostname:      {self._info['hostname'] or 'Unknown'}\n")
            f.write(f"  Domain:        {self._info['domain'] or 'Unknown'}\n")
            f.write(f"  OS Version:    {self._info['os_version'] or 'Unknown'}\n")
            f.write(f"  OS Build:      {self._info['os_build'] or 'Unknown'}\n")
            f.write(f"  Architecture:  {self._info['architecture'] or 'Unknown'}\n")
            f.write(f"  Boot Time:     {self._info['boot_time'] or 'Unknown'}\n")

            f.write(f"\n  Users ({len(self._info['usernames'])}):\n")
            if self._info["usernames"]:
                for u in self._info["usernames"]:
                    f.write(f"    {u}\n")
            else:
                f.write("    (none detected)\n")

            f.write(f"\n  IP Addresses ({len(self._info['ip_addresses'])}):\n")
            if self._info["ip_addresses"]:
                for ip in self._info["ip_addresses"]:
                    f.write(f"    {ip}\n")
            else:
                f.write("    (none detected)\n")

            f.write("\n" + "=" * 60 + "\n")

        json_path.write_text(
            json.dumps(self._info, indent=2, default=str), encoding="utf-8")

        self.log.info("System info: %s", txt_path)
        return txt_path

    @property
    def info(self) -> Dict[str, Any]:
        return self._info
