"""CresCent RAM Forensics Toolkit v6 — Windows Correlator"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set

from utils.json_converter import load_json_by_pattern


def _gv(item, *keys):
    for k in keys:
        if k in item:
            return item[k]
    return None


_INTEREST_PROCS = (
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "certutil.exe", "bitsadmin.exe", "msiexec.exe", "psexec",
    "mimikatz", "nc.exe", "ncat.exe", "netcat",
    "python.exe", "python3.exe", "perl.exe", "ruby.exe",
    "wget.exe", "curl.exe", "nmap.exe", "chisel.exe",
    "meterpreter", "mettle", "empire",
)


class Correlator:
    def __init__(self, logger: logging.Logger, redact_hashes: bool = True):
        self.log = logger
        self.redact_hashes = redact_hashes
        self._procs: Dict[str, Dict] = {}
        self._sus_pids: Set[str] = set()
        self._ext_conns: list = []
        self._malfind: list = []
        self._svcscan: list = []
        self._consoles: list = []
        self._cmdscan: list = []
        self._hashdump: list = []
        self._shellbags: list = []
        self._shimcache: list = []

    @staticmethod
    def _mask_hash(s: str) -> str:
        if not s or len(s) < 12:
            return s
        return f"{s[:4]}...{s[-4:]}"

    def _maybe_redact_hash_entry(self, item: Dict) -> Dict:
        if not self.redact_hashes:
            return item
        masked = dict(item)
        for key in list(masked.keys()):
            kl = str(key).lower()
            if any(x in kl for x in ("nthash", "lmhash", "hash", "ntlm")):
                masked[key] = self._mask_hash(str(masked[key]))
            elif kl == "raw" and ":" in str(masked[key]):
                parts = str(masked[key]).split(":")
                if len(parts) >= 4:
                    parts[2] = self._mask_hash(parts[2])
                    parts[3] = self._mask_hash(parts[3])
                    masked[key] = ":".join(parts)
        return masked

    def load_data(self, output_dir: Path):
        jd = output_dir / "json"
        if not jd.is_dir():
            self.log.error("No json/ directory: %s", jd)
            return

        self.log.info("Loading Windows process data...")
        pslist  = load_json_by_pattern(jd, "pslist")
        pstree  = load_json_by_pattern(jd, "pstree")
        psscan  = load_json_by_pattern(jd, "psscan")
        cmdline = load_json_by_pattern(jd, "cmdline")

        self.log.info("Loading Windows network data...")
        netscan     = load_json_by_pattern(jd, "netscan")
        netstat     = load_json_by_pattern(jd, "netstat")
        connscan    = load_json_by_pattern(jd, "connscan")
        connections = load_json_by_pattern(jd, "connections")
        sockscan    = load_json_by_pattern(jd, "sockscan")
        sockets     = load_json_by_pattern(jd, "sockets")

        self.log.info("Loading Windows security / Vol2 extras...")
        self._malfind   = load_json_by_pattern(jd, "malfind")
        self._svcscan   = load_json_by_pattern(jd, "svcscan")
        self._cmdscan   = load_json_by_pattern(jd, "cmdscan")
        self._consoles  = load_json_by_pattern(jd, "consoles")
        self._hashdump  = load_json_by_pattern(jd, "hashdump")
        self._shellbags = load_json_by_pattern(jd, "shellbags")
        self._shimcache = load_json_by_pattern(jd, "shimcache")

        # Build process map
        self._procs.clear()
        for p in pslist + pstree + psscan:
            pid = str(_gv(p, "PID", "pid", "Pid") or "")
            if not pid or pid in self._procs:
                continue
            name  = str(_gv(p, "ImageFileName", "Name", "Process", "name") or "")
            ppid  = str(_gv(p, "PPID", "ppid", "Ppid",
                            "InheritedFromUniqueProcessId", "ParentPID") or "")
            cmdln = str(_gv(p, "Args", "args", "CommandLine", "CmdLine") or "")
            self._procs[pid] = {
                "name": name, "ppid": ppid,
                "cmdline": cmdln, "connections": [], "suspicious": False,
            }

        # cmdline plugin fills in full command lines
        for c in cmdline:
            pid  = str(_gv(c, "PID", "pid", "Pid") or "")
            args = str(_gv(c, "Args", "args", "CommandLine", "CmdLine") or "")
            if pid in self._procs and args:
                self._procs[pid]["cmdline"] = args

        # Network — all Windows sources
        for n in netscan + netstat + connscan + connections + sockscan + sockets:
            pid    = str(_gv(n, "PID", "pid", "Pid", "Owner Pid") or "")
            local  = str(_gv(n, "LocalAddr", "Local Address", "LocalAddress", "Local") or "")
            lp     = str(_gv(n, "LocalPort", "Local Port") or "")
            remote = str(_gv(n, "ForeignAddr", "Foreign Address", "RemoteAddr",
                             "Remote", "Foreign") or "")
            rp     = str(_gv(n, "ForeignPort", "Foreign Port", "RemotePort") or "")
            state  = str(_gv(n, "State", "state") or "")
            proto  = str(_gv(n, "Proto", "Protocol", "proto", "Type") or "TCP")
            owner  = str(_gv(n, "Owner", "owner", "Process") or "")
            cs = f"{proto} {local}:{lp} -> {remote}:{rp}"
            if state:
                cs += f" ({state})"
            if pid in self._procs:
                self._procs[pid]["connections"].append(cs)
            elif pid:
                self._procs[pid] = {
                    "name": owner or "Unknown", "ppid": "",
                    "cmdline": "", "connections": [cs], "suspicious": False,
                }

        # Malfind
        for m in self._malfind:
            pid = str(_gv(m, "PID", "pid", "Pid") or "")
            if pid:
                self._sus_pids.add(pid)
                if pid in self._procs:
                    self._procs[pid]["suspicious"] = True

        self.log.info(
            "Loaded: %d procs, %d malfind hits, %d services, %d hashes",
            len(self._procs), len(self._sus_pids),
            len(self._svcscan), len(self._hashdump),
        )

    def _build_ext_conns(self):
        self._ext_conns = []
        for pid, p in self._procs.items():
            for c in p["connections"]:
                if "->" in c:
                    remote = c.split("->")[1].strip().split(":")[0].strip()
                    if remote and not remote.startswith(
                            ("127.", "0.0.0.0", "::", "*", "0:0")):
                        self._ext_conns.append((pid, p["name"], c))

    def generate_report(self, output_dir: Path) -> Path:
        od = Path(output_dir)
        od.mkdir(parents=True, exist_ok=True)
        tp = od / "correlation_report.txt"
        jd = od / "json"
        jd.mkdir(parents=True, exist_ok=True)
        jp = jd / "correlation_report.json"
        self.log.info("Generating Windows correlation report...")
        self._build_ext_conns()
        self._write_txt(tp)
        self._write_json(jp)
        self.log.info("Reports: %s, %s", tp, jp)
        return tp

    def _write_txt(self, path: Path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n  WINDOWS CORRELATION REPORT\n")
            f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("  NOTE: Raw data only — no automated threat assessments.\n")
            f.write("=" * 80 + "\n\n")

            # Processes with connections
            f.write("=" * 80 + "\n  PROCESSES WITH NETWORK CONNECTIONS\n" + "=" * 80 + "\n\n")
            net_procs = [(pid, p) for pid, p in self._procs.items() if p["connections"]]
            if net_procs:
                for pid, p in sorted(net_procs, key=lambda x: x[1]["name"].lower()):
                    mk = "[!] " if p["suspicious"] else ""
                    f.write(f"  {mk}[{pid}] {p['name']}\n")
                    if p["ppid"]:
                        f.write(f"      PPID: {p['ppid']}\n")
                    if p["cmdline"]:
                        f.write(f"      CMD: {p['cmdline']}\n")
                    for c in p["connections"]:
                        f.write(f"      NET: {c}\n")
                    f.write("\n")
            else:
                f.write("  None found.\n\n")

            # Malfind
            if self._sus_pids:
                f.write("=" * 80 + "\n  MALFIND DETECTIONS\n" + "=" * 80 + "\n\n")
                for m in self._malfind:
                    pid  = _gv(m, "PID", "pid", "Pid")
                    proc = _gv(m, "Process", "process", "Name")
                    addr = _gv(m, "Address", "Start VPN", "Vad Start")
                    prot = _gv(m, "Protection", "protection")
                    f.write(f"  [{pid}] {proc}\n")
                    if addr:
                        f.write(f"      Address: {addr}\n")
                    if prot:
                        f.write(f"      Protection: {prot}\n")
                    f.write("\n")

            # Interesting processes
            f.write("=" * 80 + "\n  PROCESSES OF INTEREST\n" + "=" * 80 + "\n\n")
            found_any = False
            for pid, p in sorted(self._procs.items(), key=lambda x: x[1]["name"].lower()):
                if any(s.lower() in p["name"].lower() for s in _INTEREST_PROCS):
                    found_any = True
                    mk = "[MALFIND] " if p["suspicious"] else ""
                    f.write(f"  {mk}[{pid}] {p['name']}\n")
                    if p["cmdline"]:
                        f.write(f"      CMD: {p['cmdline']}\n")
                    for c in p["connections"]:
                        f.write(f"      NET: {c}\n")
                    f.write("\n")
            if not found_any:
                f.write("  None found.\n\n")

            # External connections
            f.write("=" * 80 + "\n  EXTERNAL CONNECTIONS\n" + "=" * 80 + "\n\n")
            if self._ext_conns:
                for pid, name, c in self._ext_conns:
                    f.write(f"  [{pid}] {name}: {c}\n")
            else:
                f.write("  None found.\n")
            f.write("\n")

            # Windows extras
            for data, title in [
                (self._svcscan[:50],   "SERVICES"),
                (self._consoles,       "CONSOLE OUTPUT (Vol2)"),
                (self._cmdscan,        "COMMAND HISTORY (Vol2)"),
                (self._hashdump,       "PASSWORD HASHES (Vol2)"),
                (self._shellbags[:30], "SHELLBAGS (Vol2)"),
                (self._shimcache[:30], "SHIMCACHE (Vol2)"),
            ]:
                if not data:
                    continue
                f.write("=" * 80 + f"\n  {title}\n" + "=" * 80 + "\n")
                if title.startswith("PASSWORD HASHES") and self.redact_hashes:
                    f.write("  NOTE: Hash values masked. Full hashes in "
                            "json/hashdump_vol2.json.\n")
                f.write("\n")
                for item in data:
                    if title.startswith("PASSWORD HASHES"):
                        item = self._maybe_redact_hash_entry(item)
                    raw = _gv(item, "raw") or ""
                    if raw:
                        f.write(f"  {raw}\n")
                    else:
                        for k, v in item.items():
                            if k != "__children":
                                f.write(f"  {k}: {v}\n")
                    f.write("-" * 40 + "\n")
                f.write("\n")

            # Summary
            net_p = sum(1 for p in self._procs.values() if p["connections"])
            f.write("=" * 80 + "\n  SUMMARY\n" + "=" * 80 + "\n\n")
            f.write(f"  Processes: {len(self._procs)}  Network: {net_p}  "
                    f"Malfind: {len(self._sus_pids)}  External: {len(self._ext_conns)}\n")
            f.write(f"  Services: {len(self._svcscan)}  Hashes: {len(self._hashdump)}\n")
            f.write("\n" + "=" * 80 + "\n  END OF REPORT\n" + "=" * 80 + "\n")

    def _write_json(self, path: Path):
        net_p = sum(1 for p in self._procs.values() if p["connections"])
        network_processes = [
            {"pid": pid, "name": p["name"], "ppid": p["ppid"],
             "cmdline": p["cmdline"], "connections": p["connections"],
             "malfind": p["suspicious"]}
            for pid, p in sorted(self._procs.items(), key=lambda x: x[1]["name"].lower())
            if p["connections"]
        ]
        interest_processes = [
            {"pid": pid, "name": p["name"], "ppid": p["ppid"],
             "cmdline": p["cmdline"], "connections": p["connections"],
             "malfind": p["suspicious"]}
            for pid, p in sorted(self._procs.items(), key=lambda x: x[1]["name"].lower())
            if any(s.lower() in p["name"].lower() for s in _INTEREST_PROCS)
        ]
        malfind_rows = [
            {"pid":        str(_gv(m, "PID", "pid", "Pid") or ""),
             "name":       str(_gv(m, "Process", "process", "Name") or ""),
             "address":    str(_gv(m, "Address", "Start VPN", "Vad Start") or ""),
             "protection": str(_gv(m, "Protection", "protection") or "")}
            for m in self._malfind[:500]
        ]
        redacted_hashes = [
            self._maybe_redact_hash_entry(h) for h in self._hashdump
        ]
        report = {
            "generated": datetime.now().isoformat(),
            "os_type": "windows",
            "summary": {
                "total_processes":    len(self._procs),
                "network_processes":  net_p,
                "malfind":            len(self._sus_pids),
                "external_connections": len(self._ext_conns),
                "services":           len(self._svcscan),
                "hashes":             len(self._hashdump),
            },
            "network_processes":    network_processes,
            "malfind":              malfind_rows,
            "interest_processes":   interest_processes,
            "external_connections": [
                {"pid": p, "name": n, "connection": c}
                for p, n, c in self._ext_conns
            ],
            "services":   self._svcscan[:100],
            "hashes":     redacted_hashes,
            "consoles":   self._consoles,
            "cmdscan":    self._cmdscan,
            "shellbags":  self._shellbags[:50],
            "shimcache":  self._shimcache[:50],
        }
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
