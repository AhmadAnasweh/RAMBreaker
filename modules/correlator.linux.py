"""CresCent RAM Forensics Toolkit v6 — Linux Correlator"""

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
    "nc", "ncat", "socat", "netcat",
    "bash", "sh", "dash", "zsh", "fish", "ksh", "tcsh",
    "python", "python3", "perl", "ruby", "lua", "php",
    "wget", "curl", "nmap", "masscan", "fscan", "zmap",
    "chisel", "ligolo", "frpc", "frps", "ngrok", "gost",
    "mimipenguin", "pspy", "linpeas", "linenum",
    "insmod", "modprobe", "rmmod",
    "reptile", "diamorphine", "azazel", "kovid",
    "meterpreter", "mettle", "empire",
    "ssh", "scp", "rsync",
)


class Correlator:
    def __init__(self, logger: logging.Logger):
        self.log = logger
        self._procs: Dict[str, Dict] = {}
        self._sus_pids: Set[str] = set()
        self._ext_conns: list = []
        self._malfind: list = []
        self._bash: list = []
        self._lsmod: list = []
        self._check_modules: list = []

    def load_data(self, output_dir: Path):
        jd = output_dir / "json"
        if not jd.is_dir():
            self.log.error("No json/ directory: %s", jd)
            return

        self.log.info("Loading Linux process data...")
        pslist = load_json_by_pattern(jd, "pslist")
        pstree = load_json_by_pattern(jd, "pstree")
        psscan = load_json_by_pattern(jd, "psscan")
        psaux  = load_json_by_pattern(jd, "psaux")

        self.log.info("Loading Linux network data...")
        netscan  = load_json_by_pattern(jd, "netscan")
        netstat  = load_json_by_pattern(jd, "netstat")
        sockstat = load_json_by_pattern(jd, "sockstat")
        lsof     = load_json_by_pattern(jd, "lsof")

        self.log.info("Loading Linux extras...")
        self._malfind       = load_json_by_pattern(jd, "malfind")
        self._bash          = load_json_by_pattern(jd, "bash")
        self._lsmod         = load_json_by_pattern(jd, "lsmod")
        self._check_modules = load_json_by_pattern(jd, "check_modules")

        # Build process map
        self._procs.clear()
        for p in pslist + pstree + psscan + psaux:
            pid = str(_gv(p, "PID", "pid", "Pid") or "")
            if not pid or pid in self._procs:
                continue
            name  = str(_gv(p, "ImageFileName", "Name", "Process",
                            "name", "COMM", "Comm", "comm") or "")
            ppid  = str(_gv(p, "PPID", "ppid", "Ppid",
                            "InheritedFromUniqueProcessId", "ParentPID") or "")
            cmdln = str(_gv(p, "Args", "args", "Arguments",
                            "CommandLine", "CmdLine") or "")
            self._procs[pid] = {
                "name": name, "ppid": ppid,
                "cmdline": cmdln, "connections": [], "suspicious": False,
            }

        # psaux fills command lines for Linux (ARGS column)
        for a in psaux:
            pid  = str(_gv(a, "PID", "pid", "Pid") or "")
            args = str(_gv(a, "Args", "args", "Arguments", "ARGS") or "").strip()
            if pid in self._procs and args and not self._procs[pid]["cmdline"]:
                self._procs[pid]["cmdline"] = args

        # Network — netscan / netstat
        for n in netscan + netstat:
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

        # Network — sockstat (Vol3 linux.sockstat)
        for n in sockstat:
            pid      = str(_gv(n, "PID", "pid", "Pid") or "")
            local    = str(_gv(n, "Source Addr", "Source Address", "SrcAddr") or "")
            lp       = str(_gv(n, "Source Port", "SrcPort") or "")
            remote   = str(_gv(n, "Destination Addr", "Destination Address",
                               "DstAddr", "ForeignAddr") or "")
            rp       = str(_gv(n, "Destination Port", "DstPort", "ForeignPort") or "")
            state    = str(_gv(n, "State", "state") or "")
            sk_type  = str(_gv(n, "Socket Type", "Type", "Proto", "proto") or "SOCK")
            process  = str(_gv(n, "Process", "process", "Name", "name") or "")
            cs = f"{sk_type} {local}:{lp} -> {remote}:{rp}"
            if state:
                cs += f" ({state})"
            if pid in self._procs:
                self._procs[pid]["connections"].append(cs)
            elif pid:
                self._procs[pid] = {
                    "name": process or "Unknown", "ppid": "",
                    "cmdline": "", "connections": [cs], "suspicious": False,
                }

        # Network — lsof (socket entries only)
        for entry in lsof:
            pid        = str(_gv(entry, "PID", "pid", "Pid") or "")
            path_field = str(_gv(entry, "Path", "Name", "name", "FILE") or "")
            file_type  = str(_gv(entry, "Type", "type") or "")
            if file_type.upper() in ("SOCK", "IPV4", "IPV6", "UNIX") or "->" in path_field:
                if pid in self._procs:
                    label = (f"lsof: [{file_type}] {path_field}"
                             if path_field else f"lsof: [{file_type}]")
                    self._procs[pid]["connections"].append(label)

        # Malfind
        for m in self._malfind:
            pid = str(_gv(m, "PID", "pid", "Pid") or "")
            if pid:
                self._sus_pids.add(pid)
                if pid in self._procs:
                    self._procs[pid]["suspicious"] = True

        self.log.info(
            "Loaded: %d procs, %d malfind hits, %d sockstat, %d lsof",
            len(self._procs), len(self._sus_pids), len(sockstat), len(lsof),
        )

    def _build_ext_conns(self):
        self._ext_conns = []
        for pid, p in self._procs.items():
            for c in p["connections"]:
                if "->" in c:
                    remote = c.split("->")[1].strip().split(":")[0].strip()
                    if remote and not remote.startswith(
                            ("127.", "0.0.0.0", "::", "*", "0:0", "lsof:")):
                        self._ext_conns.append((pid, p["name"], c))

    def generate_report(self, output_dir: Path) -> Path:
        od = Path(output_dir)
        od.mkdir(parents=True, exist_ok=True)
        tp = od / "correlation_report.txt"
        jd = od / "json"
        jd.mkdir(parents=True, exist_ok=True)
        jp = jd / "correlation_report.json"
        self.log.info("Generating Linux correlation report...")
        self._build_ext_conns()
        self._write_txt(tp)
        self._write_json(jp)
        self.log.info("Reports: %s, %s", tp, jp)
        return tp

    def _write_txt(self, path: Path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n  LINUX CORRELATION REPORT\n")
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

            # Bash history
            if self._bash:
                f.write("=" * 80 + "\n  BASH COMMAND HISTORY\n" + "=" * 80 + "\n\n")
                for item in self._bash[:100]:
                    raw = _gv(item, "raw") or ""
                    if raw:
                        f.write(f"  {raw}\n")
                    else:
                        for k, v in item.items():
                            if k != "__children":
                                f.write(f"  {k}: {v}\n")
                    f.write("-" * 40 + "\n")
                f.write("\n")

            # Kernel modules
            if self._lsmod:
                f.write("=" * 80 + "\n  LOADED KERNEL MODULES\n" + "=" * 80 + "\n\n")
                for item in self._lsmod[:100]:
                    raw = _gv(item, "raw") or ""
                    if raw:
                        f.write(f"  {raw}\n")
                    else:
                        for k, v in item.items():
                            if k != "__children":
                                f.write(f"  {k}: {v}\n")
                    f.write("-" * 40 + "\n")
                f.write("\n")

            # Hidden modules
            if self._check_modules:
                f.write("=" * 80 + "\n  HIDDEN/SUSPICIOUS KERNEL MODULES\n" + "=" * 80 + "\n\n")
                for item in self._check_modules:
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
            if self._bash:
                f.write(f"  Bash history: {len(self._bash)} entries  "
                        f"Modules: {len(self._lsmod)}  "
                        f"Hidden modules: {len(self._check_modules)}\n")
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
        report = {
            "generated": datetime.now().isoformat(),
            "os_type": "linux",
            "summary": {
                "total_processes":    len(self._procs),
                "network_processes":  net_p,
                "malfind":            len(self._sus_pids),
                "external_connections": len(self._ext_conns),
                "bash_entries":       len(self._bash),
                "kernel_modules":     len(self._lsmod),
                "hidden_modules":     len(self._check_modules),
            },
            "network_processes":    network_processes,
            "malfind":              malfind_rows,
            "interest_processes":   interest_processes,
            "external_connections": [
                {"pid": p, "name": n, "connection": c}
                for p, n, c in self._ext_conns
            ],
            "bash_history":    self._bash[:100],
            "kernel_modules":  self._lsmod[:100],
            "hidden_modules":  self._check_modules,
        }
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
