"""
CresCent RAM Forensics Toolkit v4.0 - YARA Scanner

Scans dumped files, process executables, and raw strings against YARA rules.
Uses the system 'yara' binary if installed. Supports custom rule files
and directories of rules.
"""

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class YARAScanner:
    """Scan files against YARA rules for malware detection."""

    def __init__(self, logger: logging.Logger, timeout: int = 120):
        self.log = logger
        self.timeout = timeout
        self._yara_cmd = None

    def check_yara(self) -> bool:
        """Check if yara is installed and available."""
        cmd = shutil.which("yara") or shutil.which("yara64")
        if cmd:
            self._yara_cmd = cmd
            self.log.info("YARA found: %s", cmd)
            return True
        self.log.error("YARA not found. Install: sudo apt install yara")
        return False

    def find_rule_files(self, paths: Optional[List[str]] = None) -> List[Path]:
        """Find YARA rule files (.yar, .yara) in given paths.

        Args:
            paths: List of file/directory paths. If None, searches common locations.

        Returns:
            List of rule file paths.
        """
        if paths is None:
            home = Path.home()
            search = [
                Path("."), Path("./yara_rules"), Path("./rules"),
                home / "yara-rules", home / "Desktop" / "yara-rules",
                Path("/opt/yara-rules"), Path("/usr/share/yara-rules"),
                home / ".crescent" / "yara_rules",
            ]
        else:
            search = [Path(p) for p in paths]

        rules: List[Path] = []
        for p in search:
            if p.is_file() and p.suffix.lower() in (".yar", ".yara"):
                rules.append(p)
            elif p.is_dir():
                for ext in ("*.yar", "*.yara"):
                    rules.extend(sorted(p.rglob(ext)))

        self.log.info("Found %d YARA rule files", len(rules))
        return rules

    def scan_file(self, target: Path, rule_file: Path) -> List[Dict[str, str]]:
        """Scan a single file against a YARA rule file.

        Args:
            target: File to scan.
            rule_file: YARA rule file.

        Returns:
            List of match dicts with 'rule', 'file', 'tags', 'strings'.
        """
        if not self._yara_cmd:
            return []

        try:
            proc = subprocess.run(
                [self._yara_cmd, "-s", str(rule_file), str(target)],
                capture_output=True, text=True, timeout=self.timeout)

            matches = []
            current_rule = None
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                # Rule match line: "RuleName target_file"
                if not line.startswith("0x"):
                    parts = line.split(None, 1)
                    if parts:
                        current_rule = parts[0]
                        matches.append({
                            "rule": current_rule,
                            "file": str(target),
                            "strings": [],
                        })
                # String match: "0x1234:$string: matched_data"
                elif current_rule and matches:
                    matches[-1]["strings"].append(line)

            return matches

        except subprocess.TimeoutExpired:
            self.log.warning("YARA timeout on %s", target.name)
            return []
        except Exception as e:
            self.log.error("YARA error: %s", e)
            return []

    def scan_directory(self, target_dir: Path, rule_files: List[Path],
                       extensions: Optional[Set[str]] = None
                       ) -> List[Dict[str, str]]:
        """Scan all files in a directory against YARA rules.

        Args:
            target_dir: Directory to scan.
            rule_files: List of YARA rule files.
            extensions: File extensions to scan. None = all files.

        Returns:
            List of all matches.
        """
        target_dir = Path(target_dir)
        if not target_dir.is_dir():
            self.log.error("Directory not found: %s", target_dir)
            return []

        files = []
        for f in target_dir.rglob("*"):
            if not f.is_file():
                continue
            if extensions and f.suffix.lower() not in extensions:
                continue
            files.append(f)

        self.log.info("Scanning %d files against %d rule files",
                      len(files), len(rule_files))

        all_matches = []
        for rule_file in rule_files:
            for target in files:
                matches = self.scan_file(target, rule_file)
                all_matches.extend(matches)

        self.log.info("YARA: %d matches found", len(all_matches))
        return all_matches

    def scan_output_dir(self, output_dir: Path,
                        rule_files: List[Path]) -> Dict[str, List]:
        """Scan all forensic output (dumped files, processes, strings).

        Args:
            output_dir: Base analysis output directory.
            rule_files: YARA rule files to use.

        Returns:
            Dict with 'dumped_files', 'processes', 'total_matches' keys.
        """
        results = {"dumped_files": [], "processes": [], "total_matches": 0}

        # Scan dumped files
        df = output_dir / "dumped_files"
        if df.is_dir():
            self.log.info("Scanning dumped_files/...")
            results["dumped_files"] = self.scan_directory(df, rule_files)

        # Scan dumped processes
        dp = output_dir / "dumped_processes"
        if dp.is_dir():
            self.log.info("Scanning dumped_processes/...")
            results["processes"] = self.scan_directory(dp, rule_files)

        results["total_matches"] = (len(results["dumped_files"]) +
                                     len(results["processes"]))
        return results

    def write_report(self, output_dir: Path,
                     matches: List[Dict[str, str]]) -> Path:
        """Write YARA scan results to a report file.

        Args:
            output_dir: Output directory.
            matches: List of match dicts.

        Returns:
            Path to report file.
        """
        import json

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        txt_path = output_dir / "yara_results.txt"
        json_path = output_dir / "yara_results.json"

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  YARA SCAN RESULTS\n")
            f.write(f"  Matches: {len(matches)}\n")
            f.write("=" * 80 + "\n\n")

            if matches:
                for m in matches:
                    f.write(f"  Rule:  {m['rule']}\n")
                    f.write(f"  File:  {m['file']}\n")
                    if m.get("strings"):
                        for s in m["strings"][:10]:
                            f.write(f"    {s}\n")
                    f.write("-" * 40 + "\n")
            else:
                f.write("  No matches found.\n")

            f.write("\n" + "=" * 80 + "\n")

        json_path.write_text(
            json.dumps(matches, indent=2, default=str), encoding="utf-8")

        self.log.info("YARA report: %s", txt_path)
        return txt_path
