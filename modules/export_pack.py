"""
CresCent RAM Forensics Toolkit v4.0 - Export Pack

Generates a zip file containing all key investigation artifacts ready
for handoff to team leads, SIEM import, or incident reports.

Contents:
  - report.html (interactive report)
  - hashes.csv (file hashes for VT)
  - timeline.csv (chronological events)
  - ioc_results.json (all IOCs)
  - external_ips.txt (C2/suspicious IPs)
  - suspicious_processes.txt
  - correlation_report.txt
  - yara_results.txt (if available)
  - evtx_report.txt (if available)
  - process_tree.txt
  - network_map.txt
  - registry_report.txt
"""

import logging
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional


class ExportPack:
    """Generate a zip export of key investigation artifacts."""

    # Files to include in the export (relative to output_dir)
    EXPORT_FILES = [
        "report.html",
        "hashes.csv",
        "hashes.txt",
        "timeline.txt",
        "timeline.csv",
        "json/timeline.json",
        "iocs/ioc_results.json",
        "iocs/ioc_summary.txt",
        "suspicious_processes.txt",
        "correlation_report.txt",
        "json/correlation_report.json",
        "process_tree.txt",
        "network_map.txt",
        "json/network_map.json",
        "registry_report.txt",
        "json/registry_report.json",
        "iocs/browser_history.txt",
        "iocs/json/browser_history.json",
        "iocs/popular_files.txt",
        "iocs/json/popular_files.json",
        "scheduled_tasks.txt",
        "iocs/json/scheduled_tasks.json",
        "yara_results.txt",
        "yara_results.json",
        "evtx_report.txt",
        "json/evtx_report.json",
        "SUMMARY.txt",
        "crescent_toolkit.log",
    ]

    # Also include all ioc_*.txt files
    EXPORT_GLOBS = [
        "iocs/ioc_*.txt",
    ]

    def __init__(self, logger: logging.Logger):
        self.log = logger

    def generate(self, output_dir: Path,
                 zip_name: Optional[str] = None) -> Path:
        """Generate the export zip file.

        Args:
            output_dir: Base analysis output directory.
            zip_name: Custom zip filename. Default: crescent_export_<timestamp>.zip

        Returns:
            Path to the generated zip file.
        """
        output_dir = Path(output_dir)
        if zip_name is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            zip_name = f"crescent_export_{ts}.zip"

        zip_path = output_dir / zip_name

        # Collect files
        files_to_pack: List[Path] = []

        # Explicit files
        for rel in self.EXPORT_FILES:
            fp = output_dir / rel
            if fp.exists():
                files_to_pack.append(fp)

        # Glob patterns
        for pattern in self.EXPORT_GLOBS:
            parts = pattern.split("/", 1)
            if len(parts) == 2:
                d = output_dir / parts[0]
                if d.is_dir():
                    files_to_pack.extend(sorted(d.glob(parts[1])))
            else:
                files_to_pack.extend(sorted(output_dir.glob(pattern)))

        # Deduplicate
        seen = set()
        unique = []
        for f in files_to_pack:
            r = f.resolve()
            if r not in seen:
                seen.add(r)
                unique.append(f)

        if not unique:
            self.log.warning("No files found to export")
            return zip_path

        # Create zip
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # Create a manifest
            manifest_lines = [
                "CresCent RAM Forensics Toolkit - Export Pack",
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Source: {output_dir}",
                f"Files: {len(unique)}",
                "",
                "Contents:",
            ]

            for fp in unique:
                # Store relative to output_dir
                rel = fp.relative_to(output_dir)
                zf.write(fp, str(rel))
                size = fp.stat().st_size
                manifest_lines.append(f"  {rel}  ({self._fmt_size(size)})")

            # Add manifest
            manifest = "\n".join(manifest_lines)
            zf.writestr("MANIFEST.txt", manifest)

        zip_size = zip_path.stat().st_size
        self.log.info("Export pack: %s (%s, %d files)",
                      zip_path, self._fmt_size(zip_size), len(unique))
        return zip_path

    def list_available(self, output_dir: Path) -> List[str]:
        """List which export files are available.

        Args:
            output_dir: Base output directory.

        Returns:
            List of available relative paths.
        """
        available = []
        for rel in self.EXPORT_FILES:
            if (output_dir / rel).exists():
                available.append(rel)
        for pattern in self.EXPORT_GLOBS:
            parts = pattern.split("/", 1)
            if len(parts) == 2:
                d = output_dir / parts[0]
                if d.is_dir():
                    for f in sorted(d.glob(parts[1])):
                        available.append(str(f.relative_to(output_dir)))
        return available

    @staticmethod
    def _fmt_size(b: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if abs(b) < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"
