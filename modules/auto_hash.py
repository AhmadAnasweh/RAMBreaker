"""
CresCent RAM Forensics Toolkit v4.0 - Auto Hash

Auto-generates MD5 and SHA256 hashes for all dumped files and processes.
Outputs hashes.csv for bulk VirusTotal lookup. Optional VT API check.
"""

import csv
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class AutoHash:
    """Hash dumped files and processes with optional VT lookup."""

    # VirusTotal public API rate limit: 4 requests/minute (= one every 15s).
    # AutoHash enforces a conservative 16-second floor between calls.
    VT_MIN_INTERVAL = 16.0

    def __init__(self, logger: logging.Logger, vt_api_key: str = ""):
        self.log = logger
        self.vt_api_key = vt_api_key
        self._hashes: List[Dict[str, str]] = []
        self._vt_last_call: float = 0.0

    def hash_file(self, path: Path) -> Dict[str, str]:
        """Compute MD5 and SHA256 for a single file.

        Args:
            path: File path.

        Returns:
            Dict with 'file', 'size', 'md5', 'sha256'.
        """
        path = Path(path)
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
            result = {
                "file": str(path),
                "filename": path.name,
                "size": str(path.stat().st_size),
                "md5": md5.hexdigest(),
                "sha256": sha256.hexdigest(),
            }
            self._hashes.append(result)
            return result
        except Exception as e:
            self.log.error("Hash error %s: %s", path, e)
            return {"file": str(path), "filename": path.name,
                    "size": "0", "md5": "ERROR", "sha256": "ERROR"}

    def hash_directory(self, dir_path: Path) -> List[Dict[str, str]]:
        """Hash all files in a directory recursively.

        Args:
            dir_path: Directory to scan.

        Returns:
            List of hash dicts.
        """
        dir_path = Path(dir_path)
        if not dir_path.is_dir():
            return []

        results = []
        files = sorted(f for f in dir_path.rglob("*") if f.is_file())
        self.log.info("Hashing %d files in %s...", len(files), dir_path.name)

        for f in files:
            h = self.hash_file(f)
            results.append(h)

        return results

    def hash_all_output(self, output_dir: Path) -> List[Dict[str, str]]:
        """Hash everything in dumped_files/ and dumped_processes/.

        Args:
            output_dir: Base analysis output directory.

        Returns:
            Combined list of hash dicts.
        """
        results = []

        df = output_dir / "dumped_files"
        if df.is_dir():
            results.extend(self.hash_directory(df))

        dp = output_dir / "dumped_processes"
        if dp.is_dir():
            results.extend(self.hash_directory(dp))

        self.log.info("Hashed %d files total", len(results))
        return results

    def check_virustotal(self, sha256: str) -> Optional[Dict]:
        """Check a single hash against VirusTotal API.

        Requires self.vt_api_key to be set. Self-throttles to one request
        per VT_MIN_INTERVAL seconds (default 16s) to stay under the public
        API limit of 4 requests/minute. Handles HTTP 429 explicitly with
        a 60-second back-off.

        Args:
            sha256: SHA256 hash string.

        Returns:
            VT result dict or None.
        """
        if not self.vt_api_key:
            return None

        # Throttle
        elapsed = time.time() - self._vt_last_call
        if elapsed < self.VT_MIN_INTERVAL:
            wait = self.VT_MIN_INTERVAL - elapsed
            self.log.debug("VT rate limit: sleeping %.1fs", wait)
            time.sleep(wait)

        try:
            import urllib.request
            import urllib.error
            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            req = urllib.request.Request(url)
            req.add_header("x-apikey", self.vt_api_key)
            self._vt_last_call = time.time()
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                stats = data.get("data", {}).get("attributes", {}).get(
                    "last_analysis_stats", {})
                return {
                    "sha256": sha256,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values()),
                    "name": data.get("data", {}).get("attributes", {}).get(
                        "meaningful_name", ""),
                }
        except urllib.error.HTTPError as e:
            if e.code == 429:
                # Quota burned — wait a full minute before any further call.
                self.log.warning(
                    "VT rate limit hit (HTTP 429) on %s — backing off 60s",
                    sha256[:16])
                self._vt_last_call = time.time() + 60 - self.VT_MIN_INTERVAL
            else:
                self.log.debug("VT HTTP %d for %s: %s",
                               e.code, sha256[:16], e.reason)
            return None
        except Exception as e:
            self.log.debug("VT lookup failed for %s: %s", sha256[:16], e)
            return None

    def check_virustotal_bulk(self, sha256_list: List[str]
                              ) -> List[Optional[Dict]]:
        """Look up many hashes against VirusTotal, throttled.

        With the public API this is intentionally slow — ~4 lookups/minute.
        At 100 hashes that's ~25 minutes. Use a private API key (much higher
        quota) for incident-response scale work, or upload `hashes.csv`
        to VT's GUI directly.
        """
        if not self.vt_api_key:
            self.log.warning("VT bulk lookup requested but no API key set")
            return [None] * len(sha256_list)
        results: List[Optional[Dict]] = []
        total = len(sha256_list)
        est_minutes = (total * self.VT_MIN_INTERVAL) / 60
        self.log.info(
            "VT bulk lookup: %d hashes (estimated ~%.1f minutes at public-API rate)",
            total, est_minutes)
        for i, h in enumerate(sha256_list, 1):
            results.append(self.check_virustotal(h))
            if i % 10 == 0:
                self.log.info("VT bulk progress: %d/%d", i, total)
        return results

    def write_report(self, output_dir: Path,
                     hashes: Optional[List[Dict]] = None) -> Path:
        """Write hashes to CSV, TXT, and JSON.

        Args:
            output_dir: Output directory.
            hashes: Hash list. If None, uses accumulated hashes.

        Returns:
            Path to CSV file.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if hashes is None:
            hashes = self._hashes

        csv_path = output_dir / "hashes.csv"
        txt_path = output_dir / "hashes.txt"
        json_path = output_dir / "hashes.json"

        # CSV (for bulk VT upload)
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["filename", "size", "md5",
                                               "sha256", "file"])
            w.writeheader()
            w.writerows(hashes)

        # TXT
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  FILE HASHES\n")
            f.write(f"  Files: {len(hashes)}\n")
            f.write("=" * 80 + "\n\n")
            for h in hashes:
                f.write(f"  File:   {h['filename']}\n")
                f.write(f"  Size:   {h['size']} bytes\n")
                f.write(f"  MD5:    {h['md5']}\n")
                f.write(f"  SHA256: {h['sha256']}\n")
                f.write(f"  Path:   {h['file']}\n")
                f.write("-" * 40 + "\n")
            f.write("\n" + "=" * 80 + "\n")

        # JSON
        json_path.write_text(
            json.dumps(hashes, indent=2, default=str), encoding="utf-8")

        self.log.info("Hashes: %s (%d files)", csv_path, len(hashes))
        return csv_path

    @property
    def hashes(self) -> List[Dict[str, str]]:
        return self._hashes
