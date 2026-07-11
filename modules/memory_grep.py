"""
CresCent RAM Forensics Toolkit v4.0 - Process Memory Grep

Search inside dumped process memory and files for keywords, regex, or hex
patterns. Shows which PID matched with context lines.
"""

import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class MemoryGrep:
    """Search inside dumped memory files for patterns."""

    def __init__(self, logger: logging.Logger):
        self.log = logger

    def search_file(self, path: Path, pattern: str,
                    context_lines: int = 3,
                    is_regex: bool = False) -> List[Dict[str, Any]]:
        """Search a single file for a pattern using strings + grep.

        Args:
            path: File to search (can be binary .dmp or text).
            pattern: Search term or regex.
            context_lines: Number of context lines around each hit.
            is_regex: If True, treat pattern as regex.

        Returns:
            List of match dicts with 'line', 'context', 'offset'.
        """
        path = Path(path)
        if not path.exists():
            return []

        matches = []

        # For binary files, run strings first
        if self._is_binary(path):
            matches = self._search_binary(path, pattern, context_lines,
                                           is_regex)
        else:
            matches = self._search_text(path, pattern, context_lines,
                                         is_regex)

        return matches

    def search_directory(self, dir_path: Path, pattern: str,
                         context_lines: int = 3,
                         is_regex: bool = False,
                         extensions: Optional[Set[str]] = None
                         ) -> Dict[str, List[Dict]]:
        """Search all files in a directory for a pattern.

        Args:
            dir_path: Directory to search.
            pattern: Search term.
            context_lines: Context lines per match.
            is_regex: Regex mode.
            extensions: File extensions to include. None = all.

        Returns:
            Dict mapping filename -> list of matches.
        """
        dir_path = Path(dir_path)
        if not dir_path.is_dir():
            return {}

        results = {}
        files = sorted(f for f in dir_path.rglob("*") if f.is_file())
        if extensions:
            files = [f for f in files if f.suffix.lower() in extensions]

        self.log.info("Searching %d files for '%s'...", len(files), pattern)

        for f in files:
            matches = self.search_file(f, pattern, context_lines, is_regex)
            if matches:
                results[str(f)] = matches
                self.log.info("  %s: %d hits", f.name, len(matches))

        total = sum(len(m) for m in results.values())
        self.log.info("Total: %d hits in %d files", total, len(results))
        return results

    def search_dumps(self, output_dir: Path, pattern: str,
                     context_lines: int = 3,
                     is_regex: bool = False) -> Dict[str, List[Dict]]:
        """Search all dumped files and processes for a pattern.

        Args:
            output_dir: Base analysis output directory.
            pattern: Search term.
            context_lines: Context lines.
            is_regex: Regex mode.

        Returns:
            Dict mapping filepath -> list of matches.
        """
        results = {}

        for subdir in ("dumped_files", "dumped_processes"):
            d = output_dir / subdir
            if d.is_dir():
                r = self.search_directory(d, pattern, context_lines, is_regex)
                results.update(r)

        return results

    def _is_binary(self, path: Path) -> bool:
        """Check if a file is binary."""
        try:
            with open(path, "rb") as f:
                chunk = f.read(8192)
                if b"\x00" in chunk:
                    return True
                # High ratio of non-printable = binary
                non_text = sum(1 for b in chunk if b < 32 and b not in
                               (9, 10, 13))
                return non_text / max(len(chunk), 1) > 0.3
        except Exception:
            return True

    def _search_binary(self, path: Path, pattern: str,
                       context: int, is_regex: bool) -> List[Dict]:
        """Search binary file: run strings, then grep the output."""
        matches = []
        try:
            # Run strings on the binary
            proc = subprocess.run(
                ["strings", "-a", str(path)],
                capture_output=True, text=True, timeout=60,
                errors="ignore")
            lines = proc.stdout.splitlines()
        except Exception as e:
            self.log.debug("strings failed on %s: %s", path.name, e)
            return []

        return self._grep_lines(lines, pattern, context, is_regex, str(path))

    def _search_text(self, path: Path, pattern: str,
                     context: int, is_regex: bool) -> List[Dict]:
        """Search text file line by line."""
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()
        except Exception:
            return []

        return self._grep_lines(lines, pattern, context, is_regex, str(path))

    def _grep_lines(self, lines: List[str], pattern: str,
                    context: int, is_regex: bool,
                    source: str) -> List[Dict]:
        """Search a list of lines for a pattern with context."""
        matches = []
        if is_regex:
            try:
                rx = re.compile(pattern, re.IGNORECASE)
            except re.error:
                return []
            test = lambda line: rx.search(line)
        else:
            pat_lower = pattern.lower()
            test = lambda line: pat_lower in line.lower()

        for i, line in enumerate(lines):
            if test(line):
                start = max(0, i - context)
                end = min(len(lines), i + context + 1)
                ctx = []
                for j in range(start, end):
                    prefix = " >> " if j == i else "    "
                    ctx.append(f"{prefix}{lines[j]}")

                matches.append({
                    "line_number": i + 1,
                    "match_line": line.strip(),
                    "context": "\n".join(ctx),
                    "source": source,
                })

        return matches

    def write_report(self, output_dir: Path, pattern: str,
                     results: Dict[str, List[Dict]]) -> Path:
        """Write search results to file.

        Args:
            output_dir: Output directory.
            pattern: The search pattern used.
            results: Search results.

        Returns:
            Path to report.
        """
        import json

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        txt_path = output_dir / "memory_grep_results.txt"
        json_path = output_dir / "memory_grep_results.json"

        total = sum(len(m) for m in results.values())

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write(f"  MEMORY GREP: '{pattern}'\n")
            f.write(f"  Hits: {total} in {len(results)} files\n")
            f.write("=" * 80 + "\n\n")

            for filepath, matches in results.items():
                fname = Path(filepath).name
                f.write(f"--- {fname} ({len(matches)} hits) ---\n\n")
                for m in matches:
                    f.write(f"  Line {m['line_number']}:\n")
                    f.write(m["context"] + "\n\n")
                f.write("\n")

            f.write("=" * 80 + "\n")

        json_path.write_text(
            json.dumps({"pattern": pattern, "total_hits": total,
                         "results": results}, indent=2, default=str),
            encoding="utf-8")

        self.log.info("Memory grep report: %s", txt_path)
        return txt_path
