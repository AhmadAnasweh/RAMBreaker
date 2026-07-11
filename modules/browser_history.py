"""
CresCent RAM Forensics Toolkit v4.0 - Browser History Scanner

Extracts browser history, URLs, searches, downloads, and cookies
from memory using strings + regex patterns. Works on ANY browser
because it scans raw memory strings, not browser-specific databases.

Supported patterns:
  - Chrome/Chromium: visited URLs, search queries, downloads
  - Firefox: visited URLs, search queries, downloads
  - Internet Explorer/Edge Legacy: visited URLs, cache entries
  - Edge Chromium: same as Chrome (Chromium-based)
  - Opera: same as Chromium
  - Brave: same as Chromium

Also detects:
  - Google searches, Bing searches, Yahoo searches, DuckDuckGo
  - Social media URLs (Facebook, Twitter, Instagram, etc.)
  - Email URLs (Gmail, Outlook, Yahoo Mail)
  - File download URLs
  - Suspicious/malicious URL patterns
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


class BrowserHistoryScanner:
    """Extract browser history and web activity from memory strings."""

    # URL extraction patterns
    URL_PATTERN = re.compile(
        r'(https?://[^\s<>"\'}{|\\^\[\]`\x00-\x1f]{8,500})', re.IGNORECASE)

    # Browser-specific patterns in strings output
    CHROME_PATTERNS = {
        "visited": re.compile(r'(https?://[^\s"\'<>]{8,300})\s*\x00', re.IGNORECASE),
        "search": re.compile(
            r'https?://www\.google\.com/search\?[^\s"\'<>]*q=([^&\s"\'<>]+)',
            re.IGNORECASE),
        "download": re.compile(
            r'(https?://[^\s"\'<>]+\.(?:exe|msi|zip|rar|7z|pdf|doc[x]?|xls[x]?|bat|ps1|vbs|js|dll|iso|img))',
            re.IGNORECASE),
    }

    FIREFOX_PATTERNS = {
        "places": re.compile(r'moz-anno:favicon:(https?://[^\s"\'<>]+)', re.IGNORECASE),
        "download": re.compile(r'file:///[^\s"\'<>]+', re.IGNORECASE),
    }

    IE_PATTERNS = {
        "cache": re.compile(
            r'(?:Visited|Cookie|History):\s*\S+@(https?://[^\s"\'<>]+)',
            re.IGNORECASE),
        "typed_url": re.compile(r'TypedURLs.*?(https?://[^\s"\'<>]+)', re.IGNORECASE),
    }

    # Search engine query extraction
    SEARCH_ENGINES = {
        "Google": re.compile(
            r'google\.com/search\?[^&]*q=([^&\s"\'<>]+)', re.IGNORECASE),
        "Bing": re.compile(
            r'bing\.com/search\?[^&]*q=([^&\s"\'<>]+)', re.IGNORECASE),
        "Yahoo": re.compile(
            r'search\.yahoo\.com/search\?[^&]*p=([^&\s"\'<>]+)', re.IGNORECASE),
        "DuckDuckGo": re.compile(
            r'duckduckgo\.com/\?[^&]*q=([^&\s"\'<>]+)', re.IGNORECASE),
        "Yandex": re.compile(
            r'yandex\.com/search\?[^&]*text=([^&\s"\'<>]+)', re.IGNORECASE),
        "Baidu": re.compile(
            r'baidu\.com/s\?[^&]*wd=([^&\s"\'<>]+)', re.IGNORECASE),
    }

    # Interesting URL categories
    CATEGORIES = {
        "social_media": re.compile(
            r'(facebook\.com|twitter\.com|x\.com|instagram\.com|'
            r'linkedin\.com|reddit\.com|tiktok\.com|youtube\.com|'
            r'snapchat\.com|pinterest\.com|tumblr\.com)',
            re.IGNORECASE),
        "email": re.compile(
            r'(mail\.google\.com|outlook\.live\.com|outlook\.office\.com|'
            r'mail\.yahoo\.com|protonmail\.com|tutanota\.com)',
            re.IGNORECASE),
        "cloud_storage": re.compile(
            r'(drive\.google\.com|dropbox\.com|onedrive\.live\.com|'
            r'box\.com|mega\.nz|wetransfer\.com|mediafire\.com)',
            re.IGNORECASE),
        "messaging": re.compile(
            r'(web\.whatsapp\.com|web\.telegram\.org|discord\.com|'
            r'slack\.com|teams\.microsoft\.com|signal\.org)',
            re.IGNORECASE),
        "file_sharing": re.compile(
            r'(pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.com|'
            r'file\.io|transfer\.sh|0x0\.st|ix\.io)',
            re.IGNORECASE),
        "suspicious": re.compile(
            r'(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|'
            r'ngrok\.io|serveo\.net|portmap\.io|'
            r'\.onion|\.i2p|'
            r'raw\.githubusercontent\.com|'
            r'exec|eval|cmd|shell|reverse|payload|exploit|'
            r'mimikatz|cobalt|beacon|meterpreter)',
            re.IGNORECASE),
        "download": re.compile(
            r'\.(exe|msi|bat|cmd|ps1|vbs|js|wsf|scr|pif|dll|'
            r'zip|rar|7z|tar|gz|iso|img|dmg)(\?|$|&)',
            re.IGNORECASE),
    }

    # Common browser process names
    BROWSER_PROCESSES = {
        "chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe",
        "opera.exe", "brave.exe", "vivaldi.exe", "safari.exe",
        "chromium.exe", "waterfox.exe", "tor.exe", "browser.exe",
    }

    # Noise patterns to filter out
    NOISE_PATTERNS = [
        re.compile(r'^https?://schemas\.', re.IGNORECASE),
        re.compile(r'^https?://www\.w3\.org/', re.IGNORECASE),
        re.compile(r'^https?://ns\.adobe\.com/', re.IGNORECASE),
        re.compile(r'^https?://purl\.org/', re.IGNORECASE),
        re.compile(r'^https?://xml\.', re.IGNORECASE),
        re.compile(r'^https?://localhost[:/]', re.IGNORECASE),
        re.compile(r'^https?://127\.0\.0\.1[:/]', re.IGNORECASE),
        re.compile(r'^https?://[^/]*microsoft\.com/.*(?:schema|xmlns|wsdl)', re.IGNORECASE),
        re.compile(r'\.(?:xsd|dtd|wsdl)$', re.IGNORECASE),
    ]

    def __init__(self, logger: logging.Logger):
        self.log = logger
        self._urls: Set[str] = set()
        self._searches: List[Dict] = []
        self._downloads: List[str] = []
        self._categorized: Dict[str, Set[str]] = {}
        self._ie_history: List[str] = []
        self._firefox_urls: Set[str] = set()

    def scan_strings_file(self, strings_path: Path) -> Dict[str, Any]:
        """Scan a strings file for browser history.

        Args:
            strings_path: Path to strings_ascii.txt or strings_all.txt

        Returns:
            Dict with all results.
        """
        strings_path = Path(strings_path)
        if not strings_path.exists():
            self.log.error("Strings file not found: %s", strings_path)
            return {}

        self.log.info("Scanning %s for browser history...", strings_path.name)
        self._urls.clear()
        self._searches.clear()
        self._downloads.clear()
        self._categorized.clear()
        self._ie_history.clear()
        self._firefox_urls.clear()

        line_count = 0
        try:
            with open(strings_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_count += 1
                    self._process_line(line.strip())
        except Exception as e:
            self.log.error("Error reading %s: %s", strings_path, e)
            return {}

        self.log.info("Scanned %d lines", line_count)
        self.log.info("  URLs: %d", len(self._urls))
        self.log.info("  Searches: %d", len(self._searches))
        self.log.info("  Downloads: %d", len(self._downloads))
        self.log.info("  IE/Edge history: %d", len(self._ie_history))

        return self._compile_results()

    def scan_output_dir(self, output_dir: Path) -> Dict[str, Any]:
        """Scan all available strings files in the output directory."""
        od = Path(output_dir)
        for name in ("strings_all.txt", "strings_ascii.txt",
                      "strings_unicode.txt", "strings.txt"):
            sf = od / name
            if sf.exists():
                return self.scan_strings_file(sf)

        self.log.error("No strings file found in %s", od)
        return {}

    def _process_line(self, line: str):
        """Process a single line from strings output."""
        if not line or len(line) < 10:
            return

        # Helper: URL-decode but keep the result safe for display.
        # Strings memory dumps sometimes contain partially decoded URLs;
        # analysts shouldn't have to manually decode %20, %2F, etc. in
        # ioc_url_http.txt or browser_history.json.
        from urllib.parse import unquote
        def _decode_url(url: str) -> str:
            try:
                return unquote(url)
            except Exception:
                return url

        # Extract URLs
        for m in self.URL_PATTERN.finditer(line):
            url = m.group(1).rstrip(".,;:)>]}'\"")
            if self._is_noise(url):
                continue
            url = _decode_url(url)
            self._urls.add(url)

            # Categorize
            for cat, pattern in self.CATEGORIES.items():
                if pattern.search(url):
                    self._categorized.setdefault(cat, set()).add(url)

            # Check for downloads
            if self.CHROME_PATTERNS["download"].search(url):
                self._downloads.append(url)

        # Extract search queries
        for engine, pattern in self.SEARCH_ENGINES.items():
            for m in pattern.finditer(line):
                query = m.group(1)
                try:
                    from urllib.parse import unquote_plus
                    query = unquote_plus(query)
                except Exception:
                    query = query.replace("+", " ").replace("%20", " ")
                self._searches.append({"engine": engine, "query": query})

        # IE/Edge Legacy history entries
        for pat in self.IE_PATTERNS.values():
            for m in pat.finditer(line):
                url = m.group(1) if m.lastindex else m.group(0)
                url = url.rstrip(".,;:)>]}'\"")
                if not self._is_noise(url):
                    self._ie_history.append(_decode_url(url))

        # Firefox-specific
        for pat in self.FIREFOX_PATTERNS.values():
            for m in pat.finditer(line):
                url = m.group(1) if m.lastindex else m.group(0)
                self._firefox_urls.add(_decode_url(url))

    def _is_noise(self, url: str) -> bool:
        """Check if URL is XML schema or other noise."""
        for pat in self.NOISE_PATTERNS:
            if pat.search(url):
                return True
        return False

    def _compile_results(self) -> Dict[str, Any]:
        """Compile all results into a structured dict."""
        # Deduplicate searches
        seen_searches = set()
        unique_searches = []
        for s in self._searches:
            key = f"{s['engine']}:{s['query']}"
            if key not in seen_searches:
                seen_searches.add(key)
                unique_searches.append(s)

        return {
            "urls": sorted(self._urls),
            "url_count": len(self._urls),
            "searches": unique_searches,
            "search_count": len(unique_searches),
            "downloads": sorted(set(self._downloads)),
            "download_count": len(set(self._downloads)),
            "ie_history": sorted(set(self._ie_history)),
            "ie_history_count": len(set(self._ie_history)),
            "firefox_urls": sorted(self._firefox_urls),
            "categories": {k: sorted(v) for k, v in self._categorized.items()},
        }

    def write_report(self, output_dir: Path,
                     results: Optional[Dict] = None) -> Path:
        """Write browser history report.

        Args:
            output_dir: Output directory.
            results: Results dict. If None, uses last scan.

        Returns:
            Path to TXT report.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if results is None:
            results = self._compile_results()

        iocs_dir = output_dir / "iocs"
        iocs_dir.mkdir(parents=True, exist_ok=True)
        txt_path = iocs_dir / "browser_history.txt"
        json_dir = iocs_dir / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        json_path = json_dir / "browser_history.json"

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  BROWSER HISTORY ANALYSIS\n")
            f.write(f"  URLs: {results['url_count']}  "
                    f"Searches: {results['search_count']}  "
                    f"Downloads: {results['download_count']}\n")
            f.write("=" * 80 + "\n\n")

            # Search queries (most valuable for investigation)
            if results["searches"]:
                f.write("--- SEARCH QUERIES ---\n\n")
                for s in results["searches"]:
                    f.write(f"  [{s['engine']:12s}] {s['query']}\n")
                f.write("\n")

            # Downloads (high value)
            if results["downloads"]:
                f.write("--- FILE DOWNLOADS ---\n\n")
                for url in results["downloads"]:
                    f.write(f"  {url}\n")
                f.write("\n")

            # Suspicious URLs
            sus = results["categories"].get("suspicious", [])
            if sus:
                f.write("--- SUSPICIOUS URLs ---\n\n")
                for url in sus:
                    f.write(f"  {url}\n")
                f.write("\n")

            # Messaging
            msgs = results["categories"].get("messaging", [])
            if msgs:
                f.write("--- MESSAGING ---\n\n")
                for url in msgs:
                    f.write(f"  {url}\n")
                f.write("\n")

            # Cloud storage
            cloud = results["categories"].get("cloud_storage", [])
            if cloud:
                f.write("--- CLOUD STORAGE ---\n\n")
                for url in cloud:
                    f.write(f"  {url}\n")
                f.write("\n")

            # File sharing (high value for exfil detection)
            fs = results["categories"].get("file_sharing", [])
            if fs:
                f.write("--- FILE SHARING (potential exfiltration) ---\n\n")
                for url in fs:
                    f.write(f"  {url}\n")
                f.write("\n")

            # Email
            email = results["categories"].get("email", [])
            if email:
                f.write("--- EMAIL ---\n\n")
                for url in email:
                    f.write(f"  {url}\n")
                f.write("\n")

            # Social media
            social = results["categories"].get("social_media", [])
            if social:
                f.write("--- SOCIAL MEDIA ---\n\n")
                for url in social:
                    f.write(f"  {url}\n")
                f.write("\n")

            # IE/Edge Legacy history
            if results["ie_history"]:
                f.write("--- IE/EDGE LEGACY HISTORY ---\n\n")
                for url in results["ie_history"]:
                    f.write(f"  {url}\n")
                f.write("\n")

            # All URLs
            f.write(f"--- ALL URLs ({results['url_count']}) ---\n\n")
            for url in results["urls"]:
                f.write(f"  {url}\n")

            # Category summary
            f.write("\n" + "=" * 80 + "\n")
            f.write("  SUMMARY\n")
            f.write(f"  Total URLs:    {results['url_count']}\n")
            f.write(f"  Searches:      {results['search_count']}\n")
            f.write(f"  Downloads:     {results['download_count']}\n")
            f.write(f"  IE History:    {results['ie_history_count']}\n")
            for cat, urls in sorted(results["categories"].items()):
                f.write(f"  {cat:16s} {len(urls)}\n")
            f.write("=" * 80 + "\n")

        # JSON
        json_path.write_text(
            json.dumps(results, indent=2, default=str), encoding="utf-8")

        self.log.info("Browser history report: %s", txt_path)
        return txt_path
