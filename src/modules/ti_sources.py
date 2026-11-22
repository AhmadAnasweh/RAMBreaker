"""Threat-intelligence databases for the "DFIR + Threat Intel" mode (RAMBreaker v2.2).

Two kinds of local knowledge, both checked ON THIS PC (nothing is sent anywhere):
  * YARA rule sets   - <app>/yara_rules/yara-forge/{core,extended}.yar (bundled) and
                        <app>/yara_rules/custom/ (the analyst's own .yar/.yara files)
  * indicator feeds  - lists of known-bad IPs / networks / domains / URLs / hashes in
                        <app>/threat_intel_db/bundled/   (shipped with the tool) and
                        <app>/threat_intel_db/downloaded/ (fetched on the user's request)

Threat intelligence goes stale within days (C2 servers move, new malware families
appear), so every source records when it was fetched. The GUI shows the age of each
source and OFFERS an update; it never updates on its own. Offline, the bundled copies
are used and the report says how old they are.

Only freely redistributable sources are bundled (Unlicense / CC0 / the YARA Forge
package). Sources whose terms do not allow redistribution (Maltrail trails, Spamhaus
DROP, Emerging Threats, CINS Army, OpenPhish, abuse.ch keyed exports) are downloaded
to the user's own PC by the update, for the user's own defensive use.
"""

import csv
import http.client
import io
import ipaddress
import json
import logging
import os
import re
import shutil
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from modules import platform_compat

UA = "RAMBreaker-TI-update/2.2"

# id, name, what, url, licence, bundled, key, fmt, homepage, file
SOURCES: List[Dict[str, Any]] = [
    {"id": "yaraforge_core", "name": "YARA Forge - core rule set", "what": "YARA rules",
     "url": "github:YARAHQ/yara-forge:yara-forge-rules-core.zip", "file": "core.yar",
     "licence": "Package of public YARA repositories; each repository's licence is kept in the file "
                "(DRL 1.1, MIT, Apache-2.0, BSD, GPL-3.0 ...)",
     "bundled": True, "fmt": "yara", "homepage": "https://github.com/YARAHQ/yara-forge",
     "why": "Content signatures for malware families, hack tools and exploits. Works on partial and "
            "memory-rebuilt files, where a hash lookup cannot match."},
    {"id": "yaraforge_extended", "name": "YARA Forge - extended rule set", "what": "YARA rules",
     "url": "github:YARAHQ/yara-forge:yara-forge-rules-extended.zip", "file": "extended.yar",
     "licence": "as core", "bundled": True, "fmt": "yara",
     "homepage": "https://github.com/YARAHQ/yara-forge",
     "why": "About twice the rules of 'core', including threat-hunting rules with more false positives."},
    {"id": "ipsum", "name": "IPsum (aggregated bad-IP list)", "what": "IP addresses",
     "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", "file": "ipsum.txt",
     "licence": "Unlicense (public domain)", "bundled": True, "fmt": "ipsum",
     "homepage": "https://github.com/stamparm/ipsum",
     "why": "Daily merge of 30+ public blocklists; each IP carries how many lists name it."},
    {"id": "feodo", "name": "abuse.ch Feodo Tracker (botnet C2 IPs)", "what": "IP addresses",
     "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "file": "feodo.txt",
     "licence": "CC0", "bundled": True, "fmt": "iplist",
     "homepage": "https://feodotracker.abuse.ch/",
     "why": "Command-and-control servers of Emotet/Dridex/QakBot-style botnets."},
    {"id": "maltrail", "name": "Maltrail trails (malware / C2 / suspicious domains, IPs, URLs)",
     "what": "domains, IPs, URLs", "url": "https://github.com/stamparm/trails/archive/refs/heads/master.zip",
     "file": "trails", "licence": "Maltrail Trails Community Data License 1.0 - free for your own "
                                  "defence, research and education; NOT redistributed with this tool",
     "bundled": False, "fmt": "trails", "homepage": "https://github.com/stamparm/trails",
     "why": "Over a million curated indicators with the malware family or campaign they belong to."},
    {"id": "spamhaus_drop", "name": "Spamhaus DROP (hijacked / criminal networks)", "what": "IP networks",
     "url": "https://www.spamhaus.org/drop/drop_v4.json", "file": "spamhaus_drop.json",
     "licence": "Spamhaus DROP terms (free use, not redistributed)", "bundled": False, "fmt": "drop",
     "homepage": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
     "why": "Address blocks run by criminals; traffic to them is almost never legitimate."},
    {"id": "et_compromised", "name": "Emerging Threats compromised hosts", "what": "IP addresses",
     "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "file": "et_compromised.txt",
     "licence": "Proofpoint ET Open (not redistributed)", "bundled": False, "fmt": "iplist",
     "homepage": "https://rules.emergingthreats.net/",
     "why": "Hosts seen attacking or compromised."},
    {"id": "cins", "name": "CINS Army list", "what": "IP addresses",
     "url": "https://cinsscore.com/list/ci-badguys.txt", "file": "cins.txt",
     "licence": "CINS Army terms (not redistributed)", "bundled": False, "fmt": "iplist",
     "homepage": "https://cinsscore.com/",
     "why": "IPs with a poor reputation in the Sentinel IPS network."},
    {"id": "openphish", "name": "OpenPhish community feed", "what": "URLs",
     "url": "https://openphish.com/feed.txt", "file": "openphish.txt",
     "licence": "OpenPhish community feed terms (non-commercial, not redistributed)", "bundled": False,
     "fmt": "urllist", "homepage": "https://openphish.com/",
     "why": "Live phishing pages; matches browser history and URLs found in memory."},
    {"id": "threatfox", "name": "abuse.ch ThreatFox (IOCs with malware family)", "what": "hashes, domains, IPs, URLs",
     "url": "https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip", "file": "threatfox.csv",
     "licence": "abuse.ch fair-use terms; needs your own free abuse.ch Auth-Key", "bundled": False,
     "key": "abusech", "fmt": "threatfox", "homepage": "https://threatfox.abuse.ch/",
     "why": "Last 6 months of community-shared IOCs, each tagged with its malware family."},
    {"id": "urlhaus", "name": "abuse.ch URLhaus (malware download URLs)", "what": "URLs",
     "url": "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv", "file": "urlhaus.csv",
     "licence": "abuse.ch fair-use terms; needs your own free abuse.ch Auth-Key", "bundled": False,
     "key": "abusech", "fmt": "urlhaus", "homepage": "https://urlhaus.abuse.ch/",
     "why": "URLs that served malware recently."},
    {"id": "malwarebazaar", "name": "abuse.ch MalwareBazaar (recent malware hashes)", "what": "file hashes",
     "url": "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv", "file": "malwarebazaar.csv",
     "licence": "abuse.ch fair-use terms; needs your own free abuse.ch Auth-Key", "bundled": False,
     "key": "abusech", "fmt": "bazaar", "homepage": "https://bazaar.abuse.ch/",
     "why": "SHA-256 of malware samples shared in the last 48 hours."},
    {"id": "malwarebazaar_full", "name": "abuse.ch MalwareBazaar - FULL local hash database (optional, ~230 MB download)",
     "what": "file hashes (SHA-256, SHA-1, MD5) with malware family",
     "url": "https://mb-api.abuse.ch/v2/files/exports/{key}/full.csv.zip", "file": "malwarebazaar_full.sqlite",
     "licence": "abuse.ch fair-use terms (CC0 data); needs your own free abuse.ch Auth-Key", "bundled": False,
     "key": "abusech", "fmt": "bazaar_full", "optional": True, "homepage": "https://bazaar.abuse.ch/export/",
     "size": "about 230 MB download, 280 MB on disk",
     "why": "Every malware sample MalwareBazaar has ever received (not only the last 48 hours), stored as a local "
            "database. Each dumped file's hash is looked up on this PC, with the malware family - no VirusTotal "
            "needed for known-malware hashes. Install it only if you want it: the download is about 230 MB."},
    {"id": "virusshare", "name": "VirusShare - malware MD5 hash lists (optional, ~1.4 GB download)",
     "what": "file hashes (MD5 only, no family names)",
     "url": "https://virusshare.com/hashfiles/VirusShare_{part:05d}.md5", "file": "virusshare_md5.sqlite",
     "licence": "VirusShare.com hash lists, free to download; no key needed", "bundled": False,
     "fmt": "virusshare", "optional": True, "homepage": "https://virusshare.com/hashes",
     "size": "about 1.4 GB download (500+ list files), 1.5 GB on disk; an update only fetches new lists",
     "why": "Tens of millions of MD5 hashes of malware samples collected by VirusShare. A match means the file "
            "is a known malware sample; the list has no family names. Looked up on this PC."},
    {"id": "nsrl_delta", "name": "NIST NSRL known files - latest quarterly update (optional, ~0.2 GB download)",
     "what": "hashes of KNOWN software files (not a malware list)",
     "url": "nsrl:modern_minimal_delta", "file": "nsrl_known.sqlite",
     "licence": "NIST National Software Reference Library RDS (public, US government work)", "bundled": False,
     "fmt": "nsrl", "optional": True, "homepage": "https://www.nist.gov/itl/ssd/software-quality-group/"
                                                  "national-software-reference-library-nsrl",
     "size": "about 0.2 GB download; only the files NIST added in the last quarter",
     "why": "Files published in known software (Windows, Office, drivers, applications). A dumped file whose hash "
            "is in NSRL is a known, published file - context that lets you look at the unknown ones first. "
            "NSRL also lists some hacking tools, so 'known' does not mean 'harmless'."},
    {"id": "nsrl_full", "name": "NIST NSRL known files - FULL modern set (optional, ~19 GB download)",
     "what": "hashes of KNOWN software files (not a malware list)",
     "url": "nsrl:modern_minimal", "file": "nsrl_known.sqlite",
     "licence": "NIST National Software Reference Library RDS (public, US government work)", "bundled": False,
     "fmt": "nsrl", "optional": True, "homepage": "https://www.nist.gov/itl/ssd/software-quality-group/"
                                                  "national-software-reference-library-nsrl",
     "size": "about 19 GB download and well over 100 GB of free disk space while it is built; takes hours",
     "why": "The complete 'modern minimal' NSRL set: hundreds of millions of known software files. Same use as "
            "the quarterly update, far more coverage. Very large: read the size note before installing."},
]
NSRL_INDEX = ("https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/"
              "nsrl-download/current-rds")
BY_ID = {s["id"]: s for s in SOURCES}
STALE_DAYS = 7          # older than this: the GUI suggests an update
# v2.6: free disk space an optional database needs while it is downloaded and built
# (download + database + temporary files); the GUI warns before starting with less.
NEED_FREE_GB = {"malwarebazaar_full": 1, "virusshare": 2, "nsrl_delta": 2, "nsrl_full": 120}


# --------------------------------------------------------------------- places
def db_root() -> Path:
    return platform_compat.app_root() / "threat_intel_db"


def rules_root() -> Path:
    return platform_compat.app_root() / "yara_rules"


def _meta_path(where: str) -> Path:
    return db_root() / where / "_meta.json"


def _read_meta(where: str) -> Dict[str, Any]:
    try:
        return json.loads(_meta_path(where).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_meta(where: str, meta: Dict[str, Any]) -> None:
    p = _meta_path(where)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def source_path(src: Dict[str, Any]) -> Tuple[Optional[Path], str, Dict[str, Any]]:
    """(path, 'downloaded'|'bundled', meta) of the newest local copy, or (None, '', {})."""
    if src["fmt"] == "yara":
        cands = [("downloaded", rules_root() / "yara-forge" / "_downloaded" / src["file"]),
                 ("bundled", rules_root() / "yara-forge" / src["file"])]
        metas = {"downloaded": _read_meta("downloaded"), "bundled": _read_meta("bundled")}
    else:
        cands = [("downloaded", db_root() / "downloaded" / src["file"]),
                 ("bundled", db_root() / "bundled" / src["file"])]
        metas = {"downloaded": _read_meta("downloaded"), "bundled": _read_meta("bundled")}
    for where, p in cands:
        if p.exists():
            return p, where, metas[where].get(src["id"], {})
    return None, "", {}


def status() -> List[Dict[str, Any]]:
    """One row per source: present?, where, fetched date, age in days, entries."""
    out = []
    now = time.time()
    for s in SOURCES:
        p, where, m = source_path(s)
        if s["fmt"] == "nsrl" and not m.get("fetched_epoch"):
            p, where, m = None, "", {}      # the two NSRL rows share one file: installed = has its own record
        fetched = m.get("fetched_epoch")
        if p is not None and not fetched:
            try:
                fetched = p.stat().st_mtime
            except OSError:
                fetched = None
        age = round((now - fetched) / 86400.0, 1) if fetched else None
        # v2.4: downloaded on this PC (the update recorded it) but the file is gone.
        # Seen live: Defender quarantined threatfox.csv minutes after the download,
        # and the run then reported it as "not downloaded".
        dl_meta = _read_meta("downloaded").get(s["id"]) or {}
        removed = bool(p is None and dl_meta.get("fetched_epoch"))
        # v2.6: what Delete would remove. The NSRL rows share one file: a row only owns
        # it when it has its own record (else Delete on an uninstalled row would remove
        # the other row's database); leftovers of an interrupted update always count.
        files = downloaded_files(s)
        if s["fmt"] == "nsrl":
            owned = ([files[0]] if p is not None and where == "downloaded" else []) + files[1:]
        else:
            owned = files
        dl_bytes = sum(_size(f) for f in owned)
        out.append({"id": s["id"], "name": s["name"], "what": s["what"], "licence": s["licence"],
                    "bundled": s["bundled"], "needs_key": bool(s.get("key")), "why": s["why"],
                    "homepage": s["homepage"], "present": p is not None, "where": where,
                    "path": str(p) if p else "", "fetched": time.strftime("%Y-%m-%d", time.localtime(fetched))
                    if fetched else "", "age_days": age, "entries": m.get("entries"),
                    # NSRL changes once a quarter: never nag about it after 7 days
                    "stale": bool(p is not None and age is not None and age > STALE_DAYS and s["fmt"] != "nsrl"),
                    "removed": removed, "optional": bool(s.get("optional")), "size": s.get("size", ""),
                    "removed_fetched": time.strftime("%Y-%m-%d", time.localtime(dl_meta["fetched_epoch"]))
                    if removed else "",
                    # v2.6: size on disk, what Delete can remove, a cancelled multi-file update
                    "disk_bytes": _size(p) if p is not None else 0,
                    "downloaded": bool(removed or any(f.exists() for f in owned)),
                    "downloaded_bytes": dl_bytes,
                    "partial": bool(where == "downloaded" and m.get("partial")),
                    "need_free": NEED_FREE_GB.get(s["id"], 0) * 1024 ** 3})
    return out


# --------------------------------------------------------------------- disk (v2.6)
def _size(p: Optional[Path]) -> int:
    """Bytes a file or a folder (all files inside) uses; 0 when missing."""
    try:
        if p is None or not p.exists():
            return 0
        if p.is_dir():
            return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
        return p.stat().st_size
    except OSError:
        return 0


def downloaded_files(src: Dict[str, Any]) -> List[Path]:
    """Everything an update of `src` leaves on disk: the downloaded copy first, then the
    temporary leftovers of an interrupted update. Never the bundled copy."""
    if src["fmt"] == "yara":
        base = rules_root() / "yara-forge" / "_downloaded" / src["file"]
    else:
        base = db_root() / "downloaded" / src["file"]
    out = [base] + [base.with_name(base.name + x) for x in (".part", ".old", ".zip.part")]
    if src["fmt"] == "nsrl":
        for kind in ("modern_minimal", "modern_minimal_delta"):
            out += [base.with_name(f"nsrl_{kind}.zip.part"), base.with_name(f"nsrl_{kind}.unpack")]
    return out


def disk_free() -> Tuple[int, str]:
    """(free bytes, drive) of the disk that holds the databases; (-1, '') if unknown."""
    p = db_root()
    while not p.exists() and p.parent != p:
        p = p.parent
    try:
        return shutil.disk_usage(str(p)).free, (p.drive or p.anchor)
    except OSError:
        return -1, ""


def space_used(rows: Optional[List[Dict[str, Any]]] = None) -> int:
    """Bytes all local database copies use together (a shared file counted once)."""
    seen, total = set(), 0
    for r in (rows if rows is not None else status()):
        if r["present"] and r["path"] and r["path"] not in seen:
            seen.add(r["path"])
            total += r["disk_bytes"]
    return total


def delete(ids: Iterable[str]) -> List[Dict[str, Any]]:
    """Delete the DOWNLOADED copies of the chosen databases (v2.6, only on the user's
    request). Bundled copies ship with RAMBreaker and are never deleted: where one
    exists it is used again. The source's record in downloaded/_meta.json goes too, so
    the table does not report the file as removed by antivirus. The two NSRL rows share
    one database: deleting either removes it and both records. A file that is open (an
    analysis is reading it) stays, with its record, and is reported."""
    meta_d = _read_meta("downloaded")
    results, gone = [], set()
    for sid in ids:
        s = BY_ID.get(sid)
        if not s:
            continue
        freed, errs = 0, []
        for p in downloaded_files(s):
            if p in gone or not p.exists():
                continue
            size = _size(p)
            try:
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
                freed += size
                gone.add(p)
            except OSError as e:
                errs.append(f"{p.name}: " + ("in use - close the analysis that reads it and try again"
                                             if isinstance(e, PermissionError) else str(e)))
        if not errs:
            for k in (("nsrl_delta", "nsrl_full") if s["fmt"] == "nsrl" else (sid,)):
                meta_d.pop(k, None)
        results.append({"id": sid, "name": s["name"], "ok": not errs, "freed": freed, "detail": "; ".join(errs)})
    _write_meta("downloaded", meta_d)
    return results


def custom_rule_files(extra_dirs: Iterable[str] = ()) -> List[Path]:
    dirs = [rules_root() / "custom"] + [Path(d) for d in extra_dirs if d]
    seen, out = set(), []
    for d in dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*")):
            if p.is_file() and p.suffix.lower() in (".yar", ".yara") and p.resolve() not in seen:
                seen.add(p.resolve())
                out.append(p)
    return out


# --------------------------------------------------------------------- transfer control (v2.6)
CHUNK = 256 * 1024      # read size: progress, Pause and Cancel react within one chunk
NET_TIMEOUT = 60        # seconds without data before a read gives up (Cancel waits at most this)
NET_RETRIES = 3         # reconnects in a row after a dropped connection (reset when data arrives)


class Cancelled(Exception):
    """The user pressed Cancel (Transfer.cancel())."""


class _PartialCancel(Cancelled):
    """Cancelled part-way through a multi-file database; the files installed so far stay."""

    def __init__(self, entries: int, nbytes: int, parts: int):
        super().__init__(f"cancelled after {parts} lists")
        self.entries, self.nbytes, self.parts = entries, nbytes, parts


class Transfer:
    """Live state and Pause / Resume / Cancel of one update run (v2.6).

    Shared by the download thread and the GUI: the worker writes the plain attributes
    and calls checkpoint() between chunks and database batches; the GUI reads the
    attributes on a timer and calls pause() / resume() / cancel(). Each field is one
    int / str / None, so single reads and writes are atomic under the GIL."""

    def __init__(self):
        self._go = threading.Event()
        self._go.set()
        self.cancelled = False
        self.index = 0            # 1-based position of the current database in this run
        self.count = 0            # databases in this run
        self.source = ""          # its name
        self.phase = ""           # "downloading" | "unpacking" | "building"
        self.detail = ""          # extra words: "list 12", "1,200,000 hashes"
        self.done = 0             # bytes of the current file so far
        self.total = None         # size of the current file when the server sends it
        self.source_bytes = 0     # bytes downloaded for the current database (all its files)
        self.received = 0         # bytes downloaded in the whole run (the GUI derives the speed)
        self.multi = False        # the current database is many files (VirusShare): no single %

    @property
    def paused(self) -> bool:
        return not self._go.is_set() and not self.cancelled

    def pause(self) -> None:
        if not self.cancelled:
            self._go.clear()

    def resume(self) -> None:
        self._go.set()

    def cancel(self) -> None:
        self.cancelled = True
        self._go.set()            # a paused worker wakes up and stops

    def checkpoint(self) -> None:
        """Wait while paused; raise Cancelled once cancelled."""
        self._go.wait()
        if self.cancelled:
            raise Cancelled()

    def begin(self, index: int, source: str) -> None:
        self.index, self.source, self.phase, self.detail = index, source, "downloading", ""
        self.done, self.total, self.source_bytes, self.multi = 0, None, 0, False


def _sqlite_gate(ctl: Transfer):
    """SQLite progress handler: lets one long statement (NSRL import, index build) pause
    and stop. Returning 1 makes SQLite abort the statement ('interrupted')."""
    def gate():
        ctl._go.wait()
        return 1 if ctl.cancelled else 0
    return gate


def _gated(con, ctl: Transfer, *statements: str):
    """Run long SQL statements so that Pause holds them and Cancel stops them (Cancelled)."""
    import sqlite3
    con.set_progress_handler(_sqlite_gate(ctl), 200000)
    try:
        cur = None
        for sql in statements:
            ctl.checkpoint()
            cur = con.execute(sql)
        return cur
    except sqlite3.OperationalError as e:
        if ctl.cancelled:
            raise Cancelled() from e
        raise
    finally:
        con.set_progress_handler(None, 0)


class _MemSink:
    def __init__(self):
        self.buf = bytearray()

    def write(self, b: bytes) -> None:
        self.buf += b

    def reset(self) -> None:
        self.buf = bytearray()


class _FileSink:
    def __init__(self, fh):
        self.fh = fh

    def write(self, b: bytes) -> None:
        self.fh.write(b)

    def reset(self) -> None:
        self.fh.seek(0)
        self.fh.truncate()


def _content_total(r, start: int) -> Optional[int]:
    """Full size of the file from a 206 (Content-Range) or 200 (Content-Length) answer."""
    m = re.match(r"bytes\s+\d+-\d+/(\d+)", r.headers.get("Content-Range") or "")
    if m:
        return int(m.group(1))
    cl = (r.headers.get("Content-Length") or "").strip()
    return start + int(cl) if cl.isdigit() else None


def _nap(ctl: Transfer, seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if ctl.cancelled:
            raise Cancelled()
        time.sleep(0.1)


def _stream(url: str, sink, ctl: Optional[Transfer] = None, timeout: int = NET_TIMEOUT) -> int:
    """Download `url` into `sink` in CHUNK pieces, with progress (ctl.done / total /
    received) and Pause / Cancel (ctl.checkpoint() between pieces).

    A connection that breaks part-way (a server may drop it during a long pause; a flaky
    line) is reopened with an HTTP Range request for the rest. A server that ignores
    Range sends the whole file again: the sink is emptied and the file starts over. A
    failure before the first byte and every HTTP error status are raised at once, as
    before. Returns the number of bytes in the sink."""
    ctl = ctl or Transfer()
    done, total, fails = 0, None, 0
    ctl.done, ctl.total = 0, None
    while True:
        ctl.checkpoint()
        hdr = {"User-Agent": UA}
        if done:
            hdr["Range"] = f"bytes={done}-"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=timeout) as r:  # nosec - fixed https URLs
                if done and r.status != 206:          # Range ignored: the whole file comes again
                    sink.reset()
                    done = 0
                total = _content_total(r, done)
                ctl.done, ctl.total = done, total
                # read1: whatever has arrived (up to CHUNK) - on a slow line read(CHUNK) would
                # wait for a full chunk, so progress, Pause and Cancel would lag by seconds
                read = getattr(r, "read1", r.read)
                while True:
                    ctl.checkpoint()
                    b = read(CHUNK)
                    if not b:
                        break
                    sink.write(b)
                    n = len(b)
                    done += n
                    ctl.done = done
                    ctl.source_bytes += n
                    ctl.received += n
                    fails = 0
            if total is not None and done < total:
                raise ConnectionError(f"connection closed after {done:,} of {total:,} bytes")
            return done
        except Cancelled:
            raise
        except urllib.error.HTTPError as e:
            if e.code == 416 and done and (total is None or done >= total):
                return done                            # asked for bytes past the end: all of it is here
            raise
        except (OSError, http.client.HTTPException):   # dropped, reset, timed out, incomplete read
            fails += 1
            if not done or fails > NET_RETRIES:
                raise
            _nap(ctl, min(2.0 * fails, 5.0))


def _fetch(url: str, ctl: Optional[Transfer] = None) -> bytes:
    """A whole download in memory, with progress / Pause / Cancel (small and medium files)."""
    sink = _MemSink()
    _stream(url, sink, ctl)
    return bytes(sink.buf)


# --------------------------------------------------------------------- update
def _get(url: str, timeout: int = 300) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:      # nosec - fixed https URLs
        return r.read()


def _github_asset(spec: str) -> str:
    _, repo, asset = spec.split(":", 2)
    rel = json.loads(_get(f"https://api.github.com/repos/{repo}/releases/latest", 60))
    for a in rel.get("assets", []):
        if a.get("name") == asset:
            return a["browser_download_url"]
    raise RuntimeError(f"{asset} not in the latest {repo} release")


def update(ids: Iterable[str], keys: Optional[Dict[str, str]] = None,
           log: Optional[logging.Logger] = None, progress=None,
           ctl: Optional[Transfer] = None) -> List[Dict[str, Any]]:
    """Download the chosen sources (called ONLY on the user's request). Each file is
    validated (parses, >0 entries) before it replaces the old copy, so a failed or
    garbage download never destroys a working database.

    v2.6: `ctl` (a Transfer) carries live progress and Pause / Resume / Cancel. Cancel
    stops the database being fetched - its previous copy stays - and skips the rest;
    databases finished earlier in the run keep their new copies. VirusShare keeps the
    lists installed before the cancel and the next update continues from there."""
    log = log or logging.getLogger("TI")
    keys = keys or {}
    ctl = ctl or Transfer()
    ids = [i for i in ids if i in BY_ID]
    ctl.count = len(ids)
    meta_d = _read_meta("downloaded")
    results = []
    for n, sid in enumerate(ids, 1):
        s = BY_ID[sid]
        res = {"id": sid, "name": s["name"], "ok": False, "detail": ""}
        if ctl.cancelled:
            res.update(detail="not started (update cancelled)", cancelled=True)
            results.append(res)
            continue
        ctl.begin(n, s["name"])
        if progress:
            progress(s["name"])
        try:
            if s.get("key"):
                k = (keys.get(s["key"]) or "").strip()
                if not k:
                    res["detail"] = "skipped - needs an abuse.ch Auth-Key (free at https://auth.abuse.ch/)"
                    results.append(res)
                    continue
                url = s["url"].format(key=k)
            elif s["url"].startswith("github:"):
                url = _github_asset(s["url"])
            else:
                url = s["url"]
            log.info("TI update: downloading %s", s["name"])
            if s["fmt"] == "bazaar_full":
                dest = db_root() / "downloaded" / s["file"]
                entries, nbytes = _install_hash_db(url, dest, log, ctl)
                meta_d[sid] = {"fetched_epoch": time.time(), "entries": entries, "bytes": nbytes,
                               "url": url.replace(keys.get(s.get("key") or "", "") or "\0", "<key>")}
                _write_meta("downloaded", meta_d)
                res.update(ok=True, detail=f"{entries:,} entries")
                results.append(res)
                continue
            if s["fmt"] == "virusshare":
                dest = db_root() / "downloaded" / s["file"]
                prev = meta_d.get(sid) or {}
                try:
                    entries, nbytes, parts = _install_virusshare(s["url"], dest, log,
                                                                 int(prev.get("parts") or 0) if dest.exists() else 0,
                                                                 ctl)
                except _PartialCancel as pc:            # keep the lists already installed
                    meta_d[sid] = {"fetched_epoch": prev.get("fetched_epoch") or time.time(), "entries": pc.entries,
                                   "parts": pc.parts, "bytes": pc.nbytes, "url": s["url"], "partial": True}
                    _write_meta("downloaded", meta_d)
                    res.update(cancelled=True, detail=f"cancelled after {pc.parts:,} lists - the {pc.entries:,} "
                                                      "hashes installed so far are kept; the next update continues")
                    log.info("TI update %s cancelled by the user after %d lists", sid, pc.parts)
                    results.append(res)
                    continue
                meta_d[sid] = {"fetched_epoch": time.time(), "entries": entries, "parts": parts,
                               "bytes": nbytes, "url": s["url"]}
                _write_meta("downloaded", meta_d)
                res.update(ok=True, detail=f"{entries:,} entries ({parts} lists)")
                results.append(res)
                continue
            if s["fmt"] == "nsrl":
                dest = db_root() / "downloaded" / s["file"]
                entries, nbytes, ver = _install_nsrl(s["url"].split(":", 1)[1], dest, log, ctl)
                for other in ("nsrl_delta", "nsrl_full"):       # one shared database
                    if other == sid or other in meta_d:
                        meta_d[other] = dict(meta_d.get(other) or {}, entries=entries)
                meta_d[sid] = {"fetched_epoch": time.time(), "entries": entries, "bytes": nbytes,
                               "version": ver, "url": NSRL_INDEX}
                _write_meta("downloaded", meta_d)
                res.update(ok=True, detail=f"{entries:,} entries (RDS {ver})")
                results.append(res)
                continue
            data = _fetch(url, ctl)
            ctl.checkpoint()                             # Cancel right after the download: keep the old copy
            ctl.phase = "building"
            if s["fmt"] == "yara":
                dest = rules_root() / "yara-forge" / "_downloaded" / s["file"]
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    names = [x for x in z.namelist() if x.endswith(".yar")]
                    if not names:
                        raise RuntimeError("no .yar in the release zip")
                    body = z.read(names[0])
                ctl.detail = "checking the rules"
                _install_yara(body, dest, ctl)
                entries = body.count(b"\nrule ") + body.count(b"\nprivate rule ")
            elif s["fmt"] == "trails":
                dest = db_root() / "downloaded" / s["file"]
                entries = _install_trails(data, dest)
            else:
                dest = db_root() / "downloaded" / s["file"]
                if url.endswith(".zip"):
                    with zipfile.ZipFile(io.BytesIO(data)) as z:
                        data = z.read([n for n in z.namelist() if not n.endswith("/")][0])
                entries = sum(1 for _ in parse_source(s, data.decode("utf-8", "replace")))
                if not entries:
                    raise RuntimeError("downloaded file has no usable entries "
                                       f"(starts: {data[:80]!r})")
                _atomic_write(dest, data)
            meta_d[sid] = {"fetched_epoch": time.time(), "url": url.replace(keys.get(s.get("key") or "", "") or
                                                                              "\0", "<key>"),
                           "entries": entries, "bytes": len(data)}
            _write_meta("downloaded", meta_d)
            res.update(ok=True, detail=f"{entries:,} entries")
        except Cancelled:
            res.update(cancelled=True, detail="cancelled - the previous copy is kept")
            log.info("TI update %s cancelled by the user", sid)
        except Exception as e:                     # network, HTTP 4xx/5xx, parse
            res["detail"] = f"{type(e).__name__}: {str(e)[:200]}"
            log.warning("TI update %s failed: %s", sid, res["detail"])
        results.append(res)
    return results


def _install_hash_db(url: str, dest: Path, log: logging.Logger,
                     ctl: Optional[Transfer] = None) -> Tuple[int, int]:
    """Download MalwareBazaar's full CSV export (zip) to disk and turn it into a local
    SQLite hash database: h(sha256, md5, sha1, sig, ftype, first). The download and the
    CSV are streamed (the CSV is ~1 GB unpacked), and the finished database only replaces
    the old one when it holds a plausible number of rows. Returns (rows, download bytes).
    v2.6: progress, Pause and Cancel via `ctl`; a cancel leaves the old database as it was."""
    import sqlite3
    ctl = ctl or Transfer()
    dest.parent.mkdir(parents=True, exist_ok=True)
    zpath = dest.with_name(dest.name + ".zip.part")
    tmp = dest.with_name(dest.name + ".part")
    for f in (zpath, tmp):
        if f.exists():
            f.unlink()
    try:
        with open(zpath, "wb") as out:
            nbytes = _stream(url, _FileSink(out), ctl)
        ctl.phase, ctl.detail = "building", ""
        con = sqlite3.connect(str(tmp))
        try:
            con.execute("PRAGMA journal_mode=OFF")
            con.execute("PRAGMA synchronous=OFF")
            con.execute("CREATE TABLE h(sha256 BLOB PRIMARY KEY, md5 BLOB, sha1 BLOB, sig TEXT, ftype TEXT, "
                        "first TEXT) WITHOUT ROWID")
            n = 0
            with zipfile.ZipFile(zpath) as z:
                name = [x for x in z.namelist() if not x.endswith("/")][0]
                with z.open(name) as fh:
                    text = io.TextIOWrapper(fh, encoding="utf-8", errors="replace", newline="")
                    batch = []
                    for row in csv.reader((ln for ln in text if ln and not ln.startswith("#")),
                                          skipinitialspace=True):
                        if len(row) < 9:
                            continue
                        h256 = row[1].strip().strip('"').lower()
                        if len(h256) != 64:
                            continue
                        try:
                            rec = (bytes.fromhex(h256), _hexb(row[2], 32), _hexb(row[3], 40),
                                   row[8].strip().strip('"')[:80], row[6].strip().strip('"')[:20],
                                   row[0].strip().strip('"')[:19])
                        except ValueError:
                            continue
                        batch.append(rec)
                        if len(batch) >= 50000:
                            con.executemany("INSERT OR IGNORE INTO h VALUES (?,?,?,?,?,?)", batch)
                            n += len(batch)
                            batch = []
                            ctl.detail = f"{n:,} hashes"
                            ctl.checkpoint()
                    if batch:
                        con.executemany("INSERT OR IGNORE INTO h VALUES (?,?,?,?,?,?)", batch)
                        n += len(batch)
            if n < 100000:
                raise RuntimeError(f"full export has only {n:,} usable rows - not installed")
            ctl.detail = f"{n:,} hashes, indexing"
            _gated(con, ctl, "CREATE INDEX h_md5 ON h(md5)", "CREATE INDEX h_sha1 ON h(sha1)")
            con.commit()
        finally:
            con.close()
        ctl.checkpoint()                                 # last chance to keep the old database
        os.replace(tmp, dest)
        log.info("TI update: local hash database built - %s hashes", f"{n:,}")
        return n, nbytes
    finally:
        for f in (zpath, tmp):
            try:
                if f.exists():
                    f.unlink()
            except OSError:
                pass


def _download_to(url: str, path: Path, ctl: Optional[Transfer] = None) -> int:
    """Stream a download to disk (no size limit in RAM), with progress, Pause, Cancel and
    resume after a dropped connection (v2.6). Returns the byte count."""
    with open(path, "wb") as out:
        return _stream(url, _FileSink(out), ctl)


def _max_parts() -> int:
    """RAMBREAKER_TI_MAX_PARTS=<n> stops a multi-file install after n NEW files (testing a
    huge database without downloading all of it). 0 / unset = everything."""
    v = os.environ.get("RAMBREAKER_TI_MAX_PARTS", "")
    return int(v) if v.isdigit() else 0


def _install_virusshare(url_tpl: str, dest: Path, log: logging.Logger, have_parts: int,
                        ctl: Optional[Transfer] = None) -> Tuple[int, int, int]:
    """VirusShare publishes numbered MD5 lists (VirusShare_00000.md5 ...). Fetch every list
    from `have_parts` on until the first one that does not exist and add the hashes to a
    local SQLite table v(md5). Lists already installed are not downloaded again, so an
    update is cheap. Returns (total hashes, bytes downloaded, lists installed).
    v2.6: Pause / Cancel via `ctl`. Every list is committed on its own, so a cancel keeps
    the lists installed so far (_PartialCancel says how many); a first install cancelled
    before any list was added leaves no file behind."""
    import sqlite3
    ctl = ctl or Transfer()
    ctl.multi = True
    dest.parent.mkdir(parents=True, exist_ok=True)
    existed = dest.exists()
    con = sqlite3.connect(str(dest))
    nbytes, part, new = 0, have_parts, 0
    limit = _max_parts()
    try:
        con.execute("PRAGMA synchronous=OFF")
        con.execute("CREATE TABLE IF NOT EXISTS v(md5 BLOB PRIMARY KEY) WITHOUT ROWID")
        while not limit or new < limit:
            ctl.detail = f"list {part + 1:,}"
            try:
                data = _fetch(url_tpl.format(part=part), ctl)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    break                              # past the newest list
                raise
            except Cancelled:
                total = con.execute("SELECT COUNT(*) FROM v").fetchone()[0]
                con.close()
                con = None
                if new and total:
                    raise _PartialCancel(total, nbytes, part)
                if not existed:
                    dest.unlink(missing_ok=True)
                raise
            nbytes += len(data)
            rows = []
            for ln in data.splitlines():
                ln = ln.strip()
                if len(ln) == 32 and not ln.startswith(b"#"):
                    try:
                        rows.append((bytes.fromhex(ln.decode("ascii")),))
                    except ValueError:
                        pass
            if not rows:
                raise RuntimeError(f"VirusShare list {part} has no MD5 lines (starts: {data[:60]!r})")
            con.executemany("INSERT OR IGNORE INTO v VALUES (?)", rows)
            con.commit()
            part += 1
            new += 1
            if part % 25 == 0:
                log.info("TI update: VirusShare list %d installed", part)
        total = con.execute("SELECT COUNT(*) FROM v").fetchone()[0]
    finally:
        if con is not None:
            con.close()
    if not total:
        raise RuntimeError("no VirusShare hashes were installed")
    return total, nbytes, part


def nsrl_latest(kind: str, index_html: Optional[str] = None) -> Tuple[str, str]:
    """(url, version) of the newest NSRL RDS zip of `kind` ('modern_minimal' or
    'modern_minimal_delta') named on NIST's download page."""
    html = index_html if index_html is not None else _get(NSRL_INDEX, 120).decode("utf-8", "replace")
    best = None
    for m in re.finditer(r"https://s3\.amazonaws\.com/rds\.nsrl\.nist\.gov/RDS/[^\"'<> ]*?/RDS_(\d{4}\.\d{2}\.\d+)_"
                         + re.escape(kind) + r"\.zip", html):
        ver = tuple(int(x) for x in m.group(1).split("."))
        if best is None or ver > best[0]:
            best = (ver, m.group(0), m.group(1))
    if best is None:
        raise RuntimeError(f"no '{kind}' download found on the NSRL page (the page layout may have changed)")
    return best[1], best[2]


_NSRL_ROW = re.compile(r"VALUES\('([0-9A-Fa-f]{64})','([0-9A-Fa-f]{40})','([0-9A-Fa-f]{32})'")


def _nsrl_open(dest: Path):
    import sqlite3
    con = sqlite3.connect(str(dest))
    con.execute("PRAGMA synchronous=OFF")
    con.execute("CREATE TABLE IF NOT EXISTS g(sha256 BLOB PRIMARY KEY, sha1 BLOB, md5 BLOB) WITHOUT ROWID")
    return con


def nsrl_import_sql(sql_lines: Iterable[str], con, ctl: Optional[Transfer] = None) -> int:
    """Add the FILE rows of an NSRL delta (.sql text with INSERT statements) to g().
    v2.6: Pause / Cancel between batches (the caller rolls a cancelled import back)."""
    n, batch = 0, []
    for ln in sql_lines:
        if not ln.startswith("INSERT INTO FILE"):
            continue
        m = _NSRL_ROW.search(ln)
        if not m:
            continue
        batch.append((bytes.fromhex(m.group(1)), bytes.fromhex(m.group(2)), bytes.fromhex(m.group(3))))
        if len(batch) >= 50000:
            con.executemany("INSERT OR IGNORE INTO g VALUES (?,?,?)", batch)
            n += len(batch)
            batch = []
            if ctl is not None:
                ctl.detail = f"{n:,} known files"
                ctl.checkpoint()
    if batch:
        con.executemany("INSERT OR IGNORE INTO g VALUES (?,?,?)", batch)
        n += len(batch)
    con.commit()
    return n


def nsrl_import_db(rds_db: Path, con, ctl: Optional[Transfer] = None) -> int:
    """Add the distinct file hashes of a full NSRL RDSv3 SQLite database (table FILE) to g().
    v2.6: the one long statement honours Pause / Cancel (aborted and rolled back)."""
    sql = ("INSERT OR IGNORE INTO g SELECT unhex(sha256), unhex(sha1), unhex(md5) FROM "
           "(SELECT DISTINCT sha256, sha1, md5 FROM rds.FILE "
           " WHERE length(sha256) = 64 AND length(sha1) = 40 AND length(md5) = 32)")
    con.execute("ATTACH DATABASE ? AS rds", (str(rds_db),))
    try:
        cur = _gated(con, ctl, sql) if ctl is not None else con.execute(sql)
        n = cur.rowcount
        con.commit()
    except BaseException:
        con.rollback()                          # DETACH is refused inside an open transaction
        raise
    finally:
        con.execute("DETACH DATABASE rds")
    return max(n, 0)


def _install_nsrl(kind: str, dest: Path, log: logging.Logger,
                  ctl: Optional[Transfer] = None) -> Tuple[int, int, str]:
    """Download the newest NSRL zip of `kind` and merge its file hashes into the local
    known-file database g(sha256, sha1, md5). A delta zip holds a .sql text file, the full
    set a ready SQLite .db; both end up in the same compact table. Returns (rows in the
    database, bytes downloaded, RDS version).
    v2.6: progress, Pause and Cancel via `ctl`. A cancelled import is rolled back; a first
    install cancelled part-way leaves no database file behind."""
    ctl = ctl or Transfer()
    url, ver = nsrl_latest(kind)
    dest.parent.mkdir(parents=True, exist_ok=True)
    existed = dest.exists()
    zpath = dest.with_name(f"nsrl_{kind}.zip.part")
    work = dest.with_name(f"nsrl_{kind}.unpack")
    try:
        log.info("TI update: NSRL %s %s - downloading %s", kind, ver, url.rsplit("/", 1)[-1])
        nbytes = _download_to(url, zpath, ctl)
        ctl.checkpoint()
        con = _nsrl_open(dest)
        try:
            with zipfile.ZipFile(zpath) as z:
                names = [x for x in z.namelist() if not x.endswith("/")]
                dbs = [x for x in names if x.lower().endswith(".db")]
                sqls = [x for x in names if x.lower().endswith(".sql") and "schema" not in x.lower()]
                if dbs:
                    ctl.phase, ctl.detail = "unpacking", ""
                    work.mkdir(parents=True, exist_ok=True)
                    out = work / "rds.db"
                    with z.open(dbs[0]) as fi, open(out, "wb") as fo:
                        while True:
                            ctl.checkpoint()
                            b = fi.read(16 * 1024 * 1024)
                            if not b:
                                break
                            fo.write(b)
                    ctl.phase, ctl.detail = "building", "importing the known files"
                    added = nsrl_import_db(out, con, ctl)
                elif sqls:
                    ctl.phase = "building"
                    added = 0
                    for name in sqls:
                        with z.open(name) as fh:
                            added += nsrl_import_sql(io.TextIOWrapper(fh, encoding="utf-8", errors="replace"),
                                                     con, ctl)
                else:
                    raise RuntimeError("the NSRL zip holds neither a .db nor a .sql file")
            if not added:
                raise RuntimeError("the NSRL download had no usable file rows")
            ctl.detail = "indexing"
            _gated(con, ctl, "CREATE INDEX IF NOT EXISTS g_sha1 ON g(sha1)",
                   "CREATE INDEX IF NOT EXISTS g_md5 ON g(md5)")
            con.commit()
            total = con.execute("SELECT COUNT(*) FROM g").fetchone()[0]
        except Cancelled:
            con.rollback()
            con.close()
            con = None
            if not existed:
                dest.unlink(missing_ok=True)          # a cancelled first install leaves nothing
            raise
        finally:
            if con is not None:
                con.close()
        return total, nbytes, ver
    finally:
        shutil.rmtree(work, ignore_errors=True)
        try:
            if zpath.exists():
                zpath.unlink()
        except OSError:
            pass


def known_file_lookup(kind: str, values: Iterable[str]) -> set:
    """The hashes (hex, lower-case) of `kind` that are in the local NSRL known-file database
    (empty set when it is not installed)."""
    import sqlite3
    p = db_root() / "downloaded" / "nsrl_known.sqlite"
    out: set = set()
    if kind not in ("sha256", "sha1", "md5") or not p.is_file():
        return out
    values = sorted(set(values))
    if not values:
        return out
    _warm_db(p, len(values))
    try:
        con = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error:
        return out
    try:
        q = f"SELECT 1 FROM g WHERE {kind} = ?"
        for v in values:
            try:
                if con.execute(q, (bytes.fromhex(v),)).fetchone():
                    out.add(v)
            except (ValueError, sqlite3.Error):
                continue
    finally:
        con.close()
    return out


def _hexb(v: str, n: int) -> Optional[bytes]:
    v = (v or "").strip().strip('"').lower()
    return bytes.fromhex(v) if len(v) == n else None


def _warm_db(path: Path, n_lookups: int) -> None:
    """Read a local hash database once, front to back, before many lookups. Thousands of
    index lookups in a cold file on a hard disk each cost a seek (windows10.dmp: 34,000
    lookups in a 263 MB database took 483 s); a sequential read of the file takes seconds
    and the lookups then come from the file cache. Skipped for a few lookups and for
    databases too big to cache (the full NSRL set)."""
    try:
        if n_lookups < 200 or Path(path).stat().st_size > 2 * 1024 ** 3:
            return
        with open(path, "rb") as f:
            while f.read(16 * 1024 * 1024):
                pass
    except OSError:
        pass


def hash_db_lookup(path: Path, kind: str, values: Iterable[str]) -> Dict[str, str]:
    """{hash: label} for the hashes (hex, lower-case) of `kind` (sha256 | sha1 | md5) that
    are in the local MalwareBazaar database. Read-only; a damaged database gives {}."""
    import sqlite3
    out: Dict[str, str] = {}
    if kind not in ("sha256", "sha1", "md5"):
        return out
    values = sorted(set(values))            # index order: neighbouring keys share pages
    if not values:
        return out
    _warm_db(Path(path), len(values))
    try:
        con = sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True)
    except sqlite3.Error:
        return out
    try:
        if con.execute("SELECT 1 FROM sqlite_master WHERE name = 'v'").fetchone():     # VirusShare: md5 only
            if kind == "md5":
                for v in values:
                    try:
                        if con.execute("SELECT 1 FROM v WHERE md5 = ?", (bytes.fromhex(v),)).fetchone():
                            out[v] = "VirusShare: known malware sample (MD5 list, no family name)"
                    except (ValueError, sqlite3.Error):
                        continue
            return out
        q = f"SELECT sig, ftype, first FROM h WHERE {kind} = ?"
        for v in values:
            try:
                row = con.execute(q, (bytes.fromhex(v),)).fetchone()
            except (ValueError, sqlite3.Error):
                continue
            if row:
                sig, ftype, first = row
                out[v] = (f"MalwareBazaar: {sig or 'malware (no family name)'}"
                          + (f" [{ftype}]" if ftype else "") + (f", first seen {first[:10]}" if first else ""))
    finally:
        con.close()
    return out


_YARA_CHECK = ("import sys, yara\n"
               "src = open(sys.argv[1], encoding='utf-8', errors='replace').read()\n"
               "yara.compile(source=src, externals=%r)\n")


def _install_yara(body: bytes, dest: Path, ctl: Optional[Transfer] = None) -> None:
    """Compile a downloaded YARA rule set and only then let it replace the old one.

    v2.6: the compile runs in the bundled Python 3 (runtime\\py3), not in this process.
    The GUI exe does not contain yara-python, so every YARA Forge update started from
    the GUI failed with "No module named 'yara'"; a compile of ~11,000 rules would also
    hold the Python lock for seconds and stall the window; and a child process can be
    stopped by Cancel."""
    import subprocess
    ctl = ctl or Transfer()
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    tmp.write_bytes(body)
    try:
        p = subprocess.Popen([platform_compat.python3_exe(), "-I", "-c", _YARA_CHECK % (YARA_EXTERNALS,), str(tmp)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             creationflags=platform_compat.no_window_flags())
        while True:
            try:
                _, err = p.communicate(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                if ctl.cancelled:
                    p.kill()
                    p.communicate()
                    raise Cancelled()
        if p.returncode != 0:
            last = [ln for ln in err.decode("utf-8", "replace").splitlines() if ln.strip()][-1:] or ["no output"]
            raise RuntimeError(f"the downloaded YARA rules do not compile: {last[0][:200]}")
        ctl.checkpoint()                                 # Cancel during the check: keep the old rules
        os.replace(tmp, dest)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def _atomic_write(dest: Path, data: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    tmp.write_bytes(data)
    os.replace(tmp, dest)


def _install_trails(zdata: bytes, dest: Path) -> int:
    """Keep only the trail lists (malware/, malicious/, suspicious/) of the repo zip."""
    tmp = dest.with_name(dest.name + ".part")
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    n = 0
    with zipfile.ZipFile(io.BytesIO(zdata)) as z:
        for name in z.namelist():
            parts = name.split("/")
            if len(parts) != 3 or parts[1] not in ("malware", "malicious", "suspicious") \
                    or not parts[2].endswith(".txt"):
                continue
            safe = re.sub(r"[^\w.\-]", "_", parts[2])
            out = tmp / parts[1] / safe
            out.parent.mkdir(parents=True, exist_ok=True)
            body = z.read(name)
            out.write_bytes(body)
            n += sum(1 for ln in body.splitlines() if ln.strip() and not ln.startswith(b"#"))
    if not n:
        raise RuntimeError("trails archive had no trail lists")
    old = dest.with_name(dest.name + ".old")
    if dest.exists():
        shutil.rmtree(old, ignore_errors=True)
        os.replace(dest, old)
    os.replace(tmp, dest)
    shutil.rmtree(old, ignore_errors=True)
    return n


# ---------------------------------------------------------------------- parse
YARA_EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HEX = {32: "md5", 40: "sha1", 64: "sha256"}


def _lines(text: str):
    for ln in text.splitlines():
        ln = ln.strip()
        if ln and not ln.startswith(("#", ";", "//")):
            yield ln


def parse_source(src: Dict[str, Any], text: str, label: str = ""):
    """Yield (kind, value, label, weight). kind: ip | cidr | domain | url | md5 | sha1 | sha256.
    weight 1..3 = how strong a listing is (IPsum: number of lists)."""
    fmt = src["fmt"]
    if fmt == "ipsum":
        for ln in _lines(text):
            p = ln.split()
            if len(p) >= 2 and _IP_RE.match(p[0]) and p[1].isdigit():
                n = int(p[1])
                if n >= 2:                         # 1 list = too noisy (scanners)
                    yield "ip", p[0], f"listed by {n} public blocklists", 3 if n >= 5 else 2 if n >= 3 else 1
    elif fmt == "iplist":
        for ln in _lines(text):
            ip = ln.split()[0].split(",")[0]
            if _IP_RE.match(ip):
                yield "ip", ip, label or src["name"], 2
    elif fmt == "sslbl":
        for row in csv.reader(_lines(text)):
            if len(row) >= 2 and _IP_RE.match(row[1].strip()):
                yield "ip", row[1].strip(), "botnet C2 (SSL blacklist)", 3
    elif fmt == "drop":
        for ln in _lines(text):
            try:
                d = json.loads(ln)
            except ValueError:
                continue
            if d.get("cidr"):
                yield "cidr", d["cidr"], f"Spamhaus DROP {d.get('sblid', '')}".strip(), 3
    elif fmt == "urllist":
        for ln in _lines(text):
            if ln.lower().startswith(("http://", "https://")):
                yield "url", ln, label or "phishing URL", 3
    elif fmt == "trails":
        for ln in _lines(text):
            v = ln.split("#", 1)[0].strip()
            if not v or v.startswith("/") or " " in v:
                continue                             # path-only trails need traffic, not memory
            if v.lower().startswith(("http://", "https://")):
                yield "url", v, label, 3
                continue
            host = v.split("/", 1)[0]
            if ":" in host and _IP_RE.match(host.rsplit(":", 1)[0]):
                host = host.rsplit(":", 1)[0]
            if _IP_RE.match(host):
                yield "ip", host, label, 2 if "suspicious" in label else 3
            elif "." in host:
                yield "domain", host.lower().strip("."), label, 2 if "suspicious" in label else 3
    elif fmt == "threatfox":
        rows = csv.reader(io.StringIO("\n".join(l for l in text.splitlines() if not l.startswith("#"))),
                          skipinitialspace=True)
        for r in rows:
            if len(r) < 6:
                continue
            ioc, typ, fam = r[2].strip().strip('"'), r[3].strip().lower(), r[5].strip()
            lab = f"ThreatFox: {fam or 'malware'}"
            if typ in ("ip:port",):
                yield "ip", ioc.rsplit(":", 1)[0], lab, 3
            elif typ == "domain":
                yield "domain", ioc.lower(), lab, 3
            elif typ == "url":
                yield "url", ioc, lab, 3
            elif typ in ("md5_hash", "sha1_hash", "sha256_hash"):
                yield typ.split("_")[0], ioc.lower(), lab, 3
    elif fmt == "urlhaus":
        for r in csv.reader(l for l in text.splitlines() if l and not l.startswith("#")):
            if len(r) >= 3 and r[2].lower().startswith("http"):
                yield "url", r[2], f"URLhaus: {r[5] if len(r) > 5 else 'malware URL'}", 3
    elif fmt == "bazaar":
        for r in csv.reader(l for l in text.splitlines() if l and not l.startswith("#")):
            if len(r) >= 2:
                h = r[1].strip().strip('"').lower()
                if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
                    yield "sha256", h, f"MalwareBazaar: {r[8].strip() if len(r) > 8 else 'malware'}", 3


# source id -> list files that exist but could not be opened in the last iter_source()
# (v2.4: antivirus blocks access to a detected list; open() raises OSError [Errno 22]
# and the whole threat-intel step used to end with a traceback)
UNREADABLE: Dict[str, List[str]] = {}


def iter_source(src: Dict[str, Any]):
    """Parse the newest local copy of a non-YARA source. Files that cannot be read are
    skipped and remembered in UNREADABLE[src id]."""
    p, _, _ = source_path(src)
    UNREADABLE[src["id"]] = []
    if p is None:
        return
    if src["fmt"] == "trails":
        for f in sorted(p.rglob("*.txt")):
            label = f"{f.parent.name}: {f.stem}"          # e.g. 'malware: asyncrat'
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                UNREADABLE[src["id"]].append(f.name)
                continue
            yield from parse_source(src, text, label)
    else:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            UNREADABLE[src["id"]].append(p.name)
            return
        yield from parse_source(src, text)


# ---------------------------------------------------------------------- match
def _suffixes(domain: str) -> List[str]:
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]   # never the bare TLD


def match(indicators: Dict[str, Dict[str, Any]], only: Optional[Iterable[str]] = None,
          log: Optional[logging.Logger] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Compare the case's indicators with every local feed.

    indicators: {"ip": {value: ctx}, "domain": {...}, "url": {...}, "sha256": {...},
                 "md5": {...}, "sha1": {...}} (values lower-case for domains/hashes).
    Streams each feed once and looks entries up in the (small) case sets, so even
    the million-line trail set needs no big index in memory.
    Returns (hits, sources_used)."""
    log = log or logging.getLogger("TI")
    ips = indicators.get("ip", {})
    ip_objs = []
    for v in ips:
        try:
            ip_objs.append((ipaddress.ip_address(v), v))
        except ValueError:
            pass
    dom_by_suffix: Dict[str, List[str]] = {}
    for d in indicators.get("domain", {}):
        for s in _suffixes(d):
            dom_by_suffix.setdefault(s, []).append(d)
    urls = {u.lower().rstrip("/"): u for u in indicators.get("url", {})}
    hits: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    used = []
    allow = set(only) if only else None
    for s in SOURCES:
        if s["fmt"] == "yara" or (allow is not None and s["id"] not in allow):
            continue
        p, where, m = source_path(s)
        if p is None:
            continue
        t0 = time.time()
        n = 0
        cidrs = []
        if s["fmt"] == "nsrl":
            continue                                   # known files, not threats: see known_file_lookup()
        if s["fmt"] in ("bazaar_full", "virusshare"):
            # millions of hashes: look the case's few thousand hashes up in the database
            # instead of streaming the database past them
            UNREADABLE[s["id"]] = []
            for kind in ("sha256", "sha1", "md5"):
                for v, label in hash_db_lookup(p, kind, list(indicators.get(kind, {}))).items():
                    hits.setdefault((kind, v, s["id"]), {"kind": kind, "value": v, "source": s["id"],
                                                         "source_name": s["name"], "label": label,
                                                         "weight": 3, "listed_as": ""})
            n = int(m.get("entries") or 0)
        for kind, val, label, weight in (() if s["fmt"] in ("bazaar_full", "virusshare") else iter_source(s)):
            n += 1
            found: List[Tuple[str, str]] = []
            if kind == "ip":
                if val in ips:
                    found.append(("ip", val))
            elif kind == "cidr":
                try:
                    cidrs.append((ipaddress.ip_network(val, strict=False), label, weight))
                except ValueError:
                    pass
                continue
            elif kind == "domain":
                for d in dom_by_suffix.get(val, []):
                    found.append(("domain", d))
            elif kind == "url":
                u = val.lower().rstrip("/")
                if u in urls:
                    found.append(("url", urls[u]))
            elif kind in ("md5", "sha1", "sha256"):
                if val in indicators.get(kind, {}):
                    found.append((kind, val))
            for k, v in found:
                key = (k, v, s["id"])
                if key not in hits:
                    hits[key] = {"kind": k, "value": v, "source": s["id"], "source_name": s["name"],
                                 "label": label, "weight": weight,
                                 "listed_as": val if val != v else ""}
        for net, label, weight in cidrs:
            for ipo, v in ip_objs:
                if ipo.version == net.version and ipo in net:
                    hits.setdefault(("ip", v, s["id"]), {"kind": "ip", "value": v, "source": s["id"],
                                                          "source_name": s["name"], "label": label,
                                                          "weight": weight, "listed_as": str(net)})
        st = next(x for x in status() if x["id"] == s["id"])
        used.append({"id": s["id"], "name": s["name"], "where": where, "fetched": st["fetched"],
                     "age_days": st["age_days"], "entries": n, "seconds": round(time.time() - t0, 1),
                     "unreadable": list(UNREADABLE.get(s["id"]) or [])})
        if UNREADABLE.get(s["id"]) and log:
            log.warning("TI feed %s: %d file(s) could not be read and were skipped (blocked by antivirus?): %s",
                        s["id"], len(UNREADABLE[s["id"]]), ", ".join(UNREADABLE[s["id"]][:5]))
        log.info("TI feed %s: %d entries checked in %.1fs", s["id"], n, time.time() - t0)
    return list(hits.values()), used
