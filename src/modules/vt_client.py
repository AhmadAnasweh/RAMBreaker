"""VirusTotal v3 lookups for the "DFIR + Threat Intel" mode (RAMBreaker v2.2).

Lookups ONLY: GET /files/<sha256>, /ip_addresses/<ip>, /domains/<domain>.
Nothing is ever uploaded; private / reserved IPs and internal domain names are
refused before any request is made. Every identifier sent is appended to
<case>/threat_intelligence/vt_sent.txt so the analyst can show exactly what left
the machine.

Free keys allow 4 requests/minute and 500/day. The client paces itself (default
4/min, settable for premium keys), stops cleanly on a quota error (HTTP 429
QuotaExceededError) and leaves the rest as "not checked yet"; a later run continues.
Answers are cached in <app>/cache/vt/ (shared by all cases), so one hash is looked
up once: found = 7 days, not found = 1 day.

RAMBREAKER_VT_BASE overrides the API base URL (used by the offline test server).
"""

import ipaddress
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from modules import platform_compat

BASE = os.environ.get("RAMBREAKER_VT_BASE", "https://www.virustotal.com/api/v3")
GUI = "https://www.virustotal.com/gui"
TTL_FOUND = 7 * 86400
TTL_MISSING = 86400
_INTERNAL_SUFFIX = (".local", ".lan", ".localdomain", ".internal", ".corp", ".home", ".home.arpa",
                    ".intranet", ".private", ".arpa", ".test", ".example", ".invalid", ".localhost")
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class QuotaExceeded(Exception):
    pass


class BadKey(Exception):
    pass


def public_ip(v: str) -> bool:
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def public_domain(d: str) -> bool:
    d = (d or "").lower().strip(".")
    return bool(_DOMAIN_RE.match(d)) and not d.endswith(_INTERNAL_SUFFIX)


def cache_dir() -> Path:
    env = os.environ.get("RAMBREAKER_VT_CACHE")          # tests: keep mock answers out of the real cache
    return Path(env) if env else platform_compat.app_root() / "cache" / "vt"


class VTClient:
    def __init__(self, key: str, per_minute: float = 4.0, sent_log: Optional[Path] = None,
                 log: Optional[logging.Logger] = None, cache: Optional[Path] = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.key = (key or "").strip()
        self.gap = 60.0 / max(0.1, float(per_minute or 4))
        self.sent_log = sent_log
        self.log = log or logging.getLogger("VT")
        self.cache = cache or cache_dir()
        self.sleep = sleep
        self._last = 0.0
        self.requests = 0
        self.cache_hits = 0
        self.quota_hit = False

    # ------------------------------------------------------------- plumbing
    def _cpath(self, kind: str, ident: str) -> Path:
        return self.cache / kind / (re.sub(r"[^\w.\-:]", "_", ident).replace(":", "_") + ".json")

    def _cached(self, kind: str, ident: str) -> Optional[Dict[str, Any]]:
        p = self._cpath(kind, ident)
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        ttl = TTL_FOUND if d.get("found") else TTL_MISSING
        if time.time() - d.get("fetched_epoch", 0) > ttl:
            return None
        return d

    def _store(self, kind: str, ident: str, d: Dict[str, Any]) -> None:
        p = self._cpath(kind, ident)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(d), encoding="utf-8")
        os.replace(tmp, p)

    def _request(self, path: str) -> Dict[str, Any]:
        wait = self.gap - (time.time() - self._last)
        if self._last and wait > 0:
            self.sleep(wait)
        self._last = time.time()
        req = urllib.request.Request(f"{BASE}/{path}", headers={
            "x-apikey": self.key, "accept": "application/json", "User-Agent": "RAMBreaker/2.2"})
        self.requests += 1
        try:
            with urllib.request.urlopen(req, timeout=60) as r:          # nosec - fixed VT URL
                return {"status": r.status, "body": json.loads(r.read().decode("utf-8", "replace"))}
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode("utf-8", "replace"))
            except ValueError:
                body = {}
            code = (body.get("error") or {}).get("code", "")
            if e.code == 404:
                return {"status": 404, "body": body}
            if e.code == 429 or code in ("QuotaExceededError", "TooManyRequestsError"):
                self.quota_hit = True
                raise QuotaExceeded(code or "HTTP 429")
            if e.code in (401, 403) or code in ("WrongCredentialsError", "AuthenticationRequiredError",
                                                "ForbiddenError"):
                raise BadKey(code or f"HTTP {e.code}")
            raise RuntimeError(f"HTTP {e.code} {code}".strip())

    def _note_sent(self, kind: str, ident: str) -> None:
        if self.sent_log:
            with open(self.sent_log, "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{kind}\t{ident}\n")

    # --------------------------------------------------------------- public
    def lookup(self, kind: str, ident: str) -> Dict[str, Any]:
        """kind: file | ip | domain. Returns a summary dict:
        {found, malicious, suspicious, harmless, undetected, total, label, names, first_seen,
         last_analysis, reputation, tags, link, cached, raw}"""
        ident = ident.strip().lower() if kind != "ip" else ident.strip()
        if kind == "ip" and not public_ip(ident):
            raise ValueError("not a public IP - never sent")
        if kind == "domain" and not public_domain(ident):
            raise ValueError("internal or invalid domain - never sent")
        c = self._cached(kind, ident)
        if c is not None:
            self.cache_hits += 1
            c = dict(c)
            c["cached"] = True
            return c
        path = {"file": "files", "ip": "ip_addresses", "domain": "domains"}[kind] + "/" + ident
        self._note_sent(kind, ident)
        r = self._request(path)
        d = summarise(kind, ident, r["body"] if r["status"] == 200 else None)
        d["fetched_epoch"] = time.time()
        self._store(kind, ident, d)
        d["cached"] = False
        return d


def summarise(kind: str, ident: str, body: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    link = f"{GUI}/{ {'file': 'file', 'ip': 'ip-address', 'domain': 'domain'}[kind] }/{ident}"
    if not body:
        return {"found": False, "kind": kind, "id": ident, "link": link, "verdict": "not on VirusTotal"}
    a = (body.get("data") or {}).get("attributes") or {}
    st = a.get("last_analysis_stats") or {}
    mal, sus = int(st.get("malicious", 0)), int(st.get("suspicious", 0))
    total = sum(int(v) for v in st.values() if isinstance(v, int))
    ptc = a.get("popular_threat_classification") or {}
    label = ptc.get("suggested_threat_label") or ""
    if not label:
        names = [r.get("result") for r in (a.get("last_analysis_results") or {}).values()
                 if r.get("category") == "malicious" and r.get("result")]
        label = max(set(names), key=names.count) if names else ""
    verdict = ("malicious" if mal >= 3 else "suspicious" if (mal or sus) else
               "clean" if total else "no verdict")
    out = {"found": True, "kind": kind, "id": ident, "link": link, "verdict": verdict,
           "malicious": mal, "suspicious": sus, "harmless": int(st.get("harmless", 0)),
           "undetected": int(st.get("undetected", 0)), "total": total, "label": label,
           "reputation": a.get("reputation"), "tags": (a.get("tags") or [])[:12],
           "last_analysis": _ts(a.get("last_analysis_date"))}
    if kind == "file":
        out.update(names=(a.get("names") or [])[:8], meaningful_name=a.get("meaningful_name", ""),
                   type=a.get("type_description", ""), first_seen=_ts(a.get("first_submission_date")),
                   size=a.get("size"), signature=(a.get("signature_info") or {}).get("product", ""),
                   signer=(a.get("signature_info") or {}).get("signers", "")[:160])
    elif kind == "ip":
        out.update(country=a.get("country", ""), as_owner=a.get("as_owner", ""), asn=a.get("asn"))
    else:
        out.update(registrar=a.get("registrar", ""), categories=sorted(set((a.get("categories") or {}).values()))[:6],
                   created=_ts(a.get("creation_date")))
    return out


def _ts(v) -> str:
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(int(v))) if v else ""
    except (TypeError, ValueError):
        return ""
