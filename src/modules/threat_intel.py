"""DFIR + Threat Intel (RAMBreaker v2.2): dump, hash, check locally, then ask VirusTotal
about a short list only. Everything lands in <case>/threat_intelligence/ and in the
"Threat Intelligence" tab of report.html.

Steps (each one resumable; a finished step is reused on the next run):
  1. dump   every recoverable file, every process executable (NOT memory regions), and
            only the memory regions the injection correlator flagged HIGH/MEDIUM
            (fileless code never exists as a file). Engine: modules/extract_jobs.py,
            Linux: linux.pagecache.RecoverFs (one pass), macOS: mac.pagecache --dump.
  2. hash   SHA-256/SHA-1/MD5 of every output, and how far that hash can be trusted:
            complete / partial (pages missing) / rebuilt from memory (never matches disk).
  3. local  YARA (YARA Forge + the analyst's custom rules) on every dumped object, and
            offline feeds (IPsum, abuse.ch, Maltrail, Spamhaus...) against every hash, the
            network connections and the IPs / domains / URLs already extracted.
  4. shortlist  "look here first": objects with a reason (YARA, feed hit, injection,
            odd location, flagged process), scored.
  5. VirusTotal (optional, user's key): hashes / public IPs / domains of the shortlist
            only, paced to the key's rate, cached, resumable. Nothing is uploaded.
  6. ti_report.json + report.html regenerated.
"""

import json
import logging
import os
import re
import shutil
import tarfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from modules import case_index as ci
from modules import progress as pg
from modules import ti_sources as ts
from modules import vt_client
from modules import safe_zip
from modules.extract_jobs import Job, describe, protect_existing
from utils.ui import msg_info, msg_ok, msg_warn, msg_fail

PAGE = 4096
EXEC_EXT = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".ps1", ".psm1", ".vbs", ".vbe",
            ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".jar", ".py", ".sh", ".elf", ".so", ".lnk",
            ".docm", ".xlsm", ".pptm", ".dylib", ".msi", ".iso", ".apk", ".pl", ".rb", ".php"}
ODD_WIN = ("\\temp\\", "\\tmp\\", "\\appdata\\", "\\downloads\\", "\\users\\public\\", "\\$recycle.bin\\",
           "\\perflogs\\", "\\desktop\\", "\\programdata\\", "\\windows\\tasks\\", "\\intel\\")
SYS_WIN = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\", "\\windows\\microsoft.net\\",
           "\\program files\\", "\\program files (x86)\\", "\\windows\\servicing\\", "\\windows\\assembly\\",
           "\\windows\\fonts\\", "\\windows\\inf\\", "\\windows\\globalization\\", "\\windows\\")
ODD_NIX = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/", "/private/tmp/", "/users/shared/",
           "/library/launchagents/", "/.cache/", "/downloads/")
SYS_NIX = ("/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/etc/", "/opt/", "/system/", "/applications/",
           "/snap/", "/var/lib/", "/boot/")
DEFAULTS = {"yara_set": "core", "vt_rate": 4.0, "vt_max": 100, "max_regions": 60, "yara_workers": 0,
            "yara_max_mb": 512, "redump": False, "vt_only": False,
            # v2.5: every dumped object in its own password-protected ZIP (modules/safe_zip.py)
            "protect": True, "zip_password": safe_zip.DEFAULT_PASSWORD}
# YARA decrypts a protected object in memory: objects above this size are scanned
# one at a time so several workers never hold large objects at once
YARA_BIG_PROTECTED = 64 << 20


# =================================================================== helpers
def _norm_win(p: str) -> str:
    p = (p or "").replace("/", "\\").lower()
    p = re.sub(r"^\\device\\harddiskvolume\d+", "", p)
    p = re.sub(r"^\\\?\?\\", "", p)
    p = re.sub(r"^[a-z]:", "", p)
    if p.startswith("\\systemroot\\"):
        p = "\\windows\\" + p[len("\\systemroot\\"):]
    return p


def location_class(path: str, os_type: str) -> str:
    """odd (Temp, AppData, Downloads, /tmp ...) | system (OS / program folders) | other."""
    if not path:
        return "other"
    if os_type == "windows":
        p = _norm_win(path)
        if any(s in p for s in ODD_WIN) and not p.startswith("\\programdata\\microsoft\\"):
            return "odd"
        if any(p.startswith(s) for s in SYS_WIN):
            return "system"
        return "other"
    p = path.lower()
    if any(s in p for s in ODD_NIX):
        return "odd"
    if any(p.startswith(s) for s in SYS_NIX):
        return "system"
    return "other"


def is_executable(name: str, typ: str) -> bool:
    t = (typ or "").lower()
    if t.startswith(("pe ", "elf", "mach-o", "script")):
        return True
    return Path(name or "").suffix.lower() in EXEC_EXT


def page_gaps(p: Path) -> Tuple[int, int]:
    """(all-zero 4 KiB pages, total pages). A resident file has no all-zero page
    except where the real file has one; memory dumps fill missing pages with zeros.
    A protected ZIP carries both numbers in its metadata (nothing is decrypted)."""
    m = safe_zip.read_meta(p) if str(p).lower().endswith(safe_zip.SUFFIX) else None
    if m is not None and "zero_pages" in m:
        return int(m["zero_pages"]), int(m["pages"])
    zero = total = 0
    z = bytes(PAGE)
    try:
        with open(p, "rb") as f:
            while True:
                b = f.read(PAGE)
                if not b:
                    break
                total += 1
                if len(b) == PAGE and b == z:
                    zero += 1
    except OSError:
        pass
    return zero, total


def pe_declared_size(p: Path) -> Optional[int]:
    """End of the last section's raw data (the size the PE file has on disk, without overlay)."""
    m = safe_zip.read_meta(p) if str(p).lower().endswith(safe_zip.SUFFIX) else None
    if m is not None:
        return m.get("pe_raw_end")
    try:
        with open(p, "rb") as f:
            return safe_zip.pe_raw_end(f.read(4096))
    except OSError:
        return None


def hash_quality(entry: Dict[str, Any], abs_path: Path) -> Tuple[str, str]:
    """(quality, why). quality: complete | partial | rebuilt | region | empty."""
    if not entry.get("size") or entry.get("nonzero_pct", 0) == 0:
        return "empty", "no byte was in RAM"
    kind = entry.get("kind")
    if kind == "region":
        return "region", "memory region - a hash of live memory, never a file on disk"
    if kind == "process":
        return "rebuilt", "executable rebuilt from process memory - its hash differs from the file on disk"
    name = safe_zip.plain_name(abs_path.name).lower()
    if name.endswith(".img"):
        return "rebuilt", "ImageSectionObject (the file as mapped for execution) - not the on-disk bytes"
    if name.endswith(".vacb"):
        return "partial", "SharedCacheMap views - only the parts of the file that were cached"
    zero, total = page_gaps(abs_path)
    if zero:
        return "partial", f"{zero} of {total} pages were not in RAM (zero-filled)"
    exp = entry.get("expected_size")
    if exp and entry["size"] < exp:
        return "partial", f"recovered {entry['size']:,} of {exp:,} bytes"
    if (entry.get("type") or "").startswith("PE "):
        dec = pe_declared_size(abs_path)
        if dec and entry["size"] < dec:
            return "partial", f"PE sections end at {dec:,} bytes, recovered {entry['size']:,}"
    return "complete", "every page present - the hash should match the original file"


# ============================================================ YARA (workers)
_RULES = None
_ZIP_PW = safe_zip.DEFAULT_PASSWORD


def _yara_init(compiled: str, zip_password: str = safe_zip.DEFAULT_PASSWORD):
    global _RULES, _ZIP_PW
    import yara
    _RULES = yara.load(compiled)
    _ZIP_PW = zip_password


def _yara_scan(job: Tuple[int, str, str]) -> Tuple[int, List[Dict[str, Any]], str]:
    idx, path, orig = job
    try:
        ext = Path(orig or path).suffix.lstrip(".").lower()
        ext_vars = {"filename": Path(orig or path).name, "filepath": orig or path, "extension": ext}
        if path.lower().endswith(safe_zip.SUFFIX) and safe_zip.read_meta(path) is not None:
            # protected object: decrypted into this worker's memory only, never to disk
            ms = _RULES.match(data=safe_zip.read_member(path, _ZIP_PW), timeout=60, externals=ext_vars)
        else:
            ms = _RULES.match(path, timeout=60, externals=ext_vars)
    except Exception as e:                      # timeout / unreadable
        return idx, [], f"{type(e).__name__}: {str(e)[:120]}"
    out = []
    for m in ms:
        meta = dict(m.meta or {})
        strs = []
        for s in (m.strings or [])[:6]:
            for inst in list(s.instances)[:2]:
                d = bytes(inst.matched_data[:48])
                strs.append({"id": s.identifier, "offset": inst.offset,
                             "text": d.decode("latin-1").encode("unicode_escape").decode("ascii")[:96]})
        out.append({"rule": m.rule, "namespace": m.namespace, "tags": list(m.tags or []),
                    "score": _int(meta.get("score")), "description": str(meta.get("description", ""))[:300],
                    "author": str(meta.get("author", ""))[:120], "reference": str(meta.get("reference", ""))[:300],
                    "date": str(meta.get("date", "")), "strings": strs})
    return idx, out, ""


def _int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def compile_rules(yara_set: str, custom_dirs: Iterable[str], log: logging.Logger) -> Dict[str, Any]:
    """Compile the chosen YARA Forge set + every custom file (each file on its own, so
    one broken file is skipped instead of breaking all). Cached by content digest."""
    import hashlib
    import yara
    files: List[Tuple[str, Path, str]] = []
    src = ts.BY_ID.get(f"yaraforge_{yara_set}") or ts.BY_ID["yaraforge_core"]
    p, where, meta = ts.source_path(src)
    if p:
        files.append((f"yaraforge_{yara_set}", p, where))
    for c in ts.custom_rule_files(custom_dirs):
        files.append((f"custom_{re.sub(r'[^0-9A-Za-z_]', '_', c.stem)}", c, "custom"))
    good: Dict[str, str] = {}
    info = {"files": [], "skipped": [], "rules": 0, "compiled": ""}
    for ns, f, where in files:
        try:
            txt = f.read_text(encoding="utf-8", errors="replace")
            r = yara.compile(source=txt, externals=ts.YARA_EXTERNALS)
            n = sum(1 for _ in r)
            good[ns] = txt
            info["files"].append({"namespace": ns, "file": str(f), "where": where, "rules": n,
                                  "modified": time.strftime("%Y-%m-%d", time.localtime(f.stat().st_mtime))})
            info["rules"] += n
        except Exception as e:
            info["skipped"].append({"file": str(f), "error": str(e)[:300]})
            log.warning("YARA: skipped %s: %s", f, e)
    if not good:
        return info
    dig = hashlib.sha256(json.dumps(sorted((k, hashlib.sha256(v.encode()).hexdigest())
                                           for k, v in good.items())).encode()).hexdigest()[:20]
    from modules import platform_compat
    cdir = platform_compat.app_root() / "cache" / "yara"
    cdir.mkdir(parents=True, exist_ok=True)
    out = cdir / f"rules_{dig}.yarc"
    if not out.is_file():
        rules = yara.compile(sources=good, externals=ts.YARA_EXTERNALS)
        rules.save(str(out))
    info["compiled"] = str(out)
    return info


# ================================================================= pipeline
class ThreatIntel:
    def __init__(self, case: Path, image: str, vol, log: logging.Logger, opts: Dict[str, Any]):
        self.case = Path(case)
        self.image = image
        self.vol = vol
        self.log = log
        self.o = dict(DEFAULTS, **{k: v for k, v in (opts or {}).items() if v is not None})
        self.os = (vol.os_type if vol else "") or ci.read_summary(self.case)["os"] or "windows"
        self.ti = self.case / "threat_intelligence"
        self.dumps = self.ti / "dumps"
        self.ti.mkdir(parents=True, exist_ok=True)
        self.t0 = time.time()
        self.timings: Dict[str, float] = {}
        self.notes: List[str] = []

    # ---------------------------------------------------------------- utils
    TI_STEPS = ["dumping all files", "dumping all process executables", "dumping injection-flagged regions",
                "hashing every dumped object", "YARA scan", "offline threat feeds", "VirusTotal lookups"]

    def stage(self, name: str, state: str = "start", detail: str = ""):
        i = self.TI_STEPS.index(name) + 1 if name in self.TI_STEPS else 0
        pg.emit("stage", name=f"Threat intel: {name}", state=state, detail=detail,
                ti_step=i, ti_steps=len(self.TI_STEPS))

    def _save(self, name: str, obj: Any):
        p = self.ti / name
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(obj, indent=1, default=str), encoding="utf-8")
        os.replace(tmp, p)

    def _load(self, name: str) -> Any:
        return ci.load_json(self.ti / name)

    def _job(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        spec = dict(spec, case=str(self.case), image=self.image, protect=bool(self.o["protect"]),
                    zip_password=self.o["zip_password"])
        j = Job(spec, self.vol, self.log)
        j.execute()
        return ci.load_json(Path(spec["dest"]) / "manifest.json") or {}

    def _dump_lanes(self) -> int:
        """How many file-dump batches may run at once (v2.4): up to 4, a third of the
        CPU threads, 1 for a big dump on a spinning disk, fewer when RAM is short.
        RAMBREAKER_TI_LANES=<n> overrides it."""
        env = os.environ.get("RAMBREAKER_TI_LANES", "")
        if env.isdigit():
            return max(1, min(8, int(env)))
        lanes = max(1, min(4, (os.cpu_count() or 2) // 3))
        try:
            from modules.platform_compat import io_limited_jobs, available_ram_gb
            lanes = min(lanes, io_limited_jobs(self.image, lanes))
            avail = available_ram_gb()
            if avail:
                lanes = min(lanes, max(1, int((avail - 2.0) / 1.5)))
        except Exception:
            pass
        return max(1, lanes)

    def _done(self, sub: str) -> Optional[Dict[str, Any]]:
        m = self.dumps / sub / "manifest.json"
        if m.is_file() and not self.o["redump"]:
            if self.o["protect"]:
                # a dump from before v2.5 (or made with protection off): zip its plain files now
                n = protect_existing(self.dumps / sub, self.o["zip_password"])
                if n:
                    msg_info(f"Threat intel: {n:,} earlier dumped file(s) in {sub} put into password-protected ZIPs")
            return ci.load_json(m)
        return None

    # ----------------------------------------------------------------- dump
    def dump_files(self) -> Dict[str, Any]:
        man = self._done("files")
        if man is not None:
            msg_info("Threat intel: file dump already done for this case - reusing it")
            return man
        dest = self.dumps / "files"
        if dest.exists():
            shutil.rmtree(dest)                      # our own half-finished dump only
        src, rows = ci.file_list(self.case)
        if self.os == "windows":
            rows = [r for r in rows if r.get("offset")]
            # v2.4: virtual disks, VM state and paging files are multi-GB containers. Vol3
            # writes them out page by page (windows10.dmp: one 2.3 GB Hyper-V .VMRS cache map
            # took over an hour from a hard disk) and a hash or YARA scan of a partial
            # container says nothing. They stay available one by one in the Extraction workspace.
            big = [r for r in rows if is_container_file(str(r.get("name") or r.get("path") or ""))]
            if big:
                skip = {id(r) for r in big}
                rows = [r for r in rows if id(r) not in skip]
                names = sorted({str(r.get("name") or "")[:60] for r in big})
                self.notes.append(
                    f"{len(big)} container file object(s) were not dumped in the bulk pass (virtual disks, "
                    f"virtual-machine state, page/hibernation files: {', '.join(names[:6])}"
                    f"{' ...' if len(names) > 6 else ''}). They can be several GB and a partial copy cannot be "
                    "hashed or scanned meaningfully; dump one in the Extraction workspace if you need it.")
                msg_info(f"Threat intel: {len(big)} container file(s) (virtual disk / VM state / page file) skipped")
            msg_info(f"Threat intel: dumping ALL {len(rows):,} file objects from {src or 'filescan'} "
                     "(batched by address)")
            lanes = self._dump_lanes()
            # one lane: big batches (fewer Volatility start-ups); several lanes: smaller
            # batches so the lanes stay evenly loaded
            return self._job({"kind": "files", "dest": str(dest), "items": rows,
                              "batch": 400 if lanes == 1 else 100, "quiet": 400,
                              "flags": "auto", "vol2_fallback": False, "parallel": lanes})
        if self.os == "linux" and (self.vol.vol_version or "vol3") == "vol3":
            return self._recoverfs(dest, rows)
        if self.os == "mac":
            return self._mac_all(dest)
        rows = [r for r in rows if r.get("dumpable")]
        keep = [r for r in rows if is_executable(r.get("name", ""), "") or
                location_class(r.get("path", ""), self.os) == "odd"][:1500]
        self.notes.append(f"Volatility 2 Linux image: files are dumped one per Volatility run, so only "
                          f"executables, scripts and files in odd locations were dumped ({len(keep)} of "
                          f"{len(rows)} cached files).")
        return self._job({"kind": "files", "dest": str(dest), "items": keep})

    def _recoverfs(self, dest: Path, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """linux.pagecache.RecoverFs: every cached file in ONE pass (tarball), unpacked
        with flat safe names (paths from a dump are untrusted: no traversal)."""
        j = Job({"kind": "files", "case": str(self.case), "image": self.image, "dest": str(dest), "quiet": 500,
                 "protect": bool(self.o["protect"]), "zip_password": self.o["zip_password"]}, self.vol, self.log)
        dest.mkdir(parents=True, exist_ok=True)
        stg = j.staging()
        msg_info("Threat intel: recovering the whole cached file system (linux.pagecache.RecoverFs, one pass)")
        rc, so, se, dur, to = j.run(j.v3(stg) + ["linux.pagecache.RecoverFs", "--compression-format", "gz"],
                                    "linux.pagecache.RecoverFs", floor=1800)
        tars = [t for t in j.outputs(stg) if ".tar" in t.name.lower()]
        sizes = {r.get("path"): r.get("size") for r in rows}
        items = []
        out_dir = dest / "files"
        out_dir.mkdir(parents=True, exist_ok=True)
        src = None
        if tars:
            n = 0
            prot = safe_zip.is_protected(tars[0])
            if j.protect and not prot:                  # Vol3 without the output hook
                tars[0] = Path(safe_zip.pack_file(tars[0], j.zip_pw))
                prot = True
            # protected: the tarball is decrypted as a stream in memory and every file
            # in it goes straight into its own protected ZIP - nothing plain on disk
            if prot:
                src = safe_zip.AesZipReader(tars[0], j.zip_pw)
            with (tarfile.open(fileobj=src, mode="r|*") if prot else tarfile.open(tars[0], "r:*")) as tf:
                for m in tf:
                    if not m.isreg():
                        continue
                    n += 1
                    orig = "/" + m.name.split("/", 1)[-1] if "/" in m.name else "/" + m.name
                    nm = f"{n:06d}_{ci.safe_name(Path(orig).name or 'file', 80)}"
                    t = out_dir / nm
                    f = tf.extractfile(m)
                    if f is None:
                        continue
                    if prot:
                        t = out_dir / (nm + safe_zip.SUFFIX)
                        safe_zip.pack_stream(f, str(t), nm, j.zip_pw)
                    else:
                        with open(t, "wb") as w:
                            shutil.copyfileobj(f, w, 1 << 20)
                    e = j.out_entry(t, note="")
                    exp = sizes.get(orig)
                    it = {"label": orig, "source": {"path": orig, "size": exp}, "outputs": [e],
                          "status": "ok" if e.get("nonzero_pct", 0) > 0 else "empty", "detail": ""}
                    items.append(it)
            if src is not None:
                src.close()                     # Windows cannot move a file that is still open
            shutil.move(str(tars[0]), str(dest / tars[0].name))
        j.drop_staging(stg)
        ok = sum(1 for i in items if i["status"] == "ok")
        man = {"kind": "files", "engine": "linux.pagecache.RecoverFs", "ok": ok,
               "empty": len(items) - ok, "failed": 0 if tars else 1,
               "detail": "" if tars else (("timed out" if to else j.err_line(se)) or "no tarball written"),
               "items": items, "duration_s": round(dur, 1)}
        if src is not None:
            man["protection"] = {"format": safe_zip.ENCRYPTION, "password": j.zip_pw}
        (dest / "manifest.json").write_text(json.dumps(man, indent=1), encoding="utf-8")
        msg_ok(f"Threat intel: {len(items):,} cached files recovered ({ok:,} with content) in {dur:.0f}s")
        return man

    def _mac_all(self, dest: Path) -> Dict[str, Any]:
        j = Job({"kind": "files", "case": str(self.case), "image": self.image, "dest": str(dest), "quiet": 500,
                 "protect": bool(self.o["protect"]), "zip_password": self.o["zip_password"]}, self.vol, self.log)
        dest.mkdir(parents=True, exist_ok=True)
        stg = j.staging()
        msg_info("Threat intel: dumping every cached file (mac.pagecache --dump, one pass)")
        rc, so, se, dur, to = j.run(j.v3(stg) + ["mac.pagecache.Pagecache", "--dump"],
                                    "mac.pagecache.Pagecache#all", floor=1800)
        items = []
        for f in j.outputs(stg):
            m = re.match(r"mac_pagecache\.(.+)\.(0x[0-9a-f]+)\.dmp$", safe_zip.plain_name(f.name), re.I)
            orig = "/" + m.group(1).replace("_", "/") if m else f.name     # name is path with / -> _
            t = j.move(f, dest / "files")
            e = j.out_entry(t)
            items.append({"label": orig, "source": {"path": orig, "path_approx": True}, "outputs": [e],
                          "status": "ok" if e.get("nonzero_pct", 0) > 0 else "empty", "detail": ""})
        j.drop_staging(stg)
        ok = sum(1 for i in items if i["status"] == "ok")
        man = {"kind": "files", "engine": "mac.pagecache.Pagecache --dump", "ok": ok, "empty": len(items) - ok,
               "failed": 0 if items else 1, "detail": "" if items else (j.err_line(se) or "no files written"),
               "items": items, "duration_s": round(dur, 1)}
        if j.protect and items:
            man["protection"] = {"format": safe_zip.ENCRYPTION, "password": j.zip_pw}
        (dest / "manifest.json").write_text(json.dumps(man, indent=1), encoding="utf-8")
        return man

    def dump_procs(self) -> Dict[str, Any]:
        man = self._done("processes")
        if man is not None:
            msg_info("Threat intel: process dump already done for this case - reusing it")
            return man
        dest = self.dumps / "processes"
        if dest.exists():
            shutil.rmtree(dest)
        procs = ci.process_list(self.case)
        if self.os == "mac":
            self.notes.append("macOS: Volatility has no executable-only dumper; process executables are "
                              "covered by the page-cache file dump (the app bundles' binaries) instead.")
            return {"kind": "procs", "items": [], "ok": 0, "empty": 0, "failed": 0}
        msg_info(f"Threat intel: dumping the executable of ALL {len(procs)} processes")
        return self._job({"kind": "procs", "dest": str(dest), "what": ["exe"], "quiet": 100,
                          "items": [{"pid": p["pid"], "name": p["name"]} for p in procs]})

    def flagged_regions(self) -> List[Dict[str, Any]]:
        inj = ci.load_json(self.case / "json" / "injection_correlation.json")
        rows = []
        for f in (inj.get("findings") or []) if isinstance(inj, dict) else []:
            if f.get("confidence") in ("HIGH", "MEDIUM") and f.get("base_address"):
                rows.append(f)
        rows.sort(key=lambda f: (f.get("confidence") != "HIGH",))
        return rows[: int(self.o["max_regions"])]

    def dump_regions(self) -> Dict[str, Any]:
        man = self._done("regions")
        if man is not None:
            return man
        dest = self.dumps / "regions"
        if dest.exists():
            shutil.rmtree(dest)
        regs = self.flagged_regions()
        if not regs:
            msg_info("Threat intel: no HIGH/MEDIUM injection findings - no memory regions to scan")
            dest.mkdir(parents=True, exist_ok=True)
            m = {"kind": "vad", "items": [], "ok": 0, "empty": 0, "failed": 0}
            (dest / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
            return m
        by: Dict[str, Dict[str, Any]] = {}
        for f in regs:
            pid = str(f.get("pid"))
            e = by.setdefault(pid, {"pid": pid, "name": f.get("process_name", ""), "regions": []})
            e["regions"].append({"start": f["base_address"], "end": f.get("end_address"),
                                 "injection": f"{f.get('confidence')}: {f.get('evidence', '')}"[:200]})
        msg_info(f"Threat intel: dumping {len(regs)} injection-flagged memory region(s) in {len(by)} process(es)")
        return self._job({"kind": "vad", "dest": str(dest), "mode": "region", "items": list(by.values())})

    # ------------------------------------------------------------ inventory
    def inventory(self, mans: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        procs = {p["pid"]: p for p in ci.process_list(self.case)}
        img_path = self._process_image_paths()
        inv: List[Dict[str, Any]] = []
        for sub, kind in (("files", "file"), ("processes", "process"), ("regions", "region")):
            man = mans.get(sub) or {}
            base = self.dumps / sub
            for it in man.get("items") or []:
                srcd = it.get("source") or {}
                for o in it.get("outputs") or []:
                    ap = base / o["file"]
                    pid = str(srcd.get("pid", "") or "")
                    path = srcd.get("path") or ""
                    lib = False
                    if kind == "process":
                        path = img_path.get(pid, "")
                        # Linux/mac process dumps also hold the libraries mapped into the
                        # process (linux.elfs): name each by its own path, not the process
                        obj = str(o.get("object") or "")
                        if obj.startswith("/") and obj != path:
                            path, lib = obj, True
                    e = {"kind": kind, "name": (Path(path).name if path else "") or srcd.get("name") or
                         it.get("label", ""), "path": path, "pid": pid,
                         "process": srcd.get("name") or (procs.get(pid) or {}).get("name", ""),
                         "file": str(ap.relative_to(self.ti)).replace("\\", "/"),
                         "size": o.get("size", 0), "type": o.get("type", ""), "sha256": o.get("sha256", ""),
                         "sha1": o.get("sha1", ""), "md5": o.get("md5", ""),
                         "nonzero_pct": o.get("nonzero_pct", 0), "object": o.get("object", ""),
                         "injection": o.get("injection", ""), "expected_size": srcd.get("size") or None,
                         "flags": (procs.get(pid) or {}).get("flags", []) if pid else [], "library": lib}
                    if kind == "region":
                        e["name"] = f"{e['process']} region {safe_zip.plain_name(Path(o['file']).name)}"
                    if not e["sha1"] and ap.is_file() and e["size"]:
                        d = describe(ap)
                        e["sha1"] = d.get("sha1", "")
                    e["quality"], e["quality_why"] = hash_quality(e, ap)
                    e["location"] = location_class(path, self.os)
                    e["executable"] = is_executable(e["name"], e["type"])
                    inv.append(e)
        # link each process to the on-disk copy of its executable found among the files
        by_path: Dict[str, Dict[str, Any]] = {}
        for e in inv:
            if e["kind"] == "file" and e["quality"] == "complete" and e["path"]:
                k = _norm_win(e["path"]) if self.os == "windows" else e["path"]
                by_path.setdefault(k, e)
        for e in inv:
            if e["kind"] == "process" and e["path"]:
                k = _norm_win(e["path"]) if self.os == "windows" else e["path"]
                f = by_path.get(k)
                if f:
                    e["disk_copy"] = {"file": f["file"], "sha256": f["sha256"]}
        return inv

    def _process_image_paths(self) -> Dict[str, str]:
        """PID -> path of its executable (Windows dlllist first module / Linux elfs / maps)."""
        out: Dict[str, str] = {}
        jd = self.case / "json"
        if self.os == "windows":
            for r in ci._rows(ci._find(jd, "windows_dlllist")):
                pid = str(r.get("PID", ""))
                path = r.get("Path") or ""
                if pid and path and pid not in out and str(path).lower().endswith(".exe"):
                    out[pid] = str(path)
        else:
            for r in ci._rows(ci._find(jd, f"{self.os}_elfs", "linux_elfs")):
                pid = str(r.get("PID", ""))
                path = str(r.get("Path") or r.get("File Path") or "")
                if pid and path.startswith("/") and pid not in out and ".so" not in Path(path).name:
                    out[pid] = path
        return out

    # ---------------------------------------------------------------- YARA
    def yara(self, inv: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        info = compile_rules(self.o["yara_set"], self.o.get("custom_dirs") or [], self.log)
        if not info.get("compiled"):
            msg_warn("Threat intel: no YARA rules could be compiled - YARA step skipped")
            return [], info
        msg_info(f"Threat intel: YARA - {info['rules']:,} rules from {len(info['files'])} file(s)"
                 + (f", {len(info['skipped'])} file(s) skipped (errors)" if info["skipped"] else ""))
        cap = int(self.o["yara_max_mb"]) << 20
        jobs, skipped_big, big = [], 0, []
        for i, e in enumerate(inv):
            if e["quality"] == "empty":
                continue
            if e["size"] > cap:
                skipped_big += 1
                continue
            j = (i, str(self.ti / e["file"]), e["path"] or e["name"])
            if e["size"] > YARA_BIG_PROTECTED and e["file"].lower().endswith(safe_zip.SUFFIX):
                big.append(j)
            else:
                jobs.append(j)
        workers = int(self.o["yara_workers"]) or max(1, min(8, (os.cpu_count() or 4) - 2))
        hits: List[Dict[str, Any]] = []
        errors = 0
        t = time.time()
        done = 0
        total = len(jobs) + len(big)
        # a protected object is decrypted in the worker's memory: the big ones run in a
        # one-worker pool after the rest, so RAM never holds several of them at once
        for batch, nw in ((jobs, workers), (big, 1)):
            if not batch:
                continue
            with ProcessPoolExecutor(max_workers=nw, initializer=_yara_init,
                                     initargs=(info["compiled"], self.o["zip_password"])) as ex:
                futs = [ex.submit(_yara_scan, j) for j in batch]
                for fu in as_completed(futs):
                    idx, ms, err = fu.result()
                    done += 1
                    if err:
                        errors += 1
                    for m in ms:
                        e = inv[idx]
                        m.update({"object": e["name"], "kind": e["kind"], "path": e["path"], "pid": e["pid"],
                                  "process": e["process"], "sha256": e["sha256"], "file": e["file"],
                                  "severity": yara_severity(m), "note": unreliable_on_memory(m)})
                        hits.append(m)
                    if done % 500 == 0:
                        msg_info(f"Threat intel: YARA {done:,}/{total:,} objects scanned, {len(hits)} hit(s)")
                        pg.emit("progress", done=done, total=total, label="YARA")
        jobs = jobs + big
        info.update(scanned=len(jobs), errors=errors, skipped_too_big=skipped_big, seconds=round(time.time() - t, 1),
                    workers=workers)
        msg_ok(f"Threat intel: YARA scanned {len(jobs):,} objects in {time.time() - t:.0f}s: {len(hits)} hit(s)")
        return hits, info

    # --------------------------------------------------------------- feeds
    def indicators(self, inv: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        ind: Dict[str, Dict[str, Any]] = {"ip": {}, "domain": {}, "url": {}, "sha256": {}, "sha1": {}, "md5": {}}

        def add(kind, v, where):
            if not v:
                return
            ind[kind].setdefault(v, [])
            if where not in ind[kind][v] and len(ind[kind][v]) < 6:
                ind[kind][v].append(where)

        for e in inv:
            if e["quality"] != "empty":
                for h in ("sha256", "sha1", "md5"):
                    add(h, e.get(h, "").lower(), f"{e['kind']}: {e['name']}")
        nm = ci.load_json(self.case / "json" / "network_map.json")
        for c in (nm.get("connections") or []) if isinstance(nm, dict) else []:
            ip = _host(c.get("remote", ""))
            if ip and vt_client.public_ip(ip):
                add("ip", ip, f"connection: {c.get('process', '')} (PID {c.get('pid', '')}) "
                              f"{c.get('proto', '')} {c.get('state', '')}".strip())
        ij = self.case / "iocs" / "json"
        for nm_, kind in (("ioc_ipv4.json", "ip"), ("ioc_domain.json", "domain"), ("ioc_url_http.json", "url")):
            d = ci.load_json(ij / nm_)
            for v in (d.get("values") or []) if isinstance(d, dict) else []:
                v = str(v).strip()
                if kind == "ip" and vt_client.public_ip(v):
                    add("ip", v, "string in memory (IOC list)")
                elif kind == "domain" and vt_client.public_domain(v.lower()):
                    add("domain", v.lower(), "string in memory (IOC list)")
                elif kind == "url" and v.lower().startswith(("http://", "https://")):
                    add("url", v, "string in memory (IOC list)")
                    h = _url_host(v)
                    if h and vt_client.public_domain(h):
                        add("domain", h, "host of a URL in memory")
        bh = ci.load_json(ij / "browser_history.json")
        for r in ci._rows(None) if not bh else _browser_rows(bh):
            u = str(r.get("url") or r.get("URL") or "")
            if u.lower().startswith(("http://", "https://")):
                add("url", u, "browser history")
                h = _url_host(u)
                if h and vt_client.public_domain(h):
                    add("domain", h, "browser history")
        return ind

    def feeds(self, ind) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        msg_info(f"Threat intel: offline feeds - checking {len(ind['ip']):,} IPs, {len(ind['domain']):,} domains, "
                 f"{len(ind['url']):,} URLs and {len(ind['sha256']):,} file hashes on this PC (nothing is sent)")
        hits, used = ts.match(ind, log=self.log)
        for u in used:
            if u.get("unreadable"):
                names = ", ".join(u["unreadable"][:4]) + (" ..." if len(u["unreadable"]) > 4 else "")
                self.notes.append(
                    f"{u['name']}: {len(u['unreadable'])} list file(s) could not be opened and were skipped "
                    f"({names}). Antivirus software blocks or removes threat-intel lists it detects as malware; "
                    "to use them, exclude the threat_intel_db folder (see DEFENDER.md) and update the databases again.")
        for h in hits:
            where = ind.get(h["kind"], {}).get(h["value"], [])
            h["found_in"] = where
            conn = any(w.startswith(("connection", "browser")) for w in where) or h["kind"] in ("sha256", "sha1", "md5")
            if h["kind"] in ("sha256", "sha1", "md5"):
                h["confidence"] = "HIGH"
            elif conn:
                h["confidence"] = "HIGH" if h["weight"] >= 2 else "MEDIUM"
            else:
                h["confidence"] = "MEDIUM" if h["weight"] >= 3 else "LOW"
        # string-only hits inside a SORTED run of domains are blocklist / hosts-file / AV data
        str_only = {h["value"] for h in hits if h["kind"] in ("domain", "ip") and h["confidence"] != "HIGH"}
        if str_only:
            inlist = self.sorted_list_context(str_only)
            for h in hits:
                if h["value"] in inlist and h["confidence"] != "HIGH":
                    h["confidence"] = "LOW"
                    h["blocklist"] = True
                    h["note"] = ("found inside an alphabetically sorted list of domains in memory "
                                 f"({inlist[h['value']]}) - looks like a blocklist, hosts file or AV data, "
                                 "not activity")
            n = sum(1 for h in hits if h.get("blocklist"))
            if n:
                self.notes.append(f"{n} feed hit(s) were found inside sorted domain lists in memory (for example "
                                  "a hosts-file blocklist or browser/antivirus protection data). They are shown as "
                                  "LOW and are not sent to VirusTotal.")
        # many string-only domain hits = a blocklist / AV signature set sitting in memory
        str_dom = [h for h in hits if h["kind"] in ("domain", "url") and h["confidence"] != "HIGH"
                   and not h.get("blocklist")]
        if len(str_dom) > 150:
            for h in str_dom:
                h["confidence"] = "LOW"
                h["note"] = "one of many string-only hits - likely a blocklist, hosts file or AV data in memory"
            self.notes.append(f"{len(str_dom)} domain/URL feed hits come only from strings in memory. That many "
                              "usually means a blocklist, hosts file or antivirus signature data was in RAM; "
                              "they are shown as LOW.")
        msg_ok(f"Threat intel: offline feeds - {len(hits)} hit(s) "
               f"({sum(1 for h in hits if h['confidence'] == 'HIGH')} HIGH)")
        return hits, used

    def sorted_list_context(self, values) -> Dict[str, str]:
        """value -> short context for every value whose occurrence in the strings file sits
        between two domain-like neighbours in alphabetical order (prev < value < next).
        One streaming pass; returns {} when no strings file exists."""
        sf = next((p for p in (self.case / "strings_ascii.txt", self.case / "strings_all.txt") if p.is_file()), None)
        if sf is None:
            return {}
        dom = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$|^\d{1,3}(?:\.\d{1,3}){3}$")
        want = {v.lower() for v in values}
        found: Dict[str, str] = {}
        last_dom, since = "", 99            # nearest domain-like line before, lines ago
        pend: List[List[Any]] = []          # [value, previous domain, lines left to look ahead]
        try:
            with open(sf, "r", encoding="utf-8", errors="replace") as f:
                for ln in f:
                    s = ln.strip().lower()
                    is_dom = bool(dom.match(s))
                    if pend:                         # memory lists are often broken by junk strings:
                        keep = []                    # take the next domain-like line within 3
                        for c in pend:
                            if is_dom:
                                if c[1] < c[0] < s:
                                    found.setdefault(c[0], f"between '{c[1]}' and '{s}'")
                            elif c[2] > 1:
                                c[2] -= 1
                                keep.append(c)
                        pend = keep
                    if s in want and s not in found and last_dom and since <= 3:
                        pend.append([s, last_dom, 3])
                    if is_dom:
                        last_dom, since = s, 1
                    else:
                        since += 1
        except OSError:
            return found
        return found

    # ----------------------------------------------------------- shortlist
    def shortlist(self, inv, yhits, fhits) -> List[Dict[str, Any]]:
        obj: Dict[str, Dict[str, Any]] = {}

        def entry(key, **kw):
            e = obj.get(key)
            if e is None:
                e = obj[key] = dict(kw, reasons=[], score=0)
            return e

        def reason(e, pts, text):
            e["reasons"].append({"points": pts, "text": text})

        by_file = {e["file"]: e for e in inv}
        for h in yhits:
            e0 = by_file.get(h["file"], {})
            e = entry("obj:" + h["file"], type=e0.get("kind", h["kind"]), name=h["object"], path=h["path"],
                      pid=h["pid"], process=h["process"], sha256=h["sha256"], file=h["file"],
                      quality=e0.get("quality", ""))
            pts = {"HIGH": 90, "MEDIUM": 65, "LOW": 30}[h["severity"]]
            reason(e, pts, f"YARA {h['rule']} ({h['namespace']}, score {h['score'] if h['score'] is not None else '?'})"
                           + (f": {h['description'][:120]}" if h["description"] else ""))
        for h in fhits:
            if h["kind"] in ("sha256", "sha1", "md5"):
                for e0 in inv:
                    if e0.get(h["kind"], "").lower() == h["value"]:
                        e = entry("obj:" + e0["file"], type=e0["kind"], name=e0["name"], path=e0["path"],
                                  pid=e0["pid"], process=e0["process"], sha256=e0["sha256"], file=e0["file"],
                                  quality=e0["quality"])
                        reason(e, 95, f"hash listed by {h['source_name']}: {h['label']}")
            else:
                e = entry(f"{h['kind']}:{h['value']}", type=h["kind"], name=h["value"], path="", pid="",
                          process="", sha256="", file="", quality="")
                pts = {"HIGH": 85, "MEDIUM": 35, "LOW": 15}[h["confidence"]]
                reason(e, pts, f"{h['source_name']}: {h['label']}"
                               + (f" (listed as {h['listed_as']})" if h.get("listed_as") else ""))
                if h["confidence"] == "LOW":
                    e["reasons"][-1]["low_feed"] = True
                e["found_in"] = h.get("found_in", [])
        flagged_done, flagged_pid = set(), {}
        for e0 in inv:
            if e0["kind"] == "region":
                e = entry("obj:" + e0["file"], type="region", name=e0["name"], path="", pid=e0["pid"],
                          process=e0["process"], sha256=e0["sha256"], file=e0["file"], quality=e0["quality"])
                reason(e, 40 if e0["injection"].startswith("HIGH") else 25, f"injection finding {e0['injection']}")
            elif e0["kind"] == "process" and e0["flags"] and not e0.get("library"):
                e = entry("obj:" + e0["file"], type="process", name=e0["name"], path=e0["path"], pid=e0["pid"],
                          process=e0["process"], sha256=e0["sha256"], file=e0["file"], quality=e0["quality"])
                reason(e, 45, "flagged process: " + "; ".join(e0["flags"])[:200])
                flagged_done.add(e0["pid"])
            elif e0["kind"] == "process" and e0["flags"] and e0["pid"] not in flagged_pid:
                flagged_pid[e0["pid"]] = e0               # only libraries came back for it
            elif e0["executable"] and e0["location"] == "odd" and e0["quality"] != "empty":
                e = entry("obj:" + e0["file"], type=e0["kind"], name=e0["name"], path=e0["path"], pid=e0["pid"],
                          process=e0["process"], sha256=e0["sha256"], file=e0["file"], quality=e0["quality"])
                reason(e, 40, "executable or script in an unusual location (Temp, AppData, Downloads, /tmp ...)")
        # a flagged process whose own executable was not in RAM: ONE entry for the process
        # (its libraries are not the suspect; their hashes are generic system files)
        for pid, e0 in flagged_pid.items():
            if pid in flagged_done:
                continue
            e = entry(f"proc:{pid}", type="process", name=e0["process"] or f"PID {pid}", path="", pid=pid,
                      process=e0["process"], sha256="", file="", quality="")
            reason(e, 45, "flagged process: " + "; ".join(e0["flags"])[:200]
                   + " (its executable was not in this memory image)")
        # connection IPs are always worth a reputation check
        nm = ci.load_json(self.case / "json" / "network_map.json")
        for c in (nm.get("connections") or []) if isinstance(nm, dict) else []:
            ip = _host(c.get("remote", ""))
            if ip and vt_client.public_ip(ip):
                e = entry(f"ip:{ip}", type="ip", name=ip, path="", pid="", process="", sha256="", file="", quality="")
                pn, pp = str(c.get("process") or ""), str(c.get("pid") or "")
                if not pp and "/" in pn and pn.rsplit("/", 1)[1].isdigit():
                    pn, pp = pn.rsplit("/", 1)            # macOS netstat: "apsd/400"
                txt = f"remote end of a network connection ({pn} PID {pp})" if pp else                     f"remote end of a network connection ({pn or 'unknown process'})"
                if not any(r["text"] == txt for r in e["reasons"]):
                    reason(e, 15, txt)
        # an entry whose ONLY reasons are LOW feed hits (a domain seen only as a string, or
        # inside a blocklist in memory) stays in the Feed hits table: on a real PC there are
        # thousands (windows10.dmp: 3,149) and they would bury everything else
        out = [e for e in obj.values() if not all(r.get("low_feed") for r in e["reasons"])]
        dropped = len(obj) - len(out)
        if dropped:
            self.notes.append(f"{dropped:,} indicator(s) whose only reason is a LOW feed hit are listed under "
                              "'Feed hits' but not on the 'look here first' list.")
        for e in out:
            pts = sorted((r["points"] for r in e["reasons"]), reverse=True)
            e["score"] = min(100, pts[0] + sum(min(10, p // 5) for p in pts[1:]))
        # v2.4: optional NIST NSRL database - say when a shortlisted file is a known,
        # published software file. Context only: NSRL also lists hacking tools, so the
        # score is not changed.
        try:
            shas = {(e.get("sha256") or "").lower() for e in out
                    if e.get("type") in ("file", "process") and e.get("sha256")}
            known = ts.known_file_lookup("sha256", shas) if shas else set()
            for e in out:
                if (e.get("sha256") or "").lower() in known:
                    e["known_file"] = "NSRL"
                    e["reasons"].append({"points": 0, "text":
                                         "Context: this exact file is in the NIST NSRL list of known software "
                                         "files (a published file, usually not the thing to look at first)."})
            if known:
                self.notes.append(f"{len(known)} item(s) on the 'look here first' list are known software files "
                                  "(NIST NSRL). They keep their score; the note is shown in their 'Why' column.")
        except Exception as ex:
            self.log.debug("NSRL lookup skipped: %s", ex)
        out.sort(key=lambda e: -e["score"])
        return out

    # ------------------------------------------------------------------ VT
    def virustotal(self, short: List[Dict[str, Any]], inv: List[Dict[str, Any]]) -> Dict[str, Any]:
        key = self.o.get("vt_key") or ""
        res: Dict[str, Any] = {"enabled": bool(key), "checked": 0, "from_cache": 0, "sent": 0,
                               "not_checked": 0, "stopped": "", "results": [], "rate_per_min": self.o["vt_rate"],
                               "max_lookups": self.o["vt_max"]}
        if not key:
            res["stopped"] = "no VirusTotal key - local checks only"
            return res
        cands: List[Tuple[str, str, Dict[str, Any]]] = []
        seen = set()
        by_file = {e["file"]: e for e in inv}
        for s in short:
            if s["type"] in ("file", "process", "region"):
                e0 = by_file.get(s["file"], {})
                h = (e0.get("disk_copy") or {}).get("sha256") or s.get("sha256")
                if s["type"] == "region" and not any("YARA" in r["text"] for r in s["reasons"]):
                    continue                          # a region hash means nothing to VT without a YARA hit
                if h and ("file", h) not in seen:
                    seen.add(("file", h))
                    cands.append(("file", h, s))
            elif s["type"] in ("ip", "domain"):
                # blocklist / string-only LOW hits are not worth a lookup; connections always are
                if not (any(r["points"] >= 35 for r in s["reasons"]) or
                        any(r["text"].startswith("remote end of a network connection") for r in s["reasons"])):
                    continue
                if (s["type"], s["name"]) not in seen:
                    seen.add((s["type"], s["name"]))
                    cands.append((s["type"], s["name"], s))
            elif s["type"] == "url":
                h = _url_host(s["name"])
                if h and vt_client.public_domain(h) and ("domain", h) not in seen:
                    seen.add(("domain", h))
                    cands.append(("domain", h, s))
        # a hash VirusTotal can know first: rebuilt / partial hashes without an on-disk copy last
        def _vt_rank(c):
            kind, ident, s0 = c
            e0 = by_file.get(s0.get("file", ""), {})
            weak = kind == "file" and s0.get("quality") in ("rebuilt", "partial", "region")                 and not (e0.get("disk_copy") or {}).get("sha256")
            return (weak, -s0["score"])
        cands.sort(key=_vt_rank)
        sent_log = self.ti / "vt_sent.txt"
        c = vt_client.VTClient(key, per_minute=self.o["vt_rate"], sent_log=sent_log, log=self.log)
        cap = int(self.o["vt_max"])
        msg_info(f"Threat intel: VirusTotal - {len(cands)} shortlisted item(s); up to {cap} new lookups at "
                 f"{self.o['vt_rate']:g}/min (cached answers are free). Only hashes, public IPs and domains are sent.")
        vtdir = self.ti / "vt"
        new = 0
        for i, (kind, ident, s) in enumerate(cands, 1):
            row = {"kind": kind, "id": ident, "object": s["name"], "score": s["score"]}
            cached = c._cached(kind, ident.lower() if kind != "ip" else ident)
            if cached is None and new >= cap:
                row.update(state="not checked", why=f"lookup limit for this run ({cap}) reached")
                res["results"].append(row)
                res["not_checked"] += 1
                continue
            if res["stopped"] and cached is None:
                row.update(state="not checked", why=res["stopped"])
                res["results"].append(row)
                res["not_checked"] += 1
                continue
            try:
                d = c.lookup(kind, ident)
                if not d.get("cached"):
                    new += 1
                row.update(state="checked", **{k: v for k, v in d.items() if k not in ("kind", "id")})
                res["checked"] += 1
                (vtdir / kind).mkdir(parents=True, exist_ok=True)
                (vtdir / kind / (re.sub(r"[^\w.\-]", "_", ident) + ".json")).write_text(
                    json.dumps(d, indent=1), encoding="utf-8")
                if not d.get("cached"):
                    pg.emit("progress", done=i, total=len(cands), label="VirusTotal")
                    msg_info(f"VirusTotal {i}/{len(cands)}: {kind} {ident[:70]} -> {d.get('verdict')}"
                             + (f" ({d.get('malicious')}/{d.get('total')})" if d.get("found") else ""))
            except vt_client.QuotaExceeded as e:
                res["stopped"] = (f"VirusTotal quota reached ({e}) - the rest is 'not checked'; run "
                                  "'Continue VirusTotal lookups' later (free keys: 500/day)")
                msg_warn(res["stopped"])
                row.update(state="not checked", why=res["stopped"])
                res["not_checked"] += 1
            except vt_client.BadKey as e:
                res["stopped"] = f"VirusTotal refused the API key ({e}) - check the key"
                msg_fail(res["stopped"])
                row.update(state="not checked", why=res["stopped"])
                res["not_checked"] += 1
            except ValueError as e:
                row.update(state="skipped", why=str(e))
            except Exception as e:
                row.update(state="error", why=f"{type(e).__name__}: {str(e)[:160]}")
                if "urlopen error" in str(e) or "timed out" in str(e):
                    res["stopped"] = "VirusTotal not reachable (offline?) - local results only"
                    msg_warn(res["stopped"])
            res["results"].append(row)
        res["sent"] = c.requests
        res["from_cache"] = c.cache_hits
        msg_ok(f"Threat intel: VirusTotal - {res['checked']} checked ({c.requests} sent, {c.cache_hits} from cache), "
               f"{res['not_checked']} not checked")
        return res

    # ----------------------------------------------------------------- run
    def run(self) -> int:
        pg.emit("ti", state="start", case=str(self.case))
        vt_only = bool(self.o["vt_only"])
        if vt_only and not (self.ti / "inventory.json").is_file():
            msg_warn("Threat intel: no earlier threat-intel run for this case - running the full mode")
            vt_only = False
        if vt_only:
            inv = self._load("inventory.json") or []
            yhits = self._load("yara_hits.json") or []
            fhits = self._load("feed_hits.json") or []
            prev = self._load("ti_report.json") or {}
            yinfo, used = prev.get("yara") or {}, prev.get("feeds_used") or []
            mans = {}
            # keep what the dump / feed stages explained the first time (blocklists, Vol2 limits ...)
            self.notes = list(prev.get("stage_notes") or [
                n for n in prev.get("notes") or []
                if not n.startswith(_FIXED_NOTE_HEADS) and "only reason is a LOW feed hit" not in n])
        else:
            if not self.image or not Path(self.image).is_file():
                msg_fail(f"Threat intel needs the memory dump of this case: {self.image or '(none)'}")
                return 2
            mans = {}
            for sub, fn, label in (("files", self.dump_files, "dumping all files"),
                                   ("processes", self.dump_procs, "dumping all process executables"),
                                   ("regions", self.dump_regions, "dumping injection-flagged regions")):
                self.stage(label)
                t = time.time()
                try:
                    mans[sub] = fn() or {}
                except Exception as e:
                    self.log.exception("threat intel %s failed", sub)
                    msg_warn(f"Threat intel: {label} failed: {e}")
                    mans[sub] = {"items": [], "failed": 1, "detail": str(e)}
                self.timings[sub] = round(time.time() - t, 1)
                self.stage(label, "done")
            self.stage("hashing every dumped object")
            inv = self.inventory(mans)
            self._save("inventory.json", inv)
            self.stage("hashing every dumped object", "done")
            self.stage("YARA scan")
            t = time.time()
            yhits, yinfo = self.yara(inv)
            self.timings["yara"] = round(time.time() - t, 1)
            self._save("yara_hits.json", yhits)
            self.stage("YARA scan", "done")
            self.stage("offline threat feeds")
            t = time.time()
            fhits, used = self.feeds(self.indicators(inv))
            self.timings["feeds"] = round(time.time() - t, 1)
            self._save("feed_hits.json", fhits)
            self.stage("offline threat feeds", "done")
        self.stage_notes = list(self.notes)
        short = self.shortlist(inv, yhits, fhits)
        self.stage("VirusTotal lookups")
        t = time.time()
        vt = self.virustotal(short, inv)
        self.timings["virustotal"] = round(time.time() - t, 1)
        self._save("vt_results.json", vt)
        self.stage("VirusTotal lookups", "done")
        apply_vt(short, inv, vt)
        self._save("shortlist.json", short)
        self.write_report(inv, yhits, fhits, used, yinfo, short, vt, mans)
        pg.emit("ti", state="done", case=str(self.case), shortlist=len(short))
        return 0

    def write_report(self, inv, yhits, fhits, used, yinfo, short, vt, mans):
        dbs = ts.status()
        stale = [d for d in dbs if d["stale"]]
        removed = [d for d in dbs if d.get("removed")]
        missing_dl = [d for d in dbs if not d["present"] and not d["bundled"] and not d.get("removed")
                      and not d.get("optional")]          # optional = the user's choice, not a gap
        for d in removed:
            self.log.warning("Threat-intel database '%s' was downloaded on %s but its file is gone - "
                             "antivirus software often removes these lists (they contain malware "
                             "addresses). It was NOT checked. See DEFENDER.md (folder threat_intel_db).",
                             d["name"], d.get("removed_fetched") or "?")
        dump_stats = {}
        for sub in ("files", "processes", "regions"):
            m = mans.get(sub) or ci.load_json(self.dumps / sub / "manifest.json") or {}
            dump_stats[sub] = {"ok": m.get("ok", 0), "empty": m.get("empty", 0), "failed": m.get("failed", 0),
                               "objects": len(m.get("items") or []), "detail": m.get("detail", "")}
        q = {}
        for e in inv:
            q[e["quality"]] = q.get(e["quality"], 0) + 1
        sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for h in yhits:
            sev[h["severity"]] += 1
        fsev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for h in fhits:
            fsev[h["confidence"]] += 1
        verdicts: Dict[str, int] = {}
        for r in vt.get("results", []):
            k = r.get("verdict") if r.get("state") == "checked" else r.get("state")
            verdicts[k] = verdicts.get(k, 0) + 1
        prev = self._load("ti_report.json") or {}
        rep = {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "os": self.os, "image": self.image,
            # a VirusTotal-only rerun keeps the first run's stage times (and adds its own VT time)
            "duration_s": round(time.time() - self.t0, 1) if mans else
            round((prev.get("duration_s") or 0) + self.timings.get("virustotal", 0), 1),
            "timings": dict(prev.get("timings") or {}, **{k: v for k, v in self.timings.items()
                                                          if v or k not in (prev.get("timings") or {})})
            if not mans else dict(self.timings),
            "dumps": dump_stats if mans else prev.get("dumps", dump_stats),
            "hash_quality": q, "objects": len(inv),
            "yara": yinfo, "yara_by_severity": sev, "feeds_used": used, "feed_by_confidence": fsev,
            "databases": dbs, "stale": [d["name"] for d in stale],
            "not_downloaded": [d["name"] for d in missing_dl],
            "removed_after_download": [d["name"] for d in removed],
            "vt": {k: v for k, v in vt.items() if k != "results"}, "vt_verdicts": verdicts,
            "shortlist": short[:400], "shortlist_total": len(short),
            "yara_hits": sorted(yhits, key=lambda h: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(h["severity"], 3), -(h.get("score") or 0)))[:3000], "feed_hits": sorted(fhits, key=lambda h: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(h["confidence"], 3), h["kind"], h["value"]))[:3000],
            "vt_results": vt.get("results", [])[:2000],
            "inventory": [{k: e.get(k) for k in ("kind", "name", "path", "pid", "process", "size", "type",
                                                 "sha256", "quality", "location", "file", "vt", "yara", "feed")}
                          for e in inv],
            "stage_notes": getattr(self, "stage_notes", []),
            "notes": self.notes + [
                "Everything above was checked on this PC except the VirusTotal column: only SHA-256 hashes, "
                "public IP addresses and domain names of shortlisted items were sent to VirusTotal "
                "(the exact list is in threat_intelligence/vt_sent.txt). No file was uploaded.",
                "Hash quality matters: 'complete' files hash like the original on disk; 'partial' files miss pages "
                "and 'rebuilt' executables were reassembled from memory, so VirusTotal usually does not know their "
                "hash. YARA looks at content and still works on them.",
                "Feed and YARA hits are leads to verify, not verdicts. Strings in memory can come from blocklists, "
                "browser safe-browsing data or antivirus signatures.",
            ],
        }
        self._save("ti_report.json", rep)
        msg_ok(f"Threat intel: {len(inv):,} objects, {len(yhits)} YARA hit(s), {len(fhits)} feed hit(s), "
               f"{len(short)} on the 'look here first' list -> {self.ti}")
        try:
            from modules.html_report import HTMLReportGenerator
            HTMLReportGenerator(self.log, self.os).generate(self.case)
            msg_ok("Threat intel: report.html updated (tab 'Threat Intelligence')")
        except Exception as e:
            msg_warn(f"Threat intel: report regeneration failed: {e}")


_FIXED_NOTE_HEADS = ("Everything above was checked", "Hash quality matters", "Feed and YARA hits are leads")
_UNSIGNED = re.compile(r"unsigned|not signed|no signature|without (a )?signature|invalid signature", re.I)


def unreliable_on_memory(m: Dict[str, Any]) -> str:
    """Why a rule cannot be trusted on a file dumped from RAM ('' = it can). The Authenticode
    signature sits in the file overlay, which is almost never resident, so every dumped PE
    looks unsigned and 'unsigned X' rules fire on genuine software."""
    if _UNSIGNED.search(m.get("rule", "")) or _UNSIGNED.search(m.get("description", "")):
        return ("this rule tests for a missing digital signature; files dumped from memory almost "
                "never contain their signature block, so it fires on genuine signed software")
    return ""


def yara_severity(m: Dict[str, Any]) -> str:
    if m["namespace"].startswith("custom_"):
        return "HIGH"                                      # the analyst's own rule
    if unreliable_on_memory(m):
        return "LOW"
    s = m.get("score")
    if s is None:
        return "MEDIUM"
    return "HIGH" if s >= 80 else "MEDIUM" if s >= 60 else "LOW"


def apply_vt(short, inv, vt):
    """Fold VirusTotal answers into the shortlist (score) and the inventory (vt column)."""
    by = {}
    for r in vt.get("results", []):
        if r.get("state") == "checked":
            by[(r["kind"], r["id"].lower() if r["kind"] != "ip" else r["id"])] = r
    for s in short:
        r = None
        if s["type"] in ("file", "process", "region") and s.get("sha256"):
            r = by.get(("file", s["sha256"].lower()))
            e0 = next((e for e in inv if e["file"] == s["file"]), {})
            dc = (e0.get("disk_copy") or {}).get("sha256")
            if r is None and dc:
                r = by.get(("file", dc.lower()))
        elif s["type"] in ("ip", "domain"):
            r = by.get((s["type"], s["name"].lower() if s["type"] != "ip" else s["name"]))
        elif s["type"] == "url":
            h = _url_host(s["name"])
            r = by.get(("domain", h)) if h else None
        if r:
            s["vt"] = {k: r.get(k) for k in ("verdict", "malicious", "suspicious", "total", "label", "link", "found")}
            if r.get("verdict") == "malicious":
                s["reasons"].append({"points": 100, "text": f"VirusTotal: {r.get('malicious')}/{r.get('total')} "
                                                            f"engines - {r.get('label') or 'malicious'}"})
                s["score"] = 100
            elif r.get("verdict") == "suspicious":
                s["reasons"].append({"points": 70, "text": f"VirusTotal: {r.get('malicious')} malicious / "
                                                           f"{r.get('suspicious')} suspicious of {r.get('total')}"})
                s["score"] = max(s["score"], 75)
            if r.get("verdict") in ("malicious", "suspicious") and s["type"] in ("file", "process"):
                tool = acquisition_tool(s.get("name") or "")
                if tool:
                    # v2.4: VirusTotal engines call memory-capture tools "hack tool"; on a
                    # machine that was just imaged that is expected. The score is NOT lowered
                    # (an attacker can run the same tool) - the analyst gets the context.
                    s["reasons"].append({"points": 0, "text":
                                         f"Context: {tool} is a memory-acquisition tool. It is normally here "
                                         "because it was used to capture this memory image; antivirus engines "
                                         "often label such tools. Check who ran it and when."})
    short.sort(key=lambda e: -e["score"])
    vt_by_sha = {k[1]: v for k, v in by.items() if k[0] == "file"}
    for e in inv:
        r = vt_by_sha.get((e.get("sha256") or "").lower()) or \
            vt_by_sha.get(((e.get("disk_copy") or {}).get("sha256") or "").lower())
        if r:
            e["vt"] = f"{r.get('verdict')}" + (f" {r.get('malicious')}/{r.get('total')}" if r.get("found") else "")
    files_y: Dict[str, int] = {}
    for s in short:
        if s.get("file"):
            files_y[s["file"]] = s["score"]


def _host(remote: str) -> str:
    r = (remote or "").strip()
    if not r or r.startswith("*"):
        return ""
    if r.startswith("["):
        return r[1:].split("]", 1)[0]
    if r.count(":") == 1:
        return r.split(":", 1)[0]
    if r.count(":") > 1:                       # IPv6 "addr:port" as printed by netscan
        h = r.rsplit(":", 1)[0]
        return h
    return r


_CONTAINER_EXT = (".vhd", ".vhdx", ".avhd", ".avhdx", ".vmrs", ".vmgs", ".vmem", ".vmsn", ".vmss", ".vmdk",
                  ".vdi", ".qcow2", ".iso", ".wim", ".esd")
_CONTAINER_NAMES = ("pagefile.sys", "hiberfil.sys", "swapfile.sys")


def is_container_file(name: str) -> bool:
    """Virtual disk / VM state / paging file by its name (bulk threat-intel dump skips these)."""
    base = re.split(r"[\\/]", (name or "").lower().strip())[-1]
    return base in _CONTAINER_NAMES or base.endswith(_CONTAINER_EXT)


_ACQ_TOOLS = (("dumpit", "DumpIt"), ("winpmem", "WinPmem"), ("ftk imager", "FTK Imager"),
              ("ftkimager", "FTK Imager"), ("magnetramcapture", "Magnet RAM Capture"),
              ("mrcv", "Magnet RAM Capture"), ("ramcapture", "Belkasoft RAM Capturer"),
              ("mdd.exe", "ManTech MDD"), ("avml", "AVML"), ("memoryze", "Mandiant Memoryze"))


def acquisition_tool(name: str) -> str:
    """'DumpIt' for 'DumpIt.exe' etc.: a well-known memory-capture tool by its file name, else ''."""
    base = re.split(r"[\\/]", (name or "").lower())[-1]
    for needle, label in _ACQ_TOOLS:
        if base.startswith(needle) or (needle.endswith(".exe") and base == needle):
            return label
    return ""


def _url_host(u: str) -> str:
    m = re.match(r"^[a-z][a-z0-9+.\-]*://([^/:?#@]+@)?([^/:?#]+)", (u or "").strip(), re.I)
    return m.group(2).lower().strip(".") if m else ""


def _browser_rows(bh: Any) -> List[Dict[str, Any]]:
    if isinstance(bh, list):
        return [r for r in bh if isinstance(r, dict)]
    if isinstance(bh, dict):
        for k in ("entries", "history", "urls", "rows", "results"):
            if isinstance(bh.get(k), list):
                return [r for r in bh[k] if isinstance(r, dict)]
    return []


def run(case: Path, image: str, vol, log: logging.Logger, opts: Dict[str, Any]) -> int:
    return ThreatIntel(case, image, vol, log, opts).run()
