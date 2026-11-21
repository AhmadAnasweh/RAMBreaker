"""Extraction jobs (RAMBreaker v2): the non-interactive engine behind the GUI
Extraction workspace (`crescent_toolkit.py xjob --spec job.json`).

The CLI dumpers (dump-files / dump-procs / dump-vad / hunt / export) are
menu-driven and start one Volatility process per item. A job instead takes an
explicit selection, batches it into as few Volatility runs as the plugins allow
(dumpfiles, pslist/dlllist --dump and proc.Maps accept several addresses/PIDs
per run), sizes every run's timeout from the calibrated model
(config/timeouts.json, retry once on timeout), and writes a manifest with the
size, type, SHA-256/MD5 and non-zero share of every extracted file.

Spec (JSON):
  {"kind": "files" | "procs" | "vad" | "regions" | "filelist" | "hunt" | "export",
   "case": "<case output dir>", "image": "<dump>", "dest": "<output folder>",
   "items": [...], ...kind options}

  files    items: rows from case_index.file_list()
  procs    items: [{"pid","name"}], "what": ["exe","memory","dlls"]
  vad      items: [{"pid","name","regions":[{"start","end","injection"}]}],
           "mode": "process" (every region) | "region" (only the listed ones)
  regions  items: [{"pid"}]              -> case/extracted/_regions/pid_<pid>.json
  filelist (no items)                    -> builds the case file list
  hunt     "terms": [...], "pids": [...], "case_sensitive", "wide"
  export   (no items)                    -> export-pack zip in dest

  v2.5, any kind: "protect": true -> every extracted file is written straight
  into its own password-protected ZIP <name>.zip (AES-256, modules/safe_zip.py),
  "zip_password" (default 'infected'). Volatility 3 writes the ZIPs itself, so
  the plain bytes never reach the disk; Volatility 2 output is zipped right
  after its run. Hashes, type and size in the manifest are of the file inside.

Progress for the GUI (RAMBREAKER_PROGRESS=1):
  xjob  {"state": "start"|"done", "kind", "total", "dest", "ok", "failed", "empty"}
  xitem {"i", "n", "label", "state": "running"|"ok"|"empty"|"failed", "detail", "files"}
"""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from modules import case_index as ci
from modules import progress as pg
from modules import safe_zip
from modules.platform_compat import split_cmd
from utils.ui import msg_info, msg_ok, msg_warn, msg_fail

MAGIC = safe_zip.MAGIC

HOW_TO_OPEN = (
    "Every extracted file is inside its own password-protected ZIP (<name>.zip, {enc}).\n"
    "Password: {pw}\n"
    "The plain file was never written to this disk: it cannot be started by a double-click\n"
    "and the virus scanner cannot quarantine it. The manifest lists the size, type and\n"
    "SHA-256/SHA-1/MD5 of the file INSIDE each ZIP, so most work needs no unpacking.\n"
    "\n"
    "To unpack one - preferably inside an isolated analysis VM, never on your own PC:\n"
    "  7-Zip / WinRAR / PeaZip: open the .zip, enter the password\n"
    "  Windows 10/11 command line (built-in tar):  tar -xf <name>.zip --passphrase {pw}\n"
    "Windows Explorer cannot open AES-encrypted ZIPs (on purpose a safe default).\n")


def describe(p: Path) -> Dict[str, Any]:
    """size, sha256, md5, sniffed type and share of non-zero bytes (sparse
    page-cache/VAD dumps are mostly zeros where pages were not resident).
    A protected ZIP (v2.5) is described by the metadata it carries: the
    values are those of the file inside, and nothing is decrypted."""
    if str(p).lower().endswith(safe_zip.SUFFIX):
        m = safe_zip.read_meta(p)
        if m is not None:
            d = {k: m.get(k) for k in ("size", "sha256", "md5", "sha1", "type", "nonzero_pct")}
            d["protected"] = m.get("encryption") or safe_zip.ENCRYPTION
            return d
    h256, h5, h1 = hashlib.sha256(), hashlib.md5(), hashlib.sha1()
    size = nz = 0
    head = b""
    with open(p, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            if not head:
                head = b[:64]
            h256.update(b)
            h5.update(b)
            h1.update(b)
            size += len(b)
            nz += len(b) - b.count(0)
    return {"size": size, "sha256": h256.hexdigest(), "md5": h5.hexdigest(), "sha1": h1.hexdigest(),
            "type": safe_zip.sniff_type(head, size, nz),
            "nonzero_pct": round(100.0 * nz / size, 1) if size else 0.0}


def vol3_hook_ready(vol3_cmd: str) -> bool:
    """True when the Volatility 3 tree in vol3_cmd carries the protected-output
    hook (rb_safe_zip.py + the patched CLI), i.e. it writes ZIPs itself."""
    try:
        vp = next((Path(a) for a in split_cmd(vol3_cmd or "") if a.lower().endswith("vol.py")), None)
        if vp is None:
            return False
        pkg = vp.parent / "volatility3"
        return ((pkg / "rb_safe_zip.py").is_file() and
                safe_zip.ENV_ON in (pkg / "cli" / "__init__.py").read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return False


def protect_existing(dest: Path, password: str = safe_zip.DEFAULT_PASSWORD) -> int:
    """Put the plain outputs listed in dest/manifest.json (an extraction made
    without protection) into protected ZIPs, update the manifest; returns how
    many files were packed."""
    mp = Path(dest) / "manifest.json"
    man = ci.load_json(mp)
    if not isinstance(man, dict):
        return 0
    n = 0
    for it in man.get("items") or []:
        for o in it.get("outputs") or []:
            p = Path(dest) / str(o.get("file", ""))
            if o.get("file") and p.is_file() and not safe_zip.is_protected(p):
                z = Path(safe_zip.pack_file(p, password))
                o["file"] = str(z.relative_to(dest)).replace("\\", "/")
                o["protected"] = safe_zip.ENCRYPTION
                n += 1
    if n or "protection" not in man:
        man["protection"] = {"format": safe_zip.ENCRYPTION, "password": password}
        mp.write_text(json.dumps(man, indent=1, default=str), encoding="utf-8")
        (Path(dest) / "PROTECTED_FILES_README.txt").write_text(
            HOW_TO_OPEN.format(enc=safe_zip.ENCRYPTION, pw=password), encoding="utf-8")
    return n


class Job:
    # protected output (v2.5): set per job in __init__ from the spec
    protect = False
    zip_pw = safe_zip.DEFAULT_PASSWORD
    env: Optional[Dict[str, str]] = None
    packed_after = 0

    def __init__(self, spec: Dict[str, Any], vol, log: logging.Logger):
        self.spec = spec
        self.vol = vol
        self.log = log
        self.kind = spec["kind"]
        self.case = Path(spec["case"])
        self.image = spec["image"]
        self.os = vol.os_type or "windows"
        self.eng = vol.vol_version or "vol3"
        ts = time.strftime("%Y%m%d_%H%M%S")
        self.dest = Path(spec.get("dest") or (self.case / "extracted" / f"{self.kind}_{ts}"))
        self.items: List[Dict[str, Any]] = []
        self.ok = self.failed = self.empty = 0
        try:
            from modules import timeout_model
            self.model = timeout_model.get_model()
            self.size_gb = timeout_model.image_size_gb(self.image)
        except Exception:
            self.model, self.size_gb = None, 1.0
        # v2.5 protected output (see the module docstring)
        self.protect = bool(spec.get("protect", False))
        self.zip_pw = str(spec.get("zip_password") or safe_zip.DEFAULT_PASSWORD)
        self.env: Optional[Dict[str, str]] = None
        self.packed_after = 0          # outputs that were plain on disk before we zipped them
        if self.protect:
            self.env = dict(os.environ, **{safe_zip.ENV_ON: "1", safe_zip.ENV_PW: self.zip_pw})
            if self.vol.vol3_cmd and not vol3_hook_ready(self.vol.vol3_cmd):
                msg_warn("Protected output: this Volatility 3 has no RAMBreaker output hook - its files "
                         "are written in plain and zipped right after each run (run "
                         "build_tools\\prepare_vol3.py to install the hook)")

    # ------------------------------------------------------------ plumbing
    def v3(self, out: Optional[Path] = None, json_out: bool = False) -> List[str]:
        a = split_cmd(self.vol.vol3_cmd) + ["-q", "-f", self.image]
        if out is not None:
            a += ["-o", str(out)]
        if json_out:
            a += ["-r", "json"]
        return a

    def v2(self) -> List[str]:
        return split_cmd(self.vol.vol2_cmd) + ["-f", self.image, "--profile=" + str(self.vol.profile)]

    def timeout_for(self, key: str, n: int = 1, floor: int = 300) -> int:
        t = floor
        if self.model is not None:
            try:
                t = max(floor, self.model.timeout(key, self.eng, self.os, self.size_gb))
            except Exception:
                pass
        return int(t + 20 * max(0, n - 1))

    def run(self, argv: List[str], key: str, n: int = 1, floor: int = 300,
            cwd: Optional[Path] = None) -> Tuple[int, str, str, float, bool]:
        """Run one Volatility command; on timeout kill it and retry once with
        the model's extended timeout. Returns (rc, stdout, stderr, secs, timed_out)."""
        tmo = self.timeout_for(key, n, floor)
        for attempt in (1, 2):
            shown = argv if len(argv) <= 40 else argv[:36] + [f"... (+{len(argv) - 36} more arguments)"]
            self.log.info("Command: %s", " ".join(shown))
            msg_info(f"Running {key.split('#')[0]} (timeout {tmo}s)")
            st = time.time()
            try:
                p = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                                   timeout=tmo, cwd=str(cwd) if cwd else None, env=self.env)
                dur = time.time() - st
                self._record(key, n, dur, p.returncode == 0, False, tmo)
                return p.returncode, p.stdout or "", p.stderr or "", dur, False
            except subprocess.TimeoutExpired:
                dur = time.time() - st
                self._record(key, n, dur, False, True, tmo)
                if attempt == 1 and self.model is not None:
                    t2 = self.model.retry_timeout(tmo)
                    msg_warn(f"{key.split('#')[0]} timed out after {tmo}s - killed; "
                             f"retrying once with {t2}s")
                    tmo = t2
                    continue
                msg_fail(f"{key.split('#')[0]} timed out again after {tmo}s")
                return -1, "", f"Timed out after {tmo}s", dur, True
        return -1, "", "unreachable", 0.0, True

    def _record(self, key, n, dur, ok, to, tmo):
        if self.model is not None and n == 1:
            try:
                self.model.record(key, self.eng, self.os, self.size_gb, dur, ok, to, tmo)
            except Exception:
                pass

    @staticmethod
    def err_line(stderr: str) -> str:
        lines = [l.strip() for l in (stderr or "").splitlines()
                 if l.strip() and not l.startswith(("Progress:", "***", "Volatility 3"))]
        for l in reversed(lines):
            if any(w in l for w in ("Error", "error", "Unsatisfied", "Exception", "not ")):
                return l[:240]
        return lines[-1][:240] if lines else ""

    def staging(self) -> Path:
        # the counter keeps names unique when batches start in the same millisecond
        # (parallel file dumps, v2.4)
        self._stg_n = getattr(self, "_stg_n", 0) + 1
        # short name: every character here is taken from the 260-character path limit
        s = self.dest / f"_s{int(time.time() * 1000) % 10 ** 6}_{self._stg_n}"
        s.mkdir(parents=True, exist_ok=True)
        return s

    @staticmethod
    def drop_staging(s: Path):
        try:
            for leftover in s.iterdir():
                if leftover.is_file() and (leftover.stat().st_size == 0 or
                                           leftover.name.endswith(safe_zip.TMP_SUFFIX)):
                    leftover.unlink()
            s.rmdir()                      # only ever removes our own, now-empty dir
        except OSError:
            pass

    @staticmethod
    def outputs(s: Path) -> List[Path]:
        """The files a Volatility run left in staging folder `s`, sorted. A ZIP
        still under its temporary name (the run was killed while writing it) is
        incomplete and unreadable: it is deleted, not reported."""
        out = []
        for f in sorted(s.iterdir()):
            if f.name.endswith(safe_zip.TMP_SUFFIX):
                try:
                    f.unlink()
                except OSError:
                    pass
            elif f.is_file():
                out.append(f)
        return out

    def plain(self, f: Path) -> str:
        """Lower-case file name without the protected-ZIP suffix, for matching
        Volatility's output names."""
        return safe_zip.plain_name(f.name).lower()

    def move(self, src: Path, folder: Path, name: Optional[str] = None) -> Path:
        folder.mkdir(parents=True, exist_ok=True)
        if self.protect:
            if not safe_zip.is_protected(src):
                # Volatility 2 (or a Vol3 without the hook) wrote it in plain: zip it now
                src = Path(safe_zip.pack_file(src, self.zip_pw))
                self.packed_after += 1
            if name and not name.lower().endswith(safe_zip.SUFFIX):
                name += safe_zip.SUFFIX
        t = folder / (name or src.name)
        i = 1
        while t.exists():
            t = folder / f"{t.stem}_{i}{t.suffix}"
            i += 1
        shutil.move(str(src), str(t))
        return t

    def out_entry(self, p: Path, **extra) -> Dict[str, Any]:
        d = {"file": str(p.relative_to(self.dest)).replace("\\", "/")}
        try:
            d.update(describe(p))
        except OSError as e:
            d["error"] = str(e)
        d.update({k: v for k, v in extra.items() if v})
        return d

    def item(self, label: str, source: Dict[str, Any]) -> Dict[str, Any]:
        it = {"label": label, "source": source, "status": "pending", "outputs": [],
              "detail": "", "duration_s": 0.0}
        self.items.append(it)
        return it

    def finish_item(self, it: Dict[str, Any], i: int, n: int, detail: str = ""):
        if it["outputs"]:
            # a zero-filled file (Vol2 linux_find_file writes the inode size even
            # when no page was cached) carries no evidence: report it as empty
            real = [o for o in it["outputs"] if o.get("size") and o.get("nonzero_pct", 1) > 0]
            it["status"] = "ok" if real and not it.pop("exe_missing", False) else "empty"
            if not real and not it["detail"]:
                it["detail"] = "output is all zeros - none of its pages were in RAM"
        elif it["status"] == "pending":
            it["status"] = "failed"
        if detail and not it["detail"]:
            it["detail"] = detail
        # spec "quiet" (bulk threat-intel dumps of 10,000+ objects): no line per object,
        # one running total every "quiet" objects; failures are still logged one by one
        q = int(self.spec.get("quiet") or 0)
        if q and it["status"] in ("ok", "empty"):
            if it["status"] == "ok":
                self.ok += 1
            else:
                self.empty += 1
            if i % q == 0 or i == n:
                msg_info(f"[{i}/{n}] {self.ok} ok, {self.empty} nothing recoverable, {self.failed} failed so far")
        elif it["status"] == "ok":
            self.ok += 1
            msg_ok(f"[{i}/{n}] {it['label']}: {len(it['outputs'])} file(s), "
                   f"{ci.fmt_size(sum(o.get('size', 0) for o in it['outputs']))}")
        elif it["status"] == "empty":
            self.empty += 1
            msg_warn(f"[{i}/{n}] {it['label']}: nothing recoverable - {it['detail'] or 'output was empty'}")
        else:
            self.failed += 1
            msg_warn(f"[{i}/{n}] {it['label']}: FAILED - {it['detail'] or 'no output'}")
        pg.emit("xitem", i=i, n=n, label=it["label"], state=it["status"],
                detail=it["detail"][:200], files=len(it["outputs"]))

    def write_manifest(self, extra: Optional[Dict[str, Any]] = None) -> Path:
        man = {"kind": self.kind, "case": str(self.case), "image": self.image,
               "os": self.os, "engine": self.eng,
               "profile": self.vol.profile or "", "finished": time.strftime("%Y-%m-%d %H:%M:%S"),
               "ok": self.ok, "empty": self.empty, "failed": self.failed,
               "items": self.items}
        if extra:
            man.update(extra)
        protected = self.protect and any(o.get("protected") for it in self.items for o in it["outputs"])
        if protected:
            man["protection"] = {"format": safe_zip.ENCRYPTION, "password": self.zip_pw,
                                 "zipped_after_write": self.packed_after}
        self.dest.mkdir(parents=True, exist_ok=True)
        mp = self.dest / "manifest.json"
        mp.write_text(json.dumps(man, indent=2, default=str), encoding="utf-8")
        L = [f"RAMBreaker extraction - {self.kind}", f"Case:   {self.case}",
             f"Image:  {self.image}", f"Engine: {self.eng} ({self.os})",
             f"Result: {self.ok} ok, {self.empty} empty, {self.failed} failed", ""]
        if protected:
            how = HOW_TO_OPEN.format(enc=safe_zip.ENCRYPTION, pw=self.zip_pw)
            (self.dest / "PROTECTED_FILES_README.txt").write_text(how, encoding="utf-8")
            L[-1:-1] = ["", "PROTECTED: " + how.replace("\n", "\n           ").rstrip()]
            if self.packed_after:
                L.insert(-1, f"           {self.packed_after} file(s) came from Volatility 2 (or a Volatility 3 "
                             "without the hook) and were on disk in plain until they were zipped.")
        for it in self.items:
            L.append(f"[{it['status'].upper():6}] {it['label']}"
                     + (f"  - {it['detail']}" if it["detail"] else ""))
            for o in it["outputs"]:
                L.append(f"          {o['file']}  {ci.fmt_size(o.get('size', 0))}  "
                         f"{o.get('type', '')}  nonzero {o.get('nonzero_pct', 0)}%  "
                         f"sha256 {o.get('sha256', '')[:16]}..."
                         + (f"  [!] {o['injection']}" if o.get("injection") else ""))
        (self.dest / "manifest.txt").write_text("\n".join(L) + "\n", encoding="utf-8")
        return mp

    # ---------------------------------------------------------------- main
    def execute(self) -> int:
        items = self.spec.get("items") or []
        n = len(items) if self.kind in ("files", "procs", "vad", "regions") else 1
        if self.kind not in ("regions", "filelist"):
            self.dest.mkdir(parents=True, exist_ok=True)
        pg.emit("xjob", state="start", kind=self.kind, total=n, dest=str(self.dest))
        msg_info(f"Extraction job '{self.kind}': {n} item(s) from {Path(self.image).name} "
                 f"({self.os}, {self.eng}) -> {self.dest}")
        t0 = time.time()
        fn = getattr(self, f"job_{self.kind}", None)
        if fn is None:
            msg_fail(f"Unknown job kind: {self.kind}")
            return 2
        extra = fn(items) or {}
        man = None
        if self.kind not in ("regions", "filelist"):
            man = self.write_manifest(extra)
        dur = time.time() - t0
        pg.emit("xjob", state="done", kind=self.kind, total=n, dest=str(self.dest),
                ok=self.ok, failed=self.failed, empty=self.empty,
                manifest=str(man) if man else "", duration_s=round(dur, 1))
        msg_ok(f"Extraction job finished in {dur:.0f}s: {self.ok} ok, {self.empty} empty, "
               f"{self.failed} failed" + (f" - manifest: {man}" if man else ""))
        return 0 if (self.ok or (not self.failed and not self.empty)) else 1

    # =============================================================== FILES
    def job_files(self, items):
        if self.os == "windows":
            return self._files_windows(items)
        if self.os == "linux":
            return self._files_linux(items)
        return self._files_mac(items)

    def _files_windows(self, items):
        n = len(items)
        its = [self.item(f"{r.get('name')} @ {r.get('offset')}",
                         {"path": r.get("path"), "offset": r.get("offset")}) for r in items]
        out_dir = self.dest / "files"
        pending = list(range(n))
        if self.vol.vol3_cmd:
            # bulk jobs (threat intel) pass "flags": "auto" and "vol2_fallback": false.
            # auto: filescan reports physical offsets on older Windows (Win7: 0xf27070) and
            # kernel-virtual ones on Windows 10+ (0xdf888effc4f0). No physical address is
            # >= 1 TiB, so each object gets the one flag that can work - no wasted pass.
            fc = self.spec.get("flags")
            if fc == "auto":
                virt = {i for i in pending if (ci._int(items[i].get("offset")) or 0) >= 1 << 40}
                plan = [("--physaddr", [i for i in pending if i not in virt]),
                        ("--virtaddr", [i for i in pending if i in virt])]
            else:
                plan = [(f, None) for f in (fc or ("--physaddr", "--virtaddr"))]
            for flag, subset in plan:
                if not pending:
                    break
                skipped = []
                if subset is not None:
                    sub = set(subset)
                    skipped = [i for i in pending if i not in sub]
                    pending = [i for i in pending if i in sub]
                    if not pending:
                        pending = skipped
                        continue
                # Vol3 names every output "file.<FILE_OBJECT address>.<...>", the address we
                # passed: outputs are attributed by it, so a batch may hold any number of
                # objects (spec "batch", default 25). Names are only the fallback.
                bsize = max(1, int(self.spec.get("batch") or 25))
                batches = [pending[k:k + bsize] for k in range(0, len(pending), bsize)]
                still = []

                def _dump_batch(b, _flag=flag):
                    stg = self.staging()
                    argv = self.v3(stg, json_out=True) + ["windows.dumpfiles.DumpFiles", _flag] + \
                        [items[i]["offset"] for i in b]
                    return (stg,) + tuple(self.run(argv, "windows.dumpfiles.DumpFiles", n=len(b)))

                # v2.4: bulk jobs (threat intel) may pass "parallel": N. The Volatility runs
                # of N batches then overlap; their outputs are still attributed and moved one
                # batch at a time, in the original order, so names and manifests do not change.
                par = max(1, min(8, int(self.spec.get("parallel") or 1)))
                ready = None
                if par > 1 and len(batches) > 1:
                    from concurrent.futures import ThreadPoolExecutor
                    staged = [self.staging() for _ in batches]      # created in order (main thread)

                    def _dump_staged(k):
                        b = batches[k]
                        argv = self.v3(staged[k], json_out=True) + ["windows.dumpfiles.DumpFiles", flag] + \
                            [items[i]["offset"] for i in b]
                        return (staged[k],) + tuple(self.run(argv, "windows.dumpfiles.DumpFiles", n=len(b)))

                    for b in batches:
                        for i in b:
                            pg.emit("xitem", i=i + 1, n=n, label=its[i]["label"], state="running")
                    with ThreadPoolExecutor(max_workers=par) as ex:
                        ready = list(ex.map(_dump_staged, range(len(batches))))
                for bi, b in enumerate(batches):
                    if ready is None:
                        for i in b:
                            pg.emit("xitem", i=i + 1, n=n, label=its[i]["label"], state="running")
                        stg, rc, so, se, dur, to = _dump_batch(b)
                    else:
                        stg, rc, so, se, dur, to = ready[bi]
                    culprit: Dict[int, str] = {}
                    if rc != 0 and not to:
                        se = self._resume_after_crash(b, items, flag, stg, se, culprit)
                    files = self.outputs(stg)
                    by_off: Dict[int, List[Path]] = {}
                    for f in files:
                        m = re.match(r"file\.(0x[0-9a-f]+)\.", f.name.lower())
                        if m:
                            by_off.setdefault(int(m.group(1), 16), []).append(f)
                    for i in b:
                        nm = (items[i].get("name") or "").lower()
                        off = ci._int(items[i].get("offset"))
                        mine = [f for f in by_off.get(off, []) if f.exists()] if off is not None else []
                        if not mine and not by_off:
                            mine = [f for f in files if f.exists() and nm and nm in f.name.lower()]
                        if len(b) == 1 and not mine:
                            mine = [f for f in files if f.exists()]
                        for f in mine:
                            p = self.move(f, out_dir)
                            its[i]["outputs"].append(self.out_entry(
                                p, object=("ImageSectionObject (mapped executable image)" if Path(self.plain(p)).suffix == ".img"
                                           else "DataSectionObject (cached file data)" if Path(self.plain(p)).suffix == ".dat"
                                           else "SharedCacheMap (VACB cache views)" if Path(self.plain(p)).suffix == ".vacb" else "")))
                        its[i]["duration_s"] += round(dur / len(b), 1)
                        if not its[i]["outputs"]:
                            its[i]["detail"] = ("timed out" if to else culprit.get(i) or
                                                self.err_line(se) or "no cached data for this file object")
                            still.append(i)
                        else:                       # an earlier --physaddr miss must not linger
                            its[i]["detail"] = ""
                    for f in self.outputs(stg):             # unattributed: keep, never lose data
                        self.move(f, out_dir / "_unattributed")
                    self.drop_staging(stg)
                pending = still + skipped
        if pending and self.vol.vol2_cmd and self.vol.profile and self.spec.get("vol2_fallback", True):
            for i in list(pending):
                stg = self.staging()
                rc, so, se, dur, to = self.run(self.v2() + ["dumpfiles", "-Q", items[i]["offset"],
                                                            "-D", str(stg), "-n"],
                                               "dumpfiles#vol2", floor=300)
                for f in self.outputs(stg):
                    its[i]["outputs"].append(self.out_entry(self.move(f, out_dir)))
                self.drop_staging(stg)
                if its[i]["outputs"]:
                    its[i]["detail"] = ""
                    pending.remove(i)
        for i, it in enumerate(its):
            if not it["outputs"] and not it["detail"]:
                it["detail"] = "no cached data for this file object (not resident in RAM)"
            if not it["outputs"]:
                it["status"] = "empty" if "timed out" not in it["detail"] else "failed"
            self.finish_item(it, i + 1, n)

    def _resume_after_crash(self, b, items, flag, stg, se, culprit) -> str:
        """windows.dumpfiles stops at the first object that raises (v2.4: seen with
        an over-long output path), and every object after it in the batch used to be
        reported 'empty'. Find where it stopped, note the error on that one object,
        and run the rest of the batch again into the same staging folder (up to 8
        times). Returns the stderr that still applies to the batch ('' = clean)."""
        remaining = list(b)
        for _ in range(8):
            have = set()
            for f in stg.iterdir():
                m = re.match(r"file\.(0x[0-9a-f]+)\.", f.name.lower())
                if m:
                    have.add(int(m.group(1), 16))
            offs = [ci._int(items[i].get("offset")) for i in remaining]
            last = max((k for k, o in enumerate(offs) if o in have), default=-1)
            named = re.findall(r"file\.(0x[0-9a-fA-F]+)\.", se or "")
            pos = None
            if named:
                bo = int(named[-1], 16)
                pos = next((k for k, o in enumerate(offs) if o == bo), None)
            if pos is None:
                pos = last + 1                      # first object after the last output
            if pos >= len(remaining):
                return ""
            culprit[remaining[pos]] = self.err_line(se) or "Volatility stopped on this object"
            remaining = remaining[max(pos, last) + 1:]
            if not remaining:
                return ""
            self.log.warning("dumpfiles stopped inside a batch (%s); continuing with the %d "
                             "objects after it", (self.err_line(se) or "error")[:120], len(remaining))
            argv = self.v3(stg, json_out=True) + ["windows.dumpfiles.DumpFiles", flag] + \
                [items[i]["offset"] for i in remaining]
            rc, _so, se, _dur, to = self.run(argv, "windows.dumpfiles.DumpFiles", n=len(remaining))
            if rc == 0:
                return ""
            if to:
                return se
        return se

    def _files_linux(self, items):
        n = len(items)
        out_dir = self.dest / "files"
        for i, r in enumerate(items, 1):
            it = self.item(r.get("path") or r.get("name"), {k: r.get(k) for k in
                                                           ("path", "inode", "inode_addr", "cached_pages", "size")})
            pg.emit("xitem", i=i, n=n, label=it["label"], state="running")
            stg = self.staging()
            if self.eng == "vol2":
                if not r.get("inode_addr"):
                    it["detail"] = "no inode address (build the file list first)"
                else:
                    tgt = stg / ci.safe_name(r.get("name") or "file")
                    rc, so, se, dur, to = self.run(self.v2() + ["linux_find_file", "-i", r["inode_addr"],
                                                                "-O", str(tgt)], "linux_find_file#vol2")
                    it["duration_s"] = round(dur, 1)
                    if not to and not self.outputs(stg):
                        it["detail"] = self.err_line(se) or "no page-cache pages for this inode"
            else:
                if r.get("inode_addr"):
                    args = ["--inode", r["inode_addr"]]
                    key = "linux.pagecache.InodePages#inode"
                else:
                    args = ["--find", r.get("path", "")]
                    key = "linux.pagecache.InodePages#find"
                rc, so, se, dur, to = self.run(self.v3(stg) + ["linux.pagecache.InodePages"] + args + ["--dump"],
                                               key)
                it["duration_s"] = round(dur, 1)
                if to:
                    it["detail"] = "timed out"
                elif not self.outputs(stg):
                    it["detail"] = self.err_line(se) or "no page-cache pages for this inode"
            files = self.outputs(stg)
            for k, f in enumerate(files):
                nm = ci.safe_name(r.get("name") or f.name)
                if len(files) > 1:
                    nm = f"{k}_{nm}"
                p = self.move(f, out_dir, nm)      # move() adds _1, _2 on name clashes
                e = self.out_entry(p)
                exp = r.get("size") or 0
                if exp:
                    e["note"] = f"file size in inode {exp} B, recovered {e.get('size', 0)} B"
                it["outputs"].append(e)
            self.drop_staging(stg)
            if it["outputs"] and not any(o.get("size") for o in it["outputs"]) and not it["detail"]:
                err = self.err_line(se) if "se" in dir() else ""
                it["detail"] = f"Volatility wrote an empty file{': ' + err if err else ' (no resident pages)'}"
            self.finish_item(it, i, n)

    def _files_mac(self, items):
        n = len(items)
        out_dir = self.dest / "files"
        its = [self.item(r.get("path") or r.get("name"), {"path": r.get("path"), "vnode": r.get("offset")})
               for r in items]
        for i, it in enumerate(its, 1):
            pg.emit("xitem", i=i, n=n, label=it["label"], state="running")
        stg = self.staging()
        names = ",".join(sorted({(r.get("path") or "").strip() for r in items if r.get("path")}))
        rc, so, se, dur, to = self.run(self.v3(stg) + ["mac.pagecache.Pagecache", "--dump", "--name", names],
                                       "mac.pagecache.Pagecache#name", n=n, floor=600)
        files = self.outputs(stg)
        for idx, r in enumerate(items):
            stem = re.sub(r"[^\w.\-]", "_", (r.get("path") or "").lstrip("/"))[:180]
            vn = (r.get("offset") or "").lower()
            for f in files:
                if not f.exists():
                    continue
                fl = self.plain(f)
                if fl.startswith(f"mac_pagecache.{stem.lower()}.0x") or (vn and fl.endswith(f".{vn}.dmp")):
                    its[idx]["outputs"].append(self.out_entry(self.move(f, out_dir)))
            its[idx]["duration_s"] = round(dur / max(1, n), 1)
            if not its[idx]["outputs"]:
                its[idx]["detail"] = ("timed out" if to else
                                      self.err_line(se) or "no resident page-cache pages for this file")
        for f in self.outputs(stg):    # substring matches of --name that were not selected
            self.move(f, out_dir / "_also_matched")
        self.drop_staging(stg)
        for i, it in enumerate(its, 1):
            if not it["outputs"]:
                it["status"] = "failed" if it["detail"] == "timed out" else "empty"
            self.finish_item(it, i, n)

    # =========================================================== PROCESSES
    def _win_proc_state(self):
        """From the case JSON: (active PIDs on the pslist, {PID: ExitTime} of processes
        that only exist as exited objects, {PID: EPROCESS address} of running
        psscan-only objects). A PID reused by a running process is not 'exited'."""
        active, exited, running_off = set(), {}, {}
        jd = self.case / "json"
        for pat, is_list in (("windows_pslist", True), ("windows_psscan", False)):
            for f in sorted(jd.glob(f"{pat}*.json")) if jd.is_dir() else []:
                rows = ci.load_json(f)
                for r in rows if isinstance(rows, list) else []:
                    pid = str(r.get("PID", ""))
                    et = r.get("ExitTime")
                    if not pid:
                        continue
                    if et and str(et).upper() not in ("N/A", "NONE") and not str(et).startswith("1970"):
                        exited.setdefault(pid, str(et))
                    elif is_list:
                        active.add(pid)
                    else:
                        off = r.get("Offset(V)", r.get("Offset"))
                        if isinstance(off, int) and off:
                            running_off.setdefault(pid, off)
        exited = {p: t for p, t in exited.items() if p not in running_off}
        return active, exited, running_off

    @staticmethod
    def _pid_of(fname: str, pids: List[str]) -> Optional[str]:
        toks = re.split(r"[._\-]", fname)
        for t in toks[:4]:
            if t in pids:
                return t
        return None

    @staticmethod
    def _label_elfs(its, stdout: str):
        """linux.elfs --dump writes EVERY mapped ELF whose header page is resident
        (program, ld.so, libraries, [vdso]). Name each output after the object it
        came from, and say so when the program itself was not among them - a
        4 KB [vdso] must not read as "the executable was dumped"."""
        objs, listed, header = {}, set(), False
        for ln in stdout.splitlines():
            cols = [c.strip() for c in ln.split("\t")]
            if cols[:2] == ["PID", "Process"]:
                header = True
            elif cols and cols[0].isdigit():
                listed.add(cols[0])
            for i, c in enumerate(cols):
                if i and c.endswith((".dmp", ".dmp" + safe_zip.SUFFIX)):
                    objs[c] = cols[i - 1]

        # elfs ran and listed nothing for a PID: nothing to dump, not a failure
        nothing = ("exe: linux.elfs found no resident ELF header page for this process "
                   "(its program and libraries are not in this memory image)")
        for pid, it in its.items():
            if (header and str(pid) not in listed
                    and not any(o.get("part") == "exe" for o in it["outputs"])
                    and "exe: no output" in it["detail"]):
                it["detail"] = it["detail"].replace("exe: no output", nothing)
                if not it["outputs"]:
                    it["status"] = "empty"

        def is_lib(o: str) -> bool:
            b = o.replace("\\", "/").rsplit("/", 1)[-1]
            return o.startswith("[") or bool(re.search(r"\.so(\.[\d.]+)?$", b)) or b.startswith("ld-")

        for it in its.values():
            exe = [o for o in it["outputs"] if o.get("part") == "exe"]
            for o in exe:
                ob = objs.get(o["file"].rsplit("/", 1)[-1])
                if ob and ob.upper() not in ("N/A", "-"):
                    o["object"] = ob
            if exe and not any(o.get("object") and not is_lib(o["object"]) for o in exe):
                got = ", ".join(sorted({o.get("object") or o["file"].rsplit("/", 1)[-1] for o in exe}))
                msg = (f"exe: the program's own ELF header page is not in this memory image; "
                       f"only {got[:200]} could be dumped")
                it["detail"] = (it["detail"] + "; " if it["detail"] else "") + msg
                if all(o.get("part") == "exe" for o in it["outputs"]):
                    it["exe_missing"] = True      # finish_item reports it as EMPTY

    def job_procs(self, items):
        what = self.spec.get("what") or ["exe"]
        n = len(items)
        pids = [str(r["pid"]) for r in items]
        its = {str(r["pid"]): self.item(f"PID {r['pid']} {r.get('name', '')}",
                                        {"pid": str(r["pid"]), "name": r.get("name", ""), "what": what})
               for r in items}
        folder = {p: self.dest / f"pid_{p}_{ci.safe_name(its[p]['source']['name'], 40)}" for p in pids}
        for i, p in enumerate(pids, 1):
            pg.emit("xitem", i=i, n=n, label=its[p]["label"], state="running")

        stdouts: List[str] = []

        def batch(argv_for, key, sub, per_pid=False, floor=300, only=None):
            todo = [p for p in pids if only is None or p in only]
            groups = [[p] for p in todo] if per_pid else ([todo] if todo else [])
            for g in groups:
                stg = self.staging()
                rc, so, se, dur, to = self.run(argv_for(stg, g), key, n=len(g), floor=floor)
                stdouts.append(so or "")
                for f in self.outputs(stg):
                    p = g[0] if len(g) == 1 else self._pid_of(f.name, g)
                    if p is None:
                        self.move(f, self.dest / "_unattributed")
                        continue
                    its[p]["outputs"].append(self.out_entry(self.move(f, folder[p] / sub), part=sub))
                # procdump_offset prints one status row per process: "<off> <pid> <name> <status>"
                why = {}
                for ln in (so or "").splitlines():
                    m = re.match(r"\s*0x[0-9a-f]+\s+(\d+)\s+.*?\s(not resident: .+)$", ln, re.I)
                    if m:
                        why[m.group(1)] = m.group(2).strip()
                for p in g:
                    its[p]["duration_s"] += round(dur / len(g), 1)
                    if not any(o.get("part") == sub for o in its[p]["outputs"]):
                        msg = "timed out" if to else (why.get(p) or self.err_line(se) or "no output")
                        its[p]["detail"] = (its[p]["detail"] + "; " if its[p]["detail"] else "") + f"{sub}: {msg}"
                        if p in why and not its[p]["outputs"]:
                            its[p]["status"] = "empty"     # read fine, data simply not in RAM
                self.drop_staging(stg)

        v3, v2 = bool(self.vol.vol3_cmd) and self.eng == "vol3", bool(self.vol.vol2_cmd and self.vol.profile)
        if self.os == "windows":
            # Processes only psscan found are not on the active list, so pslist --pid
            # cannot see them: dump those through psscan. A process with an ExitTime
            # has no address space left - say so instead of a bare "no output".
            active, exited, eproc = self._win_proc_state()
            gone = {p for p in pids if p in exited and p not in active}
            for p in gone:
                its[p]["detail"] = (f"process exited at {exited[p]} - its memory was released, "
                                    "nothing left to dump")
                its[p]["status"] = "empty"
            scan_only = {p for p in pids if active and p not in active and p not in gone}
            live = [p for p in pids if p not in gone and p not in scan_only]
            if "exe" in what:
                if v3:
                    batch(lambda s, g: self.v3(s) + ["windows.pslist.PsList", "--pid", *g, "--dump"],
                          "windows.pslist.PsList#dump", "exe", only=set(live))
                    # psscan-only: dump straight from the EPROCESS address psscan already
                    # found (bundled windows.procdump_offset, seconds); a full psscan
                    # --dump re-scan only when no address is known (> 30 min on 34 GB HDD)
                    by_off = {p for p in scan_only if p in eproc}
                    batch(lambda s, g: self.v3(s) + ["windows.procdump_offset.ProcDumpOffset",
                                                     "--offset", *[str(eproc[p]) for p in g]],
                          "windows.procdump_offset.ProcDumpOffset", "exe", only=by_off)
                    batch(lambda s, g: self.v3(s) + ["windows.psscan.PsScan", "--pid", *g, "--dump"],
                          "windows.psscan.PsScan#dump", "exe", only=scan_only - by_off)
                elif v2:
                    batch(lambda s, g: self.v2() + ["procdump", "-p", ",".join(g), "-D", str(s)],
                          "procdump#vol2", "exe", only=set(pids) - gone)
            if "dlls" in what:
                if v3:
                    batch(lambda s, g: self.v3(s) + ["windows.dlllist.DllList", "--pid", *g, "--dump"],
                          "windows.dlllist.DllList#dump", "dlls", floor=600, only=set(pids) - gone)
                elif v2:
                    batch(lambda s, g: self.v2() + ["dlldump", "-p", ",".join(g), "-D", str(s)],
                          "dlldump#vol2", "dlls", floor=600, only=set(pids) - gone)
            if "memory" in what:
                if v3:
                    batch(lambda s, g: self.v3(s) + ["windows.memmap.Memmap", "--pid", g[0], "--dump"],
                          "windows.memmap.Memmap#dump", "memory", per_pid=True, floor=900, only=set(pids) - gone)
                elif v2:
                    batch(lambda s, g: self.v2() + ["memdump", "-p", g[0], "-D", str(s)],
                          "memdump#vol2", "memory", per_pid=True, floor=900, only=set(pids) - gone)
        elif self.os == "linux":
            if "exe" in what:
                if v3:
                    stdouts.clear()
                    batch(lambda s, g: self.v3(s) + ["linux.elfs.Elfs", "--pid", *g, "--dump"],
                          "linux.elfs.Elfs#dump", "exe", floor=600)
                    self._label_elfs(its, "\n".join(stdouts))
                elif v2:
                    batch(lambda s, g: self.v2() + ["linux_procdump", "-p", ",".join(g), "-D", str(s)],
                          "linux_procdump#vol2", "exe")
            if "memory" in what:
                if v3:
                    batch(lambda s, g: self.v3(s) + ["linux.proc.Maps", "--pid", g[0], "--dump"],
                          "linux.proc.Maps#dump", "memory", per_pid=True, floor=900)
                elif v2:
                    batch(lambda s, g: self.v2() + ["linux_dump_map", "-p", g[0], "-D", str(s)],
                          "linux_dump_map#vol2", "memory", per_pid=True, floor=900)
        else:  # mac: no executable-only dumper exists; memory = every mapped region
            if "exe" in what:
                for p in pids:
                    its[p]["detail"] = "exe: not available for macOS images (use Full process memory)"
            if "memory" in what and v3:
                batch(lambda s, g: self.v3(s) + ["mac.proc_maps.Maps", "--pid", g[0], "--dump"],
                      "mac.proc_maps.Maps#dump", "memory", per_pid=True, floor=900)
        for i, p in enumerate(pids, 1):
            self.finish_item(its[p], i, n)

    # ================================================================= VAD
    def job_vad(self, items):
        mode = self.spec.get("mode", "process")
        n = len(items)
        for i, r in enumerate(items, 1):
            pid = str(r["pid"])
            regs = r.get("regions") or []
            label = f"PID {pid} {r.get('name', '')} - " + \
                (f"{len(regs)} selected region(s)" if mode == "region" else "all regions")
            it = self.item(label, {"pid": pid, "name": r.get("name", ""), "mode": mode,
                                   "regions": [g.get("start") for g in regs]})
            pg.emit("xitem", i=i, n=n, label=label, state="running")
            folder = self.dest / f"pid_{pid}_{ci.safe_name(r.get('name', ''), 40)}"
            inj = {}
            known, rows = ci.region_list(self.case, pid)
            for g in (rows if known else []) + regs:
                if g.get("injection"):
                    inj[str(g.get("start", "")).lower()] = g["injection"]
            stg = self.staging()
            to_any = False
            err = ""
            v3 = bool(self.vol.vol3_cmd) and self.eng == "vol3"
            if self.os == "windows":
                if v3:
                    if mode == "region":
                        for g in regs:
                            rc, so, se, dur, to = self.run(
                                self.v3(stg) + ["windows.vadinfo.VadInfo", "--pid", pid,
                                                "--address", str(g["start"]), "--dump"],
                                "windows.vadinfo.VadInfo#dump1")
                            it["duration_s"] += round(dur, 1)
                            to_any |= to
                            err = err or self.err_line(se)
                    else:
                        rc, so, se, dur, to = self.run(
                            self.v3(stg) + ["windows.vadinfo.VadInfo", "--pid", pid, "--dump"],
                            "windows.vadinfo.VadInfo#dump", floor=900)
                        it["duration_s"] = round(dur, 1)
                        to_any, err = to, self.err_line(se)
                else:
                    if mode == "region":
                        for g in regs:
                            rc, so, se, dur, to = self.run(
                                self.v2() + ["vaddump", "-p", pid, "-b", str(g["start"]), "-D", str(stg)],
                                "vaddump1#vol2")
                            to_any |= to
                    else:
                        rc, so, se, dur, to = self.run(self.v2() + ["vaddump", "-p", pid, "-D", str(stg)],
                                                       "vaddump#vol2", floor=900)
                        to_any = to
            else:
                plugin = "linux.proc.Maps" if self.os == "linux" else "mac.proc_maps.Maps"
                if v3:
                    argv = self.v3(stg) + [plugin, "--pid", pid, "--dump"]
                    if mode == "region":
                        # --address matches ANY address inside a VMA with an
                        # inclusive end, so a VMA's start also selected the
                        # neighbour ending there: pass start+1 (strictly inside).
                        argv += ["--address"] + [hex((ci._int(g["start"]) or 0) + 1) for g in regs]
                    rc, so, se, dur, to = self.run(argv, f"{plugin}#dump" + ("1" if mode == "region" else ""),
                                                   floor=300 if mode == "region" else 900)
                    it["duration_s"] = round(dur, 1)
                    to_any, err = to, self.err_line(se)
                elif self.os == "linux":
                    if mode == "region":
                        for g in regs:
                            rc, so, se, dur, to = self.run(
                                self.v2() + ["linux_dump_map", "-p", pid, "-s", str(g["start"]), "-D", str(stg)],
                                "linux_dump_map1#vol2")
                            to_any |= to
                    else:
                        rc, so, se, dur, to = self.run(self.v2() + ["linux_dump_map", "-p", pid, "-D", str(stg)],
                                                       "linux_dump_map#vol2", floor=900)
                        to_any = to
            for f in self.outputs(stg):
                fl = self.plain(f)
                reason = ""
                m = re.search(r"\.(0x[0-9a-f]+)-0x[0-9a-f]+\.", fl)     # pid.N.vad|vma.<start>-<end>.dmp
                fstart = ci._int(m.group(1)) if m else None
                for a, why in inj.items():
                    if fstart is not None and ci._int(a) == fstart:
                        reason = why
                        break
                it["outputs"].append(self.out_entry(self.move(f, folder), injection=reason))
            self.drop_staging(stg)
            if not it["outputs"]:
                it["detail"] = "timed out" if to_any else (
                    err or ("no memory mappings returned - the process has probably exited "
                            "(psscan also lists terminated tasks)" if self.os != "windows"
                            else "no region content was resident"))
            self.finish_item(it, i, n)

    # ============================================================= REGIONS
    def job_regions(self, items):
        """List the memory regions of the given PIDs (case had none for them)."""
        n = len(items)
        plugin = {"windows": "windows.vadinfo.VadInfo", "linux": "linux.proc.Maps",
                  "mac": "mac.proc_maps.Maps"}[self.os if self.os in ("linux", "mac") else "windows"]
        for i, r in enumerate(items, 1):
            pid = str(r["pid"])
            it = self.item(f"regions of PID {pid}", {"pid": pid})
            pg.emit("xitem", i=i, n=n, label=it["label"], state="running")
            if self.eng != "vol3":
                it["detail"] = "region listing needs Volatility 3 (Vol2 case: use the plugin JSON)"
                self.finish_item(it, i, n)
                continue
            rc, so, se, dur, to = self.run(self.v3(json_out=True) + [plugin, "--pid", pid],
                                           f"{plugin}#pid")
            s = "\n".join(l for l in so.splitlines() if not l.startswith("Progress:")).strip()
            try:
                rows = json.loads(s) if s[:1] in "[{" else []
            except ValueError:
                rows = []
            if rows:
                p = ci.regions_file(self.case, pid)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(json.dumps(rows), encoding="utf-8")
                it["status"] = "ok"
                it["outputs"].append({"file": str(p), "size": p.stat().st_size, "rows": len(rows)})
                it["detail"] = f"{len(rows)} regions"
            else:
                it["detail"] = "timed out" if to else (self.err_line(se) or "no regions returned")
            self.finish_item(it, i, n)

    # ============================================================ FILELIST
    def job_filelist(self, items):
        it = self.item("build file list", {})
        pg.emit("xitem", i=1, n=1, label=it["label"], state="running")
        if self.os == "linux" and self.eng == "vol2":
            rc, so, se, dur, to = self.run(self.v2() + ["linux_find_file", "-L"], "linux_find_file_L#vol2",
                                           floor=900)
            rows = []
            for line in so.splitlines():
                m = re.match(r"\s*(\d+)\s+(0x[0-9a-fA-F]+)\s+(\S.*)$", line)
                if m:
                    rows.append({"inode": m.group(1), "inode_addr": m.group(2), "path": m.group(3).strip()})
            if rows:
                p = self.case / "json" / "linux_find_file_vol2.json"
                p.write_text(json.dumps(rows, indent=1), encoding="utf-8")
                it["status"] = "ok"
                it["outputs"].append({"file": str(p), "size": p.stat().st_size, "rows": len(rows)})
            else:
                it["detail"] = "timed out" if to else (self.err_line(se) or "linux_find_file -L returned nothing")
        else:
            plugin = {"windows": "windows.filescan.FileScan", "linux": "linux.pagecache.Files",
                      "mac": "mac.list_files.List_Files"}[self.os if self.os in ("linux", "mac") else "windows"]
            res = self.vol.run_plugin(self.image, plugin, self.case)
            src, rows = ci.file_list(self.case)
            if res.get("success") and rows:
                it["status"] = "ok"
                it["outputs"].append({"file": res.get("output_file", ""), "rows": len(rows), "size": 1})
            else:
                it["detail"] = str(res.get("error") or "no files listed")[:200]
        self.finish_item(it, 1, 1)

    # ================================================================ HUNT
    def job_hunt(self, items):
        from modules.string_hunt import StringHunter
        terms = [t for t in (self.spec.get("terms") or []) if t.strip()]
        pids = [int(p) for p in (self.spec.get("pids") or []) if str(p).strip().isdigit()]
        it = self.item(f"hunt {len(terms)} term(s)" + (f" in PID {','.join(map(str, pids))}" if pids else ""),
                       {"terms": terms, "pids": pids})
        pg.emit("xitem", i=1, n=1, label=it["label"], state="running")
        if not terms:
            it["detail"] = "no search terms"
            self.finish_item(it, 1, 1)
            return
        hunter = StringHunter(self.log)
        if self.os == "mac" and pids and self.eng == "vol3":
            # macOS has no per-process YARA plugin (YaraScan walks ALL physical
            # memory - 12+ min on a 6 GB image, PID filter impossible): dump the
            # chosen processes' regions and search them directly instead.
            res = self._hunt_regions(hunter, terms, pids)
        else:
            res = hunter.hunt(
                self.image, self.dest, terms, self.vol, self.os, pid_filter=pids or None,
                case_insensitive=not self.spec.get("case_sensitive", False),
                wide=self.spec.get("wide", True), strings_dir=self.case)
        if hunter.scan_error and not res.get("total_hits"):
            it["status"] = "failed"
            it["detail"] = (f"memory scan did not complete ({hunter.scan_error}) - 0 hits here does "
                            "NOT mean the term is absent; narrow it to PIDs and retry")
            self.finish_item(it, 1, 1)
            return {"hits": 0}
        # Linux/macOS YARA plugins report only the PID: add the process name
        hp = self.dest / "json" / "string_hunt.json"
        try:
            names = {p["pid"]: p["name"] for p in ci.process_list(self.case)}
            d = json.loads(hp.read_text(encoding="utf-8"))
            changed = False
            for h in d.get("hits", []):
                if str(h.get("process", "unknown")) in ("", "unknown") and str(h.get("pid")) in names:
                    h["process"] = names[str(h["pid"])]
                    changed = True
            if changed:
                hp.write_text(json.dumps(d, indent=2, default=str), encoding="utf-8")
        except (OSError, ValueError):
            pass
        it["status"] = "ok"
        it["detail"] = (f"{res.get('total_hits', 0)} memory hit(s) via {res.get('plugin')}; "
                        f"strings-file counts: {res.get('strings_hits')}")
        for p in (self.dest / "json" / "string_hunt.json", self.dest / "string_hunt_report.txt"):
            if p.is_file():
                it["outputs"].append(self.out_entry(p))
        self.finish_item(it, 1, 1)
        return {"hits": res.get("total_hits", 0)}

    def _hunt_regions(self, hunter, terms, pids):
        """Search the dumped memory regions of `pids` for `terms` (ASCII, plus
        UTF-16LE when wide). Regions are kept under dest/scanned_memory so every
        hit can be verified. Returns a StringHunter-shaped results dict."""
        cs = self.spec.get("case_sensitive", False)
        wide = self.spec.get("wide", True)
        names = {p["pid"]: p["name"] for p in ci.process_list(self.case)}
        pats = []
        for t in terms:
            for enc in (["ascii", "utf-16-le"] if wide else ["ascii"]):
                try:
                    b = t.encode(enc)
                except UnicodeEncodeError:
                    b = t.encode("utf-8") if enc == "ascii" else None
                if b:
                    pats.append((t, enc, b if cs else b.lower()))
        hits = []
        plugin = "mac.proc_maps.Maps" if self.os == "mac" else "linux.proc.Maps"
        for pid in map(str, pids):
            folder = self.dest / "scanned_memory" / f"pid_{pid}_{ci.safe_name(names.get(pid, ''), 40)}"
            folder.mkdir(parents=True, exist_ok=True)
            rc, so, se, dur, to = self.run(self.v3(folder) + [plugin, "--pid", pid, "--dump"],
                                           f"{plugin}#dump", floor=900)
            if to and not self.outputs(folder):
                hunter.scan_error = f"{plugin} timed out for PID {pid}"
            for f in self.outputs(folder):
                m = re.search(r"\.(0x[0-9a-f]+)-0x[0-9a-f]+\.", f.name.lower())
                base = ci._int(m.group(1)) if m else 0
                if safe_zip.is_protected(f):            # decrypted in memory only
                    data = safe_zip.read_member(f, self.zip_pw)
                else:
                    data = f.read_bytes()
                    if self.protect:
                        f = Path(safe_zip.pack_file(f, self.zip_pw))
                        self.packed_after += 1
                hay = data if cs else data.lower()
                for term, enc, pb in pats:
                    i = hay.find(pb)
                    while i >= 0 and len(hits) < 5000:
                        ctx = data[i:i + max(16, len(pb))]
                        hits.append({"pid": int(pid), "process": names.get(pid, ""),
                                     "search_term": term, "rule": f"region-scan ({enc})",
                                     "offset": f"0x{base + i:016x}",
                                     "hex_bytes": " ".join(f"{c:02x}" for c in ctx[:32]),
                                     "decoded": ctx.decode(enc, "replace").replace("\x00", ".")[:64],
                                     "region_file": str(f.relative_to(self.dest))})
                        i = hay.find(pb, i + 1)
        by_term = {t: [h for h in hits if h["search_term"] == t] for t in terms}
        res = {"terms": terms, "hits": hits, "by_term": by_term, "total_hits": len(hits),
               "plugin": f"{plugin} --dump + byte search", "image": self.image,
               "strings_hits": hunter._grep_strings_files(self.case, terms)}
        jd = self.dest / "json"
        jd.mkdir(parents=True, exist_ok=True)
        (jd / "string_hunt.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
        return res

    # ============================================================== EXPORT
    def job_export(self, items):
        from modules.export_pack import ExportPack
        it = self.item("export pack", {})
        pg.emit("xitem", i=1, n=1, label=it["label"], state="running")
        z = ExportPack(self.log).generate(self.case, dest_dir=self.dest)
        if Path(z).is_file():
            it["outputs"].append(self.out_entry(Path(z)))
        else:
            it["detail"] = "nothing to export (run an analysis first)"
        self.finish_item(it, 1, 1)


def run_spec(spec_path: str, vol, log: logging.Logger) -> int:
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    return Job(spec, vol, log).execute()
