#!/usr/bin/env python3
"""dbgsym_builder.py — build a Volatility 3 ISF from official kernel debug symbols.

CresCent v6.0 — Author: Ahmad Anasweh

WHY THIS EXISTS
    The Abyss-W4tcher community repo only carries a subset of kernel builds. When
    a memory image's exact kernel isn't there (e.g. Ubuntu 5.15.0-41-generic,
    which the repo skips — it jumps from -25 to -70), the resolver has nothing to
    download and the Linux plugins that need full struct types fail with errors
    like "Symbol type not in SymbolTable: inet6_ifaddr" or "Unable to find list
    for type Void".

    The correct fix is to build the ISF from the distro's OWN debug package, which
    contains a vmlinux with complete DWARF type info. This module automates that,
    driven only by the kernel version string:

        version  ->  find the -dbgsym .ddeb  ->  download  ->  extract vmlinux
                 ->  dwarf2json  ->  <Distro>_<ver>_<arch>.json.xz  ->  install

SOURCES (Debian-family, by distro)
    Ubuntu / Mint / Pop!_OS  — `linux-image-<ver>-dbgsym` .ddeb:
        1. ddebs.ubuntu.com pool  — fast mirror, but only keeps CURRENT releases.
        2. Launchpad API          — authoritative and dynamic: resolves ANY
                                    published build (including pruned old ones).
    Kali / Debian            — `linux-image-<ver>-dbg` .deb from the distro's OWN
        pool (`.../pool/main/l/linux/`). These are NOT on Launchpad/ddebs; we
        scrape the pool directory index for the exact filename (the package
        version, e.g. `6.19.14-1+kali1`, isn't derivable from the banner).

    RHEL-family (Fedora/CentOS/Alma/Rocky) ship debuginfo RPMs — see
    build_isf_from_rhel_debuginfo below. SUSE/Arch are out of scope here; for
    those, build manually with dwarf2json.

USAGE (CLI)
    python3 modules/dbgsym_builder.py --kernel 5.15.0-41-generic --arch amd64 --install
    python3 modules/dbgsym_builder.py --kernel 5.15.0-41-generic          # build only
    python3 modules/dbgsym_builder.py --kernel 6.8.0-31-generic --arch amd64 \
            --keep-ddeb /tmp/cache            # reuse an already-downloaded .ddeb

USAGE (import)
    from modules.dbgsym_builder import build_isf_from_dbgsym
    isf = build_isf_from_dbgsym("5.15.0-41-generic", arch="amd64", install=True)
"""

import argparse
import hashlib
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from typing import List, Optional, Tuple

# ── colour / message helpers (reuse the toolkit's if available) ────────────────
try:
    from utils.ui import msg_ok, msg_warn, msg_fail, msg_info
except Exception:  # pragma: no cover - standalone fallback
    def msg_ok(m):   print(f"  [+] {m}")
    def msg_warn(m): print(f"  [!] {m}")
    def msg_fail(m): print(f"  [x] {m}")
    def msg_info(m): print(f"  [-] {m}")

LAUNCHPAD_API = "https://api.launchpad.net/devel/ubuntu/+archive/primary"
DDEBS_POOL = "https://ddebs.ubuntu.com/pool/main/l"


# ── download integrity (H2/H3) ────────────────────────────────────────────────
# Hosts confirmed to serve these debug packages over TLS. A plain-http URL for one
# of these is silently upgraded to https so a passive network attacker can't tamper
# in transit. Hosts NOT here (e.g. the legacy CentOS vault debuginfo mirror, which
# is http-only) can't be upgraded — the package-magic + sha256 check below is the
# integrity mitigation there.
_HTTPS_CAPABLE_HOSTS = (
    "ddebs.ubuntu.com", "api.launchpad.net", "launchpad.net",
    "launchpadlibrarian.net", "kali.download", "http.kali.org",
    "deb.debian.org", "ftp.debian.org", "kojipkgs.fedoraproject.org",
    "download.rockylinux.org", "dl.rockylinux.org", "repo.almalinux.org",
)

# First bytes of the archive formats a debug package legitimately arrives as. A
# download that matches none of these is an HTML error page / redirect / garbage
# from a broken or hostile mirror — refuse it before dwarf2json ever parses it.
_PKG_MAGICS = {
    b"!<arch>": "deb/ddeb (ar archive)",
    b"\xed\xab\xee\xdb": "rpm",
    b"\xfd7zXZ\x00": "xz",
    b"\x1f\x8b": "gzip",
    b"BZh": "bzip2",
    b"\x28\xb5\x2f\xfd": "zstd",
    b"PK\x03\x04": "zip",
}


def prefer_https(url: str) -> str:
    """Upgrade a plain-http URL to https when the host is known to support TLS.
    Pure. Leaves genuinely http-only hosts untouched (they're covered by the
    post-download integrity check)."""
    if url.startswith("http://"):
        host = url.split("/", 3)[2].split("@")[-1].split(":")[0]
        if host in _HTTPS_CAPABLE_HOSTS:
            return "https://" + url[len("http://"):]
    return url


def looks_like_package(head: bytes) -> Optional[str]:
    """Return a human label if `head` (first bytes of a file) is one of the
    archive formats a debug package legitimately uses, else None. Pure."""
    for magic, kind in _PKG_MAGICS.items():
        if head.startswith(magic):
            return kind
    return None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_downloaded_package(path: Path, expected_sha256: Optional[str] = None) -> bool:
    """Integrity-check a freshly downloaded debug package BEFORE it is extracted.

    Two checks: (1) the file's magic must be a real package/archive format — this
    catches an HTML error page, a redirect body, or garbage served by a MITM or a
    broken mirror; (2) if a known-good ``expected_sha256`` is supplied, it must
    match. Always logs the computed sha256 for auditability. This is defence in
    depth, not a signature check — some legacy debuginfo mirrors are http-only —
    but it stops the obvious tamper/corruption cases. Fails CLOSED on a clear
    magic/hash mismatch, open on an unexpected read error."""
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except Exception as e:
        msg_warn(f"Integrity check could not read {path.name}: {e}")
        return True
    digest = _sha256_file(path)
    kind = looks_like_package(head)
    if kind is None:
        msg_fail(f"Downloaded {path.name} is NOT a package archive "
                 f"(magic {head[:4].hex()}) — refusing it (possible tampered/"
                 f"broken mirror). sha256={digest[:16]}…")
        return False
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        msg_fail(f"{path.name} sha256 mismatch — refusing it. "
                 f"got {digest[:16]}…, expected {expected_sha256[:16]}…")
        return False
    msg_ok(f"Verified {path.name}: {kind}, sha256={digest[:16]}…")
    return True

# Debian-family debug symbols are NOT on Launchpad/ddebs.ubuntu.com. Kali and
# Debian publish the kernel debug image as an ordinary `linux-image-<ver>-dbg`
# .deb inside their own package pool (source package `linux`, pool prefix
# `main/l/linux`). We resolve it by scraping the pool directory index, because
# the exact package version (e.g. `6.19.14-1+kali1`) isn't derivable from the
# kernel banner alone. Mirrors are tried in order; kali.download / deb.debian.org
# are CDN-fronted and usually serve a direct 200 with Content-Length.
_POOL_INDEX_HOSTS = {
    "kali": [
        "https://kali.download/kali/pool/main/l/linux/",
        "https://http.kali.org/kali/pool/main/l/linux/",
    ],
    "debian": [
        "https://deb.debian.org/debian/pool/main/l/linux/",
        "https://ftp.debian.org/debian/pool/main/l/linux/",
    ],
}

# Where to look for the dwarf2json binary if it isn't on PATH.
_REPO_ROOT = Path(__file__).resolve().parent.parent
DWARF2JSON_FALLBACKS = [
    _REPO_ROOT / "_isf_build" / "dwarf2json",
    _REPO_ROOT / "dwarf2json",
]

# Vol3 install locations (mirrors linux_resolver.VOL3_PATHS).
VOL3_PATHS = [
    Path.home() / "Desktop" / "volatility3",
    Path.home() / "volatility3",
    Path("/opt/volatility3"),
    Path.home() / "tools" / "volatility3",
]


# ══════════════════════════════════════════════════════════════════════════════
# Small utilities
# ══════════════════════════════════════════════════════════════════════════════

def normalize_arch(arch: str) -> str:
    """Map any arch label we might get to a Debian arch (amd64/i386/arm64/armhf)."""
    a = (arch or "").lower()
    return {
        "x64": "amd64", "x86_64": "amd64", "amd64": "amd64",
        "x86": "i386", "i386": "i386", "i686": "i386",
        "arm64": "arm64", "aarch64": "arm64",
        "arm": "armhf", "armv7": "armhf", "armhf": "armhf",
    }.get(a, a or "amd64")


def find_dwarf2json() -> Optional[str]:
    """Return a usable dwarf2json path — BUNDLED build preferred over PATH.

    We deliberately prefer the repo's `_isf_build/dwarf2json` over any
    dwarf2json on PATH. Distro packages (e.g. /usr/bin/dwarf2json) and the
    v0.9.0 release carry a DWARF type-merge bug: when a struct appears as a
    forward declaration in most CUs and a full definition in only a few (the
    case for the private VFS structs `struct mount` / `struct mnt_namespace`
    from fs/mount.h), the old binary registers the stub and never upgrades it.
    The resulting ISF has an empty `struct mount`, so every mount-tree-walking
    plugin (lsof, proc.Maps, malfind, mountinfo, pagecache, elfs, sockstat)
    dies with 'Member not present in template: mnt'. The bundled binary is a
    vetted current build that resolves these correctly, so it wins.
    """
    for p in DWARF2JSON_FALLBACKS:
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return shutil.which("dwarf2json")


def find_vol3_symbols_dir(os_type: str = "linux") -> Optional[Path]:
    """Locate <vol3>/volatility3/symbols/<os_type>, or None if Vol3 isn't found."""
    sub = "mac" if os_type == "mac" else "linux"
    for p in VOL3_PATHS:
        if (p / "vol.py").exists():
            d = p / "volatility3" / "symbols" / sub
            d.mkdir(parents=True, exist_ok=True)
            return d
    return None


def _kernel_flavour(kernel_ver: str) -> str:
    """'5.15.0-41-generic' -> 'generic'; default 'generic' if none present."""
    parts = kernel_ver.split("-")
    return parts[-1] if len(parts) >= 3 and not parts[-1].isdigit() else "generic"


# ══════════════════════════════════════════════════════════════════════════════
# 1. Resolve the dbgsym download URL (dynamic, version-driven)
# ══════════════════════════════════════════════════════════════════════════════

def _binary_name_candidates(kernel_ver: str) -> List[str]:
    """Debug binary package names to try, newest naming first.

    Modern Ubuntu ships 'linux-image-unsigned-<ver>-dbgsym'; older releases used
    'linux-image-<ver>-dbgsym'. We try both so the lookup is version-agnostic.
    """
    return [
        f"linux-image-unsigned-{kernel_ver}-dbgsym",
        f"linux-image-{kernel_ver}-dbgsym",
    ]


def _launchpad_lookup(binary_name: str, deb_arch: str
                      ) -> Optional[Tuple[str, str, str]]:
    """Ask Launchpad for the newest published build of `binary_name` on `deb_arch`.

    Returns (file_url, filename, source_package_name) or None. This is the
    authoritative, fully-dynamic resolver: it works for current AND pruned builds
    because Launchpad keeps every historical publication.
    """
    q = (f"{LAUNCHPAD_API}?ws.op=getPublishedBinaries&binary_name={binary_name}"
         f"&exact_match=true&order_by_date=true")
    try:
        data = json.load(urllib.request.urlopen(q, timeout=30))
    except Exception as e:
        msg_warn(f"Launchpad query failed for {binary_name}: {e}")
        return None
    entries = [e for e in data.get("entries", [])
               if e.get("distro_arch_series_link", "").endswith("/" + deb_arch)]
    # A single "<ver>-generic" can exist as several builds — the native release
    # (e.g. 5.15.0-41.44) AND HWE backports to older series (5.15.0-41.44~20.04.1).
    # Their vmlinux banners differ, so the ISF only matches the image if we build
    # from the right one. Prefer the NATIVE build (version without a '~' backport
    # suffix); Launchpad already returns newest-first, so this is a stable sort
    # that keeps date order within each group.
    entries.sort(key=lambda e: "~" in e.get("binary_package_version", ""))
    for e in entries:
        self_link = e.get("self_link")
        source = e.get("source_package_name", "linux")
        try:
            urls = json.load(urllib.request.urlopen(
                self_link + "?ws.op=binaryFileUrls", timeout=30))
        except Exception as e2:
            msg_warn(f"Launchpad file-URL fetch failed: {e2}")
            continue
        if urls:
            file_url = urls[0]
            return file_url, os.path.basename(file_url), source
    return None


def _url_ok(url: str) -> bool:
    """True if a HEAD (or ranged GET) on url returns a success status."""
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=25) as r:
            return 200 <= r.status < 400
    except Exception:
        return False


def resolve_debian_pool_dbg(kernel_ver: str, deb_arch: str, distro: str
                            ) -> Optional[Tuple[List[str], str]]:
    """Resolve a Kali/Debian kernel to its `linux-image-<ver>-dbg` .deb.

    Debian-family debug symbols ship as an ordinary `-dbg` .deb in the distro's
    own pool (`.../pool/main/l/linux/`), NOT as Ubuntu `-dbgsym` on Launchpad.
    The package version in the filename (e.g. `6.19.14-1+kali1`) can't be derived
    from the kernel banner, so we fetch the pool directory index and match
    `linux-image-<kernel_ver>-dbg_<pkgver>_<arch>.deb`. Returns
    (candidate_urls, filename) across all mirrors, or None.
    """
    hosts = _POOL_INDEX_HOSTS.get((distro or "").lower())
    if not hosts:
        return None
    # Filenames in the index may appear URL-encoded (`%2B` for `+`); match on the
    # decoded form so the regex is simple and mirror-agnostic.
    pat = re.compile(
        r'linux-image-' + re.escape(kernel_ver) +
        r'-dbg_[^"\s/]+_' + re.escape(deb_arch) + r'\.deb')
    for idx in hosts:
        try:
            with urllib.request.urlopen(idx, timeout=30) as r:
                html = urllib.parse.unquote(r.read().decode("utf-8", "ignore"))
        except Exception as e:
            msg_warn(f"{idx.split('/')[2]} pool index unreachable: {e}")
            continue
        matches = sorted(set(pat.findall(html)))
        if not matches:
            continue
        filename = matches[-1]  # lexically-newest published version
        # Build a download URL on every mirror (the `+` must be %2B in the path).
        quoted = urllib.parse.quote(filename)
        urls = [h + quoted for h in hosts]
        msg_info(f"Resolved {filename}")
        msg_info(f"  source package: linux ({distro} pool)")
        for u in urls:
            msg_info(f"  candidate: {u.split('/')[2]} …/{filename}")
        return urls, filename
    return None


def resolve_dbgsym(kernel_ver: str, deb_arch: str, distro: str = "Ubuntu"
                   ) -> Optional[Tuple[List[str], str]]:
    """Resolve a kernel version to (candidate_urls, filename).

    Debian-family (Kali/Debian) resolve to a `-dbg` .deb in the distro pool;
    Ubuntu-family resolve to a `-dbgsym` .ddeb via Launchpad + ddebs.ubuntu.com.
    candidate_urls are tried in order by the downloader.
    """
    if (distro or "").lower() in _POOL_INDEX_HOSTS:
        found = resolve_debian_pool_dbg(kernel_ver, deb_arch, distro)
        if found:
            return found
        msg_warn(f"No -dbg package in the {distro} pool for {kernel_ver} "
                 f"({deb_arch}) — trying the Ubuntu archive as a fallback...")
    for bn in _binary_name_candidates(kernel_ver):
        found = _launchpad_lookup(bn, deb_arch)
        if not found:
            continue
        lp_url, filename, source = found
        candidates = []
        # ddebs mirror derived from the resolved source + filename. Only added if
        # it actually responds (old point releases are pruned from the pool).
        ddebs_url = f"{DDEBS_POOL}/{source}/{filename}"
        if _url_ok(ddebs_url):
            candidates.append(ddebs_url)
        candidates.append(lp_url)
        msg_info(f"Resolved {filename}")
        msg_info(f"  source package: {source}")
        for u in candidates:
            msg_info(f"  candidate: {u.split('/')[2]} …/{filename}")
        return candidates, filename
    msg_fail(f"No published dbgsym found for kernel {kernel_ver} ({deb_arch}).")
    return None


# ══════════════════════════════════════════════════════════════════════════════
# 2. Download (resume + retry — survives Launchpad's intermittent 503s)
# ══════════════════════════════════════════════════════════════════════════════

def _head(url: str) -> Tuple[Optional[int], bool]:
    """HEAD a URL → (content_length, accepts_ranges)."""
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=25) as r:
            cl = r.headers.get("Content-Length")
            ar = (r.headers.get("Accept-Ranges", "") or "").lower()
            return (int(cl) if cl else None), (ar not in ("", "none"))
    except Exception:
        return None, False


def _expected_size(url: str) -> Optional[int]:
    return _head(url)[0]


def download_resume(urls: List[str], dest: Path,
                    max_attempts: int = 60) -> bool:
    """Download `dest` from the first working URL, robust to a flaky server.

    Launchpad's librarian is unreliable for large old files (its squid cache
    returns 503 on a MISS) AND advertises `Accept-Ranges: none`, so a cut stream
    cannot be resumed — `curl -C -` just errors out. We therefore adapt:

      * If the server DOES support ranges (e.g. the ddebs.ubuntu.com mirror),
        resume across failures via `curl -C -` (progress is monotonic).
      * If it does NOT, retry the WHOLE file each attempt with a long timeout, so
        one healthy, uninterrupted stream can run to completion; a 503-at-connect
        fails fast and we simply try again (or fall to the next URL).

    Returns True when the file is complete.
    """
    if not shutil.which("curl"):
        return _download_urllib(urls, dest)

    dest.parent.mkdir(parents=True, exist_ok=True)
    for idx, url in enumerate(urls):
        url = prefer_https(url)
        if url.startswith("http://"):
            msg_warn(f"{url.split('/')[2]} is http-only — cannot secure transport; "
                     "relying on the post-download package-integrity check.")
        expected, ranges = _head(url)
        if not expected:
            continue
        host = url.split("/")[2]
        msg_info(f"Downloading from {host} "
                 f"({'resumable' if ranges else 'no-resume'}, "
                 f"{expected/1024/1024:.0f} MB)")
        attempt = 0
        while attempt < max_attempts:
            cur = dest.stat().st_size if dest.exists() else 0
            if cur >= expected:
                print()
                msg_ok(f"Downloaded {dest.name} ({cur/1024/1024:.1f} MB)")
                if verify_downloaded_package(dest):
                    return True
                dest.unlink(missing_ok=True)
                break  # tampered/garbage — try the next source
            attempt += 1
            if ranges:
                cmd = ["curl", "-sL", "-C", "-", "--connect-timeout", "20",
                       "--max-time", "300", "-o", str(dest), url]
            else:
                # No range support: full stream each try, generous ceiling.
                if dest.exists():
                    dest.unlink()
                cmd = ["curl", "-sL", "--connect-timeout", "30",
                       "--max-time", "2400", "-o", str(dest), url]
            subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            new = dest.stat().st_size if dest.exists() else 0
            if new >= expected:
                print()
                msg_ok(f"Downloaded {dest.name} ({new/1024/1024:.1f} MB)")
                if verify_downloaded_package(dest):
                    return True
                dest.unlink(missing_ok=True)
                break  # tampered/garbage — try the next source
            pct = int(new * 100 / expected)
            print(f"\r  [-] Download ({host}): {pct}% "
                  f"({new/1024/1024:.0f}/{expected/1024/1024:.0f} MB), "
                  f"attempt {attempt}", end="", flush=True)
            if new <= cur:  # no progress — brief backoff before retrying
                time.sleep(3)
        print()
        msg_warn(f"{host} did not complete after {attempt} attempts"
                 + (" — trying next source" if idx + 1 < len(urls) else ""))
    msg_fail("Download did not complete from any source.")
    return False


def _download_urllib(urls: List[str], dest: Path) -> bool:
    """No-curl fallback: straight streaming download (no resume)."""
    for url in urls:
        url = prefer_https(url)
        try:
            with urllib.request.urlopen(url, timeout=60) as r, \
                    open(dest, "wb") as f:
                shutil.copyfileobj(r, f, length=1024 * 1024)
            if dest.stat().st_size > 0:
                msg_ok(f"Downloaded {dest.name} "
                       f"({dest.stat().st_size/1024/1024:.1f} MB)")
                if verify_downloaded_package(dest):
                    return True
                dest.unlink(missing_ok=True)  # tampered/garbage — try next
        except Exception as e:
            msg_warn(f"  {url.split('/')[2]} failed: {e}")
    return False


# ══════════════════════════════════════════════════════════════════════════════
# 3. Extract vmlinux from the .ddeb
# ══════════════════════════════════════════════════════════════════════════════

def extract_vmlinux(ddeb: Path, workdir: Path) -> Optional[Path]:
    """Unpack the .ddeb and return the path to its vmlinux debug image."""
    workdir.mkdir(parents=True, exist_ok=True)
    if shutil.which("dpkg-deb"):
        try:
            subprocess.run(["dpkg-deb", "-x", str(ddeb), str(workdir)],
                           check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            msg_warn(f"dpkg-deb failed: {e.stderr[:200].decode(errors='ignore')}")
    else:
        # ar + tar fallback (a .ddeb is an ar archive of {control,data}.tar.*).
        if not _extract_with_ar(ddeb, workdir):
            return None
    # The debug vmlinux lives under usr/lib/debug/boot/vmlinux-<ver>.
    hits = list(workdir.rglob("vmlinux-*")) or list(workdir.rglob("vmlinux"))
    hits = [h for h in hits if h.is_file()]
    if not hits:
        msg_fail("No vmlinux found inside the debug package.")
        return None
    vmlinux = max(hits, key=lambda p: p.stat().st_size)  # the real image is largest
    msg_ok(f"Extracted {vmlinux.name} ({vmlinux.stat().st_size/1024/1024:.1f} MB)")
    return vmlinux


def _extract_with_ar(ddeb: Path, workdir: Path) -> bool:
    try:
        subprocess.run(["ar", "x", str(ddeb)], cwd=str(workdir), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        data = next((p for p in workdir.glob("data.tar*")), None)
        if not data:
            return False
        subprocess.run(["tar", "xf", str(data), "-C", str(workdir)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        msg_fail(f"ar/tar extraction failed: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# 4. dwarf2json build + install
# ══════════════════════════════════════════════════════════════════════════════

def build_isf(vmlinux: Path, out_xz: Path) -> bool:
    """Run dwarf2json on vmlinux and write a compressed ISF to out_xz."""
    d2j = find_dwarf2json()
    if not d2j:
        msg_fail("dwarf2json not found (PATH or _isf_build/). Cannot build ISF.")
        return False
    msg_info("Building ISF with dwarf2json (reads DWARF types + ELF symbols)...")
    try:
        # --elf pulls BOTH type info (DWARF) and symbol addresses (ELF symtab)
        # from the single debug vmlinux — this is what a complete ISF needs.
        proc = subprocess.run([d2j, "linux", "--elf", str(vmlinux)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=1800)
    except subprocess.TimeoutExpired:
        msg_fail("dwarf2json timed out (>30 min).")
        return False
    if proc.returncode != 0 or not proc.stdout:
        msg_fail(f"dwarf2json failed: "
                 f"{proc.stderr[:300].decode(errors='ignore')}")
        return False
    out_xz.parent.mkdir(parents=True, exist_ok=True)
    try:
        with lzma.open(str(out_xz), "wb") as f:
            f.write(proc.stdout)
    except Exception as e:
        msg_fail(f"Failed to compress ISF: {e}")
        return False
    stubs = _isf_stub_structs(out_xz)
    if stubs:
        msg_warn("ISF built but incomplete — stub struct(s): " + ", ".join(stubs)
                 + ". Path-walking plugins (lsof/proc.Maps/malfind/mountinfo/"
                 "pagecache) will fail with 'Member not present in template: mnt'."
                 " This means an outdated dwarf2json; rebuild it with "
                 "'go install github.com/volatilityfoundation/dwarf2json@master'"
                 " into _isf_build/.")
    msg_ok(f"Built {out_xz.name} ({out_xz.stat().st_size/1024/1024:.1f} MB)")
    return True


def _isf_stub_structs(isf_xz: Path) -> List[str]:
    """Names of VFS structs that came out as empty stubs in a freshly-built ISF.

    A dwarf2json type-merge miss leaves `struct mount`/`mnt_namespace` with no
    members (or only a synthetic `_unused`), which silently breaks every Linux
    path-resolution plugin. We check the structs those plugins dereference.
    """
    key = ("mount", "mnt_namespace")
    try:
        with lzma.open(str(isf_xz)) as f:
            ut = json.load(f).get("user_types", {})
    except Exception:
        return []
    bad = []
    for name in key:
        t = ut.get(name)
        if not t:
            continue
        fields = t.get("fields", {})
        if not fields or set(fields) == {"_unused"}:
            bad.append(name)
    return bad


def install_isf(isf_xz: Path, os_type: str = "linux") -> bool:
    """Copy the built ISF into the Vol3 symbols directory."""
    sym_dir = find_vol3_symbols_dir(os_type)
    if not sym_dir:
        msg_warn("Volatility 3 not found — ISF built but not installed.")
        return False
    dest = sym_dir / isf_xz.name
    try:
        shutil.copy2(str(isf_xz), str(dest))
        msg_ok(f"Installed → {dest}")
        return True
    except Exception as e:
        msg_fail(f"Install failed: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# Orchestrator
# ══════════════════════════════════════════════════════════════════════════════

def build_isf_from_dbgsym(kernel_ver: str, arch: str = "amd64",
                          install: bool = False, distro: str = "Ubuntu",
                          keep_ddeb: Optional[Path] = None,
                          dest_dir: Optional[Path] = None) -> Optional[Path]:
    """Full pipeline: version -> dbgsym -> vmlinux -> dwarf2json -> ISF (.json.xz).

    Returns the path to the built ISF (in dest_dir, default a temp dir), or None.
    If install=True the ISF is also copied into the Vol3 symbols directory.
    `keep_ddeb` is a directory to cache/reuse the downloaded .ddeb across runs.
    """
    deb_arch = normalize_arch(arch)
    msg_info(f"Building ISF for {distro} {kernel_ver} ({deb_arch})")

    if not find_dwarf2json():
        msg_fail("dwarf2json is required but not found (PATH or _isf_build/).")
        return None

    resolved = resolve_dbgsym(kernel_ver, deb_arch, distro=distro)
    if not resolved:
        return None
    urls, filename = resolved

    ddeb_dir = Path(keep_ddeb) if keep_ddeb else Path(tempfile.mkdtemp(
        prefix="crescent_dbgsym_"))
    ddeb_dir.mkdir(parents=True, exist_ok=True)
    ddeb = ddeb_dir / filename

    # Reuse a fully-downloaded cache if present.
    exp = _expected_size(urls[0]) if urls else None
    if ddeb.exists() and exp and ddeb.stat().st_size >= exp:
        msg_ok(f"Reusing cached {ddeb.name} ({ddeb.stat().st_size/1024/1024:.1f} MB)")
    else:
        if not download_resume(urls, ddeb):
            return None

    work = Path(tempfile.mkdtemp(prefix="crescent_vmlinux_"))
    try:
        vmlinux = extract_vmlinux(ddeb, work)
        if not vmlinux:
            return None

        srcver = filename.split("_")[-2] if filename.count("_") >= 2 else ""
        stem = (f"{distro}_{kernel_ver}_{srcver}_{deb_arch}"
                if srcver else f"{distro}_{kernel_ver}_{deb_arch}")
        out_dir = Path(dest_dir) if dest_dir else Path(tempfile.mkdtemp(
            prefix="crescent_isf_"))
        out_xz = out_dir / f"{stem}.json.xz"

        if not build_isf(vmlinux, out_xz):
            return None
        if install:
            install_isf(out_xz, "linux")
        return out_xz
    finally:
        shutil.rmtree(str(work), ignore_errors=True)
        if keep_ddeb is None:
            shutil.rmtree(str(ddeb_dir), ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════════
# RHEL / CentOS / Alma / Rocky / Fedora — build ISF from a debuginfo RPM
# ══════════════════════════════════════════════════════════════════════════════
# RHEL-family kernels ship debug symbols as `kernel-debuginfo` RPMs (containing an
# unstripped vmlinux with DWARF), NOT as Debian .ddebs. This is the RPM analogue
# of build_isf_from_dbgsym.

_RHEL_RPM_ARCH = {
    "amd64": "x86_64", "x64": "x86_64", "x86_64": "x86_64",
    "arm64": "aarch64", "aarch64": "aarch64",
    "ppc64le": "ppc64le", "s390x": "s390x",
}


def rhel_rpm_arch(arch: str) -> str:
    return _RHEL_RPM_ARCH.get((arch or "x86_64").lower(), "x86_64")


def _rhel_release(kernel_ver: str) -> Tuple[Optional[str], Optional[int]]:
    """'3.10.0-1062.el7.x86_64' -> ('el', 7);  '5.14...fc38' -> ('fc', 38)."""
    m = re.search(r'\.(el|fc)(\d+)', kernel_ver)
    return (m.group(1), int(m.group(2))) if m else (None, None)


def rhel_debuginfo_urls(kernel_ver: str, arch: str = "x86_64",
                        distro: str = "CentOS") -> List[str]:
    """Candidate public URLs for `kernel-debuginfo-<ver>.<arch>.rpm`.

    kernel_ver is the banner release, e.g. '3.10.0-1062.el7.x86_64' (arch may or
    may not be already appended). We try the mirrors that host debuginfo publicly:
    CentOS debuginfo mirror + vault, AlmaLinux, Rocky, Fedora (koji). RHEL proper
    requires a subscription, so a matching CentOS/Alma/Rocky RPM is used instead
    (same source build → same DWARF).
    """
    rpm_arch = rhel_rpm_arch(arch)
    kv = kernel_ver
    if not kv.endswith("." + rpm_arch):
        kv = f"{kv}.{rpm_arch}"
    fam, num = _rhel_release(kv)
    if not num:
        return []
    fname = f"kernel-debuginfo-{kv}.rpm"
    d = (distro or "").lower()
    if fam == "fc":  # Fedora (koji)
        ver, rel = kv.split("-", 1)
        return [f"https://kojipkgs.fedoraproject.org/packages/kernel/{ver}/"
                f"{rel.replace('.'+rpm_arch,'')}/{rpm_arch}/{fname}"]
    # EL family. The exact -debuginfo RPM is distro-specific (Alma's .el8_10,
    # Rocky's .el9_x, CentOS's tag all differ), so we try each vendor's own debug
    # mirror. debuginfo.centos.org (CentOS/RHEL/Stream) and download.rockylinux.org
    # are validated-reachable; Alma's layout shifts by version so it's best-effort.
    # download_resume walks the list until one 200s.
    centos = [f"http://debuginfo.centos.org/{num}/{rpm_arch}/{fname}",
              f"http://debuginfo.centos.org/altarch/{num}/{rpm_arch}/{fname}"]
    rocky = [f"https://download.rockylinux.org/pub/rocky/{num}/BaseOS/{rpm_arch}/debug/tree/Packages/k/{fname}",
             f"https://dl.rockylinux.org/vault/rocky/{num}/BaseOS/{rpm_arch}/debug/tree/Packages/k/{fname}"]
    alma = [f"https://repo.almalinux.org/almalinux/{num}/BaseOS/debug/{rpm_arch}/Packages/{fname}",
            f"https://repo.almalinux.org/almalinux/{num}/AppStream/debug/{rpm_arch}/Packages/{fname}"]
    if "rocky" in d:
        return rocky + centos + alma
    if "alma" in d:
        return alma + rocky + centos
    return centos + rocky + alma  # CentOS / RHEL / Stream / unknown EL


def extract_vmlinux_from_rpm(rpm: Path, workdir: Path) -> Optional[Path]:
    """Unpack a kernel-debuginfo .rpm (rpm2cpio | cpio) and return its vmlinux."""
    workdir.mkdir(parents=True, exist_ok=True)
    if not shutil.which("rpm2cpio"):
        msg_fail("rpm2cpio not found (install rpm) — cannot extract RPM.")
        return None
    try:
        p1 = subprocess.Popen(["rpm2cpio", str(rpm)], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL)
        subprocess.run(["cpio", "-idm", "--quiet"], stdin=p1.stdout,
                       cwd=str(workdir), stderr=subprocess.DEVNULL, timeout=600)
        p1.wait(timeout=600)
    except Exception as e:
        msg_fail(f"RPM extraction failed: {e}")
        return None
    hits = [h for h in workdir.rglob("vmlinux") if h.is_file()]
    if not hits:
        msg_fail("No vmlinux found inside the debuginfo RPM.")
        return None
    vmlinux = max(hits, key=lambda p: p.stat().st_size)
    msg_ok(f"Extracted {vmlinux.name} "
           f"({vmlinux.stat().st_size/1024/1024:.1f} MB) from RPM")
    return vmlinux


def build_isf_from_rhel_debuginfo(kernel_ver: str, arch: str = "x86_64",
                                  install: bool = False, distro: str = "CentOS",
                                  keep_rpm: Optional[Path] = None,
                                  dest_dir: Optional[Path] = None
                                  ) -> Optional[Path]:
    """Full RHEL pipeline: version -> debuginfo RPM -> vmlinux -> dwarf2json -> ISF.

    Returns the path to the built ISF, or None. Mirrors build_isf_from_dbgsym.
    """
    if not find_dwarf2json():
        msg_fail("dwarf2json is required but not found (PATH or _isf_build/).")
        return None
    rpm_arch = rhel_rpm_arch(arch)
    msg_info(f"Building ISF for {distro} {kernel_ver} ({rpm_arch}) from debuginfo RPM")
    urls = rhel_debuginfo_urls(kernel_ver, rpm_arch, distro)
    if not urls:
        msg_fail(f"Could not derive a debuginfo RPM URL for {kernel_ver} "
                 "(no .elN/.fcN release tag).")
        return None

    kv = kernel_ver if kernel_ver.endswith("." + rpm_arch) else f"{kernel_ver}.{rpm_arch}"
    filename = f"kernel-debuginfo-{kv}.rpm"
    rpm_dir = Path(keep_rpm) if keep_rpm else Path(tempfile.mkdtemp(
        prefix="crescent_rpm_"))
    rpm_dir.mkdir(parents=True, exist_ok=True)
    rpm = rpm_dir / filename

    exp = _expected_size(urls[0]) if urls else None
    if rpm.exists() and exp and rpm.stat().st_size >= exp:
        msg_ok(f"Reusing cached {rpm.name} ({rpm.stat().st_size/1024/1024:.1f} MB)")
    else:
        if not download_resume(urls, rpm):
            return None

    work = Path(tempfile.mkdtemp(prefix="crescent_rpm_vmlinux_"))
    try:
        vmlinux = extract_vmlinux_from_rpm(rpm, work)
        if not vmlinux:
            return None
        stem = f"{distro}_{kv}"
        out_dir = Path(dest_dir) if dest_dir else Path(tempfile.mkdtemp(
            prefix="crescent_isf_"))
        out_xz = out_dir / f"{stem}.json.xz"
        if not build_isf(vmlinux, out_xz):
            return None
        if install:
            install_isf(out_xz, "linux")
        return out_xz
    finally:
        shutil.rmtree(str(work), ignore_errors=True)
        if keep_rpm is None:
            shutil.rmtree(str(rpm_dir), ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def _main(argv=None) -> int:
    # Route scratch (the ~1 GB .ddeb + ~720 MB extracted vmlinux) to the big
    # Desktop workspace, not the small /tmp tmpfs — even when run standalone.
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from modules import workspace
        workspace.setup()
    except Exception:
        pass
    p = argparse.ArgumentParser(
        description="Build a Vol3 ISF from a kernel's official debug package "
                    "(Ubuntu/Debian). Dynamic on the kernel version.")
    p.add_argument("--kernel", required=True,
                   help="Kernel version, e.g. 5.15.0-41-generic")
    p.add_argument("--arch", default="amd64",
                   help="Arch (amd64/i386/arm64/... or x64/x86/arm64). Default amd64.")
    p.add_argument("--distro", default="Ubuntu",
                   help="Distro label for the ISF filename (default Ubuntu).")
    p.add_argument("--install", action="store_true",
                   help="Copy the built ISF into the Vol3 symbols directory.")
    p.add_argument("--keep-ddeb", metavar="DIR",
                   help="Cache/reuse the downloaded .ddeb in DIR.")
    p.add_argument("--out", metavar="DIR",
                   help="Directory to write the built ISF into.")
    args = p.parse_args(argv)

    isf = build_isf_from_dbgsym(
        args.kernel, arch=args.arch, install=args.install, distro=args.distro,
        keep_ddeb=Path(args.keep_ddeb) if args.keep_ddeb else None,
        dest_dir=Path(args.out) if args.out else None)
    if not isf:
        msg_fail("ISF build failed.")
        return 1
    msg_ok(f"ISF ready: {isf}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
