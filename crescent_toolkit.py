#!/usr/bin/env python3
"""
CresCent RAM Forensics Toolkit v6.0

Main entry point. Imports all modules and provides CLI + interactive menu.
v6.0: OS-specific module split with importlib.util dispatcher architecture.

Usage:
    python3 crescent_toolkit.py menu
    python3 crescent_toolkit.py full -i memory.raw
    python3 crescent_toolkit.py extract -i memory.raw -m fast -j 6

Author: CresCent
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

# Ensure toolkit directory is on path
TOOLKIT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLKIT_DIR))

from utils.ui import (
    VERSION, R, G, Y, B, P, C, W, N,
    banner, print_line, msg_info, msg_ok, msg_fail, msg_warn,
    progress_line, clear_screen, prompt, prompt_choice,
    find_memory_images, format_size, format_duration,
)
from modules.logger import CrescentLogger, Timer
from modules.volatility import VolatilityWrapper
from modules.extractor import Extractor, PLUGINS, VOL2_EXCLUSIVE, VALID_MODES
from modules.file_dumper import FileDumper
from modules.process_dumper import ProcessDumper
from modules.strings_extractor import StringsExtractor
from modules.correlator import Correlator
from modules.ioc_extractor import IOCExtractor
from modules.process_tree import ProcessTree
from modules.network_map import NetworkMap
from modules.registry_explorer import RegistryExplorer
from modules.html_report import HTMLReportGenerator
from modules.timeline import Timeline
from modules.evtx_parser import EVTXParser
from modules.export_pack import ExportPack
from modules.elk_export import ELKExporter
from modules.installer import VolatilityInstaller
from modules.browser_history import BrowserHistoryScanner
from modules.system_info import SystemInfo
from modules.comms_scanner import CommsScanner
from modules.cmd_analyzer import CommandAnalyzer, MitreMapper
from modules.scheduled_tasks import ScheduledTasksScanner
from modules.registry_altered import RegistryAlteredScanner
from modules.popular_files import PopularFilesScanner
from modules.string_hunt import StringHunter
from utils.json_converter import load_json_safe


def _build_parser():
    p = argparse.ArgumentParser(
        prog="crescent_toolkit.py",
        description=f"CresCent RAM Forensics Toolkit v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python3 crescent_toolkit.py menu\n"
               "  python3 crescent_toolkit.py full -i memory.raw -o ./results/\n"
               "  python3 crescent_toolkit.py extract -i memory.raw -m fast -j 8\n"
               "  python3 crescent_toolkit.py dump-files -i memory.raw --pattern evtx\n"
               "  python3 crescent_toolkit.py strings -i memory.raw --strings-mode both\n"
               "  python3 crescent_toolkit.py correlate -o ./results/\n"
               "  python3 crescent_toolkit.py eye -o ./results/\n")
    p.add_argument("command", nargs="?", default="menu",
                   choices=["menu", "extract", "dump-files", "dump-procs",
                            "dump-all",
                            "strings", "correlate", "iocs", "report",
                            "timeline", "evtx", "export", "elk", "core", "full",
                            "plugins", "ctf", "eye", "dfir",
                            "hunt"])
    p.add_argument("--image", "-i", help="Path to memory image")
    p.add_argument("--output", "-o", help="Output directory")
    p.add_argument("--mode", "-m", default="full", choices=list(VALID_MODES))
    p.add_argument("--vol2", action="store_true", help="Force Volatility 2")
    p.add_argument("--vol3", action="store_true", help="Force Volatility 3")
    p.add_argument("--profile", help="Vol2 profile (e.g. Win7SP1x64)")
    p.add_argument("--symbol-isf", dest="symbol_isf", metavar="PATH",
                   help="Use your OWN Volatility3 ISF (.json/.json.xz) for a "
                        "Linux/macOS image instead of auto-resolving")
    p.add_argument("--jobs", "-j", type=int, default=4, help="Parallel jobs (2-16)")
    p.add_argument("--speed", choices=["normal", "fast", "fastest"], default="normal",
                   help="Speed mode: normal (memory-safe, RAM guard on), fast (tighter RAM budget, more parallel jobs), fastest (max jobs, no RAM guard)")
    p.add_argument("--timeout", type=int, default=600, help="Plugin timeout (s)")
    p.add_argument("--log", help="Override log file path")
    p.add_argument("--quiet", "-q", action="store_true", help="Suppress console output")
    p.add_argument("--pattern", help="File dump pattern (e.g. evtx, exe)")
    p.add_argument("--files-first", dest="files_first", action="store_true",
                   help="dump-all/dfir: recover files BEFORE dumping process "
                        "memory (default: processes first). Useful when file "
                        "content is the priority and full process dumps are slow.")
    p.add_argument("--strings-mode", default="all",
                   choices=["all", "ascii", "unicode", "both"])
    p.add_argument("--hunt-strings", nargs="+", metavar="STRING",
                   help="hunt: one or more strings to search for in memory")
    p.add_argument("--hunt-pid", nargs="+", type=int, metavar="PID",
                   help="hunt: restrict scan to specific PID(s)")
    p.add_argument("--hunt-case-sensitive", action="store_true",
                   help="hunt: disable case-insensitive matching")
    p.add_argument("--hunt-no-wide", action="store_true",
                   help="hunt: skip wide (UTF-16LE) string matching")
    return p


def _read_os_type(od: Path) -> str:
    """Read OS type from SUMMARY.txt in the output directory."""
    summary = od / "SUMMARY.txt"
    if summary.is_file():
        for line in summary.read_text(encoding="utf-8").splitlines():
            if line.startswith("OS:"):
                return line.split(":", 1)[1].strip().lower()
    return "windows"


def _resolve_output(image, output):
    if output:
        return Path(output)
    if image:
        # Include the extension (without the dot) to avoid collisions when two
        # dumps share a stem (e.g. "3.vmem" and "3.vmsn" → "3_vmem" / "3_vmsn").
        p = Path(image)
        suffix = p.suffix.lstrip(".")
        name = f"{p.stem}_{suffix}" if suffix else p.stem
        return Path.home() / "Desktop" / name
    return Path("./crescent_output")


def _resolve_image_or_exit(image_arg: str, min_size: int = 4096) -> str:
    """Return a validated image path or exit with a clear CLI error."""
    image_path = Path(image_arg).expanduser().resolve()
    if not image_path.exists():
        msg_fail(f"Memory image does not exist: {image_path}")
        sys.exit(2)
    if not image_path.is_file():
        msg_fail(f"Memory image path is not a file: {image_path}")
        sys.exit(2)
    try:
        size = image_path.stat().st_size
    except OSError as exc:
        msg_fail(f"Cannot read memory image metadata: {exc}")
        sys.exit(2)
    if size < min_size:
        msg_fail(f"Memory image is too small to analyze ({size} bytes): {image_path}")
        sys.exit(2)
    return str(image_path)


def _init_vol(clog, image, args):
    vol = VolatilityWrapper(clog.get_logger("VOLATILITY"), timeout=args.timeout)
    if not vol.find_volatility():
        msg_fail("No Volatility installation found!")
        sys.exit(1)
    if args.profile:
        vol.profile = args.profile
    if args.vol2:
        vol.vol_version = "vol2"
        if not vol.vol2_cmd:
            msg_fail("--vol2 specified but Vol2 not found")
            sys.exit(1)
        if not vol.profile:
            vol._detect_profile_vol2(image)
        vol.os_type = "linux" if "linux" in (vol.profile or "").lower() else "windows"
    elif args.vol3:
        vol.vol_version = "vol3"
        if not vol.vol3_cmd:
            msg_fail("--vol3 specified but Vol3 not found")
            sys.exit(1)
        hint = getattr(args, "os_hint", "auto")
        if hint in ("windows", "linux", "mac"):
            vol.os_type = hint
            msg_info(f"OS provided by operator: {hint} (forced Vol3)")
        else:
            vol.auto_detect(image)
    else:
        hint = getattr(args, "os_hint", "auto")
        if hint in ("windows", "linux", "mac"):
            vol.detect_for_os(image, hint)
        else:
            vol.auto_detect(image)
    # If unknown OS, default to Windows
    if vol.os_type == "unknown":
        from utils.ui import msg_warn
        msg_warn("Could not detect OS — assuming Windows.")
        vol.os_type = "windows"
    return vol


def _init_vol_from_existing(clog, image, output_dir, args):
    """Initialize Volatility wrapper by reading existing extraction results.

    Reads SUMMARY.txt and/or json/windows_info*.json from a prior run to
    determine the Volatility version and profile WITHOUT re-probing the image.
    Falls back to full auto_detect only if no prior results exist.

    Args:
        clog: Logger service.
        image: Memory image path.
        output_dir: Output directory from prior extraction.
        args: Parsed CLI arguments.

    Returns:
        Configured VolatilityWrapper instance.
    """
    vol = VolatilityWrapper(clog.get_logger("VOLATILITY"), timeout=args.timeout)
    if not vol.find_volatility():
        msg_fail("No Volatility installation found!")
        sys.exit(1)

    if args.profile:
        vol.profile = args.profile

    # Try reading SUMMARY.txt from prior extraction
    summary_path = Path(output_dir) / "SUMMARY.txt"
    loaded_from_summary = False
    if summary_path.exists():
        try:
            content = summary_path.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("Volatility:"):
                    v = line.split(":", 1)[1].strip().lower()
                    if "vol2" in v:
                        vol.vol_version = "vol2"
                    elif "vol3" in v:
                        vol.vol_version = "vol3"
                elif line.startswith("Profile:"):
                    p = line.split(":", 1)[1].strip()
                    if p and p != "N/A" and not vol.profile:
                        vol.profile = p
                elif line.startswith("OS:"):
                    vol.os_type = line.split(":", 1)[1].strip().lower()
            if vol.vol_version:
                loaded_from_summary = True
                msg_ok(f"Using prior results: {vol.vol_version}"
                        + (f" [{vol.profile}]" if vol.profile else "")
                        + f" ({vol.os_type})")
        except Exception:
            pass

    # If no SUMMARY.txt, try reading profile from json/windows_info
    if not loaded_from_summary and not vol.profile:
        json_dir = Path(output_dir) / "json"
        if json_dir.is_dir():
            for f in json_dir.glob("*info*.json"):
                data = load_json_safe(f)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            var = str(item.get("Variable", item.get("variable", "")))
                            val = str(item.get("Value", item.get("value", "")))
                            if "NTBuildLab" in var or "NTMajorVersion" in var:
                                vol.os_type = "windows"
                                if not vol.vol_version:
                                    vol.vol_version = "vol3"
                                loaded_from_summary = True
                                msg_ok(f"Detected Windows from existing json/")
                                break
                if loaded_from_summary:
                    break

    # If forced via CLI, override
    if args.vol2:
        vol.vol_version = "vol2"
    elif args.vol3:
        vol.vol_version = "vol3"

    # If we still don't have version/profile, fall back to auto_detect
    if not vol.vol_version:
        msg_info("No prior results found, running auto-detection...")
        vol.auto_detect(image)
    else:
        # Make sure we have a profile for Vol2
        if vol.vol_version == "vol2" and not vol.profile and vol.vol2_cmd:
            msg_info("Detecting Vol2 profile...")
            vol._detect_profile_vol2(image)
        if not vol.os_type:
            vol.os_type = "windows"

    return vol


def _warn_no_symbols(os_label):
    """Prominently tell the operator that no matching ISF was found.

    Without a matching symbol table the Vol3 Linux/macOS plugins (pslist,
    netstat, lsof, ...) load but walk 0 objects, so they come back empty. We
    surface that here as a single, clear, actionable notice rather than letting
    the pipeline silently report an all-empty run as "success".
    """
    print_line()
    msg_fail(f"No matching Volatility 3 symbol table (ISF) for this {os_label} image.")
    msg_warn(f"{os_label} plugins (pslist, netstat, lsof, ...) will return EMPTY "
             "results until the correct ISF is installed.")
    msg_info("To fix, install the matching kernel symbols and re-run:")
    msg_info("  • Settings → 'Download Linux/Mac symbol tables', or pick the exact "
             "build from the symbol-table catalogue, then re-run.")
    msg_info("  • Or build the ISF from the kernel debug symbols with dwarf2json "
             "(see the manual-build steps printed above).")
    print_line()


def _resolve_linux_symbols(vol, image, od, args):
    """Resolve Vol3 Linux/macOS symbols for a known Linux/mac image.

    If the operator picked a specific symbol table from the repo catalogue
    (args.symbol_isf), install that first; then run the normal auto-resolver
    (which verifies / fills any gap). For Vol2 there is nothing to download —
    just report the profile.

    Returns True when usable symbols are in place (or Vol2 is being used), and
    False when no matching ISF could be found for this Linux/macOS image — in
    which case the operator is warned that the Vol3 plugins will be empty.
    """
    os_label = "macOS" if vol.os_type == "mac" else "Linux"
    if vol.vol_version != "vol3":
        msg_info(f"{os_label} image — using Volatility 2 (profile: {vol.profile})")
        return True
    chosen = getattr(args, "symbol_isf", None)
    if chosen:
        from modules import linux_identify
        # A local file (the operator's own / an already-installed ISF) is copied
        # into the store; a repo-relative catalogue path is downloaded.
        is_local = Path(str(chosen)).expanduser().is_file()
        msg_info(f"Installing operator-selected {'local ' if is_local else ''}"
                 f"symbol table: {Path(chosen).name}")
        installed = (linux_identify.install_local_isf(chosen, vol.os_type)
                     if is_local
                     else linux_identify.install_symbol_by_path(chosen, vol.os_type))
        if installed:
            # Operator provided the symbol table explicitly — trust it and skip
            # the auto-resolver (no image re-scan, no re-download). Still record
            # the kernel version (derived from the ISF name, free) so the HTML
            # report and system_info have it.
            kver = linux_identify.kernel_version_from_isf(chosen)
            try:
                jd = Path(od) / "json"
                jd.mkdir(parents=True, exist_ok=True)
                (jd / "linux_kernel.json").write_text(json.dumps({
                    "kernel_version": kver, "banner": "",
                    "os_type": vol.os_type, "arch": "",
                    "source": "operator-selected ISF",
                    "isf": Path(chosen).name}, indent=2), encoding="utf-8")
            except Exception:
                pass
            msg_ok(f"Symbol table installed (kernel {kver or 'unknown'}) "
                   "— skipping auto symbol resolution")
            return True
        msg_warn("Could not install selected symbol table — falling back to auto")
    from modules.linux_resolver import resolve_symbols
    msg_info(f"{os_label} image detected — resolving Vol3 symbols...")
    ok = bool(resolve_symbols(image, vol.os_type, output_dir=od))
    if not ok:
        _warn_no_symbols(os_label)
    return ok


# -- Command implementations --

def _cmd_dump_all(args):
    """DUMP-EVERYTHING mode: dump every process as its native executable
    (PE on Windows, ELF on Linux, Mach-O on macOS) AND every recoverable file.

    If no prior extraction JSON exists, a full extraction is run first (which
    auto-resolves Linux/mac symbols, building the ISF from the official debug
    package when needed). Cross-OS.
    """
    if not args.image:
        msg_fail("--image (-i) required"); sys.exit(1)
    image = _resolve_image_or_exit(args.image)
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    clog.log_session_info(image, str(od), mode="dump-all")

    # 1. Ensure extraction produced actual PROCESS data (pslist/psscan/pstree),
    #    not just a json/ dir (the symbol-resolver writes linux_kernel.json there
    #    without running any plugins). If process data is missing, extract first.
    jd = od / "json"
    has_proc_data = jd.is_dir() and any(
        list(jd.glob(f"*{p}*")) for p in ("pslist", "psscan", "pstree"))
    if not has_proc_data:
        msg_info("No prior process extraction found — running extraction first "
                 "(needed for the process/file lists)...")
        vol = _init_vol(clog, image, args)
        if vol.os_type in ("linux", "mac"):
            _resolve_linux_symbols(vol, image, od, args)
        ext = Extractor(vol, clog.get_logger("EXTRACTOR"), args.jobs,
                        getattr(args, "speed", "normal"))
        ext.run(image, od, args.mode or "full")
    else:
        vol = _init_vol_from_existing(clog, image, od, args)
        # Linux/mac process & file dump plugins still need working symbols.
        if vol.os_type in ("linux", "mac"):
            _resolve_linux_symbols(vol, image, od, args)

    print_line()
    msg_ok(f"DUMP-ALL  Image: {Path(image).name}  Engine: {vol.vol_version}"
           + (f" [{vol.profile}]" if vol.profile else ""))
    print_line()

    dd = od / "dumped_all"
    fmt = {"windows": "PE", "linux": "ELF", "mac": "Mach-O"}.get(vol.os_type, "exe")
    proc_dir = dd / "processes"
    file_dir = dd / "files"

    def _dump_procs_phase():
        # Dump EVERY process as its native executable.
        try:
            pd = ProcessDumper(vol, clog.get_logger("PROCDUMPER"), args.jobs)
            pd.load_processes(od)
            if pd.processes:
                msg_info(f"Dumping ALL {len(pd.processes)} processes as {fmt} "
                         "executables (one Volatility pass per PID — may take a while)...")
                with Timer() as t:
                    pres = pd.dump_all_processes(image, proc_dir)
                msg_ok(f"Processes: dumped {pres['dumped']}/{pres['total']} → "
                       f"{proc_dir / 'process_exe'}  ({format_duration(t.elapsed)})")
            else:
                msg_warn("No processes loaded — skipping process dump "
                         "(ISF/profile may be missing or incorrect).")
        except Exception as e:
            msg_warn(f"Process dump error: {e}")

    def _dump_files_phase():
        # Dump EVERY recoverable file.
        file_dir.mkdir(parents=True, exist_ok=True)
        n_files = 0
        try:
            fd = FileDumper(vol, clog.get_logger("FILEDUMPER"), args.jobs)
            if vol.os_type == "windows":
                fj = fd.find_filescan_json(od)
                if fj:
                    fd.parse_filescan(fj)
                    msg_info(f"Dumping ALL {fd.file_count} files from filescan "
                             "(this can be large/slow)...")
                    res = fd.dump_all(image, file_dir)
                    n_files = res.get("dumped_files", 0)
                else:
                    msg_warn("No filescan.json — run full extraction to enable file dump.")
            elif vol.os_type == "linux":
                n = fd.load_linux_files_from_json(od)
                if not n:
                    n = fd.parse_linux_files(image)
                msg_info("Dumping ALL Linux files (page cache / RecoverFs)...")
                n_files = fd.dump_linux(image, file_dir)
            elif vol.os_type == "mac":
                msg_info("macOS — writing file inventory, then recovering cached "
                         "content (mac.pagecache)...")
                fd.dump_mac(image, file_dir)              # inventory → mac_file_list.json
                n_files = fd.dump_mac_content(image, file_dir)  # reconstruct cached content
        except Exception as e:
            msg_warn(f"File dump error: {e}")
        msg_ok(f"Files: {n_files} → {file_dir}")

    # Ordering: processes-first by default. --files-first recovers the (usually
    # smaller/faster) filescan/page-cache files BEFORE the heavy per-process
    # memory dumps — useful when file content is the priority and the full
    # process-memory dump would otherwise run for a long time first.
    if getattr(args, "files_first", False):
        msg_info("Order: FILES first, then processes  (--files-first)")
        _dump_files_phase()
        _dump_procs_phase()
    else:
        _dump_procs_phase()
        _dump_files_phase()

    print_line()
    msg_ok(f"DUMP-ALL complete → {dd}")
    print_line()


def _cmd_extract(args):
    if not args.image:
        msg_fail("--image (-i) required"); sys.exit(1)
    image = _resolve_image_or_exit(args.image)
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    clog.log_session_info(image, str(od), mode=args.mode)
    vol = _init_vol(clog, image, args)
    # Linux/macOS: resolve Vol3 symbols if needed (skip when already using Vol2)
    syms_ok = True
    if vol.os_type in ("linux", "mac"):
        syms_ok = _resolve_linux_symbols(vol, image, od, args)
    ext = Extractor(vol, clog.get_logger("EXTRACTOR"), args.jobs, getattr(args, "speed", "normal"))
    print_line()
    msg_ok(f"Image: {Path(image).name}  Mode: {args.mode}  Engine: {vol.vol_version}")
    print_line()
    with Timer() as t:
        res = ext.run(image, od, args.mode)
    ext.write_summary(od, image, args.mode, res)
    print_line()
    msg_ok(f"Done in {format_duration(t.elapsed)} -- JSON: {res['json_count']}  TXT: {res['txt_count']}")
    msg_info(f"OK: {res['ok']}  Failed: {res['fail']}  Skipped: {res['skipped']}")
    if not syms_ok:
        msg_warn("Reminder: no matching symbol table was found — empty Linux/macOS "
                 "results above are expected. Install the correct ISF and re-run.")
    print_line()
    # Only fail if there were real failures AND nothing was skipped (resumed).
    # A resumed run where all prior results are reused has ok=0, skipped>0 — that is fine.
    if res["ok"] == 0 and res["fail"] > 0 and res["skipped"] == 0:
        msg_fail("Extraction produced no successful plugin output.")
        sys.exit(2)


def _linux_filedump_menu(fd, image: str, dump_dir):
    """Interactive file dump menu for Linux pagecache listings."""
    dump_dir = Path(dump_dir)
    while True:
        print()
        print_line()
        print()
        src = fd.linux_files_source or "unknown"
        src_note = ("(page cache — content dumpable)"
                    if src == "pagecache" else
                    "(open file descriptors — content dump may fail if not in page cache)")
        print(f"   {W}LINUX FILE DUMPER{N} -- {fd.linux_file_count} files from {src} {src_note}")
        print(f"   Image:  {C}{Path(image).name}{N}")
        print(f"   Output: {C}{dump_dir}{N}")
        print()
        print(f"   {W}[1]{N} Search by filename / path")
        print(f"   {W}[2]{N} Dump by extension        (e.g. py, sh, conf, log)")
        print(f"   {W}[3]{N} Show top extensions")
        print(f"   {W}[4]{N} Dump ALL (bulk RecoverFs — creates .tar.gz tarball)")
        print(f"   {W}[5]{N} Change dump directory")
        print(f"   {W}[6]{N} List all files")
        print(f"   {W}[Q]{N} Back to menu")
        print()
        choice = prompt("Select").strip()
        if choice.upper() == "Q":
            return
        elif choice == "6":
            show_limit = 50
            print(f"\n   All {fd.linux_file_count} file(s):\n")
            for i, f in enumerate(fd._linux_files[:show_limit], 1):
                print(f"   [{i:4d}] {f['path']}  (inode: {f['inode']})")
            if fd.linux_file_count > show_limit:
                print(f"   ... and {fd.linux_file_count - show_limit} more")
        elif choice == "1":
            pat = prompt("Search pattern").strip()
            if not pat:
                continue
            matches = fd.search_linux_files(pat)
            if not matches:
                msg_warn(f"No files matching '{pat}'")
                continue
            print(f"\n   Found {len(matches)} file(s):\n")
            for i, f in enumerate(matches[:50], 1):
                print(f"   [{i:3d}] {f['path']}  (inode: {f['inode']})")
            if len(matches) > 50:
                print(f"   ... and {len(matches) - 50} more")
            sel = prompt("Dump which? (number, range 1-5, list 1,3,5, A=all, Q=cancel)").strip()
            if sel.upper() == "Q":
                continue
            if sel.upper() == "A":
                res = fd.dump_linux_by_pattern(image, pat, dump_dir)
            else:
                try:
                    indices = parse_selection(sel, len(matches))
                    to_dump = [matches[i] for i in indices]
                    for fe in to_dump:
                        msg_info(f"Dumping: {fe['path']}")
                        fd.dump_linux_file_by_inode(image, fe, dump_dir, verbose=True)
                    res = {"dumped_files": len(to_dump)}
                except Exception:
                    msg_warn("Invalid selection"); continue
            print()
            msg_ok(f"Done — files written to {dump_dir}")
        elif choice == "2":
            ext = prompt("Extension (without dot)").strip().lstrip(".")
            if not ext:
                continue
            res = fd.dump_linux_by_extension(image, ext, dump_dir)
            print()
            msg_ok(f"Dumped {res['dumped_files']} files to {dump_dir}")
        elif choice == "3":
            exts = fd.list_linux_extensions()
            print("\n   Top extensions in page cache:\n")
            for ext, cnt in list(exts.items())[:20]:
                print(f"   {ext:20s} {cnt}")
        elif choice == "4":
            msg_info("Running linux.pagecache.RecoverFs (creates .tar.gz in output dir — may take minutes)...")
            n = fd.dump_linux(image, dump_dir)
            msg_ok(f"Created {n} tarball(s) in {dump_dir}") if n else msg_warn("No files recovered — page cache may be empty for this image")
        elif choice == "5":
            nd = prompt("New dump directory").strip()
            if nd:
                dump_dir = Path(nd)
                dump_dir.mkdir(parents=True, exist_ok=True)


def _mac_filedump_menu(fd, image: str, dump_dir):
    """Interactive macOS file dumper — recovers cached file CONTENT from the
    page cache via mac.pagecache (not just the listing)."""
    dump_dir = Path(dump_dir)
    while True:
        print()
        print_line()
        print()
        print(f"   {W}MACOS FILE DUMPER{N} -- {fd.file_count} files listed "
              "(page-cache content recovery)")
        print(f"   Image:  {C}{Path(image).name}{N}")
        print(f"   Output: {C}{dump_dir}{N}")
        print()
        print(f"   {W}[1]{N} Search by name/path, then recover matches (content)")
        print(f"   {W}[2]{N} Recover ALL cached file content  (mac.pagecache --dump)")
        print(f"   {W}[3]{N} List files")
        print(f"   {W}[4]{N} Change dump directory")
        print(f"   {W}[Q]{N} Back to menu")
        print(f"   {P}Note: only files with pages resident in RAM can be recovered.{N}")
        print()
        choice = prompt("Select").strip()
        if choice.upper() == "Q":
            return
        elif choice == "1":
            pat = prompt("Search pattern (name or path substring)").strip()
            if not pat:
                continue
            matches = fd.search_files(pat)
            if not matches:
                msg_warn(f"No files matching '{pat}'")
                continue
            print(f"\n   Found {len(matches)} file(s):\n")
            for i, f in enumerate(matches[:50], 1):
                print(f"   [{i:3d}] {f.get('path') or f.get('filename')}")
            if len(matches) > 50:
                print(f"   ... and {len(matches) - 50} more")
            sel = prompt("Recover which? (number, range 1-5, list 1,3,5, "
                         "A=all matches, Q=cancel)").strip()
            if sel.upper() == "Q":
                continue
            if sel.upper() == "A":
                to_dump = matches
            else:
                try:
                    indices = parse_selection(sel, len(matches))
                    to_dump = [matches[i] for i in indices]
                except Exception:
                    msg_warn("Invalid selection"); continue
            if not to_dump:
                continue
            res = fd.dump_file_list(image, to_dump, dump_dir)
            (msg_ok if res["dumped_files"] else msg_warn)(
                f"Recovered {res['dumped_files']} file(s) → {dump_dir}")
        elif choice == "2":
            confirm = prompt(f"Recover content for ALL cached files? This scans the "
                             f"whole image and may take a while (y/N)", "n")
            if confirm.lower() == "y":
                n = fd.dump_mac_content(image, dump_dir)
                (msg_ok if n else msg_warn)(
                    f"Recovered {n} file(s) with cached content → {dump_dir}")
            else:
                msg_info("Cancelled")
        elif choice == "3":
            show = fd._mac_files[:50]
            print(f"\n   First {len(show)} of {fd.file_count} file(s):\n")
            for i, f in enumerate(show, 1):
                print(f"   [{i:3d}] {f.get('path') or f.get('filename')}")
        elif choice == "4":
            nd = prompt("New dump directory").strip()
            if nd:
                dump_dir = Path(nd)
                dump_dir.mkdir(parents=True, exist_ok=True)


def _find_prior_output(args):
    """Locate a prior analysis output dir (with json/) for this image.

    Tries the default resolved path first; if that has no json/ (e.g. the image
    lives off the Desktop, or the results were saved somewhere other than the
    default ~/Desktop/<name>), it SEARCHES likely locations by the image's name
    and asks the operator to confirm — instead of erroring. Returns a confirmed
    Path, or None if nothing usable was found/confirmed.
    """
    od = _resolve_output(args.image, args.output)
    if (od / "json").is_dir():
        return od
    # An explicit --output was given but has no json/ — trust it, don't guess.
    if args.output:
        return None
    p = Path(str(args.image))
    stem = p.stem
    name = f"{stem}_{p.suffix.lstrip('.')}" if p.suffix else stem
    home = Path.home()
    try:
        from modules import workspace
        results_base = getattr(workspace, "RESULTS_BASE", None)
    except Exception:
        results_base = None
    cands = []
    for base in (home / "Desktop", results_base, Path.cwd(), p.parent):
        if not base:
            continue
        cands += [base / name, base / stem, base / p.name]
        try:
            if base.is_dir():
                cands += [d for d in sorted(base.glob(f"*{stem}*")) if d.is_dir()]
        except OSError:
            pass
    seen = set()
    for c in cands:
        c = Path(c)
        if str(c) in seen:
            continue
        seen.add(str(c))
        if (c / "json").is_dir():
            ans = prompt(f"No results at the default path. Found a prior analysis "
                         f"for '{p.name}' at:\n      {C}{c}{N}\n   Use it? (Y/n)", "y")
            if ans.strip().lower() not in ("n", "no"):
                msg_ok(f"Using output: {c}")
                return c
    return None


def _cmd_dump_files(args):
    """Interactive file dumper with search, browse, and single-file dump."""
    if not args.image:
        msg_fail("--image (-i) required"); sys.exit(1)
    image = _resolve_image_or_exit(args.image)
    # Locate the prior analysis output (search by image name + confirm if the
    # default path has nothing) instead of hard-erroring.
    od = _find_prior_output(args)
    if od is None:
        msg_fail("No prior analysis output (json/) found for this image.")
        msg_info("Run extraction first (option [1] or [D]) to generate filescan data,")
        msg_info("or set the exact output directory in Settings [2].")
        return

    clog = CrescentLogger(str(od), args.quiet, args.log)

    # Use existing results -- don't re-probe the image
    vol = _init_vol_from_existing(clog, image, od, args)

    fd = FileDumper(vol, clog.get_logger("FILEDUMPER"), args.jobs)

    # Linux: load file list from pre-extracted JSON first (instant, no Vol3 needed),
    # then fall back to live pagecache.Files run, then bulk RecoverFs.
    if vol.os_type == "linux":
        dump_dir = od / "dumped_files"
        msg_info("Linux image — loading file list from existing JSON...")
        n = fd.load_linux_files_from_json(od)
        if n > 0:
            msg_ok(f"Loaded {n} files from JSON — interactive mode available")
            _linux_filedump_menu(fd, image, dump_dir)
        else:
            msg_info("No JSON file list found — running linux.pagecache.Files (may take a few minutes)...")
            n = fd.parse_linux_files(image)
            if n > 0:
                msg_ok(f"Listed {n} files in page cache — interactive mode available")
                _linux_filedump_menu(fd, image, dump_dir)
            else:
                msg_warn("pagecache.Files listing failed — falling back to bulk RecoverFs")
                n = fd.dump_linux(image, dump_dir)
                if n:
                    msg_ok(f"Recovered {n} files to {dump_dir}")
            if not n:
                msg_warn("No files recovered. Ensure correct Linux ISF symbols are installed.")
        return
    if vol.os_type == "mac":
        dump_dir = od / "dumped_files"
        msg_info("macOS image — listing files (mac.list_files)...")
        n = fd.dump_mac(image, dump_dir)
        msg_ok(f"Listed {n} file entries in {dump_dir}/mac_file_list.json")
        # One-shot: --pattern recovers matching page-cache content and returns.
        if args.pattern:
            msg_info(f"Recovering cached content for '{args.pattern}' (mac.pagecache)...")
            rec = fd.dump_mac_content(image, dump_dir, name_filter=args.pattern)
            (msg_ok if rec else msg_warn)(
                f"Recovered {rec} file(s) with cached content → {dump_dir}")
            return
        _mac_filedump_menu(fd, image, dump_dir)
        return

    fj = fd.find_filescan_json(od)
    if not fj:
        msg_fail("No filescan.json found in " + str(od / "json"))
        msg_info("Run extraction (full mode) first to generate filescan data.")
        return
    fd.parse_filescan(fj)
    if fd.file_count == 0:
        msg_fail("Filescan parsed 0 files. The JSON may be empty or unrecognized format.")
        # Show first record for debugging
        data = load_json_safe(fj)
        if data and isinstance(data, list) and isinstance(data[0], dict):
            msg_info(f"First record keys: {list(data[0].keys())}")
            msg_info(f"First record: {str(data[0])[:200]}")
        return
    msg_ok(f"Loaded {fd.file_count} files from filescan")

    # Dump directory -- prompt with sensible default
    default_dd = od / "dumped_files"

    # If called from CLI with --pattern, do one-shot and return
    if args.pattern:
        dd = default_dd
        dd.mkdir(parents=True, exist_ok=True)
        pat = args.pattern.lstrip("*.")
        if pat and not any(c in pat for c in " /\\"):
            res = fd.dump_by_extension(image, pat, dd)
        else:
            res = fd.dump_by_pattern(image, args.pattern, dd)
        print_line()
        msg_ok(f"Dumped {res['dumped_files']} files to {dd}")
        return

    # === Interactive file dumper loop ===
    dd = default_dd
    while True:
        print()
        print_line()
        print()
        print(f"   {W}FILE DUMPER{N} -- {fd.file_count} files in filescan")
        print(f"   Image:  {C}{Path(image).name}{N}")
        print(f"   Using:  {C}{vol.vol_version}{N}"
              + (f" [{vol.profile}]" if vol.profile else ""))
        print(f"   Output: {C}{dd}{N}")
        print()
        print(f"   {W}[1]{N} Search by filename     (e.g. 'security', 'demon', '.evtx')")
        print(f"   {W}[2]{N} Dump by extension      (e.g. evtx, exe, dll, txt)")
        print(f"   {W}[3]{N} Show top extensions")
        print(f"   {W}[4]{N} Dump ALL files")
        print(f"   {W}[5]{N} Change dump directory")
        print(f"   {W}[6]{N} List all files")
        print(f"   {W}[Q]{N} Back to menu")
        print()

        choice = prompt("Select").strip()

        if choice.upper() == "Q":
            return

        elif choice == "6":
            show_limit = 50
            print(f"\n   All {fd.file_count} file(s):\n")
            for i, f in enumerate(fd._files[:show_limit], 1):
                print(f"   [{i:4d}] {f['path']}")
            if fd.file_count > show_limit:
                print(f"   ... and {fd.file_count - show_limit} more")

        elif choice == "1":
            _filedump_search_loop(fd, image, dd)

        elif choice == "2":
            _filedump_extension_loop(fd, image, dd)

        elif choice == "3":
            exts = fd.list_extensions()
            print()
            if exts:
                msg_info(f"Top extensions ({len(exts)} total):")
                print()
                print(f"      {'Extension':20s} {'Count':>6s}")
                print(f"      {'-' * 20} {'-' * 6}")
                for ext, count in list(exts.items())[:25]:
                    print(f"      {ext:20s} {count:>6d}")
            else:
                msg_warn("No extensions found")
            print()
            try:
                input("   Press Enter to continue...")
            except (EOFError, KeyboardInterrupt):
                pass

        elif choice == "4":
            confirm = prompt(f"Dump ALL {fd.file_count} files? This may take a while (y/N)", "n")
            if confirm.lower() == "y":
                res = fd.dump_all(image, dd)
                msg_ok(f"Dumped {res['dumped_files']} files to {dd}")
            else:
                msg_info("Cancelled")

        elif choice == "5":
            new_dd = prompt("Dump directory", str(dd))
            dd = Path(new_dd)
            dd.mkdir(parents=True, exist_ok=True)
            msg_ok(f"Dump directory set: {dd}")

        else:
            msg_warn("Invalid choice")


def _filedump_search_loop(fd: FileDumper, image: str, dump_dir: Path):
    """Interactive search-and-dump loop. Stays until user types 'q'."""
    print()
    print(f"   {W}FILE SEARCH{N}")
    print(f"   Type a filename, part of a name, or extension to search.")
    print(f"   Type {W}q{N} to go back.")
    print()

    while True:
        query = prompt("Search").strip()
        if not query:
            continue
        if query.lower() == "q":
            return

        matches = fd.search_files(query)
        if not matches:
            msg_warn(f"No files matching '{query}' -- try a different term")
            continue

        # Show results (paginated if many)
        print()
        msg_ok(f"Found {len(matches)} file(s) matching '{query}':")
        print()
        show_limit = 40
        for i, f in enumerate(matches[:show_limit], 1):
            print(f"   {W}[{i:3d}]{N} {f['filename']}")
            print(f"         {C}{f['path']}{N}")
            print(f"         Offset: {f['offset']}")
        if len(matches) > show_limit:
            print(f"   {Y}... and {len(matches) - show_limit} more.{N}")
            print(f"   {Y}Narrow your search for better results.{N}")
        print()

        # Sub-prompt: pick specific files, dump all matches, or search again
        while True:
            print(f"   {W}[number]{N} Dump specific file    "
                  f"{W}[A]{N} Dump all {len(matches)}    "
                  f"{W}[S]{N} New search    "
                  f"{W}[Q]{N} Back")
            sel = prompt("Select").strip()

            if sel.upper() == "Q":
                return
            elif sel.upper() == "S":
                print()
                break  # Back to search prompt
            elif sel.upper() == "A":
                msg_info(f"Dumping all {len(matches)} matching files...")
                res = fd.dump_file_list(image, matches, dump_dir)
                msg_ok(f"Dumped {res['dumped_files']} files to {dump_dir}")
                break
            else:
                # Try to parse as number or comma-separated numbers
                try:
                    indices = parse_selection(sel, len(matches))
                    if indices:
                        selected = [matches[i] for i in indices]
                        for f in selected:
                            print()
                            print_line()
                            msg_info(f"File: {f['filename']}")
                            msg_info(f"Path: {f['path']}")
                            msg_info(f"Offset: {f['offset']}")
                            print()
                            ok = fd.dump_single_file(image, f, dump_dir)
                            print()
                            if ok:
                                msg_ok(f"{f['filename']} -- DONE")
                            else:
                                msg_fail(f"{f['filename']} -- all dump methods failed")
                                msg_info(f"Check log: {fd.log.handlers[0].baseFilename if fd.log.handlers else 'crescent_toolkit.log'}")
                            print_line()
                        continue  # Stay in this sub-menu to dump more
                    else:
                        msg_warn("Invalid selection. Enter a number, range (1-5), or comma list (1,3,7)")
                except Exception:
                    msg_warn("Invalid selection")


def _filedump_extension_loop(fd: FileDumper, image: str, dump_dir: Path):
    """Interactive extension-based dump loop. Stays until user types 'q'."""
    print()
    print(f"   {W}DUMP BY EXTENSION{N}")
    print(f"   Type an extension (without dot): evtx, exe, dll, pdf, txt, etc.")
    print(f"   Type {W}q{N} to go back.")
    print()

    while True:
        ext = prompt("Extension").strip().lstrip(".")
        if not ext:
            continue
        if ext.lower() == "q":
            return

        # Preview what we'll find
        ext_l = ext.lower()
        matches = [f for f in fd._files if f["filename"].lower().endswith(f".{ext_l}")]
        if not matches:
            msg_warn(f"No .{ext} files found in filescan. Try another extension.")
            # Show similar extensions as hints
            exts = fd.list_extensions()
            similar = [e for e in exts if ext_l[:3] in e.lower()]
            if similar:
                msg_info(f"Did you mean: {', '.join(similar[:5])}?")
            continue

        msg_ok(f"Found {len(matches)} .{ext} file(s):")
        print()
        for i, f in enumerate(matches[:20], 1):
            print(f"   {W}[{i:3d}]{N} {f['filename']}")
            print(f"         {C}{f['path']}{N}")
        if len(matches) > 20:
            print(f"   {Y}... and {len(matches) - 20} more{N}")
        print()

        confirm = prompt(f"Dump all {len(matches)} .{ext} files? (Y/n)", "y")
        if confirm.lower() != "n":
            res = fd.dump_by_extension(image, ext, dump_dir)
            msg_ok(f"Dumped {res['dumped_files']} files to {dump_dir}")
        else:
            msg_info("Cancelled -- pick specific files with option [1] instead")


def parse_selection(sel_str: str, max_val: int) -> List[int]:
    """Parse a user selection string into zero-based indices.

    Supports: single number '3', comma list '1,3,7', range '2-5',
    or mixed '1,3-5,8'.

    Args:
        sel_str: User input string.
        max_val: Maximum 1-based index allowed.

    Returns:
        List of valid zero-based indices, or empty list on failure.
    """
    indices: List[int] = []
    parts = sel_str.replace(" ", "").split(",")
    for part in parts:
        if "-" in part and not part.startswith("-"):
            # Range like 2-5
            try:
                a, b = part.split("-", 1)
                start, end = int(a), int(b)
                if 1 <= start <= end <= max_val:
                    indices.extend(range(start - 1, end))
            except ValueError:
                continue
        else:
            # Single number
            try:
                n = int(part)
                if 1 <= n <= max_val:
                    indices.append(n - 1)
            except ValueError:
                continue
    # Deduplicate while preserving order
    seen: set = set()
    result: List[int] = []
    for i in indices:
        if i not in seen:
            seen.add(i)
            result.append(i)
    return result


def _cmd_dump_procs(args):
    """Interactive process dumper with search, browse, and specific-process dump."""
    if not args.image:
        msg_fail("--image (-i) required"); sys.exit(1)
    image = _resolve_image_or_exit(args.image)
    # Locate the prior analysis output (search by image name + confirm if the
    # default path has nothing) instead of hard-erroring.
    od = _find_prior_output(args)
    if od is None:
        msg_fail("No prior analysis output (json/) found for this image.")
        msg_info("Run extraction first (option [1] or [D]),")
        msg_info("or set the exact output directory in Settings [2].")
        return

    clog = CrescentLogger(str(od), args.quiet, args.log)
    vol = _init_vol_from_existing(clog, image, od, args)
    pd = ProcessDumper(vol, clog.get_logger("PROCDUMPER"), args.jobs)
    pd.load_processes(od)
    if not pd.processes:
        msg_fail("No process data. Run extraction first.")
        return

    suspicious = pd.detect_suspicious()
    dd = od / "dumped_processes"

    # === Interactive process dumper loop ===
    while True:
        print()
        print_line()
        print()
        print(f"   {W}PROCESS DUMPER{N} -- {len(pd.processes)} processes loaded")
        print(f"   Image:  {C}{Path(image).name}{N}")
        print(f"   Using:  {C}{vol.vol_version}{N}"
              + (f" [{vol.profile}]" if vol.profile else ""))
        print(f"   Output: {C}{dd}{N}")
        print(f"   Flagged: {Y}{len(suspicious)}{N} suspicious")
        print()
        print(f"   {W}[1]{N} List all processes")
        print(f"   {W}[2]{N} Search by name/PID        (e.g. 'svchost', 'cmd', '1234')")
        print(f"   {W}[3]{N} Show suspicious only       ({len(suspicious)} flagged)")
        print(f"   {W}[4]{N} Dump all suspicious")
        print(f"   {W}[5]{N} Change dump directory")
        print(f"   {W}[Q]{N} Back to menu")
        print()

        choice = prompt("Select").strip()

        if choice.upper() == "Q":
            pd.write_suspicious_report(od, suspicious)
            return

        elif choice == "1":
            _procdump_list_all(pd, image, dd)

        elif choice == "2":
            _procdump_search_loop(pd, image, dd)

        elif choice == "3":
            _procdump_show_suspicious(pd, suspicious, image, dd)

        elif choice == "4":
            if not suspicious:
                msg_info("No suspicious processes flagged.")
                continue
            confirm = prompt(f"Dump all {len(suspicious)} flagged processes? (Y/n)", "y")
            if confirm.lower() != "n":
                msg_info(f"Dumping {len(suspicious)} processes...")
                res = pd.dump_suspicious(image, dd)
                msg_ok(f"Dumped {res['dumped']}/{res['total']} processes to {dd}")
                pd.write_suspicious_report(od, suspicious)
            else:
                msg_info("Cancelled")

        elif choice == "5":
            new_dd = prompt("Dump directory", str(dd))
            dd = Path(new_dd)
            dd.mkdir(parents=True, exist_ok=True)
            msg_ok(f"Dump directory: {dd}")

        else:
            msg_warn("Invalid choice")


def _procdump_display_proc(proc: Dict, idx: int = 0, show_flags: bool = True):
    """Display a single process entry with details."""
    flags_str = ""
    if show_flags and proc.get("flags"):
        flags_str = f" {Y}[FLAGGED]{N}"
    hidden = " [HIDDEN]" if "Hidden" in str(proc.get("flags", "")) else ""

    prefix = f"   {W}[{idx:3d}]{N} " if idx else "   "
    print(f"{prefix}PID: {W}{proc['pid']:>6s}{N}  "
          f"Name: {C}{proc['name']}{N}{flags_str}{hidden}")
    print(f"         PPID: {proc['ppid']}  "
          f"Threads: {proc.get('threads', '?')}  "
          f"Offset: {proc.get('offset', '?')}")
    if proc.get("cmdline"):
        cmd = proc["cmdline"]
        if len(cmd) > 100:
            cmd = cmd[:100] + "..."
        print(f"         CMD: {cmd}")
    if show_flags and proc.get("flags"):
        for flag in proc["flags"]:
            print(f"         {Y}-> {flag}{N}")


def _procdump_list_all(pd: ProcessDumper, image: str, dump_dir: Path):
    """Show all processes with details, then allow selection."""
    procs = pd.processes
    print()
    print_line()
    print(f"   {W}ALL PROCESSES{N} ({len(procs)} total)")
    print(f"   Sorted by PID")
    print_line()
    print()

    # Sort by PID numerically
    sorted_procs = sorted(procs, key=lambda p: int(p["pid"]) if p["pid"].isdigit() else 0)

    for i, p in enumerate(sorted_procs, 1):
        _procdump_display_proc(p, idx=i)
        print()

    # Dump prompt
    _procdump_selectionprompt(sorted_procs, pd, image, dump_dir)


def _procdump_search_loop(pd: ProcessDumper, image: str, dump_dir: Path):
    """Interactive search-and-dump loop for processes."""
    print()
    print(f"   {W}PROCESS SEARCH{N}")
    print(f"   Type a process name, PID, or part of command line.")
    print(f"   Type {W}q{N} to go back.")
    print()

    while True:
        query = prompt("Search").strip()
        if not query:
            continue
        if query.lower() == "q":
            return

        matches = pd.search_processes(query)
        if not matches:
            msg_warn(f"No processes matching '{query}' -- try another term")
            continue

        print()
        msg_ok(f"Found {len(matches)} process(es) matching '{query}':")
        print()

        for i, p in enumerate(matches, 1):
            _procdump_display_proc(p, idx=i)
            print()

        _procdump_selectionprompt(matches, pd, image, dump_dir)


def _procdump_show_suspicious(pd: ProcessDumper, suspicious: List, image: str, dump_dir: Path):
    """Show suspicious processes with flags, allow selection."""
    if not suspicious:
        msg_info("No suspicious processes flagged.")
        return

    print()
    print_line()
    print(f"   {W}SUSPICIOUS PROCESSES{N} ({len(suspicious)} flagged)")
    print(f"   NOTE: Raw observations, not threat assessments.")
    print_line()
    print()

    for i, p in enumerate(suspicious, 1):
        _procdump_display_proc(p, idx=i, show_flags=True)
        print()

    _procdump_selectionprompt(suspicious, pd, image, dump_dir)


def _procdump_selectionprompt(proc_list: List, pd: ProcessDumper,
                                image: str, dump_dir: Path):
    """Common selection prompt for process dump operations."""
    while True:
        print(f"   {W}[number]{N} Dump FULL MEMORY (heap/stack — ~MBs, has data)   "
              f"{W}[E number]{N} Dump EXE only (PE file)")
        print(f"   {W}[A]{N} Dump all EXEs (fast triage)    "
              f"{W}[S]{N} New search    {W}[Q]{N} Back")
        sel = prompt("Select").strip()

        if sel.upper() == "Q":
            return
        elif sel.upper() == "S":
            return  # Back to search prompt
        elif sel.upper() == "A":
            msg_info(f"Dumping all {len(proc_list)} process EXEs...")
            exe_dir = dump_dir / "process_exe"
            dumped = 0
            for p in proc_list:
                print()
                msg_info(f"[{p['pid']}] {p['name']}")
                if pd.dump_process_exe_verbose(image, p, exe_dir):
                    dumped += 1
            print()
            msg_ok(f"Done: {dumped}/{len(proc_list)} dumped to {exe_dir}")
            return
        elif sel.upper().startswith("E"):
            # EXE-only (PE file): "E 3" / "E3" / "E 1,3,5"
            _dump_exe_selection(sel[1:].strip(), proc_list, pd, image, dump_dir)
        elif sel.upper().startswith("M"):
            # Backward-compat alias: "M 3" still means full memory
            _dump_memory_selection(sel[1:].strip(), proc_list, pd, image, dump_dir)
        else:
            # Plain number now = FULL MEMORY dump (uses the mem plugin)
            _dump_memory_selection(sel, proc_list, pd, image, dump_dir)


def _dump_memory_selection(num_str, proc_list, pd, image, dump_dir):
    """Full process memory dump (Vol3 windows.memmap --dump / Vol2 memdump)."""
    try:
        indices = parse_selection(num_str, len(proc_list))
    except Exception:
        msg_warn("Invalid. Use: 3  or  1,3,5  or  2-5"); return
    if not indices:
        msg_warn("Invalid. Enter a number, range (1-5), or list (1,3,7)"); return
    mem_dir = dump_dir / "process_memory"
    for i in indices:
        p = proc_list[i]
        print(); print_line()
        msg_info(f"FULL MEMORY DUMP: [{p['pid']}] {p['name']}")
        msg_info(f"PPID: {p['ppid']}  Threads: {p.get('threads', '?')}")
        if p.get("cmdline"):
            msg_info(f"CMD: {p['cmdline'][:120]}")
        print()
        ok = pd.dump_process_memory_verbose(image, p, mem_dir)
        print()
        if ok:
            msg_ok(f"[{p['pid']}] {p['name']} memory dumped to {mem_dir}")
        else:
            msg_fail(f"[{p['pid']}] {p['name']} memory dump failed")
        print_line()


def _dump_exe_selection(num_str, proc_list, pd, image, dump_dir):
    """PE-only dump (Vol3 windows.pslist --dump / Vol2 procdump)."""
    try:
        indices = parse_selection(num_str, len(proc_list))
    except Exception:
        msg_warn("Invalid. Use: E 3  or  E 1,3,5  or  E 2-5"); return
    if not indices:
        msg_warn("Invalid. Use: E 3  or  E 1,3,5  or  E 2-5"); return
    exe_dir = dump_dir / "process_exe"
    for i in indices:
        p = proc_list[i]
        print(); print_line()
        msg_info(f"PROCESS EXE DUMP (PE only): [{p['pid']}] {p['name']}")
        msg_info(f"PPID: {p['ppid']}  Threads: {p.get('threads', '?')}  Offset: {p.get('offset', '?')}")
        if p.get("cmdline"):
            msg_info(f"CMD: {p['cmdline'][:120]}")
        print()
        ok = pd.dump_process_exe_verbose(image, p, exe_dir)
        print()
        if ok:
            msg_ok(f"[{p['pid']}] {p['name']} EXE -- DONE")
        else:
            msg_fail(f"[{p['pid']}] {p['name']} -- all methods failed")
        print_line()


def _cmd_strings(args):
    if not args.image:
        msg_fail("--image (-i) required"); sys.exit(1)
    image = _resolve_image_or_exit(args.image)
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    se = StringsExtractor(clog.get_logger("STRINGS"))
    res = se.extract(image, od, args.strings_mode)
    if "error" in res:
        msg_fail(res["error"]); sys.exit(1)
    print_line()
    for label, stats in res.get("files", {}).items():
        msg_ok(f"{label}: {format_size(stats['size'])} ({stats['lines']} lines)")
    msg_ok(f"Duration: {format_duration(res['duration'])}")


def _cmd_correlate(args):
    od = _resolve_output(args.image, args.output)
    if not (od / "json").is_dir():
        msg_fail(f"No json/ in {od}"); sys.exit(1)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    c = Correlator(clog.get_logger("CORRELATOR"), _read_os_type(od))
    c.load_data(od)
    rp = c.generate_report(od)
    msg_ok(f"Report: {rp}")


def _cmd_iocs(args):
    """Interactive IOC extraction from strings or txt files."""
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    ioc = IOCExtractor(clog.get_logger("IOC"))

    # Find input files
    strings_file = None
    for candidate in ["strings_ascii.txt", "strings.txt", "strings_all.txt"]:
        sf = od / candidate
        if sf.exists():
            strings_file = sf
            break

    txt_dir = od / "txt"
    ioc_dir = od / "iocs"

    # Interactive loop
    while True:
        print()
        print_line()
        print()
        print(f"   {W}IOC EXTRACTOR{N}")
        print(f"   Output: {C}{od}{N}")
        print()

        # Show available categories
        cats = IOCExtractor.list_categories()
        print(f"   {W}Available categories ({len(cats)}):{N}")
        for cat_name, (label, count) in cats.items():
            print(f"      {cat_name:15s} {label:25s} ({count} patterns)")
        print()

        # Show available sources
        print(f"   {W}Available sources:{N}")
        if strings_file:
            sz = format_size(strings_file.stat().st_size)
            print(f"      {G}[S]{N} Strings file: {strings_file.name} ({sz})")
        else:
            print(f"      {Y}[S]{N} Strings file: not found (run strings extraction first)")
        if txt_dir.is_dir():
            tc = sum(1 for _ in txt_dir.glob("*.txt"))
            print(f"      {G}[T]{N} TXT directory: {txt_dir.name}/ ({tc} files)")
        else:
            print(f"      {Y}[T]{N} TXT directory: not found")
        print()

        print(f"   {W}[1]{N} Scan strings file (all categories)")
        print(f"   {W}[2]{N} Scan strings file (choose categories)")
        print(f"   {W}[3]{N} Scan txt/ directory (all categories)")
        print(f"   {W}[4]{N} Scan custom file")
        print(f"   {W}[5]{N} Show all pattern details")
        print(f"   {W}[Q]{N} Back to menu")
        print()

        choice = prompt("Select").strip()

        if choice.upper() == "Q":
            return

        elif choice == "1":
            if not strings_file:
                msg_fail("No strings file found. Run strings extraction first.")
                continue
            msg_info(f"Scanning {strings_file.name} with all categories...")
            counts = ioc.extract_from_file(strings_file, ioc_dir)
            _show_ioc_results(counts, ioc_dir)

        elif choice == "2":
            if not strings_file:
                msg_fail("No strings file found.")
                continue
            # Let user pick categories
            cat_names = list(cats.keys())
            print()
            for i, cn in enumerate(cat_names, 1):
                label, count = cats[cn]
                print(f"   {W}[{i}]{N} {cn:15s} - {label} ({count} patterns)")
            print()
            sel = prompt("Select categories (e.g. 1,3,5 or 1-4)")
            indices = parse_selection(sel, len(cat_names))
            if not indices:
                msg_warn("No valid selection")
                continue
            selected_cats = [cat_names[i] for i in indices]
            msg_info(f"Using categories: {', '.join(selected_cats)}")
            custom_ioc = IOCExtractor(clog.get_logger("IOC"), categories=selected_cats)
            counts = custom_ioc.extract_from_file(strings_file, ioc_dir)
            _show_ioc_results(counts, ioc_dir)

        elif choice == "3":
            if not txt_dir.is_dir():
                msg_fail("No txt/ directory found.")
                continue
            msg_info(f"Scanning {txt_dir.name}/ with all categories...")
            counts = ioc.extract_from_directory(txt_dir, ioc_dir)
            _show_ioc_results(counts, ioc_dir)

        elif choice == "4":
            custom_path = prompt("Path to text file")
            if custom_path and Path(custom_path).exists():
                counts = ioc.extract_from_file(Path(custom_path), ioc_dir)
                _show_ioc_results(counts, ioc_dir)
            else:
                msg_fail("File not found")

        elif choice == "5":
            print()
            all_pats = IOCExtractor.list_all_patterns()
            current_cat = ""
            for p in all_pats:
                if p["category"] != current_cat:
                    current_cat = p["category"]
                    print(f"\n   {W}--- {p['category_label']} ---{N}")
                print(f"      {p['name']:30s} {p['description']}")
            print()
            try:
                input("   Press Enter to continue...")
            except (EOFError, KeyboardInterrupt):
                pass

        else:
            msg_warn("Invalid choice")


def _show_ioc_results(counts, ioc_dir):
    """Display IOC extraction results."""
    print()
    print_line()
    if counts:
        msg_ok(f"IOCs found ({sum(counts.values())} total, {len(counts)} types):")
        print()
        for name, count in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"      {name:30s} {count:>6d}")
        print()
        msg_ok(f"Results saved to: {ioc_dir}")
        msg_info(f"Summary: {ioc_dir / 'ioc_summary.txt'}")
    else:
        msg_info("No IOCs found.")
    print_line()



def _cmd_tree(args):
    """Display/generate process tree."""
    od = _resolve_output(args.image, args.output)
    if not (od / "json").is_dir():
        msg_fail(f"No json/ in {od}. Run extraction first."); return
    clog = CrescentLogger(str(od), args.quiet, args.log)
    ptree = ProcessTree(clog.get_logger("TREE"), _read_os_type(od))
    ptree.load(od)
    if not ptree.processes:
        msg_fail("No process data."); return

    # Interactive tree viewer
    while True:
        print()
        print_line()
        print(f"   {W}PROCESS TREE{N} -- {len(ptree.processes)} processes")
        print()
        print(f"   {W}[1]{N} Show full tree")
        print(f"   {W}[2]{N} Search and show subtree")
        print(f"   {W}[3]{N} Save tree to file")
        print(f"   {W}[Q]{N} Back")
        print()
        ch = prompt("Select").strip()
        if ch.upper() == "Q":
            return
        elif ch == "1":
            print()
            print(ptree.render())
            print()
            try:
                input("   Press Enter to continue...")
            except (EOFError, KeyboardInterrupt):
                pass
        elif ch == "2":
            q = prompt("Process name or PID")
            matches = ptree.search(q)
            if not matches:
                msg_warn(f"No match for '{q}'")
                continue
            for m in matches:
                print()
                print(f"   {W}[{m['pid']}] {m['name']}{N}")
                ancestors = ptree.get_ancestors(m["pid"])
                if ancestors:
                    print(f"   Chain: {' -> '.join(ancestors)} -> {m['pid']}")
                print()
                print(ptree.render_subtree(m["pid"]))
                print()
        elif ch == "3":
            path = ptree.write_tree_file(od)
            msg_ok(f"Saved: {path}")


def _cmd_netmap(args):
    """Generate network map with reverse DNS."""
    od = _resolve_output(args.image, args.output)
    if not (od / "json").is_dir():
        msg_fail(f"No json/ in {od}"); return
    clog = CrescentLogger(str(od), args.quiet, args.log)
    nmap = NetworkMap(clog.get_logger("NETMAP"))
    nmap.load(od)
    if not nmap.connections:
        msg_fail("No network data."); return

    msg_info(f"{len(nmap.connections)} connections, {len(nmap.external_ips)} external IPs")

    do_dns = False
    if nmap.external_ips:
        ans = prompt(f"Resolve DNS for {len(nmap.external_ips)} external IPs? (y/N)", "n")
        do_dns = ans.lower() == "y"

    path = nmap.write_report(od, do_dns=do_dns)
    print_line()
    msg_ok(f"Network map: {path}")
    msg_ok(f"JSON: {od / 'network_map.json'}")

    # Show external IPs
    if nmap.external_ips:
        print()
        msg_info("External IPs:")
        dns = nmap._dns_cache if do_dns else {}
        for ip in sorted(nmap.external_ips):
            host = dns.get(ip, "")
            suffix = f" -> {host}" if host and host != "N/A" else ""
            print(f"      {ip}{suffix}")
    print_line()


def _cmd_registry(args):
    """Interactive registry explorer."""
    od = _resolve_output(args.image, args.output)
    if not (od / "json").is_dir():
        msg_fail(f"No json/ in {od}"); return
    clog = CrescentLogger(str(od), args.quiet, args.log)
    reg = RegistryExplorer(clog.get_logger("REGISTRY"))
    reg.load(od)

    while True:
        print()
        print_line()
        print(f"   {W}REGISTRY EXPLORER{N}")
        print(f"   Hives: {len(reg.get_hives())}  UserAssist: {len(reg.get_userassist())}")
        print(f"   ShellBags: {len(reg.get_shellbags())}  ShimCache: {len(reg.get_shimcache())}")
        print()
        print(f"   {W}[1]{N} Show persistence indicators")
        print(f"   {W}[2]{N} Show hives")
        print(f"   {W}[3]{N} Show UserAssist (program execution)")
        print(f"   {W}[4]{N} Show ShellBags (folder access)")
        print(f"   {W}[5]{N} Show ShimCache (app history)")
        print(f"   {W}[6]{N} Search all registry data")
        print(f"   {W}[7]{N} Save full report")
        print(f"   {W}[Q]{N} Back")
        print()
        ch = prompt("Select").strip()
        if ch.upper() == "Q":
            return
        elif ch == "1":
            pers = reg.find_persistence()
            if pers:
                for p in pers:
                    print(f"   {Y}{p['persistence_key']}{N}")
                    for k, v in p["entry"].items():
                        if k != "__children":
                            print(f"      {k}: {str(v)[:100]}")
                    print(f"   {'-' * 40}")
            else:
                msg_info("No persistence entries found.")
        elif ch == "2":
            for h in reg.get_hives():
                offset = h.get("Offset", h.get("offset", ""))
                name = h.get("Name", h.get("name", h.get("FileFullPath", "")))
                print(f"   {offset}  {name}")
        elif ch == "3":
            for e in reg.get_userassist()[:50]:
                raw = e.get("raw", "")
                if raw:
                    print(f"   {raw}")
                else:
                    print(f"   {json.dumps(e, default=str)[:120]}")
        elif ch == "4":
            for e in reg.get_shellbags()[:50]:
                raw = e.get("raw", "")
                path = e.get("Path", e.get("path", ""))
                print(f"   {raw or path}")
        elif ch == "5":
            for e in reg.get_shimcache()[:50]:
                raw = e.get("raw", "")
                path = e.get("Path", e.get("path", ""))
                print(f"   {raw or path}")
        elif ch == "6":
            q = prompt("Search term")
            results = reg.search(q)
            if results:
                for src, entries in results.items():
                    msg_ok(f"{src}: {len(entries)} matches")
                    for e in entries[:10]:
                        print(f"      {json.dumps(e, default=str)[:120]}")
            else:
                msg_warn(f"No matches for '{q}'")
        elif ch == "7":
            path = reg.write_report(od)
            msg_ok(f"Report: {path}")
            msg_ok(f"JSON: {od / 'registry_report.json'}")


def _cmd_report(args):
    """Generate HTML report."""
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    # Pick the OS-specific report builder from the prior run's SUMMARY.txt
    # (was hard-coded None -> always fell back to the Windows builder, so
    # regenerating a Linux/macOS report via `report` mislabelled it and used
    # Windows-only field/label logic).
    os_type = _read_os_type(od)
    htmlgen = HTMLReportGenerator(clog.get_logger("HTML"), os_type)
    path = htmlgen.generate(od)
    msg_ok(f"HTML report: {path}")
    msg_info("Open in a browser to view the interactive report.")



def _cmd_timeline(args):
    """Build evidence timeline from all available timestamps."""
    od = _resolve_output(args.image, args.output)
    if not (od / "json").is_dir():
        msg_fail(f"No json/ in {od}. Run extraction first."); return
    clog = CrescentLogger(str(od), args.quiet, args.log)
    tl = Timeline(clog.get_logger("TIMELINE"))
    tl.load(od)
    if not tl.events:
        msg_fail("No timeline events found."); return

    # Non-interactive (batch/-q/no TTY): build + save and return instead of
    # entering the menu loop, which would spin forever reading EOF from stdin.
    if getattr(args, "quiet", False) or not sys.stdin.isatty():
        paths = tl.write_report(od)
        msg_ok(f"Timeline saved ({len(tl.events)} events): "
               + ", ".join(p.name for p in paths if p))
        return

    while True:
        print()
        print_line()
        print(f"   {W}EVIDENCE TIMELINE{N} -- {len(tl.events)} events")
        print()
        print(f"   {W}[1]{N} Show full timeline")
        print(f"   {W}[2]{N} Filter by time range")
        print(f"   {W}[3]{N} Filter by source (pslist, shimcache, etc.)")
        print(f"   {W}[4]{N} Search by keyword")
        print(f"   {W}[5]{N} Save timeline (TXT + CSV + JSON)")
        print(f"   {W}[Q]{N} Back")
        print()
        ch = prompt("Select").strip()
        if ch.upper() == "Q":
            return
        elif ch == "1":
            print()
            for e in tl.events:
                print(f"   {e['timestamp']:26s}  [{e['source']:12s}]  "
                      f"{e['type']:22s}  {e['detail']}")
            print()
            try:
                input("   Press Enter to continue...")
            except (EOFError, KeyboardInterrupt):
                pass
        elif ch == "2":
            start = prompt("Start time (e.g. 2024-01-15 14:00)")
            end = prompt("End time (e.g. 2024-01-15 15:00)")
            filtered = tl.filter(start=start, end=end)
            msg_info(f"{len(filtered)} events in range")
            for e in filtered:
                print(f"   {e['timestamp']:26s}  [{e['source']:12s}]  "
                      f"{e['type']:22s}  {e['detail']}")
        elif ch == "3":
            sources = set(e["source"] for e in tl.events)
            msg_info(f"Sources: {', '.join(sorted(sources))}")
            src = prompt("Source name")
            filtered = tl.filter(source=src)
            msg_info(f"{len(filtered)} events from '{src}'")
            for e in filtered:
                print(f"   {e['timestamp']:26s}  {e['type']:22s}  {e['detail']}")
        elif ch == "4":
            kw = prompt("Keyword")
            filtered = tl.filter(keyword=kw)
            msg_info(f"{len(filtered)} events matching '{kw}'")
            for e in filtered:
                print(f"   {e['timestamp']:26s}  [{e['source']:12s}]  "
                      f"{e['type']:22s}  {e['detail']}")
        elif ch == "5":
            txt, csvp, jsonp = tl.write_report(od)
            msg_ok(f"TXT:  {txt}")
            msg_ok(f"CSV:  {csvp}")
            msg_ok(f"JSON: {jsonp}")


def _cmd_evtx(args):
    """Parse dumped EVTX files."""
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    parser = EVTXParser(clog.get_logger("EVTX"))
    files = parser.find_evtx_files(od)
    if not files:
        msg_fail("No .evtx files found. Dump EVTX files first (DEFAULT mode or File Dumper).")
        return
    msg_info(f"Found {len(files)} EVTX files")
    for f in files:
        print(f"      {f.name}")
    print()
    events = parser.parse_all(od)
    interesting = parser.get_interesting_events(events)
    msg_ok(f"Parsed {len(events)} events, {len(interesting)} security-relevant")
    path = parser.write_report(od, events)
    msg_ok(f"Report: {path}")
    msg_ok(f"JSON: {od / 'evtx_report.json'}")
    # Show interesting events
    if interesting:
        print()
        msg_info("Security-relevant events:")
        for e in interesting[:30]:
            eid = e.get("EventID", "?")
            desc = e.get("_description", "")
            ts = e.get("TimeCreated", "")
            print(f"   [{eid}] {desc:35s} {ts}")
        if len(interesting) > 30:
            msg_info(f"... and {len(interesting) - 30} more (see report)")


def _cmd_export(args):
    """Generate export zip pack."""
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    ep = ExportPack(clog.get_logger("EXPORT"))
    available = ep.list_available(od)
    if not available:
        msg_fail("No files to export. Run analysis first."); return
    msg_info(f"{len(available)} files available for export:")
    for f in available:
        print(f"      {f}")
    print()
    zip_path = ep.generate(od)
    print_line()
    msg_ok(f"Export pack: {zip_path}")
    msg_info(f"Size: {zip_path.stat().st_size / 1024:.1f} KB")
    msg_info("Ready to share with your team or attach to a ticket.")


def _cmd_install(args):
    """Check and install Volatility 2 + 3 with all dependencies."""
    clog = CrescentLogger(str(Path.home() / "Desktop"), True)
    inst = VolatilityInstaller(clog.get_logger("INSTALLER"))

    while True:
        print()
        print_line()
        print(f"   {W}VOLATILITY INSTALLER{N}")
        print()
        status = inst.print_status()
        print()
        print(f"   {W}[1]{N} Install Volatility 3 (clone + requirements)")
        print(f"   {W}[2]{N} Install Volatility 2 (clone)")
        print(f"   {W}[3]{N} Install Vol2 dependencies (pycryptodome + distorm3)")
        print(f"   {W}[4]{N} Install Vol3 dependencies (yara-python + pefile)")
        print(f"   {W}[5]{N} Download Windows symbol tables")
        print(f"   {W}[6]{N} Download Linux symbol tables")
        print(f"   {W}[7]{N} Download ALL symbol tables (Windows + Linux + Mac)")
        print(f"   {W}[8]{N} Update Linux symbol-table catalogue (build names)")
        print(f"   {W}[A]{N} Install EVERYTHING")
        print(f"   {W}[Q]{N} Back")
        print()
        ch = prompt("Select").strip().upper()

        if ch == "Q":
            return
        elif ch == "1":
            msg_info("Installing Volatility 3...")
            ok = inst.install_vol3()
            msg_ok("Vol3 installed") if ok else msg_fail("Vol3 install failed")
        elif ch == "2":
            msg_info("Installing Volatility 2...")
            ok = inst.install_vol2()
            msg_ok("Vol2 installed") if ok else msg_fail("Vol2 install failed")
        elif ch == "3":
            msg_info("Installing Vol2 dependencies...")
            r = inst.install_vol2_deps()
            for dep, ok in r.items():
                (msg_ok if ok else msg_fail)(f"  {dep}: {'OK' if ok else 'FAILED'}")
        elif ch == "4":
            msg_info("Installing Vol3 dependencies...")
            r = inst.install_vol3_deps()
            for dep, ok in r.items():
                (msg_ok if ok else msg_fail)(f"  {dep}: {'OK' if ok else 'FAILED'}")
        elif ch == "5":
            msg_info("Downloading Windows symbols (this may take a while)...")
            r = inst.download_symbols(["windows"])
            for k, ok in r.items():
                (msg_ok if ok else msg_fail)(f"  {k}: {'OK' if ok else 'FAILED'}")
        elif ch == "6":
            msg_info("Downloading Linux symbols...")
            r = inst.download_symbols(["linux"])
            for k, ok in r.items():
                (msg_ok if ok else msg_fail)(f"  {k}: {'OK' if ok else 'FAILED'}")
        elif ch == "7":
            msg_info("Downloading ALL symbol tables...")
            r = inst.download_symbols(["windows", "linux", "mac"])
            for k, ok in r.items():
                (msg_ok if ok else msg_fail)(f"  {k}: {'OK' if ok else 'FAILED'}")
        elif ch == "8":
            from modules import linux_identify
            msg_info("Updating Linux symbol-table catalogue from repo...")
            n = linux_identify.update_symbol_catalogue(
                clog.get_logger("INSTALLER"))
            if n:
                msg_ok(f"Catalogue updated — {n} kernel builds available offline")
            else:
                msg_fail("Catalogue update failed (could not reach repo)")
        elif ch == "A":
            msg_info("Installing everything...")
            r = inst.install_all()
            print()
            for k, ok in r.items():
                (msg_ok if ok else msg_fail)(f"  {k}: {'OK' if ok else 'FAILED'}")
        else:
            msg_warn("Invalid choice")

        try:
            input("\n   Press Enter to continue...")
        except (EOFError, KeyboardInterrupt):
            pass


def _cmd_browser(args):
    """Scan memory strings for browser history."""
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    scanner = BrowserHistoryScanner(clog.get_logger("BROWSER"))
    results = scanner.scan_output_dir(od)
    if not results or not results.get("urls"):
        msg_fail("No browser history found. Run strings extraction first.")
        return
    txt = scanner.write_report(od, results)
    print()
    print_line()
    msg_ok(f"Browser History Analysis")
    print()
    msg_info(f"URLs:      {results['url_count']}")
    msg_info(f"Searches:  {results['search_count']}")
    msg_info(f"Downloads: {results['download_count']}")
    msg_info(f"IE History:{results['ie_history_count']}")
    print()
    if results["searches"]:
        msg_info("Search queries:")
        for s in results["searches"][:15]:
            print(f"      [{s['engine']:10s}] {s['query']}")
        if len(results["searches"]) > 15:
            msg_info(f"  ... and {len(results['searches']) - 15} more")
    if results["downloads"]:
        print()
        msg_info("File downloads:")
        for d in results["downloads"][:10]:
            print(f"      {d}")
    sus = results["categories"].get("suspicious", [])
    if sus:
        print()
        msg_warn("Suspicious URLs:")
        for u in sus[:10]:
            print(f"      {u}")
    print()
    msg_ok(f"Report: {txt}")
    msg_ok(f"JSON:   {od / 'iocs' / 'json' / 'browser_history.json'}")
    print_line()


def _cmd_comms(args):
    """Scan memory strings for communication app artifacts."""
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    scanner = CommsScanner(clog.get_logger("COMMS"))

    sf = od / "strings_ascii.txt"
    if not sf.exists():
        sf = od / "strings.txt"
    if not sf.exists():
        msg_fail("No strings file found. Run strings extraction first.")
        return

    results = scanner.scan_strings_file(sf)
    scanner.enrich_from_processes(od, results)

    if results.get("total_artifacts", 0) == 0:
        msg_info("No communication app artifacts found.")
        return

    txt = scanner.write_report(od, results)
    print()
    print_line()
    msg_ok("Communication App Artifacts")
    print()
    msg_info(f"Total artifacts: {results['total_artifacts']}")
    msg_info(f"Apps detected:   {', '.join(results.get('apps_detected', []))}")
    print()

    # Show running processes
    running = results.get("running_processes", {})
    if running:
        msg_info("Running app processes:")
        for app, procs in running.items():
            for proc in procs:
                print(f"      [{app.upper():10s}] PID {proc['pid']} - {proc['name']}")
        print()

    # Show per-app summary
    for app, app_data in results.get("apps", {}).items():
        display = app.replace("_", " ").upper()
        cats = app_data.get("categories", {})
        critical = sum(1 for c in cats if any(x in c for x in
                       ("token", "secret", "key", "password")))
        if critical:
            msg_warn(f"[{display}] {app_data['total']} artifacts ({critical} CRITICAL token/key types)")
        else:
            msg_ok(f"[{display}] {app_data['total']} artifacts")

        for cat, cat_data in cats.items():
            is_crit = any(x in cat for x in ("token", "secret", "key", "password"))
            marker = " [!!!]" if is_crit else ""
            print(f"        {cat}: {cat_data['count']}{marker}")

    print()
    msg_ok(f"Report: {txt}")
    msg_ok(f"JSON:   {od / 'comms_report.json'}")
    msg_ok(f"Files:  {od / 'comms/'}")
    print_line()


def _cmd_cmdanalyze(args):
    """Analyze command lines for suspicious patterns."""
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    analyzer = CommandAnalyzer(clog.get_logger("CMDANALYZER"))
    results = analyzer.analyze(od)
    if results["flags"] or results["chains"]:
        txt = analyzer.write_report(od, results)
        print_line()
        msg_ok("Command Line Analysis")
        for fl in results["flags"][:10]:
            sev = fl["severity"]
            if sev == "CRITICAL":
                msg_fail(f"[{sev}] {fl['description']} | {fl['mitre_id']}")
            elif sev == "HIGH":
                msg_warn(f"[{sev}] {fl['description']} | {fl['mitre_id']}")
            else:
                msg_ok(f"[{sev}] {fl['description']} | {fl['mitre_id']}")
            print(f"        PID {fl['pid']} ({fl['process']}): {fl['cmdline'][:100]}")
        if len(results["flags"]) > 10:
            msg_info(f"... and {len(results['flags']) - 10} more (see report)")
        if results["chains"]:
            print()
            msg_warn("Suspicious chains:")
            for c in results["chains"]:
                print(f"        {c['parent_name']}[{c['parent_pid']}] → "
                      f"{c['child_name']}[{c['child_pid']}]: {c['description']}")
        msg_ok(f"Report: {txt}")
        print_line()
    else:
        msg_ok("No suspicious commands detected.")


def _cmd_mitre(args):
    """Map all findings to MITRE ATT&CK techniques."""
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    # Run command analysis first (for cmdline-based MITRE mappings)
    cmd_analyzer = CommandAnalyzer(clog.get_logger("CMDANALYZER"))
    cmd_results = cmd_analyzer.analyze(od)
    # Map everything
    mapper = MitreMapper(clog.get_logger("MITRE"))
    results = mapper.map_all(od, cmd_results)
    if results["technique_count"] > 0:
        txt = mapper.write_report(od, results)
        print_line()
        msg_ok(f"MITRE ATT&CK Mapping — {results['technique_count']} techniques")
        print()
        for tactic, techs in results["by_tactic"].items():
            msg_info(f"{tactic}:")
            for t in techs:
                print(f"        {t['technique_id']:12s} {t['technique_name']} "
                      f"({t['evidence_count']} evidence)")
        print()
        msg_ok(f"Report: {txt}")
        msg_info("Technique IDs for ATT&CK Navigator:")
        print("        " + ", ".join(t["technique_id"] for t in results["techniques"]))
        print_line()
    else:
        msg_ok("No MITRE ATT&CK techniques identified.")


def _cmd_scheduled_tasks(args):
    """Scan for scheduled task evidence (Windows schtasks + Linux cron)."""
    od = _resolve_output(args.image, args.output)
    if not (od / "json").is_dir():
        msg_fail(f"No json/ in {od}. Run extraction first."); return
    clog = CrescentLogger(str(od), args.quiet, args.log)
    scanner = ScheduledTasksScanner(clog.get_logger("SCHTASKS"))
    results = scanner.scan(od)
    if not results or results.get("total_findings", 0) == 0:
        msg_info("No scheduled task evidence found.")
        msg_info("(Needs printkey / filescan / cmdline data — run full or persistence mode)")
        return
    txt = scanner.write_report(od, results)
    print()
    print_line()
    msg_ok("Scheduled Tasks Scan")
    print()
    msg_info(f"Registry entries:    {len(results.get('registry_tasks', []))}")
    msg_info(f"Task files:          {len(results.get('file_tasks', []))}")
    msg_info(f"Scheduler processes: {len(results.get('task_processes', []))}")
    msg_info(f"Suspicious commands: {len(results.get('suspicious_commands', []))}")
    msg_info(f"Linux cron evidence: {len(results.get('linux_cron', []))}")
    msg_info(f"macOS launchd evidence: {len(results.get('mac_launchd', []))}")
    print()
    if results.get("suspicious_commands"):
        msg_warn("Suspicious task-related commands:")
        for c in results["suspicious_commands"][:10]:
            print(f"      PID {c.get('pid', '?')}: {c.get('cmdline', '')[:100]}")
    msg_ok(f"Report: {txt}")
    msg_ok(f"JSON:   {od / 'iocs' / 'json' / 'scheduled_tasks.json'}")
    print_line()


def _cmd_registry_altered(args):
    """Scan registry artifacts for recently modified or suspicious keys."""
    od = _resolve_output(args.image, args.output)
    if not (od / "json").is_dir():
        msg_fail(f"No json/ in {od}. Run extraction first."); return
    clog = CrescentLogger(str(od), args.quiet, args.log)
    scanner = RegistryAlteredScanner(clog.get_logger("REGALT"))
    results = scanner.scan(od)
    if not results:
        msg_fail("No registry data found."); return
    txt = scanner.write_report(od, results)
    print()
    print_line()
    msg_ok("Registry Alteration Scan")
    print()
    if results.get("anomalies"):
        msg_warn(f"Anomalies: {len(results['anomalies'])}")
        for a in results["anomalies"][:5]:
            print(f"      [{a.get('type','').upper()}] {a.get('description','')}")
    msg_info(f"Sensitive key hits:     {len(results.get('sensitive_key_hits', []))}")
    msg_info(f"Hives analyzed:         {len(results.get('hive_info', []))}")
    msg_info(f"Timestamped writes:     {len(results.get('recent_writes', []))}")
    msg_info(f"UserAssist entries:     {len(results.get('userassist_timeline', []))}")
    msg_info(f"ShimCache entries:      {len(results.get('shimcache_recent', []))}")
    msg_info(f"ShellBag entries:       {len(results.get('shellbags_recent', []))}")
    print()
    msg_ok(f"Report: {txt}")
    msg_ok(f"JSON:   {od / 'json' / 'registry_altered.json'}")
    print_line()


def _cmd_popular_files(args):
    """Scan filescan for files in popular locations (Desktop, Downloads, etc.)."""
    od = _resolve_output(args.image, args.output)
    if not (od / "json").is_dir():
        msg_fail(f"No json/ in {od}. Run extraction first."); return
    clog = CrescentLogger(str(od), args.quiet, args.log)
    scanner = PopularFilesScanner(clog.get_logger("POPFILES"))
    results = scanner.scan(od)
    if not results or results.get("total_files_scanned", 0) == 0:
        msg_fail("No filescan/lsof data found. Run full extraction first."); return
    txt = scanner.write_report(od, results)
    print()
    print_line()
    msg_ok(f"Popular Files Scan  [{results.get('os_heuristic','?').upper()}]")
    print()
    msg_info(f"Total files scanned:       {results['total_files_scanned']}")
    msg_info(f"Suspicious path hits:      {len(results.get('suspicious_paths', []))}")
    msg_info(f"Executables in user dirs:  {len(results.get('executables_in_user_dirs', []))}")
    print()
    buckets = results.get("buckets", {})
    if buckets:
        msg_info("Files by location:")
        for name, bdata in sorted(buckets.items(), key=lambda x: -x[1]["count"])[:15]:
            print(f"      {name:25s} {bdata['count']:>5d} files")
    print()
    if results.get("suspicious_paths"):
        msg_warn("Top suspicious paths:")
        for e in results["suspicious_paths"][:8]:
            print(f"      [{e.get('reason','')}]")
            print(f"        {e.get('path','')[:100]}")
    msg_ok(f"Report: {txt}")
    msg_ok(f"JSON:   {od / 'iocs' / 'json' / 'popular_files.json'}")
    print_line()


def _cmd_hunt(args):
    """Search live memory image for user-specified strings (YARA-based)."""
    if not args.image:
        msg_fail("--image (-i) required for hunt"); return
    image = _resolve_image_or_exit(args.image)
    od = _resolve_output(args.image, args.output)

    # Collect search terms: from --hunt-strings or interactive prompt
    terms = list(args.hunt_strings) if getattr(args, "hunt_strings", None) else []
    if not terms:
        msg_info("Enter search strings (one per line, blank line to finish):")
        while True:
            try:
                t = input("   String> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not t:
                break
            terms.append(t)
    if not terms:
        msg_fail("No search terms provided."); return

    clog = CrescentLogger(str(od), args.quiet, args.log)
    ml   = clog.get_logger("HUNT")
    vol  = _init_vol(clog, image, args)

    pid_filter = getattr(args, "hunt_pid", None) or None
    insensitive = not getattr(args, "hunt_case_sensitive", False)
    wide = not getattr(args, "hunt_no_wide", False)

    hunter = StringHunter(ml)
    print()
    print_line()
    msg_info(f"String Hunt: {len(terms)} term(s)")
    msg_warn("Scanning ALL process memory — may take several minutes on large images.")
    if pid_filter:
        msg_info(f"Restricted to PID(s): {pid_filter}")
    print()

    results = hunter.hunt(
        image, od, terms, vol,
        os_type=vol.os_type or "windows",
        pid_filter=pid_filter,
        case_insensitive=insensitive,
        wide=wide,
        timeout=max(args.timeout, 1800),
    )

    print()
    print_line()
    total = results["total_hits"]
    dur   = results["scan_duration"]
    plugin = results["plugin"]

    if total == 0:
        msg_warn(f"No hits found in {dur}s  [{plugin}]")
    else:
        msg_ok(f"String Hunt Complete — {total} hit(s) in {dur}s  [{plugin}]")
        print()
        by_term = results.get("by_term", {})
        for term in results["terms"]:
            th = by_term.get(term, [])
            if th:
                # Show unique processes
                procs = {}
                for h in th:
                    k = f"PID {h['pid']:>6}  {h['process']}"
                    procs[k] = procs.get(k, 0) + 1
                msg_info(f'  "{term}" — {len(th)} hit(s) in {len(procs)} process(es):')
                for pk, cnt in list(procs.items())[:6]:
                    print(f"      {pk}  ({cnt}×)")
                if len(procs) > 6:
                    print(f"      ... and {len(procs) - 6} more")
            else:
                msg_warn(f'  "{term}" — no hits')

    strings_hits = results.get("strings_hits", {})
    if strings_hits:
        print()
        msg_info("Strings corpus counts (no process attribution):")
        for term, cnt in strings_hits.items():
            print(f'      "{term}"  →  {cnt} occurrence(s)')

    print()
    msg_ok(f"Report: {od / 'string_hunt.txt'}")
    msg_ok(f"JSON:   {od / 'json' / 'string_hunt.json'}")
    print_line()


def _cmd_elk(args):
    """Export all data to ELK/Kibana NDJSON format."""
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    elk = ELKExporter(clog.get_logger("ELK"))
    msg_info("Exporting data for Elasticsearch/Kibana...")
    counts = elk.export_all(od)
    if not counts:
        msg_fail("No data to export. Run analysis first."); return
    print()
    print_line()
    msg_ok("ELK Export Complete")
    print()
    total = sum(counts.values())
    msg_info(f"Indices: {len(counts)}  Documents: {total}")
    print()
    for index, count in sorted(counts.items()):
        print(f"      {index:35s} {count:>6d} docs")
    print()
    elk_dir = od / "elk_export"
    msg_ok(f"Output: {elk_dir}")
    msg_info(f"Import: cd {elk_dir} && ./import_to_elk.sh")
    msg_info("Kibana: Index pattern 'crescent-*', time field '@timestamp'")
    print_line()


def _cmd_core(args, skip_ioc=False, label="FULL"):
    """CORE analysis pipeline -- full analysis except EVTX.

    skip_ioc=True (CTF mode) still runs the Volatility plugins plus every fast,
    plugin-JSON-derived step (process tree, network map, process/command/MITRE
    analysis, correlation, popular files, scheduled tasks, registry, timeline,
    HTML report) but SKIPS the strings -> IOC -> browser -> comms scan, which is
    the slow pass CTF work rarely needs. `label` is the word shown in the run
    banner and the completion line (CORE/CTF/DFIR)."""
    if not args.image:
        msg_fail("--image (-i) required"); sys.exit(1)
    image = _resolve_image_or_exit(args.image)
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    clog.log_session_info(image, str(od), mode=args.mode)
    ml = clog.get_logger("MAIN")
    vol = _init_vol(clog, image, args)

    # Linux/macOS image → resolve Vol3 symbols if needed, then continue pipeline
    syms_ok = True
    if vol.os_type in ("linux", "mac"):
        syms_ok = _resolve_linux_symbols(vol, image, od, args)
        # Continue with normal pipeline below (extractor has Linux/Mac plugin lists)

    t0 = time.time()
    print(banner())
    print_line()
    msg_ok(f"Image:   {Path(image).name}")
    msg_ok(f"Output:  {od}")
    msg_ok(f"Mode:    {args.mode}  Engine: {vol.vol_version}  Jobs: {args.jobs}")
    if vol.profile:
        msg_ok(f"Profile: {vol.profile}")
    print_line()

    # Step 1: Extract
    ml.info("=== Step 1: Volatility Extraction ===")
    msg_info("Step 1/8: Running Volatility plugins (parallel)...")
    ext = Extractor(vol, clog.get_logger("EXTRACTOR"), args.jobs, getattr(args, "speed", "normal"))
    er = ext.run(image, od, args.mode)
    ext.write_summary(od, image, args.mode, er)
    msg_ok(f"Extraction: {er['ok']} OK, {er['fail']} failed")
    if er["ok"] == 0 and er["fail"] > 0 and er["skipped"] == 0:
        msg_fail("Extraction produced no successful plugin output; stopping pipeline.")
        sys.exit(2)

    # System Info — works for Windows and Linux/macOS (sources differ per OS)
    sysinfo = SystemInfo(clog.get_logger("SYSINFO"))
    si = sysinfo.load(od)
    sysinfo.write_report(od)
    hostname = si.get("hostname") or "Unknown"
    users = ", ".join(si.get("usernames", [])) or "Unknown"
    ips = ", ".join(si.get("ip_addresses", [])) or "Unknown"
    msg_ok(f"System: {hostname} | Users: {users} | IP: {ips}")
    print()

    # Step 2: Strings + IOC + Browser + Comms  (SKIPPED in Only-Vol-Plugins mode)
    if skip_ioc:
        ml.info("=== Step 2: Strings/IOC SKIPPED (Only Vol Plugins mode) ===")
        msg_info("Step 2/8: Strings + IOC/Browser/Comms extraction SKIPPED (Only Vol Plugins mode)")
        print()
    else:
        ml.info("=== Step 2: Strings ===")
        msg_info("Step 2/8: Extracting strings...")
        se = StringsExtractor(clog.get_logger("STRINGS"))
        sr = se.extract(image, od, "both")
        if "error" not in sr:
            msg_ok("Strings done")
            sf = od / "strings_ascii.txt"
            if not sf.exists():
                sf = od / "strings.txt"
            if sf.exists():
                # Single-pass: IOC + Browser + Comms read the file ONCE
                bh = BrowserHistoryScanner(clog.get_logger("BROWSER"))
                cs = CommsScanner(clog.get_logger("COMMS"))
                msg_info("IOC + Browser + Comms scan (single pass)...")
                ioc = IOCExtractor(clog.get_logger("IOC"))

                def _combined_callback(line):
                    bh._process_line(line)
                    cs._process_line(line)

                ioc.extract_from_file(sf, od / "iocs",
                                      line_callback=_combined_callback)
                # Write browser results
                bhr = bh._compile_results()
                if bhr and bhr.get("urls"):
                    bh.write_report(od, bhr)
                    msg_ok(f"Browser: {bhr['url_count']} URLs, {bhr['search_count']} searches, {bhr['download_count']} downloads")
                else:
                    msg_info("No browser history found")
                # Write comms results
                csr = cs._compile_results()
                cs.enrich_from_processes(od, csr)
                if csr.get("total_artifacts", 0) > 0:
                    cs.write_report(od, csr)
                    apps = ", ".join(csr.get("apps_detected", []))
                    msg_ok(f"Comms: {csr['total_artifacts']} artifacts from [{apps}]")
                else:
                    msg_info("No communication app artifacts found")
        print()

    # Step 3: Process tree + Network map
    ml.info("=== Step 3: Process Tree + Network Map ===")
    msg_info("Step 3/8: Building process tree...")
    ptree = ProcessTree(clog.get_logger("TREE"), vol.os_type)
    ptree.load(od)
    ptree.write_tree_file(od)
    msg_ok("Process tree built")

    msg_info("Building network map...")
    nmap = NetworkMap(clog.get_logger("NETMAP"))
    nmap.load(od)
    nmap.write_report(od, do_dns=False)
    msg_ok(f"Network map: {len(nmap.connections)} connections, {len(nmap.external_ips)} external IPs")
    print()

    # Step 4: Process analysis
    ml.info("=== Step 4: Process Analysis ===")
    msg_info("Step 4/8: Analyzing processes...")
    pd = ProcessDumper(vol, clog.get_logger("PROCDUMPER"))
    pd.load_processes(od)
    sus = pd.detect_suspicious()
    pd.write_suspicious_report(od, sus)
    msg_ok(f"Processes: {len(pd.processes)} total, {len(sus)} flagged")

    # Command Analysis + MITRE ATT&CK (OS-aware in v6)
    cmd_results = None
    msg_info("Analyzing command lines...")
    cmd_analyzer = CommandAnalyzer(clog.get_logger("CMDANALYZER"), vol.os_type)
    cmd_results = cmd_analyzer.analyze(od)
    if cmd_results["flags"] or cmd_results["chains"]:
        cmd_analyzer.write_report(od, cmd_results)
        crit = sum(1 for f in cmd_results["flags"] if f["severity"] == "CRITICAL")
        high = sum(1 for f in cmd_results["flags"] if f["severity"] == "HIGH")
        msg_warn(f"Commands: {len(cmd_results['flags'])} flags ({crit} CRITICAL, {high} HIGH), "
                 f"{len(cmd_results['chains'])} suspicious chains")
    else:
        msg_ok("Commands: no suspicious patterns detected")

    msg_info("Mapping to MITRE ATT&CK...")
    mitre = MitreMapper(clog.get_logger("MITRE"), vol.os_type)
    mitre_results = mitre.map_all(od, cmd_results)
    if mitre_results["technique_count"] > 0:
        mitre.write_report(od, mitre_results)
        msg_ok(f"MITRE: {mitre_results['technique_count']} techniques across "
               f"{mitre_results['tactic_count']} tactics")
    else:
        msg_ok("MITRE: no techniques identified")
    print()

    # Step 5: Correlate
    ml.info("=== Step 5: Correlation ===")
    msg_info("Step 5/8: Correlating findings...")
    cor = Correlator(clog.get_logger("CORRELATOR"), vol.os_type)
    cor.load_data(od)
    cor.generate_report(od)
    msg_ok("Correlation report done")
    print()

    # Step 5b: Popular Files (all OSes)
    ml.info("=== Step 5b: Popular Files ===")
    msg_info("Popular files scan (Desktop/Downloads/tmp/etc)...")
    pop_files = PopularFilesScanner(clog.get_logger("POPFILES"), vol.os_type)
    pf_results = pop_files.scan(od)
    if pf_results and pf_results.get("total_files_scanned", 0) > 0:
        pop_files.write_report(od, pf_results)
        msg_ok(f"Popular files: {pf_results['total_files_scanned']} scanned, "
               f"{len(pf_results.get('suspicious_paths', []))} suspicious, "
               f"OS={pf_results.get('os_heuristic', '?')}")
    else:
        msg_info("Popular files: no file data available yet")
    print()

    # Step 5c: Scheduled Tasks (all OSes)
    ml.info("=== Step 5c: Scheduled Tasks ===")
    msg_info("Scanning for scheduled tasks / cron / launchd evidence...")
    sched = ScheduledTasksScanner(clog.get_logger("SCHTASKS"), vol.os_type)
    st_results = sched.scan(od)
    if st_results and st_results.get("total_findings", 0) > 0:
        sched.write_report(od, st_results)
        msg_ok(f"Scheduled tasks: {st_results['total_findings']} findings "
               f"(Win registry={len(st_results.get('registry_tasks', []))}, "
               f"Linux cron={len(st_results.get('linux_cron', []))}, "
               f"macOS launchd={len(st_results.get('mac_launchd', []))})")
    else:
        msg_info("Scheduled tasks: no evidence found in current extraction data")
    print()

    # Step 6: Registry (Windows-only)
    if vol.os_type == "windows":
        ml.info("=== Step 6: Registry ===")
        msg_info("Step 6/8: Analyzing registry data...")
        reg = RegistryExplorer(clog.get_logger("REGISTRY"))
        reg.load(od)
        reg.write_report(od)
        pers = reg.find_persistence()
        msg_ok(f"Registry: {len(reg.get_hives())} hives, {len(pers)} persistence hits")
    print()

    # Step 7: Timeline
    ml.info("=== Step 7: Evidence Timeline ===")
    msg_info("Step 7/8: Building evidence timeline...")
    tl = Timeline(clog.get_logger("TIMELINE"))
    tl.load(od)
    tl.write_report(od)
    msg_ok(f"Timeline: {len(tl.events)} events")
    print()

    # Step 8: HTML Report
    ml.info("=== Step 8: HTML Report ===")
    msg_info("Step 8/8: Generating HTML report...")
    htmlgen = HTMLReportGenerator(clog.get_logger("HTML"), vol.os_type)
    html_path = htmlgen.generate(od)
    msg_ok(f"HTML report: {html_path}")
    print()

    total = time.time() - t0
    ml.info("%s analysis complete. Duration: %.1fs", label, total)
    print_line()
    print()
    msg_ok(f"{label} ANALYSIS COMPLETE")
    print()
    if not syms_ok:
        msg_warn("No matching symbol table was found — Linux/macOS plugin results "
                 "are expected to be empty. Install the correct ISF and re-run.")
        print()
    msg_info(f"Duration:  {format_duration(total)}")
    msg_info(f"Engine:    {vol.vol_version}" + (f" [{vol.profile}]" if vol.profile else ""))
    msg_info(f"Results:   {od}")
    print()
    msg_info("Directory:")
    print(f"   {od}/")
    for d in ("json/", "txt/", "iocs/",
              "correlation_report.txt", "process_tree.txt",
              "network_map.txt", "registry_report.txt",
              "suspicious_processes.txt", "report.html",
              "SUMMARY.txt", "crescent_toolkit.log"):
        print(f"   +-- {d}")
    print()
    print_line()


def _cmd_default(args):
    """DEFAULT mode: CORE + EVTX dumping."""
    _cmd_core(args)

    # Extra: dump EVTX files
    if not args.image:
        return
    image = _resolve_image_or_exit(args.image)
    od = _resolve_output(args.image, args.output)
    clog = CrescentLogger(str(od), args.quiet, args.log)
    vol = _init_vol_from_existing(clog, image, od, args)

    if vol.os_type == "windows":
        print()
        msg_info("DEFAULT: Dumping .evtx files...")
        fd = FileDumper(vol, clog.get_logger("FILEDUMPER"), args.jobs)
        fj = fd.find_filescan_json(od)
        if fj:
            fd.parse_filescan(fj)
            dr = fd.dump_by_extension(image, "evtx", od / "dumped_files")
            msg_ok(f"EVTX: {dr['dumped_files']} files dumped")
            # Parse the dumped EVTX files
            msg_info("Parsing EVTX files...")
            evtx = EVTXParser(clog.get_logger("EVTX"))
            events = evtx.parse_all(od)
            if events:
                evtx.write_report(od, events)
                interesting = evtx.get_interesting_events(events)
                msg_ok(f"EVTX: {len(events)} events, {len(interesting)} security-relevant")
            else:
                msg_info("No EVTX events parsed")
        else:
            msg_warn("No filescan data for EVTX extraction")

        # Regenerate HTML report with EVTX data included
        msg_info("Regenerating HTML report with EVTX data...")
        htmlgen = HTMLReportGenerator(clog.get_logger("HTML"), vol.os_type)
        htmlgen.generate(od)
        msg_ok("HTML report updated")
    print()
    print_line()
    msg_ok("DEFAULT ANALYSIS COMPLETE")
    print_line()


def _cmd_full(args):
    """Alias for DEFAULT mode (backwards compatibility)."""
    _cmd_default(args)


def _cmd_ctf(args):
    """Only Vol Plugins mode: run the Volatility plugins and all the fast,
    plugin-derived analysis + HTML report, but SKIP the strings/IOC/browser/
    comms scan.

    This is the CORE pipeline with the one slow, evidence-scanning step removed
    — for when you want just the plugin output and the report quickly and don't
    need the strings-based IOC sweep. (CLI: `plugins`, alias `ctf`.)"""
    _cmd_core(args, skip_ioc=True, label="ONLY VOL PLUGINS")


def _cmd_dfir(args):
    """CresCent Eye mode (EXPERIMENTAL): the full CORE analysis pipeline, THEN
    dump every process as its native executable (PE/ELF/Mach-O) and every
    recoverable file.

    Order is CORE first (so detection/symbols/extraction/report are done and a
    SUMMARY.txt exists), then the dump-everything acquisition step reuses that
    prior extraction (no re-detection, no re-extraction) and writes the dumps to
    <output>/dumped_all/.

    WARNING: not fully stable, and it dumps EVERYTHING — expect very large output
    (often many GB) and long runtimes (the per-process memory dumps dominate).
    Use --files-first to recover file content before the heavy process phase.
    CLI: `eye` (alias `dfir`)."""
    print()
    print_line()
    msg_warn("CresCent Eye is EXPERIMENTAL — NOT fully stable.")
    msg_warn("It DUMPS EVERYTHING: every process's memory + every recoverable "
             "file. Expect large output (often many GB) and long runtimes.")
    msg_info("Tip: add --files-first to recover file content before the heavy "
             "process-memory dumps.")
    print_line()
    _cmd_core(args, label="CRESCENT EYE")
    print()
    print_line()
    msg_ok("CresCent Eye: CORE analysis done — dumping ALL processes and files...")
    print_line()
    _cmd_dump_all(args)


# -- Interactive menu --

def _interactive_menu(args):
    vol = VolatilityWrapper(logging.getLogger("_null"), args.timeout)
    vol.find_volatility()
    while True:
        clear_screen()
        print(banner())
        print_line()
        print()
        print(f"   {W}[C]{N} {C}CORE MODE{N}        - Full analysis (no EVTX)")
        print(f"   {W}[D]{N} {G}DEFAULT MODE{N}     - CORE + EVTX dump & parse")
        print(f"   {W}[T]{N} {Y}Only Vol Plugins{N} - Just the Vol plugins (no strings/IOC scan)")
        print(f"   {W}[F]{N} {R}CresCent Eye{N}     - CORE + dump ALL files & procs  "
              f"{Y}(experimental — dumps everything){N}")
        print()
        print_line()
        print()
        print(f"   {W}[1]{N} Extractor        - Run Volatility plugins (parallel)")
        print(f"   {W}[2]{N} File Dumper       - Dump files from memory (parallel)")
        print(f"   {W}[3]{N} Process Dumper    - Dump processes from memory")
        print(f"   {W}[6]{N} Dump ALL          - Every process (PE/ELF/Mach-O) + every file")
        print(f"   {W}[4]{N} Strings           - Extract strings from memory")
        print(f"   {W}[5]{N} Correlator        - Correlate findings")
        print(f"   {W}[7]{N} IOC Extractor     - Extract IOCs from strings/txt")
        print(f"   {W}[8]{N} Process Tree      - ASCII process tree viewer")
        print(f"   {W}[9]{N} Network Map       - External IPs + reverse DNS")
        print(f"   {W}[10]{N} Registry         - Browse registry data")
        print(f"   {W}[13]{N} Browser History  - URLs, searches, downloads")
        print(f"   {W}[14]{N} Comms Scanner    - Teams, Discord, Zoom, Slack...")
        print(f"   {W}[15]{N} Command Analysis - LOLBins, encoded PS, download cradles")
        print(f"   {W}[16]{N} MITRE ATT&CK     - Map findings to technique IDs")
        print(f"   {W}[11]{N} Timeline         - Chronological evidence view")
        print(f"   {W}[12]{N} EVTX Parser      - Parse Windows event logs")
        print(f"   {W}[17]{N} Scheduled Tasks  - schtasks / cron evidence (Win+Linux)")
        print(f"   {W}[18]{N} Registry Altered - Recently modified registry keys")
        print(f"   {W}[19]{N} Popular Files    - Files in Desktop/Downloads/tmp etc.")
        print(f"   {W}[H]{N}  String Hunt      - Search memory for specific strings (YARA)")
        print()
        print(f"   {W}[R]{N} HTML Report       {W}[E]{N} Export Pack (zip)")
        print(f"   {W}[K]{N} ELK/Kibana Export")
        print(f"   {W}[I]{N} Installer          (Vol2 + Vol3 + symbols + deps)")
        print()
        print_line()
        print()
        v3s = f"Found ({vol.vol3_cmd})" if vol.vol3_cmd else "Not found"
        v2s = f"Found ({vol.vol2_cmd})" if vol.vol2_cmd else "Not found"
        print(f"   Vol3: {v3s}")
        print(f"   Vol2: {v2s}")
        print(f"   Jobs: {args.jobs} parallel   Speed: {getattr(args,'speed','normal')}")
        print()
        print(f"   {W}[S]{N} Settings    {W}[Q]{N} Quit")
        print()
        ch = prompt("Select").strip().upper()
        # The interactive pipeline (C/D/T/F) ALWAYS runs the full plugin set:
        # mode is forced to "full" and NOT prompted (by request). Only the CLI
        # (-m) and the standalone Extractor [1] can select a different plugin set.
        # (--speed, which IS prompted, is a separate RAM/jobs knob, not the mode.)
        if ch == "Q":
            msg_info("Goodbye!"); sys.exit(0)
        elif ch == "C":
            ac = argparse.Namespace(**vars(args)); ac.mode = "full"
            _prompt_image(ac)
            if ac.image:
                _prompt_os(ac)
                _prompt_speed(ac)
                _cmd_core(ac); _pause()
        elif ch == "D":
            ac = argparse.Namespace(**vars(args)); ac.mode = "full"
            _prompt_image(ac)
            if ac.image:
                _prompt_os(ac)
                _prompt_speed(ac)
                _cmd_default(ac); _pause()
        elif ch == "T":
            ac = argparse.Namespace(**vars(args)); ac.mode = "full"
            _prompt_image(ac)
            if ac.image:
                _prompt_os(ac)
                _prompt_speed(ac)
                _cmd_ctf(ac); _pause()
        elif ch == "F":
            ac = argparse.Namespace(**vars(args)); ac.mode = "full"
            _prompt_image(ac)
            if ac.image:
                _prompt_os(ac)
                _prompt_speed(ac)
                _prompt_files_first(ac)
                _cmd_dfir(ac); _pause()
        elif ch == "1":
            ac = argparse.Namespace(**vars(args))
            _prompt_image(ac); _prompt_mode(ac)
            if ac.image:
                _prompt_os(ac)
                _cmd_extract(ac); _pause()
        elif ch == "2":
            ac = argparse.Namespace(**vars(args))
            _prompt_image(ac)
            if ac.image:
                _cmd_dump_files(ac); _pause()
        elif ch == "3":
            ac = argparse.Namespace(**vars(args))
            _prompt_image(ac)
            if ac.image:
                _cmd_dump_procs(ac); _pause()
        elif ch == "6":
            ac = argparse.Namespace(**vars(args))
            _prompt_image(ac)
            if ac.image:
                _prompt_os(ac)
                _prompt_files_first(ac)
                _cmd_dump_all(ac); _pause()
        elif ch == "4":
            ac = argparse.Namespace(**vars(args))
            _prompt_image(ac)
            if ac.image:
                _cmd_strings(ac); _pause()
        elif ch == "5":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_correlate(ac); _pause()
        elif ch == "7":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_iocs(ac); _pause()
        elif ch == "8":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_tree(ac); _pause()
        elif ch == "9":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_netmap(ac); _pause()
        elif ch == "10":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_registry(ac); _pause()
        elif ch == "11":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_timeline(ac); _pause()
        elif ch == "12":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_evtx(ac); _pause()
        elif ch == "13":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_browser(ac); _pause()
        elif ch == "14":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_comms(ac); _pause()
        elif ch == "15":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_cmdanalyze(ac); _pause()
        elif ch == "16":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_mitre(ac); _pause()
        elif ch == "17":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_scheduled_tasks(ac); _pause()
        elif ch == "18":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_registry_altered(ac); _pause()
        elif ch == "19":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_popular_files(ac); _pause()
        elif ch == "H":
            ac = argparse.Namespace(**vars(args))
            _prompt_image(ac)
            if ac.image:
                _prompt_output(ac)
                ac.hunt_strings = None   # will prompt interactively
                ac.hunt_pid = None
                ac.hunt_case_sensitive = False
                ac.hunt_no_wide = False
                _cmd_hunt(ac); _pause()
        elif ch == "R":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_report(ac); _pause()
        elif ch == "E":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_export(ac); _pause()
        elif ch == "K":
            ac = argparse.Namespace(**vars(args))
            _prompt_output(ac); _cmd_elk(ac); _pause()
        elif ch == "I":
            _cmd_install(args); _pause()
        elif ch == "S":
            _settings_menu(args, vol)
        else:
            msg_warn("Invalid"); time.sleep(1)


def _settings_menu(args, vol):
    while True:
        clear_screen()
        print(banner())
        print(f"   {W}Settings{N}\n")
        print_line()
        print()
        print(f"   {W}[1]{N} Image    {C}({args.image or 'not set'}){N}")
        print(f"   {W}[2]{N} Output   {C}({args.output or 'auto'}){N}")
        print(f"   {W}[3]{N} Profile  {C}({args.profile or 'auto'}){N}")
        print(f"   {W}[4]{N} Force Vol2")
        print(f"   {W}[5]{N} Force Vol3")
        print(f"   {W}[6]{N} Jobs     {C}({args.jobs}){N}")
        print(f"   {W}[7]{N} Timeout  {C}({args.timeout}s){N}")
        print(f"   {W}[8]{N} Speed    {C}({getattr(args, 'speed', 'normal')}){N}")
        print(f"   {W}[9]{N} Known OS {C}({getattr(args, 'os_hint', 'auto')}){N}")
        _sym = getattr(args, "symbol_isf", None)
        print(f"   {W}[T]{N} Symbol table {C}({Path(_sym).name if _sym else 'auto'}){N}")
        print(f"   {W}[B]{N} Back\n")
        ch = prompt("Select").strip().upper()
        if ch == "B":
            return
        elif ch == "9":
            opts = ["auto", "windows", "linux", "mac"]
            idx = prompt_choice(opts, "Known OS")
            if 0 <= idx < len(opts):
                args.os_hint = opts[idx]
                if args.os_hint not in ("linux", "mac"):
                    args.symbol_isf = None  # symbol table only applies to Linux/mac
                msg_ok(f"Known OS set to: {args.os_hint}"); time.sleep(1)
        elif ch == "T":
            if getattr(args, "os_hint", "auto") not in ("linux", "mac"):
                msg_warn("Set Known OS to Linux/macOS first (option 9)"); time.sleep(1)
            else:
                _prompt_symbol_table(args); time.sleep(1)
        elif ch == "1":
            _prompt_image(args)
        elif ch == "2":
            args.output = prompt("Output directory")
        elif ch == "3":
            args.profile = prompt("Vol2 profile")
        elif ch == "4":
            args.vol2, args.vol3 = True, False; msg_ok("Forced Vol2"); time.sleep(1)
        elif ch == "5":
            args.vol3, args.vol2 = True, False; msg_ok("Forced Vol3"); time.sleep(1)
        elif ch == "6":
            v = prompt("Jobs (2-16)", str(args.jobs))
            try:
                args.jobs = max(2, min(16, int(v)))
            except ValueError:
                pass
        elif ch == "8":
            print("\n   normal  - memory-safe (scales down jobs on low RAM)")
            print("   fast    - tighter RAM budget, allows more parallel jobs")
            print("   fastest - max jobs, no RAM guard (risky on low-RAM systems)")
            v = prompt("Speed (normal/fast/fastest)", getattr(args, "speed", "normal")).strip().lower()
            if v in ("normal", "fast", "fastest"):
                args.speed = v
                msg_ok(f"Speed set to {v}")
                time.sleep(1)
        elif ch == "7":
            v = prompt("Timeout (s)", str(args.timeout))
            try:
                args.timeout = max(30, int(v))
            except ValueError:
                pass


def _prompt_image(args):
    if args.image and Path(args.image).exists():
        u = prompt(f"Use {Path(args.image).name}? (Y/n)", "y")
        if u.lower() != "n":
            return
    imgs = find_memory_images()
    if imgs:
        msg_info(f"Found {len(imgs)} image(s):")
        print()
        for i, im in enumerate(imgs, 1):
            sz = format_size(im.stat().st_size)
            print(f"   {W}[{i}]{N} {im.name:40s} {C}{sz}{N}")
        print(f"   {W}[P]{N} Enter path")
        print()
        sel = prompt(f"Select [1-{len(imgs)}]")
        if sel.upper() == "P":
            args.image = prompt("Path")
        else:
            try:
                idx = int(sel) - 1
                if 0 <= idx < len(imgs):
                    args.image = str(imgs[idx])
            except (ValueError, IndexError):
                pass
    else:
        args.image = prompt("Path to memory image")
    if args.image and Path(args.image).exists():
        msg_ok(f"Selected: {Path(args.image).name}")
    else:
        msg_warn("No valid image"); args.image = None


def _prompt_mode(args):
    idx = prompt_choice(list(VALID_MODES), "Scan Mode")
    if 0 <= idx < len(VALID_MODES):
        args.mode = VALID_MODES[idx]


def _prompt_speed(args):
    """Ask the operator to pick a speed mode before a run."""
    opts = [
        "normal  - memory-safe (best for low-RAM VMs)",
        "fast    - tighter RAM budget, more parallel jobs",
        "fastest - max jobs, no RAM guard (use with 16+ GB RAM)",
    ]
    print()
    idx = prompt_choice(opts, "Speed mode")
    args.speed = ["normal", "fast", "fastest"][idx] if 0 <= idx < 3 else "normal"
    msg_ok(f"Speed: {args.speed}")


def _prompt_files_first(args):
    """Ask whether dump-all/DFIR should recover files before dumping processes."""
    ans = prompt("Dump order:  Enter = processes first  ·  'f' = FILES first "
                 "(recover files before the heavy process-memory dumps)")
    args.files_first = ans.strip().lower() in ("f", "files", "file", "y", "yes")
    if args.files_first:
        msg_ok("Order: files first, then processes")


def _prompt_output(args):
    if not args.output:
        args.output = prompt("Output directory path")


def _prompt_os(args):
    """Ask whether the operator already knows the image's OS.

    Only asks when os_hint is still 'auto' — one Enter keeps auto-detection.
    For a known Linux/macOS image, optionally lets the operator pick the exact
    symbol table from the community repo (skips guessing the kernel build).
    """
    if getattr(args, "os_hint", "auto") != "auto":
        msg_info(f"Known OS: {args.os_hint} (change under Settings)")
        return
    print()
    print("   Do you already know this image's OS? (helps skip detection)")
    opts = ["Auto-detect (recommended)", "Windows", "Linux", "macOS"]
    idx = prompt_choice(opts, "OS")
    args.os_hint = {0: "auto", 1: "windows", 2: "linux", 3: "mac"}.get(idx, "auto")
    if args.os_hint != "auto":
        msg_ok(f"OS set to: {args.os_hint}")
    if args.os_hint in ("linux", "mac"):
        ans = prompt("Symbols:  Enter = auto-resolve  ·  'i' = use your OWN / an "
                     "installed ISF  ·  'y' = browse repo catalogue  ·  or type a "
                     "build (e.g. kali, 5.4.0-42)")
        a = ans.strip()
        if a.lower() in ("", "n", "no"):
            pass  # skip — auto-resolve at run time
        elif a.lower() in ("i", "own", "isf", "mine"):
            _prompt_local_isf(args)          # bring-your-own / installed ISF
        elif a.lower() in ("y", "yes"):
            _prompt_symbol_table(args)       # browse the community repo catalogue
        else:
            # Operator typed a build name directly — jump straight into the
            # catalogue picker pre-filtered by that term.
            _prompt_symbol_table(args, initial_term=a)


def _prompt_local_isf(args):
    """Bring-your-own-ISF picker.

    For operators who already built (or have) their own Volatility 3 ISF: lists
    the ISFs already installed in the symbol store as numbered options (the same
    way RAM dumps are auto-listed), shows an example filename so it's clear what
    an ISF is, and lets them pick one or point at their own .json/.json.xz file.
    Sets args.symbol_isf (a local path) which _resolve_linux_symbols installs.
    """
    from modules import linux_identify
    isfs = linux_identify.list_installed_isfs()
    print()
    print(f"   {W}USE YOUR OWN ISF{N}  (Volatility 3 symbol table)")
    print("   An ISF is a symbol file built from a kernel's debug symbols with")
    print("   dwarf2json — a .json or .json.xz. Example filename:")
    print(f"      {C}Ubuntu_5.15.0-41-generic_5.15.0-41.44_amd64.json.xz{N}")
    print()
    if isfs:
        msg_info(f"{len(isfs)} ISF(s) already installed — pick one, or provide your own:")
        print()
        for i, p in enumerate(isfs, 1):
            try:
                sz = format_size(p.stat().st_size)
            except OSError:
                sz = "?"
            print(f"   {W}[{i}]{N} {p.name:52s} {C}{sz}{N}")
    else:
        msg_info("No ISFs currently installed in the symbol store.")
    print()
    print(f"   {W}[P]{N} Provide the path to your OWN ISF file (.json / .json.xz)")
    print(f"   {W}[A]{N} Auto-resolve (let the tool find or build it)")
    print()
    sel = prompt(f"Select [1-{len(isfs)}], P, or A").strip()

    if sel == "" or sel.upper() == "A":
        args.symbol_isf = None
        msg_info("Will auto-resolve symbols at run time.")
        return
    if sel.upper() == "P":
        path = prompt("Path to your ISF file (.json or .json.xz)").strip()
        p = Path(path).expanduser()
        if p.is_file() and p.name.endswith((".json", ".json.xz")):
            args.symbol_isf = str(p)
            msg_ok(f"Will use your ISF: {p.name}")
        else:
            msg_warn("Not a valid ISF path (need an existing .json/.json.xz) "
                     "— will auto-resolve instead.")
            args.symbol_isf = None
        return
    try:
        idx = int(sel) - 1
        if 0 <= idx < len(isfs):
            args.symbol_isf = str(isfs[idx])
            msg_ok(f"Will use installed ISF: {isfs[idx].name}")
            return
    except ValueError:
        pass
    msg_warn("Invalid selection — will auto-resolve.")
    args.symbol_isf = None


def _open_symbol_catalogue_file(cat):
    """Write every available symbol-table name to a txt file and open it.

    With ~10k+ builds the list is too long to scroll in the terminal, so we
    dump it to a file and launch the system's default viewer — the operator
    can browse it side-by-side and copy a build string into the search box.
    """
    import tempfile
    import shutil
    import subprocess
    names = sorted(
        (paths[0] if isinstance(paths, list) else paths)
        for paths in cat.values()
    )
    path = Path(tempfile.gettempdir()) / "crescent_symbol_tables.txt"
    try:
        path.write_text(
            f"# {len(names)} Volatility 3 Linux/mac symbol tables "
            "(Abyss-W4tcher/volatility3-symbols)\n"
            "# Search for any fragment below in the toolkit's search box.\n\n"
            + "\n".join(names),
            encoding="utf-8",
        )
    except Exception as e:
        msg_warn(f"Could not write catalogue file: {e}")
        return
    msg_ok(f"Wrote {len(names)} symbol-table names → {path}")
    opener = next((c for c in ("xdg-open", "open") if shutil.which(c)), None)
    if opener:
        try:
            subprocess.Popen([opener, str(path)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            msg_info("Opened the full list in your default viewer")
            return
        except Exception:
            pass
    msg_info(f"Open it manually to browse: {path}")


def _prompt_symbol_table(args, initial_term=None):
    """Browse the bundled symbol-table catalogue and pick one by build.

    Uses the catalogue of available build names shipped with the tool (no ISF
    data); the chosen ISF is downloaded/installed at run time via
    _resolve_linux_symbols(). If initial_term is given, the first search uses
    it directly instead of prompting.
    """
    from modules import linux_identify
    cat = linux_identify.fetch_available_symbol_names()
    if not cat:
        msg_warn("Symbol-table catalogue unavailable — will auto-resolve at run time")
        return
    msg_ok(f"{len(cat)} kernel builds available in the catalogue")
    pending = initial_term.strip() if initial_term else None
    if not pending:
        _open_symbol_catalogue_file(cat)
    while True:
        if pending:
            term, pending = pending, None
        else:
            term = prompt("Search build (e.g. 5.4.0-42, 'ubuntu 20.04'); "
                          "blank = open full list, 'q' to cancel")
        if term.strip().lower() == "q":
            return
        if not term.strip():
            _open_symbol_catalogue_file(cat)
            continue
        all_matches = linux_identify.search_symbol_catalogue(cat, term, limit=100000)
        if not all_matches:
            msg_warn("No matches — try a different term")
            continue
        matches = all_matches[:40]
        print()
        for i, (banner, isf) in enumerate(matches, 1):
            print(f"   {W}[{i}]{N} {isf}")
        print()
        if len(all_matches) > len(matches):
            msg_info(f"Showing {len(matches)} of {len(all_matches)} matches — "
                     "refine your search (e.g. add the version) to narrow it down")
        sel = prompt(f"Select [1-{len(matches)}], or blank to search again")
        if not sel.strip():
            continue
        try:
            idx = int(sel) - 1
            if 0 <= idx < len(matches):
                args.symbol_isf = matches[idx][1]
                msg_ok(f"Selected symbol table: {Path(args.symbol_isf).name}")
                return
        except ValueError:
            pass
        msg_warn("Invalid selection")


def _pause():
    print()
    try:
        input("   Press Enter to continue...")
    except (EOFError, KeyboardInterrupt):
        pass



def main():
    # Route all scratch/temp to the large Desktop workspace (not the small /tmp
    # tmpfs) BEFORE anything allocates a temp dir — the ISF build pipeline needs
    # several GB of scratch that /tmp cannot hold.
    try:
        from modules import workspace
        workspace.setup()
    except Exception:
        pass
    parser = _build_parser()
    args = parser.parse_args()
    # Interactive-only settings (no CLI flag): OS hint + chosen Linux symbol table.
    args.os_hint = getattr(args, "os_hint", "auto")
    args.symbol_isf = getattr(args, "symbol_isf", None)
    try:
        dispatch = {
            "menu": lambda: _interactive_menu(args),
            "extract": lambda: _cmd_extract(args),
            "dump-files": lambda: _cmd_dump_files(args),
            "dump-procs": lambda: _cmd_dump_procs(args),
            "dump-all": lambda: _cmd_dump_all(args),
            "strings": lambda: _cmd_strings(args),
            "correlate": lambda: _cmd_correlate(args),
            "iocs": lambda: _cmd_iocs(args),
            "report": lambda: _cmd_report(args),
            "timeline": lambda: _cmd_timeline(args),
            "evtx": lambda: _cmd_evtx(args),
            "export": lambda: _cmd_export(args),
            "elk": lambda: _cmd_elk(args),
            "core": lambda: _cmd_core(args),
            "full": lambda: _cmd_default(args),
            "plugins": lambda: _cmd_ctf(args),
            "ctf": lambda: _cmd_ctf(args),
            "eye": lambda: _cmd_dfir(args),
            "dfir": lambda: _cmd_dfir(args),
            "hunt": lambda: _cmd_hunt(args),
        }
        dispatch.get(args.command, lambda: _interactive_menu(args))()
    except KeyboardInterrupt:
        print()
        msg_info("Interrupted. Partial results may have been saved.")
        sys.exit(130)
    except Exception as exc:
        msg_fail(f"Error: {exc}")
        try:
            od = _resolve_output(args.image, args.output)
            CrescentLogger(str(od), quiet=True).get_logger("MAIN").critical(
                "Unhandled: %s", exc, exc_info=True)
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()
