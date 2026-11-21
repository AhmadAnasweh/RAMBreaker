"""Back-fill plugin runtimes from finished runs into a timing_samples.jsonl.

Usage: python backfill_timings.py <output_root> <timing_samples.jsonl> [--merge other.jsonl] [--fit]

For every <output_root>/<case>/ with SUMMARY.txt (Image:, OS:) and
crescent_toolkit.log, the log is parsed by timeout_model.import_run_log and the
records not already present (same plugin/engine/os/size and duration within
0.1 s, or same timeout for timed-out runs) are appended. --fit re-fits
timeouts.json next to the samples file. Used to recover calibration data that
earlier builds overwrote; safe to re-run (idempotent).
"""
import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from modules import timeout_model as tm  # noqa: E402


def _key(r):
    base = (r["plugin"], r["engine"], r["os"], round(r["size_gb"], 2), bool(r["timed_out"]))
    return base + ((int(r.get("timeout_s") or r["duration"]),) if r["timed_out"]
                   else (round(r["duration"], 1),))


def main():
    out_root, target = Path(sys.argv[1]), Path(sys.argv[2])
    have = []
    if target.is_file():
        have = [json.loads(l) for l in target.read_text(encoding="utf-8").splitlines() if l.strip()]
    seen = {_key(r) for r in have}
    added = 0
    if "--merge" in sys.argv:
        other = Path(sys.argv[sys.argv.index("--merge") + 1])
        if other.is_file() and other.resolve() != target.resolve():
            n = 0
            for l in other.read_text(encoding="utf-8").splitlines():
                try:
                    r = json.loads(l)
                    k = _key(r)
                except Exception:
                    continue
                if k not in seen:
                    seen.add(k)
                    have.append(r)
                    n += 1
            added += n
            print(f"  merged {n} new from {other}")
    cases = sorted(p for p in out_root.iterdir() if p.is_dir()) if out_root.is_dir() else []
    for case in cases:
        summ, log = case / "SUMMARY.txt", case / "crescent_toolkit.log"
        if not (summ.is_file() and log.is_file()):
            continue
        txt = summ.read_text(encoding="utf-8", errors="replace")
        mi, mo = re.search(r"^Image:\s*(.+)$", txt, re.M), re.search(r"^OS:\s*(\w+)", txt, re.M)
        if not (mi and mo) or not Path(mi.group(1).strip()).is_file():
            print(f"  skip {case.name}: image/OS unknown")
            continue
        with tempfile.TemporaryDirectory() as td:
            m = tm.TimeoutModel(Path(td))
            tm.import_run_log(m, log, mi.group(1).strip(), mo.group(1).lower())
            new = m.load_samples()
        n = 0
        for r in new:
            k = _key(r)
            if k in seen:
                continue
            seen.add(k)
            r["src"] = f"log:{case.name}"
            have.append(r)
            n += 1
        added += n
        print(f"  {case.name}: {len(new)} parsed, {n} new")
    # samples recorded before the model knew image formats: tag them from the
    # case images (same OS + size -> that image's header), default raw
    fmt_of = {}
    for case in cases:
        summ = case / "SUMMARY.txt"
        if summ.is_file():
            txt = summ.read_text(encoding="utf-8", errors="replace")
            mi, mo = re.search(r"^Image:\s*(.+)$", txt, re.M), re.search(r"^OS:\s*(\w+)", txt, re.M)
            if mi and mo and Path(mi.group(1).strip()).is_file():
                img = mi.group(1).strip()
                fmt_of[(mo.group(1).lower(), round(tm.image_size_gb(img), 2))] = tm.image_profile(img)
    tagged = 0
    for r in have:
        if "fmt" not in r:
            r["fmt"] = fmt_of.get((r["os"], round(r["size_gb"], 2)), "raw")
            tagged += r["fmt"] != "raw"
    if tagged:
        print(f"  tagged {tagged} earlier samples as non-raw image formats")
    target.write_text("".join(json.dumps(r) + "\n" for r in have), encoding="utf-8")
    print(f"added {added}; total {len(have)} samples -> {target}")
    if "--fit" in sys.argv:
        cfg = tm.TimeoutModel(target.parent).fit()
        print(f"fitted {len(cfg['plugins'])} plugins from {cfg['fitted_from_samples']} samples")


if __name__ == "__main__":
    main()
