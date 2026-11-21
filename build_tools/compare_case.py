"""Compare a freshly analysed case folder with the v2.3 snapshot (tests_data/baseline_v23.json).

usage: compare_case.py <new_case_dir> <baseline_case_name> [--snapshot file]
Prints one line per difference (plugin JSON missing / new / row count changed / .error
sidecars / timeouts) and a one-line verdict. Sizes of outputs that legitimately vary
(timestamps, durations) are not compared; row counts are.
"""
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def rows_of(p: Path):
    size = p.stat().st_size
    if size > 150 * 1024 * 1024:
        n = 0
        with open(p, "rb") as f:
            while True:
                b = f.read(8 << 20)
                if not b:
                    break
                n += b.count(b'"__children"')
        return {"approx_children_markers": n}
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            d = json.load(f)
    except Exception as e:
        return {"parse_error": str(e)[:80]}
    if isinstance(d, list):
        return {"rows": len(d)}
    if isinstance(d, dict):
        return {"keys": len(d)}
    return {"type": type(d).__name__}


def main():
    new = Path(sys.argv[1])
    name = sys.argv[2]
    snap_file = HERE / "tests_data" / "baseline_v23.json"
    if "--snapshot" in sys.argv:
        snap_file = Path(sys.argv[sys.argv.index("--snapshot") + 1])
    snap = json.loads(snap_file.read_text(encoding="utf-8"))
    if name not in snap:
        print(f"NO BASELINE for {name}")
        return 2
    old = snap[name]["plugins"]
    jd = new / "json"
    cur = {}
    for fn in sorted(os.listdir(jd)):
        p = jd / fn
        if p.is_file():
            e = {"size": p.stat().st_size}
            if fn.endswith(".json"):
                e.update(rows_of(p))
            cur[fn] = e
    diffs = same = 0
    for fn in sorted(set(old) | set(cur)):
        o, c = old.get(fn), cur.get(fn)
        if fn.startswith("_") or fn.endswith((".tmp", ".part")):
            continue
        if o is None:
            print(f"  NEW      {fn}  {c}")
            diffs += 1
        elif c is None:
            print(f"  MISSING  {fn}  (old: {o})")
            diffs += 1
        else:
            ko = {k: v for k, v in o.items() if k != "size"}
            kc = {k: v for k, v in c.items() if k != "size"}
            if ko != kc:
                print(f"  CHANGED  {fn}  old {ko} ({o['size']} B) -> new {kc} ({c['size']} B)")
                diffs += 1
            else:
                same += 1
    for label, src in (("old", snap[name]["files"].get("json/_timeouts.json", "")),
                       ("new", (jd / "_timeouts.json").read_text(encoding="utf-8", errors="replace")
                        if (jd / "_timeouts.json").is_file() else "")):
        try:
            t = json.loads(src) if src.strip() else []
            print(f"  timeouts {label}: " + (", ".join(f"{x.get('plugin')}[{x.get('status')}]" for x in t) or "none"))
        except Exception:
            print(f"  timeouts {label}: (unreadable)")
    errs = [f for f in cur if f.endswith(".error")]
    olderrs = [f for f in old if f.endswith(".error")]
    print(f"  .error sidecars: old {len(olderrs)} {olderrs[:6]} / new {len(errs)} {errs[:6]}")
    print(f"VERDICT {name}: {same} identical row counts, {diffs} differences")
    return 0


if __name__ == "__main__":
    sys.exit(main())
