"""Score ioc_check.json against the truth file from make_ioc_list.py."""
import json
import sys
from pathlib import Path

res = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["results"]
truth = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
found = {r["value"].lower(): r for r in res}
norm = lambda v: v.lower().replace("hxxp", "http").replace("[.]", ".")
tp = [v for v in truth["present"] if found.get(norm(v), {}).get("found")]
fn = [v for v in truth["present"] if not found.get(norm(v), {}).get("found")]
fp = [v for v in truth["absent"] if found.get(norm(v), {}).get("found")]
print(f"present={len(truth['present'])} TP={len(tp)} FN={len(fn)}  absent={len(truth['absent'])} FP={len(fp)}")
for v in fn:
    print("  MISSED:", v)
for v in fp:
    print("  FALSE HIT:", v)
withproc = [r for r in res if r.get("processes")]
print(f"IOCs attributed to processes: {len(withproc)}; examples:",
      [(r['value'], r['processes'][:3]) for r in withproc[:4]])
