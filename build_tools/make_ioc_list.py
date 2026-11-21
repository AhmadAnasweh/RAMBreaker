"""Build a large IOC test list: known-present values (from an IOC run on the
same dump) + known-absent synthetic indicators. Writes <out> and <out>.truth.json"""

import json
import random
import sys
from pathlib import Path


def main(ioc_results: Path, out: Path, n_present=80, n_absent=120, seed=11):
    rnd = random.Random(seed)
    res = json.loads(ioc_results.read_text(encoding="utf-8")).get("results", {})
    pool = []
    for k in ("ipv4", "domain", "url_http", "email"):
        vals = [v for v in res.get(k, {}).get("values", []) if 6 <= len(v) <= 120]
        rnd.shuffle(vals)
        pool += [(k, v) for v in vals[: n_present // 4 + 10]]
    rnd.shuffle(pool)
    present = pool[:n_present]
    absent = []
    for i in range(n_absent):
        t = i % 4
        if t == 0:
            absent.append(("ipv4", f"203.0.{rnd.randint(114, 250)}.{rnd.randint(1, 254)}"))
        elif t == 1:
            absent.append(("domain", f"zq{rnd.randint(10**5, 10**6)}-c2.example-bad.net"))
        elif t == 2:
            absent.append(("url", f"hxxp://evil{rnd.randint(1000, 9999)}[.]example[.]org/gate.php"))
        else:
            absent.append(("sha256", "%064x" % rnd.getrandbits(256)))
    # boundary traps: look-alikes of present values must NOT be reported
    for k, v in present[:5]:
        if k == "ipv4" and v.count(".") == 3:
            a, b, c, d = v.split(".")
            if int(d) < 25:
                absent.append(("ipv4", f"{a}.{b}.{c}.{int(d) * 10 + 9}"))
    lines = ["# RAMBreaker IOC checker test list", "type,value,comment"]
    lines += [f"{k},{v},present" for k, v in present]
    lines += [f"{k},{v},absent" for k, v in absent]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    truth = {"present": [v for _, v in present], "absent": [v for _, v in absent]}
    out.with_suffix(".truth.json").write_text(json.dumps(truth, indent=1), encoding="utf-8")
    print(f"{len(present)} present, {len(absent)} absent -> {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
