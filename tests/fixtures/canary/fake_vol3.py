#!/usr/bin/env python3
"""Fake Volatility 3 CLI — the canary's "tiny fixture".

Invoked exactly like the real thing by VolatilityWrapper._run_vol3:

    python3 fake_vol3.py -f <image> -r json <plugin>

It reads NO memory image; it just emits canned, deterministic output per plugin
so the REAL extractor / parser / resume / run_health / crash_report / HTML-report
code can be exercised end-to-end without a multi-GB dump. The behaviours are
chosen to cover every branch the extraction path has:

  * success           -> JSON rows on stdout, rc 0
  * clean-empty       -> "[]" on stdout, rc 0            (legit empty, NOT a fail)
  * silent-struct-fail-> "[]" on stdout + AttributeError on stderr, rc 0
                         (must be DEMOTED to a failure by _vol3_success)
  * hard-fail         -> traceback on stderr, rc 1       (failure + .error sidecar)

One pslist row carries an XSS payload as its process name so the canary can prove
report.html neutralises hostile memory strings.
"""
import json
import sys


def _rows(n, tag="proc"):
    return [{"PID": 100 + i, "PPID": 1, "COMM": f"{tag}{i}",
             "CREATE TIME": "2026-07-11 00:00:00"} for i in range(n)]


# short plugin name (linux.pslist.PsList -> "pslist") -> (mode, payload)
BEHAVIOUR = {
    "pslist":        ("ok", [{"PID": 1, "PPID": 0, "COMM": "systemd"},
                             {"PID": 2, "PPID": 1,
                              "COMM": "<script>alert(1)</script>"}] + _rows(3)),
    "psscan":        ("ok", _rows(9, "scan")),   # pool scan finds more (normal)
    "pstree":        ("ok", _rows(4)),
    "psaux":         ("ok", _rows(5)),
    "lsof":          ("ok", _rows(30, "fd")),
    "sockstat":      ("empty", []),              # clean-empty -> network WARN
    "check_modules": ("empty", []),
    "bash":          ("empty", []),
    "pagecache":     ("empty", []),
    "lsmod":         ("demote", []),             # silent struct failure
    "proc":          ("hardfail", None),         # linux.proc.Maps -> rc 1
}


def _short(plugin):
    parts = plugin.split(".")
    if len(parts) >= 2 and parts[0] in ("linux", "windows", "mac"):
        return parts[1].lower()
    return parts[0].lower()


def main(argv):
    plugin = argv[-1] if argv else ""      # extractor always appends plugin last
    short = _short(plugin)
    mode, payload = BEHAVIOUR.get(short, ("empty", []))

    if mode == "hardfail":
        sys.stderr.write(
            "Volatility 3 Framework 2.28.1\n"
            "Traceback (most recent call last):\n"
            "  File \"vol.py\", line 1, in <module>\n"
            "Unhandled exception: could not read layer\n")
        return 1
    if mode == "demote":
        sys.stdout.write("[]")
        sys.stderr.write(
            "Volatility 3 Framework 2.28.1\n"
            "Progress:  100.00\t\tScanning\n"
            "AttributeError: 'module' object has no attribute 'taint_flag'\n")
        return 0
    # ok / empty
    sys.stdout.write(json.dumps(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
