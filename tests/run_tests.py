#!/usr/bin/env python3
"""Tier-A golden tests — fast, no memory images, zero third-party deps.

Run:  python3 tests/run_tests.py     (exit 0 = all pass, non-zero = failure)

These pin the pure, kernel-independent logic — the parsing/health/IOC code that
is *your* code, not Volatility's — so old bugs (e.g. the Bug-#10 silent-empty
process list) can't silently come back. They deliberately do NOT drive
Volatility; the canary matrix (a later step) covers real images.
"""

import sys
import json
import logging
import os
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIX = Path(__file__).resolve().parent / "fixtures"

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  PASS  {name}")
    else:
        _FAIL += 1
        print(f"  FAIL  {name}   {detail}")


# --------------------------------------------------------------------------- #
def test_corroborate_processes():
    from modules import run_health as rh
    C = rh.CRITICAL
    print("[corroborate_processes]")

    ok = rh.corroborate_processes({"pslist": 37, "psscan": 37, "pstree": 37})
    check("healthy run -> no findings", ok == [], detail=str(ok))

    bug10 = rh.corroborate_processes({"pslist": 0, "psscan": 120, "pstree": 0})
    check("Bug-#10 (pslist=0, psscan=120) -> CRITICAL",
          any(f["severity"] == C for f in bug10), detail=str(bug10))
    check("Bug-#10 message names psscan",
          any("psscan" in f["message"] for f in bug10))

    empty = rh.corroborate_processes({"pslist": 0, "psscan": 0, "pstree": 0})
    check("all-empty -> CRITICAL", any(f["severity"] == C for f in empty))

    none = rh.corroborate_processes({"pslist": None, "psscan": None, "pstree": None})
    check("no plugins ran -> CRITICAL", any(f["severity"] == C for f in none))

    hidden = rh.corroborate_processes({"pslist": 40, "psscan": 60, "pstree": 40})
    check("psscan>>pslist -> WARN (not critical)",
          hidden and all(f["severity"] != C for f in hidden), detail=str(hidden))

    # H1: psaux fallback corroboration when no pool-scan source ran (e.g. macOS).
    macbug = rh.corroborate_processes({"pslist": 0, "psscan": None,
                                       "pstree": 0, "psaux": 88}, "mac")
    check("mac psaux>0 + pslist empty + no psscan -> CRITICAL",
          any(f["severity"] == C for f in macbug), detail=str(macbug))
    check("mac fallback message names psaux",
          any("psaux" in f["message"] for f in macbug))
    macok = rh.corroborate_processes({"pslist": 50, "psscan": None,
                                      "pstree": 50, "psaux": 50}, "mac")
    check("mac healthy (no psscan, pslist==psaux) -> no findings",
          macok == [], detail=str(macok))
    both = rh.corroborate_processes({"pslist": 0, "psscan": 120,
                                     "pstree": 0, "psaux": 0}, "linux")
    check("psscan Bug-#10 still fires when psaux also present",
          any("psscan" in f["message"] for f in both))
    # H1: on Linux, scan ≫ list is normal (dead task_structs) — must NOT WARN.
    lin_excess = rh.corroborate_processes({"pslist": 232, "psscan": 904,
                                           "pstree": 200, "psaux": 232}, "linux")
    check("linux psscan≫pslist -> no noise WARN", lin_excess == [],
          detail=str(lin_excess))
    win_excess = rh.corroborate_processes({"pslist": 40, "psscan": 90,
                                           "pstree": 40}, "windows")
    check("windows psscan≫pslist -> WARN kept",
          any("exceeds" in f["message"] for f in win_excess))


def test_classify_failure():
    from modules import run_health as rh
    print("[classify_failure]")
    cases = {
        "AttributeError: 'taint_flag' object has no attribute 'module'": "struct-mismatch",
        "Member not present in template: mnt": "struct-mismatch",
        "No matching ISF for this banner": "symbol-missing",
        "A symbol table requirement was not fulfilled": "symbol-missing",
        "plugin timed out after 600s": "timeout",
    }
    for text, expected in cases.items():
        got = rh.classify_failure(text)["category"]
        check(f"{expected:16} <- {text[:40]!r}", got == expected, detail=f"got {got}")

    # Expected-nonbugs are recognised by PLUGIN NAME, regardless of error text.
    banner = "Volatility Foundation Volatility Framework 2.6.1"
    for name in ("connections", "connscan", "sockets", "sockstat"):
        got = rh.classify_failure(banner, name)["category"]
        check(f"expected-nonbug by name: {name}", got == "expected-nonbug",
              detail=f"got {got}")

    # Banner-only / empty error = benign empty result, not a real failure.
    check("banner-only error -> empty-result",
          rh.classify_failure(banner, "ssdt")["category"] == "empty-result")
    check("empty error -> empty-result",
          rh.classify_failure("", "whatever")["category"] == "empty-result")


def test_assess_fixtures():
    from modules import run_health as rh
    print("[assess() on fixtures]")

    good = rh.assess(FIX / "good_win", "windows")
    check("healthy fixture -> status healthy",
          good["status"] == "healthy", detail=good["status"])
    check("healthy fixture -> no critical findings",
          all(f["severity"] != rh.CRITICAL for f in good["findings"]))

    bug = rh.assess(FIX / "bug10_win", "windows")
    check("Bug-#10 fixture -> status broken",
          bug["status"] == "broken", detail=bug["status"])
    check("Bug-#10 fixture -> critical process finding",
          any(f["check"] == "processes" and f["severity"] == rh.CRITICAL
              for f in bug["findings"]))


def test_advisory_nonempty():
    from modules import run_health as rh
    print("[advisory_nonempty]")
    W, C = rh.WARN, rh.CRITICAL

    f = rh.advisory_nonempty("windows", {"svcscan": 0, "modules": 120})
    check("windows empty svcscan -> WARN",
          any(x["check"] == "svcscan" and x["severity"] == W for x in f), detail=str(f))
    check("windows non-empty modules -> not flagged",
          not any(x["check"] == "modules" for x in f))

    check("plugin that didn't run (None) -> not flagged",
          rh.advisory_nonempty("windows", {"svcscan": None, "modules": None}) == [])
    check("linux non-empty lsof -> no WARN",
          rh.advisory_nonempty("linux", {"lsof": 4200}) == [])

    f4 = rh.advisory_nonempty("linux", {"lsof": 0})
    check("linux empty lsof -> WARN", any(x["check"] == "lsof" for x in f4))
    check("advisory findings are never critical",
          all(x["severity"] != C for x in f + f4))
    check("unknown os -> no advisory", rh.advisory_nonempty("plan9", {"x": 0}) == [])


def test_ioc_extractor():
    from modules.ioc_extractor import IOCExtractor
    print("[ioc_extractor.scan_single_string]")
    ie = IOCExtractor(logging.getLogger("test"))

    def cats(s):
        return {r["category"] for r in ie.scan_single_string(s)}

    def matches(s):
        return {r["match"] for r in ie.scan_single_string(s)}

    check("plain prose -> NO IOCs (false-positive guard)",
          cats("hello world this is a normal sentence") == set(),
          detail=str(cats("hello world this is a normal sentence")))
    check("public IP -> network category",
          "network" in cats("attacker at 203.0.113.45 connected"))
    check("URL -> network category",
          "network" in cats("beacon to http://evil.example.com/c2"))
    check("email -> email category",
          "email" in cats("contact bad.actor@evil.com"))
    btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    check("bitcoin address -> crypto, exact match",
          "crypto" in cats(f"pay {btc}") and btc in matches(f"pay {btc}"))


# Frozen whitelist of top-level keys crash_report.build may ever emit. A new key
# here must be a deliberate, reviewed change — this guards against a future field
# silently carrying image-derived data into the handoff artifact.
_CRASH_KEYS = {
    "schema", "generated", "note", "tool_version", "run", "host", "target",
    "toolchain", "process_corroboration", "findings", "failed_plugins",
    "ok_plugins", "fingerprint",
}


def test_crash_report():
    from modules import crash_report as cr
    from modules import run_health as rh
    print("[crash_report]")

    # --- scrub(): every sensitive shape is redacted ---
    s = cr.scrub("read /home/kali/case/dump.raw at 0xdeadbeef and "
                 "C:\\Users\\victim\\m.exe")
    check("scrub redacts unix user path", "/home/kali" not in s, detail=s)
    check("scrub redacts windows path", "victim" not in s, detail=s)
    check("scrub redacts hex address", "0xdeadbeef" not in s, detail=s)
    check("scrub inserts placeholders", "<path>" in s and "<addr>" in s, detail=s)

    # --- parse_kernel_banner(): version+distro only, builder identity dropped ---
    banner = ("Linux version 6.1.0-kali9-amd64 (devel@buildbox) "
              "(gcc 13) #1 SMP Kali 6.1.27-1kali1")
    pk = cr.parse_kernel_banner(banner)
    check("banner -> kernel version", pk["kernel"] == "6.1.0-kali9-amd64",
          detail=str(pk))
    check("banner -> distro Kali", pk["distro"] == "Kali", detail=str(pk))
    check("banner builder user@host NOT retained",
          "buildbox" not in json.dumps(pk) and "devel@" not in json.dumps(pk))
    check("ubuntu banner -> Ubuntu",
          cr.distro_from_banner("Linux version 5.15.0-91 (Ubuntu 11.4)") == "Ubuntu")

    # --- fingerprint(): 16 hex chars, order-independent ---
    tgt = {"os_type": "linux", "engine": "vol3", "kernel": "6.1", "distro": "Kali"}
    f1 = cr.fingerprint(tgt, [{"plugin": "a", "category": "x"},
                              {"plugin": "b", "category": "y"}])
    f2 = cr.fingerprint(tgt, [{"plugin": "b", "category": "y"},
                              {"plugin": "a", "category": "x"}])
    check("fingerprint stable + order-independent",
          f1 == f2 and len(f1) == 16, detail=f"{f1} vs {f2}")

    # --- build(): whitelisted keys only, correct status, no leakage ---
    health = {
        "status": "degraded",
        "process_counts": {"pslist": 5, "psscan": 5, "pstree": 5},
        "findings": [{"severity": "warning", "check": "files",
                      "message": "empty at /home/zztopsecret/case 0xCAFEB0BE"}],
        "failure_taxonomy": [{"plugin": "linux.lsof.Lsof",
                              "category": "struct-mismatch",
                              "reason": "read /home/zzanalyst/x on 0x41414141"}],
    }
    rep = cr.build(FIX / "good_win", os_type="linux", engine="vol3", profile=None,
                   mode="full",
                   results={"ok": 10, "fail": 1, "duration": 12.3,
                            "skipped": 0, "dep_skipped": 0},
                   health=health)
    check("build emits only whitelisted keys",
          set(rep) == _CRASH_KEYS, detail=str(set(rep) ^ _CRASH_KEYS))
    check("build carries status through", rep["run"]["status"] == "degraded")
    check("build maps taxonomy -> failed_plugins",
          rep["failed_plugins"] and rep["failed_plugins"][0]["name"] == "linux.lsof.Lsof")
    blob = json.dumps(rep)
    check("build leaks NO target path", "zztopsecret" not in blob
          and "zzanalyst" not in blob, detail="path leaked into report")
    check("build leaks NO raw address", "0xCAFEB0BE" not in blob
          and "0x41414141" not in blob)
    check("build scrubs into placeholders", "<path>" in blob and "<addr>" in blob)

    # --- _should_write(): fires on real trouble, silent on benign-only ---
    sw = cr._should_write
    check("healthy + no failures -> no report",
          sw({"fail": 0}, {"status": "healthy", "failure_taxonomy": []}) is False)
    check("healthy + only expected-nonbug/empty -> no report",
          sw({"fail": 2}, {"status": "healthy",
             "failure_taxonomy": [{"category": "expected-nonbug"},
                                  {"category": "empty-result"}]}) is False)
    check("healthy + a real failure (timeout) -> report",
          sw({"fail": 1}, {"status": "healthy",
             "failure_taxonomy": [{"category": "timeout"}]}) is True)
    check("degraded status -> report",
          sw({"fail": 0}, {"status": "degraded", "failure_taxonomy": []}) is True)
    check("failures present but unclassified -> report",
          sw({"fail": 3}, {"status": "healthy", "failure_taxonomy": []}) is True)

    # --- write(): artifact only on real failure; benign/clean runs leave nothing ---
    v = types.SimpleNamespace(os_type="windows", vol_version="vol3", profile=None)
    good_health = rh.assess(FIX / "good_win", "windows")
    none_path = cr.write(FIX / "good_win", "img.raw", v,
                         "full", {"ok": 5, "fail": 0}, good_health)
    check("healthy run writes NO crash_report", none_path is None, detail=str(none_path))

    bug_health = rh.assess(FIX / "bug10_win", "windows")
    out = cr.write(FIX / "bug10_win", "img.raw", v,
                   "full", {"ok": 1, "fail": 0, "duration": 3.0}, bug_health)
    try:
        check("broken run writes crash_report.json",
              out is not None and Path(out).is_file(), detail=str(out))
        if out and Path(out).is_file():
            data = json.loads(Path(out).read_text())
            check("written report has broken status",
                  data["run"]["status"] == "broken", detail=str(data["run"]))
            check("ok_plugins excludes bookkeeping files",
                  "run_health" not in data["ok_plugins"]
                  and "crash_report" not in data["ok_plugins"])
    finally:
        if out and Path(out).is_file():
            Path(out).unlink()  # keep fixtures pristine


def test_vol3_demotion():
    from modules.volatility import (_vol3_success, _is_empty_result,
                                    _is_plugin_exception, _write_error_marker)
    print("[vol3 silent-failure demotion]")
    ATTR = "AttributeError: 'module' object has no attribute 'taint_flag'"

    # _is_empty_result
    check("'[]' is empty", _is_empty_result("[]"))
    check("'[\\n]' is empty (whitespace-tolerant)", _is_empty_result("[\n]"))
    check("real rows not empty", not _is_empty_result('[{"pid":1}]'))

    # _is_plugin_exception — systemic only, no benign demotes
    check("AttributeError -> exception", _is_plugin_exception(ATTR))
    check("not-present-in-template -> exception",
          _is_plugin_exception("Member not present in template: mnt"))
    check("clean banner -> not exception",
          not _is_plugin_exception("Volatility 3 Framework 2.28.1"))
    check("warning -> not exception (won't demote)",
          not _is_plugin_exception("UserWarning: deprecated"))
    check("empty stderr -> not exception", not _is_plugin_exception(""))

    # _vol3_success — the core new-kernel demotion
    check("linux rc0 + rows -> success",
          _vol3_success(0, '[{"pid":1}]', "", "linux"))
    check("linux rc0 + clean-empty -> success (no false demote)",
          _vol3_success(0, "[]", "", "linux"))
    check("linux rc0 + EMPTY + struct exc -> DEMOTED to fail",
          not _vol3_success(0, "[]", ATTR, "linux"))
    check("linux rc0 + ROWS + struct exc -> kept (evidence-preserving)",
          _vol3_success(0, '[{"pid":1}]', ATTR, "linux"))
    check("mac rc0 + empty + struct exc -> DEMOTED",
          not _vol3_success(0, "[]", ATTR, "mac"))
    check("rc!=0 -> fail", not _vol3_success(1, '[{"pid":1}]', "", "linux"))
    check("stdout 'Unsatisfied requirement' -> fail",
          not _vol3_success(0, "Unsatisfied requirement for kernel", "", "linux"))
    check("windows rc0 + empty -> fail (unchanged)",
          not _vol3_success(0, "[]", "", "windows"))
    check("windows rc0 + real rows -> success (unchanged)",
          _vol3_success(0, '[{"pid":1,"name":"System"}]', "", "windows"))

    # _write_error_marker — resume sidecar lifecycle (fixes cache poisoning)
    import tempfile, shutil
    d = Path(tempfile.mkdtemp())
    try:
        jp = d / "linux_lsmod_Lsmod.json"
        jp.write_text("[]")
        marker = Path(str(jp) + ".error")
        _write_error_marker(jp, False, ATTR)
        check("failure leaves .error sidecar",
              marker.exists() and "taint_flag" in marker.read_text())
        _write_error_marker(jp, True, "")
        check("success clears .error sidecar", not marker.exists())
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_telemetry():
    from modules import crash_report as cr
    import tempfile, threading, shutil
    from http.server import BaseHTTPRequestHandler, HTTPServer
    print("[telemetry / Step 2 transport]")

    # Isolate config to a temp file so the real ~/.config is never touched.
    tmpdir = Path(tempfile.mkdtemp())
    os.environ["CRESCENT_TELEMETRY_CONFIG"] = str(tmpdir / "telemetry.json")
    os.environ.pop("CRESCENT_TELEMETRY", None)
    os.environ.pop("CRESCENT_TELEMETRY_ENDPOINT", None)
    try:
        # gating: default OFF, env precedence over config
        check("default OFF (no config/env)", cr.telemetry_enabled({}) is False)
        check("env=1 forces ON",
              cr.telemetry_enabled({}, {"CRESCENT_TELEMETRY": "1"}) is True)
        check("env=0 forces OFF over enabled config",
              cr.telemetry_enabled({"enabled": True}, {"CRESCENT_TELEMETRY": "0"}) is False)
        check("config enabled -> ON", cr.telemetry_enabled({"enabled": True}, {}) is True)

        # _should_send dedup/gating
        check("no endpoint -> no send", not cr._should_send("fp1", [], True, None))
        check("disabled -> no send", not cr._should_send("fp1", [], False, "http://x"))
        check("new fingerprint -> send", cr._should_send("fp1", ["fp0"], True, "http://x"))
        check("already-sent fingerprint -> skip",
              not cr._should_send("fp1", ["fp1"], True, "http://x"))

        # payload keeps the scrubbed report, only adds install_id
        rep = {"schema": cr.SCHEMA, "fingerprint": "abc", "target": {"kernel": "6.1"}}
        pl = cr.build_payload(rep, "iid123")
        check("payload adds install_id", pl.get("install_id") == "iid123")
        check("payload preserves report body", pl["fingerprint"] == "abc")
        check("send('') is a no-op (no endpoint)", cr.send({"x": 1}, "") is False)

        # REAL localhost transport — validates the POST path with no external svc
        received = {}
        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                received["body"] = json.loads(self.rfile.read(n))
                self.send_response(200); self.end_headers()
            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.handle_request, daemon=True).start()
        ok = cr.send({"schema": cr.SCHEMA, "fingerprint": "abc"},
                     f"http://127.0.0.1:{srv.server_address[1]}/ingest")
        check("send() POSTs to a live endpoint (2xx)", ok is True)
        check("endpoint received the scrubbed payload",
              received.get("body", {}).get("fingerprint") == "abc")
        srv.server_close()

        # maybe_send end-to-end via saved config, with fingerprint dedup
        hits = {"n": 0}
        class H2(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0)); self.rfile.read(n)
                hits["n"] += 1
                self.send_response(200); self.end_headers()
            def log_message(self, *a):
                pass
        srv2 = HTTPServer(("127.0.0.1", 0), H2)
        threading.Thread(target=lambda: (srv2.handle_request(), srv2.handle_request()),
                         daemon=True).start()
        cr.enable(f"http://127.0.0.1:{srv2.server_address[1]}/ingest")
        report = {"fingerprint": "zz-once", "schema": cr.SCHEMA}
        first = cr.maybe_send(report)
        second = cr.maybe_send(report)  # same fingerprint -> deduped, no 2nd POST
        check("maybe_send delivers first time", first is True)
        check("maybe_send dedups the second time", second is False)
        check("exactly one POST reached the endpoint", hits["n"] == 1)
        check("install_id generated on opt-in send", cr.get_install_id() is not None)
        srv2.server_close()
    finally:
        for k in ("CRESCENT_TELEMETRY_CONFIG", "CRESCENT_TELEMETRY",
                  "CRESCENT_TELEMETRY_ENDPOINT"):
            os.environ.pop(k, None)
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_html_report_xss():
    from utils.json_converter import safe_js_json
    print("[html report XSS hardening]")
    PAY = '</script><img src=x onerror=alert(1)><!-- &'

    blob = safe_js_json({"proc": PAY})
    check("embedded JSON has no raw '<'", "<" not in blob)
    check("embedded JSON has no raw '>'", ">" not in blob)
    check("embedded JSON has no raw '&'", "&" not in blob)
    check("embedded JSON has no U+2028", "\u2028" not in blob)
    check("payload round-trips losslessly", json.loads(blob)["proc"] == PAY)
    check("break-out sequence encoded, not literal",
          "</script><img" not in blob and "\\u003c/script" in blob)

    # end-to-end: the report generator must embed via safe_js_json, so a hostile
    # process name cannot inject a live <script>/<img> into report.html.
    try:
        from modules.html_report import HTMLReportGenerator
        gen = HTMLReportGenerator(logging.getLogger("t"), "windows")
        html = gen._build_html({"counts": {"evilproc": PAY}}, Path("/tmp/x"))
        check("_build_html: no live break-out from payload",
              "</script><img src=x" not in html)
        check("_build_html: payload survives only encoded",
              "\\u003c/script" in html)
    except Exception as exc:
        check("_build_html end-to-end reachable", False, detail=repr(exc))


def test_download_integrity():
    from modules import dbgsym_builder as db
    import tempfile, shutil, hashlib
    print("[download integrity H2/H3]")

    # prefer_https: upgrade TLS-capable hosts, leave genuine http-only untouched
    check("http ddebs -> https",
          db.prefer_https("http://ddebs.ubuntu.com/pool/x.ddeb")
          == "https://ddebs.ubuntu.com/pool/x.ddeb")
    check("https left unchanged",
          db.prefer_https("https://deb.debian.org/x") == "https://deb.debian.org/x")
    check("http-only host (centos) left as-is",
          db.prefer_https("http://debuginfo.centos.org/x.rpm")
          == "http://debuginfo.centos.org/x.rpm")
    check("unknown http host not force-upgraded",
          db.prefer_https("http://evil.example.com/x")
          == "http://evil.example.com/x")
    check("DDEBS_POOL is https", db.DDEBS_POOL.startswith("https://"))

    # looks_like_package: real archive magics vs an HTML error page
    check("ar (deb) magic recognised", db.looks_like_package(b"!<arch>\n") is not None)
    check("rpm magic recognised", db.looks_like_package(b"\xed\xab\xee\xdb\x00") is not None)
    check("xz magic recognised", db.looks_like_package(b"\xfd7zXZ\x00") is not None)
    check("HTML error page rejected", db.looks_like_package(b"<!DOCTYPE html>") is None)
    check("empty rejected", db.looks_like_package(b"") is None)

    # verify_downloaded_package on real temp files (magic + sha256)
    d = Path(tempfile.mkdtemp())
    try:
        good = d / "pkg.ddeb"; good.write_bytes(b"!<arch>\ndebian-binary  2.0\n")
        bad = d / "err.ddeb"; bad.write_bytes(b"<html><body>404 Not Found</body></html>")
        check("verify accepts a real ar archive", db.verify_downloaded_package(good) is True)
        check("verify rejects an HTML error page", db.verify_downloaded_package(bad) is False)
        h = hashlib.sha256(good.read_bytes()).hexdigest()
        check("verify accepts matching sha256", db.verify_downloaded_package(good, h) is True)
        check("verify rejects wrong sha256",
              db.verify_downloaded_package(good, "00" * 32) is False)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_symbol_zip_integrity():
    from modules.installer import verify_symbol_zip, PINNED_SYMBOL_SHA256
    import tempfile, shutil, zipfile
    print("[symbol zip integrity / pinning]")
    d = Path(tempfile.mkdtemp())
    try:
        good = d / "linux.zip"
        with zipfile.ZipFile(good, "w") as z:
            z.writestr("System.map-6.1.0", "ffffffffdeadbeef kernel_symbol\n" * 20)
        ok, digest, reason = verify_symbol_zip(good)
        check("valid zip -> ok", ok is True, detail=reason)
        check("valid zip -> 64-hex sha256", len(digest) == 64)
        check("matching pin accepted", verify_symbol_zip(good, digest)[0] is True)
        check("wrong pin rejected", verify_symbol_zip(good, "00" * 32)[0] is False)

        bad = d / "err.zip"; bad.write_bytes(b"<html><body>404 Not Found</body></html>")
        ok2, _, reason2 = verify_symbol_zip(bad)
        check("HTML error page rejected", ok2 is False)
        check("rejection reason names zip/mirror",
              "zip" in reason2.lower() or "mirror" in reason2.lower())

        corrupt = d / "trunc.zip"; corrupt.write_bytes(good.read_bytes()[:20])
        check("truncated/corrupt zip rejected", verify_symbol_zip(corrupt)[0] is False)
        check("missing file rejected", verify_symbol_zip(d / "nope.zip")[0] is False)
        check("no default pins (upstream updates not broken)",
              PINNED_SYMBOL_SHA256 == {})
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    for t in (test_corroborate_processes, test_classify_failure,
              test_assess_fixtures, test_advisory_nonempty, test_ioc_extractor,
              test_crash_report, test_vol3_demotion, test_telemetry,
              test_html_report_xss, test_download_integrity,
              test_symbol_zip_integrity):
        try:
            t()
        except Exception as exc:  # a crashing test is a failing test
            global _FAIL
            _FAIL += 1
            print(f"  FAIL  {t.__name__} raised {type(exc).__name__}: {exc}")
    print("-" * 50)
    print(f"RESULT: {_PASS} passed, {_FAIL} failed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
