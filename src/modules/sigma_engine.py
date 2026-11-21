"""Sigma rule engine for memory-forensics output (new in RAMBreaker v2).

Sigma rules describe log events. A memory image has no live log stream, so
this module RECONSTRUCTS Sigma-shaped events from Volatility plugin JSON:

  process_creation   <- pstree/pslist + cmdline (Image, CommandLine,
                        ParentImage, ParentCommandLine, ProcessId, ...)
  network_connection <- netscan / netstat / linux sockstat
  registry_*         <- printkey (TargetObject, Details)
  image_load         <- dlllist (Image, ImageLoaded)
  windows eventlog   <- EVTX records recovered from memory (EventID + data)

and evaluates the rules' detection logic in-process: selections (maps and
lists of maps), keyword lists, field modifiers (contains, startswith,
endswith, all, re, base64, base64offset, cidr, windash, exists, cased,
lt/lte/gt/gte), wildcards, null checks, and conditions with and/or/not,
parentheses, "1 of X*", "all of X*", "1 of them", "all of them".

Rules that use features which cannot be evaluated on memory data
(aggregations "| count", correlation rules, fieldref) are reported as
unsupported, never silently dropped.
"""

import base64
import fnmatch
import ipaddress
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml  # PyYAML
except Exception:  # pragma: no cover
    yaml = None


class Unsupported(Exception):
    """Rule uses a Sigma feature this engine cannot evaluate."""


# ════════════════════════════════════════════════════════════════════════════
# Value matching
# ════════════════════════════════════════════════════════════════════════════

_KNOWN_MODS = {"contains", "startswith", "endswith", "all", "re", "base64",
               "base64offset", "cidr", "windash", "exists", "cased", "lt",
               "lte", "gt", "gte", "wide", "utf16le", "utf16", "i", "m", "s",
               "expand"}


def _wild_to_regex(s: str) -> str:
    """Sigma wildcard string -> regex body (* ? with \\ escapes)."""
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "*?\\":
            out.append(re.escape(s[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def _b64_variants(v: str, offset: bool) -> List[str]:
    raw = v.encode("utf-8")
    if not offset:
        return [base64.b64encode(raw).decode().rstrip("=")]
    # Same construction as pySigma's SigmaBase64OffsetModifier.
    start_off = (0, 2, 3)
    end_off = (None, -3, -2)
    outs = []
    for i in range(3):
        enc = base64.b64encode(b" " * i + raw).decode()
        outs.append(enc[start_off[i]:end_off[(len(raw) + i) % 3]])
    return outs


def _windash_variants(v: str) -> List[str]:
    if "-" not in v and "/" not in v:
        return [v]
    out = set()
    for dash in ("-", "/", "\u2013", "\u2014", "\u2015"):
        out.add(re.sub(r"(^|\s)[-/]", lambda m: m.group(1) + dash, v))
    return sorted(out)


class Matcher:
    """A compiled field condition: field|mods: values."""

    def __init__(self, field: Optional[str], mods: List[str], values: List[Any]):
        for m in mods:
            if m not in _KNOWN_MODS:
                raise Unsupported(f"modifier '{m}'")
        if "expand" in mods:
            raise Unsupported("modifier 'expand' (placeholders)")
        self.field = field
        self.mods = mods
        self.match_all = "all" in mods
        self.kind = "eq"
        for k in ("contains", "startswith", "endswith"):
            if k in mods:
                self.kind = k
        self.cased = "cased" in mods
        self.is_re = "re" in mods
        self.is_cidr = "cidr" in mods
        self.is_exists = "exists" in mods
        self.cmp = next((m for m in ("lt", "lte", "gt", "gte") if m in mods), None)
        vals: List[Any] = []
        for v in values:
            if v is None or isinstance(v, (int, float, bool)):
                vals.append(v)
                continue
            v = str(v)
            if "wide" in mods or "utf16le" in mods or "utf16" in mods:
                pass  # memory strings are already decoded text
            if "windash" in mods:
                vals.extend(_windash_variants(v))
                continue
            if "base64offset" in mods:
                vals.extend(_b64_variants(v, True))
                continue
            if "base64" in mods:
                vals.extend(_b64_variants(v, False))
                continue
            vals.append(v)
        self.values = vals
        self._compiled = [self._compile(v) for v in vals]

    def _compile(self, v):
        if v is None or isinstance(v, bool) or self.is_cidr or self.cmp \
                or self.is_exists:
            return v
        if isinstance(v, (int, float)):
            v = str(v)
        flags = 0 if self.cased else re.IGNORECASE
        if self.is_re:
            rf = 0
            if "i" in self.mods:
                rf |= re.IGNORECASE
            if "m" in self.mods:
                rf |= re.MULTILINE
            if "s" in self.mods:
                rf |= re.DOTALL
            try:
                return re.compile(v, rf)
            except re.error as e:
                raise Unsupported(f"bad regex {v!r}: {e}")
        body = _wild_to_regex(v)
        if self.kind == "contains":
            body = ".*" + body + ".*"
        elif self.kind == "startswith":
            body = body + ".*"
        elif self.kind == "endswith":
            body = ".*" + body
        return re.compile(r"\A" + body + r"\Z", flags | re.DOTALL)

    def _one(self, comp, raw, ev_val) -> bool:
        if self.is_exists:
            present = ev_val not in (None, "")
            return present == bool(raw)
        if raw is None:
            return ev_val in (None, "")
        if ev_val is None:
            return False
        if self.is_cidr:
            try:
                return ipaddress.ip_address(str(ev_val)) in \
                    ipaddress.ip_network(str(raw), strict=False)
            except ValueError:
                return False
        if self.cmp:
            try:
                a, b = float(ev_val), float(raw)
            except (TypeError, ValueError):
                return False
            return {"lt": a < b, "lte": a <= b, "gt": a > b, "gte": a >= b}[self.cmp]
        if isinstance(raw, bool):
            return str(ev_val).lower() == str(raw).lower()
        s = str(ev_val)
        if self.is_re:
            return comp.search(s) is not None
        return comp.match(s) is not None

    def match(self, event: Dict[str, Any]) -> bool:
        if self.field is None:          # keyword search over all values
            hay = [v for v in event.values() if v not in (None, "")]
            res = [any(self._one(c, r, h) for h in hay)
                   for c, r in zip(self._compiled, self.values)]
        else:
            ev_val = _get_field(event, self.field)
            vals = ev_val if isinstance(ev_val, list) else [ev_val]
            res = [any(self._one(c, r, v) for v in vals)
                   for c, r in zip(self._compiled, self.values)]
        if not res:
            return False
        return all(res) if self.match_all else any(res)


def _get_field(event: Dict[str, Any], field: str):
    if field in event:
        return event[field]
    lf = field.lower()
    for k, v in event.items():
        if k.lower() == lf:
            return v
    return None


# ════════════════════════════════════════════════════════════════════════════
# Detection / condition compilation
# ════════════════════════════════════════════════════════════════════════════

def _compile_selection(sel) -> Any:
    """Return a callable(event)->bool for one detection identifier."""
    if isinstance(sel, dict):
        ms = []
        for key, val in sel.items():
            parts = str(key).split("|")
            field, mods = parts[0] or None, [p for p in parts[1:] if p]
            vals = val if isinstance(val, list) else [val]
            ms.append(Matcher(field, mods, vals))
        return lambda ev, ms=ms: all(m.match(ev) for m in ms)
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            subs = [_compile_selection(x) for x in sel]
            return lambda ev, subs=subs: any(s(ev) for s in subs)
        kw = Matcher(None, ["contains"], [x for x in sel if not isinstance(x, dict)])
        return kw.match
    if isinstance(sel, (str, int)):
        return Matcher(None, ["contains"], [sel]).match
    raise Unsupported(f"selection type {type(sel).__name__}")


_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


def _compile_condition(cond: str, idents: Dict[str, Any]):
    if "|" in cond:
        raise Unsupported("aggregation in condition")
    toks = _TOKEN.findall(cond)
    pos = [0]

    def peek():
        return toks[pos[0]].lower() if pos[0] < len(toks) else None

    def take():
        t = toks[pos[0]]
        pos[0] += 1
        return t

    def group(pattern: str):
        if pattern.lower() == "them":
            names = [n for n in idents if not n.startswith("_")]
        else:
            names = [n for n in idents if fnmatch.fnmatchcase(n, pattern)]
        if not names:
            raise Unsupported(f"no identifiers match '{pattern}'")
        return [idents[n] for n in names]

    def primary():
        t = peek()
        if t is None:
            raise Unsupported("truncated condition")
        if t == "(":
            take()
            f = expr()
            if peek() != ")":
                raise Unsupported("unbalanced parentheses")
            take()
            return f
        if t == "not":
            take()
            f = primary()
            return lambda ev, f=f: not f(ev)
        if t in ("1", "all", "any") and pos[0] + 2 <= len(toks) and \
                toks[pos[0] + 1].lower() == "of":
            q = take().lower()
            take()
            fs = group(take())
            if q == "all":
                return lambda ev, fs=fs: all(f(ev) for f in fs)
            return lambda ev, fs=fs: any(f(ev) for f in fs)
        name = take()
        if name not in idents:
            raise Unsupported(f"unknown identifier '{name}'")
        return idents[name]

    def and_expr():
        f = primary()
        while peek() == "and":
            take()
            g = primary()
            f = (lambda a, b: lambda ev: a(ev) and b(ev))(f, g)
        return f

    def expr():
        f = and_expr()
        while peek() == "or":
            take()
            g = and_expr()
            f = (lambda a, b: lambda ev: a(ev) or b(ev))(f, g)
        return f

    fn = expr()
    if pos[0] != len(toks):
        raise Unsupported(f"trailing tokens in condition: {toks[pos[0]:]}")
    return fn


class SigmaRule:
    def __init__(self, doc: Dict[str, Any], path: Path):
        self.path = path
        self.id = str(doc.get("id", ""))
        self.title = str(doc.get("title", path.stem))
        self.level = str(doc.get("level", "medium")).lower()
        self.status = str(doc.get("status", ""))
        self.description = str(doc.get("description", "") or "")
        self.tags = [str(t) for t in (doc.get("tags") or [])]
        ls = doc.get("logsource") or {}
        self.category = str(ls.get("category", "") or "").lower()
        self.product = str(ls.get("product", "") or "").lower()
        self.service = str(ls.get("service", "") or "").lower()
        if doc.get("correlation"):
            raise Unsupported("correlation rule")
        det = doc.get("detection")
        if not isinstance(det, dict) or "condition" not in det:
            raise Unsupported("no detection/condition")
        cond = det["condition"]
        conds = cond if isinstance(cond, list) else [cond]
        idents = {}
        for k, v in det.items():
            if k in ("condition", "timeframe"):
                continue
            idents[k] = _compile_selection(v)
        fns = [_compile_condition(str(c), idents) for c in conds]
        self._fn = lambda ev: any(f(ev) for f in fns)

    def matches(self, ev: Dict[str, Any]) -> bool:
        try:
            return bool(self._fn(ev))
        except Exception:
            return False


# ════════════════════════════════════════════════════════════════════════════
# Event reconstruction from plugin JSON
# ════════════════════════════════════════════════════════════════════════════

def _load_rows(json_dir: Path, *names: str) -> List[Dict[str, Any]]:
    """Load and flatten (__children) rows of the first existing plugin JSON."""
    for n in names:
        for p in (json_dir / f"{n}.json", json_dir / "json" / f"{n}.json"):
            if p.is_file():
                try:
                    data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    continue
                out: List[Dict[str, Any]] = []

                def walk(rows, parent=None):
                    for r in rows or []:
                        if isinstance(r, dict):
                            r = dict(r)
                            kids = r.pop("__children", None)
                            out.append(r)
                            walk(kids)
                walk(data if isinstance(data, list) else [])
                return out
    return []


_DEV = re.compile(r"^\\Device\\HarddiskVolume\d+\\", re.I)
_KERNEL_PROCS = {"system", "registry", "memcompression", "secure system",
                 "memory compression", "idle", "system idle process"}


def _win_path(p: Optional[str], name: Optional[str]) -> str:
    if p:
        p = str(p)
        if _DEV.match(p):
            return _DEV.sub(r"C:\\", p)
        if p.lower().startswith("\\systemroot\\"):
            return "C:\\Windows\\" + p[12:]
        if p.startswith("\\??\\"):
            return p[4:]
        return p
    return ("\\" + str(name)) if name else ""


def _plausible_win_proc(pid: Any, name: Any) -> bool:
    try:
        ipid = int(pid)
    except (TypeError, ValueError):
        return False
    if ipid <= 0 or ipid > 0xFFFFFFFF or ipid % 4:
        return False
    n = str(name or "")
    return bool(n) and n.isprintable() and not any(c in n for c in '\\/:*?"<>|')


def build_events(output_dir: Path, os_type: str) -> List[Dict[str, Any]]:
    """Reconstruct Sigma-shaped events from a RAMBreaker output folder."""
    od = Path(output_dir)
    jd = od / "json" if (od / "json").is_dir() else od
    events: List[Dict[str, Any]] = []
    os_type = (os_type or "windows").lower()

    if os_type == "windows":
        procs = _load_rows(jd, "windows_pstree_PsTree", "windows_pslist_PsList")
        cmd = {r.get("PID"): r.get("Args")
               for r in _load_rows(jd, "windows_cmdline_CmdLine")}
        byp: Dict[Any, Dict[str, Any]] = {}
        for r in procs:
            pid = r.get("PID")
            image = _win_path(r.get("Path") or r.get("Audit"), r.get("ImageFileName"))
            byp[pid] = {"image": image,
                        "cmd": cmd.get(pid) or r.get("Cmd") or "",
                        "ppid": r.get("PPID"), "name": r.get("ImageFileName"),
                        "time": r.get("CreateTime")}
        for pid, p in byp.items():
            # Kernel pseudo-processes never appear as process_creation events
            # in real telemetry; evaluating them only yields false positives.
            if pid in (0, 4) or str(p["name"] or "").lower() in _KERNEL_PROCS:
                continue
            # Smeared/bogus EPROCESS records (seen on a 35 GB Win11 dump: PID
            # 259258702926855, binary image name) are not processes: real
            # Windows PIDs are 32-bit multiples of 4 and names are printable.
            if not _plausible_win_proc(pid, p["name"]):
                continue
            par = byp.get(p["ppid"], {})
            events.append({
                "_category": "process_creation", "_product": "windows",
                "_source": "pstree+cmdline", "_pid": pid,
                # full path unknown (exited/unmapped PEB) -> "\\name" fallback
                "_image_partial": not p["image"] or p["image"].startswith("\\")
                and ":" not in p["image"][:3],
                "Image": p["image"], "CommandLine": p["cmd"],
                "OriginalFileName": p["name"] or "",
                "ProcessId": pid, "ParentProcessId": p["ppid"],
                "ParentImage": par.get("image", ""),
                "ParentCommandLine": par.get("cmd", ""),
                "UtcTime": p["time"],
            })
        for r in _load_rows(jd, "windows_netscan_NetScan", "windows_netstat_NetStat"):
            pid = r.get("PID")
            events.append({
                "_category": "network_connection", "_product": "windows",
                "_source": "netscan", "_pid": pid,
                "Image": byp.get(pid, {}).get("image") or _win_path(None, r.get("Owner")),
                "ProcessId": pid, "Protocol": r.get("Proto"),
                "SourceIp": r.get("LocalAddr"), "SourcePort": r.get("LocalPort"),
                "DestinationIp": r.get("ForeignAddr"),
                "DestinationPort": r.get("ForeignPort"),
                "State": r.get("State"), "UtcTime": r.get("Created"),
            })
        for r in _load_rows(jd, "windows_registry_printkey_PrintKey"):
            key = str(r.get("Key") or "")
            name = str(r.get("Name") or "")
            target = re.sub(r"^\\REGISTRY\\MACHINE", "HKLM", key, flags=re.I)
            target = re.sub(r"^\\REGISTRY\\USER\\[^\\]+", "HKU", target, flags=re.I)
            events.append({
                "_category": "registry_set", "_product": "windows",
                "_source": "printkey", "_pid": None,
                "TargetObject": f"{target}\\{name}" if name else target,
                "Details": r.get("Data"), "EventType": "SetValue",
            })
        for r in _load_rows(jd, "windows_dlllist_DllList"):
            pid = r.get("PID")
            events.append({
                "_category": "image_load", "_product": "windows",
                "_source": "dlllist", "_pid": pid,
                "Image": byp.get(pid, {}).get("image", ""),
                "ImageLoaded": _win_path(r.get("Path"), r.get("Name")),
                "ProcessId": pid,
            })
        events.extend(_evtx_events(od))
    else:
        prod = "linux" if os_type == "linux" else "macos"
        pre = "linux" if os_type == "linux" else "mac"
        # Vol3 (linux_pslist_PsList / ARGS ...) and Vol2 (linux_pslist_vol2 /
        # Pid PPid Name / Arguments) outputs; merge list + args by PID.
        def _int(v):
            try:
                return int(str(v).strip())
            except (TypeError, ValueError):
                return v
        info: Dict[Any, Dict[str, Any]] = {}
        for r in _load_rows(jd, f"{pre}_pslist_PsList", f"{pre}_pstree_PsTree",
                            f"{pre}_pslist_vol2", f"{pre}_pstree_vol2"):
            pid = _int(r.get("PID", r.get("Pid")))
            info.setdefault(pid, {}).update(
                comm=r.get("COMM") or r.get("Name") or "",
                ppid=_int(r.get("PPID", r.get("PPid"))))
        for r in _load_rows(jd, f"{pre}_psaux_PsAux", f"{pre}_psaux_vol2"):
            pid = _int(r.get("PID", r.get("Pid")))
            d = info.setdefault(pid, {})
            d["args"] = r.get("ARGS") or r.get("Arguments") or ""
            d.setdefault("comm", r.get("COMM") or "")
            if r.get("PPID") is not None:
                d.setdefault("ppid", _int(r.get("PPID")))
        byp = {}
        for pid, d in info.items():
            comm, args = d.get("comm", ""), d.get("args", "")
            exe = str(args).split(" ", 1)[0] if args and not str(args).startswith("[") else ""
            if not exe.startswith("/"):
                exe = "/" + comm if comm else exe
            byp[pid] = {"image": exe, "cmd": args or comm, "ppid": d.get("ppid")}
        for pid, p in byp.items():
            par = byp.get(p["ppid"], {})
            events.append({
                "_category": "process_creation", "_product": prod,
                "_source": "psaux/pslist", "_pid": pid,
                "Image": p["image"], "CommandLine": p["cmd"],
                "ProcessId": pid, "ParentProcessId": p["ppid"],
                "ParentImage": par.get("image", ""),
                "ParentCommandLine": par.get("cmd", ""),
            })
        for r in _load_rows(jd, f"{pre}_sockstat_Sockstat", f"{pre}_netstat_Netstat",
                            f"{pre}_netstat_vol2"):
            if r.get("Proto") == "UNIX" or "raw" in r:
                continue
            fam = str(r.get("Family") or "")
            if fam and fam not in ("AF_INET", "AF_INET6"):
                continue        # AF_UNIX / NETLINK etc. are not network connections
            dst = r.get("Destination Addr") or r.get("ForeignAddr")
            src = r.get("Source Addr") or r.get("LocalAddr")
            try:
                ipaddress.ip_address(str(dst or src or "").split("%")[0])
            except ValueError:
                continue        # path-like 'addresses' (/run/systemd/journal/stdout)
            pid = r.get("Pid") or r.get("PID")
            events.append({
                "_category": "network_connection", "_product": prod,
                "_source": "sockstat/netstat", "_pid": pid,
                "Image": byp.get(pid, {}).get("image", ""),
                "SourceIp": r.get("Source Addr") or r.get("LocalAddr"),
                "SourcePort": r.get("Source Port") or r.get("LocalPort"),
                "DestinationIp": r.get("Destination Addr") or r.get("ForeignAddr"),
                "DestinationPort": r.get("Destination Port") or r.get("ForeignPort"),
                "Protocol": r.get("Proto"),
            })
    return events


def _evtx_events(od: Path) -> List[Dict[str, Any]]:
    """EVTX records recovered by evtx_parser (if it ran)."""
    out = []
    for p in list(od.glob("evtx*/**/*.json"))[:200]:
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        recs = data.get("events") if isinstance(data, dict) else data
        if not isinstance(recs, list):
            continue
        for r in recs:
            if not isinstance(r, dict):
                continue
            ev = {"_category": "", "_product": "windows", "_source": f"evtx:{p.name}",
                  "_pid": None}
            chan = str(r.get("channel") or r.get("Channel") or "").lower()
            ev["_service"] = ("security" if "security" in chan else
                              "system" if chan == "system" else
                              "powershell" if "powershell" in chan else
                              "sysmon" if "sysmon" in chan else chan)
            for k, v in r.items():
                if isinstance(v, dict):
                    ev.update(v)
                else:
                    ev[k[:1].upper() + k[1:]] = v
            if "EventID" not in ev and "Event_id" in ev:
                ev["EventID"] = ev["Event_id"]
            out.append(ev)
    return out


def _applies(rule: SigmaRule, ev: Dict[str, Any]) -> bool:
    if rule.product and rule.product != ev.get("_product"):
        return False
    if rule.category:
        cat = ev.get("_category", "")
        if rule.category.startswith("registry_"):
            return cat.startswith("registry_")
        return rule.category == cat
    if rule.service:
        return rule.service == ev.get("_service")
    return False  # product-only rules are too broad to apply to memory data


# ════════════════════════════════════════════════════════════════════════════
# Loading + running
# ════════════════════════════════════════════════════════════════════════════

def default_rules_dir() -> Optional[Path]:
    """sigma_rules/ beside the app (exe dir or project root), else None."""
    cands = []
    try:
        from modules.platform_compat import app_root
        cands.append(app_root() / "sigma_rules")
    except Exception:
        pass
    here = Path(__file__).resolve().parent.parent
    cands += [here / "sigma_rules", here.parent / "sigma_rules"]
    for c in cands:
        if c.is_dir():
            return c
    return None


def load_rules(rules_dir: Path, log: Optional[logging.Logger] = None
               ) -> Tuple[List[SigmaRule], List[Tuple[str, str]]]:
    log = log or logging.getLogger(__name__)
    rules, bad = [], []
    if yaml is None:
        log.error("PyYAML missing - Sigma disabled")
        return rules, [("*", "PyYAML not installed")]
    for p in sorted(Path(rules_dir).rglob("*.yml")) + sorted(Path(rules_dir).rglob("*.yaml")):
        try:
            loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)  # libyaml: ~5x faster
            docs = [d for d in yaml.load_all(p.read_text(encoding="utf-8", errors="replace"),
                                             Loader=loader)
                    if isinstance(d, dict)]
            if len(docs) != 1:
                raise Unsupported("multi-document rule collection")
            rules.append(SigmaRule(docs[0], p))
        except Unsupported as e:
            bad.append((str(p), f"unsupported: {e}"))
        except Exception as e:
            bad.append((str(p), f"error: {e}"))
    log.info("Sigma: loaded %d rules (%d unsupported/invalid) from %s",
             len(rules), len(bad), rules_dir)
    return rules, bad


def run(output_dir: Path, os_type: str, rules_dir: Path,
        log: Optional[logging.Logger] = None) -> Dict[str, Any]:
    """Evaluate all rules over the reconstructed events; write sigma/ results."""
    log = log or logging.getLogger(__name__)
    rules, bad = load_rules(rules_dir, log)
    events = build_events(output_dir, os_type)
    by_cat: Dict[str, int] = {}
    for e in events:
        by_cat[e["_category"] or e.get("_service", "?")] = \
            by_cat.get(e["_category"] or e.get("_service", "?"), 0) + 1
    log.info("Sigma: %d events reconstructed %s", len(events), by_cat)
    hits = []
    applicable = 0
    # v2.4: _applies() only looks at (_product, _category, _service), so events are
    # bucketed by that triple once instead of testing every rule against every event
    # (3,159 rules x thousands of events). Event order inside a rule is unchanged.
    groups: Dict[Tuple[Any, Any, Any], List[Tuple[int, Dict[str, Any]]]] = {}
    for i, e in enumerate(events):
        groups.setdefault((e.get("_product"), e.get("_category", ""), e.get("_service")),
                          []).append((i, e))
    for r in rules:
        picked = [g for g in groups.values() if _applies(r, g[0][1])]
        if len(picked) == 1:
            evs = [e for _i, e in picked[0]]
        else:
            evs = [e for _i, e in sorted((x for g in picked for x in g), key=lambda x: x[0])]
        if evs:
            applicable += 1
        matched = [e for e in evs if r.matches(e)]
        if matched:
            partial = all(e.get("_image_partial") for e in matched)
            hits.append({
                "rule_id": r.id, "title": r.title, "level": r.level,
                # evidence built from an incomplete image path is weaker
                "confidence": "low" if partial else "normal",
                "tags": r.tags, "file": r.path.name,
                "logsource": {"category": r.category, "product": r.product,
                              "service": r.service},
                "description": r.description[:500],
                "matches": [{k: v for k, v in e.items()} for e in matched[:50]],
                "match_count": len(matched),
            })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    hits.sort(key=lambda h: (order.get(h["level"], 5), h["title"]))
    res = {"rules_loaded": len(rules), "rules_unsupported": len(bad),
           "rules_applicable": applicable, "events": len(events),
           "events_by_category": by_cat, "rules_fired": len(hits), "hits": hits,
           "unsupported": [{"file": Path(f).name, "reason": why} for f, why in bad]}
    sd = Path(output_dir) / "sigma"
    sd.mkdir(parents=True, exist_ok=True)
    (sd / "sigma_results.json").write_text(json.dumps(res, indent=2, default=str),
                                           encoding="utf-8")
    with open(sd / "sigma_results.txt", "w", encoding="utf-8") as f:
        f.write(f"SIGMA RESULTS  rules={len(rules)} applicable={applicable} "
                f"unsupported={len(bad)} events={len(events)} fired={len(hits)}\n\n")
        for h in hits:
            f.write(f"[{h['level'].upper()}] {h['title']}  ({h['file']}, "
                    f"{h['match_count']} match(es))\n")
            for m in h["matches"][:5]:
                ev = ", ".join(f"{k}={v}" for k, v in m.items()
                               if not k.startswith("_") and v not in (None, ""))[:400]
                f.write(f"    pid={m.get('_pid')} src={m.get('_source')}: {ev}\n")
            f.write("\n")
    log.info("Sigma: %d/%d rules fired", len(hits), len(rules))
    return res
