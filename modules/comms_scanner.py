"""
CresCent RAM Forensics Toolkit v4.0 - Communication App Scanner

Extracts artifacts from messaging/conferencing apps found in memory:
  - Microsoft Teams: messages, tokens, meeting URLs, contacts
  - Discord: messages, tokens, server/channel info, webhooks
  - Zoom: meeting IDs, passwords, join URLs, participants
  - Slack: messages, tokens (xoxc/xoxb/xoxp), webhooks, workspace
  - Telegram: messages, phone numbers, session data
  - WhatsApp: messages, contacts, media URLs
  - Skype: messages, contacts, call logs
  - Webex: meeting IDs, join URLs
  - Signal: messages, contacts
  - Google Meet: meeting codes
  - VooV/Tencent Meeting: meeting IDs
  - Flock (Flock Team Messaging): flock.com URLs, API/session tokens, deep links,
    CDN URLs; running-process + network correlation (flock / flock helper)
  - Generic: OAuth tokens, API keys, JWT tokens

Sources:
  1. strings_ascii.txt (primary — single-pass with line_callback)
  2. Process list (identifies running apps)

Output:
  comms_report.txt     — Human-readable report
  comms_report.json    — Machine-readable JSON
  comms/               — Per-app artifact files
"""

import json
import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class CommsScanner:
    """Scan memory strings for communication app artifacts."""

    # Human-readable display names for apps whose full product name differs
    # from the uppercased key. Falls back to APP.upper() when not listed.
    _DISPLAY_NAMES = {
        "flock": "Flock Team Messaging",
    }

    @classmethod
    def _display(cls, app: str) -> str:
        return cls._DISPLAY_NAMES.get(app, app.replace("_", " ").upper())

    def __init__(self, logger: logging.Logger):
        self.log = logger
        self._results: Dict[str, Dict[str, Set[str]]] = {}
        self._line_count = 0
        self._patterns = self._build_patterns()
        self._init_results()

    def _init_results(self):
        """Initialize empty result sets for all apps and categories."""
        for app in self._patterns:
            self._results[app] = {}
            for cat in self._patterns[app]:
                self._results[app][cat] = set()

    def _build_patterns(self) -> Dict[str, Dict[str, Tuple[re.Pattern, str]]]:
        """Build regex patterns for each app and artifact type.

        Structure: {app_name: {category: (compiled_regex, description)}}
        """
        p = {}

        # =====================================================================
        # MICROSOFT TEAMS
        # =====================================================================
        p["teams"] = {
            "auth_token": (
                re.compile(r'eyJ[A-Za-z0-9_-]{50,}\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}'),
                "JWT/OAuth token (Teams auth)"),
            "message": (
                re.compile(r'"(?:content|body)":\s*"([^"]{10,500})"'),
                "Chat message content"),
            "meeting_url": (
                re.compile(r'https://teams\.microsoft\.com/l/meetup-join/[^\s"<>]{20,}'),
                "Teams meeting join URL"),
            "meeting_id": (
                re.compile(r'(?:meeting|thread)\.v2/[A-Za-z0-9_-]{20,}'),
                "Teams meeting/thread ID"),
            "user_email": (
                re.compile(r'[a-zA-Z0-9._%+-]+@(?:microsoft\.com|outlook\.com|hotmail\.com|live\.com|office365\.com)'),
                "Microsoft email address"),
            "tenant_id": (
                re.compile(r'(?:tenant[_-]?id|tid)["\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'),
                "Azure AD Tenant ID"),
            "sharepoint_url": (
                re.compile(r'https://[a-zA-Z0-9-]+\.sharepoint\.com/[^\s"<>]{10,}'),
                "SharePoint/OneDrive file URL"),
        }

        # =====================================================================
        # DISCORD
        # =====================================================================
        p["discord"] = {
            "user_token": (
                re.compile(r'[MN][A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}'),
                "Discord user/bot token (CRITICAL — full account access)"),
            "bot_token": (
                re.compile(r'Bot [MN][A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}'),
                "Discord bot token"),
            "webhook_url": (
                re.compile(r'https://(?:discord\.com|discordapp\.com)/api/webhooks/\d+/[A-Za-z0-9_-]+'),
                "Discord webhook URL"),
            "invite_url": (
                re.compile(r'https://discord\.(?:gg|com/invite)/[A-Za-z0-9]+'),
                "Discord server invite link"),
            "cdn_url": (
                re.compile(r'https://cdn\.discordapp\.com/(?:attachments|avatars|icons)/\d+/[^\s"<>]+'),
                "Discord CDN file/attachment URL"),
            "channel_id": (
                re.compile(r'"(?:channel_id|guild_id)":\s*"(\d{17,20})"'),
                "Discord channel/guild ID"),
            "message_content": (
                re.compile(r'"content":\s*"([^"]{5,500})"'),
                "Discord message content"),
            "nitro_url": (
                re.compile(r'https://discord\.gift/[A-Za-z0-9]+'),
                "Discord Nitro gift link"),
        }

        # =====================================================================
        # ZOOM
        # =====================================================================
        p["zoom"] = {
            "meeting_url": (
                re.compile(r'https://[a-zA-Z0-9-]*\.?zoom\.us/j/\d{9,11}(?:\?pwd=[A-Za-z0-9_-]+)?'),
                "Zoom meeting join URL"),
            "meeting_id": (
                re.compile(r'(?:meeting[_\s]?id|conf(?:erence)?[_\s]?(?:id|no|number))["\s:=]*(\d{9,11})'),
                "Zoom meeting ID"),
            "meeting_password": (
                re.compile(r'(?:meeting[_\s]?(?:password|passcode|pwd))["\s:=]*([A-Za-z0-9]{6,10})'),
                "Zoom meeting password"),
            "jwt_token": (
                re.compile(r'(?:zoom[_.]?(?:token|jwt|api[_.]?key))["\s:=]+([A-Za-z0-9_-]{20,})'),
                "Zoom API token"),
            "recording_url": (
                re.compile(r'https://[a-zA-Z0-9-]*\.?zoom\.us/rec/[^\s"<>]+'),
                "Zoom recording URL"),
            "zak_token": (
                re.compile(r'"zak":\s*"([^"]{50,})"'),
                "Zoom ZAK token (host key)"),
        }

        # =====================================================================
        # SLACK
        # =====================================================================
        p["slack"] = {
            "xoxc_token": (
                re.compile(r'xoxc-[0-9]+-[0-9]+-[0-9]+-[0-9a-f]+'),
                "Slack client token (xoxc — user session)"),
            "xoxb_token": (
                re.compile(r'xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+'),
                "Slack bot token (xoxb)"),
            "xoxp_token": (
                re.compile(r'xoxp-[0-9]+-[0-9]+-[0-9]+-[0-9a-f]+'),
                "Slack user token (xoxp — legacy)"),
            "xoxa_token": (
                re.compile(r'xoxa-[0-9]+-[0-9]+-[A-Za-z0-9]+'),
                "Slack app token (xoxa)"),
            "xoxo_token": (
                re.compile(r'xoxo-[0-9]+-[0-9]+-[A-Za-z0-9]+'),
                "Slack config token (xoxo)"),
            "webhook_url": (
                re.compile(r'https://hooks\.slack\.com/[^\s"<>]+'),
                "Slack webhook URL"),
            "workspace_url": (
                re.compile(r'https://([a-zA-Z0-9-]+)\.slack\.com'),
                "Slack workspace URL"),
            "file_url": (
                re.compile(r'https://files\.slack\.com/[^\s"<>]+'),
                "Slack file URL"),
            "message": (
                re.compile(r'"text":\s*"([^"]{10,500})"'),
                "Slack message text"),
            "channel": (
                re.compile(r'"(?:channel|channel_name)":\s*"([^"]{1,80})"'),
                "Slack channel name"),
        }

        # =====================================================================
        # TELEGRAM
        # =====================================================================
        p["telegram"] = {
            "api_id": (
                re.compile(r'(?:api[_-]?id)["\s:=]+(\d{5,10})'),
                "Telegram API ID"),
            "api_hash": (
                re.compile(r'(?:api[_-]?hash)["\s:=]+([0-9a-f]{32})'),
                "Telegram API hash"),
            "bot_token": (
                re.compile(r'\d{8,10}:[A-Za-z0-9_-]{35}'),
                "Telegram bot token"),
            "tg_url": (
                re.compile(r'https://t\.me/[A-Za-z0-9_]+(?:/\d+)?'),
                "Telegram link (user/channel/message)"),
            "phone_number": (
                re.compile(r'"phone":\s*"\+?(\d{10,15})"'),
                "Phone number (Telegram contact)"),
            "session_file": (
                re.compile(r'[A-Za-z0-9_-]+\.session'),
                "Telegram session file reference"),
        }

        # =====================================================================
        # WHATSAPP
        # =====================================================================
        p["whatsapp"] = {
            "wa_url": (
                re.compile(r'https://(?:web|api)\.whatsapp\.com/[^\s"<>]+'),
                "WhatsApp Web/API URL"),
            "wa_invite": (
                re.compile(r'https://chat\.whatsapp\.com/[A-Za-z0-9]{15,25}'),
                "WhatsApp group invite link"),
            "wa_phone": (
                re.compile(r'whatsapp://send\?phone=(\d{10,15})'),
                "WhatsApp phone number (deep link)"),
            "wa_media": (
                re.compile(r'https://mmg[-.]whatsapp\.net/[^\s"<>]+'),
                "WhatsApp media URL"),
            "message": (
                re.compile(r'"(?:body|caption)":\s*"([^"]{5,500})"'),
                "WhatsApp message content"),
        }

        # =====================================================================
        # SKYPE
        # =====================================================================
        p["skype"] = {
            "skype_url": (
                re.compile(r'https://(?:join\.skype\.com|web\.skype\.com)/[^\s"<>]+'),
                "Skype join/web URL"),
            "skype_token": (
                re.compile(r'(?:skype[_-]?token|registrationToken)["\s:=]+([A-Za-z0-9=+/]{50,})'),
                "Skype auth token"),
            "skype_id": (
                re.compile(r'(?:live|skype):[a-zA-Z0-9_.]+'),
                "Skype ID"),
            "conversation": (
                re.compile(r'(?:19|8):[a-z0-9]+@thread\.(?:skype|tacv2)'),
                "Skype conversation thread ID"),
        }

        # =====================================================================
        # WEBEX / CISCO
        # =====================================================================
        p["webex"] = {
            "meeting_url": (
                re.compile(r'https://[a-zA-Z0-9-]+\.webex\.com/[^\s"<>]*(?:meet|join)[^\s"<>]*'),
                "Webex meeting URL"),
            "meeting_number": (
                re.compile(r'(?:meeting[_\s]?number|access[_\s]?code)["\s:=]*(\d{9,11})'),
                "Webex meeting number"),
            "recording": (
                re.compile(r'https://[a-zA-Z0-9-]+\.webex\.com/[^\s"<>]*(?:recording|playback)[^\s"<>]*'),
                "Webex recording URL"),
            "api_token": (
                re.compile(r'(?:Bearer\s+)([A-Za-z0-9_-]{60,}(?:\.webex\.com)?)'),
                "Webex Bearer token"),
        }

        # =====================================================================
        # SIGNAL
        # =====================================================================
        p["signal"] = {
            "signal_url": (
                re.compile(r'https://signal\.(?:org|me|group)/[^\s"<>]+'),
                "Signal link"),
            "safety_number": (
                re.compile(r'(?:safety.?number|fingerprint)["\s:=]+(\d{60})'),
                "Signal safety number"),
            "signal_key": (
                re.compile(r'"(?:identityKey|signedPreKey|preKey)":\s*"([A-Za-z0-9+/=]{20,})"'),
                "Signal encryption key material"),
        }

        # =====================================================================
        # GOOGLE MEET
        # =====================================================================
        p["google_meet"] = {
            "meeting_url": (
                re.compile(r'https://meet\.google\.com/[a-z]{3}-[a-z]{4}-[a-z]{3}'),
                "Google Meet URL"),
            "calendar_event": (
                re.compile(r'https://calendar\.google\.com/[^\s"<>]*(?:event|meeting)[^\s"<>]*'),
                "Google Calendar event URL"),
            "google_token": (
                re.compile(r'ya29\.[A-Za-z0-9_-]{50,}'),
                "Google OAuth access token"),
        }

        # =====================================================================
        # VOOV / TENCENT MEETING
        # =====================================================================
        p["voov"] = {
            "meeting_url": (
                re.compile(r'https://(?:voovmeeting|meeting\.tencent)\.com/[^\s"<>]+'),
                "VooV/Tencent meeting URL"),
            "meeting_id": (
                re.compile(r'(?:voov|tencent)[_\s]?(?:meeting)?[_\s]?(?:id|code)["\s:=]*(\d{9,11})'),
                "VooV meeting ID"),
        }

        # =====================================================================
        # FLOCK  (Flock Team Messaging)
        # Patterns are anchored to flock.com / flock:// so they do not
        # false-match unrelated strings (per the v4.1 IOC anti-FP lesson).
        # =====================================================================
        p["flock"] = {
            "flock_url": (
                re.compile(r'https?://(?:[a-zA-Z0-9-]+\.)*flock\.com/[^\s"\'<>]{0,200}'),
                "Flock web/app/API URL"),
            "flock_api_token": (
                re.compile(r'flock\.com/[^\s"\'<>]*[?&](?:token|access_token|flockToken)=[A-Za-z0-9._-]{12,}'),
                "Flock API/session token in URL (CRITICAL — account access)"),
            "flock_deeplink": (
                re.compile(r'flock://[^\s"\'<>]{0,200}'),
                "Flock app deep link"),
            "flock_cdn": (
                re.compile(r'https?://(?:[a-zA-Z0-9-]+\.)*flockcdn\.com/[^\s"\'<>]{0,200}'),
                "Flock CDN/media/file URL"),
        }

        # =====================================================================
        # GENERIC / CROSS-APP TOKENS
        # =====================================================================
        p["generic_tokens"] = {
            "jwt_token": (
                re.compile(r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'),
                "JWT token (any app)"),
            "bearer_token": (
                re.compile(r'(?:Authorization|Bearer)[:\s]+Bearer\s+([A-Za-z0-9_-]{20,})'),
                "Bearer auth token"),
            "aws_key": (
                re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'),
                "AWS access key"),
            "github_token": (
                re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
                "GitHub personal access token"),
            "private_key": (
                re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
                "Private key header"),
            "oauth_secret": (
                re.compile(r'(?:client[_-]?secret|api[_-]?secret)["\s:=]+([A-Za-z0-9_-]{20,})'),
                "OAuth client secret"),
        }

        return p

    @staticmethod
    def _is_plausible_discord_token(tok: str) -> bool:
        """Reject JWT-shaped strings that aren't real Discord tokens.

        Real Discord user tokens have three dot-separated segments where the
        first segment is the base64-encoded user ID (a Discord 'snowflake' —
        an integer in the rough range 10^16 to 10^19). Many JWTs (including
        ones from completely unrelated apps) start with M or N because their
        base64-encoded JSON header starts with that letter, and they match
        the same overall shape. This check decodes the first segment and
        rejects anything that isn't a numeric user ID.
        """
        import base64
        segs = tok.split(".", 2)
        if len(segs) != 3:
            return False
        head = segs[0]
        # Strip 'Bot ' prefix if present
        if head.startswith("Bot "):
            head = head[4:].split(".", 1)[0]
        # Add base64 padding
        padded = head + "=" * (-len(head) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False).decode(
                "ascii", errors="ignore")
        except Exception:
            return False
        # Real Discord IDs are 17–20 digit decimals
        if not decoded.isdigit():
            return False
        return 17 <= len(decoded) <= 20

    def _process_line(self, line: str):
        """Process a single line — designed as callback for IOC single-pass.

        This is called for every line in strings_ascii.txt during the IOC scan.
        """
        self._line_count += 1
        if len(line) < 8:
            return

        for app, categories in self._patterns.items():
            for cat, (regex, desc) in categories.items():
                for match in regex.findall(line):
                    if isinstance(match, tuple):
                        match = match[0]
                    match = match.strip()
                    if not match or len(match) <= 5:
                        continue
                    # Validate Discord tokens to suppress JWT false positives.
                    # CRITICAL-flagged matches need to actually be Discord tokens.
                    if (app == "discord"
                            and cat in ("user_token", "bot_token")
                            and not self._is_plausible_discord_token(match)):
                        continue
                    self._results[app][cat].add(match)

    def scan_strings_file(self, strings_path: Path) -> Dict[str, Any]:
        """Standalone scan of a strings file (if not using callback).

        Args:
            strings_path: Path to strings_ascii.txt

        Returns:
            Compiled results dict.
        """
        self.log.info("Scanning %s for communication app artifacts...",
                      strings_path.name)
        self._init_results()
        self._line_count = 0

        try:
            with open(strings_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    self._process_line(line.strip())
        except Exception as e:
            self.log.error("Error reading %s: %s", strings_path, e)

        return self._compile_results()

    def _compile_results(self) -> Dict[str, Any]:
        """Compile results into a structured dict."""
        compiled = {
            "lines_scanned": self._line_count,
            "apps": {},
            "total_artifacts": 0,
            "apps_detected": [],
        }

        for app, categories in self._results.items():
            app_total = 0
            app_data = {}
            for cat, matches in categories.items():
                if matches:
                    desc = self._patterns[app][cat][1]
                    app_data[cat] = {
                        "description": desc,
                        "count": len(matches),
                        "values": sorted(matches)[:500],  # Cap at 500 per category
                    }
                    app_total += len(matches)

            if app_data:
                compiled["apps"][app] = {
                    "total": app_total,
                    "categories": app_data,
                }
                compiled["apps_detected"].append(app)
                compiled["total_artifacts"] += app_total

        return compiled

    def enrich_from_processes(self, output_dir: Path, results: Dict[str, Any]):
        """Add process-level context from pslist/cmdline data."""
        from utils.json_converter import load_json_by_pattern
        jd = Path(output_dir) / "json"
        if not jd.is_dir():
            return

        # Map of exe names → app names
        exe_map = {
            "teams.exe": "teams", "teams": "teams",
            "discord.exe": "discord", "discord": "discord",
            "update.exe": None,  # skip — ambiguous
            "zoom.exe": "zoom", "zoom": "zoom",
            "caphost.exe": "zoom",
            "slack.exe": "slack", "slack": "slack",
            "telegram.exe": "telegram", "telegram": "telegram",
            "whatsapp.exe": "whatsapp", "whatsapp": "whatsapp",
            "skype.exe": "skype", "skype": "skype",
            "skypeapp.exe": "skype",
            "webex.exe": "webex", "ciscowebex": "webex",
            "webexmta.exe": "webex",
            "signal.exe": "signal", "signal": "signal",
            "voovmeeting.exe": "voov", "wemeetapp.exe": "voov",
            "flock.exe": "flock", "flock": "flock",
            "flock helper": "flock", "flock helper (renderer)": "flock",
            "flock helper (gpu)": "flock",
        }

        running_apps = {}
        for item in load_json_by_pattern(jd, "pslist"):
            # NAME = macOS pslist field; ImageFileName/Name = Windows; COMM = Linux
            name = str(item.get("ImageFileName", item.get("Name", item.get("NAME", item.get("COMM", ""))))).lower()
            pid = item.get("PID", item.get("pid", ""))
            if name in exe_map and exe_map[name]:
                app = exe_map[name]
                if app not in running_apps:
                    running_apps[app] = []
                running_apps[app].append({
                    "pid": pid,
                    "name": name,
                })

        # Add cmdline data
        cmdlines = {}
        for item in load_json_by_pattern(jd, "cmdline"):
            pid = str(item.get("PID", item.get("pid", "")))
            args = item.get("Args", item.get("args", item.get("CommandLine", "")))
            if args:
                cmdlines[pid] = str(args)

        for app, procs in running_apps.items():
            for proc in procs:
                proc["cmdline"] = cmdlines.get(str(proc["pid"]), "")

        results["running_processes"] = running_apps

        # Add network connections for these PIDs
        net_conns = {}
        for pat in ("netscan", "netstat"):
            for item in load_json_by_pattern(jd, pat):
                pid = str(item.get("PID", item.get("pid", "")))
                # Owner = Windows netscan; Process ("name/pid") = macOS netstat
                owner = str(item.get("Owner", item.get("Process", ""))).lower()
                for exe_name, app_name in exe_map.items():
                    if app_name and (owner == exe_name or exe_name in owner):
                        if app_name not in net_conns:
                            net_conns[app_name] = []
                        foreign = item.get("ForeignAddr", item.get("Foreign Address", item.get("Remote IP", "")))
                        foreign_port = item.get("ForeignPort", item.get("Foreign Port", item.get("Remote Port", "")))
                        local = item.get("LocalAddr", item.get("Local Address", item.get("Local IP", "")))
                        local_port = item.get("LocalPort", item.get("Local Port", ""))
                        state = item.get("State", "")
                        net_conns[app_name].append({
                            "pid": pid,
                            "local": f"{local}:{local_port}",
                            "foreign": f"{foreign}:{foreign_port}",
                            "state": state,
                        })
                        break

        results["network_connections"] = net_conns

    def write_report(self, output_dir: Path, results: Dict[str, Any]) -> Path:
        """Write human-readable report and JSON output.

        Returns:
            Path to TXT report.
        """
        od = Path(output_dir)
        comms_dir = od / "comms"
        comms_dir.mkdir(parents=True, exist_ok=True)

        txt_path = od / "comms_report.txt"
        json_dir = od / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        json_path = json_dir / "comms_report.json"

        total = results.get("total_artifacts", 0)
        detected = results.get("apps_detected", [])

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("  COMMUNICATION APP ARTIFACTS\n")
            f.write("  CresCent RAM Forensics Toolkit v4.0\n")
            f.write("=" * 70 + "\n\n")

            if not detected:
                f.write("  No communication app artifacts detected.\n")
            else:
                f.write(f"  Apps detected: {', '.join(detected)}\n")
                f.write(f"  Total artifacts: {total}\n")

                # Running processes
                running = results.get("running_processes", {})
                if running:
                    f.write(f"\n  Running app processes:\n")
                    for app, procs in running.items():
                        for proc in procs:
                            f.write(f"    [{app.upper()}] PID {proc['pid']} - {proc['name']}")
                            if proc.get("cmdline"):
                                f.write(f" | {proc['cmdline'][:100]}")
                            f.write("\n")

                # Network connections
                net = results.get("network_connections", {})
                if net:
                    f.write(f"\n  Network connections:\n")
                    for app, conns in net.items():
                        for c in conns[:20]:
                            f.write(f"    [{self._display(app)}] {c['local']} -> {c['foreign']} ({c['state']})\n")

                f.write("\n")

                # Per-app details
                app_display_order = [
                    "teams", "discord", "zoom", "slack", "telegram",
                    "whatsapp", "skype", "webex", "signal", "google_meet",
                    "voov", "flock", "generic_tokens",
                ]

                for app in app_display_order:
                    if app not in results.get("apps", {}):
                        continue
                    app_data = results["apps"][app]
                    f.write("-" * 70 + "\n")
                    display_name = self._display(app)
                    f.write(f"  {display_name}  ({app_data['total']} artifacts)\n")
                    f.write("-" * 70 + "\n\n")

                    # Write per-category
                    for cat, cat_data in app_data["categories"].items():
                        count = cat_data["count"]
                        desc = cat_data["description"]
                        values = cat_data["values"]

                        # Mark critical items
                        critical = any(x in cat.lower() for x in
                                       ("token", "secret", "key", "password",
                                        "credential", "private"))
                        marker = " [!!! CRITICAL]" if critical else ""

                        f.write(f"  [{cat}] {desc}{marker} ({count})\n")

                        # Write individual per-type file
                        cat_file = comms_dir / f"{app}_{cat}.txt"
                        with open(cat_file, "w", encoding="utf-8") as cf:
                            cf.write(f"# {display_name} - {desc}\n")
                            cf.write(f"# Count: {count}\n")
                            cf.write("#" + "-" * 60 + "\n")
                            for v in values:
                                cf.write(v + "\n")

                        # Show first few in main report
                        show_count = min(5, len(values))
                        for v in values[:show_count]:
                            # Truncate long values
                            display = v[:120] + "..." if len(v) > 120 else v
                            if critical:
                                # Partially mask tokens
                                if len(display) > 20:
                                    display = display[:10] + "****" + display[-6:]
                            f.write(f"    {display}\n")
                        if count > show_count:
                            f.write(f"    ... and {count - show_count} more"
                                    f" (see comms/{app}_{cat}.txt)\n")
                        f.write("\n")

            f.write("=" * 70 + "\n")

        # JSON output
        # Convert sets to lists for JSON serialization
        json_safe = json.loads(json.dumps(results, default=lambda x: sorted(x) if isinstance(x, set) else str(x)))
        json_path.write_text(json.dumps(json_safe, indent=2, default=str),
                             encoding="utf-8")

        self.log.info("Comms report: %s (%d artifacts from %d apps)",
                      txt_path, total, len(detected))
        return txt_path
