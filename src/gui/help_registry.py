"""Help text for every control + glossary. Plain language, written for juniors.

Each entry: (title, what it is, what happens, example, when to use).
Widgets reference entries through the Qt property "help_key"; the automated
check in gui/help_check.py fails if any interactive widget lacks one.
"""

H = {
    # ── toolbar ────────────────────────────────────────────────────────────
    "tb.open": ("Open memory dump",
        "Picks the RAM image (memory dump) you want to analyse.",
        "A file dialog opens; the chosen file is put into the 'Memory dump' field. Nothing runs yet.",
        "C:\\Cases\\4711\\laptop.raw or a .vmem / .lime / .mem / .dmp file.",
        "At the start of every case. You can also drag a file onto the window."),
    "tb.run": ("Start analysis",
        "Starts the analysis with the settings shown on the left.",
        "RAMBreaker detects the OS (unless you told it), resolves symbols, runs the plugins in parallel, extracts strings and IOCs, evaluates Sigma rules and writes the report. Progress, ETA and logs update live.",
        "Pick laptop.raw, keep the 'Standard' preset, press Start.",
        "When the dump and options are set. The button is disabled while a run is active."),
    "tb.stop": ("Stop analysis",
        "Stops the running analysis.",
        "The analysis process and its Volatility children are terminated. Results written so far stay on disk and can still be opened.",
        "A run on a 30 GB dump takes too long and you only needed the process list.",
        "Only when you really want to abort; a stopped run is incomplete."),
    "tb.output": ("Open output folder",
        "Opens the folder that holds this case's results in Windows Explorer.",
        "Explorer opens on output\\<dump name> (JSON, TXT, IOCs, report.html, logs).",
        "To copy report.html into a ticket or to inspect a raw plugin JSON file.",
        "After or during a run."),
    "tb.report": ("Open HTML report",
        "Opens the generated HTML report in your default browser.",
        "report.html opens; it has the full tab set (summary, correlation, injection, IOCs, Sigma ...). It is a single offline file.",
        "Share the case with a colleague who has no RAMBreaker installed.",
        "Once the 'HTML report' stage has finished."),
    "tb.loadresults": ("Load existing results",
        "Opens the results of an earlier run without re-analysing.",
        "Pick an output folder; the results viewer fills from its JSON files.",
        "Re-open yesterday's case output\\laptop_raw.",
        "To review a finished case or results produced by the command-line tool."),
    "tb.helpmode": ("Help mode",
        "A switch that turns every click into a help request.",
        "While it is on, clicking any button, field or tab shows its help instead of doing anything. Click the switch again to return to normal.",
        "Turn it on and click 'Engine' to learn what Vol2 vs Vol3 means.",
        "When you are new to the tool or unsure what a control does."),
    "tb.tour": ("Guided tour",
        "A short step-by-step walkthrough of the main screen.",
        "Each part of the window is highlighted in turn with an explanation. Press Next/Back, or Esc to quit.",
        "First day using RAMBreaker.",
        "Any time; it also runs automatically on first start."),
    "tb.settings": ("Settings",
        "Paths, theme, performance and timeout options.",
        "A dialog opens; changes are saved to config\\gui_settings.json beside the program.",
        "Change the default output folder to a larger disk.",
        "When defaults do not fit your machine or workflow."),
    "tb.theme": ("Dark / light theme",
        "Switches between the dark (default) and the light colour theme.",
        "The whole window recolours immediately; the choice is remembered.",
        "Use light theme on a projector in a bright room.",
        "Whenever readability matters."),
    "tb.glossary": ("Glossary",
        "A searchable list of forensic terms used in this tool.",
        "Opens a window with definitions of OS profile, ISF, BTF, plugin, IOC, Sigma, timeout and more.",
        "Search 'ISF' to learn what a symbol table is.",
        "Whenever a term in the UI or logs is unfamiliar."),
    "tb.about": ("About",
        "Version information for RAMBreaker, Volatility 2 and Volatility 3.",
        "Shows exact versions/commits of the bundled engines and licences.",
        "Quote the versions in your forensic report.",
        "For documentation and support."),
    # ── case setup ─────────────────────────────────────────────────────────
    "setup.dump": ("Memory dump",
        "Path of the RAM image to analyse.",
        "The run reads this file. It is NEVER modified - RAMBreaker only reads it.",
        "D:\\Evidence\\srv01.mem",
        "Always required. Drag & drop a file here or use Browse."),
    "setup.browse": ("Browse for dump",
        "Opens a file dialog to pick the memory image.",
        "The chosen path goes into the 'Memory dump' field.",
        "Navigate to the evidence drive and pick the .raw file.",
        "When you don't want to type or drag the path."),
    "setup.drop": ("Drop zone",
        "Drag a memory dump from Explorer and drop it here.",
        "The dropped file path is put into the 'Memory dump' field.",
        "Drag laptop.vmem from the case folder onto this box.",
        "The quickest way to load a dump."),
    "setup.known": ("I already know this image",
        "Skips automatic OS detection and uses what you enter.",
        "When ticked, the OS / profile / symbol-file fields are used directly; detection (which can take minutes on big images) is skipped.",
        "You know it is a Windows 7 SP1 x64 box: tick, choose Windows and profile Win7SP1x64.",
        "Only when you are sure. A wrong choice makes plugins return nothing; leave it off when in doubt."),
    "setup.os": ("Operating system",
        "The OS of the machine the RAM came from.",
        "Selects which plugin family runs (windows.*, linux.*, mac.*).",
        "Linux for a server dump taken with LiME.",
        "Only with 'I already know this image'."),
    "setup.version": ("OS version (notes)",
        "Free-text OS version, kept in the case notes and log.",
        "Recorded in the log for your report; detection is not affected.",
        "Windows 10 22H2, Ubuntu 22.04, Kali 2024.4",
        "Optional, for documentation."),
    "setup.profile": ("Volatility 2 profile",
        "The Vol2 profile name that matches the Windows build.",
        "Volatility 2 uses it instead of guessing via imageinfo.",
        "Win7SP1x64, Win10x64_19041",
        "Only when you know it; leave empty to let RAMBreaker detect it."),
    "setup.isf": ("Symbol file (ISF)",
        "Your own Volatility 3 symbol table (.json / .json.xz) for a Linux or macOS image.",
        "The automatic symbol ladder (community repo, debug packages, BTF) is skipped and this file is used.",
        "Ubuntu_5.15.0-41-generic.json.xz that you built earlier.",
        "When you already have the exact ISF for this kernel."),
    "setup.isfbrowse": ("Browse for ISF",
        "Opens a file dialog to pick a symbol (ISF) file.",
        "The path goes into the 'Symbol file' field.",
        "Pick the .json.xz built for this kernel.",
        "Together with 'Symbol file'."),
    "setup.v2zip": ("Volatility 2 profile zip",
        "A Volatility 2 Linux/macOS profile: a .zip with module.dwarf and System.map for one exact kernel.",
        "The zip is installed beside the program (cache\\vol2_profiles) and the image is analysed with "
        "Volatility 2 using it. RAMBreaker also tries installed profiles automatically when no "
        "Volatility 3 symbol table can be found.",
        "Debian5_26.zip for a Debian 5 (kernel 2.6.26) server.",
        "For old Linux kernels (before ~4.x) that have no Vol3 symbols and no BTF."),
    "setup.v2zipbrowse": ("Browse for Vol2 profile", "Pick a Volatility 2 profile .zip.",
        "The path goes into 'Vol2 profile zip'.", "Debian5_26.zip", "With 'Vol2 profile zip'."),
    "setup.preset": ("Analysis preset",
        "A ready-made recipe: which pipeline runs (plugins only, or plugins + strings, IOCs, "
        "Sigma and the HTML report, or all that + EVTX) and which plugins it uses.",
        "Picking a preset fills in 'Plugin category' and 'Fast mode' below and updates the "
        "estimated time. Quick triage = quick plugins only, no report; Standard = everything "
        "except EVTX; Full DFIR = Standard + EVTX carving + slow Vol2 extras; the focus presets "
        "run one category of plugins plus the full analysis. Click ? for the animated guide.",
        "Quick triage to get a process list and connections in minutes; Standard for a real case.",
        "Standard is right for most cases."),
    "setup.mode": ("Plugin set",
        "Which group of Volatility plugins runs (now two controls: Plugin category + Fast mode).",
        "fast = essentials; full = everything; malware / network / persistence / registry = focused sets.",
        "network for a suspected C2 beacon investigation.",
        "Usually set by the preset; change it to narrow or widen the plugin list."),
    "setup.category": ("Plugin category",
        "WHAT the plugins look at: everything, or one investigation topic (malware, network, "
        "persistence, registry).",
        "Only the Volatility plugins of that category run; strings, IOCs, Sigma and the report "
        "still run on whatever they produce. Linux and macOS have no persistence/registry set: "
        "those choices run the complete set there. Locked to 'All categories' while Fast mode "
        "is on. Click ? for the animated guide with the exact plugin lists.",
        "Network for a suspected C2 beacon: 7 Windows plugins instead of 33.",
        "Keep 'All categories' unless you know exactly what you are hunting and want a shorter run."),
    "setup.fastmode": ("Fast mode",
        "HOW MUCH runs: a short, curated set of the cheapest high-value plugins (about a third "
        "of the complete set), across all categories.",
        "The run uses the quick plugin set (CLI -m fast): processes, command lines, network, "
        "malfind, services, hashes, registry hives and the file list. Slow scans (handles, "
        "DLL lists, VADs, mutants, MFT ...) are skipped. With the Standard preset the strings, "
        "IOC, Sigma and report steps still run. It does NOT change RAM use or parallel jobs.",
        "Windows 2 GB: 11 plugins (~7 min) instead of 33 (~21 min).",
        "First look at a big dump, or when time matters more than completeness."),
    "setup.speed": ("RAM / jobs mode",
        "How hard the PC may work: how much RAM each parallel plugin may take and whether the "
        "RAM guard can lower 'Parallel jobs'. It never changes WHICH plugins run.",
        "normal = keeps ~1.5 GB free per job and lowers jobs when RAM is short; fast = ~1 GB per "
        "job, so more jobs stay running; fastest = exactly 'Parallel jobs', no RAM guard and no "
        "slow-disk limit. Click ? for the animated guide.",
        "fastest on a 64 GB analysis workstation with the dump on an SSD.",
        "Keep normal on a laptop or a VM; this is not the same thing as Fast mode."),
    "setup.engine": ("Engine",
        "Which Volatility version runs the plugins.",
        "Auto picks the best one (Vol3 normally, Vol2 for old Windows XP-era images). Vol2-only plugins still run in the background where useful.",
        "Force Vol2 for a Windows XP image.",
        "Leave on Auto unless you have a specific reason."),
    "setup.jobs": ("Parallel jobs",
        "How many plugins run at the same time.",
        "More jobs = faster but more RAM. A RAM guard lowers it automatically when memory is short (except in 'fastest').",
        "4 on a 16 GB machine; 8 on a 32 GB workstation.",
        "Lower it if the PC becomes sluggish."),
    "setup.ioclist": ("IOC list",
        "A text file with indicators to look for (one per line).",
        "After the analysis, every IOC is searched in the raw dump (ASCII + UTF-16), all plugin outputs and dumped files; hits show plugin, process and offset.",
        "threat_intel.txt with 150 IPs, domains, URLs and hashes from a TI feed.",
        "Whenever you have indicators from an alert or threat report."),
    "setup.iocbrowse": ("Browse for IOC list",
        "Pick the IOC list file.",
        "The path goes into 'IOC list'.",
        "Choose iocs.txt or a CSV export.",
        "Together with 'IOC list'."),
    "setup.iocclear": ("Clear IOC list",
        "Removes the IOC list from this run.",
        "No IOC check will be done.",
        "You picked the wrong file.",
        "When you do not want an IOC check."),
    "setup.output": ("Output folder",
        "Where the results of this case are written.",
        "A sub-folder named after the dump is used; existing results there are reused/overwritten.",
        "E:\\Cases\\4711\\ram",
        "Leave the default (output\\ beside the program) unless disk space is short."),
    "setup.outbrowse": ("Browse output folder",
        "Pick the folder for results.",
        "The path goes into 'Output folder'.",
        "Choose a big data disk.",
        "When the default location is not suitable."),
    "setup.estimate": ("Estimated time",
        "Predicted run time from the calibrated timing model.",
        "Computed from dump size, OS and each plugin's measured cost; refined live during the run.",
        "~14 min for a 2 GB Windows dump with the Standard preset.",
        "Check it before starting a long run."),
    "setup.queue.list": ("Queue",
        "The memory dumps waiting to be analysed, in the order they will run.",
        "Each entry keeps the preset and options that were set when it was added. Hover an entry to see its dump, "
        "case folder and command. Entries disappear from the list as they start.",
        "windows10.dmp - Quick triage, then ubuntu.mem - Quick triage.",
        "When you have several dumps (several machines of one incident) and want them analysed unattended."),
    "setup.queue.add": ("Add to queue",
        "Adds a dump to the queue with the preset and options chosen above.",
        "With a dump in the 'Memory dump' field that dump is added; with the field empty a file picker opens and "
        "you can choose several dumps at once. Dropping several files on the window also adds them. You can add "
        "more while a queue is running.",
        "Pick the Standard preset, press Add to queue, choose five dumps.",
        "Before pressing Start queue, or during a run to line up more work."),
    "setup.queue.remove": ("Remove from queue",
        "Removes the selected queue entries, or the last one when nothing is selected.",
        "Only the waiting entry is removed; a dump that is already being analysed is not affected.",
        "Select a dump added by mistake and press Remove.",
        "When the queue holds something you do not want to run."),
    "setup.queue.start": ("Start queue",
        "Analyses the queued dumps one after another.",
        "Each dump gets its own case folder and report. When one finishes (or fails) the next starts by itself; a "
        "summary is written to the log at the end. Stop ends the current dump and keeps the rest in the list. "
        "Dumps never run at the same time: memory analysis needs the whole PC.",
        "Queue three dumps in the evening, press Start queue, read three reports in the morning.",
        "When more than one dump has to be analysed."),
    "setup.start": ("Start analysis",
        "Starts the analysis with the options above.",
        "Same as the Start button in the toolbar.",
        "Press after choosing the dump.",
        "When everything is set."),
    # ── progress ───────────────────────────────────────────────────────────
    "prog.overall": ("Overall progress",
        "How far the whole analysis is.",
        "Moves as stages and plugins finish.",
        "62 % - plugins done, strings running.",
        "Watch it to know how long remains."),
    "prog.stage": ("Current stage",
        "What RAMBreaker is doing right now, in plain words.",
        "Updates on every stage change (Detecting OS, Resolving symbols, Running plugins ...).",
        "Running windows.netscan (12/33).",
        "Read it when the bar seems slow."),
    "prog.heartbeat": ("Heartbeat",
        "Shows the analysis is alive and when it last produced output.",
        "Pulses continuously; turns amber only when nothing happened for a long time, and tells you what the tool will do about it.",
        "last activity: 4 s ago",
        "If you wonder whether the tool hangs."),
    "prog.plugins": ("Plugin status",
        "Every Volatility plugin of this run with its state.",
        "queued / running (spinner) / done / failed / timed out / skipped, plus duration and timeout. Failed, timed-out, skipped and not-run plugins get a retry button in the last column. After a run (or Load results) the list shows the case's plugins as saved on disk.",
        "windows.malfind - running - 37 s of 380 s",
        "To see which plugin is slow or failed."),
    "prog.retry": ("Retry this plugin",
        "The circular-arrow button beside a plugin that failed, timed out, was skipped because a plugin it needs failed, or never ran.",
        "A confirm box opens: it says what went wrong, lets you choose the time limit (pre-filled with double the limit it was killed at, or no limit), lists the skipped plugins that will run with it, and warns that the HTML report is recreated. During an analysis the retry is queued and starts when the analysis finishes.",
        "windows.netscan timed out at 380 s -> press the button, keep 760 s, Retry now. Network map, correlation, timeline, Sigma and the report are rebuilt with the new connections.",
        "When a plugin you need is missing from the results. Also works on old cases opened with Load results."),
    "retry.limit": ("Retry time limit",
        "How long the retried plugin may run before RAMBreaker kills it.",
        "The plugin runs once with exactly this limit (no automatic extra retry). If it is killed again it is marked TIMED OUT in the report.",
        "Killed at 1767 s -> pre-filled 3534 s (about 59 min).",
        "Raise it for big dumps or slow disks; the estimate under the field shows the calibrated time."),
    "retry.nolimit": ("No time limit",
        "Lets the retried plugin run until it finishes.",
        "The limit field is ignored; the plugin runs until it is done or you press Stop in the toolbar.",
        "windows.vadinfo on a 34 GB dump that needs more than an hour.",
        "When you are sure the plugin is slow but not stuck, and you can wait."),
    "retry.ok": ("Retry now / Queue retry",
        "Starts the retry (or queues it while an analysis is running).",
        "The plugin (and the plugins skipped because of it) run again, then the analysis steps that read plugin output and the HTML report are rebuilt. The strings/IOC scan, IOC-list check, EVTX dump and threat intel are not redone.",
        "Retry netscan -> about 30 s of rebuilding after the plugin on a 2 GB dump.",
        "After choosing the time limit."),
    "retry.cancel": ("Cancel",
        "Closes the box without retrying.",
        "Nothing runs and nothing changes; the retry button stays.",
        "You opened the box only to read why the plugin failed.",
        "Any time."),
    "prog.ram": ("Memory map animation",
        "A live picture of the dump being processed.",
        "Cells fill as stages and plugins complete; colours show the stage type (blue scan, teal symbols, amber extraction, red IOC hits). It shimmers between steps so it never looks frozen.",
        "Half the module is lit: about half the work is done.",
        "Just a visual aid; the numbers next to it are exact."),
    # ── log console ────────────────────────────────────────────────────────
    "log.view": ("Live log",
        "Everything the tool does, as it happens.",
        "New lines stream in, coloured by level (info, warning, error, success). The same lines go to the log file.",
        "[21:40:12] Running windows.pslist (expected ~2 s, timeout 120 s)",
        "To follow or troubleshoot a run."),
    "log.pause": ("Pause auto-scroll",
        "Stops the log from jumping to the newest line.",
        "Lines keep arriving but the view stays where you are reading.",
        "Pause to read a warning while plugins keep running.",
        "When you want to read older lines during a run."),
    "log.level": ("Level filter",
        "Shows only lines of a given importance.",
        "All / Warnings+errors / Errors only / Success.",
        "Errors only - see quickly what failed.",
        "When the log is long."),
    "log.search": ("Search log",
        "Filters the log to lines containing this text.",
        "Only matching lines stay visible; clear the field to see all.",
        "netscan",
        "To find everything about one plugin or IOC."),
    "log.copy": ("Copy log",
        "Copies the visible log lines to the clipboard.",
        "Paste them into a ticket or e-mail.",
        "Copy errors only for a support request.",
        "When sharing what happened."),
    "log.openfile": ("Open log file",
        "Opens the full log file of this case.",
        "crescent_toolkit.log opens in your text editor.",
        "Check DEBUG-level command lines.",
        "For deep troubleshooting."),
    "log.clear": ("Clear view",
        "Empties the log view (not the log file).",
        "The window is cleared; the log file on disk is untouched.",
        "Start a new run with a clean view.",
        "Cosmetic only."),
    # ── results ────────────────────────────────────────────────────────────
    "res.nav": ("Case navigator",
        "Tree of everything the case produced: dump, plugins, IOCs, findings.",
        "Click an item to open it in a tab on the right.",
        "Findings > Sigma hits",
        "To move around the results."),
    "res.tabs": ("Result tabs",
        "Open result views (summary, processes, network, IOCs, e-mail, Sigma ...).",
        "Each tab is a sortable, filterable table or summary.",
        "Processes tab sorted by start time.",
        "Main reading area after a run."),
    "res.filter": ("Table filter",
        "Shows only rows that contain this text (any column).",
        "The table below filters as you type.",
        "powershell",
        "To find a process, IP or IOC quickly."),
    "res.table": ("Result table",
        "Rows from a plugin or analysis output.",
        "Click a header to sort; drag to resize; select cells and Ctrl+C to copy.",
        "Sort netscan by ForeignAddr.",
        "Reading results."),
    "res.export": ("Export CSV",
        "Saves the current table (after filtering) as CSV.",
        "A save dialog opens; the CSV opens in Excel.",
        "Export the IOC hits for the incident ticket.",
        "When sharing a table."),
    "res.openreport": ("Open HTML report", "Opens report.html for this case.",
        "Your browser opens the offline HTML report.", "Send it to the lead investigator.",
        "When you want the full report view."),
    # ── settings dialog ────────────────────────────────────────────────────
    "set.theme": ("Theme", "Colour theme of the window.", "Applied immediately.",
        "Dark", "Personal preference."),
    "set.outdir": ("Default output folder", "Where new cases are written by default.",
        "Used for every new analysis unless you change it per case.",
        "E:\\RAMBreaker\\output", "When the program disk is small."),
    "set.outbrowse": ("Browse", "Pick the default output folder.", "Fills the field.",
        "Choose E:\\Cases", "With 'Default output folder'."),
    "set.jobs": ("Default parallel jobs", "Default for 'Parallel jobs'.",
        "Used when a new case is set up.", "4", "Tune once for your PC."),
    "set.speed": ("Default RAM / jobs mode", "Default for 'RAM / jobs mode' on the setup panel "
        "(stored as normal / fast / fastest, the same words as the CLI --speed).",
        "Used for new cases. It changes RAM use and parallelism only, never which plugins run "
        "(that is 'Fast mode').", "normal", "Tune once for your PC."),
    "set.fixedto": ("Use fixed timeout",
        "Turns off the calibrated per-plugin timeouts.",
        "Every plugin gets the same timeout (below) instead of one computed from dump size and measured plugin cost.",
        "Fixed 600 s for reproducing an old run.",
        "Rarely; the calibrated model is better."),
    "set.timeout": ("Fixed timeout (s)", "Timeout used when 'Use fixed timeout' is on.",
        "Each plugin is killed after this many seconds.", "900", "Only with fixed timeout."),
    "set.attrib": ("Attribute IOC hits to processes",
        "After the IOC check, find which process memory contains each hit.",
        "Runs an extra Volatility YARA scan for IOCs that were found; slower but tells you the PID.",
        "Find which process holds the C2 domain.", "Keep on unless the run must be fast."),
    "set.anim": ("Animation", "Show the RAM animation during runs.",
        "Off = a static progress view (saves a little CPU).", "On", "Turn off on very slow PCs."),
    "set.tour": ("Show tour on start", "Runs the guided tour when the program starts.",
        "Tour opens at start-up.", "On for a new team member's PC.", "Training setups."),
    "set.ok": ("Save", "Saves the settings.", "Settings are written and applied.", "-", "After changes."),
    "set.cancel": ("Cancel", "Closes without saving.", "Changes are discarded.", "-", "To undo edits."),
    # ── threat intel (v2.2) ──
    'set.tidb': ('Threat-intel databases', 'Shows the YARA rule sets and threat feeds RAMBreaker uses, how old each copy is, and lets you update them.', 'A window lists every database with its age. Tick the ones to refresh and press Update; nothing is updated unless you ask.', 'The IPsum list is 12 days old before a ransomware case: tick it and update.', 'Before a threat-intel run, when you have internet access.'),
    'tb.ti': ('Threat intel on this case', 'Runs the threat-intel step on the case that is loaded now, without repeating the analysis.', "Every file and process executable is dumped and hashed, injection-flagged regions are dumped, everything is checked with YARA and the offline feeds, then a short list goes to VirusTotal if you gave a key. The results go to report.html, tab 'Threat Intelligence'.", "Yesterday's Standard run of laptop.raw: load it and add threat intel.", "For cases analysed before, or with another preset than 'DFIR + Threat Intel'."),
    'tb.ticont': ('Continue VirusTotal lookups', 'Looks up the shortlisted items that were not checked last time (free-key quota or lookup limit reached).', "No new dump or scan: only the items marked 'not checked' are sent; answers already known come from the cache. The report is rebuilt.", 'Yesterday 500 lookups used the daily quota; today you continue with the rest.', "When the report says 'not checked' for some items."),
    'tb.tidb': ('Threat-intel databases', 'Shows the YARA rule sets and threat feeds, their age, and updates the ones you tick.', 'A window lists every database; out-of-date ones are marked. Updating downloads the newest copy from its publisher (nothing about your case is sent).', 'IPsum is 9 days old: tick it, press Update.', 'Before a threat-intel run when you are online. Updating is never automatic.'),
    'ti.db.table': ('Threat-intel databases', 'Every database the threat-intel step checks against, with where its copy comes from, the space it uses on disk (Size), its age and its number of entries.', "Tick a row to include it in the next update (or in Delete ticked downloads). 'bundled' copies ship with RAMBreaker; 'downloaded' ones were fetched on this PC; 'not downloaded' ones are skipped until you update them. Rows marked 'optional' are large local hash databases (MalwareBazaar full set, VirusShare, NIST NSRL known files): they are never ticked for you. Tick one yourself to install it; the Copy column shows its download size. With them installed, file hashes are checked on this PC and VirusTotal is not needed for known hashes.", 'Maltrail trails: downloaded, 2 days, 1,895,768 entries.', 'To see how fresh your threat intelligence is. Hover a name for what it contains and its licence.'),
    'ti.db.abusekey': ('abuse.ch Auth-Key', 'Optional free key for the abuse.ch ThreatFox, URLhaus and MalwareBazaar downloads.', 'With a key those three databases can be updated; the key is stored encrypted for your Windows user. Without it they are skipped.', 'Sign in at https://auth.abuse.ch/, create a key, paste it here.', 'If you want malware hashes and C2 indicators tagged with their malware family.'),
    'ti.db.tickstale': ('Tick out-of-date', 'Ticks every database that is older than 7 days or not downloaded yet.', 'Only the ticks change; nothing is downloaded until you press Update.', 'Three feeds are 10 days old: one click ticks them.', 'Before pressing Update.'),
    'ti.db.update': ('Update ticked databases', 'Downloads the newest copy of every ticked database from its publisher.', 'Each file is checked before it replaces the old copy, so a failed or cancelled download never breaks a working database. While it runs you see which database is being fetched, how much is downloaded and left, the download speed and the time left, and you can Pause, Resume or Cancel it. Takes about 20 s on a normal connection for the standard feeds. The optional hash databases are far bigger: minutes for MalwareBazaar (230 MB) and VirusShare (1.4 GB), hours and over 100 GB of free disk space for the full NSRL set; RAMBreaker warns first when the drive does not have the space.', 'Update IPsum, Maltrail and Spamhaus DROP before a new case.', 'When you are online and a database is old. It is always your choice.'),
    'ti.db.delete': ('Delete ticked downloads', 'Deletes the downloaded copies of the ticked databases to free disk space.', "Only copies downloaded on this PC are deleted, with any temporary files an interrupted update left behind. Copies that ship with RAMBreaker (IPsum, Feodo, YARA Forge) are never deleted: that copy is used again. The two NSRL rows share one database, so deleting either removes it. You are asked first and told how much space is freed; Update downloads a database again. A database that an analysis is reading right now cannot be deleted until that analysis ends. The button is active when a ticked row has a downloaded copy.", 'Tick VirusShare and press Delete: about 1.5 GB is freed.', 'When a large optional database is no longer needed or the disk is getting full.'),
    'ti.db.pause': ('Pause / Resume', 'Pauses the running update; press Resume to continue.', 'Nothing is lost while paused: the download continues where it stopped. If the server closed the connection during a long pause, RAMBreaker asks it for the rest of the file; a server that cannot do that sends the file again from the start. Building a local database (MalwareBazaar, NSRL) pauses too.', 'Pause the VirusShare download while you need the bandwidth for a call, resume afterwards.', 'When you need the connection or the disk for something else for a while.'),
    'ti.db.cancel': ('Cancel', 'Stops the running update.', 'The database being downloaded keeps its previous copy (the partial download is removed). Databases finished earlier in the same update keep their new copies; the remaining ones are not started. VirusShare keeps the lists it already installed and continues from there on the next update. A download that is waiting for a slow server can take up to a minute to stop.', 'Cancel a 19 GB NSRL download you started by mistake.', 'When an update takes too long or was started by mistake.'),
    'ti.db.progress': ('Update progress', 'Which database is being updated, how much is downloaded and how much is left, the download speed and the time left.', "The speed is averaged over the last few seconds. When the server does not say the size of a file, or while a download is turned into a local database (MalwareBazaar, NSRL) or VirusShare fetches its hundreds of small lists, the bar moves without a percentage. 'Paused' is shown while paused.", 'Database 2 of 4: abuse.ch MalwareBazaar - 120.5 MB of 231.0 MB  ·  110.5 MB left  ·  4.2 MB/s  ·  about 26 s left', 'While an update runs.'),
    'ti.db.disk': ('Disk space', 'Free space left on the drive that holds the threat-intel databases, and how much space all databases use together.', 'Refreshed while an update runs. The Size column shows each database. Before an update that needs more free space than the drive has, RAMBreaker warns you.', 'Free disk space on D: 154.2 GB  ·  threat-intel databases use 1.3 GB', 'Before installing a large optional database, and to see what Delete would free.'),
    'ti.close': ('Close', 'Closes the database window.', 'Nothing else happens. If an update is running, RAMBreaker asks whether to cancel it first.', '-', 'When done.'),
    'ti.vtkey': ('VirusTotal API key', 'Your personal VirusTotal key. Used only for lookups of the short list: SHA-256 hashes, public IP addresses and domain names.', 'The key is handed to the analysis process privately (never on the command line or in a log). Files are never uploaded.', 'Free key from virustotal.com > your profile > API key.', 'When you want VirusTotal verdicts in the report. Leave empty for local checks only.'),
    'ti.remember': ('Remember the key', 'Stores the VirusTotal key encrypted with Windows DPAPI for your user account on this PC.', 'Next time the key is filled in. Copying the RAMBreaker folder to another PC does not copy a usable key. Untick to forget a stored key.', 'Your own analysis workstation.', 'On a PC only you use. Untick on shared machines.'),
    'ti.novt': ('Local checks only', 'Runs the threat-intel step without VirusTotal.', 'Dump, hashes, YARA and offline feeds still run; nothing leaves the PC. The VirusTotal column stays empty.', 'A case under strict confidentiality rules.', 'When you have no key, no internet, or must not contact external services.'),
    'ti.rate': ('Lookups per minute', 'How fast RAMBreaker asks VirusTotal.', 'Requests are spaced to stay under this rate. A free key allows 4 per minute; a premium key allows far more.', 'Free key: 4. Premium key: 300.', 'Change it only if your key has a higher quota.'),
    'ti.max': ('Maximum new lookups', 'Upper limit of new VirusTotal requests in this run (answers already in the cache do not count).', "The highest-scored items are looked up first; the rest is marked 'not checked' and can be continued later.", '100 at 4/min = up to 25 minutes.', 'Lower it for a quick run, raise it with a premium key. Free keys allow 500 per day.'),
    'ti.yaraset': ('YARA rule set', "Which bundled YARA Forge package is used: 'core' (about 5,100 well-tested rules) or 'extended' (about 10,900, including threat-hunting rules).", 'Every dumped file, process executable and flagged memory region is scanned with it, plus your custom rules.', 'core for a normal case; extended when hunting for anything unusual.', "Keep 'core' unless you accept more false positives for more coverage."),
    'ti.customdir': ('Extra rules folder', 'An optional folder with your own YARA rules (.yar / .yara), used in addition to yara_rules\\custom.', 'Every rule file found there is compiled on its own (a broken file is skipped and named in the report). Hits of your own rules count as HIGH.', 'D:\\Rules\\company_yara', 'When your team keeps its own rules somewhere else.'),
    'ti.browsecustom': ('Browse', 'Picks the extra rules folder.', 'A folder dialog opens.', '-', 'To choose the folder.'),
    'ti.opencustom': ('Open custom rules folder', 'Opens yara_rules\\custom beside RAMBreaker.exe in Explorer.', 'Drop .yar / .yara files there; they are used in every threat-intel run.', 'Save case_4711_loader.yar there before the run.', 'To add your own rules.'),
    'ti.protect': ('Protect dumped files', 'Every file, process executable and memory region the threat-intel step dumps goes straight into its own password-protected ZIP (AES-256) instead of a plain file.', 'The plain file never touches this disk, so nothing can be started by accident and the virus scanner cannot quarantine the evidence. Hashes and YARA still work: YARA decrypts each object in memory only. A dump from an earlier run is zipped when it is reused. Same setting as in the Extraction workspace.', 'threat_intelligence\\dumps\\processes\\pid_4084_DumpIt.exe\\exe\\4084.DumpIt.exe.0x3a0000.dmp.zip', 'Keep it on unless this is an isolated analysis machine.'),
    'ti.zippw': ('ZIP password', 'Password of the protected ZIPs. Default: infected (the malware-exchange convention).', 'Open a ZIP with 7-Zip, or with the built-in command  tar -xf <name>.zip --passphrase infected  - in an isolated VM.', 'infected', 'Change it only if your lab uses another convention.'),
    'ti.start': ('Start', 'Starts the run with these options.', 'The dialog closes and the run monitor shows the progress.', '-', 'When the options are set.'),
    'ti.cancel': ('Cancel', 'Closes without running.', 'Nothing is started; a key you typed is not stored.', '-', 'To go back.'),
    # ── misc dialogs ──────────────────────────────────────────────────────
    "gl.search": ("Glossary search", "Filters the glossary.", "Only matching terms stay listed.",
        "ISF", "To find a definition fast."),
    "gl.list": ("Glossary terms", "All terms; click one to read its definition.",
        "The definition shows on the right.", "BTF", "Learning the vocabulary."),
    "gl.text": ("Definition", "The explanation of the selected term.", "Read-only.", "-", "-"),
    "dlg.close": ("Close", "Closes this window.", "Nothing else happens.", "-", "When done."),
    "dock.float": ("Detach panel", "Pops this panel out into its own window.",
        "The panel floats; drag it back onto an edge of the main window to dock it again.",
        "Float the Live log onto a second monitor.", "On multi-monitor setups."),
    "dock.close": ("Hide panel", "Hides this panel.",
        "Bring it back via View > (panel name).", "Hide the Case setup panel to give results more room.",
        "When you need more space."),
    "ui.more": ("More", "Shows toolbar/menu items that do not fit the window width.",
        "A small menu with the hidden items opens.", "-", "On small screens."),
    "about.text": ("Version details", "Exact versions of the bundled engines and licences.",
        "Read-only text; select and copy for your report.", "Volatility 3 2.28.2 (881e9701)",
        "When documenting your tooling."),
    "res.summarytext": ("Run summary", "Run health and the SUMMARY.txt of this case.",
        "Read-only; shows status (healthy/degraded/broken), OS, banner and per-plugin results.",
        "Run health: degraded - 1 plugin timed out.", "First thing to read after a run."),
    # -- extraction workspace (files / processes / VAD / string hunt / export) --
    "tb.extract": ("Extract", "Opens the Extraction workspace for the loaded case.",
        "A tab opens with five pages: Files, Processes, Memory regions (VAD), String hunt and Export pack. "
        "Lists come from the finished analysis, so browsing is instant; only the extraction itself runs Volatility.",
        "Pull System.evtx and the hosts file out of laptop.raw, or dump the injected region malfind found.",
        "After an analysis has finished (or after Load results)."),
    "x.overview": ("Extraction workspace",
        "Gets real data OUT of the memory dump: files, process executables/DLLs/memory, memory regions, string hits.",
        "Each extraction runs in the background and writes its output plus a manifest (size, type, SHA-256, MD5) "
        "into its own folder under 'Save to'. Nothing in the dump is ever changed.",
        "Files tab: search 'hosts', tick it, press Extract -> extracted\\files_20261112_1510\\files\\...hosts.dat",
        "Whenever you need the actual bytes for a sandbox, YARA, a hash lookup or a report."),
    "x.dump": ("Memory dump of this case",
        "The dump file the extraction reads. Filled in from the case's SUMMARY.txt.",
        "If the dump was moved (orange border), extraction cannot start until you point to it with Browse.",
        "D:\\Cases\\4711\\laptop.raw", "Only when the dump is no longer where the analysis found it."),
    "x.dumpbrowse": ("Locate dump", "Picks the memory dump for this case.",
        "A file dialog opens; the chosen file is used for every extraction of this case.",
        "The case was analysed on another PC and the dump now sits on E:\\.", "When the dump path is wrong."),
    "x.dest": ("Save to", "The base folder that receives extracted data.",
        "Each extraction creates a new sub-folder here named after the job and time, e.g. procs_20261112_153012. "
        "Default: <case>\\extracted.", "E:\\Evidence\\4711\\extracted",
        "Change it to keep large dumps on another disk."),
    "x.protect": ("Protect extracted files",
        "Writes every extracted file straight into its own password-protected ZIP (<name>.zip, AES-256) "
        "instead of as a plain file. A file from a memory dump can be live malware such as ransomware.",
        "Volatility writes the encrypted ZIP itself, so the plain file never touches this disk: nothing can be "
        "started by a double-click and the virus scanner cannot quarantine the evidence. The results table and "
        "manifest still show the size, type and SHA-256/SHA-1/MD5 of the file inside. Unpack one only in an "
        "isolated analysis VM: 7-Zip, or the built-in command  tar -xf <name>.zip --passphrase infected. "
        "Windows Explorer cannot open these ZIPs. Volatility 2 output (old images) is plain for a moment and "
        "is zipped right after its run. The setting is shared with the threat-intel step.",
        "Dump the executable of a suspicious process: you get 4084.DumpIt.exe.0x3a0000.dmp.zip.",
        "Keep it on. Turn it off only on an isolated analysis machine where plain files are wanted."),
    "x.zippw": ("ZIP password", "The password of the protected ZIPs. Default: infected.",
        "'infected' is the convention used for exchanging malware samples, so colleagues and sandboxes "
        "recognise it. It is written into each extraction's PROTECTED_FILES_README.txt and manifest.",
        "infected", "Change it only if your lab uses another convention."),
    "x.destbrowse": ("Choose folder", "Picks the 'Save to' folder.", "A folder dialog opens.",
        "A larger data disk.", "Before a big extraction (full process memory can be GBs)."),
    "x.destopen": ("Open folder", "Opens the 'Save to' folder in Explorer.", "Explorer opens.", "-",
        "To look at what has been extracted."),
    "x.tabs": ("Extraction pages", "Files, Processes, Memory regions (VAD), String hunt, Export pack.",
        "Click a tab to switch. Ticks you made on one page are kept when you switch.", "-", "-"),
    "x.progress": ("Extraction progress", "Shows the running extraction: current item, progress and elapsed time.",
        "The bar fills per finished item; the text says what Volatility is working on. If Volatility is quiet for a "
        "while the elapsed time says so - large items (full process memory) simply take longer.",
        "[2/5] notepad.exe @ 0x7dd173f0", "While an extraction runs."),
    "x.stop": ("Stop extraction", "Stops the running extraction.",
        "The extraction process and its Volatility children are terminated; files already written stay.",
        "You ticked 40 processes for full memory by mistake.", "Only to abort."),
    # files
    "x.f.search": ("Search files",
        "Filters the file list by name or path. Every word must match (AND).",
        "The table shows only matching rows instead of the full list (often thousands of files).",
        "'winevt .evtx' shows the event logs; '\\Users\\ .lnk' shows shortcut files in user profiles; 'hosts'.",
        "To find the files you want to pull out."),
    "x.f.ext": ("File type", "Shows only one extension (with its count in this dump).",
        "The table is limited to that type; combine with the search box.", ".exe (57)",
        "To browse e.g. all executables or all event logs."),
    "x.f.rec": ("Only recoverable",
        "Linux: hides files that have no pages in RAM (their content is not in this dump at all).",
        "Only files with cached pages stay listed.", "A 2 MB /var/log/auth.log with 300 cached pages is kept; "
        "a file with 0 cached pages is hidden.", "Leave it on unless you want the full inventory."),
    "x.f.table": ("File list",
        "Every file the analysis found in memory (Windows: filescan; Linux: page cache; macOS: list_files). "
        "Tick the checkbox of each file to extract.",
        "Click a header to sort; ticks are kept while you search.",
        "Tick \\Windows\\System32\\winevt\\Logs\\Security.evtx.", "Select what to extract."),
    "x.f.build": ("Build file list", "Runs the file-listing plugin once for this case.",
        "Windows: windows.filescan; Linux: linux.pagecache.Files (Vol2: linux_find_file -L); macOS: mac.list_files. "
        "The result is stored with the case, so this is needed only once.",
        "A Quick-triage case has no filescan yet.", "When the Files page says there is no file list."),
    "x.f.checkall": ("Check all shown", "Ticks every row currently shown by the search/type filter.",
        "All visible rows are ticked (asks first above 500).", "Search '.evtx', then Check all shown.",
        "To extract a whole group of files."),
    "x.f.uncheck": ("Uncheck all", "Clears every tick on this page.", "No file is selected any more.", "-",
        "To start a new selection."),
    "x.f.extract": ("Extract checked files", "Pulls the ticked files out of the dump.",
        "Windows: windows.dumpfiles by file-object address (several files per Volatility run). Each file can "
        "yield .dat (cached file data), .img (mapped executable image) and .vacb (cache views). Linux: page-cache "
        "pages of the inode. macOS: the resident page-cache pages. Files whose data is not in RAM are reported as "
        "'empty' - that is a fact about the dump, not an error.",
        "System.evtx -> file....DataSectionObject.System.evtx.dat (starts with 'ElfFile').",
        "When you need the file content."),
    # processes
    "x.p.search": ("Filter processes", "Filters the process list by PID, name, command line or flag.",
        "Only matching rows stay listed.", "'powershell' or '4732'.", "To find a process quickly."),
    "x.p.flagged": ("Only flagged", "Shows only processes with an observation (unexpected parent, hidden, "
        "injection hit, known tool name...).", "Unflagged processes are hidden.", "-",
        "To start from the leads the analysis found."),
    "x.p.table": ("Process list", "Processes from the analysis with their flags. Tick the ones to extract.",
        "Click a header to sort; Flags are observations, not verdicts.",
        "explorer.exe  - Injection: 0 HIGH, 2 MEDIUM", "Select processes."),
    "x.p.exe": ("Executable image",
        "Windows: the process's main EXE rebuilt from memory (windows.pslist --dump). Linux: the ELF executable "
        "and its loaded libraries (linux.elfs).",
        "One PE/ELF file per process, ready for hashing, a sandbox or a disassembler.",
        "2040.svchost.exe.0xff140000.dmp", "To check what binary really ran."),
    "x.p.dll": ("Loaded DLLs (Windows)", "Every DLL loaded into the process (windows.dlllist --dump).",
        "One file per DLL - often 50-150 files per process.", "explorer.exe -> 160 DLL files",
        "To look for a malicious or side-loaded DLL."),
    "x.p.mem": ("Full process memory",
        "All memory of the process in one file (Windows: windows.memmap --dump; Linux/macOS: every mapped region).",
        "Large output: typically 100 MB - 1 GB per process.", "svchost.exe -> pid.2040.dmp (307 MB)",
        "For carving, YARA or strings over everything the process held."),
    "x.p.checkflagged": ("Check flagged", "Ticks every flagged process.", "All processes with observations are "
        "ticked.", "-", "Quick start on suspicious processes."),
    "x.p.uncheck": ("Uncheck all", "Clears every process tick.", "-", "-", "-"),
    "x.p.extract": ("Extract checked processes", "Runs the extraction for the ticked processes.",
        "Output: pid_<PID>_<name>\\exe, \\dlls and \\memory folders plus the manifest. Several PIDs share one "
        "Volatility run where the plugin allows it.", "Tick explorer.exe and svchost.exe, Executable + DLLs.",
        "When you need process binaries or memory."),
    # VAD
    "x.v.modeproc": ("Whole process (every region)",
        "Dumps EVERY memory region (VAD) of each ticked process, one file per region.",
        "A folder per process with all regions: heaps, stacks, mapped files, private code. Complete but large.",
        "notepad.exe -> ~120 files / ~60 MB in pid_2140_notepad.exe\\",
        "When you want the whole address space for offline carving or YARA."),
    "x.v.modereg": ("Selected regions only",
        "Dumps only the regions you tick in the right-hand table (from one or several processes).",
        "One small file per ticked region; the manifest marks regions that look injected.",
        "malfind flagged explorer.exe at 0x3bd0000 (PAGE_EXECUTE_READWRITE) -> tick it -> one 64 KB file with "
        "exactly that code.", "When you already know which region matters (malfind/injection leads)."),
    "x.v.psearch": ("Filter processes", "Filters the process list on this page.", "Only matching rows stay.",
        "'svchost'", "-"),
    "x.v.procs": ("Processes", "Click a process to show its memory regions on the right. In 'Whole process' "
        "mode, tick the processes to dump.", "The region table fills with that process's VADs.",
        "Click explorer.exe.", "-"),
    "x.v.list": ("List regions", "Builds the region list for the selected process when the case has none.",
        "Runs windows.vadinfo / linux.proc.Maps / mac.proc_maps for that PID only (seconds to a minute) and "
        "stores it with the case.", "The Win11 case has no vadinfo output - press List regions for PID 4120.",
        "When the region table says there is no region list yet."),
    "x.v.regions": ("Memory regions",
        "The process's memory regions: start/end address, size, protection, tag and the mapped file (if any). "
        "'Injection flag' marks executable+writable or executable private regions - classic injected code.",
        "In 'Selected regions only' mode, tick the regions to dump.",
        "0x3bd0000  64 KB  PAGE_EXECUTE_READWRITE  RWX region - classic code injection",
        "To inspect and pick regions."),
    "x.v.checkinj": ("Check injection-flagged", "Ticks every region of this process that has an injection flag.",
        "Those regions are selected for extraction.", "-", "Fast path from a malfind lead to the bytes."),
    "x.v.uncheck": ("Uncheck regions", "Clears the region ticks of the shown process.", "-", "-", "-"),
    "x.v.extract": ("Extract regions", "Dumps the regions chosen by the mode above.",
        "Whole process: all regions of each ticked process. Selected regions: only the ticked regions. Each "
        "dumped region is hashed and injection-flagged in the manifest.",
        "pid.1732.vad.0x3bd0000-0x3bdffff.dmp", "-"),
    # hunt
    "x.h.terms": ("Search terms", "The strings to look for, one per line (plain text, not regex).",
        "Turned into one YARA rule and scanned in process memory (Windows VadYaraScan, Linux VmaYaraScan; "
        "Volatility 2 cases: yarascan / linux_yarascan). macOS has no per-process YARA plugin: with PIDs "
        "set, those processes' regions are dumped (kept as evidence) and searched directly; without PIDs "
        "all physical memory is scanned, which is slow on big images. The whole-dump strings files are "
        "counted too. If a scan times out the job says so - '0 hits' is only reported for a completed scan.",
        "evil-domain.com\\npassword=\\n10.13.37.5", "To find which process holds a known indicator."),
    "x.h.pids": ("Limit to PIDs", "Optional comma-separated PIDs to scan; empty scans all processes.",
        "Only those processes are scanned - much faster.", "1732, 2040", "When you already suspect processes."),
    "x.h.case": ("Case-sensitive", "Match upper/lower case exactly.", "'Password' no longer matches 'password'.",
        "-", "For exact tokens such as keys."),
    "x.h.wide": ("Also UTF-16", "Also match the UTF-16 (wide) form Windows uses for most text.",
        "Finds strings stored as W.i.d.e text.", "Outlook and browsers keep URLs as UTF-16.", "Keep it on for Windows."),
    "x.h.run": ("Run string hunt", "Starts the hunt in the background.",
        "Hits appear in the table below with PID, process, address and matched bytes.", "-", "-"),
    "x.h.results": ("Hunt hits", "Each memory hit: term, PID, process, virtual address, match, raw bytes.",
        "Sortable/filterable; also saved as json\\string_hunt.json in the job folder.",
        "go.microsoft.com  1732  explorer.exe  0x8a91b0e", "-"),
    # export
    "x.e.list": ("Files in the pack", "The case results that will go into the export zip.",
        "Read-only list.", "report.html, iocs\\ioc_results.json, sigma\\sigma_results.json ...", "-"),
    "x.e.run": ("Create export pack", "Zips the key results of this case with a MANIFEST.txt.",
        "The zip is written to a new export_<time> folder under 'Save to'.", "crescent_export_20261112_1530.zip",
        "To hand the case to a colleague or attach it to a ticket."),
    # results
    "x.r.history": ("Extraction history", "Every extraction made for this case (newest first).",
        "Choosing one shows its manifest in the table below.", "procs_20261112_153012", "To review earlier jobs."),
    "x.r.open": ("Open folder", "Opens the folder of the shown extraction.", "Explorer opens.", "-", "-"),
    "x.r.manifest": ("Open manifest", "Opens manifest.txt of the shown extraction.",
        "The text lists every item, status, file, size, type and SHA-256.", "-", "For your report."),
    "x.r.table": ("Extraction results",
        "One row per extracted file: status, item, file, size, detected type, non-zero share and SHA-256.",
        "Double-click a row to open its folder. 'Non-zero %' below ~5 means most pages were not in RAM.",
        "OK  notepad.exe  ...ImageSectionObject.notepad.exe.img  192.5 KB  PE  33.5%",
        "To verify what you got."),
    # rich guides (help_guide.GuideWindow)
    "guide.pages": ("Guide pages", "The topics of this guide.",
        "Choosing one shows its animation and its explanation.", "Quick triage", "-"),
    "guide.media": ("Animated example", "A short annotated recording of the real window: "
        "numbered callouts and highlights show where to click and what you get.",
        "Click it to pause or resume; the buttons below step through the frames.", "-", "-"),
    "guide.play": ("Pause / play", "Pauses or resumes the animation.", "The picture stops on "
        "the current step so you can read it.", "-", "-"),
    "guide.prev": ("Previous step", "Shows the previous frame of the animation (pauses it).",
        "-", "-", "-"),
    "guide.next": ("Next step", "Shows the next frame of the animation (pauses it).",
        "-", "-", "-"),
    "guide.text": ("Explanation", "What the option runs, how long it takes, what you get "
        "and when to pick it.", "Scroll for more.", "-", "-"),
    "guide.close": ("Close guide", "Closes this guide window.", "The setup panel is unchanged.",
        "-", "-"),
    "tour.next": ("Next", "Next step of the tour.", "Highlights the next area.", "-", "-"),
    "tour.back": ("Back", "Previous step of the tour.", "Highlights the previous area.", "-", "-"),
    "tour.skip": ("Skip tour", "Ends the tour.", "The tour closes; reopen it from the toolbar.", "-", "-"),
}

GLOSSARY = {
    'Threat intelligence (TI)': 'Knowledge about known attackers and malware: bad IP addresses, domains, URLs, file hashes and detection rules. RAMBreaker compares what it finds in memory with this knowledge. It goes stale quickly, so update the databases regularly.',
    'YARA': 'A pattern language for describing malware by its content (strings, byte sequences, PE structure). A YARA rule still matches a file that is partial or rebuilt from memory, where a hash lookup fails.',
    'YARA Forge': "A project that collects public YARA rules from many repositories, tests them and publishes them as 'core' (low false positives) and 'extended' packages. RAMBreaker ships both.",
    'VirusTotal': 'An online service that scans files with about 70 antivirus engines and keeps reputation data for hashes, IPs and domains. RAMBreaker only LOOKS UP hashes, public IPs and domains; it never uploads files.',
    'Threat feed': 'A regularly updated list of known-bad indicators (e.g. IPsum, Maltrail, Spamhaus DROP). RAMBreaker reads feeds from local copies, so checking them sends nothing anywhere.',
    'Hash quality': 'How far a hash of something dumped from memory can be trusted to match the original file: complete (every page present), partial (pages were not in RAM and were filled with zeros), rebuilt (an executable reassembled from process memory, which never hashes like the file on disk).',
    "Memory dump / RAM image": "A file containing a copy of a computer's physical memory (RAM) at one moment: running processes, network connections, open files, decrypted data, malware that never touched the disk. Formats: .raw/.mem (raw), .vmem (VMware), .lime (Linux LiME), .dmp (crash dump).",
    "Volatility": "The open-source memory-forensics framework RAMBreaker drives. Volatility 3 is the current version; Volatility 2 is the older one, still useful for old Windows images and some plugins that were never ported.",
    "Plugin": "One Volatility analysis module, e.g. windows.pslist (process list) or windows.netscan (network connections). RAMBreaker runs many in parallel and parses their JSON output.",
    "OS profile (Vol2)": "A Volatility 2 description of a specific OS build (e.g. Win7SP1x64) telling it where kernel structures are. Picked automatically via imageinfo, or set manually.",
    "Symbol table / ISF": "Intermediate Symbol Format: the JSON file Volatility 3 uses to understand kernel data structures for one exact kernel/OS build. Windows ISFs come from Microsoft's PDB symbol server; Linux/macOS ISFs must match the exact kernel.",
    "BTF": "BPF Type Format: compact type information modern Linux kernels (5.x+) keep in memory. RAMBreaker can rebuild a full ISF from the BTF found inside the dump, so Linux images work even when no ISF exists anywhere.",
    "Symbol ladder": "RAMBreaker's order for finding Linux symbols: 1. community ISF repository, 2. other sources / distro debug packages built with dwarf2json, 3. BTF reconstruction from inside the dump. If all fail, symbol-free plugins still run.",
    "dwarf2json": "The Volatility tool that converts a kernel's DWARF debug information (from a debug package) into an ISF.",
    "Banner": "The 'Linux version ...' or 'Darwin Kernel Version ...' string in memory; it identifies the exact kernel and is how matching symbols are found.",
    "IOC": "Indicator of Compromise: an observable such as an IP, domain, URL, file hash, e-mail address or registry key associated with malicious activity.",
    "IOC check": "Searching a list of known-bad IOCs everywhere in the case (raw dump, strings, plugin output, dumped files) and reporting where each one was found.",
    "Sigma": "An open, generic rule format for detecting suspicious events. RAMBreaker rebuilds process, network, registry and event-log records from memory and evaluates Sigma rules against them (rules in sigma_rules\\ beside the program).",
    "Timeout": "Maximum time a plugin may run. RAMBreaker computes it per plugin from the dump size, OS and measured plugin cost; on timeout the plugin is killed, retried once with a longer limit, and flagged if it fails again.",
    "ETA": "Estimated time of arrival: the predicted remaining run time from the calibrated timing model.",
    "Strings": "Readable text pulled from the dump (ASCII and UTF-16). IOC, e-mail, browser and chat artefacts are searched in it.",
    "Malfind / injection": "Detection of executable memory regions that look injected (no file behind them, suspicious permissions) - a classic sign of fileless malware.",
    "Fileless-injection correlator": "RAMBreaker's cross-check of malfind hits against the loader's module lists; an injected region that the loader does not know about is a strong (HIGH) indicator.",
    "VAD": "Virtual Address Descriptor: Windows' bookkeeping of a process's memory regions. Dumping VADs extracts the memory of a process region by region.",
    "File object / section objects": "Windows keeps an open file in memory as a _FILE_OBJECT. Its cached content can live in a DataSectionObject (.dat: cached file data), an ImageSectionObject (.img: an executable mapped for running) and a SharedCacheMap (.vacb: cache views). Only pages that were in RAM are recoverable; the rest come back as zeros.",
    "Page cache": "The kernel's in-RAM cache of file contents (Linux/macOS). File extraction on Linux/macOS rebuilds a file from its cached pages; 'cached pages: 0' means its content is not in the dump.",
    "Extraction manifest": "manifest.json / manifest.txt written with every extraction: what was asked, what came out, file sizes, detected type, SHA-256/MD5 and the share of non-zero bytes - the evidence record for your report.",
    "String hunt": "A search for your own strings inside process memory using a generated YARA rule; every hit is attributed to a PID and virtual address.",
    "PID / PPID":"Process ID and Parent Process ID. A suspicious parent (e.g. winword.exe starting powershell.exe) is a common detection lead.",
    "EVTX": "Windows event log files. RAMBreaker can carve them from memory and parse their records.",
    "LiME": "Linux Memory Extractor, a common tool for capturing Linux RAM; its .lime format is detected automatically.",
    "Confidence": "How sure RAMBreaker is about a reconstructed item. Memory holds fragments, so e-mails and Sigma hits carry high/medium/low confidence - verify low ones by hand.",
    "Hash (MD5/SHA1/SHA256)": "A fingerprint of a file's content. Hash IOCs are compared with files and processes dumped from memory.",
    "Preset": "A ready-made recipe on the setup panel: which pipeline runs (plugins only / plugins + strings, IOCs, Sigma, report / + EVTX) and which plugins. It fills in Plugin category and Fast mode; you can still change them afterwards.",
    "Plugin category": "WHAT the Volatility plugins look at: all categories, or one topic (malware, network, persistence, registry). Same as the CLI -m value of that name.",
    "Fast mode": "HOW MUCH runs: the quick plugin set (about a third of the plugins, the cheap high-value ones) across all categories. Same as the CLI -m fast. Not the same as RAM / jobs mode.",
    "RAM / jobs mode": "How hard the PC may work (CLI --speed normal / fast / fastest): RAM budget per parallel job and whether the RAM guard may lower the number of jobs. It never changes which plugins run.",
}


# ═══════════════════════════════════════════════════════════════ rich guides
# Opened by the "?" of the controls below (help_guide.GuideWindow), instead of
# the small card. Each page: label, media (help_media/<name>_<theme>.gif) and
# HTML. Tokens filled in at display time from the REAL plugin lists and the
# timing model, so the numbers never drift from the code:
#   [[plugins:MODE]]       plugin list per OS for that -m value
#   [[eta:CMD:MODE]]       model estimate on a 2 GB and an 8 GB Windows image
#   [[accent]] [[muted]]   theme colours

def _page(one, runs, time_, get, pick, avoid, cli):
    sec = lambda t, body: (f"<p style='margin:10px 0 2px 0'><b style='color:[[accent]]'>{t}</b></p>"
                           f"{body}")
    return (f"<p style='margin:0 0 4px 0;font-size:10.5pt'>{one}</p>"
            + sec("What it runs", runs)
            + sec("How long it takes", time_)
            + sec("What you get", get)
            + sec("Pick it when", pick)
            + sec("Do not pick it when", avoid)
            + sec("Same thing on the command line", f"<p><code>{cli}</code></p>"))


_STD_STEPS = ("<ol style='margin-top:2px'>"
              "<li>Detect the OS and find symbols (Linux: community ISF, debug package or BTF from inside the dump).</li>"
              "<li>Run the Volatility plugins in parallel (list below). On older Windows the Vol2-only extras "
              "(consoles, shellbags, shimcache, clipboard ...) run in the background.</li>"
              "<li>Extract ASCII + UTF-16 strings and find IOCs: IPs, domains, URLs, e-mail, keys, tokens, hashes, "
              "browser history, chat/e-mail remnants.</li>"
              "<li>Process tree, network map, command-line and MITRE ATT&amp;CK analysis.</li>"
              "<li>Correlation, fileless-injection correlator, popular files, scheduled tasks, registry analysis.</li>"
              "<li>Evidence timeline and Sigma rules.</li>"
              "<li>IOC check (only if you loaded an IOC list) and the HTML report.</li></ol>")

_FOCUS_NOTE = ("<p>The analysis steps 3-7 of Standard (strings, IOCs, correlation, Sigma, timeline, report) "
               "still run, but they only see what these plugins produced: pages that need a plugin outside "
               "the set (for example Network without netscan) stay empty.</p>")

GUIDES = {
    "setup.preset": {
        "title": "Analysis presets",
        "intro": "A preset is a ready-made recipe. It decides which pipeline runs and fills in "
                 "Plugin category and Fast mode for you. Pick one, check the estimated time, press Start.",
        "pages": [
            ("How to use", "preset_overview",
             "<p style='font-size:10.5pt'>Three things change when you pick a preset:</p>"
             "<ol><li><b>The pipeline</b>: plugins only (Quick triage), plugins + the full analysis "
             "(Standard and the focus presets) or full analysis + EVTX (Full DFIR).</li>"
             "<li><b>Plugin category</b> (what the plugins look at) and <b>Fast mode</b> (how many "
             "plugins) are set below the preset. You can change them afterwards; the preset name "
             "stays but the run uses what the controls show.</li>"
             "<li><b>The estimated time</b> is recalculated from the dump size and the measured cost "
             "of every plugin.</li></ol>"
             "<p><b style='color:[[accent]]'>Which one?</b></p>"
             "<table cellspacing='0' cellpadding='3' border='0'>"
             "<tr><td><b>Standard</b></td><td>Default for a real case. Everything except EVTX.</td></tr>"
             "<tr><td><b>Quick triage</b></td><td>Minutes. Process list, connections, malfind. No report.</td></tr>"
             "<tr><td><b>Full DFIR</b></td><td>Longest. Standard + event logs + slow Vol2 extras.</td></tr>"
             "<tr><td><b>Malware hunt</b></td><td>Injection, rootkit hooks, drivers, hidden processes.</td></tr>"
             "<tr><td><b>Network focus</b></td><td>Connections, sockets, listening services.</td></tr>"
             "<tr><td><b>Persistence focus</b></td><td>Services, Run keys, drivers, callbacks (Windows).</td></tr>"
             "<tr><td><b>Registry focus</b></td><td>Hives, keys, UserAssist (Windows).</td></tr>"
             "<tr><td><b>DFIR + Threat Intel</b></td><td>Full DFIR + dump every file and process, YARA, "
             "threat feeds, VirusTotal.</td></tr></table>"
             "<p style='color:[[muted]]'>Nothing is ever written to the dump. Re-running the same dump "
             "with another preset reuses plugin results that already exist in the case folder.</p>"),
            ("Standard", "preset_standard", _page(
                "The recommended full analysis: every plugin of the complete set plus every analysis "
                "step, except carving event logs.",
                _STD_STEPS + "[[plugins:full]]",
                "<p>[[eta:core:full]]</p><p>The plugins are most of it; strings + IOC + report add "
                "roughly 45 s per GB. Big dumps on a spinning disk run with fewer parallel jobs.</p>",
                "<ul><li><b>Results</b>: Summary tiles, Processes, Network, Findings (Sigma hits, "
                "fileless injection, correlation, timeline), IOCs by type, e-mail artefacts, browser "
                "history, every plugin table.</li>"
                "<li><b>report.html</b>: the 13-tab offline report for your ticket.</li>"
                "<li><b>Extraction</b> workspace: dump files, processes, VAD memory, hunt strings.</li></ul>",
                "You have a real incident and want the complete picture in one run. When unsure, pick this.",
                "You only need a quick yes/no on a huge dump (use Quick triage first), or you need "
                "Windows event logs from memory (use Full DFIR).",
                "core -i memory.raw -m full")),
            ("Quick triage", "preset_quick", _page(
                "The fastest useful look: only the quick plugin set, no strings, no IOCs, no Sigma, "
                "no HTML report.",
                "<p>Step 1 and 2 of Standard only: detect the OS, find symbols, run the quick set "
                "(Fast mode is switched on). On older Windows only the cheap Vol2 extras run "
                "(cmdscan, consoles, hashdump, clipboard, iehistory).</p>[[plugins:fast]]",
                "<p>[[eta:extract:fast]]</p><p>No post-processing time: the run ends when the last "
                "plugin finishes.</p>",
                "<ul><li><b>Results</b>: Processes, Network and the Plugins list (one table per "
                "plugin). Findings, IOCs and Sigma stay empty because those steps do not run.</li>"
                "<li>An IOC list is <b>not</b> checked in Quick triage.</li>"
                "<li>No report.html. You can run Standard on the same dump later; plugins that "
                "already ran are reused.</li></ul>",
                "You must decide fast whether a machine is compromised, you are triaging many hosts, "
                "or the dump is very large and you want a first look before the full run.",
                "You need IOCs, Sigma, e-mail, a timeline or a report to hand over.",
                "extract -i memory.raw -m fast")),
            ("Full DFIR", "preset_fulldfir", _page(
                "Everything Standard does, plus Windows event-log carving and the slow Volatility 2 "
                "extras. The most complete and the slowest preset.",
                _STD_STEPS + "<p>Then, on Windows:</p><ol start='8'>"
                "<li>Every <b>.evtx</b> event log found by filescan is dumped from memory to "
                "dumped_files\\ and parsed; security-relevant events are listed.</li>"
                "<li>The HTML report is rebuilt with the event-log data.</li>"
                "<li>The slow Vol2 extras (timers, apihooks) run as well (skipped by the other presets: "
                "timers alone took 12 min on a 2 GB Windows 7 image).</li></ol>[[plugins:full]]",
                "<p>[[eta:core:full]] plus the EVTX dump (usually a few minutes) and, on older Windows, "
                "the slow Vol2 extras (10+ min).</p>",
                "<ul><li>Everything from Standard.</li><li>dumped_files\\ with the carved .evtx "
                "files, the parsed events and an event-log section in report.html.</li></ul>"
                "<p style='color:[[muted]]'>On Linux and macOS there is no EVTX: Full DFIR then "
                "equals Standard.</p>",
                "A full Windows investigation where logon events, service installs or PowerShell "
                "logs held in RAM matter, and time is not critical.",
                "You need answers quickly, or the image is Linux/macOS (use Standard).",
                "full -i memory.raw -m full")),
            ("Malware hunt", "preset_malware", _page(
                "Only the plugins that find code injection, rootkits, hooks and hidden processes, "
                "plus the full analysis of what they find.",
                "[[plugins:malware]]" + _FOCUS_NOTE,
                "<p>[[eta:core:malware]]</p>",
                "<ul><li><b>Findings > Fileless injection</b>: malfind regions graded HIGH/MEDIUM/LOW "
                "(no file behind them, PE header present, JIT process ...).</li>"
                "<li>Hidden processes (psscan vs pslist), suspicious drivers, SSDT/callback hooks.</li>"
                "<li>IOCs, Sigma hits and report.html as in Standard.</li>"
                "<li>Windows: no Network table, netscan is not in this set (Linux keeps sockstat).</li></ul>",
                "An EDR alert, a suspected implant or a process that looks injected.",
                "The question is about connections, persistence or user activity.",
                "core -i memory.raw -m malware")),
            ("Network focus", "preset_network", _page(
                "Connections, listening ports and the processes that own them, plus the full "
                "analysis of what they show.",
                "[[plugins:network]]" + _FOCUS_NOTE,
                "<p>[[eta:core:network]]</p>",
                "<ul><li><b>Network</b> table: protocol, local/remote address and port, state, PID, "
                "owner process, creation time.</li><li>Network map (network_map.txt) and the IP/"
                "domain/URL IOCs from strings.</li><li>Sigma network rules and report.html.</li></ul>",
                "A suspected C2 beacon, data exfiltration or lateral movement.",
                "You need injection, persistence or registry evidence.",
                "core -i memory.raw -m network")),
            ("Persistence focus", "preset_persistence", _page(
                "How something survives a reboot: services, Run keys, drivers and kernel callbacks.",
                "[[plugins:persistence]]" + _FOCUS_NOTE +
                "<p style='color:[[muted]]'>Linux and macOS have no persistence set: they run the "
                "complete set (cron/systemd evidence is found by the scheduled-tasks step).</p>",
                "<p>[[eta:core:persistence]]</p>",
                "<ul><li>Services (svcscan), drivers and modules, callbacks, SSDT.</li>"
                "<li>Registry: hives, Run/RunOnce and other autostart keys (registry analysis step), UserAssist (programs the user ran).</li>"
                "<li>Scheduled tasks, Sigma, IOCs and report.html.</li></ul>",
                "Malware keeps coming back after cleaning, or you must find how an attacker kept access.",
                "You need network or injection details.",
                "core -i memory.raw -m persistence")),
            ("Registry focus", "preset_registry", _page(
                "Only the registry plugins: the shortest run, for questions about user activity "
                "and configuration.",
                "[[plugins:registry]]" + _FOCUS_NOTE +
                "<p style='color:[[muted]]'>No process list is run, so the Processes page and "
                "process-based findings stay empty. Linux and macOS have no registry: they run the "
                "complete set.</p>",
                "<p>[[eta:core:registry]]</p>",
                "<ul><li>Registry hives found in memory (hivelist + hivescan) and their keys.</li>"
                "<li>UserAssist: which programs the user started and how often.</li>"
                "<li>Registry analysis (registry_report.txt), IOCs, report.html.</li></ul>",
                "You only need registry evidence (user activity, Run keys, configuration).",
                "You need processes, network or malware evidence.",
                "core -i memory.raw -m registry")),
            ("DFIR + Threat Intel", "preset_dfirti", _page(
                "Full DFIR, then every file and every process executable in the image is dumped, hashed and "
                "checked against threat intelligence. The answers go into report.html, tab 'Threat Intelligence'.",
                "<p>Before the run a window asks for the options:</p><ul>"
                "<li><b>VirusTotal key</b> (optional; stored encrypted only if you tick 'Remember'). "
                "Without a key everything stays on this PC.</li>"
                "<li><b>YARA rule set</b>: core (fewer false positives) or extended, plus your own rules from "
                "yara_rules\\custom.</li>"
                "<li><b>Threat-intel databases</b>: their age, and an Update button. Updating is your choice; "
                "threat intelligence goes out of date in days.</li></ul>"
                "<p>Then:</p><ol><li>Everything Full DFIR does.</li>"
                "<li>Dump <b>all files</b> found in memory and the <b>executable of every process</b> "
                "(not every memory region), plus only the regions the injection correlator flagged "
                "(fileless code is never a file).</li>"
                "<li>SHA-256 / SHA-1 / MD5 of each object and its <b>hash quality</b>: complete, partial "
                "(pages missing) or rebuilt from memory.</li>"
                "<li><b>YARA</b> on every object and <b>offline feeds</b> (IPsum, Maltrail, Spamhaus DROP, "
                "abuse.ch ...) against hashes, network connections and the IPs/domains/URLs already "
                "extracted. Nothing is sent anywhere.</li>"
                "<li>A <b>'look here first'</b> list scores what has a reason to be checked.</li>"
                "<li><b>VirusTotal</b> (only with a key): hashes, public IPs and domains of that short list. "
                "Files are never uploaded; private IPs and internal names are never sent.</li></ol>",
                "<p>[[eta:core:full]] plus the dump (a few minutes per GB on an SSD) and the VirusTotal step: "
                "a free key allows 4 lookups per minute, so 100 lookups take up to 25 minutes.</p>",
                "<ul><li><b>report.html &gt; Threat Intelligence</b>: look-here-first list, YARA matches, "
                "feed hits, VirusTotal verdicts with links, database ages, and every dumped object with "
                "its hash.</li>"
                "<li><b>threat_intelligence\\</b> in the case folder: the dumps, inventory.json, yara_hits.json, "
                "feed_hits.json, vt_results.json, vt_sent.txt (exactly what was sent) and the raw "
                "VirusTotal answers.</li>"
                "<li>If the VirusTotal quota runs out: <b>Analysis &gt; Continue VirusTotal lookups</b> "
                "finishes the rest later. <b>Analysis &gt; Threat intel on this case</b> adds threat intel to "
                "a case analysed before.</li></ul>",
                "You need to know quickly whether anything in the image is known malware, or which "
                "connections go to known-bad servers.",
                "The case must not touch any external service (tick 'Local checks only'), or you only "
                "need a quick look (use Quick triage).",
                "dfir-ti -i memory.raw -m full   (existing case: ti -o <case>)")),
        ],
    },
    "setup.category": {
        "title": "Plugin category",
        "intro": "WHAT the plugins look at. Choose all of them or one investigation topic. "
                 "How MANY plugins run is a separate choice: Fast mode.",
        "pages": [
            ("How to use", "category_overview",
             "<ol><li>Open <b>Plugin category</b> and pick a topic.</li>"
             "<li>The estimated time and plugin count update at once.</li>"
             "<li>Start. Only the plugins of that category run; the analysis steps after the "
             "plugins still run (except in Quick triage).</li></ol>"
             "<p>Category and Fast mode are two separate ideas that the command line keeps in one "
             "switch (<code>-m</code>):</p>"
             "<table cellspacing='0' cellpadding='3'>"
             "<tr><td><b>Category</b></td><td><b>Fast mode</b></td><td><b>CLI</b></td></tr>"
             "<tr><td>All categories</td><td>off</td><td><code>-m full</code></td></tr>"
             "<tr><td>All categories</td><td>on</td><td><code>-m fast</code></td></tr>"
             "<tr><td>Malware / Network / ...</td><td>off</td><td><code>-m malware</code> ...</td></tr></table>"
             "<p style='color:[[muted]]'>The focus categories are already short lists, so Fast "
             "mode has its own single quick set and locks the category to 'All categories'.</p>"),
            ("All categories", "category_all",
             "<p>The complete set: every plugin RAMBreaker runs for this OS.</p>[[plugins:full]]"
             "<p>[[eta:core:full]]</p>"),
            ("Malware", "category_malware",
             "<p>Injection, rootkits, hooks, drivers, hidden processes.</p>[[plugins:malware]]"
             "<p>[[eta:core:malware]]</p>"),
            ("Network", "category_network",
             "<p>Connections, sockets, listening ports and the owning processes.</p>"
             "[[plugins:network]]<p>[[eta:core:network]]</p>"),
            ("Persistence", "category_persistence",
             "<p>Services, drivers, callbacks, Run keys, UserAssist (Windows only; Linux and "
             "macOS run the complete set).</p>[[plugins:persistence]]<p>[[eta:core:persistence]]</p>"),
            ("Registry", "category_registry",
             "<p>Registry hives and keys (Windows only; Linux and macOS run the complete set). "
             "No process list.</p>[[plugins:registry]]<p>[[eta:core:registry]]</p>"),
        ],
    },
    "setup.fastmode": {
        "title": "Fast mode",
        "intro": "HOW MUCH runs: a quick, curated plugin set instead of the complete one. "
                 "It is about the plugin list, not about RAM or parallel jobs.",
        "pages": [
            ("How it works", "fastmode",
             "<ol><li>Tick <b>Fast mode</b>. Plugin category switches to 'All categories' and is "
             "locked, because the quick set already covers every category.</li>"
             "<li>The estimate drops: about a third of the plugins run.</li>"
             "<li>After the run, the Plugins list holds only the quick set.</li></ol>"
             "<p><b style='color:[[accent]]'>What stays, what goes</b></p>"
             "<p>Kept: process list and tree, command lines, network, malfind, services, password "
             "hashes, registry hives and the file list (Windows); processes, bash history, modules, "
             "sockets, open files, maps and the page cache (Linux).</p>"
             "<p>Skipped: the slow or niche scans (handles, DLL lists, VAD info, mutants, symbolic "
             "links, thread scan, MFT, driver IRPs, SIDs, privileges ...). On older Windows only "
             "the cheap Vol2 extras run.</p>[[plugins:fast]]"
             "<p><b style='color:[[accent]]'>Time</b></p><p>Plugins only: [[eta:extract:fast]]</p>"
             "<p><b style='color:[[accent]]'>Combine it with a preset</b></p>"
             "<ul><li><b>Quick triage</b> = Fast mode + plugins only (no strings, IOCs, report).</li>"
             "<li><b>Standard + Fast mode</b> = quick plugins + the full analysis and report: a good "
             "middle ground for a big dump.</li></ul>"
             "<p style='color:[[muted]]'>Not to be confused with <b>RAM / jobs mode</b> 'fast', "
             "which changes how much RAM each parallel plugin may use. CLI: <code>-m fast</code>.</p>"),
        ],
    },
    "setup.speed": {
        "title": "RAM / jobs mode",
        "intro": "How hard the PC may work while plugins run. It never changes which plugins "
                 "run (that is Fast mode and Plugin category).",
        "pages": [
            ("How it works", "speedmode",
             "<p>RAMBreaker runs up to <b>Parallel jobs</b> plugins at the same time. Each one is a "
             "separate Volatility process that can take 1-2 GB of RAM on a big dump. This setting "
             "decides how carefully that number is used:</p>"
             "<table cellspacing='0' cellpadding='3'>"
             "<tr><td><b>normal</b></td><td>Keeps ~1.5 GB of free RAM per job. If RAM is short, "
             "fewer jobs run (the log says 'Adaptive jobs: 4 -> 2'). A dump on a spinning disk that "
             "is bigger than the free RAM drops to 1 job, so the disk is not thrashed.</td></tr>"
             "<tr><td><b>fast</b></td><td>Budgets ~1 GB per job, so more jobs keep running on the "
             "same RAM. Same slow-disk rule.</td></tr>"
             "<tr><td><b>fastest</b></td><td>Exactly 'Parallel jobs', no RAM guard and no slow-disk "
             "rule. Fastest on a strong workstation; can make a small PC swap or freeze.</td></tr></table>"
             "<p><b style='color:[[accent]]'>Pick</b></p><ul><li>Laptop, VM, 8-16 GB RAM: "
             "<b>normal</b>.</li><li>32 GB+ workstation: <b>fast</b>.</li><li>64 GB+ box, dump on "
             "an SSD, nothing else running: <b>fastest</b>.</li></ul>"
             "<p style='color:[[muted]]'>The default for new cases is set in Settings. CLI: "
             "<code>--speed normal|fast|fastest</code>.</p>"),
        ],
    },
}


def guide(key: str):
    return GUIDES.get(key)


def get(key: str):
    return H.get(key)


def html(key: str, theme: dict) -> str:
    e = H.get(key)
    if not e:
        return f"<b>{key}</b><br>No help text."
    title, what, effect, example, when = e
    m, a = theme["muted"], theme["accent"]
    return (f"<div style='font-size:10.5pt;font-weight:600;color:{a}'>{title}</div>"
            f"<p style='margin:6px 0 2px 0'><b>What it is</b><br>{what}</p>"
            f"<p style='margin:6px 0 2px 0'><b>What happens</b><br>{effect}</p>"
            f"<p style='margin:6px 0 2px 0'><b>Example</b><br><span style='color:{m}'>{example}</span></p>"
            f"<p style='margin:6px 0 0 0'><b>When to use it</b><br>{when}</p>")


def tooltip(key: str) -> str:
    e = H.get(key)
    more = "click ? for the animated guide" if key in GUIDES else "click ? for details"
    return f"{e[0]} - {e[1]}  ({more})" if e else key
