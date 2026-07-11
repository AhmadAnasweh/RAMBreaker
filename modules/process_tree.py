"""
CresCent RAM Forensics Toolkit v4.0 - Process Tree Viewer

Builds and displays an ASCII process tree from pslist/pstree JSON data.
Shows parent-child relationships, thread counts, flags, and cmdline.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from utils.json_converter import load_json_by_pattern


def _gv(item, *keys):
    # Exact match first
    for k in keys:
        if k in item:
            return item[k]
    # Case-insensitive fallback (Vol2/Vol3 column name variations)
    lower_map = {str(k).lower(): k for k in item}
    for k in keys:
        lk = str(k).lower()
        if lk in lower_map:
            return item[lower_map[lk]]
    return None


class ProcessTree:
    """Build and render ASCII process trees from Volatility JSON output."""

    def __init__(self, logger: logging.Logger, os_type: str = 'windows'):
        self.log = logger
        self.os_type = os_type
        self._procs: Dict[str, Dict[str, Any]] = {}
        self._children: Dict[str, List[str]] = {}
        self._roots: List[str] = []

    @staticmethod
    def _flatten_pstree(nodes: list) -> list:
        """Recursively flatten Vol3 pstree nested __children into a flat list."""
        result = []
        for n in nodes:
            result.append(n)
            children = n.get("__children") or n.get("Children") or n.get("children") or []
            if children:
                result.extend(ProcessTree._flatten_pstree(children))
        return result

    def load(self, output_dir: Path) -> int:
        """Load process data from existing JSON output.

        Args:
            output_dir: Base analysis output directory containing json/.

        Returns:
            Number of processes loaded.
        """
        jd = output_dir / "json"
        if not jd.is_dir():
            self.log.error("No json/ directory: %s", jd)
            return 0

        pslist = load_json_by_pattern(jd, "pslist")
        pstree_raw = load_json_by_pattern(jd, "pstree")
        pstree = self._flatten_pstree(pstree_raw)
        psscan = load_json_by_pattern(jd, "psscan")
        cmdline = load_json_by_pattern(jd, "cmdline")

        # Build cmdline map (cmdline plugin for Windows, psaux for Linux/macOS)
        cmdlines: Dict[str, str] = {}
        for c in cmdline:
            pid = str(_gv(c, "PID", "pid", "Pid") or "")
            args = str(_gv(c, "Args", "args", "CommandLine", "CmdLine") or "")
            if pid:
                cmdlines[pid] = args
        for c in load_json_by_pattern(jd, "psaux"):
            pid = str(_gv(c, "PID", "pid", "Pid") or "")
            args = str(_gv(c, "ARGS", "Arguments", "Args", "args") or "")
            if pid and args.strip() and pid not in cmdlines:
                cmdlines[pid] = args.strip()

        # Build process map
        self._procs.clear()
        self._children.clear()
        self._roots.clear()
        seen: Set[str] = set()

        for p in pslist + pstree + psscan:
            pid = str(_gv(p, "PID", "pid", "Pid") or "")
            if not pid or pid in seen:
                continue
            seen.add(pid)
            self._procs[pid] = {
                "pid": pid,
                "name": str(_gv(p, "ImageFileName", "Name", "Process", "name", "COMM", "Comm") or ""),
                "ppid": str(_gv(p, "PPID", "ppid", "Ppid",
                                "InheritedFromUniqueProcessId") or ""),
                "threads": _gv(p, "Threads", "threads", "NumberOfThreads"),
                "offset": str(_gv(p, "Offset", "offset", "Offset(V)") or ""),
                "createtime": str(_gv(p, "CreateTime", "Create Time",
                                      "createtime") or ""),
                "cmdline": cmdlines.get(pid, ""),
                "source": "psscan" if p in psscan and p not in pslist else "pslist",
            }

        # Build parent-child map
        # A process is an OS root only when PPID is 0 (Linux init / Windows
        # System process). Any other process whose parent isn't in the map
        # is an *orphan* — its parent exited or was hidden, which is itself
        # forensically interesting and shouldn't be visually indistinguishable
        # from System.
        all_pids = set(self._procs.keys())
        for pid, proc in self._procs.items():
            ppid = proc["ppid"]
            if ppid and ppid in all_pids and ppid != pid:
                self._children.setdefault(ppid, []).append(pid)
            else:
                self._roots.append(pid)
                # Tag the kind of root so render() can label it.
                if ppid in ("", "0", "None") or not ppid:
                    proc["_root_kind"] = "os"
                else:
                    proc["_root_kind"] = "orphan"
                    proc["_orphan_ppid"] = ppid

        # Sort roots and children by PID
        self._roots.sort(key=lambda p: int(p) if p.isdigit() else 0)
        for k in self._children:
            self._children[k].sort(key=lambda p: int(p) if p.isdigit() else 0)

        self.log.info("Process tree: %d processes, %d roots",
                      len(self._procs), len(self._roots))
        return len(self._procs)

    def render(self, highlight_pids: Optional[Set[str]] = None,
               max_cmd_len: int = 80) -> str:
        """Render the full process tree as an ASCII string."""
        if not self._procs:
            return "  (no processes loaded)\n"

        if highlight_pids is None:
            highlight_pids = set()

        lines: List[str] = []
        for ri, root in enumerate(self._roots):
            self._render_node(root, "", ri == len(self._roots) - 1,
                              lines, highlight_pids, max_cmd_len, is_root=True)

        return "\n".join(lines)

    def _render_node(self, pid: str, prefix: str, is_last: bool,
                     lines: List[str], highlight: Set[str],
                     max_cmd: int, is_root: bool = False) -> None:
        """Recursively render a tree node with proper indentation."""
        proc = self._procs.get(pid)
        if not proc:
            return

        # Connector + child prefix
        if is_root:
            connector = ""
            child_prefix = ""
        else:
            connector = "└── " if is_last else "├── "
            child_prefix = prefix + ("    " if is_last else "│   ")

        # Node line
        name = proc["name"] or "(?)"
        threads = proc.get("threads", "?")
        flag = " [!]" if pid in highlight else ""
        hidden = " [HIDDEN]" if proc.get("source") == "psscan" else ""
        # Mark orphans (parent exited / not in image) — forensically interesting
        if is_root and proc.get("_root_kind") == "orphan":
            orphan = f" [ORPHAN — missing PPID {proc.get('_orphan_ppid', '?')}]"
        else:
            orphan = ""
        lines.append(f"{prefix}{connector}{name} ({pid})  thr:{threads}{flag}{hidden}{orphan}")

        # Command line — indented under this node
        if proc["cmdline"]:
            cmd = proc["cmdline"]
            if len(cmd) > max_cmd:
                cmd = cmd[:max_cmd] + "..."
            children = self._children.get(pid, [])
            # hang cmd on the children's vertical bar (or plain indent if no children)
            cmd_pre = child_prefix + ("│" if children else " ")
            cmd_label = "cmd" if self.os_type == "windows" else "cmdline"
            lines.append(f"{cmd_pre}     {cmd_label}: {cmd}")

        # Recurse into children
        children = self._children.get(pid, [])
        for i, child_pid in enumerate(children):
            self._render_node(child_pid, child_prefix,
                              i == len(children) - 1,
                              lines, highlight, max_cmd, is_root=False)

    def render_subtree(self, pid: str, highlight_pids: Optional[Set[str]] = None,
                       max_cmd_len: int = 80) -> str:
        """Render a subtree starting from a specific PID.

        Args:
            pid: Root PID for the subtree.
            highlight_pids: PIDs to flag.
            max_cmd_len: Max command line length.

        Returns:
            ASCII tree string for just this subtree.
        """
        if pid not in self._procs:
            return f"  PID {pid} not found\n"
        if highlight_pids is None:
            highlight_pids = set()
        lines: List[str] = []
        self._render_node(pid, "", True, lines, highlight_pids, max_cmd_len)
        return "\n".join(lines)

    def search(self, pattern: str) -> List[Dict[str, Any]]:
        """Search processes by name, PID, or cmdline.

        Args:
            pattern: Case-insensitive search term.

        Returns:
            List of matching process dicts.
        """
        pat = pattern.strip().lower()
        if not pat:
            return []
        results = []
        for pid, proc in self._procs.items():
            if (pat in proc["name"].lower()
                    or pat == pid
                    or pat in proc["cmdline"].lower()):
                results.append(proc)
        return results

    def get_ancestors(self, pid: str) -> List[str]:
        """Get the chain of parent PIDs up to the root.

        Args:
            pid: Starting PID.

        Returns:
            List of PIDs from root down to (not including) pid.
        """
        chain = []
        current = pid
        visited = set()
        while current in self._procs and current not in visited:
            visited.add(current)
            ppid = self._procs[current]["ppid"]
            if ppid and ppid in self._procs and ppid != current:
                chain.append(ppid)
                current = ppid
            else:
                break
        chain.reverse()
        return chain

    def write_tree_file(self, output_dir: Path,
                        highlight_pids: Optional[Set[str]] = None) -> Path:
        """Write the full process tree to a text file.

        Args:
            output_dir: Output directory.
            highlight_pids: PIDs to flag.

        Returns:
            Path to the written file.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out_path = output_dir / "process_tree.txt"

        tree = self.render(highlight_pids)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  PROCESS TREE\n")
            f.write(f"  Total: {len(self._procs)} processes\n")
            f.write("=" * 80 + "\n\n")
            f.write(tree)
            f.write("\n\n" + "=" * 80 + "\n")

        self.log.info("Process tree written: %s", out_path)
        return out_path

    @property
    def processes(self) -> Dict[str, Dict[str, Any]]:
        return self._procs

    @property
    def roots(self) -> List[str]:
        return self._roots
