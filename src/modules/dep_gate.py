"""Dependency gate for the parallel plugin batch (v2.4.1).

Before v2.4.1 every plugin was submitted to the thread pool before any result
came back, so the extractors' "skip the dependents of a failed parent" check
always saw an empty failed-set and never skipped anything. The gate holds a
dependent back until every parent of it in the SAME batch has finished:

  * parent OK                -> the dependent is released (submitted);
  * parent failed for real   -> the dependent is skipped (it reads the parent's
                                structures and would fail the same way);
  * parent timed out, hit the cold-symbol race, or could not be started by
    Windows                  -> the dependent is released anyway: none of these
                                say anything about whether the dependent works
                                (e.g. a timed-out netscan, a fast netstat).

A parent that is not in the batch (not in this mode's plugin list, or already
done in an earlier run of the case) gates nothing. Mutual edges (A gates B and
B gates A) are dropped, so the gate can never deadlock. A skipped plugin counts
as failed for its own dependents.
"""
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

def failure_kind(res: Optional[dict]) -> str:
    """'ok', 'timed out', 'symbol tables not ready yet', 'process did not run', or
    'plugin error'. Only 'plugin error' (Volatility ran and reported an error:
    unsatisfied requirement, unreadable structure, ...) means the dependents would
    fail the same way. A timeout, the cold-symbol race (retried serially) and a
    process Windows could not start or ended (NT status exit codes such as
    0xC0000142 out of memory / 0xC000013A console closed) analysed nothing."""
    if not res:
        return "process did not run"
    if res.get("success"):
        return "ok"
    low = str(res.get("error", "") or "").lower()
    if res.get("timed_out") or low.startswith(("timeout", "timed out")):
        return "timed out"
    if "symbol_table_name" in low or "symbol table requirement" in low:
        return "symbol tables not ready yet"
    rc = res.get("returncode")
    if isinstance(rc, int) and (rc == -1 or (rc & 0xFFFFFFFF) >= 0xC0000000):
        return "process did not run"
    if "could not start the plugin process" in low:
        return "process did not run"
    return "plugin error"


def is_hard_failure(res: Optional[dict]) -> bool:
    """True when the dependents of this plugin would fail the same way."""
    return failure_kind(res) == "plugin error"


class DependencyGate:
    def __init__(self, plugins: Iterable[str], deps: Dict[str, Set[str]],
                 short_name: Callable[[str], str]):
        self.order: List[str] = list(plugins)
        self._short = {p: short_name(p) for p in self.order}
        present = {}
        for p in self.order:
            present.setdefault(self._short[p], p)
        # child plugin -> parent plugins (full names) in this batch
        self.parents: Dict[str, Set[str]] = {p: set() for p in self.order}
        for parent_sn, children in deps.items():
            if parent_sn not in present:
                continue
            for p in self.order:
                sn = self._short[p]
                if sn == parent_sn or sn not in children:
                    continue
                # drop mutual edges (A<->B): neither may wait for the other
                if parent_sn in deps.get(sn, set()):
                    continue
                self.parents[p].add(present[parent_sn])
        self._pending: Dict[str, Set[str]] = {p: set(v) for p, v in self.parents.items()}
        self._released: Set[str] = set()
        self._failed: Dict[str, str] = {}      # plugin -> why (for dependents)
        self.skipped: List[Tuple[str, str]] = []

    def initial(self) -> List[str]:
        """Plugins that can start now (no parent in this batch), in list order."""
        out = [p for p in self.order if not self._pending[p]]
        self._released.update(out)
        return out

    def finished(self, plugin: str, hard_failed: bool) -> Tuple[List[str], List[Tuple[str, str]]]:
        """Record a finished plugin. Returns (plugins to start now, [(skipped, parent)]),
        both in list order."""
        if hard_failed:
            self._failed[plugin] = plugin
        release: List[str] = []
        skipped: List[Tuple[str, str]] = []
        queue = [plugin]
        while queue:
            done = queue.pop(0)
            for p in self.order:
                if p in self._released or done not in self._pending[p]:
                    continue
                self._pending[p].discard(done)
                bad = next((par for par in self.parents[p] if par in self._failed), None)
                if bad is not None:
                    self._released.add(p)
                    self._failed[p] = bad
                    skipped.append((p, self._short[bad]))
                    queue.append(p)          # cascade to its own dependents
                elif not self._pending[p]:
                    self._released.add(p)
                    release.append(p)
        self.skipped.extend(skipped)
        return release, skipped

    def unreleased(self) -> List[str]:
        """Plugins never started or skipped (should be empty once all have finished)."""
        return [p for p in self.order if p not in self._released]
