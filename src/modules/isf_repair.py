"""ISF repair (RAMBreaker v2): fix a known dwarf2json defect in Linux ISFs.

dwarf2json names anonymous members `unnamed_field_<offset>`. Inside a union all
variants sit at offset 0, so several anonymous structs collide on the same key
and only the LAST one survives. In `struct page` (64-bit kernels >= 4.18) the
union at offset 8 holds ~8 anonymous variants; the page-cache one

    struct { struct list_head lru; struct address_space *mapping;
             pgoff_t index; unsigned long private; };

is lost, so Vol3 raises "StructType has no attribute ...page.mapping" and every
page-cache file dump (linux.pagecache.InodePages / RecoverFs) comes out empty.
Seen on Ubuntu 5.4.0-1059-azure (debug-package ISF).

repair(path) restores that variant only when the layout is exactly the known one
(anonymous 40-byte union at offset 8 of a 64-byte page, `mapping` unreachable),
so correct ISFs are never touched. Returns a list of fixes applied.
"""

import json
import lzma
from pathlib import Path
from typing import Any, Dict, List


def _reachable(ut: Dict[str, Any], tname: str, field: str, depth: int = 0) -> bool:
    t = ut.get(tname)
    if not t or depth > 4:
        return False
    for fname, f in t.get("fields", {}).items():
        if fname == field:
            return True
        ty = f.get("type", {})
        if f.get("anonymous") and ty.get("kind") in ("struct", "union"):
            if _reachable(ut, ty.get("name", ""), field, depth + 1):
                return True
    return False


def repair_isf(isf: Dict[str, Any]) -> List[str]:
    fixes: List[str] = []
    ut = isf.get("user_types", {})
    bt = isf.get("base_types", {})
    page = ut.get("page")
    if not page or page.get("size") != 64 or _reachable(ut, "page", "mapping"):
        return fixes
    if "list_head" not in ut or "address_space" not in ut or "long unsigned int" not in bt:
        return fixes
    union = None
    for f in page.get("fields", {}).values():
        ty = f.get("type", {})
        if f.get("offset") == 8 and f.get("anonymous") and ty.get("kind") == "union":
            u = ut.get(ty.get("name", ""))
            if u and u.get("size") == 40:
                union = u
    if union is None:
        return fixes
    name = "rambreaker_page_cache_variant"
    # lru is a 16-byte list_head: mapping @16, index @24, private @32 (= the
    # 40-byte union), i.e. page.mapping at +24 as in every 64-bit kernel >= 4.18
    if ut["list_head"].get("size") != 16:
        return fixes
    ut[name] = {"kind": "struct", "size": 40, "fields": {
        "lru": {"offset": 0, "type": {"kind": "struct", "name": "list_head"}},
        "mapping": {"offset": 16, "type": {"kind": "pointer",
                                           "subtype": {"kind": "struct", "name": "address_space"}}},
        "index": {"offset": 24, "type": {"kind": "base", "name": "long unsigned int"}},
        "private": {"offset": 32, "type": {"kind": "base", "name": "long unsigned int"}},
    }}
    union["fields"]["rambreaker_page_cache"] = {"offset": 0, "anonymous": True,
                                                "type": {"kind": "struct", "name": name}}
    fixes.append("struct page: restored the page-cache variant (lru/mapping/index/private) "
                 "lost to a dwarf2json anonymous-member name collision")
    return fixes


def repair(path) -> List[str]:
    p = str(path)
    opener = lzma.open if p.endswith(".xz") else open
    with opener(p, "rb") as f:
        isf = json.loads(f.read())
    fixes = repair_isf(isf)
    if fixes:
        with opener(p, "wb") as f:
            f.write(json.dumps(isf).encode())
    return fixes


if __name__ == "__main__":                       # repair installed ISFs by hand
    import sys
    for a in sys.argv[1:]:
        print(Path(a).name, repair(a) or "no change")
