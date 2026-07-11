# PoC — Recovering File Content from macOS RAM with `mac.pagecache`

**Date:** 2026-07-05
**Image:** `/home/kali/Desktop/RAMDUMPS (copy 1)/MAC` (macOS 10.12.6, build 16G29)
**Plugin:** `mac.pagecache.Pagecache` (see `MAC_PAGECACHE_PLUGIN.md`)
**PoC folder on disk:** `/home/kali/Desktop/MacRAM_PoC/`

Demonstrates a capability Volatility 3 did not previously have: carving real
**file content** out of a macOS memory image's page cache (Unified Buffer Cache).

---

## What was recovered (all byte-verified, non-zero)

| File in PoC folder | Size | Original path | Verification |
|---|---|---|---|
| `1_SystemVersion.plist` | 480 B | `/System/Library/CoreServices/SystemVersion.plist` | valid XML; **ProductVersion 10.12.6 / build 16G29** — matches the image OS exactly, proving the bytes are genuine |
| `2_dyld` | 698,896 B | `/usr/lib/dyld` | **Mach-O universal (x86_64 + i386 dynamic linker)**; 118/~171 pages resident → multi-page reassembly, non-resident pages sparse |
| `3_GlobalPreferences.plist` (+ `.decoded.txt`) | 2,888 B | `/Library/Preferences/.GlobalPreferences.plist` | **Apple binary plist**; decodes to real system settings (below) |
| `4_AddressBook_window_2.data` | 40,704 B | `/Users/admin/.../com.apple.AddressBook.savedState/window_2.data` | user app-state blob; **10/10 pages resident** → fully recovered |

## The forensic payload

Decoding the recovered `.GlobalPreferences.plist` yields real machine settings
pulled straight from RAM:

```
AppleLanguages                          = ['ru']
AppleLocale                             = en_TN
Country                                 = RU
com.apple.TimeZonePref.Last_Selected_City = ['55.75222','37.61555','0',
                                             'Europe/Moscow','RU','Moscow','Russia', ...]
com.apple.AppleModemSettingTool.LastCountryCode = FI
```

i.e. the host was configured with Russian language, Country = RU, timezone
Europe/Moscow (lat/long of Moscow) — genuine investigative context reconstructed
from a memory image with no disk access.

## How it was produced

```bash
cd ~/Desktop/volatility3
# OS-identity artifact + the dynamic linker
python3 vol.py -q -o out/ -f MAC mac.pagecache.Pagecache --dump \
    --name "CoreServices/SystemVersion.plist,/usr/lib/dyld"
# user/system preferences + user app state
python3 vol.py -q -o out/ -f MAC mac.pagecache.Pagecache --dump \
    --name "GlobalPreferences.plist,savedState/window_2.data"
```
Each recovered file lands as `mac_pagecache.<path>.0x<vnode>.dmp`. `--name` takes
a comma-separated OR list of path substrings.

## Honest caveats (important)

- **Only RAM-resident pages are recoverable.** Files whose data was never faulted
  in or was evicted have `memq` placeholder pages with `phys_page == 0` and recover
  **nothing** (reported as 0 cached pages — not silently zeroed). In this capture,
  e.g. the user's Messages `chat.db` and most image files had no resident data, so
  they were NOT recoverable. Of the image's files, **387** had genuinely
  recoverable content.
- Verified on macOS 10.12.6 (Intel). Other XNU versions may need field tweaks.

## Status

Proof of concept complete and byte-verified. The plugin is wired into CresCentC's
macOS file dumper (`modules/file_dumper.mac.py`), so `dump-files` and `dfir` /
`dump-all` on macOS now recover content — see
`SESSION_2026-07-05_MODES_AND_MAC_PAGECACHE.md`.
