# `mac.pagecache.Pagecache` — macOS Page-Cache File-Content Recovery (Vol3 plugin)

**Author:** CresCentC (2026-07-05)
**File:** `/home/kali/Desktop/volatility3/volatility3/framework/plugins/mac/pagecache.py`
**Status:** working, verified on macOS 10.12.6 (Intel / `macOS_KDK_10.12.6_build-16G29`).

---

## 1. Why this exists

Volatility 3 can recover **file content** from RAM on Windows
(`windows.dumpfiles`) and Linux (`linux.pagecache.RecoverFs` / `InodePages`), but
NOT macOS. `mac.list_files` only walks vnodes to enumerate **paths** — it never
descends to the cached bytes. This plugin closes that gap: it reconstructs a
file's content from the macOS **Unified Buffer Cache (UBC)**.

## 2. The structure chain (what it walks)

```
vnode                      (one per file; regular files only, v_type == VREG == 1)
  .v_un.vu_ubcinfo   ->  ubc_info            (the UBC record for the file)
        .ui_size            file size (authoritative bound for reassembly)
        .ui_control  ->  memory_object_control
              .moc_object ->  vm_object       (the VM object backing the file)
                    .memq   ->  vm_page queue (all resident pages of the object)
                          each vm_page:
                            .offset       offset of this page within the file
                            .phys_page    physical page number (ppnum), 0 = no frame
                            .listq.next   packed link to the next page in memq
```

Recovery: for each resident `vm_page`, read `PAGE_SIZE` (4096) bytes from the
physical layer at `phys_page * 4096`, write them at `page.offset`, and truncate
the output to `ui_size`. Non-resident pages are left as sparse zero-holes.

This mirrors `linux.pagecache.write_inode_content_to_stream` (seek to page
offset, write, truncate to size) — only the structure walk differs.

## 3. The hard part: packed `memq` pointers

`vm_object.memq` and `vm_page.listq` are **not** plain 64-bit pointers. XNU packs
them into 32-bit `vm_page_packed_t` values. On the ISF this shows up as
`vm_page_queue_head_t` / `vm_page_queue_chain_t` each being 8 bytes with
`next`/`prev` typed `unsigned int`.

The first attempt (treating them as raw addresses, or as a classic `queue_chain`
with container_of) yielded **0 pages**. The fix: implement XNU's
`VM_PAGE_UNPACK_PTR`, reading its constants from **kernel globals by symbol** so
the KASLR slide is applied automatically:

- `vm_packed_pointer_shift`            (= 6 here)
- `vm_min_kernel_and_kext_address`     (= 0xFFFFFF7F80000000 here — the zone base)
- `vm_packed_from_vm_pages_array_mask` (= 0x80000000 here — the "in vm_pages array" bit)
- `vm_pages`                           (base of the vm_pages array)

Dual scheme (matches XNU `vm_page_unpack_ptr`):
```
unpack(p):
  if p & array_mask:  return vm_pages + (p & ~array_mask) * sizeof(vm_page)   # array page
  else:               return (p << shift) + min_kernel_and_kext_address        # zoned page
```
Each unpacked link points to the **next vm_page base directly** (no container_of);
the walk ends when a link unpacks back to `&memq` (i.e. the vm_object address,
since `memq` sits at object offset 0).

## 4. The correctness gotcha: placeholder pages (`phys_page == 0`)

A file's `memq` can contain pages that are reserved/known but have **no physical
frame** (never faulted in, or evicted). Their `phys_page` is 0 (and/or
`absent`/`fictitious` set). These carry NO data — reading them yields zeros.

`_page_has_data(page)` skips pages that are `absent`, `fictitious`, or have
`phys_page == 0`. This is applied in BOTH the counting path
(`_cached_page_offsets`) and the read path (`_read_page`), so:
- `CachedPages` / `CachedBytes` report only genuinely recoverable data, and
- `--dump` only writes real bytes (missing pages stay sparse).

Symptom if you skip this: files list with `CachedPages > 0` but dump as all-zeros.

## 5. Physical read

```python
phys_name = context.layers[kernel.layer_name].config.get("memory_layer", kernel.layer_name)
phys = context.layers[phys_name]
paddr = phys_page * 4096
if phys.is_valid(paddr, 4096):
    data = phys.read(paddr, 4096)
```
(Same idiom Vol3's Linux page extension uses.)

## 6. ISF requirements

The macOS ISF **must** carry these types (the KDK ISF does):
`vnode` (with `v_un.vu_ubcinfo`), `ubc_info` (`ui_control`, `ui_size`),
`memory_object_control` (`moc_object`), `vm_object` (`memq`),
`vm_page` (`offset`, `phys_page`, `listq`, `absent`, `fictitious`), and the
`enum vtype` (VREG = 1). Plus the packing globals in §3 as symbols.

If an ISF lacks these (some community ISFs are stripped), the plugin logs an error
and yields nothing rather than crashing.

## 7. Usage

```bash
# List every file that has recoverable page-cache content
python3 vol.py -f MAC mac.pagecache.Pagecache
#   -> Vnode | Path | Size | CachedPages | CachedBytes | FileOutput

# Recover ALL cached content into out/
python3 vol.py -f MAC -o out/ mac.pagecache.Pagecache --dump

# Recover only matching files (--name is a path substring; comma = match ANY)
python3 vol.py -f MAC -o out/ mac.pagecache.Pagecache --dump \
    --name "SystemVersion.plist,/Users/admin/,GlobalPreferences.plist"
```

Options: `--dump` (BooleanRequirement, default off), `--name` (StringRequirement,
comma-separated OR substrings). Requirements mirror `mac.list_files` (kernel
module, `mount`, `mac_utilities`) since the vnode enumeration reuses
`list_files.List_Files.list_files`.

## 8. Verified results (MAC, 10.12.6)

- **387** files with genuinely recoverable pages (after the `phys_page != 0` fix;
  a naive count reported ~8,634 including placeholders).
- `SystemVersion.plist` — 480 B, valid XML, `ProductVersion 10.12.6 / 16G29`
  (matches the image OS = the bytes are genuine).
- `/usr/lib/dyld` — 698,896 B, `Mach-O universal (x86_64 + i386 dynamic linker)`;
  118/~171 pages resident → correct multi-page reassembly with sparse holes.
- `.GlobalPreferences.plist` — 2,888 B binary plist, decodes to real settings
  (AppleLocale, AppleLanguages, Country, selected timezone city).
- AddressBook `window_2.data` — 40,704 B, 10/10 pages, fully recovered.

## 9. Limitations

- Only pages resident in the capture are recoverable; evicted / never-faulted file
  data cannot be (reported as 0 cached pages, not silently zeroed).
- Verified on 10.12.6 Intel. Field names/offsets and the packing scheme vary across
  XNU versions; the packing **base** is read at runtime (handles KASLR + some
  version drift) but struct layout still depends on the ISF. ARM/Apple-Silicon not
  tested.
- Enumerating all vnodes takes minutes on a real image (reuses `mac.list_files`).
