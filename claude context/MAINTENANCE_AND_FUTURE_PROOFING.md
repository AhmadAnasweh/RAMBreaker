# Maintenance & Future-Proofing — Reducing Future Breakage

Written 2026-07-11 after a session that hit three failures on a live Kali
`6.19.14+kali-amd64` LiME capture (Ubuntu-only ISF resolver, incomplete
`struct mount` from an old dwarf2json, and `linux.lsmod` crashing on the changed
`struct taint_flag`). All three are now fixed; this doc is about not being
surprised by the *next* ones.

## The honest framing
You cannot make these errors go away. Volatility rides on kernel internals, and
the kernel changes its structs every release — so new kernels will keep breaking
plugins, permanently. The goal is not zero errors; it is shifting from
**"surprised mid-investigation by a cryptic failure"** to **"caught early, on my
schedule, diagnosed in minutes."** Every item below serves that shift.

Two independent error sources, keep them separate:
- **Tool-environment errors** (yours): stale dwarf2json, unapplied framework
  fixes, dependency drift. Fixable by pinning. *A container helps only here.*
- **Target-image errors** (the kernel's): missing/incomplete ISF, plugin-vs-new-
  kernel struct changes. These depend on the image, not your host — a container
  does NOT help. This is most of the pain.

## Highest-leverage action
**Keep Volatility3 current, and pin it.** Almost all target-kernel breakage
(`taint_flag`, and the next dozen like it) is fixed upstream by the Vol3 team
continuously. Running a months-old Vol3 against a days-old kernel means driving
behind the fix line. Bump Vol3 on a cadence + re-test and most struct-mismatch
gaps close before you ever see them. If you do one thing, do this.

## The ranked stack (reduce frequency, then reduce diagnosis time)
1. **Update Vol3 regularly** — kills most kernel-struct failures at the source.
2. **A tiny canary matrix** — not re-running one old Ubuntu image, but the
   *newest kernel per major distro* (Ubuntu / Debian / Kali / Fedora) + one
   bleeding-edge live capture. Run before trusting the tool on a real case; this
   turns "found it mid-case" into "found it Tuesday."
3. **Broaden symbol coverage proactively** — ISF acquisition is the other big
   source. Debian is now free from the Kali pool work; add Fedora/RHEL
   confidence, then SUSE/Arch as needed. Consider a BTF fallback for self-captures
   (image kernel == running kernel → build ISF from `/sys/kernel/btf/vmlinux`).
4. **Pin the whole toolchain** — dwarf2json@master (bundled in `_isf_build/`),
   Vol3 commit, deps. The ONLY axis where a container/reproducible env pays off
   (prevents the environment-regression class, e.g. the dwarf2json bug).
5. **Self-diagnosing failures** — the stub-struct guard in `dbgsym_builder`
   (done); the end-of-run failure fingerprint + opt-in crash report
   (`FUTURE_CRASH_REPORTING.md`). Doesn't prevent errors; collapses diagnosis
   from an hour to a glance.
6. **Categorize errors** in the log/report — tag each failure as
   *expected-nonbug* / *symbol* / *struct-mismatch* / *timeout*. Labeled, a
   struct-mismatch on a brand-new kernel reads as routine, not a fire.
7. **Smoke-test the ISF at build time** — after building an ISF, run one
   mount-dependent plugin (or rely on the stub-struct check) so an incomplete ISF
   is caught at resolution time, not 8 plugins deep.

## Suggested routine (before important runs)
`git pull` Vol3 → re-apply framework fixes (`installer.apply_framework_fixes`,
idempotent) → run the canary matrix → glance at the fingerprints. When a canary
breaks, patch on your own time.

## Diagnosing without the image
A failed run is usually fixable from `crescent_toolkit.log` alone, because
Volatility errors are self-labeling and the log records per-plugin pass/fail plus
the **kernel banner** — which lets the maintainer refetch that kernel's debug
package and reproduce the ISF/struct layout without the (multi-GB) image. Send the
log; for struct issues also the small ISF (`.json.xz`) or just the kernel version.
Never the image. Full signature table in `FUTURE_CRASH_REPORTING.md`.

## What a container will and won't do (settled this session)
- WILL: freeze a known-good toolchain (dwarf2json, Vol3, deps, framework fixes),
  keep the host clean, make runs reproducible/portable.
- WON'T: supply symbols for the target kernel, prevent new-kernel plugin
  breakage, or help the live-BTF self-capture path (a container shares the host
  kernel). Most of the recurring pain is target-image-driven and untouched by it.
