"""Export the publishable RAMBreaker source into a clone of the GitHub repository.

Usage, from the project root:
    runtime\\py3\\Scripts\\python.exe -I build_tools\\make_github_export.py <clone-dir>

<clone-dir> is a git clone of github.com/AhmadAnasweh/RAMBreaker. Its working tree
(everything except .git) is replaced by:
  - the files committed at HEAD in this repo under INCLUDE below (uncommitted
    edits and untracked files are never exported), and
  - a root LICENSE (copy of src/LICENSE) and the public .gitignore below.
Dev notes, agent prompts, test reports, screenshots, work files and case output
are not in INCLUDE, so they never reach the public repository.

A privacy scan then checks every exported text file for this machine's user
profile path, the folder that holds the project, the git user e-mail and each
line of config/private_terms.txt (gitignored, never exported). Any hit is listed
and the exit code is 1. Nothing is committed or pushed: review with
`git status` in the clone, then commit there.
"""
import io
import os
import shutil
import subprocess
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INCLUDE = (
    "src", "sigma_rules", "yara_rules", "threat_intel_db/bundled",
    "README.md", "CHANGELOG.md", "VERSIONS.md", "DEFENDER.md",
    "requirements-py3.lock.txt", "requirements-py27.lock.txt",
    "config/timeouts.json", "config/timing_samples.jsonl",
    "build_tools/build.ps1", "build_tools/make_release.ps1", "build_tools/prepare_vol3.py",
    "build_tools/check_frozen_imports.py", "build_tools/backfill_timings.py",
    "build_tools/make_help_media.py", "build_tools/make_icon.py",
    "build_tools/make_ioc_list.py", "build_tools/score_ioc_check.py",
    "build_tools/report_check.py", "build_tools/compare_case.py",
    "build_tools/e2e_queue.py", "build_tools/run_sample.ps1",
    "build_tools/run_detached.ps1", "build_tools/make_github_export.py",
    "build_tools/make_manual_shots.py",
)

PUBLIC_GITIGNORE = """\
# Portable runtimes, build and release output (see README "Building from source")
/runtime/
/build/
/dist/
/release/
# Per-machine state and case data: never commit evidence
/output/
/logs/
/cache/
/work/
/config/gui_settings.json
/config/secrets.dat
/config/private_terms.txt
/threat_intel_db/downloaded/
/yara_rules/yara-forge/_downloaded/
CresCentC_work/
CresCentC_RESULTS/
__pycache__/
*.pyc
venv*/
"""


def git(*args, cwd=ROOT, binary=False):
    out = subprocess.run(["git", "-c", "core.autocrlf=false", *args], cwd=cwd,
                         check=True, capture_output=True).stdout
    return out if binary else out.decode("utf-8", "replace")


def private_terms():
    """(term, label) pairs; labels keep e-mail and private terms out of the console."""
    terms = []
    home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    parent = os.path.dirname(ROOT)
    for path, label in ((home, "user profile path"), (parent, "project parent folder")):
        if path and len(path) > 3:
            for v in {path, path.replace("\\", "/"), path.replace("\\", "\\\\")}:
                terms.append((v, label))
    try:
        email = git("config", "user.email").strip()
        if email:
            terms.append((email, "git user.email"))
    except subprocess.CalledProcessError:
        pass
    extra = os.path.join(ROOT, "config", "private_terms.txt")
    if os.path.isfile(extra):
        with open(extra, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                if line.strip() and not line.startswith("#"):
                    terms.append((line.strip(), f"private_terms.txt line {i}"))
    return [(t.lower(), label) for t, label in terms]


def scan(dst, terms):
    hits = []
    for base, dirs, names in os.walk(dst):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in names:
            path = os.path.join(base, name)
            with open(path, "rb") as fh:
                data = fh.read()
            if b"\0" in data[:8192]:
                continue
            for n, line in enumerate(data.decode("utf-8", "ignore").lower().splitlines(), 1):
                for term, label in terms:
                    if term in line:
                        hits.append(f"{os.path.relpath(path, dst)}:{n}: {label}")
    return hits


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    dst = os.path.abspath(sys.argv[1])
    if not os.path.isdir(os.path.join(dst, ".git")):
        sys.exit(f"not a git clone: {dst}")
    if os.path.normcase(dst) == os.path.normcase(ROOT):
        sys.exit("refusing to export into the dev repo itself")
    if "RAMBreaker" not in git("remote", "get-url", "origin", cwd=dst):
        sys.exit("the clone's origin is not a RAMBreaker repository")

    tracked = set(p for p in git("ls-tree", "-r", "-z", "--name-only", "HEAD").split("\0") if p)
    missing = [p for p in INCLUDE if p not in tracked and not any(t.startswith(p + "/") for t in tracked)]
    if missing:
        sys.exit("not committed in this repo: " + ", ".join(missing))

    for name in os.listdir(dst):
        if name == ".git":
            continue
        path = os.path.join(dst, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    data = git("archive", "--format=tar", "HEAD", "--", *INCLUDE, binary=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        members = [m for m in tar.getmembers() if m.isfile()]
        tar.extractall(dst, filter="data")
    shutil.copyfile(os.path.join(dst, "src", "LICENSE"), os.path.join(dst, "LICENSE"))
    with open(os.path.join(dst, ".gitignore"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(PUBLIC_GITIGNORE)

    size = sum(m.size for m in members)
    print(f"exported {len(members)} files ({size / 1e6:.1f} MB) from {git('rev-parse', '--short', 'HEAD').strip()}"
          f" + LICENSE + .gitignore -> {dst}")

    ignored = [p for p in git("ls-files", "--others", "--ignored", "--exclude-standard", cwd=dst).splitlines() if p]
    if ignored:
        print(f"WARNING: {len(ignored)} exported files are hidden by a .gitignore (git add would skip them):")
        for p in ignored[:20]:
            print("   ", p)

    hits = scan(dst, private_terms())
    if hits:
        print(f"PRIVACY SCAN: {len(hits)} hit(s) - fix them in this repo and export again:")
        for h in hits[:50]:
            print("   ", h)
        return 1
    print("privacy scan: clean")
    return 1 if ignored else 0


if __name__ == "__main__":
    sys.exit(main())
