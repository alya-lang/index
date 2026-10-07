#!/usr/bin/env python3
"""Rebuild packages/*.json from live GitHub data.

Discovers packages as sibling directories containing alya.toml (run from a
checkout where this repo sits next to the package repos), lists release
tags via `gh`, and fills checksums + alya-version via raw URLs:

    python scripts/generate.py
    python scripts/generate.py --packages "http,tz" [--lib-dir Lib]

Only semver-looking tags become entries. A tag without an
alya-pkg.tar.gz asset keeps its entry with no checksum (the client falls
back to git for those versions). A full rebuild refreshes every entry
from live data but preserves previously recorded `yanked: true` flags,
so yanks are never silently dropped (un-yanking likewise takes effect
on the next full rebuild).
"""
import argparse
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER_TAG = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$")
ALYA_VERSION = re.compile(r'^\s*alya-version\s*=\s*["\']([^"\']+)["\']', re.M)


def run_gh(args):
    proc = subprocess.run(
        ["gh"] + args, capture_output=True, text=True, timeout=60
    )
    if proc.returncode != 0:
        raise RuntimeError(f"gh failed: {proc.stderr.strip()}")
    return proc.stdout


def fetch_text(url, timeout=20):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def list_tags(repo):
    out = run_gh(["release", "list", "--repo", repo, "--limit", "100", "--json", "tagName"])
    try:
        releases = json.loads(out)
    except json.JSONDecodeError:
        return []
    tags = []
    for rel in releases:
        tag = (rel.get("tagName") or "").strip()
        if SEMVER_TAG.fullmatch(tag):
            tags.append(tag)
    return tags


def semver_key(tag):
    m = SEMVER_TAG.fullmatch(tag)
    nums = tuple(int(m.group(i)) for i in (1, 2, 3))
    pre = m.group(4) or ""
    return (nums, pre == "", pre)


def checksum_for(owner, repo, tag):
    url = (
        f"https://github.com/{owner}/{repo}/releases/download/"
        f"{tag}/alya-pkg.tar.gz.sha256"
    )
    text = fetch_text(url)
    if not text:
        return None
    first = text.split()[0].strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", first):
        return f"sha256:{first}"
    return None


def requires_alya(owner, repo, tag):
    text = fetch_text(
        f"https://raw.githubusercontent.com/{owner}/{repo}/{tag}/alya.toml"
    )
    if not text:
        return None
    m = ALYA_VERSION.search(text)
    return m.group(1).strip() if m else None


def discover_packages(lib_dir):
    found = []
    for child in sorted(lib_dir.iterdir()):
        if not child.is_dir() or child.name in ("index", "template"):
            continue
        if (child / "alya.toml").is_file():
            found.append(child.name)
    return found


def shard_dir(name):
    lower = name.lower()
    if len(lower) == 1:
        return "1"
    if len(lower) == 2:
        return "2"
    return lower[:2] if lower else "_"


def doc_path(repo_root, name, layout):
    if layout == "sharded":
        return repo_root / "packages" / shard_dir(name) / f"{name}.json"
    return repo_root / "packages" / f"{name}.json"


def build_entry(owner, repo, tag):
    version = tag[1:] if tag[:1] in ("v", "V") else tag
    entry = {"version": version, "tag": tag}
    checksum = checksum_for(owner, repo, tag)
    if checksum:
        entry["checksum"] = checksum
    req = requires_alya(owner, repo, tag)
    if req:
        entry["requires_alya"] = req
    return entry


def load_existing_versions(doc_path):
    """Version entries of an existing index document ({} when absent)."""
    try:
        doc = json.loads(doc_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    versions = doc.get("versions")
    return versions if isinstance(versions, list) else []


def apply_preserved_yanked(old_versions, new_versions):
    """Carry `yanked: true` flags across a full rebuild.

    Everything else (checksum, requires_alya) is refreshed from live data;
    only an explicit yank survives, so un-yanking is a full rebuild away
    while yanks are never silently dropped.
    """
    yanked_tags = {
        e["tag"]
        for e in old_versions
        if isinstance(e, dict) and e.get("tag") and e.get("yanked") is True
    }
    for e in new_versions:
        if e.get("tag") in yanked_tags:
            e["yanked"] = True
    return new_versions


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib-dir", default=None)
    parser.add_argument("--packages", default=None)
    parser.add_argument(
        "--owner",
        default="alya-lang",
        help="GitHub owner for tag listing and repository URLs",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="repository root to write into (default: this repo)",
    )
    parser.add_argument(
        "--layout",
        choices=("flat", "sharded"),
        default="flat",
        help="index layout: flat writes packages/<name>.json, sharded writes "
        "packages/<aa>/<name>.json plus a root index.json declaring the layout",
    )
    parser.add_argument(
        "--incremental",
        action="store_true",
        help="only process tags missing from the existing documents "
        "(skips API/HTTP work for known versions)",
    )
    args = parser.parse_args()

    lib_dir = Path(args.lib_dir) if args.lib_dir else ROOT.parent
    repo_root = Path(args.out) if args.out else ROOT
    out_dir = repo_root / "packages"
    out_dir.mkdir(parents=True, exist_ok=True)
    layout = args.layout

    if args.packages:
        names = [p.strip() for p in args.packages.split(",") if p.strip()]
    else:
        names = discover_packages(lib_dir)

    ok, failed = 0, []
    for name in names:
        try:
            tags = sorted(set(list_tags(f"{args.owner}/{name}")), key=semver_key)
            if not tags:
                print(f"  ! {name}: no semver tags")
                failed.append(name)
                continue
            if args.incremental:
                # Reuse recorded entries: only new tags cost API/HTTP calls.
                # A tag whose entry exists with a checksum is trusted as-is.
                existing = {}
                dest_probe = doc_path(repo_root, name, args.layout)
                if dest_probe.is_file():
                    try:
                        old_doc = json.loads(dest_probe.read_text(encoding="utf-8"))
                        for entry in old_doc.get("versions", []):
                            if isinstance(entry, dict) and entry.get("tag"):
                                existing[entry["tag"]] = entry
                    except (OSError, ValueError):
                        pass
                missing = [t for t in tags if t not in existing]
                if not missing:
                    print(f"  = {name}: up to date ({len(tags)} version(s))")
                    ok += 1
                    continue
                kept = [existing[t] for t in tags if t in existing]
                fresh = [build_entry(args.owner, name, t) for t in missing]
                versions = sorted(kept + fresh, key=lambda e: semver_key(e["tag"]))
            else:
                old_versions = load_existing_versions(
                    doc_path(repo_root, name, args.layout)
                )
                versions = [build_entry(args.owner, name, t) for t in tags]
                versions = apply_preserved_yanked(old_versions, versions)
            doc = {
                "name": name,
                "repository": f"https://github.com/{args.owner}/{name}",
                "versions": versions,
            }
            dest = doc_path(repo_root, name, layout)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(
                json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline=""
            )
            print(f"  + {name}: {len(versions)} version(s)")
            ok += 1
        except Exception as e:  # per-package isolation: never abort the run
            print(f"  ! {name}: {e}")
            failed.append(name)
    root_doc = {"layout": "sharded-v2" if layout == "sharded" else "flat-v1"}
    (repo_root / "index.json").write_text(
        json.dumps(root_doc, indent=2) + "\n", encoding="utf-8", newline=""
    )
    print(f"layout: {root_doc['layout']}")
    print(f"done: {ok} package(s), {len(failed)} failed {failed}")
    return 1 if failed and ok == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
