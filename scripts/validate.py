#!/usr/bin/env python3
"""Offline schema gate for packages/*.json. Exit 1 on any violation."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = ROOT / "packages"

SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[A-Za-z0-9_-]+$")
LAYOUTS = ("flat-v1", "sharded-v2")


def expected_relpath(name, layout):
    if layout == "sharded-v2":
        lower = name.lower()
        if len(lower) == 1:
            shard = "1"
        elif len(lower) == 2:
            shard = "2"
        else:
            shard = lower[:2]
        return Path("packages") / shard / f"{name}.json"
    return Path("packages") / f"{name}.json"


def fail(errors, msg):
    errors.append(msg)


def check_file(path, errors):
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        fail(errors, f"{path.name}: unreadable JSON: {e}")
        return
    if not isinstance(doc, dict):
        fail(errors, f"{path.name}: top level must be an object")
        return
    name = doc.get("name")
    if not isinstance(name, str) or not NAME.fullmatch(name):
        fail(errors, f"{path.name}: bad 'name'")
    elif name != path.stem:
        fail(errors, f"{path.name}: 'name' must match filename")
    repo = doc.get("repository", "")
    if repo and not isinstance(repo, str):
        fail(errors, f"{path.name}: 'repository' must be a string")
    versions = doc.get("versions")
    if not isinstance(versions, list) or not versions:
        fail(errors, f"{path.name}: 'versions' must be a non-empty array")
        return
    seen = set()
    for i, entry in enumerate(versions):
        where = f"{path.name}#[{i}]"
        if not isinstance(entry, dict):
            fail(errors, f"{where}: entry must be an object")
            continue
        version = entry.get("version", "")
        if not isinstance(version, str) or not SEMVER.fullmatch(version):
            fail(errors, f"{where}: bad 'version'")
        if version in seen:
            fail(errors, f"{where}: duplicate version '{version}'")
        seen.add(version)
        tag = entry.get("tag", "")
        if not isinstance(tag, str) or not tag:
            fail(errors, f"{where}: missing 'tag'")
        checksum = entry.get("checksum", "")
        if checksum:
            hexpart = checksum[7:] if checksum.startswith("sha256:") else checksum
            if not HEX64.fullmatch(hexpart.lower()):
                fail(errors, f"{where}: bad 'checksum'")
        tarball = entry.get("tarball", "")
        if tarball and not (
            isinstance(tarball, str)
            and (tarball.startswith(("https://", "http://", "file://")))
        ):
            fail(errors, f"{where}: bad 'tarball' URL")
        yanked = entry.get("yanked", False)
        if not isinstance(yanked, bool):
            fail(errors, f"{where}: 'yanked' must be a bool")
        req = entry.get("requires_alya", "")
        if req and not (
            isinstance(req, str) and SEMVER.fullmatch(req.strip().lstrip("vV"))
        ):
            fail(errors, f"{where}: bad 'requires_alya'")


def main():
    errors = []
    if not PKG_DIR.is_dir():
        print("packages/ missing (nothing to validate)")
        return 0
    layout = "flat-v1"
    root_doc = ROOT / "index.json"
    if root_doc.is_file():
        try:
            declared = json.loads(root_doc.read_text(encoding="utf-8")).get("layout")
        except (OSError, json.JSONDecodeError) as e:
            print(f"index.json unreadable: {e}")
            return 1
        if declared not in LAYOUTS:
            print(f"index.json declares unknown layout '{declared}'")
            return 1
        layout = declared
    files = sorted(p for p in PKG_DIR.rglob("*.json") if p.is_file())
    if not files:
        print("no package documents found")
        return 1
    for path in files:
        check_file(path, errors)
        try:
            name = json.loads(path.read_text(encoding="utf-8")).get("name", "")
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(name, str) and name:
            want = ROOT / expected_relpath(name, layout)
            if path.resolve() != want.resolve():
                rel = want.relative_to(ROOT).as_posix()
                errors.append(
                    f"{path.name}: misplaced for layout '{layout}' (want {rel})"
                )
    if errors:
        print(f"{len(errors)} schema violation(s):")
        for msg in errors:
            print(f"  - {msg}")
        return 1
    print(f"OK: {len(files)} package document(s) valid (layout {layout})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
