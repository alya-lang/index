# Alya Static Package Index

The machine-readable registry for Alya packages: one JSON document per
package under `packages/<name>.json`, listing every published version
with its release tag, tarball checksum, and minimum compiler version.

The `alya` compiler reads this index (no server involved) to resolve
`version = "x.y"` requirements to exact tags and to install
checksum-verified `alya-pkg.tar.gz` release assets:

- Default index: `https://raw.githubusercontent.com/alya-lang/index/main`
- Override: `ALYA_REGISTRY_INDEX` (`https://...` or `file://...`)
- No index / no match: the installer silently keeps git-based resolution.

## Layout

```text
index.json             # root document declaring the layout
packages/<name>.json   # one document per package (generated, committed)
scripts/generate.py    # rebuilds documents from live GitHub data
scripts/validate.py    # offline schema gate (runs in CI)
```

Two layouts are supported (`index.json`: `{"layout": ...}`):

- `flat-v1`: `packages/<name>.json` (current; fine into the thousands).
- `sharded-v2`: `packages/<aa>/<name>.json` (`aa` = first two lowercase
  characters, `1`/`2` for one- and two-letter names). Migration trigger:
  thousands of documents in one directory. Generate with
  `python scripts/generate.py --layout sharded`.

Clients read the root document first (cached like package documents)
and fall back to `flat-v1` when it is absent, so old and new readers
interoperate during any migration.

Entry shape:

```json
{
  "name": "http",
  "repository": "https://github.com/alya-lang/http",
  "versions": [
    {
      "version": "0.2.0",
      "tag": "v0.2.0",
      "checksum": "sha256:<hex of alya-pkg.tar.gz>",
      "requires_alya": "0.0.19",
      "yanked": false
    }
  ]
}
```

- `checksum` is omitted when the tag has no `alya-pkg.tar.gz` asset
  (the client falls back to git for those versions).
- `tarball` (optional URL) overrides the release-asset convention.
- `yanked` versions are never selected.

## Regenerating

```bash
python scripts/generate.py                  # all packages beside this repo
python scripts/generate.py --packages "http,tz"
python scripts/generate.py --layout sharded # sharded-v2 + root index.json
python scripts/generate.py --incremental    # only new tags (fast path)
python scripts/generate.py --packages "mypkg" --owner myname --out /tmp/myindex
python scripts/validate.py                  # offline schema check
```

## Automation

- **Weekly refresh** (`.github/workflows/update-index.yml`, Mondays 03:00
  UTC, plus manual dispatch): incremental regenerate → validate → PR
  labeled `automerge`.
- **Automerge** (`.github/workflows/automerge.yml`): merges labeled PRs
  only when the diff touches `packages/*.json`/`index.json` and CI is
  green. Anything else (scripts, workflows, docs) always needs a human.
  The label is the approval gate: only maintainers can label.

`generate.py` discovers packages as sibling directories containing
`alya.toml` (run it from a checkout where this repo sits next to the
package repos, e.g. `Lib/`), reads tags via `gh`, checksums and
`alya-version` via raw URLs. It needs `gh` authenticated for the tag
listing; everything else is anonymous HTTP.
