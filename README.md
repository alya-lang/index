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
packages/<name>.json   # one document per package (generated, committed)
scripts/generate.py    # rebuilds packages/*.json from live GitHub data
scripts/validate.py    # offline schema gate (runs in CI)
```

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
python scripts/validate.py                  # offline schema check
```

`generate.py` discovers packages as sibling directories containing
`alya.toml` (run it from a checkout where this repo sits next to the
package repos, e.g. `Lib/`), reads tags via `gh`, checksums and
`alya-version` via raw URLs. It needs `gh` authenticated for the tag
listing; everything else is anonymous HTTP.
