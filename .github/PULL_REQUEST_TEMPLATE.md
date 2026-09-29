## 📝 Description

What index entry does this change (package + versions)?

## 🔍 Type of Change

- [ ] 📦 New package entry (`packages/<name>.json`)
- [ ] 🔄 Version update (new release entries for an existing package)
- [ ] 🚫 Yank a version (set `yanked: true`, never delete entries)
- [ ] 🐛 Metadata fix (wrong checksum, tag, URL)
- [ ] 🛠️ Generator/validator tooling

## 📋 Checklist

- [ ] `python scripts/validate.py` passes locally
- [ ] Checksums copied from the real `alya-pkg.tar.gz.sha256` release assets (never hand-typed)
- [ ] Entries sorted ascending by version; no duplicate versions
- [ ] I own / maintain the package, or the change is generated output (`scripts/generate.py`)
