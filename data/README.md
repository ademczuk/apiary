# Datasets

## Primary: figshare NPM Malicious Package Study

- DOI: 10.6084/m9.figshare.31869370
- Landing page: https://figshare.com/articles/online_resource/NPM_Malicious_Package_Study/31869370
- License: CC BY 4.0
- Files (two ZIP archives, both named NPMStudy.zip but different sizes):
  - 87,885,991 bytes, direct URL: https://ndownloader.figshare.com/files/63179326
  - 3,365,075,598 bytes, direct URL: https://ndownloader.figshare.com/files/63260731

The smaller archive looks like a curated subset or labels-only bundle. The larger one is the full package corpus. Probe both before committing to one.

Run `python scripts/download_figshare.py` to fetch, verify, and unpack into `data/raw/figshare/`.

## Backup: OSSF malicious-packages

- Repo: https://github.com/ossf/malicious-packages
- License: Apache-2.0
- Repo size: ~260 MB checked out
- npm OSV records: 213,418 (counted via `git ls-tree -r HEAD`)
- Schema: OSV 1.5.0 JSON, one file per malicious release
- Path glob: `osv/malicious/npm/<package>/MAL-YYYY-N.json`

WINDOWS GOTCHA: the working tree contains paths longer than 260 chars and filenames with colons (e.g. `osv/malicious/vscode:open-vsx.org/...`). A naive `git clone` on Windows produces partial checkout errors. Two options:

1. Clone in WSL: works cleanly.
2. Clone with sparse checkout on Windows, pulling only `osv/malicious/npm/`:

```bash
git clone --filter=blob:none --no-checkout https://github.com/ossf/malicious-packages data/raw/ossf-malpkg
cd data/raw/ossf-malpkg
git sparse-checkout init --cone
git sparse-checkout set osv/malicious/npm
git checkout main
```

A handful of npm subdirectories also exceed Windows path limits because the package names themselves are very long; expect a small number of skipped files even with sparse checkout. The count of usable records on Windows is in the high 200,000s minus a few dozen.

If you don't need the working tree at all (e.g. you only want to iterate over records), use `git ls-tree -r HEAD --name-only | grep '/npm/.*\.json$'` plus `git show HEAD:<path>` to stream contents without ever materializing the file on disk.

## Excluded: Backstabbers Knife Collection

Access is email-gated. The maintainer at ohm[at]cs.uni-bonn.de approves requests from institutional addresses. Lead time exceeds the hackathon budget. Re-evaluate after the event.

## On-disk layout

```
data/
├── raw/
│   ├── figshare/         # NPMStudy.zip unpacked here
│   └── ossf-malpkg/      # OSSF OSV records
├── processed/            # HuggingFace Dataset arrow files
└── interim/              # extracted features, AST trees, etc.
```
