# Andreas finetune data integration

## What we expect

Andreas is sharing a Drive folder of supervised finetune data to fold
into the apiary v3 audit-model training run. We do not yet know the
exact format because the Drive MCP server is offline at integration
time and we have not seen the files.

Working assumptions:

- Volume: somewhere between 5k and 200k examples (educated guess from
  a single contributor working solo over a quarter).
- License: tagged on receipt. We will reject anything that does not
  carry a license header or a separate LICENSE file alongside the
  examples. License goes into `meta.license` per record.
- Domain overlap: at least partial alignment with npm supply-chain
  audit. If the data is broader (general security, general code QA),
  the adapter still ingests it. The data-mix decision happens
  downstream in `data_prep.py`.

## Shapes the adapter auto-detects

`apiary_train.andreas_data_adapter` samples the first 100 records and
classifies into one of four shapes.

| Shape | Detection key | Mapping to messages |
|-------|---------------|---------------------|
| A     | top-level `messages` list of `{role, content}` | pass through |
| B     | top-level `prompt` + `completion` strings | system + user(prompt) + assistant(completion) |
| C     | `input`/`question`/`instruction` plus `output`/`answer`/`response` | system + user + assistant |
| D     | directory holding two or more of `train.json{,l}`, `validation.json{,l}`, `test.json{,l}` | per-split detect of A/B/C, merge with `meta.split` preserved |

Anything else returns `"unknown"` and the adapter refuses to write
output. That is the design: silent passthrough of malformed data is
worse than a clear stop.

## How to point the training pipeline at it

Two steps:

```bash
# 1. fetch the data (once Andreas confirms public access or hands us a token)
python scripts/fetch_andreas_data.py \
    --drive-folder-id 1GaNVt0eP9k-BW_E0fuIdqd5gsvY2a1Mz \
    --output data/raw/andreas-finetune/ \
    --auth-method gdown

# 2. fold it into the SFT prep
python -m apiary_train.data_prep \
    --figshare-archive data/raw/figshare/63179326_NPMStudy.zip \
    --synthetic-dir data/synthetic/v1 \
    --andreas-data data/raw/andreas-finetune/ \
    --output data/sft/v1.jsonl
```

The `--andreas-data` flag triggers shape detection, normalization to
the chat-message target, and append-with-shuffle into the train/test
split. Counts per source are printed at the end and persisted to
`data/sft/v1.stats.json`.

## What to do if the shape is not recognized

1. Read the first 5 records by hand and pick out the load-bearing keys.
2. Add a new shape variant in `andreas_data_adapter.py`. Two pieces:
   a tag for `_classify_record` and a normalizer function that returns
   the messages list. Add a smoke test in
   `tests/test_andreas_adapter.py` and confirm it passes.
3. If the new shape needs configuration (e.g., the system prompt
   should be context-dependent), thread that through
   `normalize_to_sft_format`'s call signature.

The four shapes we ship today cover the formats published by the
common SFT data tooling (Axolotl, OpenAI fine-tuning, HuggingFace
datasets, LMFlow). The hit rate on Andreas's data should be high.

## Data flow

```
Google Drive folder
        |
        v
scripts/fetch_andreas_data.py
        |
        v  (zip/tar unpacked, sha256 + sft-key sample logged)
data/raw/andreas-finetune/manifest.json
        |
        v
apiary_train.andreas_data_adapter.normalize_to_sft_format
        |
        v
data/sft/v1.jsonl   (combined with figshare + synthetic)
        |
        v
apiary_train.sft_lora  (Axolotl style LoRA run on 64x H100)
        |
        v
apiary v3 audit model
```

## Honest note on the integration state

We have not seen the data yet. The Google Drive MCP server is down at
integration time, so the only way to fetch is via the user-facing
share link plus one of:

- `gdown --folder <url>` (works for public anyone-with-link Drives)
- `rclone copy gdrive:...` (works if the operator has a configured
  rclone remote against their own Drive account)
- manual list of pre-shared direct URLs

The adapter is built shape-agnostic and smoke-tested against synthetic
records of each shape. When the real data lands, the steps are:

1. Run `fetch_andreas_data.py` and read the manifest. If the
   `sft_candidate_count` is zero, the data is not in any shape we
   recognize and we need to handle it manually before retrying.
2. Run `normalize_to_sft_format` on the unpacked tree and check the
   `written / skipped` counts. Skip rate over 10% is a smell.
3. Run the full `data_prep.py` invocation with `--andreas-data` and
   eyeball the `by_source` counts in `v1.stats.json`.
4. Spot-check 5 random records in `data/sft/v1.jsonl` to confirm the
   messages list is well-formed and the assistant content looks like
   a real audit verdict, not a stray prompt-completion mix-up.

If any of those steps fail, the bug is almost certainly in the shape
detection or in the assumption that all of Andreas's records use the
same shape. Edge cases will appear; the test suite has room to grow.
