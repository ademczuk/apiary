"""Detect the shape of Andreas's finetune data and normalize to SFT format.

The ``apiary_train.data_prep`` pipeline expects records of the form:

    {"messages": [{"role": "system", "content": "..."},
                  {"role": "user", "content": "..."},
                  {"role": "assistant", "content": "..."}],
     "meta": {...}}

Andreas's data could arrive in any of four shapes. The adapter samples
the first ``DETECT_SAMPLE`` records, decides which shape it is looking
at, and dispatches to the right normalizer.

Shapes:

    A - chat messages (Llama/Mistral style):
        {"messages": [{"role": "...", "content": "..."}, ...]}

    B - OpenAI completion:
        {"prompt": "...", "completion": "..."}

    C - generic input/output (also question/answer, instruction/response):
        {"input": "...", "output": "..."}

    D - HuggingFace dataset split files (train.json / validation.json /
        test.json living side by side). Each can be a JSON array or
        JSONL of any of A-C.

Anything else returns ``"unknown"`` and we refuse to write output.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterator, Literal

logger = logging.getLogger("apiary.andreas_adapter")

Shape = Literal["A", "B", "C", "D", "unknown"]

DETECT_SAMPLE = 100

C_INPUT_KEYS = ("input", "question", "instruction")
C_OUTPUT_KEYS = ("output", "answer", "response")

SYSTEM_PROMPT_DEFAULT = (
    "You are an npm supply-chain security auditor. Reply with a JSON "
    "verdict only, no surrounding text."
)


def _iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    """Yield dicts from a .jsonl/.ndjson file, skipping bad lines."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                yield rec


def _iter_json_array(path: Path) -> Iterator[dict[str, Any]]:
    """Yield dicts from a .json file holding a top-level array."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        logger.warning("could not parse %s: %s", path, exc)
        return
    if isinstance(data, list):
        for rec in data:
            if isinstance(rec, dict):
                yield rec
    elif isinstance(data, dict):
        yield data


def _iter_records(path: Path) -> Iterator[dict[str, Any]]:
    """Dispatch to the right line/array iterator based on extension."""
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        yield from _iter_jsonl(path)
    elif path.suffix.lower() == ".json":
        yield from _iter_json_array(path)


def _classify_record(rec: dict[str, Any]) -> Shape:
    """Best-effort single-record shape classification."""
    if "messages" in rec and isinstance(rec["messages"], list):
        msgs = rec["messages"]
        if msgs and isinstance(msgs[0], dict) and "role" in msgs[0]:
            return "A"
    if "prompt" in rec and "completion" in rec:
        return "B"
    has_input = any(k in rec for k in C_INPUT_KEYS)
    has_output = any(k in rec for k in C_OUTPUT_KEYS)
    if has_input and has_output:
        return "C"
    return "unknown"


def detect_shape(input_path: Path) -> Shape:
    """Sample up to ``DETECT_SAMPLE`` records and return the majority shape.

    For directories that look like HuggingFace splits (train.json,
    validation.json, test.json), returns ``"D"`` regardless of inner
    record shape (the merge function handles per-split detection).
    """
    input_path = Path(input_path)
    if input_path.is_dir():
        split_names = {p.stem.lower() for p in input_path.glob("*.json")}
        split_names.update(p.stem.lower() for p in input_path.glob("*.jsonl"))
        hf_markers = {"train", "validation", "val", "test", "dev"}
        if hf_markers & split_names and len(split_names & hf_markers) >= 2:
            return "D"
        json_files = list(input_path.glob("*.jsonl")) + list(input_path.glob("*.json"))
        if not json_files:
            return "unknown"
        input_path = json_files[0]
    if not input_path.exists():
        return "unknown"

    counts: dict[Shape, int] = {"A": 0, "B": 0, "C": 0, "unknown": 0}
    for idx, rec in enumerate(_iter_records(input_path)):
        if idx >= DETECT_SAMPLE:
            break
        counts[_classify_record(rec)] += 1
    if sum(counts.values()) == 0:
        return "unknown"
    best = max(counts.items(), key=lambda kv: kv[1])
    if best[1] == 0 or best[0] == "unknown":
        return "unknown"
    return best[0]


def _record_to_messages(rec: dict[str, Any], shape: Shape) -> list[dict[str, str]] | None:
    """Convert a single record of known shape to a messages list."""
    if shape == "A":
        msgs = rec.get("messages", [])
        if not isinstance(msgs, list):
            return None
        clean: list[dict[str, str]] = []
        for m in msgs:
            if not isinstance(m, dict):
                continue
            role = m.get("role")
            content = m.get("content")
            if isinstance(role, str) and isinstance(content, str):
                clean.append({"role": role, "content": content})
        return clean or None
    if shape == "B":
        prompt = rec.get("prompt")
        completion = rec.get("completion")
        if not isinstance(prompt, str) or not isinstance(completion, str):
            return None
        return [
            {"role": "system", "content": SYSTEM_PROMPT_DEFAULT},
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": completion},
        ]
    if shape == "C":
        user_text: str | None = None
        assistant_text: str | None = None
        for k in C_INPUT_KEYS:
            if isinstance(rec.get(k), str):
                user_text = rec[k]
                break
        for k in C_OUTPUT_KEYS:
            if isinstance(rec.get(k), str):
                assistant_text = rec[k]
                break
        if user_text is None or assistant_text is None:
            return None
        return [
            {"role": "system", "content": SYSTEM_PROMPT_DEFAULT},
            {"role": "user", "content": user_text},
            {"role": "assistant", "content": assistant_text},
        ]
    return None


def _normalize_shape_A(input_path: Path, output_path: Path) -> tuple[int, int]:
    written = 0
    skipped = 0
    with output_path.open("w", encoding="utf-8") as out:
        for rec in _iter_records(input_path):
            messages = _record_to_messages(rec, "A")
            if not messages:
                skipped += 1
                continue
            out.write(
                json.dumps(
                    {"messages": messages, "meta": {"source": "andreas", "shape": "A"}},
                    ensure_ascii=False,
                )
                + "\n"
            )
            written += 1
    return written, skipped


def _normalize_shape_B(input_path: Path, output_path: Path) -> tuple[int, int]:
    written = 0
    skipped = 0
    with output_path.open("w", encoding="utf-8") as out:
        for rec in _iter_records(input_path):
            messages = _record_to_messages(rec, "B")
            if not messages:
                skipped += 1
                continue
            out.write(
                json.dumps(
                    {"messages": messages, "meta": {"source": "andreas", "shape": "B"}},
                    ensure_ascii=False,
                )
                + "\n"
            )
            written += 1
    return written, skipped


def _normalize_shape_C(input_path: Path, output_path: Path) -> tuple[int, int]:
    written = 0
    skipped = 0
    with output_path.open("w", encoding="utf-8") as out:
        for rec in _iter_records(input_path):
            messages = _record_to_messages(rec, "C")
            if not messages:
                skipped += 1
                continue
            out.write(
                json.dumps(
                    {"messages": messages, "meta": {"source": "andreas", "shape": "C"}},
                    ensure_ascii=False,
                )
                + "\n"
            )
            written += 1
    return written, skipped


def _normalize_shape_D(input_dir: Path, output_path: Path) -> tuple[int, int]:
    """Merge HF splits, preserving the split label per record."""
    split_files: dict[str, Path] = {}
    for path in list(input_dir.glob("*.json")) + list(input_dir.glob("*.jsonl")):
        stem = path.stem.lower()
        if stem in {"train", "validation", "val", "dev", "test"}:
            split_files[stem] = path
    written = 0
    skipped = 0
    with output_path.open("w", encoding="utf-8") as out:
        for split_name, path in sorted(split_files.items()):
            inner_shape = detect_shape(path)
            if inner_shape == "unknown" or inner_shape == "D":
                logger.warning("split %s has unrecognized inner shape; skipping", path)
                skipped += sum(1 for _ in _iter_records(path))
                continue
            for rec in _iter_records(path):
                messages = _record_to_messages(rec, inner_shape)
                if not messages:
                    skipped += 1
                    continue
                out.write(
                    json.dumps(
                        {
                            "messages": messages,
                            "meta": {
                                "source": "andreas",
                                "shape": "D",
                                "inner_shape": inner_shape,
                                "split": split_name,
                            },
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                written += 1
    return written, skipped


def normalize_to_sft_format(input_path: Path, output_path: Path) -> tuple[int, int]:
    """Detect shape and write a normalized JSONL.

    Returns ``(examples_written, examples_skipped)``.
    Raises ``ValueError`` if shape cannot be detected.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    shape = detect_shape(input_path)
    logger.info("detected shape %s for %s", shape, input_path)
    if shape == "unknown":
        raise ValueError(
            f"could not detect SFT shape for {input_path}. "
            "Expected messages/prompt+completion/input+output keys."
        )
    if shape == "D":
        return _normalize_shape_D(input_path, output_path)
    normalizers = {
        "A": _normalize_shape_A,
        "B": _normalize_shape_B,
        "C": _normalize_shape_C,
    }
    return normalizers[shape](input_path, output_path)


def merge_with_apiary_synthetic(
    andreas_path: Path,
    apiary_synth_path: Path,
    output_path: Path,
    shuffle_seed: int = 42,
) -> dict[str, int]:
    """Interleave Andreas's normalized data with apiary synthetic SFT lines.

    Both inputs are expected to be JSONL files of ``{"messages": [...], ...}``
    records. Output preserves a balanced interleave (deterministic via the
    seed) so neither source dominates contiguous training batches.
    """
    import random

    andreas_lines = (
        Path(andreas_path).read_text(encoding="utf-8", errors="replace").splitlines()
        if Path(andreas_path).exists()
        else []
    )
    synth_lines = (
        Path(apiary_synth_path).read_text(encoding="utf-8", errors="replace").splitlines()
        if Path(apiary_synth_path).exists()
        else []
    )
    andreas_lines = [ln for ln in andreas_lines if ln.strip()]
    synth_lines = [ln for ln in synth_lines if ln.strip()]
    rng = random.Random(shuffle_seed)
    combined = andreas_lines + synth_lines
    rng.shuffle(combined)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(combined) + ("\n" if combined else ""), encoding="utf-8")
    counts = {
        "andreas": len(andreas_lines),
        "apiary_synthetic": len(synth_lines),
        "total": len(combined),
    }
    logger.info("merged: %s -> %s", counts, output_path)
    return counts
