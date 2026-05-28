"""Smoke tests for the Andreas finetune-data adapter.

We verify that each of the four documented shapes is detected and
normalized into the chat-messages target format that
``apiary_train.data_prep`` consumes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from apiary_train.andreas_data_adapter import (
    detect_shape,
    merge_with_apiary_synthetic,
    normalize_to_sft_format,
)


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n",
        encoding="utf-8",
    )


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_shape_A_messages_pass_through(tmp_path: Path) -> None:
    src = tmp_path / "andreas_a.jsonl"
    records = [
        {
            "messages": [
                {"role": "system", "content": "audit npm"},
                {"role": "user", "content": "package foo@1.0.0"},
                {"role": "assistant", "content": '{"verdict": "clean"}'},
            ]
        },
        {
            "messages": [
                {"role": "user", "content": "package bar@2.0.0"},
                {"role": "assistant", "content": '{"verdict": "malicious"}'},
            ]
        },
    ]
    _write_jsonl(src, records)
    assert detect_shape(src) == "A"

    out = tmp_path / "out_a.jsonl"
    written, skipped = normalize_to_sft_format(src, out)
    assert written == 2
    assert skipped == 0
    result = _read_jsonl(out)
    assert result[0]["messages"][0]["role"] == "system"
    assert result[0]["messages"][-1]["content"] == '{"verdict": "clean"}'
    assert result[0]["meta"]["shape"] == "A"


def test_shape_B_prompt_completion_to_messages(tmp_path: Path) -> None:
    src = tmp_path / "andreas_b.jsonl"
    records = [
        {"prompt": "is foo safe?", "completion": '{"verdict": "clean"}'},
        {"prompt": "is bar safe?", "completion": '{"verdict": "malicious"}'},
        {"prompt": "is baz safe?", "completion": '{"verdict": "suspicious"}'},
    ]
    _write_jsonl(src, records)
    assert detect_shape(src) == "B"

    out = tmp_path / "out_b.jsonl"
    written, skipped = normalize_to_sft_format(src, out)
    assert written == 3
    assert skipped == 0
    result = _read_jsonl(out)
    first = result[0]
    assert first["messages"][0]["role"] == "system"
    assert first["messages"][1]["role"] == "user"
    assert first["messages"][1]["content"] == "is foo safe?"
    assert first["messages"][2]["role"] == "assistant"
    assert first["messages"][2]["content"] == '{"verdict": "clean"}'
    assert first["meta"]["shape"] == "B"


def test_shape_C_input_output_detected(tmp_path: Path) -> None:
    src = tmp_path / "andreas_c.jsonl"
    records = [
        {"input": "audit foo", "output": '{"verdict": "clean"}'},
        {"question": "audit bar", "answer": '{"verdict": "malicious"}'},
        {"instruction": "audit baz", "response": '{"verdict": "suspicious"}'},
    ]
    _write_jsonl(src, records)
    assert detect_shape(src) == "C"

    out = tmp_path / "out_c.jsonl"
    written, skipped = normalize_to_sft_format(src, out)
    assert written == 3
    assert skipped == 0
    result = _read_jsonl(out)
    assert result[0]["messages"][1]["content"] == "audit foo"
    assert result[1]["messages"][1]["content"] == "audit bar"
    assert result[2]["messages"][1]["content"] == "audit baz"
    for rec in result:
        assert rec["meta"]["shape"] == "C"


def test_shape_D_hf_splits_merged_with_split_label(tmp_path: Path) -> None:
    splits_dir = tmp_path / "hf_dataset"
    splits_dir.mkdir()
    _write_jsonl(
        splits_dir / "train.jsonl",
        [{"prompt": "p1", "completion": "c1"}, {"prompt": "p2", "completion": "c2"}],
    )
    _write_jsonl(
        splits_dir / "validation.jsonl",
        [{"prompt": "vp1", "completion": "vc1"}],
    )
    _write_jsonl(
        splits_dir / "test.jsonl",
        [{"prompt": "tp1", "completion": "tc1"}],
    )
    assert detect_shape(splits_dir) == "D"

    out = tmp_path / "out_d.jsonl"
    written, skipped = normalize_to_sft_format(splits_dir, out)
    assert written == 4
    assert skipped == 0
    result = _read_jsonl(out)
    splits = {r["meta"]["split"] for r in result}
    assert splits == {"train", "validation", "test"}
    for rec in result:
        assert rec["meta"]["shape"] == "D"
        assert rec["meta"]["inner_shape"] == "B"


def test_unknown_shape_raises_clean_error(tmp_path: Path) -> None:
    src = tmp_path / "weird.jsonl"
    _write_jsonl(
        src,
        [
            {"foo": "bar", "baz": 1},
            {"hello": "world"},
        ],
    )
    assert detect_shape(src) == "unknown"
    out = tmp_path / "out_unknown.jsonl"
    with pytest.raises(ValueError, match="could not detect SFT shape"):
        normalize_to_sft_format(src, out)
    assert not out.exists() or out.stat().st_size == 0


def test_merge_with_apiary_synthetic_interleaves(tmp_path: Path) -> None:
    andreas = tmp_path / "andreas.jsonl"
    synth = tmp_path / "synth.jsonl"
    _write_jsonl(
        andreas,
        [
            {
                "messages": [{"role": "user", "content": f"a{i}"}],
                "meta": {"source": "andreas"},
            }
            for i in range(3)
        ],
    )
    _write_jsonl(
        synth,
        [
            {
                "messages": [{"role": "user", "content": f"s{i}"}],
                "meta": {"source": "synth"},
            }
            for i in range(5)
        ],
    )
    out = tmp_path / "merged.jsonl"
    counts = merge_with_apiary_synthetic(andreas, synth, out, shuffle_seed=7)
    assert counts == {"andreas": 3, "apiary_synthetic": 5, "total": 8}
    lines = _read_jsonl(out)
    assert len(lines) == 8
    sources = [ln["meta"]["source"] for ln in lines]
    assert sources.count("andreas") == 3
    assert sources.count("synth") == 5


def test_data_prep_andreas_data_flag(tmp_path: Path) -> None:
    """End-to-end: --andreas-data flag writes records into the output."""
    from apiary_train.data_prep import main as data_prep_main

    src = tmp_path / "andreas.jsonl"
    _write_jsonl(
        src,
        [
            {"prompt": f"audit pkg-{i}", "completion": '{"verdict": "clean"}'}
            for i in range(20)
        ],
    )
    out = tmp_path / "sft.jsonl"
    rc = data_prep_main(
        [
            "--andreas-data",
            str(src),
            "--output",
            str(out),
            "--seed",
            "1",
            "--split-test-frac",
            "0.1",
        ]
    )
    assert rc == 0
    train_lines = _read_jsonl(out)
    test_path = out.with_suffix(".test.jsonl")
    test_lines = _read_jsonl(test_path) if test_path.exists() else []
    assert len(train_lines) + len(test_lines) == 20
    assert all(rec["meta"]["shape"] == "B" for rec in train_lines)
