"""Smoke test for figshare ground-truth label loading.

Verifies that ``_load_ground_truth`` finds the NPMStudy reports under
``data/raw/figshare/63179326_unpacked`` and produces a non-degenerate
label distribution. If this passes, training will see a real mix of
positive and negative examples instead of an all-zero target column.

Run with ``python -m pytest tests/test_preprocess_labels.py -v``.
"""

from __future__ import annotations

import logging
import sys
from collections import Counter
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.preprocess import (  # noqa: E402
    _find_npmstudy_root,
    _load_ground_truth,
    _resolve_pkg_name_version,
)

EXTRACT_DIR = REPO_ROOT / "data" / "raw" / "figshare" / "63179326_unpacked"
MIN_TOTAL_LABELS = 500
MIN_PER_CLASS = 50

logger = logging.getLogger("apiary.tests.labels")


@pytest.fixture(scope="module")
def label_index() -> dict[str, dict[str, int]]:
    """Parse the figshare ground truth once for the whole module."""
    if not EXTRACT_DIR.is_dir():
        pytest.skip(f"figshare archive not unpacked at {EXTRACT_DIR}")
    return _load_ground_truth(EXTRACT_DIR)


def test_npmstudy_root_discoverable() -> None:
    if not EXTRACT_DIR.is_dir():
        pytest.skip("figshare archive not unpacked")
    root = _find_npmstudy_root(EXTRACT_DIR)
    assert root is not None, "could not locate NPMStudy/ in extract dir"
    assert (root / "Data" / "cleaning").is_dir()


def test_label_index_is_substantial(
    label_index: dict[str, dict[str, int]],
) -> None:
    total = sum(len(v) for v in label_index.values())
    assert total >= MIN_TOTAL_LABELS, (
        f"only {total} labels parsed; expected >= {MIN_TOTAL_LABELS}. "
        "Ground-truth wiring is probably broken."
    )
    logger.info("parsed %d labels across %d package names", total, len(label_index))


def test_label_distribution_has_both_classes(
    label_index: dict[str, dict[str, int]],
) -> None:
    counts: Counter[int] = Counter()
    for versions in label_index.values():
        for label in versions.values():
            counts[label] += 1
    benign = counts.get(0, 0)
    malicious = counts.get(1, 0)
    logger.info("class counts -> benign=%d malicious=%d", benign, malicious)
    assert benign >= MIN_PER_CLASS, f"only {benign} benign labels; got mostly malicious"
    assert malicious >= MIN_PER_CLASS, (
        f"only {malicious} malicious labels; constant classifier risk"
    )


def test_classifies_packages_in_archive(
    label_index: dict[str, dict[str, int]],
) -> None:
    """At least a few real package dirs should resolve to a known label."""
    npmstudy = _find_npmstudy_root(EXTRACT_DIR)
    assert npmstudy is not None

    classified: Counter[int] = Counter()
    seen = 0
    for pkg_json in npmstudy.rglob("package.json"):
        if "node_modules" in pkg_json.parts or "__MACOSX" in pkg_json.parts:
            continue
        pkg_dir = pkg_json.parent
        name, version = _resolve_pkg_name_version(pkg_dir)
        versions = label_index.get(name)
        if versions and version in versions:
            classified[versions[version]] += 1
        seen += 1
        if seen >= 200:
            break

    logger.info("of %d archive packages: classified=%s", seen, dict(classified))
    assert sum(classified.values()) >= 50, (
        f"only {sum(classified.values())} of {seen} archive packages matched the "
        "ground-truth index; lookup keys are probably misaligned"
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    idx = _load_ground_truth(EXTRACT_DIR)
    total = sum(len(v) for v in idx.values())
    counts: Counter[int] = Counter()
    for versions in idx.values():
        for label in versions.values():
            counts[label] += 1
    print(f"total labels: {total}")
    print(f"benign: {counts.get(0, 0)}  malicious: {counts.get(1, 0)}")
