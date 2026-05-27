"""Score a single npm package and emit a JSON verdict.

Takes a package directory or .tgz tarball, preprocesses it identically to
training (package.json plus lifecycle scripts plus top-3 .js files by line
count), runs a model (CodeBERT LoRA dir OR LightGBM model file), and prints
JSON with score, decision, and an evidence list.

Usage:
    python scripts/score_package.py \
        --model models/codebert-lora-v1/ \
        --package /path/to/package_dir_or.tgz \
        --gate-config modulewarden_gate/thresholds.yaml

    python scripts/score_package.py \
        --no-model --package /path/to/pkg
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

import yaml

# Reuse preprocess helpers to keep training-time / inference-time identical.
from scripts.extract_features import extract_row
from scripts.preprocess import _record_for_package

logger = logging.getLogger("apiary.score")

DEFAULT_THRESHOLDS = (
    Path(__file__).resolve().parent.parent / "modulewarden_gate" / "thresholds.yaml"
)


def _setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def load_thresholds(path: Path = DEFAULT_THRESHOLDS) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def decide(score: float, thresholds: dict) -> str:
    """Map a [0, 1] score to allow / quarantine / block."""
    if score < thresholds["allow_below"]:
        return "allow"
    if score >= thresholds["block_at_or_above"]:
        return "block"
    return "quarantine"


def _safe_tar_extract(archive: Path, dest: Path) -> None:
    """Extract a tarball into ``dest`` rejecting any path-traversal members.

    Rejects absolute paths, ``..`` traversal segments, and symlink / hardlink
    members entirely. We never call ``tarfile.extractall`` because it does
    not validate member names before writing them. Members that resolve
    outside ``dest`` are logged and skipped.
    """
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, mode="r:*") as tf:
        for member in tf.getmembers():
            name = member.name
            if not name or name.startswith("/") or os.path.isabs(name):
                logger.warning("skipping absolute tarball member: %s", name)
                continue
            if ".." in Path(name).parts:
                logger.warning("skipping traversal tarball member: %s", name)
                continue
            if member.issym() or member.islnk():
                logger.warning("skipping link tarball member: %s", name)
                continue
            target = (dest / name).resolve()
            try:
                target.relative_to(dest)
            except ValueError:
                logger.warning("skipping out-of-tree tarball member: %s", name)
                continue
            tf.extract(member, dest)


def _safe_zip_extract(archive: Path, dest: Path) -> None:
    """Extract a zip into ``dest`` rejecting any path-traversal members."""
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, mode="r") as zf:
        for info in zf.infolist():
            name = info.filename
            if not name or name.startswith("/") or os.path.isabs(name):
                logger.warning("skipping absolute zip member: %s", name)
                continue
            if ".." in Path(name).parts:
                logger.warning("skipping traversal zip member: %s", name)
                continue
            target = (dest / name).resolve()
            try:
                target.relative_to(dest)
            except ValueError:
                logger.warning("skipping out-of-tree zip member: %s", name)
                continue
            zf.extract(info, dest)


def _ensure_package_dir(package: Path, work_dir: Path) -> Path:
    """Return a directory containing the npm package contents.

    Accepts a directory (returned as-is) or a .tgz / .zip tarball, which is
    unpacked into work_dir and the top-level package dir returned.
    """
    if package.is_dir():
        return package
    if not package.is_file():
        raise FileNotFoundError(f"package not found: {package}")

    target = work_dir / "extracted"
    target.mkdir(parents=True, exist_ok=True)
    suffix = "".join(package.suffixes).lower()

    if suffix.endswith(".tgz") or suffix.endswith(".tar.gz") or suffix == ".tar":
        _safe_tar_extract(package, target)
    elif suffix == ".zip":
        _safe_zip_extract(package, target)
    else:
        raise ValueError(f"unsupported archive format: {package}")

    # npm tarballs nest under a top-level `package/` directory
    nested = target / "package"
    if (nested / "package.json").exists():
        return nested
    # else: first child that contains package.json
    for child in target.iterdir():
        if (child / "package.json").exists():
            return child
    return target


def _build_record(pkg_dir: Path) -> dict:
    """Construct the same record shape preprocess.py emits."""
    rec = _record_for_package(pkg_dir, archive_path=Path("inference"))
    if rec is None:
        raise ValueError(f"could not read package.json in {pkg_dir}")
    rec.setdefault("label", 0)
    return rec


def _heuristic_score(features: dict) -> tuple[float, list[str]]:
    """Hand-coded scoring on the extract_features output."""
    score = 0.0
    evidence: list[str] = []

    weights = {
        "has_postinstall_script": 0.18,
        "has_preinstall_script": 0.18,
        "n_eval_calls": 0.04,
        "n_function_constructor": 0.05,
        "n_child_process_calls": 0.04,
        "n_fs_writes_to_dotfiles": 0.20,
        "n_obfuscated_identifiers": 0.02,
        "n_dynamic_require": 0.03,
        "has_binary_files": 0.10,
    }

    if features.get("has_postinstall_script"):
        score += weights["has_postinstall_script"]
        evidence.append("postinstall_script_present")
    if features.get("has_preinstall_script"):
        score += weights["has_preinstall_script"]
        evidence.append("preinstall_script_present")
    if features.get("has_binary_files"):
        score += weights["has_binary_files"]
        evidence.append("binary_files_in_package")

    n_dotfile = features.get("n_fs_writes_to_dotfiles", 0)
    if n_dotfile:
        score += min(weights["n_fs_writes_to_dotfiles"] * n_dotfile, 0.30)
        evidence.append(f"fs_writes_to_dotfiles_{n_dotfile}")

    n_eval = features.get("n_eval_calls", 0) + features.get("n_function_constructor", 0)
    if n_eval:
        score += min(0.05 * n_eval, 0.15)
        evidence.append(f"eval_or_function_constructor_{n_eval}")

    n_child = features.get("n_child_process_calls", 0)
    if n_child:
        score += min(weights["n_child_process_calls"] * n_child, 0.15)
        evidence.append(f"child_process_calls_{n_child}")

    entropy = features.get("entropy_install_script", 0.0) or 0.0
    if entropy >= 5.0:
        score += 0.15
        evidence.append(f"install_script_entropy_{entropy:.2f}")
    elif entropy >= 4.5:
        score += 0.08
        evidence.append(f"install_script_entropy_{entropy:.2f}")

    if features.get("n_obfuscated_identifiers", 0) >= 5:
        score += 0.10
        evidence.append(f"obfuscated_identifiers_{features['n_obfuscated_identifiers']}")

    n_b64 = features.get("n_base64_strings", 0)
    if n_b64 >= 3:
        score += 0.10
        evidence.append(f"base64_strings_{n_b64}")

    return min(score, 1.0), evidence


def _load_predictor(model_path: Path | None):
    """Return (predict_callable, label) or (None, 'heuristic') for --no-model."""
    if model_path is None:
        return None, "heuristic-v0"
    from scripts.eval import load_model

    return load_model(model_path)


def _evidence_from_features(features: dict) -> list[str]:
    """Surface notable feature signals as human-readable strings."""
    out: list[str] = []
    if features.get("has_postinstall_script"):
        out.append("postinstall_script_present")
    if features.get("has_preinstall_script"):
        out.append("preinstall_script_present")
    if features.get("has_binary_files"):
        out.append("binary_files_in_package")
    if features.get("n_fs_writes_to_dotfiles", 0):
        out.append(f"fs_writes_to_dotfiles_{features['n_fs_writes_to_dotfiles']}")
    if features.get("n_child_process_calls", 0):
        out.append(f"child_process_calls_{features['n_child_process_calls']}")
    if features.get("n_network_calls", 0):
        out.append(f"network_calls_{features['n_network_calls']}")
    entropy = features.get("entropy_install_script", 0.0) or 0.0
    if entropy >= 4.5:
        out.append(f"install_script_entropy_{entropy:.2f}")
    if features.get("n_obfuscated_identifiers", 0) >= 5:
        out.append(f"obfuscated_identifiers_{features['n_obfuscated_identifiers']}")
    return out


def score_package(
    package_path: Path,
    model_path: Path | None,
    thresholds: dict,
) -> dict:
    """Return a verdict dict for one package."""
    with tempfile.TemporaryDirectory(prefix="apiary-score-") as tmp:
        work_dir = Path(tmp)
        pkg_dir = _ensure_package_dir(package_path, work_dir)
        record = _build_record(pkg_dir)
        features = extract_row(record)

        predict_fn, model_label = _load_predictor(model_path)
        if predict_fn is None:
            score, primary_evidence = _heuristic_score(features)
            evidence = primary_evidence
        else:
            if model_label.startswith("lightgbm"):
                score = float(predict_fn([record])[0])
            else:
                score = float(predict_fn([record.get("text", "")])[0])
            evidence = _evidence_from_features(features)

    decision = decide(score, thresholds)

    return {
        "package": record.get("package_name"),
        "version": record.get("version"),
        "score": float(score),
        "decision": decision,
        "evidence": evidence,
        "model": model_label,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, default=None)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument(
        "--gate-config", type=Path, default=DEFAULT_THRESHOLDS, dest="gate_config"
    )
    parser.add_argument(
        "--no-model",
        action="store_true",
        help="ignore --model and run heuristics only",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    _setup_logging(args.verbose)
    thresholds = load_thresholds(args.gate_config)

    model_path = None if args.no_model else args.model
    if model_path and not model_path.exists():
        logger.error("model path does not exist: %s", model_path)
        return 1

    try:
        verdict = score_package(args.package, model_path, thresholds)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1
    except (ValueError, OSError) as exc:
        logger.error("scoring failed: %s", exc)
        return 1

    print(json.dumps(verdict))
    return 0


if __name__ == "__main__":
    sys.exit(main())
