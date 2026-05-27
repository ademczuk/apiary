"""Tests for the source-match rule.

Two kinds of tests:

* Unit tests for the URL parser + ratio math (always run).
* A live smoke test against lodash@4.17.21 (skipped unless
  ``APIARY_LIVE_TESTS=1`` is set in the env).
"""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
from pathlib import Path

import pytest

from apiary_policy.source_match import (
    DEFAULT_MATCH_THRESHOLD,
    MatchReport,
    compare_trees,
    parse_repository_url,
    verify_source_match,
)


# ---------- URL parser ------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected_host,expected_owner,expected_repo",
    [
        ("git+https://github.com/lodash/lodash.git", "github", "lodash", "lodash"),
        ("https://github.com/lodash/lodash", "github", "lodash", "lodash"),
        ("git@github.com:lodash/lodash.git", "github", "lodash", "lodash"),
        ("git+https://gitlab.com/owner/repo.git", "gitlab", "owner", "repo"),
        ("https://gitlab.com/owner/repo", "gitlab", "owner", "repo"),
    ],
)
def test_parse_repository_url_recognises_common_forms(
    url: str, expected_host: str, expected_owner: str, expected_repo: str
) -> None:
    ref = parse_repository_url(url)
    assert ref is not None
    assert ref.host == expected_host
    assert ref.owner == expected_owner
    assert ref.repo == expected_repo


def test_parse_repository_url_returns_none_for_unsupported() -> None:
    assert parse_repository_url("") is None
    assert parse_repository_url("not a url") is None
    assert parse_repository_url("https://example.com/foo/bar") is None


def test_archive_url_for_sha_github() -> None:
    ref = parse_repository_url("https://github.com/lodash/lodash")
    assert ref is not None
    url = ref.archive_url_for_sha.format(sha="abc1234")
    assert url == "https://github.com/lodash/lodash/archive/abc1234.tar.gz"


# ---------- compare_trees ratio math ---------------------------------------


def _write_file(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_compare_trees_full_match(tmp_path: Path) -> None:
    npm = tmp_path / "npm"
    src = tmp_path / "src"
    _write_file(npm / "index.js", b"module.exports = 1;\n")
    _write_file(npm / "lib" / "util.js", b"export const x = 1;\n")
    _write_file(src / "index.js", b"module.exports = 1;\n")
    _write_file(src / "lib" / "util.js", b"export const x = 1;\n")

    report = compare_trees(npm, src)
    assert report.compared == 2
    assert report.matched == 2
    assert report.ratio == 1.0
    assert report.suspicious == []


def test_compare_trees_partial_match(tmp_path: Path) -> None:
    npm = tmp_path / "npm"
    src = tmp_path / "src"
    _write_file(npm / "a.js", b"identical\n")
    _write_file(npm / "b.js", b"npm-version\n")
    _write_file(src / "a.js", b"identical\n")
    _write_file(src / "b.js", b"source-version\n")

    report = compare_trees(npm, src)
    assert report.compared == 2
    assert report.matched == 1
    assert report.ratio == 0.5
    assert "b.js" in report.suspicious


def test_compare_trees_ignores_build_output_when_no_source_counterpart(
    tmp_path: Path,
) -> None:
    npm = tmp_path / "npm"
    src = tmp_path / "src"
    _write_file(npm / "index.js", b"src\n")
    _write_file(npm / "dist" / "bundle.js", b"minified\n")
    _write_file(src / "index.js", b"src\n")

    report = compare_trees(npm, src)
    # dist/bundle.js was silently skipped because no source counterpart.
    assert report.compared == 1
    assert report.matched == 1


def test_compare_trees_ts_to_js_stem_fallback(tmp_path: Path) -> None:
    npm = tmp_path / "npm"
    src = tmp_path / "src"
    payload = b"compiled output\n"
    _write_file(npm / "lib" / "thing.js", payload)
    # source ships .ts; compiled .js exists at top level via stem match.
    _write_file(src / "src" / "thing.js", payload)
    _write_file(src / "src" / "thing.ts", b"export const Thing = 1;\n")

    report = compare_trees(npm, src)
    # stem fallback should find the matching SHA.
    assert report.compared == 1
    assert report.matched == 1


def test_match_report_ratio_zero_safe() -> None:
    rpt = MatchReport(compared=0, matched=0, suspicious=[])
    assert rpt.ratio == 1.0


# ---------- verify_source_match end-to-end (synthetic) ---------------------


def _make_npm_tarball(files: dict[str, bytes]) -> bytes:
    """Build an npm-style tarball with content nested under ``package/``."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, payload in files.items():
            info = tarfile.TarInfo(name=f"package/{name}")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _make_source_archive(repo_subdir: str, files: dict[str, bytes]) -> bytes:
    """Build a GitHub-style archive nested under ``{repo}-{sha}/``."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, payload in files.items():
            info = tarfile.TarInfo(name=f"{repo_subdir}/{name}")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def test_verify_source_match_with_local_source_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end check: pre-seed the cache, run verify_source_match."""
    cache_dir = tmp_path / "source-cache"
    cache_dir.mkdir()

    # Files in the npm tarball, all identical in source.
    files = {
        "index.js": b"module.exports = function() { return 1; };\n",
        "lib/util.js": b"export const x = 42;\n",
        "lib/helper.js": b"export function help() { return 'ok'; }\n",
    }
    npm_tarball = _make_npm_tarball(files)

    sha = "a" * 40
    repo_subdir = f"lodash-{sha}"
    src_archive = _make_source_archive(repo_subdir, files)

    # Pre-seed the cache so fetch_source_archive returns immediately.
    cache_path = cache_dir / "github" / "lodash" / "lodash" / f"{sha}.tar.gz"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(src_archive)

    metadata = {
        "name": "lodash",
        "versions": {
            "4.17.21": {
                "repository": {"url": "git+https://github.com/lodash/lodash.git"},
                "gitHead": sha,
            }
        },
    }

    result = verify_source_match(
        npm_tarball_bytes=npm_tarball,
        metadata=metadata,
        version="4.17.21",
        cache_dir=cache_dir,
        threshold=DEFAULT_MATCH_THRESHOLD,
    )
    assert result is not None
    passed, reason = result
    assert passed is True, f"expected PASS, got {reason}"
    assert "100% of files match" in reason


def test_verify_source_match_returns_none_when_no_pointers(tmp_path: Path) -> None:
    metadata = {"name": "x", "versions": {"1.0.0": {}}}
    result = verify_source_match(
        npm_tarball_bytes=b"junk",
        metadata=metadata,
        version="1.0.0",
        cache_dir=tmp_path,
    )
    assert result is None


# ---------- live smoke test (opt-in only) ----------------------------------


@pytest.mark.skipif(
    os.environ.get("APIARY_LIVE_TESTS") != "1",
    reason="set APIARY_LIVE_TESTS=1 to enable live network test",
)
def test_lodash_source_match_live(tmp_path: Path) -> None:
    """Download lodash@4.17.21 and verify source-match against upstream."""
    import httpx

    pkg_url = (
        "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    )
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        resp = client.get(pkg_url)
    resp.raise_for_status()
    npm_bytes = resp.content

    # Look up the real gitHead from the npm metadata.
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        meta_resp = client.get("https://registry.npmjs.org/lodash")
    meta_resp.raise_for_status()
    metadata = meta_resp.json()

    result = verify_source_match(
        npm_tarball_bytes=npm_bytes,
        metadata=metadata,
        version="4.17.21",
        cache_dir=tmp_path,
    )
    # Result may be None if upstream gitHead points at a tag that GitHub
    # cannot serve as a tarball; that's an interesting outcome but not a
    # test failure.
    if result is None:
        pytest.skip("verify_source_match returned None (upstream unreachable)")
    passed, reason = result
    print(f"LODASH SMOKE RESULT: passed={passed} reason={reason}")
    # Lodash should match its upstream at the published gitHead.
    assert passed, reason
