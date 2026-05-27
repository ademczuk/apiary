"""Source-match verifier: compare an npm tarball against its upstream git tree.

Given a package's metadata containing ``repository.url`` and ``gitHead``, this
module downloads the matching source archive (GitHub or GitLab) and compares
file-by-file against the published npm tarball.

Algorithm summary:

1. Parse ``repository.url`` into ``(host, owner, repo)``.
2. Fetch ``https://github.com/{owner}/{repo}/archive/{sha}.tar.gz`` (or the
   GitLab equivalent). Cache the archive under ``data/source-cache/...``.
3. Extract both the npm tarball and the source archive into temp dirs using
   the path-traversal-safe extractor.
4. For each comparable file in the npm package, look for the same relative
   path in the source archive and compare SHA256 digests. If the exact path
   is not present, fall back to matching by file stem (handles compiled
   ``.js`` shipped alongside ``.ts`` source).
5. Compute match ratio over the set of comparable files. PASSED if >= 0.95,
   FAILED if < 0.95, SKIPPED (None) if the inputs were missing or unreachable.

Edge cases:

- ``.npmignore`` legitimately causes divergence (built ``dist/`` files,
  removed test fixtures, generated declarations). We do NOT attempt to honour
  ``.npmignore`` here; instead we ignore files that look like build output
  (``dist/`` ``build/`` ``lib/`` when no source counterpart exists) so they do
  not penalise the ratio.
- TypeScript packages publish compiled ``.js`` even though only ``.ts`` is in
  the source. We match by filename stem when an exact-path lookup misses.
- GitHub rate-limit returns 403 / 429. We retry with exponential backoff up
  to ``DEFAULT_MAX_RETRIES`` attempts.
- Source archive downloads are cached so repeated audits of the same SHA do
  not re-download.

The public entry point is ``check_source_match(metadata, version) -> Optional[Tuple[bool, str]]``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import httpx
except ImportError:  # pragma: no cover - httpx is a hard dep in pyproject
    httpx = None  # type: ignore[assignment]

logger = logging.getLogger("apiary.policy.source_match")

DEFAULT_CACHE_DIR = Path("data/source-cache")
DEFAULT_MATCH_THRESHOLD = 0.95
DEFAULT_MAX_RETRIES = 5
DEFAULT_HTTP_TIMEOUT = 30.0
DEFAULT_BACKOFF_BASE = 1.5

# File extensions we compare. Other extensions (binaries, lockfiles, images)
# are skipped because npm publishes minified or transformed copies that do
# not match the source byte-for-byte.
COMPARABLE_SUFFIXES: frozenset[str] = frozenset(
    {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".md"}
)

# Path prefixes inside the npm package that are typically build output. If no
# counterpart exists in the source archive we silently skip these instead of
# counting them as a miss.
BUILD_OUTPUT_PREFIXES: tuple[str, ...] = (
    "dist/",
    "build/",
    "lib/",
    "out/",
    "es/",
    "esm/",
    "umd/",
)

# Files we always skip (generated, metadata, or noise).
SKIP_FILENAMES: frozenset[str] = frozenset(
    {"package.json", "LICENSE", "README.md", "CHANGELOG.md", ".npmignore"}
)


# ---------------------------------------------------------------------------
# Repository URL parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RepoRef:
    """Parsed repository pointer."""

    host: str  # "github" | "gitlab"
    owner: str
    repo: str

    @property
    def archive_url_for_sha(self) -> str:
        """Return the upstream tarball URL for a given commit SHA."""
        if self.host == "github":
            return f"https://github.com/{self.owner}/{self.repo}/archive/{{sha}}.tar.gz"
        if self.host == "gitlab":
            return (
                f"https://gitlab.com/{self.owner}/{self.repo}/-/archive/"
                f"{{sha}}/{self.repo}-{{sha}}.tar.gz"
            )
        raise ValueError(f"unsupported host: {self.host}")


_GITHUB_PATTERNS = (
    re.compile(r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+?)(?:\.git)?/?$", re.I),
)
_GITLAB_PATTERNS = (
    re.compile(r"gitlab\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+?)(?:\.git)?/?$", re.I),
)


def parse_repository_url(raw_url: str) -> Optional[RepoRef]:
    """Normalise a package.json ``repository.url`` into a ``RepoRef``.

    Accepts the common npm forms: ``git+https://github.com/o/r.git``,
    ``https://github.com/o/r``, ``git@github.com:o/r.git``, ``git://...``.
    Returns ``None`` for anything we cannot map.
    """
    if not raw_url or not isinstance(raw_url, str):
        return None
    # Strip the leading ``git+`` qualifier npm loves to attach.
    url = raw_url.strip()
    if url.lower().startswith("git+"):
        url = url[4:]
    # Drop common suffixes / fragments.
    url = url.split("#", 1)[0]

    for pattern in _GITHUB_PATTERNS:
        match = pattern.search(url)
        if match:
            return RepoRef(host="github", owner=match["owner"], repo=match["repo"])
    for pattern in _GITLAB_PATTERNS:
        match = pattern.search(url)
        if match:
            return RepoRef(host="gitlab", owner=match["owner"], repo=match["repo"])
    return None


# ---------------------------------------------------------------------------
# Source archive download + cache
# ---------------------------------------------------------------------------


def _cache_path_for(ref: RepoRef, sha: str, cache_dir: Path) -> Path:
    return cache_dir / ref.host / ref.owner / ref.repo / f"{sha}.tar.gz"


def fetch_source_archive(
    ref: RepoRef,
    sha: str,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    max_retries: int = DEFAULT_MAX_RETRIES,
    timeout: float = DEFAULT_HTTP_TIMEOUT,
) -> Optional[Path]:
    """Download (or return cached) source archive for ``ref@sha``.

    Returns the local path on success, or ``None`` if the upstream is
    unreachable after all retries.
    """
    if httpx is None:
        logger.warning("httpx not available; cannot fetch source archive")
        return None

    cache_path = _cache_path_for(ref, sha, cache_dir)
    if cache_path.exists() and cache_path.stat().st_size > 0:
        return cache_path

    url = ref.archive_url_for_sha.format(sha=sha)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = cache_path.with_suffix(cache_path.suffix + ".tmp")

    last_error: str | None = None
    for attempt in range(max_retries):
        try:
            with httpx.Client(
                timeout=httpx.Timeout(timeout, connect=10.0),
                follow_redirects=True,
                headers={"User-Agent": "apiary-source-match/0.1"},
            ) as client:
                with client.stream("GET", url) as resp:
                    if resp.status_code == 404:
                        logger.info("source archive 404: %s", url)
                        return None
                    if resp.status_code in (403, 429):
                        last_error = f"rate-limited ({resp.status_code})"
                        sleep_for = DEFAULT_BACKOFF_BASE ** attempt
                        logger.warning(
                            "rate-limited on %s, sleeping %.1fs", url, sleep_for
                        )
                        time.sleep(sleep_for)
                        continue
                    if resp.status_code >= 400:
                        last_error = f"http {resp.status_code}"
                        logger.warning("http %s on %s", resp.status_code, url)
                        return None
                    with tmp_path.open("wb") as fh:
                        for chunk in resp.iter_bytes():
                            fh.write(chunk)
                    tmp_path.replace(cache_path)
                    return cache_path
        except httpx.HTTPError as exc:
            last_error = str(exc)
            sleep_for = DEFAULT_BACKOFF_BASE ** attempt
            logger.warning("http error on %s: %s; retrying in %.1fs", url, exc, sleep_for)
            time.sleep(sleep_for)

    logger.warning(
        "exhausted retries fetching source archive %s: last=%s", url, last_error
    )
    try:
        if tmp_path.exists():
            tmp_path.unlink()
    except OSError:
        pass
    return None


# ---------------------------------------------------------------------------
# Safe extraction (kept local so this module has no internal-cross-dep)
# ---------------------------------------------------------------------------


def _safe_extract(archive_path: Path, into: Path) -> None:
    """Extract a tar.gz validating each member; rejects path traversal + links."""
    into.mkdir(parents=True, exist_ok=True)
    base = into.resolve()
    with tarfile.open(archive_path, mode="r:*") as tf:
        for member in tf.getmembers():
            name = member.name
            if name.startswith("/") or ".." in Path(name).parts or os.path.isabs(name):
                logger.warning("skipping unsafe member %s in %s", name, archive_path)
                continue
            if member.issym() or member.islnk():
                continue
            target = (into / name).resolve()
            try:
                target.relative_to(base)
            except ValueError:
                logger.warning("skipping out-of-tree member %s", name)
                continue
            try:
                tf.extract(member, into, filter="data")
            except TypeError:
                # Python < 3.12 has no ``filter`` kwarg.
                tf.extract(member, into)


def _find_npm_inner_dir(extracted: Path) -> Path:
    """npm tarballs nest content under ``package/``. Return that subdir."""
    candidate = extracted / "package"
    if candidate.is_dir():
        return candidate
    # Fall back to the only top-level directory if present.
    children = [c for c in extracted.iterdir() if c.is_dir()]
    if len(children) == 1:
        return children[0]
    return extracted


def _find_source_inner_dir(extracted: Path) -> Path:
    """GitHub archives nest under ``{repo}-{sha}/``. Return that subdir."""
    children = [c for c in extracted.iterdir() if c.is_dir()]
    if len(children) == 1:
        return children[0]
    return extracted


# ---------------------------------------------------------------------------
# File comparison
# ---------------------------------------------------------------------------


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_comparable(rel_path: Path) -> bool:
    if rel_path.name in SKIP_FILENAMES:
        return False
    return rel_path.suffix.lower() in COMPARABLE_SUFFIXES


def _looks_like_build_output(rel_path: Path) -> bool:
    posix = rel_path.as_posix()
    return any(posix.startswith(prefix) for prefix in BUILD_OUTPUT_PREFIXES)


def _index_source_tree(root: Path) -> tuple[dict[str, str], dict[str, list[Path]]]:
    """Walk the source tree once and build two indices.

    Returns ``(by_relpath, by_stem)``:
      * ``by_relpath`` maps the POSIX-style relative path to its SHA256
      * ``by_stem`` maps each file stem to all paths sharing that stem
    """
    by_relpath: dict[str, str] = {}
    by_stem: dict[str, list[Path]] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        digest = _sha256_of(path)
        by_relpath[rel.as_posix()] = digest
        by_stem.setdefault(rel.stem.lower(), []).append(path)
    return by_relpath, by_stem


@dataclass
class MatchReport:
    """Outcome of a tarball-vs-source comparison."""

    compared: int
    matched: int
    suspicious: list[str]

    @property
    def ratio(self) -> float:
        if self.compared == 0:
            return 1.0
        return self.matched / self.compared


def compare_trees(npm_inner: Path, source_inner: Path) -> MatchReport:
    """Compare the published package tree against the source tree."""
    src_by_relpath, src_by_stem = _index_source_tree(source_inner)

    compared = 0
    matched = 0
    suspicious: list[str] = []

    for path in npm_inner.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(npm_inner)
        except ValueError:
            continue
        if not _is_comparable(rel):
            continue

        rel_posix = rel.as_posix()
        npm_digest = _sha256_of(path)

        # Exact path match first
        src_digest = src_by_relpath.get(rel_posix)
        if src_digest is not None:
            compared += 1
            if src_digest == npm_digest:
                matched += 1
            else:
                suspicious.append(rel_posix)
            continue

        # Stem fallback (compiled .js vs .ts source)
        candidates = src_by_stem.get(rel.stem.lower(), [])
        candidate_digests = {_sha256_of(c) for c in candidates}
        if candidate_digests:
            compared += 1
            if npm_digest in candidate_digests:
                matched += 1
            else:
                # Stem found but bytes differ. Treat compiled output as a
                # legitimate divergence we cannot verify, NOT a suspicion.
                if _looks_like_build_output(rel):
                    compared -= 1  # withdraw the comparison
                else:
                    suspicious.append(rel_posix)
            continue

        # No path and no stem in source. Build output is silently skipped.
        if _looks_like_build_output(rel):
            continue
        # Otherwise count it as a miss.
        compared += 1
        suspicious.append(rel_posix)

    return MatchReport(compared=compared, matched=matched, suspicious=suspicious)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _extract_repo_and_sha(
    metadata: dict, version: str
) -> tuple[Optional[str], Optional[str]]:
    versions = metadata.get("versions") or {}
    block = versions.get(version) or {}
    repo = block.get("repository")
    git_head = block.get("gitHead")

    repo_url: Optional[str] = None
    if isinstance(repo, dict):
        raw = repo.get("url")
        if isinstance(raw, str):
            repo_url = raw
    elif isinstance(repo, str):
        repo_url = repo
    return repo_url, git_head if isinstance(git_head, str) else None


def verify_source_match(
    npm_tarball_bytes: bytes,
    metadata: dict,
    version: str,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    threshold: float = DEFAULT_MATCH_THRESHOLD,
) -> Optional[tuple[bool, str]]:
    """Verify the npm tarball matches its upstream source.

    Returns:
        ``(True, reason)`` when match ratio meets ``threshold``.
        ``(False, reason)`` when match ratio falls below ``threshold``.
        ``None`` when the inputs were missing or the upstream was unreachable.
    """
    if httpx is None:
        logger.warning("httpx missing; source-match skipped")
        return None

    repo_url, sha = _extract_repo_and_sha(metadata, version)
    if not repo_url:
        return None
    if not sha:
        return None

    ref = parse_repository_url(repo_url)
    if ref is None:
        logger.info("repository url unparseable: %s", repo_url)
        return None

    archive_path = fetch_source_archive(ref, sha, cache_dir=cache_dir)
    if archive_path is None:
        return None

    with tempfile.TemporaryDirectory(prefix="apiary-srcmatch-") as tmp:
        tmp_root = Path(tmp)
        npm_extracted = tmp_root / "npm"
        src_extracted = tmp_root / "src"
        npm_extracted.mkdir()
        src_extracted.mkdir()

        npm_tar = tmp_root / "package.tgz"
        npm_tar.write_bytes(npm_tarball_bytes)

        try:
            _safe_extract(npm_tar, npm_extracted)
        except tarfile.TarError as exc:
            logger.warning("npm tarball extract failed: %s", exc)
            return None
        try:
            _safe_extract(archive_path, src_extracted)
        except tarfile.TarError as exc:
            logger.warning("source archive extract failed: %s", exc)
            return None

        npm_inner = _find_npm_inner_dir(npm_extracted)
        src_inner = _find_source_inner_dir(src_extracted)

        report = compare_trees(npm_inner, src_inner)

    short_sha = sha[:7]
    pct = int(report.ratio * 100)
    if report.compared == 0:
        # Nothing comparable: treat as inconclusive.
        return None
    if report.ratio >= threshold:
        return (
            True,
            f"source-match: {pct}% of files match upstream repo at sha={short_sha} "
            f"({report.matched}/{report.compared})",
        )
    suspicious_count = len(report.suspicious)
    return (
        False,
        f"source-match: only {pct}% of files match (sha={short_sha}); "
        f"{suspicious_count} suspicious file(s) differ",
    )


def check_source_match(
    metadata: dict,
    version: str,
    tarball_bytes: Optional[bytes],
    cache_dir: Path = DEFAULT_CACHE_DIR,
    threshold: float = DEFAULT_MATCH_THRESHOLD,
) -> Optional[tuple[bool, str]]:
    """Rule-shaped wrapper for ``verify_source_match``.

    Returns the same tri-state as ``verify_source_match``. ``None`` means
    "could not verify"; the caller (decide_policy) treats that as a
    quarantine-worthy outcome.
    """
    if tarball_bytes is None:
        return None
    return verify_source_match(
        npm_tarball_bytes=tarball_bytes,
        metadata=metadata,
        version=version,
        cache_dir=cache_dir,
        threshold=threshold,
    )
