"""LLM-driven audit backends for the Apiary proxy.

The audit prompt budgets the model's context window so the criteria rubric
gets about 25 percent of the available tokens and the package code gets the
remaining 75 percent. File selection prioritises package.json + lifecycle
scripts + the conventional entry points (index.js, files in lib/, files
named in the ``main`` field) and stops once the byte budget is exhausted.

Three backends ship in-tree:

* ``OpenAIBackend``  - openai SDK, env var ``OPENAI_API_KEY``.
* ``OllamaBackend``  - local Ollama daemon, default ``deepseek-coder:6.7b``.
* ``DwarfstarBackend`` - OpenAI-compatible /v1/chat/completions endpoint.

All backends parse the model output as a JSON object matching the schema in
``criteria/default-criteria.md``. Malformed JSON falls back to a
``suspicious`` verdict with the raw text in ``reasoning`` so the caller
never sees an exception.
"""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger("apiary.auditors")

Verdict = Literal["clean", "suspicious", "malicious"]

# 4 chars per token is the canonical OpenAI estimate; close enough for
# pre-allocation across model families.
CHARS_PER_TOKEN = 4

DEFAULT_CRITERIA_PATH = (
    Path(__file__).resolve().parent / "criteria" / "default-criteria.md"
)

LIFECYCLE_FILES = ("package.json",)
PRIORITISED_DIRS = ("", "lib", "src", "bin", "scripts")


@dataclass
class AuditPrompt:
    """A built prompt ready to send to a backend."""

    criteria: str
    code: str
    package_meta: dict[str, Any]

    def to_text(self) -> str:
        meta_blurb = (
            f"Package: {self.package_meta.get('name', '<unknown>')}\n"
            f"Version: {self.package_meta.get('version', '<unknown>')}\n"
        )
        return (
            f"{self.criteria}\n\n"
            f"---\n\n"
            f"{meta_blurb}\n"
            f"```\n{self.code}\n```\n"
        )


@dataclass
class AuditResult:
    verdict: Verdict
    confidence: float
    reasoning: str
    findings: list[str] = field(default_factory=list)
    raw: str = ""


# ----------------------------------------------------------------------------
# Prompt construction
# ----------------------------------------------------------------------------


def _read_text_safely(path: Path, limit: int = 200_000) -> str:
    try:
        data = path.read_bytes()[:limit]
    except OSError:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def _entry_point_files(package_dir: Path, package_json: dict[str, Any]) -> list[Path]:
    """Return candidate entry-point files from ``main`` / ``bin``."""
    out: list[Path] = []
    main = package_json.get("main")
    if isinstance(main, str):
        candidate = (package_dir / main).resolve()
        if candidate.exists() and candidate.is_file():
            out.append(candidate)

    bin_field = package_json.get("bin")
    if isinstance(bin_field, dict):
        for rel in bin_field.values():
            if isinstance(rel, str):
                candidate = (package_dir / rel).resolve()
                if candidate.exists() and candidate.is_file():
                    out.append(candidate)
    elif isinstance(bin_field, str):
        candidate = (package_dir / bin_field).resolve()
        if candidate.exists() and candidate.is_file():
            out.append(candidate)
    return out


def _enumerate_source_files(package_dir: Path) -> list[Path]:
    """List .js / .ts / .cjs / .mjs files under prioritised dirs."""
    suffixes = {".js", ".ts", ".cjs", ".mjs", ".jsx", ".tsx"}
    found: list[Path] = []
    for sub in PRIORITISED_DIRS:
        base = package_dir / sub if sub else package_dir
        if not base.exists() or not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix.lower() in suffixes:
                # exclude node_modules under the package dir
                if "node_modules" in path.parts:
                    continue
                found.append(path)
    return found


def build_audit_prompt(
    package_dir: Path,
    criteria_md: str | None = None,
    max_context_tokens: int = 8192,
    criteria_share: float = 0.25,
) -> AuditPrompt:
    """Construct an ``AuditPrompt`` for ``package_dir``.

    Reserves ``criteria_share`` of the token budget for the rubric and uses
    the rest for source code. File ordering: package.json first, lifecycle
    script files, then entry-point files, then everything else by size
    ascending so we cover surface area before any single bloated file
    exhausts the budget.
    """
    package_dir = Path(package_dir)
    pj_path = package_dir / "package.json"
    if not pj_path.exists():
        raise FileNotFoundError(f"package.json not in {package_dir}")

    if criteria_md is None:
        criteria_md = DEFAULT_CRITERIA_PATH.read_text(encoding="utf-8")

    try:
        package_json = json.loads(pj_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        package_json = {}

    total_budget_chars = max_context_tokens * CHARS_PER_TOKEN
    criteria_budget = int(total_budget_chars * criteria_share)
    code_budget = total_budget_chars - criteria_budget - len(criteria_md)
    code_budget = max(code_budget, 2000)

    chosen: list[tuple[Path, str]] = []
    used = 0

    # package.json always included
    pj_text = _read_text_safely(pj_path)
    chosen.append((pj_path, pj_text))
    used += len(pj_text)

    # lifecycle script files referenced from scripts.*
    scripts = package_json.get("scripts") or {}
    script_files: list[Path] = []
    if isinstance(scripts, dict):
        for cmd in scripts.values():
            if not isinstance(cmd, str):
                continue
            # naive extraction of any .js path the script invokes
            for token in re.findall(r"[\w./\\-]+\.(?:js|cjs|mjs)", cmd):
                candidate = (package_dir / token).resolve()
                if candidate.exists() and candidate.is_file():
                    script_files.append(candidate)

    entry_files = _entry_point_files(package_dir, package_json)
    other_files = _enumerate_source_files(package_dir)

    # de-dupe while preserving priority order
    seen: set[Path] = {pj_path.resolve()}
    ordered: list[Path] = []
    for bucket in (script_files, entry_files, other_files):
        for path in bucket:
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            ordered.append(resolved)

    for path in ordered:
        if used >= code_budget:
            break
        body = _read_text_safely(path, limit=code_budget - used)
        if not body:
            continue
        chosen.append((path, body))
        used += len(body)

    code_blob = "\n\n".join(
        f"// FILE: {p.relative_to(package_dir.resolve())}\n{body}"
        for p, body in chosen
        if p != pj_path  # package.json gets its own header
    )
    code_blob = (
        f"// FILE: package.json\n{pj_text}\n\n{code_blob}"
        if chosen
        else ""
    )

    return AuditPrompt(
        criteria=criteria_md,
        code=code_blob,
        package_meta={
            "name": package_json.get("name", package_dir.name),
            "version": package_json.get("version", ""),
            "files_included": [str(p.relative_to(package_dir.resolve())) for p, _ in chosen],
            "code_chars": used,
            "code_budget_chars": code_budget,
        },
    )


# ----------------------------------------------------------------------------
# Output parsing
# ----------------------------------------------------------------------------


_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def parse_audit_response(raw: str) -> AuditResult:
    """Coerce model output into an ``AuditResult``.

    Models occasionally wrap JSON in code fences or add a leading sentence.
    We extract the first balanced-looking JSON object and validate the
    required fields; anything else collapses to a ``suspicious`` verdict so
    the proxy errs on the safer side.
    """
    if not raw or not raw.strip():
        return AuditResult(
            verdict="suspicious",
            confidence=0.0,
            reasoning="empty model response",
            raw=raw,
        )

    candidate = raw.strip()
    # strip code fences if present
    if candidate.startswith("```"):
        candidate = re.sub(r"^```(?:json)?\s*", "", candidate)
        candidate = re.sub(r"\s*```$", "", candidate)

    match = _JSON_OBJECT_RE.search(candidate)
    if match is None:
        return AuditResult(
            verdict="suspicious",
            confidence=0.0,
            reasoning=f"could not find JSON object in response: {candidate[:200]!r}",
            raw=raw,
        )

    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        return AuditResult(
            verdict="suspicious",
            confidence=0.0,
            reasoning=f"json parse error: {exc}",
            raw=raw,
        )

    verdict_raw = str(payload.get("verdict", "suspicious")).lower().strip()
    if verdict_raw not in ("clean", "suspicious", "malicious"):
        verdict_raw = "suspicious"

    try:
        confidence = float(payload.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    findings = payload.get("findings") or []
    if not isinstance(findings, list):
        findings = [str(findings)]
    findings = [str(f) for f in findings]

    reasoning = str(payload.get("reasoning", "")).strip()

    return AuditResult(
        verdict=verdict_raw,  # type: ignore[arg-type]
        confidence=confidence,
        reasoning=reasoning,
        findings=findings,
        raw=raw,
    )


# ----------------------------------------------------------------------------
# Backends
# ----------------------------------------------------------------------------


class AuditBackend(ABC):
    name: str = "abstract"

    @abstractmethod
    def audit(self, prompt: AuditPrompt) -> AuditResult:
        """Send ``prompt`` to the backend and return a parsed result."""


class OpenAIBackend(AuditBackend):
    name = "openai"

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: str | None = None,
        temperature: float = 0.1,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.temperature = temperature

    def audit(self, prompt: AuditPrompt) -> AuditResult:
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "openai SDK not installed; pip install openai"
            ) from exc

        client = OpenAI(api_key=self.api_key) if self.api_key else OpenAI()
        completion = client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an npm supply-chain security auditor. "
                        "Reply with one JSON object matching the schema."
                    ),
                },
                {"role": "user", "content": prompt.to_text()},
            ],
            response_format={"type": "json_object"},
        )
        raw = completion.choices[0].message.content or ""
        return parse_audit_response(raw)


class OllamaBackend(AuditBackend):
    name = "ollama"

    def __init__(
        self,
        model: str = "deepseek-coder:6.7b",
        base_url: str = "http://localhost:11434",
        temperature: float = 0.1,
        timeout: float = 120.0,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout

    def audit(self, prompt: AuditPrompt) -> AuditResult:
        import httpx

        body = {
            "model": self.model,
            "prompt": prompt.to_text(),
            "stream": False,
            "format": "json",
            "options": {"temperature": self.temperature},
        }
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(f"{self.base_url}/api/generate", json=body)
            resp.raise_for_status()
            data = resp.json()
        raw = data.get("response", "")
        return parse_audit_response(raw)


class DwarfstarBackend(AuditBackend):
    """OpenAI-compatible /v1/chat/completions endpoint (Dwarfstar runtime)."""

    name = "dwarfstar"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        temperature: float = 0.1,
        timeout: float = 120.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self.timeout = timeout

    def audit(self, prompt: AuditPrompt) -> AuditResult:
        import httpx

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an npm supply-chain security auditor. "
                        "Reply with one JSON object matching the schema."
                    ),
                },
                {"role": "user", "content": prompt.to_text()},
            ],
        }
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/v1/chat/completions",
                headers=headers,
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()
        choices = data.get("choices") or []
        raw = ""
        if choices:
            message = choices[0].get("message") or {}
            raw = message.get("content", "") or ""
        return parse_audit_response(raw)


class ApiaryFineTunedBackend(AuditBackend):
    """Local inference against an apiary-trained model from apiary_train.

    Loads either a full HF model directory or a base model plus a LoRA
    adapter produced by ``apiary_train.sft_lora``. Heavy: pins the model
    in GPU/CPU memory for the lifetime of the process, so one instance
    per worker is the right pattern.
    """

    name = "apiary-finetuned"

    def __init__(
        self,
        model_path: str,
        base_model: str | None = None,
        max_new_tokens: int = 512,
        temperature: float = 0.1,
        dtype: str = "bfloat16",
        device_map: str = "auto",
    ) -> None:
        self.model_path = model_path
        self.base_model = base_model
        self.max_new_tokens = max_new_tokens
        self.temperature = temperature
        self.dtype = dtype
        self.device_map = device_map
        self._model: Any = None
        self._tokenizer: Any = None

    def _load(self) -> None:
        if self._model is not None:
            return
        try:
            import torch  # type: ignore
            from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "transformers + torch required for ApiaryFineTunedBackend"
            ) from exc

        dtype_map = {"bfloat16": torch.bfloat16, "float16": torch.float16, "float32": torch.float32}
        torch_dtype = dtype_map.get(self.dtype, torch.bfloat16)

        adapter_dir = Path(self.model_path)
        is_adapter = (adapter_dir / "adapter_config.json").exists()
        tokenizer_source = self.base_model if (is_adapter and self.base_model) else self.model_path
        self._tokenizer = AutoTokenizer.from_pretrained(tokenizer_source, trust_remote_code=True)
        if self._tokenizer.pad_token is None:
            self._tokenizer.pad_token = self._tokenizer.eos_token

        if is_adapter:
            if not self.base_model:
                raise ValueError("ApiaryFineTunedBackend(adapter) requires base_model")
            try:
                from peft import PeftModel  # type: ignore
            except ImportError as exc:
                raise RuntimeError("peft required to load an adapter") from exc
            base = AutoModelForCausalLM.from_pretrained(
                self.base_model,
                torch_dtype=torch_dtype,
                device_map=self.device_map,
                trust_remote_code=True,
            )
            self._model = PeftModel.from_pretrained(base, self.model_path)
        else:
            self._model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                torch_dtype=torch_dtype,
                device_map=self.device_map,
                trust_remote_code=True,
            )
        self._model.eval()
        logger.info("apiary-finetuned model loaded: %s", self.model_path)

    def audit(self, prompt: AuditPrompt) -> AuditResult:
        self._load()
        import torch  # type: ignore

        system = (
            "You are an npm supply-chain security auditor. Reply with one "
            "JSON object matching the schema."
        )
        text = f"{system}\n\n{prompt.to_text()}"
        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=8192,
        ).to(self._model.device)
        with torch.no_grad():
            out = self._model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                do_sample=self.temperature > 0.0,
                temperature=max(self.temperature, 1e-5),
                pad_token_id=self._tokenizer.pad_token_id,
            )
        new_tokens = out[0][inputs["input_ids"].shape[1]:]
        raw = self._tokenizer.decode(new_tokens, skip_special_tokens=True)
        return parse_audit_response(raw)


def get_backend(name: str, **kwargs: Any) -> AuditBackend:
    """Factory for CLI / cache seeder use."""
    name = name.lower()
    if name == "openai":
        return OpenAIBackend(**kwargs)
    if name == "ollama":
        return OllamaBackend(**kwargs)
    if name == "dwarfstar":
        return DwarfstarBackend(**kwargs)
    if name in ("apiary", "apiary-finetuned", "finetuned"):
        return ApiaryFineTunedBackend(**kwargs)
    raise ValueError(f"unknown audit backend: {name}")
