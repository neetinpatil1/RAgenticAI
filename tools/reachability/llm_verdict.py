"""
tools/reachability/llm_verdict.py
===================================
LLM fallback verdict for UNKNOWN reachability cases.
Uses llama3.2:3b (Tier 2 — fast) via Ollama.
Only invoked when static analysis returns UNKNOWN.
"""
from __future__ import annotations
import json
import logging
import httpx
from core.config import settings

logger = logging.getLogger(__name__)


async def get_llm_verdict(
    package_name:   str,
    vuln_id:        str,
    cve_description: str,
    target_class:   str,
    scan_path:      str,
) -> dict:
    """
    Ask LLM whether the CVE is likely reachable based on usage context.

    Returns:
        {verdict: "LIKELY_REACHABLE"|"LIKELY_NOT_REACHABLE"|"UNKNOWN",
         confidence: float, reasoning: str}
    """
    # Read a small sample of source files that import the package to give LLM context
    context_snippets = _get_usage_snippets(scan_path, package_name)

    prompt = f"""CVE: {vuln_id}
Package: {package_name}
Vulnerable class/functionality: {target_class or 'not specified'}
CVE description: {cve_description[:600]}

Application usage context (source snippets that reference this package):
{context_snippets or 'No direct usage found in source code.'}

Question: Based on how the application uses this library, is the vulnerable functionality likely to be triggered?
Respond with valid JSON:
{{
  "verdict": "LIKELY_REACHABLE" or "LIKELY_NOT_REACHABLE" or "UNKNOWN",
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation"
}}"""

    try:
        async with httpx.AsyncClient(timeout=settings.ollama.request_timeout) as client:
            r = await client.post(
                f"{settings.ollama.base_url}/api/chat",
                json={
                    "model": settings.ollama.tier2_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "format": "json",
                },
            )
            r.raise_for_status()
            content = r.json()["message"]["content"]
            data    = json.loads(content.strip())
            verdict = data.get("verdict", "UNKNOWN")
            if verdict not in ("LIKELY_REACHABLE", "LIKELY_NOT_REACHABLE", "UNKNOWN"):
                verdict = "UNKNOWN"
            return {
                "verdict":    verdict,
                "confidence": float(data.get("confidence", 0.4)),
                "reasoning":  data.get("reasoning", ""),
            }
    except Exception as exc:
        logger.warning("llm_verdict | failed: %s", exc)
        return {"verdict": "UNKNOWN", "confidence": 0.0, "reasoning": f"LLM error: {exc}"}


def _get_usage_snippets(scan_path: str, package_name: str, max_lines: int = 20) -> str:
    """Extract a few lines of source code that reference the package."""
    from pathlib import Path
    import re
    root = Path(scan_path)
    pkg_simple = package_name.split("-")[0].split(":")[0].lower()
    pattern    = re.compile(re.escape(pkg_simple), re.IGNORECASE)
    snippets: list[str] = []
    seen_files = 0

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in (".java", ".py", ".js", ".ts", ".tsx"):
            continue
        if any(p in {".git", "node_modules", ".venv", "target", "build"} for p in path.parts):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            file_snippets = [
                f"{path.name}:{i+1}: {line.strip()}"
                for i, line in enumerate(lines)
                if pattern.search(line) and len(line.strip()) < 200
            ]
            if file_snippets:
                snippets.extend(file_snippets[:5])
                seen_files += 1
                if seen_files >= 3 or len(snippets) >= max_lines:
                    break
        except Exception:
            continue

    return "\n".join(snippets[:max_lines])
