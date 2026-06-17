"""
core/prompt_manager.py
========================
Local YAML prompt loader for Phase 0.

Design (SSDLC_Design_v3.2.docx §10):
  - Prompts are stored as YAML files with semantic versioning.
  - Every prompt change goes through PR review (in Phase 1: Gitea PR gate).
  - Phase 0: reads from local filesystem (prompts/ directory).
  - Phase 1+: extend to pull from Gitea repo for version-controlled delivery.

Directory structure:
  prompts/
    sast_agent/
      v1.0/
        system.yml        ← system prompt for SAST analysis
        fp_analysis.yml   ← FP pipeline user prompt template

YAML schema:
  version: "1.0"
  description: "..."
  prompts:
    system: |
      You are a ...
    fp_analysis: |
      Analyse the following ...

Usage:
    pm = PromptManager(prompts_dir="./prompts")
    system_prompt = pm.get("sast_agent", "v1.0", "fp_analysis", "system")
"""

import yaml
import logging
from pathlib import Path
from functools import lru_cache

logger = logging.getLogger(__name__)


class PromptManager:
    """
    File-based prompt loader with in-memory cache.

    Cache is per (agent, version, file) tuple.
    Call invalidate_cache() after hot-reloading prompts from Gitea.
    """

    def __init__(self, prompts_dir: str = "./prompts"):
        self.prompts_dir = Path(prompts_dir)
        # Cache: (agent, version, filename) → dict of prompt keys → content
        self._cache: dict[tuple, dict] = {}

    def get(
        self,
        agent: str,
        version: str,
        filename: str,
        key: str,
    ) -> str:
        """
        Retrieve a specific prompt string by agent, version, file, and key.

        Args:
            agent:    e.g. "sast_agent"
            version:  e.g. "v1.0"
            filename: e.g. "fp_analysis" (without .yml)
            key:      e.g. "system" or "user_template"

        Returns:
            Prompt string.

        Raises:
            FileNotFoundError: if the YAML file doesn't exist.
            KeyError:          if the key doesn't exist in the file.
        """
        cache_key = (agent, version, filename)
        if cache_key not in self._cache:
            self._cache[cache_key] = self._load(agent, version, filename)

        prompts = self._cache[cache_key]
        if key not in prompts:
            raise KeyError(
                f"Prompt key '{key}' not found in {agent}/{version}/{filename}.yml. "
                f"Available keys: {list(prompts.keys())}"
            )
        return prompts[key]

    def _load(self, agent: str, version: str, filename: str) -> dict:
        """Load and parse a single prompt YAML file."""
        path = self.prompts_dir / agent / version / f"{filename}.yml"

        if not path.exists():
            raise FileNotFoundError(
                f"Prompt file not found: {path}\n"
                f"Create it or check prompts_dir setting in config."
            )

        with open(path) as f:
            data = yaml.safe_load(f)

        # Support both flat {key: value} and nested {prompts: {key: value}}
        if "prompts" in data:
            return data["prompts"]
        return {k: v for k, v in data.items() if k not in ("version", "description")}

    def invalidate_cache(self, agent: str | None = None) -> None:
        """
        Clear cached prompts to force reload from disk.
        Pass agent=None to clear all, or a specific agent name to clear just that agent.
        """
        if agent is None:
            self._cache.clear()
            logger.info("Prompt cache cleared (all agents)")
        else:
            keys_to_clear = [k for k in self._cache if k[0] == agent]
            for k in keys_to_clear:
                del self._cache[k]
            logger.info("Prompt cache cleared | agent=%s cleared=%d", agent, len(keys_to_clear))

    def list_versions(self, agent: str) -> list[str]:
        """List available versions for a given agent."""
        agent_dir = self.prompts_dir / agent
        if not agent_dir.exists():
            return []
        return sorted([d.name for d in agent_dir.iterdir() if d.is_dir()])


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_prompt_manager_instance: PromptManager | None = None


def init_prompt_manager(prompts_dir: str) -> None:
    global _prompt_manager_instance
    _prompt_manager_instance = PromptManager(prompts_dir)
    logger.info("PromptManager initialised | dir=%s", prompts_dir)


def get_prompt_manager() -> PromptManager:
    if _prompt_manager_instance is None:
        raise RuntimeError("PromptManager not initialised — call init_prompt_manager() first")
    return _prompt_manager_instance
