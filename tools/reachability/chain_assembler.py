"""
tools/reachability/chain_assembler.py
=======================================
Assembles the full reachability chain:
  App code → Parent library method → Child library vulnerable class

Uses:
  1. ImportScanner  — does app import the vulnerable class directly?
  2. JarAnalyzer    — which parent JAR classes reference the vulnerable class?
  3. ImportScanner  — does app import those parent classes?

Returns a ReachabilityResult with verdict + evidence string.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from tools.reachability.import_scanner import scan_imports, ImportEvidence
from tools.reachability.jar_analyzer   import find_class_refs_in_jar
from tools.reachability.dep_tree       import DepTree

logger = logging.getLogger(__name__)

# Max transitive hops before we give up
MAX_HOPS = 5


@dataclass
class ReachabilityResult:
    verdict: str          # REACHABLE | NOT_REACHABLE | UNKNOWN
    evidence: str         # Human-readable explanation
    confidence: float     # 0.0-1.0
    source: str           # import-scan | jar-bytecode | unknown


def assemble_chain(
    scan_path:       str,
    dep_tree:        DepTree,
    target_class:    str,          # vulnerable class from CVE enricher
    package_name:    str,          # e.g. "jackson-databind"
) -> ReachabilityResult:
    """
    Build reachability evidence chain for one CVE.

    Algorithm:
      Step 1: Direct import check — does app code import target_class?
              YES → REACHABLE (highest confidence)
      Step 2: Transitive check — for each resolved JAR (parent deps):
              a. Does the JAR bytecode reference target_class?
              b. If yes: does app import any class from that JAR's package?
              Chain found → REACHABLE
      Step 3: No chain found → NOT_REACHABLE
      Any failure → UNKNOWN
    """
    if not target_class:
        return ReachabilityResult(
            verdict="UNKNOWN",
            evidence="No vulnerable class mapping available for this CVE — cannot determine reachability.",
            confidence=0.0,
            source="unknown",
        )

    # ── Step 1: Direct import ────────────────────────────────────────────────
    try:
        direct = scan_imports(scan_path, target_class)
        if direct.found:
            evidence_lines = [f"Vulnerable class `{target_class}` directly imported in application code:"]
            for m in direct.matches[:3]:
                evidence_lines.append(f"  {m['file']}:{m['line_no']}  →  {m['line']}")
            if direct.is_wildcard:
                evidence_lines.append(
                    f"  (wildcard import covers {target_class} — "
                    "manual verification recommended)"
                )
            return ReachabilityResult(
                verdict="REACHABLE",
                evidence="\n".join(evidence_lines),
                confidence=0.95 if not direct.is_wildcard else 0.70,
                source="import-scan",
            )
    except Exception as exc:
        logger.warning("chain_assembler | direct import check failed: %s", exc)

    # ── Step 2: Transitive via JAR bytecode ──────────────────────────────────
    if dep_tree.jar_paths:
        try:
            for jar_path in dep_tree.jar_paths[:30]:   # cap at 30 JARs to avoid slow scans
                # Skip the vulnerable JAR itself
                if package_name.lower() in jar_path.name.lower():
                    continue

                parent_refs = find_class_refs_in_jar(jar_path, target_class)
                if not parent_refs:
                    continue

                # Parent JAR references the vulnerable class.
                # Now check if app imports anything from this parent JAR.
                # Use the first 2 path segments of the first referenced class
                # to derive the parent package.
                sample_class  = parent_refs[0]
                pkg_parts     = sample_class.split(".")
                parent_pkg    = ".".join(pkg_parts[:3]) if len(pkg_parts) >= 3 else sample_class

                app_uses_parent = scan_imports(scan_path, parent_pkg)
                if app_uses_parent.found:
                    evidence_lines = [
                        f"Transitive reachability via `{jar_path.name}`:",
                        f"  Application imports `{parent_pkg}` (parent library)",
                        f"  `{jar_path.name}` internally references `{target_class}` "
                        f"in {len(parent_refs)} class(es):",
                    ]
                    for ref in parent_refs[:3]:
                        evidence_lines.append(f"    · {ref}")
                    evidence_lines.append(
                        f"  App call site: {app_uses_parent.matches[0]['file']}:"
                        f"{app_uses_parent.matches[0]['line_no']}"
                    )
                    return ReachabilityResult(
                        verdict="REACHABLE",
                        evidence="\n".join(evidence_lines),
                        confidence=0.75,
                        source="jar-bytecode",
                    )
        except Exception as exc:
            logger.warning("chain_assembler | transitive check failed: %s", exc)
            return ReachabilityResult(
                verdict="UNKNOWN",
                evidence=f"JAR analysis encountered an error: {exc}",
                confidence=0.0,
                source="unknown",
            )

        # All JARs checked — no chain found
        jar_count  = len(dep_tree.jar_paths)
        return ReachabilityResult(
            verdict="NOT_REACHABLE",
            evidence=(
                f"No import of `{target_class}` found in application source code.\n"
                f"Analyzed {min(jar_count, 30)} dependency JAR(s) — none bridge the "
                f"app to the vulnerable class via their internal calls."
            ),
            confidence=0.80,
            source="jar-bytecode",
        )

    # ── Step 3: No JARs to analyze — import scan only ───────────────────────
    # We only know the app doesn't directly import the class.
    # Can't rule out transitive reachability without JAR analysis.
    return ReachabilityResult(
        verdict="UNKNOWN",
        evidence=(
            f"No direct import of `{target_class}` found in application source code. "
            f"Could not resolve dependency JARs from ~/.m2/ to perform transitive analysis. "
            f"Manual review recommended."
        ),
        confidence=0.0,
        source="unknown",
    )
