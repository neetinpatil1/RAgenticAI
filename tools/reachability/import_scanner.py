"""
tools/reachability/import_scanner.py
======================================
Scans application source code for imports of a target class/package.

Works across Java, JavaScript/TypeScript, Python source files.
Returns ImportEvidence with matching files and lines.
"""
from __future__ import annotations
import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",
              "target", "build", "dist", ".gradle", ".mvn"}

_EXT_PATTERNS: dict[str, list[re.Pattern]] = {
    ".java": [
        re.compile(r'^\s*import\s+(static\s+)?({target_escaped}[.\w*]*)\s*;', re.MULTILINE),
    ],
    ".py": [
        re.compile(r'^\s*(?:from\s+({target_escaped}[\w.]*)\s+import|import\s+({target_escaped}[\w.]*))', re.MULTILINE),
    ],
    ".js": [
        re.compile(r'''(?:require|import)\s*\(?[\'"]{target_simple}[^'\"]*[\'"]\)?'''),
    ],
    ".ts": [
        re.compile(r'''(?:require|import)\s*\(?[\'"]{target_simple}[^'\"]*[\'"]\)?'''),
    ],
    ".tsx": [
        re.compile(r'''(?:require|import)\s*\(?[\'"]{target_simple}[^'\"]*[\'"]\)?'''),
    ],
}


@dataclass
class ImportEvidence:
    found: bool
    matches: list[dict]   # [{file, line_no, line}]
    is_wildcard: bool     # true if import covers the class but isn't exact


def scan_imports(scan_path: str, target_class: str) -> ImportEvidence:
    """
    Scan source files for imports of target_class.

    For Java: matches 'import org.foo.Bar;' and 'import org.foo.*;'
    For Python: matches 'from org.foo import Bar' and 'import org.foo'
    For JS/TS: matches require/import of the npm package name

    Args:
        scan_path:    Root of the project to scan.
        target_class: Fully-qualified class, e.g. 'org.apache.log4j.core.lookup.JndiLookup'
                      or npm package name 'lodash'.
    """
    root = Path(scan_path)
    matches: list[dict] = []
    is_wildcard = False

    # For Java: also match wildcard imports of the parent package
    # e.g. target = "org.foo.Bar" → wildcard = "org.foo.*"
    parts            = target_class.split(".")
    parent_pkg       = ".".join(parts[:-1]) if len(parts) > 1 else target_class
    class_name_only  = parts[-1]
    # npm package name is usually the first segment or first two (scoped: @org/pkg)
    npm_pkg          = parts[0] if not target_class.startswith("@") else "/".join(parts[:2])

    escaped = re.escape(target_class)
    escaped_pkg = re.escape(parent_pkg)
    simple  = re.escape(npm_pkg)

    patterns: list[tuple[re.Pattern, bool]] = [
        # Exact import
        (re.compile(rf'^\s*import\s+(?:static\s+)?{escaped}[\w.]*\s*;', re.MULTILINE), False),
        # Wildcard Java import of parent package
        (re.compile(rf'^\s*import\s+{escaped_pkg}\.\*\s*;', re.MULTILINE), True),
        # Python from ... import
        (re.compile(rf'^\s*from\s+{escaped_pkg}[\w.]*\s+import\s+\w', re.MULTILINE), False),
        (re.compile(rf'^\s*import\s+{escaped}', re.MULTILINE), False),
        # JS/TS require/import
        (re.compile(rf"""['"]{re.escape(npm_pkg)}['"/]"""), False),
    ]

    try:
        for path in _walk_source(root):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                for pattern, wildcard in patterns:
                    for m in pattern.finditer(text):
                        line_no = text[:m.start()].count("\n") + 1
                        line    = text.splitlines()[line_no - 1].strip() if line_no <= len(text.splitlines()) else ""
                        matches.append({
                            "file":    str(path.relative_to(root)),
                            "line_no": line_no,
                            "line":    line,
                        })
                        if wildcard:
                            is_wildcard = True
            except Exception:
                continue
    except Exception as exc:
        logger.warning("import_scanner | error: %s", exc)

    found = len(matches) > 0
    if found:
        logger.info("import_scanner | target=%s found=%s wildcard=%s matches=%d",
                    target_class, found, is_wildcard, len(matches))
    return ImportEvidence(found=found, matches=matches, is_wildcard=is_wildcard)


def _walk_source(root: Path):
    """Yield source files, skipping build/vendor dirs."""
    SOURCE_EXTS = {".java", ".py", ".js", ".ts", ".tsx"}
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in SOURCE_EXTS:
            if not any(part in _SKIP_DIRS for part in path.parts):
                yield path
