"""
tools/reachability/dep_tree.py
===============================
Build a dependency tree for a scanned project — ecosystem-agnostic.

Returns a DepTree dataclass with:
  - direct_deps: list of (package, version, ecosystem) declared directly
  - jar_paths: list of Path to resolved JARs (Maven only, from ~/.m2/)
  - npm_module_path: Path to node_modules/ (npm only)
  - all_transitive_ids: set of "package:version" strings

All I/O wrapped in try/except — returns empty tree on failure.
"""
from __future__ import annotations
import json
import logging
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_M2_HOME = Path.home() / ".m2" / "repository"


@dataclass
class DepTree:
    ecosystem: str                            # maven | npm | python | unknown
    direct_deps: list[dict] = field(default_factory=list)   # {name, version, group}
    jar_paths: list[Path]   = field(default_factory=list)   # resolved JARs from ~/.m2/
    npm_modules_path: Optional[Path] = None                 # node_modules/ dir
    all_ids: set[str]       = field(default_factory=set)    # "name:version"


def build_dep_tree(scan_path: str) -> DepTree:
    """Build dependency tree for the project at scan_path."""
    root = Path(scan_path)

    if (root / "pom.xml").exists():
        return _build_maven_tree(root)
    if (root / "package-lock.json").exists() or (root / "package.json").exists():
        return _build_npm_tree(root)
    if (root / "requirements.txt").exists() or (root / "pyproject.toml").exists():
        return _build_python_tree(root)

    return DepTree(ecosystem="unknown")


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------

_NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def _resolve_jar(group: str, artifact: str, version: str) -> Optional[Path]:
    """Resolve a Maven JAR from the local ~/.m2 repository."""
    if not group or not artifact or not version:
        return None
    jar = _M2_HOME / group.replace(".", "/") / artifact / version / f"{artifact}-{version}.jar"
    return jar if jar.exists() else None


def _pom_ns(tag: str, ns: dict) -> str:
    """Get tag text handling Maven namespace or no-namespace pom.xml files."""
    return tag


def _parse_pom(pom_path: Path) -> list[dict]:
    """Parse pom.xml and return list of {group, name, version} dicts."""
    deps = []
    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()

        # Handle both namespaced and non-namespaced pom.xml
        ns_prefix = ""
        if root.tag.startswith("{"):
            ns_uri = root.tag.split("}")[0].lstrip("{")
            ns_prefix = f"{{{ns_uri}}}"

        deps_el = root.find(f"{ns_prefix}dependencies")
        if deps_el is None:
            # Try nested under <dependencyManagement>
            dm = root.find(f"{ns_prefix}dependencyManagement")
            if dm is not None:
                deps_el = dm.find(f"{ns_prefix}dependencies")

        if deps_el is None:
            return deps

        for dep in deps_el.findall(f"{ns_prefix}dependency"):
            group   = (dep.findtext(f"{ns_prefix}groupId")    or "").strip()
            name    = (dep.findtext(f"{ns_prefix}artifactId") or "").strip()
            version = (dep.findtext(f"{ns_prefix}version")    or "").strip()
            scope   = (dep.findtext(f"{ns_prefix}scope")      or "compile").strip()
            if scope in ("test", "provided"):
                continue
            if group and name:
                deps.append({"group": group, "name": name, "version": version})
    except Exception as exc:
        logger.warning("dep_tree | pom.xml parse error: %s", exc)
    return deps


def _build_maven_tree(root: Path) -> DepTree:
    tree = DepTree(ecosystem="maven")
    seen_jars: set[str] = set()

    try:
        pom_files = list(root.rglob("pom.xml"))
        for pom in pom_files:
            for dep in _parse_pom(pom):
                tree.direct_deps.append(dep)
                tree.all_ids.add(f"{dep['name']}:{dep['version']}")
                jar = _resolve_jar(dep["group"], dep["name"], dep["version"])
                if jar and jar.name not in seen_jars:
                    seen_jars.add(jar.name)
                    tree.jar_paths.append(jar)
    except Exception as exc:
        logger.warning("dep_tree | maven build error: %s", exc)

    # Fallback: scan target/dependency/ (populated by mvn dependency:copy-dependencies).
    # This is the primary JAR source when the project has been built but deps aren't
    # in ~/.m2 (e.g. first build, CI environment, or a standalone test lab project).
    fallback_dirs = [
        root / "target" / "dependency",        # standard Maven copy-dependencies output
        root / "target" / "lib",               # some project conventions
        root / "lib",                           # bundled JARs checked into the repo
    ]
    for jar_dir in fallback_dirs:
        if not jar_dir.is_dir():
            continue
        for jar_path in jar_dir.glob("*.jar"):
            if jar_path.name not in seen_jars:
                seen_jars.add(jar_path.name)
                tree.jar_paths.append(jar_path)
                logger.debug("dep_tree | fallback JAR: %s", jar_path.name)

    logger.info("dep_tree | maven deps=%d jars_resolved=%d",
                len(tree.direct_deps), len(tree.jar_paths))
    return tree


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

def _build_npm_tree(root: Path) -> DepTree:
    tree = DepTree(ecosystem="npm")
    try:
        lock = root / "package-lock.json"
        if lock.exists():
            data = json.loads(lock.read_text(encoding="utf-8", errors="replace"))
            # npm v2/v3 lock format uses "packages" key; v1 uses "dependencies"
            pkgs = data.get("packages") or data.get("dependencies") or {}
            for pkg_key, info in pkgs.items():
                if not isinstance(info, dict):
                    continue
                name    = pkg_key.replace("node_modules/", "").strip("/") or pkg_key
                version = info.get("version", "")
                if name:
                    tree.direct_deps.append({"name": name, "version": version, "group": ""})
                    tree.all_ids.add(f"{name}:{version}")
        # Point to node_modules for source analysis
        nm = root / "node_modules"
        if nm.is_dir():
            tree.npm_modules_path = nm
    except Exception as exc:
        logger.warning("dep_tree | npm build error: %s", exc)
    logger.info("dep_tree | npm deps=%d", len(tree.direct_deps))
    return tree


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

def _build_python_tree(root: Path) -> DepTree:
    tree = DepTree(ecosystem="python")
    try:
        req = root / "requirements.txt"
        if req.exists():
            for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Handle: package==1.0, package>=1.0, package
                for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", "@"):
                    if sep in line:
                        parts = line.split(sep, 1)
                        name    = parts[0].strip()
                        version = parts[1].strip() if len(parts) > 1 else ""
                        tree.direct_deps.append({"name": name, "version": version, "group": ""})
                        tree.all_ids.add(f"{name}:{version}")
                        break
                else:
                    tree.direct_deps.append({"name": line, "version": "", "group": ""})
    except Exception as exc:
        logger.warning("dep_tree | python build error: %s", exc)
    logger.info("dep_tree | python deps=%d", len(tree.direct_deps))
    return tree
