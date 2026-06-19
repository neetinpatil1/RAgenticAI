"""
tools/reachability/jar_analyzer.py
====================================
Analyzes Java JAR files to find internal references to a target class.

Technique: Binary string search in .class files.
Java class files store ALL referenced class names as UTF-8 strings in the
constant pool (CONSTANT_Utf8 entries for Methodref/Fieldref/Classref).
Searching for b'org/foo/Bar' in raw .class bytes is reliable and fast —
no JDK or javatools dependency required.

Returns list of classes inside the JAR that reference the target.
"""
from __future__ import annotations
import logging
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)


def find_class_refs_in_jar(jar_path: Path, target_class: str) -> list[str]:
    """
    Scan a JAR for .class files that reference target_class.

    Args:
        jar_path:     Path to the JAR file.
        target_class: Fully-qualified class name, e.g.
                      'org.apache.logging.log4j.core.lookup.JndiLookup'

    Returns:
        List of class names inside the JAR that reference target_class.
        Empty list if JAR can't be read or no references found.
    """
    if not jar_path.exists():
        return []

    # JVM stores class names with '/' separators in bytecode
    target_bytes = target_class.replace(".", "/").encode("utf-8")
    # Also search for dot-separated form (appears in string literals / annotations)
    target_dots  = target_class.encode("utf-8")

    matching: list[str] = []
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            for entry in zf.namelist():
                if not entry.endswith(".class"):
                    continue
                try:
                    data = zf.read(entry)
                    if target_bytes in data or target_dots in data:
                        class_name = entry.removesuffix(".class").replace("/", ".")
                        matching.append(class_name)
                except Exception:
                    continue  # corrupted entry — skip silently
    except zipfile.BadZipFile:
        logger.warning("jar_analyzer | bad zip: %s", jar_path.name)
    except Exception as exc:
        logger.warning("jar_analyzer | error reading %s: %s", jar_path.name, exc)

    if matching:
        logger.info("jar_analyzer | %s → %d classes reference %s",
                    jar_path.name, len(matching), target_class)
    return matching


def scan_jar_for_package(jar_path: Path, target_package: str) -> bool:
    """
    Quick check: does this JAR reference ANY class in target_package?
    Faster than find_class_refs_in_jar when you only need a yes/no answer.
    """
    if not jar_path.exists():
        return False
    target_bytes = target_package.replace(".", "/").encode("utf-8")
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            for entry in zf.namelist():
                if not entry.endswith(".class"):
                    continue
                try:
                    if target_bytes in zf.read(entry):
                        return True
                except Exception:
                    continue
    except Exception:
        pass
    return False
