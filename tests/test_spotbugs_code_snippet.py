"""
tests/test_spotbugs_code_snippet.py
=====================================
Tests for SpotBugs source-file path resolution and code snippet extraction.

Background
----------
SpotBugs analyses Java bytecode and reports file paths as bytecode class paths,
e.g. ``org/cysecurity/cspf/jvl/controller/EmailFormatterServlet.java``.

These paths do NOT exist directly under the project root.  The actual source
lives under the Maven standard layout:
    <scan_root>/src/main/java/org/cysecurity/cspf/jvl/controller/EmailFormatterServlet.java

The bug: ``_insert_findings`` was doing ``root / f.file_path``, which produced
a non-existent path, so ``_read_code_context`` always returned ``None`` and
``code_snippet`` was stored as NULL in the DB.

The fix: try three candidate paths in order:
    1. ``{root}/{file_path}``                       — direct (rarely works for Maven)
    2. ``{root}/src/main/java/{file_path}``         — Maven standard layout  ✅
    3. ``{root}/src/{file_path}``                   — alternative layout

Real findings used as test fixtures (from scan_20260621_172036_5544aa):
    • findsecbugs/SERVLET_PARAMETER — EmailFormatterServlet.java line 50
      "The method getParameter returns a String value that is controlled by the client"
    • findsecbugs/SQL_INJECTION_JDBC — Install.java line 123
    • findsecbugs/XSS_SERVLET       — EmailFormatterServlet.java line 79
"""
from __future__ import annotations

import tempfile
import textwrap
from pathlib import Path

import pytest

# ── import the helpers under test ────────────────────────────────────────────
from workflows.spotbugs_workflow import _read_code_context


# ============================================================================
# Helpers
# ============================================================================

def _make_project(tmp_path: Path, rel_class_path: str, source: str) -> Path:
    """
    Create a fake Maven project rooted at tmp_path.

    The source file is placed at:
        tmp_path / src / main / java / <rel_class_path>

    Returns tmp_path (the scan_root).
    """
    src_file = tmp_path / "src" / "main" / "java" / rel_class_path
    src_file.parent.mkdir(parents=True, exist_ok=True)
    src_file.write_text(textwrap.dedent(source), encoding="utf-8")
    return tmp_path


def _resolve_snippet(scan_root: Path, class_path: str,
                     line_start: int, line_end: int | None = None) -> str | None:
    """
    Replicate the candidate-path resolution logic from _insert_findings.
    Returns the snippet string or None if no candidate resolved.
    """
    root = Path(scan_root)
    candidates = [
        root / class_path,
        root / "src" / "main" / "java" / class_path,
        root / "src" / class_path,
    ]
    for candidate in candidates:
        snippet = _read_code_context(str(candidate), line_start, line_end)
        if snippet:
            return snippet
    return None


# ============================================================================
# _read_code_context unit tests
# ============================================================================

class TestReadCodeContext:
    """Unit tests for the _read_code_context helper."""

    def test_returns_none_for_missing_file(self, tmp_path):
        result = _read_code_context(
            str(tmp_path / "DoesNotExist.java"), line_start=1, line_end=None
        )
        assert result is None

    def test_returns_none_when_line_start_is_none(self, tmp_path):
        f = tmp_path / "Foo.java"
        f.write_text("line1\nline2\n")
        result = _read_code_context(str(f), line_start=None, line_end=None)
        assert result is None

    def test_marks_vulnerable_line_with_arrow(self, tmp_path):
        source = "\n".join(f"line{i}" for i in range(1, 11))
        f = tmp_path / "Sample.java"
        f.write_text(source)
        snippet = _read_code_context(str(f), line_start=5, line_end=5)
        assert snippet is not None
        # The vulnerable line must be prefixed with >>>
        lines = snippet.splitlines()
        vuln = [l for l in lines if "line5" in l]
        assert len(vuln) == 1
        assert vuln[0].startswith(">>>")

    def test_context_lines_before_and_after(self, tmp_path):
        source = "\n".join(f"L{i}" for i in range(1, 20))
        f = tmp_path / "Sample.java"
        f.write_text(source)
        snippet = _read_code_context(str(f), line_start=10, line_end=10,
                                     context_lines=3)
        assert snippet is not None
        lines = snippet.splitlines()
        line_numbers = [int(l.split("|")[0].strip().lstrip(">").strip()) for l in lines]
        assert min(line_numbers) == 7   # 10 - 3
        assert max(line_numbers) == 13  # 10 + 3

    def test_multi_line_range_all_marked(self, tmp_path):
        source = "\n".join(f"code{i}" for i in range(1, 15))
        f = tmp_path / "Multi.java"
        f.write_text(source)
        snippet = _read_code_context(str(f), line_start=5, line_end=7)
        assert snippet is not None
        marked = [l for l in snippet.splitlines() if l.startswith(">>>")]
        assert len(marked) == 3   # lines 5, 6, 7 all marked

    def test_does_not_crash_on_empty_file(self, tmp_path):
        f = tmp_path / "Empty.java"
        f.write_text("")
        result = _read_code_context(str(f), line_start=1, line_end=None)
        assert result is None   # no lines → empty output → None

    def test_handles_line_start_beyond_eof(self, tmp_path):
        f = tmp_path / "Short.java"
        f.write_text("only one line\n")
        # Should not raise; returns None or empty because no matching lines
        result = _read_code_context(str(f), line_start=999, line_end=None)
        assert result is None


# ============================================================================
# Path resolution integration tests (real Maven layout)
# ============================================================================

class TestSpotBugsPathResolution:
    """
    Verify that the candidate-path resolution finds source files in a
    Maven-layout project when SpotBugs reports a bytecode class path.
    """

    # ── fixture: EmailFormatterServlet (SERVLET_PARAMETER, line 50) ──────────

    SERVLET_SOURCE = """\
        package org.cysecurity.cspf.jvl.controller;
        import javax.servlet.*;
        import javax.servlet.http.*;
        import java.io.*;

        public class EmailFormatterServlet extends HttpServlet {
            protected void processRequest(HttpServletRequest request,
                                          HttpServletResponse response)
                    throws ServletException, IOException {

                response.setContentType("text/plain;charset=UTF-8");
                PrintWriter out = response.getWriter();

                // Lines 13-14 in this fixture correspond to real lines 50-51
                String name  = request.getParameter("name");   // SERVLET_PARAMETER hit
                String email = request.getParameter("email");  // SERVLET_PARAMETER hit

                if (name == null || email == null) {
                    response.sendError(400, "name and email required");
                    return;
                }
                // … format and return …
            }
        }
    """

    CLASS_PATH_SERVLET = (
        "org/cysecurity/cspf/jvl/controller/EmailFormatterServlet.java"
    )

    def test_maven_layout_resolves(self, tmp_path):
        """Candidate 2 (src/main/java) must find the file."""
        _make_project(tmp_path, self.CLASS_PATH_SERVLET, self.SERVLET_SOURCE)
        snippet = _resolve_snippet(tmp_path, self.CLASS_PATH_SERVLET,
                                   line_start=14, line_end=14)
        assert snippet is not None, (
            "code_snippet must not be None for Maven-layout project"
        )

    def test_direct_path_does_not_exist(self, tmp_path):
        """Candidate 1 (direct) must NOT resolve — the class path alone is wrong."""
        _make_project(tmp_path, self.CLASS_PATH_SERVLET, self.SERVLET_SOURCE)
        direct = tmp_path / self.CLASS_PATH_SERVLET
        assert not direct.exists(), (
            "Direct class path should NOT exist under project root"
        )

    def test_snippet_contains_getparameter(self, tmp_path):
        """
        The snippet for SERVLET_PARAMETER must contain 'getParameter' —
        the exact API that triggered the SpotBugs finding.
        """
        _make_project(tmp_path, self.CLASS_PATH_SERVLET, self.SERVLET_SOURCE)
        snippet = _resolve_snippet(tmp_path, self.CLASS_PATH_SERVLET,
                                   line_start=14, line_end=15)
        assert snippet is not None
        assert "getParameter" in snippet, (
            "Snippet must contain the vulnerable API call 'getParameter'"
        )

    def test_snippet_marks_vulnerable_line(self, tmp_path):
        """The vulnerable line must be prefixed with >>> in the snippet."""
        _make_project(tmp_path, self.CLASS_PATH_SERVLET, self.SERVLET_SOURCE)
        snippet = _resolve_snippet(tmp_path, self.CLASS_PATH_SERVLET,
                                   line_start=14, line_end=14)
        assert snippet is not None
        marked = [l for l in snippet.splitlines() if l.startswith(">>>")]
        assert len(marked) >= 1, "At least one line must be marked with >>>"

    # ── fixture: SQL_INJECTION_JDBC (Install.java line 123) ─────────────────

    SQL_SOURCE = """\
        package org.cysecurity.cspf.jvl.controller;
        import java.sql.*;
        import javax.servlet.http.*;

        public class Install extends HttpServlet {
            private Connection conn;

            protected void processRequest(HttpServletRequest request,
                                          HttpServletResponse response) throws Exception {
                String user = request.getParameter("username");
                String pass = request.getParameter("password");
                // Lines 11-13 simulate the vulnerable block at real line 123
                Statement stmt = conn.createStatement();
                String sql = "INSERT INTO users VALUES('" + user + "','" + pass + "')";
                stmt.executeUpdate(sql);   // SQL_INJECTION_JDBC hit
            }
        }
    """

    CLASS_PATH_INSTALL = "org/cysecurity/cspf/jvl/controller/Install.java"

    def test_sql_injection_snippet_resolves(self, tmp_path):
        """SQL_INJECTION_JDBC finding must produce a snippet."""
        _make_project(tmp_path, self.CLASS_PATH_INSTALL, self.SQL_SOURCE)
        snippet = _resolve_snippet(tmp_path, self.CLASS_PATH_INSTALL,
                                   line_start=15, line_end=15)
        assert snippet is not None

    def test_sql_injection_snippet_contains_execute(self, tmp_path):
        """Snippet for SQL_INJECTION_JDBC must contain the dangerous executeUpdate call."""
        _make_project(tmp_path, self.CLASS_PATH_INSTALL, self.SQL_SOURCE)
        snippet = _resolve_snippet(tmp_path, self.CLASS_PATH_INSTALL,
                                   line_start=15, line_end=15)
        assert snippet is not None
        assert "executeUpdate" in snippet

    # ── edge cases ───────────────────────────────────────────────────────────

    def test_missing_file_returns_none(self, tmp_path):
        """No source file present → snippet must be None (no crash)."""
        snippet = _resolve_snippet(tmp_path,
                                   "org/example/NonExistent.java",
                                   line_start=10)
        assert snippet is None

    def test_alternative_src_layout(self, tmp_path):
        """Candidate 3 (src/<class_path>) must resolve for non-Maven layouts."""
        class_path = "com/example/MyServlet.java"
        src_file = tmp_path / "src" / class_path
        src_file.parent.mkdir(parents=True, exist_ok=True)
        src_file.write_text(
            "package com.example;\npublic class MyServlet {\n"
            "  String val = req.getParameter(\"x\"); // line 3\n}\n"
        )
        snippet = _resolve_snippet(tmp_path, class_path, line_start=3)
        assert snippet is not None
        assert "getParameter" in snippet

    def test_direct_layout_wins_over_maven(self, tmp_path):
        """
        If the file happens to exist at the direct path (candidate 1),
        it should be used without needing the Maven prefix.
        """
        class_path = "com/example/Direct.java"
        direct_file = tmp_path / class_path
        direct_file.parent.mkdir(parents=True, exist_ok=True)
        direct_file.write_text(
            "public class Direct {\n  void foo() { /* line 2 */ }\n}\n"
        )
        snippet = _resolve_snippet(tmp_path, class_path, line_start=2)
        assert snippet is not None
        assert "foo" in snippet
