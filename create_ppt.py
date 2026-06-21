"""
Generate SSDLC Platform Technical Presentation
"""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt
import copy

# ── Colour Palette ──────────────────────────────────────────────────────────
DARK_BG    = RGBColor(0x0D, 0x1B, 0x2A)   # deep navy
ACCENT     = RGBColor(0x00, 0xC8, 0xFF)   # cyan
ACCENT2    = RGBColor(0x00, 0xFF, 0xA3)   # mint green
WHITE      = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT_GRAY = RGBColor(0xCC, 0xD6, 0xE0)
CARD_BG    = RGBColor(0x13, 0x2A, 0x3E)   # slightly lighter navy
YELLOW     = RGBColor(0xFF, 0xD6, 0x00)
RED_LIGHT  = RGBColor(0xFF, 0x6B, 0x6B)
GREEN_LIGHT= RGBColor(0x6B, 0xFF, 0xB8)

SLIDE_W = Inches(13.33)
SLIDE_H = Inches(7.5)

prs = Presentation()
prs.slide_width  = SLIDE_W
prs.slide_height = SLIDE_H

blank_layout = prs.slide_layouts[6]   # completely blank


# ── Helpers ─────────────────────────────────────────────────────────────────

def bg(slide, color=DARK_BG):
    """Fill slide background."""
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = color

def box(slide, l, t, w, h, color, radius=False):
    """Add a filled rectangle."""
    from pptx.util import Emu
    shape = slide.shapes.add_shape(1, l, t, w, h)   # MSO_SHAPE_TYPE.RECTANGLE = 1
    shape.fill.solid()
    shape.fill.fore_color.rgb = color
    shape.line.fill.background()
    return shape

def txt(slide, text, l, t, w, h,
        size=18, bold=False, color=WHITE, align=PP_ALIGN.LEFT,
        italic=False, wrap=True):
    tf = slide.shapes.add_textbox(l, t, w, h)
    tf.word_wrap = wrap
    p = tf.text_frame.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.size  = Pt(size)
    run.font.bold  = bold
    run.font.color.rgb = color
    run.font.italic = italic
    return tf

def header_bar(slide, title, subtitle=None):
    """Top gradient-like header bar."""
    box(slide, 0, 0, SLIDE_W, Inches(1.15), CARD_BG)
    # accent left strip
    box(slide, 0, 0, Inches(0.07), Inches(1.15), ACCENT)
    txt(slide, title, Inches(0.2), Inches(0.1), Inches(10), Inches(0.55),
        size=28, bold=True, color=ACCENT)
    if subtitle:
        txt(slide, subtitle, Inches(0.2), Inches(0.65), Inches(11), Inches(0.4),
            size=13, color=LIGHT_GRAY, italic=True)

def badge(slide, label, l, t, w=Inches(1.8), h=Inches(0.38), color=ACCENT):
    box(slide, l, t, w, h, color)
    txt(slide, label, l, t, w, h, size=11, bold=True, color=DARK_BG, align=PP_ALIGN.CENTER)

def card(slide, title, bullets, l, t, w, h, title_color=ACCENT, bullet_size=13):
    box(slide, l, t, w, h, CARD_BG)
    # left accent bar
    box(slide, l, t, Inches(0.045), h, title_color)
    txt(slide, title, l+Inches(0.1), t+Inches(0.07), w-Inches(0.15), Inches(0.38),
        size=14, bold=True, color=title_color)
    body_top = t + Inches(0.48)
    body_h   = h - Inches(0.55)
    tf = slide.shapes.add_textbox(l+Inches(0.12), body_top, w-Inches(0.18), body_h)
    tf.word_wrap = True
    tf_frame = tf.text_frame
    tf_frame.word_wrap = True
    first = True
    for b in bullets:
        if first:
            p = tf_frame.paragraphs[0]
            first = False
        else:
            p = tf_frame.add_paragraph()
        p.space_before = Pt(2)
        run = p.add_run()
        run.text = f"• {b}"
        run.font.size  = Pt(bullet_size)
        run.font.color.rgb = LIGHT_GRAY


def arrow(slide, x1, y1, x2, y2, color=ACCENT, width=Pt(2)):
    """Draw a simple line connector arrow."""
    from pptx.util import Pt
    from pptx.oxml.ns import qn
    import lxml.etree as etree
    connector = slide.shapes.add_connector(1, x1, y1, x2, y2)
    connector.line.color.rgb = color
    connector.line.width = width


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 1 — TITLE
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)

# Big accent stripe left
box(s, 0, 0, Inches(0.12), SLIDE_H, ACCENT)
# Bottom stripe
box(s, 0, SLIDE_H - Inches(0.08), SLIDE_W, Inches(0.08), ACCENT2)

txt(s, "SSDLC", Inches(0.4), Inches(0.8), Inches(12), Inches(1.8),
    size=96, bold=True, color=ACCENT, align=PP_ALIGN.CENTER)
txt(s, "Secure Software Development Lifecycle Platform",
    Inches(0.4), Inches(2.5), Inches(12), Inches(0.8),
    size=28, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
txt(s, "AI-Powered Multi-Agent Security Scanning & False Positive Elimination",
    Inches(0.4), Inches(3.2), Inches(12), Inches(0.55),
    size=17, color=LIGHT_GRAY, italic=True, align=PP_ALIGN.CENTER)

# Badges row
badge_labels = ["SAST", "SCA", "Secrets", "Code Review", "Reachability", "FP Challenger"]
badge_colors = [ACCENT, ACCENT2, YELLOW, RGBColor(0xFF,0x8C,0x00), RED_LIGHT, GREEN_LIGHT]
bx = Inches(0.9)
for i, (lbl, col) in enumerate(zip(badge_labels, badge_colors)):
    badge(s, lbl, bx + i * Inches(2.08), Inches(4.3), Inches(1.9), Inches(0.44), col)

txt(s, "Powered by Ollama  ·  Local LLM  ·  Apple Silicon GPU  ·  Air-Gapped Ready",
    Inches(0.4), Inches(5.2), Inches(12), Inches(0.4),
    size=13, color=LIGHT_GRAY, align=PP_ALIGN.CENTER)

txt(s, "Technical Architecture & Design",
    Inches(0.4), Inches(6.4), Inches(12), Inches(0.4),
    size=12, color=ACCENT2, italic=True, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 2 — PLATFORM OVERVIEW
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "Platform Overview",
           "End-to-end automated security scanning embedded into the development lifecycle")

# 3-column value props
cols = [
    ("🔍  Detect", ["Multi-tool SAST scanning", "Semgrep + SpotBugs/FindSecBugs", "Secret detection", "SCA dependency CVEs", "Java bytecode analysis"]),
    ("🤖  Analyse", ["LLM-powered FP pipeline", "3-layer false-positive filter", "High-stakes CWE escalation", "Vector memory similarity", "Blast radius enrichment"]),
    ("✅  Decide", ["REAL / FP / ESCALATED verdict", "Confidence scoring 0–1", "FP Challenger verification", "Code review per file", "Human-label feedback loop"]),
]
cw = Inches(3.9)
for i, (title, bullets) in enumerate(cols):
    card(s, title, bullets, Inches(0.22) + i*Inches(4.37), Inches(1.3), cw, Inches(5.7),
         [ACCENT, ACCENT2, YELLOW][i])

# Footer
txt(s, "Single platform · One scan triggers all agents · Results in < 5 minutes",
    0, SLIDE_H - Inches(0.38), SLIDE_W, Inches(0.35),
    size=11, color=LIGHT_GRAY, italic=True, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 3 — HIGH-LEVEL ARCHITECTURE
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "High-Level Architecture", "FastAPI backend · PostgreSQL/pgvector · React UI · Ollama LLM")

# Layer boxes
layers = [
    ("UI Layer",          "React + TypeScript  |  Real-time SSE streaming  |  Command Centre Dashboard",  ACCENT,  Inches(1.3)),
    ("API Gateway",       "FastAPI (async)  |  REST endpoints  |  SSE scan stream  |  Watchdog SLA monitor", ACCENT2, Inches(2.1)),
    ("Agent Workflows",   "SAST · SpotBugs · SCA · Secrets · Code Review · Reachability · FP Pipeline · FP Challenger", YELLOW, Inches(2.9)),
    ("LLM Engine",        "Ollama  |  Tier-1: qwen2.5-coder:14b  |  Tier-2: llama3.2:3b  |  Apple Silicon Metal GPU", RGBColor(0xFF,0x8C,0x00), Inches(3.7)),
    ("Data Layer",        "PostgreSQL + pgvector  |  fp_decisions · findings_reports · workflow_runs  |  UniXcoder embeddings", RED_LIGHT, Inches(4.5)),
]
for title, desc, color, top in layers:
    box(s, Inches(0.3), top, Inches(12.7), Inches(0.62), CARD_BG)
    box(s, Inches(0.3), top, Inches(0.06), Inches(0.62), color)
    txt(s, title, Inches(0.5), top+Inches(0.04), Inches(2.2), Inches(0.55),
        size=13, bold=True, color=color)
    txt(s, desc, Inches(2.8), top+Inches(0.09), Inches(10.1), Inches(0.48),
        size=12, color=LIGHT_GRAY)

# Arrows between layers
for top in [Inches(1.93), Inches(2.72), Inches(3.51), Inches(4.3)]:
    txt(s, "▼", Inches(6.4), top, Inches(0.5), Inches(0.28),
        size=13, color=ACCENT, align=PP_ALIGN.CENTER)

txt(s, "Docker sandbox for Semgrep  ·  Air-gap ready  ·  No cloud dependency",
    0, SLIDE_H - Inches(0.38), SLIDE_W, Inches(0.35),
    size=11, color=LIGHT_GRAY, italic=True, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 4 — SCAN PIPELINE FLOW
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "Scan Pipeline — Agent Execution Flow",
           "5-step orchestrated pipeline: code submission → verified security report")

steps = [
    ("STEP 1",  "Graph Build",        "Call graph\nconstruction\nfrom source",         ACCENT),
    ("STEP 2",  "Parallel Scan",      "SAST + SCA\n+ Secrets +\nSpotBugs",             ACCENT2),
    ("STEP 3",  "FP Pipeline",        "L1 Rules →\nL3 LLM\nAnalysis",                  YELLOW),
    ("STEP 4",  "Code Review",        "Per-file LLM\nreview of\nvulnerable files",     RGBColor(0xFF,0x8C,0x00)),
    ("STEP 5",  "FP Challenger",      "Re-evaluate\nREAL findings\nfor reversals",     RED_LIGHT),
]

sw = Inches(2.2)
gap = Inches(0.22)
start_x = Inches(0.3)
top_box = Inches(1.4)

for i, (step, title, desc, color) in enumerate(steps):
    lx = start_x + i * (sw + gap)
    # Step box
    box(s, lx, top_box, sw, Inches(3.2), CARD_BG)
    box(s, lx, top_box, sw, Inches(0.35), color)
    txt(s, step, lx, top_box + Inches(0.04), sw, Inches(0.3),
        size=10, bold=True, color=DARK_BG, align=PP_ALIGN.CENTER)
    txt(s, title, lx, top_box + Inches(0.42), sw, Inches(0.5),
        size=15, bold=True, color=color, align=PP_ALIGN.CENTER)
    txt(s, desc, lx, top_box + Inches(0.95), sw, Inches(2.1),
        size=12, color=LIGHT_GRAY, align=PP_ALIGN.CENTER)
    # Arrow (except after last)
    if i < len(steps) - 1:
        ax = lx + sw + Inches(0.02)
        txt(s, "→", ax, top_box + Inches(1.35), gap + Inches(0.18), Inches(0.4),
            size=22, bold=True, color=ACCENT, align=PP_ALIGN.CENTER)

# Parallel note under step 2
txt(s, "⚡ All 4 scanners run concurrently",
    start_x + sw + gap, top_box + Inches(3.3), sw, Inches(0.35),
    size=11, color=ACCENT2, italic=True, align=PP_ALIGN.CENTER)

# Result row
results = [
    ("Semgrep findings", ACCENT),
    ("SpotBugs findings", ACCENT2),
    ("CVE findings", YELLOW),
    ("Secret findings", RED_LIGHT),
    ("FP verdicts", GREEN_LIGHT),
    ("Code issues", RGBColor(0xFF,0x8C,0x00)),
]
bw = Inches(2.0)
by = Inches(4.85)
for i, (label, color) in enumerate(results):
    bx2 = Inches(0.3) + i * (bw + Inches(0.12))
    box(s, bx2, by, bw, Inches(0.42), color)
    txt(s, label, bx2, by, bw, Inches(0.42),
        size=11, bold=True, color=DARK_BG, align=PP_ALIGN.CENTER)

txt(s, "↑  Consolidated outputs written to PostgreSQL — streamed live to UI via SSE",
    0, by + Inches(0.52), SLIDE_W, Inches(0.35),
    size=11, color=LIGHT_GRAY, italic=True, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 5 — SAST + FP PIPELINE DEEP DIVE
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "SAST Agent — 3-Layer False Positive Pipeline",
           "Semgrep OSS (Docker sandbox) + FindSecBugs + intelligent FP elimination")

# Left: flow
flow_items = [
    (ACCENT,  "Semgrep Scan",     "42 OWASP + custom rules\n236 Java files · Docker sandboxed\nOutputs: rule_id, CWE, file, line"),
    (ACCENT2, "Layer 1 — Rules",  "Deterministic YAML rules\nPattern matching on code_snippet\nFast: 0ms, no LLM needed"),
    (YELLOW,  "Layer 3 — LLM",    "Tier-1 LLM for high-stakes CWEs\nTier-2 LLM for standard findings\nJSON: verdict + confidence + reasoning"),
    (RED_LIGHT,"Escalation",      "confidence < 0.60 → escalate to T1\nHigh-stakes CWE always T1\nFP Challenger re-evaluates REAL/ESC"),
]

fx = Inches(0.25)
fw = Inches(5.8)
for i, (color, title, desc) in enumerate(flow_items):
    fy = Inches(1.35) + i * Inches(1.42)
    box(s, fx, fy, fw, Inches(1.25), CARD_BG)
    box(s, fx, fy, Inches(0.05), Inches(1.25), color)
    txt(s, f"{i+1}. {title}", fx+Inches(0.12), fy+Inches(0.06), fw-Inches(0.15), Inches(0.38),
        size=13, bold=True, color=color)
    txt(s, desc, fx+Inches(0.12), fy+Inches(0.44), fw-Inches(0.15), Inches(0.75),
        size=11, color=LIGHT_GRAY)
    if i < len(flow_items)-1:
        txt(s, "▼", fx+fw/2-Inches(0.25), fy+Inches(1.27), Inches(0.5), Inches(0.2),
            size=12, color=ACCENT, align=PP_ALIGN.CENTER)

# Right: verdict card
rx = Inches(6.5)
rw = Inches(6.5)
txt(s, "Verdict Classification", rx, Inches(1.32), rw, Inches(0.45),
    size=16, bold=True, color=ACCENT)

verdicts = [
    (GREEN_LIGHT, "REAL",      "Genuine vulnerability — high confidence\nshown in security findings report"),
    (RED_LIGHT,   "FP",        "False positive — suppressed from report\nstored for training feedback loop"),
    (YELLOW,      "ESCALATED", "Low confidence or high-stakes CWE\nqueued for manual security review"),
]
for i, (color, label, desc) in enumerate(verdicts):
    vy = Inches(1.85) + i * Inches(1.42)
    box(s, rx, vy, rw, Inches(1.28), CARD_BG)
    box(s, rx, vy, Inches(0.05), Inches(1.28), color)
    badge(s, label, rx+Inches(0.12), vy+Inches(0.1), Inches(1.6), Inches(0.36), color)
    txt(s, desc, rx+Inches(1.85), vy+Inches(0.1), rw-Inches(2.0), Inches(1.0),
        size=12, color=LIGHT_GRAY)

# SpotBugs note
box(s, rx, Inches(6.05), rw, Inches(0.75), CARD_BG)
box(s, rx, Inches(6.05), Inches(0.05), Inches(0.75), ACCENT2)
txt(s, "SpotBugs + FindSecBugs",
    rx+Inches(0.12), Inches(6.08), rw, Inches(0.3),
    size=12, bold=True, color=ACCENT2)
txt(s, "Java bytecode analysis · 112 bug patterns · Source snippet resolved from class path · Same FP pipeline",
    rx+Inches(0.12), Inches(6.38), rw-Inches(0.15), Inches(0.35),
    size=10, color=LIGHT_GRAY)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 6 — SCA AGENT
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "SCA Agent — Dependency Vulnerability Scanning",
           "Multi-ecosystem CVE detection: Maven · Python pip · Node.js npm · OSV/NVD database")

# Left: how it works flow
fx = Inches(0.25)
fw = Inches(5.8)
sca_flow = [
    (ACCENT,  "Step 1 — Manifest Discovery",
     "Locate pom.xml / requirements*.txt / package.json\nAuto-detect project type per directory\nSkip build output dirs (target, dist, node_modules)"),
    (ACCENT2, "Step 2 — Version Resolution",
     "Maven: parse <version> tags or run mvnw dependency:list\nBOM inheritance resolved via Maven wrapper\nPython: pip-audit · Node: npm audit --json"),
    (YELLOW,  "Step 3 — OSV Batch CVE Lookup",
     "POST /v1/querybatch — 50 packages per request\nGET /v1/vulns/{id} for full advisory details\nExtracts: severity, fixed version, CVE description"),
    (GREEN_LIGHT, "Step 4 — Finding Enrichment",
     "CVSS score → CRITICAL / HIGH / MEDIUM / LOW\nFixed version extracted from affected ranges\nInserted into findings_reports (ecosystem=maven/python/npm)"),
]
for i, (color, title, desc) in enumerate(sca_flow):
    fy = Inches(1.35) + i * Inches(1.42)
    box(s, fx, fy, fw, Inches(1.28), CARD_BG)
    box(s, fx, fy, Inches(0.05), Inches(1.28), color)
    txt(s, f"{i+1}. {title}", fx+Inches(0.12), fy+Inches(0.06), fw-Inches(0.15), Inches(0.38),
        size=13, bold=True, color=color)
    txt(s, desc, fx+Inches(0.12), fy+Inches(0.44), fw-Inches(0.15), Inches(0.78),
        size=11, color=LIGHT_GRAY)
    if i < len(sca_flow)-1:
        txt(s, "▼", fx+fw/2-Inches(0.25), fy+Inches(1.3), Inches(0.5), Inches(0.2),
            size=12, color=ACCENT, align=PP_ALIGN.CENTER)

# Right: ecosystem cards
rx = Inches(6.5)
rw = Inches(6.5)
txt(s, "Supported Ecosystems", rx, Inches(1.32), rw, Inches(0.45),
    size=16, bold=True, color=ACCENT)

ecosystems = [
    (ACCENT,  "Maven (Java)",
     "pom.xml parse + mvnw dependency:list fallback\nResolves Spring Boot BOM-managed transitive deps\nOSV Maven ecosystem · group:artifact:version format"),
    (ACCENT2, "Python",
     "pip-audit scans requirements*.txt\nPyPI Advisory Database via OSV\nOutputs: package, installed version, CVE, fix"),
    (RGBColor(0xFF,0x8C,0x00), "Node.js",
     "npm audit --json per package.json directory\nnpm Advisory Database\nSeverity mapping: moderate → MEDIUM"),
]
for i, (color, title, desc) in enumerate(ecosystems):
    ey = Inches(1.85) + i * Inches(1.72)
    box(s, rx, ey, rw, Inches(1.55), CARD_BG)
    box(s, rx, ey, Inches(0.05), Inches(1.55), color)
    txt(s, title, rx+Inches(0.12), ey+Inches(0.08), rw, Inches(0.36),
        size=13, bold=True, color=color)
    txt(s, desc, rx+Inches(0.12), ey+Inches(0.46), rw-Inches(0.15), Inches(1.0),
        size=11, color=LIGHT_GRAY)

txt(s, "BOM inheritance fix: Spring Boot parent POM manages all versions — mvnw dependency:list resolves 89 transitive deps",
    0, SLIDE_H - Inches(0.38), SLIDE_W, Inches(0.35),
    size=10, color=LIGHT_GRAY, italic=True, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 7 — SECRETS SCANNING AGENT
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "Secrets Scanner Agent — Credential & Token Detection",
           "Regex + entropy analysis across all source files · Zero false-positive on test fixtures")

# Left: detection methods
fx = Inches(0.25)
fw = Inches(5.8)

txt(s, "Detection Strategy", fx, Inches(1.32), fw, Inches(0.4),
    size=16, bold=True, color=ACCENT)

methods = [
    (ACCENT,  "Pattern-Based Regex Detection",
     "High-confidence patterns for well-known secret formats:\n"
     "AWS Access Keys (AKIA…) · GitHub tokens (ghp_…) · Stripe keys\n"
     "JWT tokens · Private keys (-----BEGIN RSA…) · Basic auth strings"),
    (ACCENT2, "Entropy-Based Heuristic",
     "Shannon entropy score on strings in assignments\n"
     "High-entropy strings (>4.5 bits/char) flagged as candidate secrets\n"
     "Combined with keyword hints: password, secret, token, key, api_key"),
    (YELLOW,  "Context-Aware Filtering",
     "Suppresses false positives from test fixtures, examples, comments\n"
     "File-type aware: skips .md, .txt docs and __pycache__\n"
     "Allowlist for known safe patterns (e.g. placeholder 'YOUR_KEY_HERE')"),
]
for i, (color, title, desc) in enumerate(methods):
    my = Inches(1.82) + i * Inches(1.68)
    box(s, fx, my, fw, Inches(1.52), CARD_BG)
    box(s, fx, my, Inches(0.05), Inches(1.52), color)
    txt(s, title, fx+Inches(0.12), my+Inches(0.08), fw-Inches(0.15), Inches(0.36),
        size=13, bold=True, color=color)
    txt(s, desc, fx+Inches(0.12), my+Inches(0.44), fw-Inches(0.15), Inches(1.0),
        size=11, color=LIGHT_GRAY)

# Right: what it finds + output
rx = Inches(6.5)
rw = Inches(6.5)

txt(s, "Secret Categories Detected", rx, Inches(1.32), rw, Inches(0.4),
    size=16, bold=True, color=ACCENT)

secret_types = [
    (RED_LIGHT,  "API Keys & Tokens",    "AWS, GCP, Azure, GitHub, Slack,\nStripe, Twilio, SendGrid"),
    (YELLOW,     "Authentication Creds", "Passwords, Basic Auth,\nHTTP Authorization headers"),
    (ACCENT2,    "Cryptographic Keys",   "RSA/EC private keys, SSH keys,\nPEM certificates, JWT secrets"),
    (GREEN_LIGHT,"Database Credentials", "Connection strings with passwords,\nMySQL/Postgres/MongoDB URIs"),
]
for i, (color, title, examples) in enumerate(secret_types):
    row = i // 2
    col = i % 2
    sx = rx + col * (rw/2 + Inches(0.05))
    sy = Inches(1.82) + row * Inches(1.55)
    sw2 = rw/2 - Inches(0.08)
    box(s, sx, sy, sw2, Inches(1.42), CARD_BG)
    box(s, sx, sy, Inches(0.05), Inches(1.42), color)
    txt(s, title, sx+Inches(0.12), sy+Inches(0.08), sw2-Inches(0.15), Inches(0.34),
        size=12, bold=True, color=color)
    txt(s, examples, sx+Inches(0.12), sy+Inches(0.46), sw2-Inches(0.15), Inches(0.88),
        size=10, color=LIGHT_GRAY)

# Output format card
box(s, rx, Inches(4.95), rw, Inches(1.3), CARD_BG)
box(s, rx, Inches(4.95), Inches(0.05), Inches(1.3), ACCENT)
txt(s, "Finding Output", rx+Inches(0.12), Inches(5.02), rw, Inches(0.34),
    size=13, bold=True, color=ACCENT)
txt(s,
    "rule_id: secrets/aws-access-key  ·  severity: CRITICAL\n"
    "file_path: src/config/AppConfig.java  ·  line_start: 42\n"
    "code_snippet: String awsKey = \"AKIA...\";  ·  message: Hardcoded AWS credential detected",
    rx+Inches(0.12), Inches(5.38), rw-Inches(0.15), Inches(0.82),
    size=10, color=LIGHT_GRAY)

txt(s, "Runs in parallel with SAST · Results streamed to UI · Same findings_reports schema · FP pipeline applied",
    0, SLIDE_H - Inches(0.38), SLIDE_W, Inches(0.35),
    size=10, color=LIGHT_GRAY, italic=True, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 8 — REACHABILITY ANALYSIS: PIPELINE + CIA TRIAD
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "Reachability Analysis — Pipeline & CIA Impact Scoring",
           "Call graph BFS · Taint tracking · CIA triad from CVSS vector · Risk = Reachability × CIA")

# ── Left: 4-step pipeline (compact) ──────────────────────────────────────
fx = Inches(0.25)
fw = Inches(5.75)

reach_flow = [
    (ACCENT,  "Step 1 — Call Graph Construction",
     "Static source analysis builds a directed call graph\nCaller → callee edges · Java class hierarchy · depth cap = 5\nEntry points: HTTP Servlets, @RestController, main(), public APIs"),
    (ACCENT2, "Step 2 — Taint Analysis (Source → Sink)",
     "Tracks user-controlled input from source to vulnerable sink\nSources: request.getParameter(), headers, form fields\nSinks: SQL execute(), Runtime.exec(), response.write()"),
    (YELLOW,  "Step 3 — Blast Radius BFS",
     "BFS traversal up the call graph from the vulnerable node\nCounts all unique callers (direct + transitive) reaching the vuln\nblast_radius stored per finding in findings_reports"),
    (RGBColor(0xFF,0x8C,0x00), "Step 4 — LLM Verdict",
     "Tier-2 LLM (llama3.2:3b) evaluates the full call path\nContext: entry points, taint path, call chain, code snippet\nVerdict: REACHABLE / NOT_REACHABLE / UNKNOWN"),
]
for i, (color, title, desc) in enumerate(reach_flow):
    fy = Inches(1.32) + i * Inches(1.47)
    box(s, fx, fy, fw, Inches(1.32), CARD_BG)
    box(s, fx, fy, Inches(0.05), Inches(1.32), color)
    txt(s, f"{i+1}. {title}", fx+Inches(0.12), fy+Inches(0.06), fw-Inches(0.15), Inches(0.34),
        size=12, bold=True, color=color)
    txt(s, desc, fx+Inches(0.12), fy+Inches(0.42), fw-Inches(0.15), Inches(0.84),
        size=10, color=LIGHT_GRAY)
    if i < len(reach_flow)-1:
        txt(s, "▼", fx+fw/2-Inches(0.25), fy+Inches(1.34), Inches(0.5), Inches(0.18),
            size=11, color=ACCENT, align=PP_ALIGN.CENTER)

# ── Right: CIA Triad + Verdicts ───────────────────────────────────────────
rx = Inches(6.3)
rw = Inches(6.7)

txt(s, "CIA Triad — Impact Scoring from CVSS Vector", rx, Inches(1.3), rw, Inches(0.4),
    size=15, bold=True, color=ACCENT)
txt(s, "Each reachable finding is scored against CIA using the CVSS v3 vector returned by OSV (C:H/I:H/A:H)",
    rx, Inches(1.72), rw, Inches(0.32), size=10, color=LIGHT_GRAY, italic=True)

cia = [
    (RED_LIGHT,   "C — Confidentiality",
     "Can an attacker exfiltrate data?\nSQL injection leaking records · Path traversal\nexposing files · SSRF reading internal services"),
    (YELLOW,      "I — Integrity",
     "Can an attacker modify data or execute code?\nCommand injection · Deserialization RCE\nCSRF modifying state · Stored XSS"),
    (ACCENT2,     "A — Availability",
     "Can an attacker cause denial of service?\nResource exhaustion · ReDoS · Infinite loop\nUncontrolled recursion consuming heap"),
]
for i, (color, label, desc) in enumerate(cia):
    cy = Inches(2.1) + i * Inches(1.3)
    cw2 = rw
    box(s, rx, cy, cw2, Inches(1.18), CARD_BG)
    box(s, rx, cy, Inches(0.05), Inches(1.18), color)
    badge(s, label, rx+Inches(0.12), cy+Inches(0.09), Inches(2.4), Inches(0.33), color)
    txt(s, desc, rx+Inches(2.65), cy+Inches(0.06), cw2-Inches(2.8), Inches(1.05),
        size=10, color=LIGHT_GRAY)

# Risk formula banner
box(s, rx, Inches(6.03), rw, Inches(0.58), CARD_BG)
box(s, rx, Inches(6.03), Inches(0.05), Inches(0.58), YELLOW)
txt(s, "Risk Score  =  Reachability Verdict  ×  CIA Impact  ×  CVSS Exploitability",
    rx+Inches(0.12), Inches(6.07), rw-Inches(0.15), Inches(0.32),
    size=12, bold=True, color=YELLOW)
txt(s, "REACHABLE + C:H/I:H + AV:Network → CRITICAL priority  ·  Findings sorted by Risk Score in UI",
    rx+Inches(0.12), Inches(6.39), rw-Inches(0.15), Inches(0.2),
    size=9, color=LIGHT_GRAY)

txt(s, "Reachable findings surface first in developer queue · Reduces MTTR by eliminating noise from unreachable vulns",
    0, SLIDE_H - Inches(0.38), SLIDE_W, Inches(0.35),
    size=10, color=LIGHT_GRAY, italic=True, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 9 — ECLIPSE STEADY + TAINT ANALYSIS INTEGRATION
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "Eclipse Steady & Taint Analysis — Deep Reachability Integration",
           "Function-level CVE reachability · Static + dynamic · Taint source-to-sink tracking")

# ── Left: Eclipse Steady ──────────────────────────────────────────────────
fx = Inches(0.25)
fw = Inches(6.1)

txt(s, "Eclipse Steady Integration", fx, Inches(1.28), fw, Inches(0.42),
    size=16, bold=True, color=ACCENT)
txt(s, "Formerly SAP Vulas — purpose-built for SCA + function-level reachability combined",
    fx, Inches(1.7), fw, Inches(0.3), size=10, color=LIGHT_GRAY, italic=True)

steady_steps = [
    (ACCENT,  "Why Eclipse Steady?",
     "OSV says 'this library version has a CVE'\nEclipse Steady answers: 'is the specific vulnerable\nfunction in that library actually called by your app?'\nEliminates false alarms from unused vulnerable code"),
    (ACCENT2, "Static Call Graph Tracing",
     "After SCA finds a CVE (e.g. Log4Shell in log4j-core)\nSteady traces call graph from your app into the\nvulnerable library method (e.g. JndiLookup.lookup())\nVerdict: function_reachable = true / false"),
    (YELLOW,  "Dynamic Analysis (Runtime Confirmation)",
     "Instruments JVM during test suite execution\nCaptures actual method invocations at runtime\nCatches reflection, dynamic proxies, Spring AOP calls\nthat static analysis cannot see"),
    (RGBColor(0xFF,0x8C,0x00), "Integration Point in Pipeline",
     "Triggers after SCA agent finds HIGH/CRITICAL CVEs\nRuns in parallel with FP pipeline (Step 2 → Step 3)\nUpgrades SCA finding: library_vulnerable → function_reachable\nResult stored in findings_reports.blast_radius + metadata"),
]
for i, (color, title, desc) in enumerate(steady_steps):
    sy2 = Inches(2.06) + i * Inches(1.28)
    box(s, fx, sy2, fw, Inches(1.15), CARD_BG)
    box(s, fx, sy2, Inches(0.05), Inches(1.15), color)
    txt(s, title, fx+Inches(0.12), sy2+Inches(0.06), fw-Inches(0.15), Inches(0.32),
        size=12, bold=True, color=color)
    txt(s, desc, fx+Inches(0.12), sy2+Inches(0.4), fw-Inches(0.15), Inches(0.7),
        size=10, color=LIGHT_GRAY)
    if i < len(steady_steps)-1:
        txt(s, "▼", fx+fw/2-Inches(0.2), sy2+Inches(1.17), Inches(0.4), Inches(0.16),
            size=10, color=ACCENT, align=PP_ALIGN.CENTER)

# ── Right: Taint Analysis + CVSS Exploitability + Integration Map ─────────
rx = Inches(6.65)
rw = Inches(6.35)

txt(s, "Taint Analysis — Source to Sink Tracking", rx, Inches(1.28), rw, Inches(0.42),
    size=15, bold=True, color=ACCENT2)

taint_items = [
    (ACCENT2, "Taint Sources (User-Controlled Input)",
     "request.getParameter() · request.getHeader()\ngetInputStream() · cookie values\nCLI args (args[]) · Environment variables"),
    (GREEN_LIGHT, "Taint Sinks (Dangerous Operations)",
     "SQL: Statement.execute() · PreparedStatement\nOS: Runtime.exec() · ProcessBuilder\nOutput: response.write() · PrintWriter.print()"),
    (RED_LIGHT, "Taint Propagation Rules",
     "String concatenation with tainted value → tainted\nMethod return value if arg is tainted → tainted\nSanitiser calls (encode, escape, validate) → untaint"),
]
for i, (color, title, desc) in enumerate(taint_items):
    ty2 = Inches(1.78) + i * Inches(1.32)
    box(s, rx, ty2, rw, Inches(1.18), CARD_BG)
    box(s, rx, ty2, Inches(0.05), Inches(1.18), color)
    txt(s, title, rx+Inches(0.12), ty2+Inches(0.07), rw-Inches(0.15), Inches(0.32),
        size=11, bold=True, color=color)
    txt(s, desc, rx+Inches(0.12), ty2+Inches(0.41), rw-Inches(0.15), Inches(0.72),
        size=10, color=LIGHT_GRAY)

# CVSS Exploitability sub-score panel
box(s, rx, Inches(5.78), rw, Inches(0.78), CARD_BG)
box(s, rx, Inches(5.78), Inches(0.05), Inches(0.78), YELLOW)
txt(s, "CVSS v3 Exploitability Sub-Score",
    rx+Inches(0.12), Inches(5.82), rw, Inches(0.3),
    size=12, bold=True, color=YELLOW)
txt(s,
    "AV: Network (N) > Adjacent (A) > Local (L)  ·  AC: Low (L) > High (H)\n"
    "PR: None (N) > Low (L) > High (H)  ·  UI: None (N) > Required (R)\n"
    "Network + Low complexity + No privileges = highest exploitability weight",
    rx+Inches(0.12), Inches(6.12), rw-Inches(0.15), Inches(0.38),
    size=9, color=LIGHT_GRAY)

txt(s, "Eclipse Steady + Taint + CIA + CVSS Exploitability = complete exploitability picture beyond simple CVE presence",
    0, SLIDE_H - Inches(0.38), SLIDE_W, Inches(0.35),
    size=10, color=LIGHT_GRAY, italic=True, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 10 — LLM ARCHITECTURE (OLLAMA)
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "LLM Architecture — Ollama Local Inference",
           "Two-tier model strategy: accuracy vs speed — fully local, no cloud dependency")

# Centre diagram
cx = Inches(0.3)

# Tier 1
box(s, cx, Inches(1.35), Inches(5.9), Inches(2.5), CARD_BG)
box(s, cx, Inches(1.35), Inches(0.06), Inches(2.5), ACCENT)
txt(s, "TIER 1  —  High-Accuracy Model", cx+Inches(0.15), Inches(1.42),
    Inches(5.7), Inches(0.4), size=15, bold=True, color=ACCENT)
txt(s, "qwen2.5-coder : 14b-instruct-q5_K_M",
    cx+Inches(0.15), Inches(1.85), Inches(5.7), Inches(0.45),
    size=20, bold=True, color=YELLOW)
tier1_use = [
    "SAST FP analysis — complex code reasoning",
    "High-stakes CWE arbitration (SQLi, XSS, RCE…)",
    "Confidence escalation fallback",
    "Code Review per-file vulnerability analysis",
]
for i, u in enumerate(tier1_use):
    txt(s, f"  ▸  {u}", cx+Inches(0.15), Inches(2.35)+i*Inches(0.27),
        Inches(5.7), Inches(0.26), size=11, color=LIGHT_GRAY)

# Tier 2
box(s, cx, Inches(4.1), Inches(5.9), Inches(2.5), CARD_BG)
box(s, cx, Inches(4.1), Inches(0.06), Inches(2.5), ACCENT2)
txt(s, "TIER 2  —  Fast Routing Model", cx+Inches(0.15), Inches(4.17),
    Inches(5.7), Inches(0.4), size=15, bold=True, color=ACCENT2)
txt(s, "llama3.2 : 3b",
    cx+Inches(0.15), Inches(4.6), Inches(5.7), Inches(0.45),
    size=20, bold=True, color=YELLOW)
tier2_use = [
    "FP Challenger — initial screening of REAL findings",
    "CVE class extraction from advisory text",
    "Reachability verdict (REACHABLE / NOT_REACHABLE)",
    "Standard SAST findings — fast classification",
]
for i, u in enumerate(tier2_use):
    txt(s, f"  ▸  {u}", cx+Inches(0.15), Inches(5.1)+i*Inches(0.27),
        Inches(5.7), Inches(0.26), size=11, color=LIGHT_GRAY)

# Right column: Ollama infra
rx = Inches(6.55)
rw = Inches(6.45)

box(s, rx, Inches(1.35), rw, Inches(1.6), CARD_BG)
box(s, rx, Inches(1.35), Inches(0.06), Inches(1.6), YELLOW)
txt(s, "Ollama Runtime", rx+Inches(0.15), Inches(1.42), rw, Inches(0.4),
    size=14, bold=True, color=YELLOW)
txt(s, "Local HTTP API  ·  http://localhost:11434\nApple Silicon Metal GPU acceleration\nConcurrent generation: OLLAMA_NUM_PARALLEL=2",
    rx+Inches(0.15), Inches(1.85), rw-Inches(0.2), Inches(0.95),
    size=12, color=LIGHT_GRAY)

infra_cards = [
    (ACCENT,  "Escalation Logic",
     "confidence < 0.60 → auto-escalate Tier-2 → Tier-1\nHigh-stakes CWEs always start on Tier-1\nUp to 2 LLM calls per finding for accuracy"),
    (ACCENT2, "Prompt Engineering",
     "YAML prompt store (versioned v1.0)\nSystem + user role separation\nCode wrapped in <user_code> tags (injection defence)"),
    (YELLOW,  "Vector Memory",
     "UniXcoder embeddings (dim=768)\nTop-5 similar past decisions injected as context\nPostgreSQL pgvector cosine similarity search"),
    (RED_LIGHT,"Structured Output",
     "JSON schema: verdict · confidence · fp_category · reasoning\nStrict parse with fallback ESCALATED on failure\nmax_tokens=2048 (thinking model headroom)"),
]
for i, (color, title, desc) in enumerate(infra_cards):
    iy = Inches(3.1) + i * Inches(1.06)
    box(s, rx, iy, rw, Inches(0.95), CARD_BG)
    box(s, rx, iy, Inches(0.05), Inches(0.95), color)
    txt(s, title, rx+Inches(0.12), iy+Inches(0.06), rw, Inches(0.32),
        size=12, bold=True, color=color)
    txt(s, desc, rx+Inches(0.12), iy+Inches(0.38), rw-Inches(0.15), Inches(0.52),
        size=10, color=LIGHT_GRAY)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 10 — AGENT DESCRIPTIONS
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "Security Agents — Capabilities & Responsibilities",
           "Six specialised agents run in an orchestrated pipeline for each scan")

agents = [
    (ACCENT,  "SAST Agent",
     ["Semgrep OSS in Docker sandbox",
      "42 OWASP + custom YAML rules",
      "Java, Python, JS support",
      "CWE mapping + OWASP category",
      "Code snippet extraction from source"]),
    (ACCENT2, "SpotBugs Agent",
     ["Java bytecode static analysis",
      "FindSecBugs security plugin",
      "112 security bug patterns",
      "Runs against compiled .class files",
      "Source snippet resolved from classpath"]),
    (YELLOW,  "SCA Agent",
     ["Software composition analysis",
      "Maven pom.xml dependency parse",
      "OSV / NVD CVE database lookup",
      "CVSS score + fix version",
      "85 CVEs detected per scan"]),
    (RGBColor(0xFF,0x8C,0x00), "Secret Scanner",
     ["Regex + entropy-based detection",
      "API keys, tokens, passwords",
      "95 source files scanned",
      "No false-positive on test fixtures",
      "File + line + secret type reported"]),
    (RED_LIGHT, "Code Review Agent",
     ["Per-file LLM security review",
      "Tier-1 LLM for deep analysis",
      "Identifies issues Semgrep misses",
      "Outputs severity + description",
      "Runs concurrently post-SAST"]),
    (GREEN_LIGHT, "FP Challenger",
     ["Re-evaluates REAL/ESCALATED findings",
      "Tier-2 LLM for speed at scale",
      "Detects false positives missed by L3",
      "fp_found counter tracks reversals",
      "Updates fp_decisions in DB"]),
]

cw = Inches(4.15)
ch = Inches(2.6)
for i, (color, title, bullets) in enumerate(agents):
    col = i % 3
    row = i // 3
    lx = Inches(0.22) + col * (cw + Inches(0.22))
    ty = Inches(1.3) + row * (ch + Inches(0.18))
    card(s, title, bullets, lx, ty, cw, ch, color, bullet_size=12)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 11 — DATA FLOW & PERSISTENCE
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "Data Flow & Persistence Layer",
           "PostgreSQL + pgvector · Async connection pool · Real-time SSE streaming to UI")

# Tables
tables = [
    (ACCENT,  "workflow_runs",      ["run_id (PK)", "state: pending→running→completed", "metadata JSONB (fp_summary, scan stats)", "created_at / completed_at"]),
    (ACCENT2, "findings_reports",   ["id (UUID PK)", "run_id, rule_id, cwe_id, severity", "file_path, line_start, code_snippet", "blast_radius, is_baseline"]),
    (YELLOW,  "fp_decisions",       ["finding_id (FK)", "verdict: REAL|FP|ESCALATED", "confidence 0.0–1.0", "reasoning, fp_category, source"]),
    (RGBColor(0xFF,0x8C,0x00), "finding_embeddings", ["finding_id (FK)", "embedding vector(768)", "UniXcoder model", "pgvector cosine search"]),
    (RED_LIGHT,"pg_jobs",           ["run_id, job_type", "state: pending→processing→done", "Async job queue", "Watchdog SLA monitoring"]),
    (GREEN_LIGHT,"human_labels",    ["finding_id (FK)", "verdict: REAL|FP", "fp_category, reviewer", "Feedback loop for training"]),
]

tw = Inches(4.1)
th = Inches(2.42)
for i, (color, title, rows) in enumerate(tables):
    col = i % 3
    row = i // 3
    lx = Inches(0.22) + col * (tw + Inches(0.22))
    ty = Inches(1.3) + row * (th + Inches(0.18))
    card(s, title, rows, lx, ty, tw, th, color, bullet_size=12)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 12 — KEY BENEFITS
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "Key Benefits & Business Value",
           "Why SSDLC outperforms traditional scanners")

benefits = [
    (ACCENT,  "🔒  Air-Gap Ready",
     "Fully local LLM inference via Ollama. No source code, no findings, no API keys leave the network. Ideal for regulated industries."),
    (ACCENT2, "🧠  Intelligent FP Reduction",
     "3-layer pipeline (rules → LLM → challenger) eliminates noise. Only genuine vulnerabilities reach developers — no alert fatigue."),
    (YELLOW,  "⚡  Fast End-to-End",
     "All 4 scanners run in parallel. Full pipeline (SAST + SCA + Secrets + SpotBugs + FP + Code Review) completes in under 5 minutes."),
    (RGBColor(0xFF,0x8C,0x00), "🎯  Context-Aware Analysis",
     "LLM sees actual vulnerable code lines with 3-line context. Understands framework, CWE, and call path — not just pattern matching."),
    (RED_LIGHT,"📊  Blast Radius Enrichment",
     "Call graph analysis identifies which functions/classes are affected by each vulnerability. Prioritises findings by reachability."),
    (GREEN_LIGHT,"🔄  Continuous Learning",
     "Human label feedback stored in human_labels table. Vector memory injects similar past decisions as LLM context — improves over time."),
]

bw = Inches(4.1)
bh = Inches(2.42)
for i, (color, title, desc) in enumerate(benefits):
    col = i % 3
    row = i // 3
    lx = Inches(0.22) + col * (bw + Inches(0.22))
    ty = Inches(1.3) + row * (bh + Inches(0.18))
    box(s, lx, ty, bw, bh, CARD_BG)
    box(s, lx, ty, Inches(0.05), bh, color)
    txt(s, title, lx+Inches(0.12), ty+Inches(0.1), bw-Inches(0.15), Inches(0.42),
        size=14, bold=True, color=color)
    txt(s, desc, lx+Inches(0.12), ty+Inches(0.55), bw-Inches(0.2), bh-Inches(0.65),
        size=12, color=LIGHT_GRAY, wrap=True)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 13 — TECH STACK
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "Technology Stack",
           "Production-grade open-source components — zero proprietary cloud lock-in")

categories = [
    ("Backend",       ACCENT,  ["Python 3.9+",  "FastAPI (async)", "asyncpg", "httpx", "Pydantic v2", "python-dotenv"]),
    ("LLM / AI",      ACCENT2, ["Ollama runtime", "qwen2.5-coder:14b", "llama3.2:3b", "UniXcoder (embeddings)", "pgvector", "Two-tier strategy"]),
    ("SAST Tools",    YELLOW,  ["Semgrep OSS", "SpotBugs 4.x", "FindSecBugs", "Docker sandbox", "42 OWASP rules", "Custom rule packs"]),
    ("Database",      RGBColor(0xFF,0x8C,0x00), ["PostgreSQL 15+", "pgvector extension", "asyncpg pool", "JSONB metadata", "Vector dim=768", "Connection pool 2–10"]),
    ("Frontend",      RED_LIGHT, ["React 18", "TypeScript", "Vite", "SSE streaming", "Tailwind CSS", "Command Centre UI"]),
    ("Infra / DevOps",GREEN_LIGHT, ["Docker (Semgrep)", "Apple Silicon Metal GPU", "Async job queue (pg_jobs)", "Watchdog SLA monitor", "Air-gap deployable", "Local-first"]),
]

cw = Inches(4.1)
ch = Inches(2.5)
for i, (title, color, items) in enumerate(categories):
    col = i % 3
    row = i // 3
    lx = Inches(0.22) + col * (cw + Inches(0.22))
    ty = Inches(1.3) + row * (ch + Inches(0.2))
    card(s, title, items, lx, ty, cw, ch, color, bullet_size=12)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 14 — METRICS & PERFORMANCE
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
header_bar(s, "Performance Metrics — JavaVulnerableLab Benchmark",
           "236 Java files · 14 Maven dependencies · Real-world vulnerable application")

metrics = [
    (ACCENT,     "41",    "Semgrep\nFindings"),
    (ACCENT2,    "112",   "SpotBugs\nFindings"),
    (YELLOW,     "85",    "CVE\nFindings"),
    (RED_LIGHT,  "3",     "Secrets\nDetected"),
    (GREEN_LIGHT,"~20%",  "FP\nEliminated"),
    (RGBColor(0xFF,0x8C,0x00), "<5 min", "Full Pipeline\nDuration"),
]

mw = Inches(2.0)
mh = Inches(1.8)
gap_m = Inches(0.18)
start_mx = (SLIDE_W - (6 * mw + 5 * gap_m)) / 2

for i, (color, value, label) in enumerate(metrics):
    mx = start_mx + i * (mw + gap_m)
    my = Inches(1.45)
    box(s, mx, my, mw, mh, CARD_BG)
    box(s, mx, my, mw, Inches(0.07), color)
    txt(s, value, mx, my+Inches(0.2), mw, Inches(0.85),
        size=36, bold=True, color=color, align=PP_ALIGN.CENTER)
    txt(s, label, mx, my+Inches(1.0), mw, Inches(0.7),
        size=11, color=LIGHT_GRAY, align=PP_ALIGN.CENTER)

# Pipeline timing breakdown
timing = [
    ("Graph Build",   "< 1s",  ACCENT),
    ("Semgrep Scan",  "~11s",  ACCENT2),
    ("SpotBugs",      "~7s",   YELLOW),
    ("SCA / Secrets", "~2s",   RGBColor(0xFF,0x8C,0x00)),
    ("FP Pipeline",   "~70s",  RED_LIGHT),
    ("Code Review",   "~60s",  GREEN_LIGHT),
    ("FP Challenger", "~45s",  ACCENT),
]
txt(s, "Pipeline Stage Timing", Inches(0.3), Inches(3.55), Inches(12), Inches(0.4),
    size=15, bold=True, color=WHITE)

bar_y = Inches(4.05)
bar_h = Inches(0.55)
total_seconds = 190
bar_total_w = Inches(12.3)
offset = Inches(0.3)
for stage, timing_val, color in timing:
    # Proportional width (approximate)
    secs_map = {"< 1s": 1, "~11s": 11, "~7s": 7, "~2s": 2, "~70s": 70, "~60s": 60, "~45s": 45}
    secs = secs_map.get(timing_val, 10)
    w = bar_total_w * secs / total_seconds
    box(s, offset, bar_y, max(w, Inches(0.5)), bar_h, color)
    # label inside bar if wide enough
    if w > Inches(0.7):
        txt(s, f"{stage}\n{timing_val}", offset+Inches(0.04), bar_y,
            w-Inches(0.06), bar_h, size=8, bold=True, color=DARK_BG, align=PP_ALIGN.CENTER)
    offset += w + Inches(0.02)

txt(s, "⚡ Steps 2–4 run in parallel — wall-clock time dominated by LLM calls (FP pipeline + Code Review)",
    0, Inches(4.75), SLIDE_W, Inches(0.35),
    size=11, color=LIGHT_GRAY, italic=True, align=PP_ALIGN.CENTER)

# Verdict distribution
txt(s, "Typical Verdict Distribution (Semgrep 41 findings)",
    Inches(0.3), Inches(5.2), Inches(12), Inches(0.4),
    size=14, bold=True, color=WHITE)

vd = [("REAL  ~66%", ACCENT, 0.66), ("FP  ~20%", GREEN_LIGHT, 0.20), ("ESCALATED  ~14%", YELLOW, 0.14)]
bar_y2 = Inches(5.7)
bh2    = Inches(0.65)
offset2 = Inches(0.3)
for label, color, pct in vd:
    w = bar_total_w * pct
    box(s, offset2, bar_y2, w, bh2, color)
    txt(s, label, offset2+Inches(0.08), bar_y2,
        w-Inches(0.1), bh2, size=12, bold=True, color=DARK_BG, align=PP_ALIGN.CENTER)
    offset2 += w + Inches(0.04)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE 15 — ROADMAP / CLOSING
# ════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(blank_layout)
bg(s)
box(s, 0, 0, Inches(0.12), SLIDE_H, ACCENT)
box(s, 0, SLIDE_H - Inches(0.08), SLIDE_W, Inches(0.08), ACCENT2)

txt(s, "SSDLC Platform",
    Inches(0.3), Inches(0.25), Inches(12.7), Inches(0.65),
    size=32, bold=True, color=ACCENT, align=PP_ALIGN.CENTER)
txt(s, "Secure • Intelligent • Local • Fast",
    Inches(0.3), Inches(0.9), Inches(12.7), Inches(0.45),
    size=18, color=LIGHT_GRAY, italic=True, align=PP_ALIGN.CENTER)

phases = [
    ("Phase 0  ✅", "Foundation",   ["Multi-agent scan pipeline", "Ollama LLM integration", "FP pipeline (L1+L3)", "PostgreSQL + pgvector", "React Command Centre UI"]),
    ("Phase 1  🔄", "Enterprise",   ["HashiCorp Vault secrets", "Gitea prompt versioning", "CodeQL integration", "CI/CD webhook triggers", "Multi-repo scanning"]),
    ("Phase 2  📋", "Intelligence", ["Fine-tuned security model", "Automated rule generation", "Cross-scan trend analysis", "SBOM generation", "Compliance reporting"]),
]

pw = Inches(4.1)
ph = Inches(4.5)
for i, (phase, subtitle, items) in enumerate(phases):
    px = Inches(0.3) + i * (pw + Inches(0.22))
    py = Inches(1.5)
    colors_p = [ACCENT, YELLOW, ACCENT2]
    card(s, f"{phase} — {subtitle}", items, px, py, pw, ph, colors_p[i])

txt(s, "Built on open-source · Local-first · Developer-friendly · Air-gap deployable",
    0, SLIDE_H - Inches(0.42), SLIDE_W, Inches(0.35),
    size=12, color=LIGHT_GRAY, italic=True, align=PP_ALIGN.CENTER)


# ── Save ─────────────────────────────────────────────────────────────────────
out = "/Users/nitinpatil/IdeaProjects/RAgenticAI/SSDLC_Platform_Technical.pptx"
prs.save(out)
print(f"Saved: {out}")
