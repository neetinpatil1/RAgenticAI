"""
tools/cve_enricher.py
======================
Enriches a CVE ID with the specific vulnerable class/method.

Priority order:
  1. Hardcoded known-CVE map (fastest, most accurate for famous CVEs)
  2. OSV.dev API — affected[].ecosystem_specific.affected_functions (when available, ~30% of CVEs)
  3. LLM extraction from CVE description (fallback for the other ~70%)

Returns a dict: {
    "vuln_id": str,
    "affected_classes": list[str],   # e.g. ["org.apache.logging.log4j.core.lookup.JndiLookup"]
    "affected_methods": list[str],   # e.g. ["lookup"]
    "source": str                    # "known-map" | "osv-api" | "llm" | "unknown"
}
"""
from __future__ import annotations
import json
import logging
from typing import Optional
import httpx
from core.config import settings
from core.llm_client import llm_chat

logger = logging.getLogger(__name__)

# Famous CVEs with known affected classes — hardcoded for reliability
_KNOWN_CVE_MAP: dict[str, dict] = {
    "CVE-2021-44228": {  # Log4Shell
        "classes": ["org.apache.logging.log4j.core.lookup.JndiLookup"],
        "methods": ["lookup"],
        "packages": ["log4j-core"],
    },
    "CVE-2021-45046": {  # Log4Shell bypass
        "classes": ["org.apache.logging.log4j.core.lookup.JndiLookup"],
        "methods": ["lookup"],
        "packages": ["log4j-core"],
    },
    "CVE-2022-22965": {  # Spring4Shell
        "classes": ["org.springframework.web.util.pattern.PathPatternParser",
                    "org.springframework.beans.CachedIntrospectionResults"],
        "methods": [],
        "packages": ["spring-webmvc", "spring-web"],
    },
    "CVE-2017-5638": {  # Apache Struts RCE
        "classes": ["org.apache.struts2.dispatcher.multipart.JakartaMultiPartRequest"],
        "methods": [],
        "packages": ["struts2-core"],
    },
    "CVE-2017-7525": {  # Jackson deserialization
        "classes": ["com.fasterxml.jackson.databind.ObjectMapper",
                    "com.fasterxml.jackson.databind.deser.BeanDeserializerFactory"],
        "methods": ["readValue", "enableDefaultTyping"],
        "packages": ["jackson-databind"],
    },
    "CVE-2019-12384": {  # Jackson deserialization
        "classes": ["com.fasterxml.jackson.databind.ObjectMapper"],
        "methods": ["readValue"],
        "packages": ["jackson-databind"],
    },
    "CVE-2020-36518": {  # Jackson stack overflow
        "classes": ["com.fasterxml.jackson.databind.ObjectMapper"],
        "methods": ["readValue", "readTree"],
        "packages": ["jackson-databind"],
    },
    "CVE-2022-42004": {  # Jackson deserialization
        "classes": ["com.fasterxml.jackson.databind.ObjectMapper"],
        "methods": ["readValue"],
        "packages": ["jackson-databind"],
    },
    "CVE-2018-7489": {  # Jackson deserialization
        "classes": ["com.fasterxml.jackson.databind.ObjectMapper"],
        "methods": ["enableDefaultTyping"],
        "packages": ["jackson-databind"],
    },
}


async def enrich_cve(vuln_id: str) -> dict:
    """Return affected classes/methods for a CVE ID."""
    # 1. Known-map first
    key = vuln_id.upper()
    if key in _KNOWN_CVE_MAP:
        entry = _KNOWN_CVE_MAP[key]
        logger.info("CVE enricher | vuln=%s source=known-map classes=%s", vuln_id, entry["classes"])
        return {
            "vuln_id": vuln_id,
            "affected_classes": entry["classes"],
            "affected_methods": entry["methods"],
            "source": "known-map",
        }

    # 2. OSV.dev API
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"https://api.osv.dev/v1/vulns/{vuln_id}")
            if r.status_code == 200:
                data = r.json()

                # Check OSV aliases (e.g. GHSA → CVE) against known map before
                # doing any further parsing — gives us the most accurate class data.
                for alias in data.get("aliases", []):
                    alias_key = alias.upper()
                    if alias_key in _KNOWN_CVE_MAP:
                        entry = _KNOWN_CVE_MAP[alias_key]
                        logger.info(
                            "CVE enricher | vuln=%s alias=%s source=known-map classes=%s",
                            vuln_id, alias, entry["classes"],
                        )
                        return {
                            "vuln_id": vuln_id,
                            "affected_classes": entry["classes"],
                            "affected_methods": entry["methods"],
                            "source": "known-map",
                        }

                classes = []
                for affected in data.get("affected", []):
                    es = affected.get("ecosystem_specific") or {}
                    for fn in es.get("affected_functions", []):
                        # fn may be "org.foo.Bar.method" — extract class
                        parts = fn.rsplit(".", 1)
                        classes.append(parts[0] if len(parts) == 2 else fn)
                if classes:
                    logger.info("CVE enricher | vuln=%s source=osv-api classes=%s", vuln_id, classes)
                    return {
                        "vuln_id": vuln_id,
                        "affected_classes": list(dict.fromkeys(classes)),
                        "affected_methods": [],
                        "source": "osv-api",
                    }
                # Fall through to LLM with the description
                description = (data.get("summary") or "") + " " + (data.get("details") or "")
                if description.strip():
                    classes = await _extract_classes_with_llm(vuln_id, description)
                    if classes:
                        return {
                            "vuln_id": vuln_id,
                            "affected_classes": classes,
                            "affected_methods": [],
                            "source": "llm",
                        }
    except Exception as exc:
        logger.warning("CVE enricher | vuln=%s OSV fetch failed: %s", vuln_id, exc)

    logger.info("CVE enricher | vuln=%s source=unknown — no class mapping found", vuln_id)
    return {
        "vuln_id": vuln_id,
        "affected_classes": [],
        "affected_methods": [],
        "source": "unknown",
    }


async def _extract_classes_with_llm(vuln_id: str, description: str) -> list[str]:
    """Ask LLM to extract Java class names from CVE description."""
    try:
        prompt = (
            f"CVE ID: {vuln_id}\n"
            f"Description: {description[:800]}\n\n"
            "Extract the specific Java class names (fully qualified, e.g. org.foo.Bar) "
            "that contain the vulnerability. Return ONLY a JSON array of strings. "
            "If no specific class is mentioned, return []. "
            'Example: ["com.example.VulnClass"]'
        )
        content = await llm_chat(
            tier="tier2",
            messages=[{"role": "user", "content": prompt}],
            json_mode=True,
            max_tokens=1024,
            timeout=settings.llm.request_timeout,
        )
        # Parse JSON from response — model may return bare array OR wrapped object
        cleaned = content.strip()
        parsed = json.loads(cleaned)
        if isinstance(parsed, list):
            classes = parsed
        elif isinstance(parsed, dict):
            # format:json wraps array — look for any list value
            classes = next(
                (v for v in parsed.values() if isinstance(v, list)), []
            )
        else:
            classes = []
        return [c for c in classes if isinstance(c, str) and "." in c]
    except Exception as exc:
        logger.warning("CVE enricher LLM | vuln=%s error=%s", vuln_id, str(exc) or type(exc).__name__)
    return []
