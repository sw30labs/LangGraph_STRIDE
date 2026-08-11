"""Optional thin web spark via DuckDuckGo Instant Answer API.

Best-effort only: offline, timeout, or empty results never block a forge.
"""

from __future__ import annotations

import httpx


def duckduckgo_spark(query: str, *, timeout: float = 4.0) -> list[dict[str, str]]:
    """Return a few abstract/related topics; empty list on any failure."""
    q = (query or "").strip()
    if not q:
        return []
    try:
        with httpx.Client(timeout=timeout, trust_env=True) as client:
            response = client.get(
                "https://api.duckduckgo.com/",
                params={
                    "q": q,
                    "format": "json",
                    "no_html": "1",
                    "skip_disambig": "1",
                },
            )
            response.raise_for_status()
            payload = response.json()
    except Exception:
        return []

    sparks: list[dict[str, str]] = []
    abstract = str(payload.get("AbstractText") or "").strip()
    abstract_url = str(payload.get("AbstractURL") or "").strip()
    if abstract:
        sparks.append({"title": "Abstract", "text": abstract[:600], "url": abstract_url})

    for topic in (payload.get("RelatedTopics") or [])[:6]:
        if not isinstance(topic, dict):
            continue
        if topic.get("Topics") and isinstance(topic["Topics"], list):
            for nested in topic["Topics"][:2]:
                if isinstance(nested, dict) and nested.get("Text"):
                    sparks.append(
                        {
                            "title": str(nested.get("FirstURL") or "related")[:80],
                            "text": str(nested["Text"])[:400],
                            "url": str(nested.get("FirstURL") or ""),
                        }
                    )
            continue
        if topic.get("Text"):
            sparks.append(
                {
                    "title": str(topic.get("FirstURL") or "related")[:80],
                    "text": str(topic["Text"])[:400],
                    "url": str(topic.get("FirstURL") or ""),
                }
            )
    return sparks[:8]


def format_sparks_for_prompt(sparks: list[dict[str, str]]) -> str:
    if not sparks:
        return "(no external spark — rely on internal adversarial knowledge)"
    lines = []
    for index, spark in enumerate(sparks, start=1):
        lines.append(f"{index}. {spark.get('text', '')} [{spark.get('url', '')}]")
    return "\n".join(lines)


def default_search_query(card_id: str, steer: str) -> str:
    base = {
        "dark_matter": "novel MITRE ATT&CK intrusion chain techniques 2024 2025",
        "control_counter": "bypassing enterprise security controls living off the land",
        "app_adversary": "application-specific cyber attack techniques cloud SaaS",
        "blind_spot_fill": "underused MITRE ATT&CK tactics resource development collection",
    }.get(card_id, "advanced persistent threat technique chain")
    steer = (steer or "").strip()
    return f"{base} {steer}".strip() if steer else base
