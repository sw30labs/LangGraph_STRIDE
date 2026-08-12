"""Geopolitical threat-research feeds → CTI packs.

Vendor research blogs are the richest free geopolitical CTI: Securelist
(Kaspersky) and the Microsoft Security Blog track nation-state campaigns with
actor naming and ATT&CK references. Same deal as the CISA advisory feed —
public RSS, no API key, offline file ingest first-class. Items without
attribution hints are dropped by default so the library stays dense with
geopolitical signal rather than generic security news.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import httpx

from src.config import PathConfig
from src.intel.advisories import ACTOR_HINTS, TECHNIQUE_ID, _slug, html_to_text
from src.intel.cti import DESC_HINTS, delete_cti_pack, list_cti_packs, upsert_cti_pack
from src.intel.manifest import now_iso, patch_catalog

FEEDS: dict[str, dict[str, str]] = {
    "msft-security": {
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "label": "Microsoft Security Blog",
        "source": "msft-security",
    },
    "securelist": {
        "url": "https://securelist.com/feed/",
        "label": "Securelist (Kaspersky) threat research",
        "source": "securelist",
    },
}


def feed_keys() -> list[str]:
    return sorted(FEEDS)


def _item_text(item: ElementTree.Element, tag: str) -> str:
    node = item.find(tag)
    return (node.text or "").strip() if node is not None else ""


def parse_feed_rows(xml_text: str, *, limit: int = 25) -> list[dict[str, str]]:
    """Parse a plain RSS 2.0 feed into listing rows (newest first)."""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise ValueError(f"Invalid RSS/XML payload: {exc}") from exc
    items = root.findall(".//item")
    if not items:
        raise ValueError("RSS payload has no <item> entries")
    rows = []
    for item in items[: max(1, int(limit))]:
        rows.append(
            {
                "title": _item_text(item, "title"),
                "link": _item_text(item, "link"),
                "published": _item_text(item, "pubDate"),
                "summary": _item_text(item, "description"),
            }
        )
    return rows


def geointel_row_to_pack(
    feed_key: str,
    title: str,
    link: str,
    published: str,
    summary: str,
    *,
    body: str = "",
    attributed_only: bool = True,
) -> dict[str, Any] | None:
    """Map one feed item onto a CTI pack; None when it carries no attribution
    hints and ``attributed_only`` is set (keeps packs geopolitically dense)."""
    feed = FEEDS[feed_key]
    summary_text = html_to_text(summary, limit=2000) if "<" in summary else summary.strip()
    blob = f"{title} {summary_text} {body}"
    actors = sorted({label for pattern, label in ACTOR_HINTS if pattern.search(blob)})
    if attributed_only and not actors:
        return None
    techniques: set[str] = set()
    for pattern, tids in DESC_HINTS:
        if pattern.search(blob):
            techniques.update(tids)
    techniques.update(tid.upper() for tid in TECHNIQUE_ID.findall(body))
    sections = [
        f"Feed item: {title}",
        f"Published: {published or 'n/a'}",
        f"Link: {link or 'n/a'}",
        f"Attribution hints: {', '.join(actors) or 'none detected'}",
        "",
        summary_text[:2000],
    ]
    if body:
        sections.extend(["", "Article body (excerpt):", body[:2500]])
    sections.extend(["", f"Source: {feed['label']} (RSS)"])
    return {
        "id": f"{feed['source']}-{_slug(title)[:60]}",
        "title": f"{feed['label']}: {title}"[:120],
        "actors": actors,
        "techniques": sorted(techniques),
        "iocs": [],
        "notes": "\n".join(sections),
        "source": feed["source"],
    }


def packs_from_feed(
    feed_key: str,
    xml_text: str,
    *,
    limit: int = 25,
    attributed_only: bool = True,
    body_fetcher: Callable[[str], str] | None = None,
) -> list[dict[str, Any]]:
    """Parse one feed into CTI pack dicts (fetches article bodies when given)."""
    if feed_key not in FEEDS:
        raise ValueError(f"Unknown geointel feed: {feed_key}. Choose from {feed_keys()}")
    packs: dict[str, dict[str, Any]] = {}
    for row in parse_feed_rows(xml_text, limit=limit):
        body = ""
        if body_fetcher and row["link"]:
            with contextlib.suppress(Exception):
                body = body_fetcher(row["link"])
        pack = geointel_row_to_pack(
            feed_key,
            row["title"],
            row["link"],
            row["published"],
            row["summary"],
            body=body,
            attributed_only=attributed_only,
        )
        if pack is not None:
            packs[pack["id"]] = pack
    return list(packs.values())


def import_geointel(
    paths: PathConfig,
    feed_key: str,
    xml_text: str,
    *,
    limit: int = 25,
    attributed_only: bool = True,
    replace_previous: bool = True,
    body_fetcher: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    """Materialize geointel packs for one feed (per-source replace)."""
    packs = packs_from_feed(
        feed_key,
        xml_text,
        limit=limit,
        attributed_only=attributed_only,
        body_fetcher=body_fetcher,
    )
    source = FEEDS[feed_key]["source"]
    if replace_previous:
        for existing in list_cti_packs(paths):
            if str(existing.get("source") or "") == source:
                with contextlib.suppress(ValueError):
                    delete_cti_pack(paths, existing["id"])
    written = [upsert_cti_pack(paths, pack) for pack in packs]
    patch_catalog(
        paths,
        "cti",
        status="ready",
        pack_count=len(list_cti_packs(paths)),
        last_success_at=now_iso(),
        last_error=None,
        source=f"geointel:{source}",
    )
    return {
        "feed": feed_key,
        "written": len(written),
        "pack_count": len(list_cti_packs(paths)),
        "source": source,
    }


def import_geointel_file(
    paths: PathConfig,
    feed_key: str,
    path: Path | str,
    *,
    limit: int = 25,
    attributed_only: bool = True,
) -> dict[str, Any]:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"Geointel feed file not found: {source}")
    result = import_geointel(
        paths,
        feed_key,
        source.read_text(encoding="utf-8"),
        limit=limit,
        attributed_only=attributed_only,
    )
    result["source_file"] = str(source)
    return result


def update_geointel_online(
    paths: PathConfig,
    feed_key: str = "all",
    *,
    limit: int = 25,
    attributed_only: bool = True,
    client: httpx.Client | None = None,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Download live geointel feeds and materialize CTI packs.

    ``feed_key='all'`` pulls every registered feed. Each selected article
    page is fetched so packs carry full attribution text and explicit ATT&CK
    technique IDs, not just the RSS summary.
    """
    keys = feed_keys() if feed_key == "all" else [feed_key]
    for key in keys:
        if key not in FEEDS:
            raise ValueError(f"Unknown geointel feed: {key}. Choose from all, {feed_keys()}")
    owns_client = client is None
    # Some feeds 403 the default httpx UA; present a plain browser agent.
    http = client or httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; stride-geointel/1.0)"},
    )
    results = []
    errors: dict[str, str] = {}
    try:
        for key in keys:
            try:
                response = http.get(FEEDS[key]["url"])
                response.raise_for_status()
                xml_text = response.text

                def fetch_body(url: str) -> str:
                    page = http.get(url)
                    page.raise_for_status()
                    return html_to_text(page.text)

                results.append(
                    import_geointel(
                        paths,
                        key,
                        xml_text,
                        limit=limit,
                        attributed_only=attributed_only,
                        body_fetcher=fetch_body,
                    )
                )
            except Exception as exc:
                patch_catalog(
                    paths,
                    "cti",
                    status="error",
                    last_error=f"geointel:{key}: {type(exc).__name__}: {exc}",
                )
                errors[key] = f"{type(exc).__name__}: {exc}"
    finally:
        if owns_client:
            http.close()
    if not results:
        raise RuntimeError(f"geointel update failed for all feeds: {errors}")
    return {
        "feeds": results,
        "errors": errors,
        "written": sum(row["written"] for row in results),
        "pack_count": len(list_cti_packs(paths)),
    }
