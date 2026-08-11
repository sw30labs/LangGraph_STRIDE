"""CISA cybersecurity advisories → CTI packs.

Joint advisories (the AA-series, co-sealed with FBI/NSA and international
partners) are the most geopolitical free feed CISA publishes: nation-state
attribution, targeted sectors, and actor TTPs. I parse the public RSS listing
(no API key), keep the AA-numbered items, and map attribution/description hints
onto actors and ATT&CK techniques so packs can match attack chains. The online
path also fetches each advisory page so packs carry full attribution text and
the explicit ATT&CK IDs the advisories cite.

Offline ingest of a saved RSS/XML file stays first-class for air-gapped boxes
(summary text only — no page fetches without network).
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Callable
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import httpx

from src.config import PathConfig
from src.intel.cti import DESC_HINTS, delete_cti_pack, list_cti_packs, upsert_cti_pack
from src.intel.manifest import now_iso, patch_catalog

# Public CISA advisory listing (RSS, no auth).
CISA_ADVISORIES_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"

CISA_ADVISORY_SOURCE = "cisa-advisory"

# Joint advisories carry an AA number, e.g. AA25-141A; #StopRansomware guides
# are joint FBI/CISA publications without an AA number.
AA_NUMBER = re.compile(r"AA\d{2}-\d{3}[A-Z]?", re.I)
JOINT_TITLE = re.compile(r"#StopRansomware", re.I)

# Explicit ATT&CK technique IDs cited in advisory bodies.
TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


# Attribution hints → actor labels (geopolitical signal in advisory text).
def _actor(pattern: str, label: str) -> tuple[re.Pattern[str], str]:
    return (re.compile(pattern, re.I), label)


ACTOR_HINTS: list[tuple[re.Pattern[str], str]] = [
    _actor(
        r"\brussia(?:n)?\b|\bGRU\b|\bFSB\b|sandworm|apt ?28|apt ?29|cozy bear"
        r"|forest blizzard|star blizzard",
        "russia-nexus",
    ),
    _actor(
        r"\bchina\b|\bchinese\b|\bPRC\b|volt typhoon|salt typhoon|apt ?40|apt ?41"
        r"|brass typhoon",
        "prc-nexus",
    ),
    _actor(r"\bDPRK\b|north korea|lazarus|kimsuky|diamond sleet|jade sleet", "dprk-nexus"),
    _actor(r"\biran(?:ian)?\b|\bIRGC\b|muddywater|peach sandstorm|fox kitten", "iran-nexus"),
    _actor(r"\bransomware\b", "ransomware-operators"),
    _actor(r"\bhacktivis", "hacktivists"),
    _actor(
        r"\bcybercriminal|cyber criminal|crime syndicate|initial access broker",
        "cybercriminals",
    ),
]


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().casefold()).strip("-")
    return slug or "advisory"


def _strip_html(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()


def _item_text(item: ElementTree.Element, tag: str) -> str:
    node = item.find(tag)
    return (node.text or "").strip() if node is not None else ""


class _TextExtractor(HTMLParser):
    """Collect visible text from an advisory HTML page (no dependencies)."""

    def __init__(self) -> None:
        super().__init__()
        self._skip = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript", "svg"}:
            self._skip += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg"} and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str, *, limit: int = 8000) -> str:
    parser = _TextExtractor()
    # Malformed HTML still yields partial text.
    with contextlib.suppress(Exception):
        parser.feed(html)
    return re.sub(r"\s+", " ", " ".join(parser.parts)).strip()[:limit]


def advisory_row_to_pack(
    title: str,
    link: str,
    published: str,
    summary: str,
    *,
    body: str = "",
) -> dict[str, Any]:
    """Map one advisory listing row onto a CTI pack.

    ``body`` is the fetched advisory page text (online path only); hints and
    explicit ATT&CK IDs are mined from it when present.
    """
    summary = _strip_html(summary)
    blob = f"{title} {summary} {body}"
    actors = sorted({label for pattern, label in ACTOR_HINTS if pattern.search(blob)})
    techniques: set[str] = set()
    for pattern, tids in DESC_HINTS:
        if pattern.search(blob):
            techniques.update(tids)
    # Joint advisories cite ATT&CK IDs explicitly — trust those over hints.
    techniques.update(TECHNIQUE_ID.findall(body))
    techniques = {tid.upper() for tid in techniques}
    number = AA_NUMBER.search(title) or AA_NUMBER.search(link)
    if number:
        pack_id = f"cisa-adv-{number.group(0).casefold()}"
    else:
        pack_id = f"cisa-adv-{_slug(title)[:60]}"
    sections = [
        f"Advisory: {title}",
        f"Published: {published or 'n/a'}",
        f"Link: {link or 'n/a'}",
        f"Attribution hints: {', '.join(actors) or 'none detected'}",
        "",
        summary[:2000],
    ]
    if body:
        sections.extend(["", "Advisory body (excerpt):", body[:2500]])
    sections.extend(["", "Source: CISA cybersecurity advisories (RSS listing + advisory page)"])
    return {
        "id": pack_id,
        "title": f"CISA advisory: {title}"[:120],
        "actors": actors,
        "techniques": sorted(techniques),
        "iocs": [],
        "notes": "\n".join(sections),
        "source": CISA_ADVISORY_SOURCE,
    }


def parse_rss_rows(xml_text: str, *, limit: int = 25) -> list[dict[str, str]]:
    """Parse a CISA advisories RSS feed into listing rows.

    Prefers joint publications (AA-numbered advisories and #StopRansomware
    guides); falls back to the newest items when none are present.
    """
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise ValueError(f"Invalid RSS/XML payload: {exc}") from exc
    items = root.findall(".//item")
    if not items:
        raise ValueError("RSS payload has no <item> entries")
    joint = [
        item
        for item in items
        if AA_NUMBER.search(_item_text(item, "title"))
        or JOINT_TITLE.search(_item_text(item, "title"))
    ]
    chosen = joint if joint else items
    rows = []
    for item in chosen[: max(1, int(limit))]:
        rows.append(
            {
                "title": _item_text(item, "title"),
                "link": _item_text(item, "link"),
                "published": _item_text(item, "pubDate"),
                "summary": _item_text(item, "description"),
            }
        )
    return rows


def advisories_from_rss(
    xml_text: str,
    *,
    limit: int = 25,
    body_fetcher: Callable[[str], str] | None = None,
) -> list[dict[str, Any]]:
    """Parse a CISA advisories RSS feed into CTI pack dicts.

    When ``body_fetcher`` is given (online path), each advisory page is
    fetched and its text mined for attribution and explicit ATT&CK IDs.
    """
    packs: dict[str, dict[str, Any]] = {}
    for row in parse_rss_rows(xml_text, limit=limit):
        body = ""
        if body_fetcher and row["link"]:
            with contextlib.suppress(Exception):
                body = body_fetcher(row["link"])
        pack = advisory_row_to_pack(
            row["title"],
            row["link"],
            row["published"],
            row["summary"],
            body=body,
        )
        packs[pack["id"]] = pack
    return list(packs.values())


def import_cisa_advisories(
    paths: PathConfig,
    xml_text: str,
    *,
    limit: int = 25,
    replace_previous: bool = True,
    body_fetcher: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    """Materialize CISA advisory packs (per-source replace)."""
    packs = advisories_from_rss(xml_text, limit=limit, body_fetcher=body_fetcher)
    if replace_previous:
        for existing in list_cti_packs(paths):
            if str(existing.get("source") or "") == CISA_ADVISORY_SOURCE:
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
        source=CISA_ADVISORY_SOURCE,
    )
    return {
        "written": len(written),
        "pack_count": len(list_cti_packs(paths)),
        "source": CISA_ADVISORY_SOURCE,
    }


def import_cisa_advisories_file(
    paths: PathConfig,
    path: Path | str,
    *,
    limit: int = 25,
) -> dict[str, Any]:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"CISA advisories file not found: {source}")
    result = import_cisa_advisories(paths, source.read_text(encoding="utf-8"), limit=limit)
    result["source_file"] = str(source)
    return result


def update_cisa_advisories_online(
    paths: PathConfig,
    *,
    limit: int = 25,
    client: httpx.Client | None = None,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Download the live CISA advisories RSS and materialize CTI packs.

    Each selected advisory page is fetched so packs carry full attribution
    text and explicit ATT&CK technique IDs, not just the RSS summary.
    """
    owns_client = client is None
    http = client or httpx.Client(timeout=timeout, follow_redirects=True)
    try:
        response = http.get(CISA_ADVISORIES_RSS_URL)
        response.raise_for_status()
        xml_text = response.text

        def fetch_body(url: str) -> str:
            page = http.get(url)
            page.raise_for_status()
            return html_to_text(page.text)

        result = import_cisa_advisories(paths, xml_text, limit=limit, body_fetcher=fetch_body)
    except Exception as exc:
        patch_catalog(
            paths,
            "cti",
            status="error",
            last_error=f"cisa-advisories: {type(exc).__name__}: {exc}",
        )
        raise
    finally:
        if owns_client:
            http.close()
    result["url"] = CISA_ADVISORIES_RSS_URL
    return result
