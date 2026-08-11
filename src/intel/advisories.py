"""CISA cybersecurity advisories → CTI packs.

Joint advisories (the AA-series, co-sealed with FBI/NSA and international
partners) are the most geopolitical free feed CISA publishes: nation-state
attribution, targeted sectors, and actor TTPs. I parse the public RSS listing
(no API key), keep the AA-numbered items, and map attribution/description hints
onto actors and ATT&CK techniques so packs can match attack chains.

Offline ingest of a saved RSS/XML file stays first-class for air-gapped boxes.
"""

from __future__ import annotations

import contextlib
import re
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


def advisory_row_to_pack(title: str, link: str, published: str, summary: str) -> dict[str, Any]:
    """Map one advisory listing row onto a CTI pack."""
    summary = _strip_html(summary)
    blob = f"{title} {summary}"
    actors = sorted({label for pattern, label in ACTOR_HINTS if pattern.search(blob)})
    techniques: set[str] = set()
    for pattern, tids in DESC_HINTS:
        if pattern.search(blob):
            techniques.update(tids)
    number = AA_NUMBER.search(title) or AA_NUMBER.search(link)
    if number:
        pack_id = f"cisa-adv-{number.group(0).casefold()}"
    else:
        pack_id = f"cisa-adv-{_slug(title)[:60]}"
    notes = "\n".join(
        [
            f"Advisory: {title}",
            f"Published: {published or 'n/a'}",
            f"Link: {link or 'n/a'}",
            f"Attribution hints: {', '.join(actors) or 'none detected'}",
            "",
            summary[:2000],
            "",
            "Source: CISA cybersecurity advisories (RSS listing)",
        ]
    )
    return {
        "id": pack_id,
        "title": f"CISA advisory: {title}"[:120],
        "actors": actors,
        "techniques": sorted(techniques),
        "iocs": [],
        "notes": notes,
        "source": CISA_ADVISORY_SOURCE,
    }


def advisories_from_rss(xml_text: str, *, limit: int = 25) -> list[dict[str, Any]]:
    """Parse a CISA advisories RSS feed into CTI pack dicts.

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

    def to_pack(item: ElementTree.Element) -> dict[str, Any]:
        return advisory_row_to_pack(
            _item_text(item, "title"),
            _item_text(item, "link"),
            _item_text(item, "pubDate"),
            _item_text(item, "description"),
        )

    joint = [
        item
        for item in items
        if AA_NUMBER.search(_item_text(item, "title"))
        or JOINT_TITLE.search(_item_text(item, "title"))
    ]
    chosen = joint if joint else items
    packs: dict[str, dict[str, Any]] = {}
    for item in chosen[: max(1, int(limit))]:
        pack = to_pack(item)
        packs[pack["id"]] = pack
    return list(packs.values())


def import_cisa_advisories(
    paths: PathConfig,
    xml_text: str,
    *,
    limit: int = 25,
    replace_previous: bool = True,
) -> dict[str, Any]:
    """Materialize CISA advisory packs (per-source replace)."""
    packs = advisories_from_rss(xml_text, limit=limit)
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
    """Download the live CISA advisories RSS and materialize CTI packs."""
    owns_client = client is None
    http = client or httpx.Client(timeout=timeout, follow_redirects=True)
    try:
        response = http.get(CISA_ADVISORIES_RSS_URL)
        response.raise_for_status()
        xml_text = response.text
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
    result = import_cisa_advisories(paths, xml_text, limit=limit)
    result["url"] = CISA_ADVISORIES_RSS_URL
    return result
