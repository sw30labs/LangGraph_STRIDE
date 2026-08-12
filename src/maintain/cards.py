"""Maintain studio card catalog — playground-style operator actions."""

from __future__ import annotations

from typing import Any

# Card groups answer different operator questions, same spirit as contingency-atlas playground.
CARD_GROUPS: list[dict[str, Any]] = [
    {
        "id": "forge",
        "title": "What should not exist yet?",
        "sub": "graph voids + adversarial imagination · requires LLM + judge loop",
    },
    {
        "id": "audit",
        "title": "What is already too similar?",
        "sub": "deterministic library surgery · LLM optional for merge narratives",
    },
    {
        "id": "sight",
        "title": "Where is the library blind?",
        "sub": "coverage heatmaps, dark-matter pairs, bipartite galaxy · offline",
    },
]

CARD_CATALOG: list[dict[str, Any]] = [
    {
        "id": "dark_matter",
        "group": "forge",
        "name": "Dark Matter Chain",
        "short": "Novel attack template",
        "btn": "FORGE",
        "llm": True,
        "tag": "forge",
        "desc": (
            "Generate a genuinely novel ATT&CK chain from library dark-matter pairs "
            "(techniques that never co-occur) and rare nodes. Exhausts model adversarial "
            "knowledge first; optional DuckDuckGo only for a thin external spark. "
            "Deterministic Jaccard gate blocks near-duplicates; an LLM judge loop "
            "(Ralph-style) retries until novelty, kill-chain coherence, and realism pass — "
            "or attempts are exhausted. Proposals land under output/maintain/; you decide "
            "whether to commit them to the chain library."
        ),
        "fields": [
            {
                "k": "steer",
                "label": (
                    "Steer (optional) — a hunch about the adversary, asset, or constraint. "
                    "Recorded with the proposal as DIRECTED so undirected forges stay comparable. "
                    "It does not lower the novelty bar: zero honest candidates is a valid answer."
                ),
                "ph": (
                    "e.g. identity-provider trust abuse that never touches endpoint malware; "
                    "or OT historian pivot after a contractor VPN foothold"
                ),
                "type": "textarea",
            },
            {
                "k": "web_spark",
                "label": "Allow DuckDuckGo spark (optional, best-effort)",
                "type": "checkbox",
            },
            {
                "k": "max_jaccard",
                "label": "Max Jaccard vs existing chains",
                "type": "number",
                "min": 0.15,
                "max": 0.7,
                "step": 0.05,
                "value": 0.45,
            },
        ],
    },
    {
        "id": "control_counter",
        "group": "forge",
        "name": "Control Counter-Forge",
        "short": "Defeat the control stack",
        "btn": "COUNTER",
        "llm": True,
        "tag": "forge",
        "desc": (
            "Read the packaged control taxonomy, find the densest control clusters "
            "(identity, monitoring, malware, network), and invent an attack chain that "
            "specifically routes around those assumptions — living-off-the-land, "
            "trusted-path abuse, and process gaps rather than 'yet another phishing + LSASS'. "
            "Same novelty gate and judge loop as Dark Matter."
        ),
        "fields": [
            {
                "k": "steer",
                "label": "Steer (optional) — which control story to break",
                "ph": "e.g. bypass JIT privileged access without disabling agents",
                "type": "textarea",
            },
            {
                "k": "max_jaccard",
                "label": "Max Jaccard vs existing chains",
                "type": "number",
                "min": 0.15,
                "max": 0.7,
                "step": 0.05,
                "value": 0.45,
            },
        ],
    },
    {
        "id": "app_adversary",
        "group": "forge",
        "name": "App-Shaped Adversary",
        "short": "CMDB-tuned chain",
        "btn": "SHAPE",
        "llm": True,
        "tag": "forge",
        "desc": (
            "Pick an application from the CMDB and forge a chain that respects its "
            "platform, external facing, and data sensitivity — not a generic ransomware "
            "stencil. Uses library fingerprints to stay novel, then judge-loops for "
            "asset fit and kill-chain realism."
        ),
        "fields": [
            {
                "k": "aa_id",
                "label": "AA ID (application)",
                "type": "aa_select",
            },
            {
                "k": "steer",
                "label": "Steer (optional) — attacker motive or constraint",
                "ph": "e.g. quiet data staging for BEC follow-on, no ransomware",
                "type": "textarea",
            },
            {
                "k": "max_jaccard",
                "label": "Max Jaccard vs existing chains",
                "type": "number",
                "min": 0.15,
                "max": 0.7,
                "step": 0.05,
                "value": 0.45,
            },
        ],
    },
    {
        "id": "blind_spot_fill",
        "group": "forge",
        "name": "Blind-Spot Fill",
        "short": "Force weak kill-chain coverage",
        "btn": "FILL",
        "llm": True,
        "tag": "forge",
        "desc": (
            "Measure tactic coverage across the library, then force a coherent chain that "
            "must visit the weakest / missing kill-chain phases (e.g. resource-development, "
            "collection, impact) without collapsing into the overused initial-access + "
            "execution clichés. Novelty gate + judge still apply."
        ),
        "fields": [
            {
                "k": "steer",
                "label": "Steer (optional)",
                "ph": "e.g. emphasize pre-compromise resource development, not the breach",
                "type": "textarea",
            },
            {
                "k": "max_jaccard",
                "label": "Max Jaccard vs existing chains",
                "type": "number",
                "min": 0.15,
                "max": 0.7,
                "step": 0.05,
                "value": 0.45,
            },
        ],
    },
    {
        "id": "kev_forge",
        "group": "forge",
        "name": "KEV Gap Forge",
        "short": "Arm actively-exploited gaps",
        "btn": "ARM",
        "llm": True,
        "tag": "forge",
        "desc": (
            "Cross the CISA KEV catalog with the chain library: techniques that are "
            "actively exploited in the wild but no chain simulates become forge seeds. "
            "The card drafts a coherent intrusion anchored on those gaps, so the library "
            "chases real adversary tempo instead of abstract novelty. Works offline from "
            "the local KEV cache; the same gaps are queryable in Neo4j as kev_gaps. "
            "Novelty gate + judge still apply."
        ),
        "fields": [
            {
                "k": "steer",
                "label": "Steer (optional) — which gap or adversary story to arm first",
                "ph": "e.g. prioritize credential-theft gaps for the VDI estate",
                "type": "textarea",
            },
            {
                "k": "max_jaccard",
                "label": "Max Jaccard vs existing chains",
                "type": "number",
                "min": 0.15,
                "max": 0.7,
                "step": 0.05,
                "value": 0.45,
            },
        ],
    },
    {
        "id": "clone_autopsy",
        "group": "audit",
        "name": "Clone Autopsy",
        "short": "Near-duplicate scan",
        "btn": "SCAN",
        "llm": False,
        "tag": "audit",
        "desc": (
            "Purely deterministic: technique-set Jaccard across every chain pair. "
            "Surfaces near-duplicates and 'slight remixes' (same mix of techniques with "
            "cosmetic renames) so the library does not rot into twelve flavors of "
            "phishing → PowerShell → LSASS → exfil. Writes a report under output/maintain/."
        ),
        "fields": [
            {
                "k": "threshold",
                "label": "Jaccard threshold",
                "type": "number",
                "min": 0.3,
                "max": 0.95,
                "step": 0.05,
                "value": 0.55,
            },
        ],
    },
    {
        "id": "technique_galaxy",
        "group": "sight",
        "name": "Technique Galaxy",
        "short": "Graph + heatmaps",
        "btn": "MAP",
        "llm": False,
        "tag": "sight",
        "desc": (
            "Rebuild the bipartite chain↔technique graph, persist a SQLite query cache, "
            "and emit heatmap cells, rare nodes, dark-matter pairs, and tactic coverage. "
            "No LLM — this is the observatory the forges consult. The Maintain page renders "
            "the galaxy SVG and heatmaps live."
        ),
        "fields": [],
    },
]


def get_card(card_id: str) -> dict[str, Any]:
    for card in CARD_CATALOG:
        if card["id"] == card_id:
            return card
    raise ValueError(f"Unknown maintain card: {card_id}")


def cards_payload() -> dict[str, Any]:
    return {"groups": CARD_GROUPS, "cards": CARD_CATALOG}
