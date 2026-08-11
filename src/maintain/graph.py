"""Bipartite attack-chain ↔ technique graph and novelty analytics.

I rebuild this from workspace chains on demand — no separate graph DB to drift.
SQLite is only used as an optional queryable cache under output/workspace/.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

from src.config import PathConfig
from src.workspace import load_chains, now_iso, workspace_dir

# Technique IDs look like T1059, T1059.001, or sloppy "T1499,001"
TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# Canonical ATT&CK tactic order for kill-chain progression scoring
TACTIC_ORDER = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)

TACTIC_ALIASES = {
    "recon": "reconnaissance",
    "initial access": "initial-access",
    "privilege escalation": "privilege-escalation",
    "defense evasion": "defense-evasion",
    "credential access": "credential-access",
    "lateral movement": "lateral-movement",
    "command and control": "command-and-control",
    "c2": "command-and-control",
}


def normalize_technique_id(value: str | None) -> str | None:
    if not value:
        return None
    match = TECHNIQUE_ID_RE.search(str(value))
    if not match:
        return None
    tid = match.group(0).upper().replace(",", ".")
    # Repair common typo T1499,001 → T1499.001
    tid = re.sub(r"^(T\d{4}),(\d{3})$", r"\1.\2", tid)
    return tid


def technique_keys_from_chain(chain: dict[str, Any]) -> set[str]:
    """Stable technique fingerprint for a chain (prefer IDs, fall back to names)."""
    keys: set[str] = set()
    for step in chain.get("steps") or []:
        if not isinstance(step, dict):
            continue
        tid = normalize_technique_id(step.get("technique_id")) or normalize_technique_id(
            str(step.get("raw") or "")
        )
        if tid:
            keys.add(tid)
            continue
        name = str(step.get("name") or step.get("raw") or "").strip().casefold()
        if name:
            keys.add(f"name:{name}")
    return keys


def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    union = a | b
    return len(a & b) / len(union)


def normalize_tactic(value: str | None) -> str | None:
    if not value:
        return None
    raw = str(value).strip().casefold().replace("_", "-").replace(" ", "-")
    raw = TACTIC_ALIASES.get(raw.replace("-", " "), raw)
    raw = TACTIC_ALIASES.get(raw, raw)
    return raw if raw in TACTIC_ORDER else raw


def infer_tactic_from_label(label: str) -> str | None:
    """Pull a leading 'Tactic: Name (Txxxx)' style tactic if present."""
    text = label.strip()
    if ":" in text:
        head = text.split(":", 1)[0].strip().casefold()
        return normalize_tactic(head)
    return None


def graph_db_path(paths: PathConfig) -> Path:
    return workspace_dir(paths) / "attack_graph.sqlite"


def build_chain_graph(paths: PathConfig) -> dict[str, Any]:
    """Build analytics payload from the current chain library."""
    chains = load_chains(paths)
    technique_freq: Counter[str] = Counter()
    pair_freq: Counter[tuple[str, str]] = Counter()
    tactic_freq: Counter[str] = Counter()
    chain_rows: list[dict[str, Any]] = []
    technique_labels: dict[str, str] = {}
    edges: list[dict[str, str]] = []
    nodes: list[dict[str, Any]] = []

    fingerprints: dict[str, set[str]] = {}

    for chain in chains:
        keys = technique_keys_from_chain(chain)
        fingerprints[chain["id"]] = keys
        tactics_in_chain: list[str] = []
        for step in chain.get("steps") or []:
            if not isinstance(step, dict):
                continue
            tid = normalize_technique_id(step.get("technique_id")) or normalize_technique_id(
                str(step.get("raw") or "")
            )
            label = str(step.get("name") or step.get("raw") or tid or "unknown")
            key = tid or f"name:{label.casefold()}"
            technique_freq[key] += 1
            technique_labels[key] = label if not tid else f"{label} ({tid})" if label else tid
            tactic = normalize_tactic(step.get("tactic")) or infer_tactic_from_label(
                str(step.get("raw") or "")
            )
            if tactic:
                tactic_freq[tactic] += 1
                tactics_in_chain.append(tactic)
            edges.append({"chain_id": chain["id"], "technique": key})

        key_list = sorted(keys)
        for i, a in enumerate(key_list):
            for b in key_list[i + 1 :]:
                pair_freq[(a, b)] += 1

        chain_rows.append(
            {
                "id": chain["id"],
                "name": chain["name"],
                "technique_count": len(keys),
                "techniques": sorted(keys),
                "tactics": tactics_in_chain,
                "source": chain.get("source") or "",
            }
        )

    # Nodes for visualization
    for chain in chains:
        nodes.append(
            {
                "id": f"chain:{chain['id']}",
                "kind": "chain",
                "label": chain["name"],
                "weight": len(fingerprints.get(chain["id"], ())),
            }
        )
    for key, count in technique_freq.most_common():
        nodes.append(
            {
                "id": f"tech:{key}",
                "kind": "technique",
                "label": technique_labels.get(key, key),
                "weight": count,
            }
        )

    # Rare / common techniques
    if technique_freq:
        max_f = max(technique_freq.values())
        min_f = min(technique_freq.values())
    else:
        max_f = min_f = 0

    rare = [
        {"technique": key, "label": technique_labels.get(key, key), "count": count}
        for key, count in sorted(technique_freq.items(), key=lambda item: (item[1], item[0]))
        if count == min_f
    ][:24]
    common = [
        {"technique": key, "label": technique_labels.get(key, key), "count": count}
        for key, count in technique_freq.most_common(18)
    ]

    # Dark-matter pairs: techniques that appear in the library but never together
    tech_list = [key for key, _ in technique_freq.most_common(40)]
    cooccur = set(pair_freq)
    voids: list[dict[str, Any]] = []
    for i, a in enumerate(tech_list):
        for b in tech_list[i + 1 :]:
            pair = (a, b) if a < b else (b, a)
            if pair in cooccur:
                continue
            # Prefer pairing rare-ish nodes
            score = 1.0 / (technique_freq[a] * technique_freq[b])
            voids.append(
                {
                    "a": a,
                    "b": b,
                    "label_a": technique_labels.get(a, a),
                    "label_b": technique_labels.get(b, b),
                    "score": round(score, 6),
                    "freq_a": technique_freq[a],
                    "freq_b": technique_freq[b],
                }
            )
    voids.sort(key=lambda row: (-row["score"], row["a"], row["b"]))
    voids = voids[:40]

    # Tactic coverage (kill-chain blind spots)
    tactic_coverage = [
        {"tactic": tactic, "count": tactic_freq.get(tactic, 0)} for tactic in TACTIC_ORDER
    ]
    blind = [row for row in tactic_coverage if row["count"] == 0]
    weak = sorted(tactic_coverage, key=lambda row: (row["count"], row["tactic"]))[:5]

    # Heatmap matrix: chain × top techniques
    top_techs = [key for key, _ in technique_freq.most_common(16)]
    heatmap = {
        "techniques": [{"id": key, "label": technique_labels.get(key, key)} for key in top_techs],
        "chains": [],
    }
    for chain in chain_rows:
        tech_set = set(chain["techniques"])
        heatmap["chains"].append(
            {
                "id": chain["id"],
                "name": chain["name"],
                "cells": [1 if tech in tech_set else 0 for tech in top_techs],
            }
        )

    payload = {
        "built_at": now_iso(),
        "counts": {
            "chains": len(chains),
            "techniques": len(technique_freq),
            "edges": len(edges),
            "pairs": len(pair_freq),
        },
        "chains": chain_rows,
        "technique_frequency": common,
        "rare_techniques": rare,
        "dark_matter_pairs": voids,
        "tactic_coverage": tactic_coverage,
        "blind_tactics": blind,
        "weak_tactics": weak,
        "heatmap": heatmap,
        "nodes": nodes,
        "edges": [
            {"source": f"chain:{edge['chain_id']}", "target": f"tech:{edge['technique']}"}
            for edge in edges
        ],
        "fingerprints": {cid: sorted(keys) for cid, keys in fingerprints.items()},
        "freq_range": {"min": min_f, "max": max_f},
    }
    persist_graph_sqlite(paths, payload, fingerprints)
    return payload


def persist_graph_sqlite(
    paths: PathConfig,
    payload: dict[str, Any],
    fingerprints: dict[str, set[str]],
) -> Path:
    """Optional queryable cache — analytics still rebuild from chains as source of truth."""
    path = graph_db_path(paths)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            DROP TABLE IF EXISTS chains;
            DROP TABLE IF EXISTS techniques;
            DROP TABLE IF EXISTS chain_techniques;
            CREATE TABLE chains (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                technique_count INTEGER,
                source TEXT
            );
            CREATE TABLE techniques (
                key TEXT PRIMARY KEY,
                label TEXT,
                frequency INTEGER
            );
            CREATE TABLE chain_techniques (
                chain_id TEXT NOT NULL,
                technique_key TEXT NOT NULL,
                PRIMARY KEY (chain_id, technique_key)
            );
            """
        )
        for chain in payload.get("chains") or []:
            conn.execute(
                "INSERT INTO chains(id, name, technique_count, source) VALUES (?,?,?,?)",
                (
                    chain["id"],
                    chain["name"],
                    chain.get("technique_count") or 0,
                    chain.get("source") or "",
                ),
            )
        seen: set[str] = set()
        freq_rows = list(payload.get("technique_frequency") or [])
        freq_rows.extend(payload.get("rare_techniques") or [])
        for row in freq_rows:
            key = row["technique"]
            if key in seen:
                continue
            seen.add(key)
            conn.execute(
                "INSERT OR REPLACE INTO techniques(key, label, frequency) VALUES (?,?,?)",
                (key, row.get("label") or key, row.get("count") or 0),
            )
        for chain_id, keys in fingerprints.items():
            for key in keys:
                conn.execute(
                    "INSERT OR IGNORE INTO chain_techniques(chain_id, technique_key) VALUES (?,?)",
                    (chain_id, key),
                )
        conn.commit()
    finally:
        conn.close()
    return path


def clone_pairs(paths: PathConfig, *, threshold: float = 0.55) -> list[dict[str, Any]]:
    """Near-duplicate chain pairs by technique Jaccard."""
    chains = load_chains(paths)
    fps = [(chain, technique_keys_from_chain(chain)) for chain in chains]
    pairs: list[dict[str, Any]] = []
    for i, (a, fa) in enumerate(fps):
        for b, fb in fps[i + 1 :]:
            score = jaccard(fa, fb)
            if score < threshold:
                continue
            shared = sorted(fa & fb)
            pairs.append(
                {
                    "a_id": a["id"],
                    "a_name": a["name"],
                    "b_id": b["id"],
                    "b_name": b["name"],
                    "jaccard": round(score, 4),
                    "shared_count": len(shared),
                    "shared": shared[:20],
                    "a_only": sorted(fa - fb)[:12],
                    "b_only": sorted(fb - fa)[:12],
                    "severity": (
                        "near-duplicate"
                        if score >= 0.75
                        else "close remix"
                        if score >= 0.55
                        else "related"
                    ),
                }
            )
    pairs.sort(key=lambda row: (-row["jaccard"], row["a_name"], row["b_name"]))
    return pairs


def library_fingerprint(paths: PathConfig) -> list[dict[str, Any]]:
    """Compact fingerprints for LLM prompts (avoid pasting entire library)."""
    rows = []
    for chain in load_chains(paths):
        keys = sorted(technique_keys_from_chain(chain))
        rows.append(
            {
                "id": chain["id"],
                "name": chain["name"],
                "technique_count": len(keys),
                "techniques": keys,
                "tags": chain.get("tags") or [],
            }
        )
    return rows


def max_jaccard_against_library(
    candidate_keys: set[str],
    paths: PathConfig,
) -> tuple[float, str | None]:
    best = 0.0
    best_id: str | None = None
    for chain in load_chains(paths):
        score = jaccard(candidate_keys, technique_keys_from_chain(chain))
        if score > best:
            best = score
            best_id = chain["id"]
    return best, best_id


def candidate_keys_from_steps(steps: list[dict[str, Any]]) -> set[str]:
    fake = {"steps": steps}
    return technique_keys_from_chain(fake)


def kill_chain_progression_score(steps: list[dict[str, Any]]) -> float:
    """0–1 score: do declared tactics roughly advance through the kill chain?"""
    indices: list[int] = []
    for step in steps:
        tactic = normalize_tactic(step.get("tactic")) or infer_tactic_from_label(
            str(step.get("raw") or step.get("name") or "")
        )
        if tactic in TACTIC_ORDER:
            indices.append(TACTIC_ORDER.index(tactic))
    if len(indices) < 2:
        return 0.35
    advances = sum(1 for i in range(1, len(indices)) if indices[i] >= indices[i - 1])
    return advances / (len(indices) - 1)


def write_maintain_artifact(paths: PathConfig, name: str, payload: dict[str, Any]) -> Path:
    out = paths.output_dir / "maintain"
    out.mkdir(parents=True, exist_ok=True)
    stamp = now_iso().replace(":", "").replace("+", "_")
    path = out / f"{name}_{stamp}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path
