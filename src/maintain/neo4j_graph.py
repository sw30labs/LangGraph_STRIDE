"""Neo4j attack-template graph for LangGraph STRIDE.

Dedicated store (compose.neo4j.yaml → bolt://127.0.0.1:7688). TwinOps keeps
its own container on 7687; we never touch it.

Schema
------
  (:Chain {id, name, description, source, updated_at, technique_count, tags})
  (:Technique {key, technique_id, name, frequency, is_subtechnique})
  (:Tactic {name, ord})
  (:Tag {name})
  (:LibraryMeta {id})                 # singleton sync watermark

  (Chain)-[:USES {step, tactic, raw}]->(Technique)
  (Technique)-[:IN_TACTIC]->(Tactic)
  (Technique)-[:CO_OCCURS {weight, shared_chains}]->(Technique)   # key-ordered
  (Chain)-[:SIMILAR_TO {jaccard, verdict}]->(Chain)               # key-ordered
  (Chain)-[:TAGGED]->(Tag)

Analytics still rebuild from the JSON chain library (source of truth). Neo4j
is the queryable projection + Browser playground.
"""

from __future__ import annotations

import contextlib
import math
from typing import Any

from src.config import AppConfig, Neo4jConfig
from src.maintain.graph import (
    TACTIC_ORDER,
    clone_pairs,
    normalize_tactic,
    normalize_technique_id,
    technique_keys_from_chain,
)
from src.workspace import load_chains, now_iso

CONSTRAINTS = (
    "CREATE CONSTRAINT chain_id IF NOT EXISTS FOR (c:Chain) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT technique_key IF NOT EXISTS FOR (t:Technique) REQUIRE t.key IS UNIQUE",
    "CREATE CONSTRAINT tactic_name IF NOT EXISTS FOR (t:Tactic) REQUIRE t.name IS UNIQUE",
    "CREATE CONSTRAINT tag_name IF NOT EXISTS FOR (t:Tag) REQUIRE t.name IS UNIQUE",
    "CREATE CONSTRAINT library_meta IF NOT EXISTS FOR (m:LibraryMeta) REQUIRE m.id IS UNIQUE",
)

INDEXES = (
    "CREATE INDEX technique_freq IF NOT EXISTS FOR (t:Technique) ON (t.frequency)",
    "CREATE INDEX chain_source IF NOT EXISTS FOR (c:Chain) ON (c.source)",
)


def _driver(config: Neo4jConfig):
    try:
        from neo4j import GraphDatabase
    except ImportError as exc:  # pragma: no cover - optional until pip install
        raise RuntimeError(
            "neo4j package not installed — run: pip install 'langgraph-stride[graph]'"
        ) from exc
    return GraphDatabase.driver(config.uri, auth=(config.user, config.password))


def neo4j_status(config: Neo4jConfig | None = None) -> dict[str, Any]:
    """Probe Bolt reachability without raising."""
    cfg = config or Neo4jConfig()
    base = {
        "enabled": cfg.enabled,
        "uri": cfg.uri,
        "user": cfg.user,
        "database": cfg.database,
        "browser_url": cfg.browser_url,
        "ready": False,
        "detail": "disabled" if not cfg.enabled else "not probed",
        "counts": {},
    }
    if not cfg.enabled:
        return base
    try:
        driver = _driver(cfg)
    except Exception as exc:
        base["detail"] = str(exc)
        return base
    try:
        with driver.session(database=cfg.database) as session:
            session.run("RETURN 1 AS ok").single()
            counts = session.run(
                """
                OPTIONAL MATCH (c:Chain) WITH count(c) AS chains
                OPTIONAL MATCH (t:Technique) WITH chains, count(t) AS techniques
                OPTIONAL MATCH ()-[u:USES]->() WITH chains, techniques, count(u) AS uses
                OPTIONAL MATCH ()-[co:CO_OCCURS]->()
                RETURN chains, techniques, uses, count(co) AS co_occurs
                """
            ).single()
            meta = session.run(
                "MATCH (m:LibraryMeta {id:'stride'}) RETURN m.synced_at AS synced_at, "
                "m.chain_count AS chain_count"
            ).single()
        base["ready"] = True
        base["detail"] = "ok"
        if counts:
            base["counts"] = {
                "chains": int(counts["chains"] or 0),
                "techniques": int(counts["techniques"] or 0),
                "uses": int(counts["uses"] or 0),
                "co_occurs": int(counts["co_occurs"] or 0),
            }
        if meta:
            base["synced_at"] = meta.get("synced_at")
            base["synced_chain_count"] = meta.get("chain_count")
    except Exception as exc:
        base["detail"] = f"{type(exc).__name__}: {exc}"
    finally:
        with contextlib.suppress(Exception):
            driver.close()
    return base


def ensure_schema(session) -> None:
    for statement in CONSTRAINTS:
        session.run(statement)
    for statement in INDEXES:
        session.run(statement)


def _technique_rows(chains: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """key → {key, technique_id, name, frequency, tactics:set}"""
    rows: dict[str, dict[str, Any]] = {}
    for chain in chains:
        for step in chain.get("steps") or []:
            if not isinstance(step, dict):
                continue
            tid = normalize_technique_id(step.get("technique_id")) or normalize_technique_id(
                str(step.get("raw") or "")
            )
            name = str(step.get("name") or step.get("raw") or tid or "unknown").strip()
            key = tid or f"name:{name.casefold()}"
            row = rows.setdefault(
                key,
                {
                    "key": key,
                    "technique_id": tid,
                    "name": name,
                    "frequency": 0,
                    "tactics": set(),
                    "is_subtechnique": bool(tid and "." in tid),
                },
            )
            row["frequency"] += 1
            if not row.get("name") and name:
                row["name"] = name
            tactic = normalize_tactic(step.get("tactic"))
            if tactic:
                row["tactics"].add(tactic)
    return rows


def _cooccur_edges(
    chains: list[dict[str, Any]],
) -> list[tuple[str, str, int, list[str]]]:
    pair_chains: dict[tuple[str, str], list[str]] = {}
    for chain in chains:
        keys = sorted(technique_keys_from_chain(chain))
        for i, a in enumerate(keys):
            for b in keys[i + 1 :]:
                pair = (a, b)
                pair_chains.setdefault(pair, []).append(chain["id"])
    return [
        (a, b, len(cids), cids)
        for (a, b), cids in pair_chains.items()
    ]


def sync_library_to_neo4j(
    config: AppConfig | Neo4jConfig,
    *,
    paths=None,
    similarity_threshold: float = 0.45,
) -> dict[str, Any]:
    """Full rebuild of the Neo4j projection from the workspace chain library."""
    if isinstance(config, AppConfig):
        neo = config.neo4j
        path_cfg = config.paths
    else:
        neo = config
        from src.config import PathConfig

        path_cfg = paths or PathConfig()

    if not neo.enabled:
        return {"ok": False, "detail": "STRIDE Neo4j disabled", "synced": False}

    chains = load_chains(path_cfg)
    techniques = _technique_rows(chains)
    cooccurs = _cooccur_edges(chains)
    similar = clone_pairs(path_cfg, threshold=similarity_threshold)
    synced_at = now_iso()

    driver = _driver(neo)
    try:
        with driver.session(database=neo.database) as session:
            ensure_schema(session)
            # Wipe projection nodes/rels (keep nothing foreign — this DB is ours).
            session.run("MATCH (n) DETACH DELETE n")

            # Tactics
            for ord_i, name in enumerate(TACTIC_ORDER):
                session.run(
                    "CREATE (:Tactic {name:$name, ord:$ord})",
                    name=name,
                    ord=ord_i,
                )

            # Techniques
            for row in techniques.values():
                session.run(
                    """
                    CREATE (t:Technique {
                        key: $key,
                        technique_id: $technique_id,
                        name: $name,
                        frequency: $frequency,
                        is_subtechnique: $is_subtechnique
                    })
                    """,
                    key=row["key"],
                    technique_id=row["technique_id"],
                    name=row["name"],
                    frequency=row["frequency"],
                    is_subtechnique=row["is_subtechnique"],
                )
                for tactic in row["tactics"]:
                    session.run(
                        """
                        MATCH (t:Technique {key:$key})
                        MATCH (a:Tactic {name:$tactic})
                        MERGE (t)-[:IN_TACTIC]->(a)
                        """,
                        key=row["key"],
                        tactic=tactic,
                    )

            # Chains + USES + TAGS
            for chain in chains:
                tags = [str(t) for t in (chain.get("tags") or [])]
                session.run(
                    """
                    CREATE (c:Chain {
                        id: $id,
                        name: $name,
                        description: $description,
                        source: $source,
                        updated_at: $updated_at,
                        technique_count: $technique_count,
                        tags: $tags
                    })
                    """,
                    id=chain["id"],
                    name=chain["name"],
                    description=str(chain.get("description") or ""),
                    source=str(chain.get("source") or ""),
                    updated_at=str(chain.get("updated_at") or synced_at),
                    technique_count=len(technique_keys_from_chain(chain)),
                    tags=tags,
                )
                for tag in tags:
                    session.run(
                        """
                        MATCH (c:Chain {id:$id})
                        MERGE (g:Tag {name:$tag})
                        MERGE (c)-[:TAGGED]->(g)
                        """,
                        id=chain["id"],
                        tag=tag,
                    )
                for step_i, step in enumerate(chain.get("steps") or []):
                    if not isinstance(step, dict):
                        continue
                    tid = normalize_technique_id(step.get("technique_id"))
                    if not tid:
                        tid = normalize_technique_id(str(step.get("raw") or ""))
                    name = str(step.get("name") or step.get("raw") or tid or "").strip()
                    key = tid or (f"name:{name.casefold()}" if name else None)
                    if not key:
                        continue
                    session.run(
                        """
                        MATCH (c:Chain {id:$cid})
                        MATCH (t:Technique {key:$key})
                        CREATE (c)-[:USES {
                            step: $step,
                            tactic: $tactic,
                            raw: $raw
                        }]->(t)
                        """,
                        cid=chain["id"],
                        key=key,
                        step=step_i,
                        tactic=normalize_tactic(step.get("tactic")) or "",
                        raw=str(step.get("raw") or name or ""),
                    )

            # Co-occurrence (ordered keys so one undirected edge)
            for a, b, weight, cids in cooccurs:
                session.run(
                    """
                    MATCH (a:Technique {key:$a})
                    MATCH (b:Technique {key:$b})
                    CREATE (a)-[:CO_OCCURS {
                        weight: $weight,
                        shared_chains: $shared
                    }]->(b)
                    """,
                    a=a,
                    b=b,
                    weight=weight,
                    shared=cids,
                )

            # Similarity between chains
            for pair in similar:
                a_id = str(pair.get("a_id") or "")
                b_id = str(pair.get("b_id") or "")
                if not a_id or not b_id:
                    continue
                if a_id > b_id:
                    a_id, b_id = b_id, a_id
                session.run(
                    """
                    MATCH (a:Chain {id:$a})
                    MATCH (b:Chain {id:$b})
                    CREATE (a)-[:SIMILAR_TO {
                        jaccard: $jaccard,
                        verdict: $verdict,
                        shared_count: $shared_count
                    }]->(b)
                    """,
                    a=a_id,
                    b=b_id,
                    jaccard=float(pair.get("jaccard") or 0),
                    verdict=str(pair.get("verdict") or "related"),
                    shared_count=int(pair.get("shared_count") or 0),
                )

            session.run(
                """
                CREATE (:LibraryMeta {
                    id: 'stride',
                    synced_at: $synced_at,
                    chain_count: $chain_count,
                    technique_count: $technique_count,
                    cooccur_count: $cooccur_count,
                    similar_count: $similar_count
                })
                """,
                synced_at=synced_at,
                chain_count=len(chains),
                technique_count=len(techniques),
                cooccur_count=len(cooccurs),
                similar_count=len(similar),
            )
    finally:
        driver.close()

    return {
        "ok": True,
        "synced": True,
        "synced_at": synced_at,
        "uri": neo.uri,
        "browser_url": neo.browser_url,
        "counts": {
            "chains": len(chains),
            "techniques": len(techniques),
            "co_occurs": len(cooccurs),
            "similar": len(similar),
        },
        "detail": "ok",
    }


def run_cypher(
    config: Neo4jConfig,
    query: str,
    params: dict[str, Any] | None = None,
    *,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Run a read query; rows are plain dicts."""
    driver = _driver(config)
    try:
        with driver.session(database=config.database) as session:
            result = session.run(query, **(params or {}))
            rows = []
            for i, record in enumerate(result):
                if i >= limit:
                    break
                rows.append({key: _neo_value(record[key]) for key in record})
            return rows
    finally:
        driver.close()


def _neo_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_neo_value(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _neo_value(v) for k, v in value.items()}
    # Node / Relationship
    try:
        from neo4j.graph import Node, Relationship

        if isinstance(value, Node):
            return {
                "labels": list(value.labels),
                "id": value.element_id,
                "props": dict(value),
            }
        if isinstance(value, Relationship):
            return {
                "type": value.type,
                "id": value.element_id,
                "props": dict(value),
            }
    except Exception:
        pass
    return str(value)


# ── canned analytics queries (also power the UI) ─────────────────────────

CANNED_QUERIES: dict[str, dict[str, str]] = {
    "hub_techniques": {
        "title": "Hub techniques",
        "cypher": (
            "MATCH (t:Technique)<-[:USES]-(c:Chain) "
            "RETURN t.key AS key, t.name AS name, t.frequency AS frequency, "
            "count(c) AS chains ORDER BY frequency DESC LIMIT 20"
        ),
    },
    "orphan_techniques": {
        "title": "Singleton techniques",
        "cypher": (
            "MATCH (t:Technique) WHERE t.frequency = 1 "
            "RETURN t.key AS key, t.name AS name ORDER BY t.name LIMIT 40"
        ),
    },
    "near_duplicates": {
        "title": "Near-duplicate chains",
        "cypher": (
            "MATCH (a:Chain)-[s:SIMILAR_TO]->(b:Chain) "
            "RETURN a.name AS a, b.name AS b, s.jaccard AS jaccard, s.verdict AS verdict "
            "ORDER BY s.jaccard DESC LIMIT 25"
        ),
    },
    "dark_matter": {
        "title": "Dark-matter pair candidates",
        "cypher": (
            # techniques that never CO_OCCURS but both appear ≥1
            "MATCH (a:Technique), (b:Technique) "
            "WHERE a.key < b.key AND a.frequency <= 3 AND b.frequency <= 3 "
            "AND NOT (a)-[:CO_OCCURS]-(b) "
            "RETURN a.key AS a, a.name AS name_a, b.key AS b, b.name AS name_b, "
            "a.frequency AS freq_a, b.frequency AS freq_b "
            "ORDER BY a.frequency + b.frequency ASC LIMIT 30"
        ),
    },
    "tactic_coverage": {
        "title": "Tactic coverage",
        "cypher": (
            "MATCH (tac:Tactic) "
            "OPTIONAL MATCH (t:Technique)-[:IN_TACTIC]->(tac) "
            "RETURN tac.name AS tactic, tac.ord AS ord, count(t) AS techniques "
            "ORDER BY tac.ord"
        ),
    },
    "chain_neighborhood": {
        "title": "Chain neighborhood (param $chain_id)",
        "cypher": (
            "MATCH (c:Chain {id: $chain_id})-[:USES]->(t:Technique) "
            "OPTIONAL MATCH (t)<-[:USES]-(other:Chain) WHERE other.id <> c.id "
            "RETURN t.key AS technique, t.name AS name, "
            "collect(DISTINCT other.name)[..8] AS also_in ORDER BY t.key"
        ),
    },
}


def canned_query(
    config: Neo4jConfig,
    name: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if name not in CANNED_QUERIES:
        raise ValueError(f"Unknown query: {name}. Choose from {sorted(CANNED_QUERIES)}")
    meta = CANNED_QUERIES[name]
    rows = run_cypher(config, meta["cypher"], params)
    return {"id": name, "title": meta["title"], "rows": rows}


def force_layout(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    width: float = 720,
    height: float = 480,
    iterations: int = 80,
) -> list[dict[str, Any]]:
    """Simple Fruchterman-Reingold-ish layout — no extra deps."""
    if not nodes:
        return []
    n = len(nodes)
    # seed on a circle
    positions: dict[str, list[float]] = {}
    for i, node in enumerate(nodes):
        angle = 2 * math.pi * i / max(n, 1)
        positions[node["id"]] = [
            width / 2 + (width * 0.35) * math.cos(angle),
            height / 2 + (height * 0.35) * math.sin(angle),
        ]

    # adjacency
    adj: dict[str, set[str]] = {node["id"]: set() for node in nodes}
    for edge in edges:
        src, tgt = edge["source"], edge["target"]
        if src in adj and tgt in adj:
            adj[src].add(tgt)
            adj[tgt].add(src)

    area = width * height
    k = math.sqrt(area / max(n, 1))
    temperature = width / 8

    for _ in range(iterations):
        disp = {nid: [0.0, 0.0] for nid in positions}
        ids = list(positions)
        # repulsion
        for i, id_a in enumerate(ids):
            xa, ya = positions[id_a]
            for id_b in ids[i + 1 :]:
                xb, yb = positions[id_b]
                dx, dy = xa - xb, ya - yb
                dist = math.hypot(dx, dy) or 0.01
                force = (k * k) / dist
                fx, fy = (dx / dist) * force, (dy / dist) * force
                disp[id_a][0] += fx
                disp[id_a][1] += fy
                disp[id_b][0] -= fx
                disp[id_b][1] -= fy
        # attraction
        for edge in edges:
            src, tgt = edge["source"], edge["target"]
            if src not in positions or tgt not in positions:
                continue
            xa, ya = positions[src]
            xb, yb = positions[tgt]
            dx, dy = xa - xb, ya - yb
            dist = math.hypot(dx, dy) or 0.01
            weight = float(edge.get("weight") or 1)
            force = (dist * dist) / k * min(weight, 4) * 0.15
            fx, fy = (dx / dist) * force, (dy / dist) * force
            disp[src][0] -= fx
            disp[src][1] -= fy
            disp[tgt][0] += fx
            disp[tgt][1] += fy
        # apply
        for nid, (dx, dy) in disp.items():
            dist = math.hypot(dx, dy) or 0.01
            positions[nid][0] += (dx / dist) * min(dist, temperature)
            positions[nid][1] += (dy / dist) * min(dist, temperature)
            positions[nid][0] = min(width - 20, max(20, positions[nid][0]))
            positions[nid][1] = min(height - 20, max(20, positions[nid][1]))
        temperature *= 0.92

    out = []
    for node in nodes:
        x, y = positions[node["id"]]
        out.append({**node, "x": round(x, 2), "y": round(y, 2)})
    return out


def visualization_payload(paths, *, neo: Neo4jConfig | None = None) -> dict[str, Any]:
    """Layout-ready payload for the Maintain observatory (works offline)."""
    from src.maintain.graph import build_chain_graph

    graph = build_chain_graph(paths)
    # Technique co-occurrence subgraph for force layout
    tech_nodes = [
        {
            "id": row["technique"],
            "label": row["label"],
            "kind": "technique",
            "weight": row["count"],
        }
        for row in (graph.get("technique_frequency") or [])[:28]
    ]
    tech_ids = {n["id"] for n in tech_nodes}
    # rebuild co-occur among top techs from fingerprints
    pair_w: dict[tuple[str, str], int] = {}
    for chain in graph.get("chains") or []:
        keys = [k for k in (chain.get("techniques") or []) if k in tech_ids]
        keys = sorted(set(keys))
        for i, a in enumerate(keys):
            for b in keys[i + 1 :]:
                pair_w[(a, b)] = pair_w.get((a, b), 0) + 1
    tech_edges = [
        {"source": a, "target": b, "weight": w}
        for (a, b), w in pair_w.items()
    ]
    laid = force_layout(tech_nodes, tech_edges, width=720, height=460)

    # Bipartite positions (chains left, techniques right)
    chains = (graph.get("chains") or [])[:20]
    techs = (graph.get("technique_frequency") or [])[:24]
    bipartite_nodes = []
    bipartite_edges = []
    h = 520
    for i, chain in enumerate(chains):
        y = 30 + (i * (h - 60)) / max(len(chains) - 1, 1)
        bipartite_nodes.append(
            {
                "id": f"chain:{chain['id']}",
                "label": chain["name"],
                "kind": "chain",
                "x": 40,
                "y": round(y, 2),
                "weight": chain.get("technique_count") or 1,
            }
        )
    tech_y = {
        row["technique"]: 30 + (i * (h - 60)) / max(len(techs) - 1, 1)
        for i, row in enumerate(techs)
    }
    for row in techs:
        bipartite_nodes.append(
            {
                "id": f"tech:{row['technique']}",
                "label": row["label"],
                "kind": "technique",
                "x": 680,
                "y": round(tech_y[row["technique"]], 2),
                "weight": row["count"],
            }
        )
    for chain in chains:
        for tech in chain.get("techniques") or []:
            if tech in tech_y:
                bipartite_edges.append(
                    {
                        "source": f"chain:{chain['id']}",
                        "target": f"tech:{tech}",
                        "weight": 1,
                    }
                )

    status = neo4j_status(neo) if neo else {"ready": False, "detail": "not configured"}
    return {
        **graph,
        "layouts": {
            "cooccurrence": {
                "width": 720,
                "height": 460,
                "nodes": laid,
                "edges": tech_edges,
            },
            "bipartite": {
                "width": 760,
                "height": h,
                "nodes": bipartite_nodes,
                "edges": bipartite_edges,
            },
        },
        "neo4j": status,
    }


def try_sync_after_build(config: AppConfig, payload: dict[str, Any]) -> dict[str, Any]:
    """Best-effort Neo4j push used by build_chain_graph; never raises to callers."""
    if not config.neo4j.enabled:
        return {"ok": False, "detail": "disabled", "synced": False}
    try:
        result = sync_library_to_neo4j(config)
        payload["neo4j"] = {
            "ready": True,
            "synced": True,
            "uri": result.get("uri"),
            "browser_url": result.get("browser_url"),
            "counts": result.get("counts"),
            "synced_at": result.get("synced_at"),
            "detail": "ok",
        }
        return result
    except Exception as exc:
        info = {
            "ok": False,
            "synced": False,
            "ready": False,
            "detail": f"{type(exc).__name__}: {exc}",
            "uri": config.neo4j.uri,
            "browser_url": config.neo4j.browser_url,
        }
        payload["neo4j"] = info
        return info
