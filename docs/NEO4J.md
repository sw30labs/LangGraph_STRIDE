# STRIDE attack-template Neo4j

Dedicated graph database for the Maintain studio. **Not** the TwinOps graph
(`twinops-neo4j` on 7474/7687).

| | TwinOps | STRIDE |
|---|---|---|
| Container | `twinops-neo4j` | `stride-neo4j` |
| Browser | http://127.0.0.1:7474 | http://127.0.0.1:7475 |
| Bolt | `bolt://127.0.0.1:7687` | `bolt://127.0.0.1:7688` |
| Default auth | (your TwinOps secret) | `neo4j` / `stride-graph-dev` |

## Start

```bash
docker compose -f compose.neo4j.yaml up -d
# wait until healthy
docker compose -f compose.neo4j.yaml ps
```

Override the password **before first boot** (empty volume):

```bash
export STRIDE_NEO4J_PASSWORD='your-strong-secret'
docker compose -f compose.neo4j.yaml up -d
```

Also set the same value in `.env` as `STRIDE_NEO4J_PASSWORD` so the app can connect.

## Schema

```
(:Chain {id, name, description, source, updated_at, technique_count, tags})
(:Technique {key, technique_id, name, frequency, is_subtechnique})
(:Tactic {name, ord})
(:Tag {name})
(:LibraryMeta {id:'stride', synced_at, …})

(Chain)-[:USES {step, tactic, raw}]->(Technique)
(Technique)-[:IN_TACTIC]->(Tactic)
(Technique)-[:CO_OCCURS {weight, shared_chains}]->(Technique)
(Chain)-[:SIMILAR_TO {jaccard, verdict, shared_count}]->(Chain)
(Chain)-[:TAGGED]->(Tag)
```

Source of truth remains `output/workspace/attack_templates.json`. Neo4j is a
**full-rebuild projection** on each sync (detach-delete + recreate).

## Sync

```bash
pip install -e ".[graph]"   # neo4j driver (the dev extra alone is not enough)
python -m src.cli maintain neo4j-status
python -m src.cli maintain neo4j-sync
python -m src.cli maintain graph              # analytics + sync
python -m src.cli maintain neo4j-query hub_techniques
python -m src.cli maintain neo4j-query near_duplicates
python -m src.cli maintain neo4j-query dark_matter
```

GUI: **Maintain → Sync Neo4j** or **Refresh galaxy** (syncs by default).

## Environment

| Variable | Default |
|---|---|
| `STRIDE_NEO4J_ENABLED` | `true` |
| `STRIDE_NEO4J_URI` | `bolt://127.0.0.1:7688` |
| `STRIDE_NEO4J_USER` | `neo4j` |
| `STRIDE_NEO4J_PASSWORD` | `stride-graph-dev` |
| `STRIDE_NEO4J_DATABASE` | `neo4j` |
| `STRIDE_NEO4J_BROWSER` | `http://127.0.0.1:7475` |

## Browser playground snippets

Hub techniques:

```cypher
MATCH (t:Technique)<-[:USES]-(c:Chain)
RETURN t.name, t.frequency, count(c) AS chains
ORDER BY t.frequency DESC LIMIT 20
```

Near-duplicates:

```cypher
MATCH (a:Chain)-[s:SIMILAR_TO]->(b:Chain)
RETURN a.name, b.name, s.jaccard, s.verdict
ORDER BY s.jaccard DESC
```

Dark-matter candidates (rare techniques that never co-occur):

```cypher
MATCH (a:Technique), (b:Technique)
WHERE a.key < b.key AND a.frequency <= 3 AND b.frequency <= 3
  AND NOT (a)-[:CO_OCCURS]-(b)
RETURN a.name, b.name, a.frequency, b.frequency
ORDER BY a.frequency + b.frequency ASC LIMIT 30
```
