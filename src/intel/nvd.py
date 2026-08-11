"""Local NVD/CVE catalog backed by SQLite.

I ingest offline NVD JSON (or our demo CVE fixture), optionally pull a bounded
slice from the NVD 2.0 API, and answer simple searches for the scenario CVE
stage. If the store is empty I let the workflow fall back to the packaged demo.
"""


from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

import httpx

from src.config import PACKAGE_ROOT, PathConfig
from src.intel.manifest import now_iso, patch_catalog
from src.workspace import intel_dir

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def default_cve_db_path(paths: PathConfig, override: str | Path | None = None) -> Path:
    if override:
        candidate = Path(override)
        if not candidate.is_absolute():
            candidate = paths.project_root / candidate
        return candidate
    return intel_dir(paths) / "nvd" / "cve.sqlite"


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            cvss REAL,
            vector TEXT,
            cwe TEXT,
            published TEXT,
            platforms TEXT,
            raw_json TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss)")
    conn.commit()
    return conn


def cve_count(db_path: Path) -> int:
    if not db_path.is_file():
        return 0
    with _connect(db_path) as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()
        return int(row["n"] if row else 0)


def _cvss_from_metrics(metrics: dict[str, Any] | None) -> tuple[float | None, str]:
    if not isinstance(metrics, dict):
        return None, ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key)
        if not isinstance(rows, list) or not rows:
            continue
        primary = rows[0] if isinstance(rows[0], dict) else {}
        data = primary.get("cvssData") if isinstance(primary.get("cvssData"), dict) else {}
        score = data.get("baseScore")
        vector = str(data.get("vectorString") or primary.get("vectorString") or "")
        try:
            return float(score), vector
        except (TypeError, ValueError):
            continue
    return None, ""


def _description_from_cve(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions")
    if not isinstance(descriptions, list):
        return ""
    for lang in ("en", "en-US"):
        for row in descriptions:
            if isinstance(row, dict) and row.get("lang") == lang:
                return str(row.get("value") or "")
    for row in descriptions:
        if isinstance(row, dict) and row.get("value"):
            return str(row["value"])
    return ""


def _cwe_from_cve(cve: dict[str, Any]) -> str:
    weaknesses = cve.get("weaknesses")
    if not isinstance(weaknesses, list):
        return ""
    ids: list[str] = []
    for weak in weaknesses:
        if not isinstance(weak, dict):
            continue
        for desc in weak.get("description") or []:
            if isinstance(desc, dict) and desc.get("value"):
                ids.append(str(desc["value"]))
    return ", ".join(ids)


def _platforms_from_cve(cve: dict[str, Any]) -> str:
    configs = cve.get("configurations")
    text = json.dumps(configs) if configs else ""
    hits = []
    for token in ("linux", "windows", "macos", "android", "ios"):
        if token in text.casefold():
            hits.append(token)
    return ",".join(hits)


def normalize_nvd_item(item: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize NVD 2.0 vulnerability object or project demo CVE row."""
    if "cve" in item and isinstance(item["cve"], dict):
        cve = item["cve"]
        cve_id = str(cve.get("id") or "").strip()
        if not cve_id:
            return None
        score, vector = _cvss_from_metrics(cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {})
        return {
            "cve_id": cve_id,
            "description": _description_from_cve(cve),
            "cvss": score,
            "vector": vector,
            "cwe": _cwe_from_cve(cve),
            "published": str(cve.get("published") or ""),
            "platforms": _platforms_from_cve(cve),
            "raw_json": json.dumps(item),
        }
    # Project demo / simplified shape
    cve_id = str(item.get("id") or item.get("cve_id") or "").strip()
    if not cve_id:
        return None
    try:
        score = float(item["score"]) if item.get("score") is not None else None
    except (TypeError, ValueError):
        score = None
    platforms = []
    if item.get("affects_linux"):
        platforms.append("linux")
    if item.get("affects_windows"):
        platforms.append("windows")
    return {
        "cve_id": cve_id,
        "description": str(item.get("description") or ""),
        "cvss": score,
        "vector": str(item.get("attack_vector") or item.get("vector") or ""),
        "cwe": str(item.get("cwe") or ""),
        "published": str(item.get("published") or ""),
        "platforms": ",".join(platforms),
        "raw_json": json.dumps(item),
    }


def _upsert_rows(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> int:
    count = 0
    for row in rows:
        conn.execute(
            """
            INSERT INTO cves (cve_id, description, cvss, vector, cwe, published, platforms, raw_json)
            VALUES (:cve_id, :description, :cvss, :vector, :cwe, :published, :platforms, :raw_json)
            ON CONFLICT(cve_id) DO UPDATE SET
                description=excluded.description,
                cvss=excluded.cvss,
                vector=excluded.vector,
                cwe=excluded.cwe,
                published=excluded.published,
                platforms=excluded.platforms,
                raw_json=excluded.raw_json
            """,
            row,
        )
        count += 1
    conn.commit()
    return count


def import_nvd_payload(paths: PathConfig, payload: Any, *, db_path: Path | None = None) -> dict[str, Any]:
    """Ingest NVD 2.0 JSON, list of CVE objects, or demo-style array."""
    target = db_path or default_cve_db_path(paths)
    rows: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        vulns = payload.get("vulnerabilities")
        if isinstance(vulns, list):
            for item in vulns:
                if isinstance(item, dict):
                    normalized = normalize_nvd_item(item)
                    if normalized:
                        rows.append(normalized)
        elif "id" in payload or "cve_id" in payload or "cve" in payload:
            normalized = normalize_nvd_item(payload)
            if normalized:
                rows.append(normalized)
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                normalized = normalize_nvd_item(item)
                if normalized:
                    rows.append(normalized)
    if not rows:
        raise ValueError("No CVE records found in import payload")
    with _connect(target) as conn:
        written = _upsert_rows(conn, rows)
        total = int(conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"])
    patch_catalog(
        paths,
        "nvd",
        status="ready",
        path=str(target),
        cve_count=total,
        last_success_at=now_iso(),
        last_error=None,
        source="offline-import",
    )
    return {"written": written, "cve_count": total, "path": str(target)}


def import_nvd_file(paths: PathConfig, path: Path | str, *, db_path: Path | None = None) -> dict[str, Any]:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"NVD import file not found: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {source}: {exc}") from exc
    result = import_nvd_payload(paths, payload, db_path=db_path)
    result["source_file"] = str(source)
    return result


def seed_demo_cves(paths: PathConfig, *, db_path: Path | None = None) -> dict[str, Any]:
    demo = PACKAGE_ROOT / "data" / "demo_critical_vulnerability.json"
    return import_nvd_file(paths, demo, db_path=db_path)


def query_cves(
    paths: PathConfig,
    *,
    min_cvss: float = 0.0,
    q: str = "",
    platform: str | None = None,
    limit: int = 25,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    target = default_cve_db_path(paths, db_path)
    if not target.is_file():
        return []
    clauses = ["1=1"]
    params: list[Any] = []
    if min_cvss > 0:
        clauses.append("(cvss IS NOT NULL AND cvss >= ?)")
        params.append(float(min_cvss))
    if q.strip():
        clauses.append("(cve_id LIKE ? OR description LIKE ? OR cwe LIKE ?)")
        like = f"%{q.strip()}%"
        params.extend([like, like, like])
    if platform and platform.strip():
        clauses.append("(platforms LIKE ? OR platforms = '' OR platforms IS NULL)")
        params.append(f"%{platform.strip().casefold()}%")
    sql = f"""
        SELECT cve_id, description, cvss, vector, cwe, published, platforms
        FROM cves
        WHERE {' AND '.join(clauses)}
        ORDER BY cvss DESC NULLS LAST, cve_id
        LIMIT ?
    """
    params.append(max(1, min(int(limit), 500)))
    with _connect(target) as conn:
        try:
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            # SQLite without NULLS LAST
            sql = sql.replace(" NULLS LAST", "")
            rows = conn.execute(sql, params).fetchall()
    return [
        {
            "id": row["cve_id"],
            "description": row["description"] or "",
            "score": row["cvss"],
            "attack_vector": row["vector"] or "",
            "cwe": row["cwe"] or "",
            "published": row["published"] or "",
            "platforms": row["platforms"] or "",
        }
        for row in rows
    ]


def load_cves_for_scenario(
    paths: PathConfig,
    *,
    min_cvss: float,
    platform_text: str = "",
    limit: int = 20,
    db_path: Path | str | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """Return CVE rows for the scenario agent plus a source label."""
    target = default_cve_db_path(paths, db_path)
    platform_hint = None
    text = platform_text.casefold()
    for token in ("linux", "windows", "macos"):
        if token in text:
            platform_hint = token
            break
    rows = query_cves(
        paths,
        min_cvss=min_cvss,
        platform=platform_hint,
        limit=limit,
        db_path=target if target.is_file() else None,
    )
    if rows:
        return rows, f"nvd-store:{target}"
    # Fallback to packaged demo fixture
    demo_path = PACKAGE_ROOT / "data" / "demo_critical_vulnerability.json"
    demo = json.loads(demo_path.read_text(encoding="utf-8"))
    if isinstance(demo, list):
        filtered = []
        for item in demo:
            if not isinstance(item, dict):
                continue
            try:
                score = float(item.get("score") or 0)
            except (TypeError, ValueError):
                score = 0.0
            if score >= min_cvss:
                filtered.append(item)
        return filtered or list(demo), "demo-fixture"
    return [], "empty"


def update_nvd_online(
    paths: PathConfig,
    *,
    results_per_page: int = 50,
    max_pages: int = 2,
    min_cvss: float | None = 7.0,
    api_key: str | None = None,
    db_path: Path | None = None,
    sleep_s: float = 0.6,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Pull a bounded slice of NVD 2.0 results (operator-triggered, rate-limited)."""
    key = api_key if api_key is not None else os.getenv("NVD_API_KEY", "")
    headers = {"User-Agent": "langgraph-stride-intel/0.1"}
    if key:
        headers["apiKey"] = key
    owns_client = client is None
    http = client or httpx.Client(timeout=60.0, headers=headers)
    written = 0
    pages = 0
    try:
        patch_catalog(paths, "nvd", status="updating", last_error=None)
        start_index = 0
        while pages < max_pages:
            params: dict[str, Any] = {
                "resultsPerPage": max(1, min(results_per_page, 2000)),
                "startIndex": start_index,
            }
            if min_cvss is not None:
                params["cvssV3Severity"] = "HIGH" if min_cvss >= 7 else "MEDIUM"
            response = http.get(NVD_API, params=params)
            response.raise_for_status()
            payload = response.json()
            batch = import_nvd_payload(paths, payload, db_path=db_path)
            written += int(batch["written"])
            pages += 1
            total = int(payload.get("totalResults") or 0)
            start_index += int(payload.get("resultsPerPage") or results_per_page)
            if start_index >= total or not payload.get("vulnerabilities"):
                break
            time.sleep(sleep_s)
        total_count = cve_count(default_cve_db_path(paths, db_path))
        patch_catalog(
            paths,
            "nvd",
            status="ready",
            path=str(default_cve_db_path(paths, db_path)),
            cve_count=total_count,
            last_success_at=now_iso(),
            last_error=None,
            source="nvd-api-2.0",
        )
        return {"written": written, "pages": pages, "cve_count": total_count}
    except Exception as exc:
        patch_catalog(paths, "nvd", status="error", last_error=str(exc))
        raise
    finally:
        if owns_client:
            http.close()
