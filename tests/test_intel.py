import json
from pathlib import Path

import httpx

from src.config import AppConfig, PathConfig, build_inference_config
from src.intel.advisories import (
    advisories_from_rss,
    import_cisa_advisories_file,
    update_cisa_advisories_online,
)
from src.intel.cti import (
    import_cisa_kev_file,
    ingest_cti_pack,
    list_cti_packs,
    matching_cti_packs,
    update_cisa_kev_online,
)
from src.intel.manifest import intel_status
from src.intel.mitre import import_mitre_file, search_techniques, update_mitre_online
from src.intel.nvd import import_nvd_file, query_cves, seed_demo_cves, update_nvd_online
from src.scenario import ScenarioWorkflow

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "intel"


def paths(tmp_path: Path) -> PathConfig:
    return PathConfig(
        project_root=tmp_path,
        data_dir=ROOT / "src" / "data",
        prompts_dir=ROOT / "src" / "prompts",
        output_dir=tmp_path / "output",
    )


def test_import_nvd_and_query_filters(tmp_path):
    cfg = paths(tmp_path)
    result = import_nvd_file(cfg, FIXTURES / "nvd_sample.json")
    assert result["written"] == 2
    assert result["cve_count"] == 2
    high = query_cves(cfg, min_cvss=9.0)
    assert len(high) == 1
    assert high[0]["id"] == "CVE-2024-0001"
    hits = query_cves(cfg, q="disclosure")
    assert hits[0]["id"] == "CVE-2024-0002"
    status = intel_status(cfg)
    assert status["catalogs"]["nvd"]["status"] == "ready"
    assert status["catalogs"]["nvd"]["cve_count"] == 2


def test_seed_demo_cves(tmp_path):
    cfg = paths(tmp_path)
    result = seed_demo_cves(cfg)
    assert result["cve_count"] >= 1
    assert query_cves(cfg)


def test_import_mitre_and_search(tmp_path):
    cfg = paths(tmp_path)
    result = import_mitre_file(cfg, FIXTURES / "mitre_sample.json")
    assert result["technique_count"] == 2  # revoked excluded
    rows = search_techniques(cfg, "T1190")
    assert rows[0]["technique_id"] == "T1190"
    rows = search_techniques(cfg, "powershell")
    assert rows[0]["technique_id"] == "T1059.001"
    assert rows[0]["is_subtechnique"] is True


def test_import_mitre_builds_group_packs(tmp_path):
    cfg = paths(tmp_path)
    result = import_mitre_file(cfg, FIXTURES / "mitre_sample.json")
    assert result["group_pack_count"] == 1  # deprecated group excluded
    packs = {pack["id"]: pack for pack in list_cti_packs(cfg)}
    pack = packs["mitre-group-g0001"]
    assert pack["source"] == "mitre-attack-group"
    assert pack["actors"] == ["Test Panda", "Granite Typhoon"]
    assert pack["techniques"] == ["T1190"]  # resolved via "uses" relationship
    assert "PRC-nexus" in pack["notes"]
    matched = matching_cti_packs(cfg, ["T1190"])
    assert any(p["id"] == "mitre-group-g0001" for p in matched)


def test_cti_ingest_and_match(tmp_path):
    cfg = paths(tmp_path)
    ingest_cti_pack(cfg, FIXTURES / "cti_sample.json")
    packs = list_cti_packs(cfg)
    assert packs[0]["id"] == "api-threats"
    matched = matching_cti_packs(cfg, ["T1190"])
    assert matched[0]["title"] == "API Exposure Campaign Notes"


def test_cisa_kev_offline_import_builds_packs(tmp_path):
    cfg = paths(tmp_path)
    result = import_cisa_kev_file(cfg, FIXTURES / "cisa_kev_sample.json", recent_limit=10)
    assert result["written"] >= 3  # individuals + rollup
    assert result["catalog_version"] == "2026.01.01-test"
    packs = list_cti_packs(cfg)
    ids = {pack["id"] for pack in packs}
    assert "cisa-kev-rollup" in ids
    assert "cisa-kev-cve-2024-1111" in ids
    assert "cisa-kev-cve-2024-2222" in ids
    # SQLi maps to T1190 so scenario matching can hit KEV packs
    matched = matching_cti_packs(cfg, ["T1190"])
    assert any(pack["source"] == "cisa-kev" for pack in matched)
    status = intel_status(cfg)
    assert status["catalogs"]["cti"]["status"] == "ready"
    assert status["catalogs"]["cti"]["source"] == "cisa-kev"


def test_cisa_kev_online_uses_mock_transport(tmp_path):
    cfg = paths(tmp_path)
    payload = json.loads((FIXTURES / "cisa_kev_sample.json").read_text())

    def handler(request: httpx.Request) -> httpx.Response:
        assert "cisa.gov" in str(request.url)
        return httpx.Response(200, json=payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = update_cisa_kev_online(cfg, client=client, recent_limit=5)
    assert result["written"] >= 2
    assert result["url"]


def test_cisa_advisories_offline_import_builds_packs(tmp_path):
    cfg = paths(tmp_path)
    result = import_cisa_advisories_file(cfg, FIXTURES / "cisa_advisories_sample.xml")
    assert result["written"] == 3  # AA-numbered + #StopRansomware joint items
    packs = {pack["id"]: pack for pack in list_cti_packs(cfg)}
    gru = packs["cisa-adv-aa25-141a"]
    assert gru["source"] == "cisa-advisory"
    assert "russia-nexus" in gru["actors"]
    assert "T1190" in gru["techniques"]
    prc = packs["cisa-adv-aa25-100b"]
    assert "prc-nexus" in prc["actors"]
    assert prc["techniques"]  # auth bypass / SQLi hints mapped
    stop = packs["cisa-adv-stopransomware-interlock-ransomware"]
    assert "ransomware-operators" in stop["actors"]


def test_cisa_advisories_online_uses_mock_transport(tmp_path):
    cfg = paths(tmp_path)
    xml_text = (FIXTURES / "cisa_advisories_sample.xml").read_text()
    page_html = """
    <html><head><script>var x = 1;</script></head><body>
    <p>Full advisory body: DPRK-nexus Lazarus Group actors used T1059 and T1203
    against defense contractors after a drive-by compromise.</p>
    </body></html>
    """

    def handler(request: httpx.Request) -> httpx.Response:
        assert "cisa.gov" in str(request.url)
        if str(request.url).endswith("all.xml"):
            return httpx.Response(200, text=xml_text)
        return httpx.Response(200, text=page_html)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = update_cisa_advisories_online(cfg, client=client, limit=10)
    assert result["written"] == 3
    assert result["url"]
    packs = {pack["id"]: pack for pack in list_cti_packs(cfg)}
    gru = packs["cisa-adv-aa25-141a"]
    # Body-only signals: Lazarus actor + explicit ATT&CK IDs from the page.
    assert "dprk-nexus" in gru["actors"]
    assert "T1203" in gru["techniques"]
    assert "Advisory body (excerpt)" in gru["notes"]


def test_advisories_fallback_to_newest_when_no_aa_items():
    xml = """<rss version="2.0"><channel>
      <item><title>Plain alert</title><link>https://x.test/1</link>
      <description>Ransomware note.</description></item>
    </channel></rss>"""
    packs = advisories_from_rss(xml)
    assert len(packs) == 1
    assert packs[0]["id"] == "cisa-adv-plain-alert"
    assert "ransomware-operators" in packs[0]["actors"]


def test_update_nvd_online_uses_mock_transport(tmp_path):
    cfg = paths(tmp_path)
    payload = json.loads((FIXTURES / "nvd_sample.json").read_text())

    def handler(request: httpx.Request) -> httpx.Response:
        assert "services.nvd.nist.gov" in str(request.url)
        return httpx.Response(200, json=payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = update_nvd_online(cfg, max_pages=1, client=client, sleep_s=0)
    assert result["written"] == 2
    assert result["cve_count"] == 2


def test_update_mitre_online_uses_mock_transport(tmp_path):
    cfg = paths(tmp_path)
    payload = json.loads((FIXTURES / "mitre_sample.json").read_text())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = update_mitre_online(cfg, client=client)
    assert result["technique_count"] == 2


class FakeClient:
    def __init__(self):
        self.prompts = []

    def chat(self, messages, **kwargs):
        self.prompts.append(messages[-1]["content"])
        return "report body"


def test_scenario_cve_uses_nvd_store_and_cti_packs(tmp_path):
    cfg = paths(tmp_path)
    import_nvd_file(cfg, FIXTURES / "nvd_sample.json")
    ingest_cti_pack(cfg, FIXTURES / "cti_sample.json")
    model = tmp_path / "model.json"
    model.write_text(
        json.dumps(
            {
                "system_metadata": {
                    "aa_id": "AA123456",
                    "Application Name": "Payments",
                    "SWC Description": "Payment service",
                    "Solution Description": "Processes payments",
                    "Platform": ["Linux"],
                    "Confidentiality": "High",
                    "Integrity": "High",
                },
                "Spoofing": [],
                "dread_assessment": [],
                "_meta": {"artifact_id": "tm_AA123456_1", "aa_id": "AA123456"},
            }
        ),
        encoding="utf-8",
    )
    client = FakeClient()
    app = AppConfig(
        inference=build_inference_config("omlx"),
        paths=cfg,
    )
    path = ScenarioWorkflow(app, client=client).run(
        model, "API Exposure Attack [New]", min_cvss=9.0
    )
    assert path.is_file()
    assert "CVE-2024-0001" in client.prompts[0]
    assert "nvd-store" in client.prompts[0]
    # CTI prompt is second call
    assert "API Exposure Campaign Notes" in client.prompts[1]


def test_scenario_cti_uses_graph_briefing_when_available(tmp_path, monkeypatch):
    import src.maintain.neo4j_graph as ng

    def fake_run_cypher(config, query, params=None, *, limit=100):
        return [
            {
                "tid": "T1190",
                "actors": ["Graph Bear"],
                "advisories": ["AA99-001A"],
                "kev_cves": ["CVE-2025-9999"],
            }
        ]

    monkeypatch.setattr(ng, "run_cypher", fake_run_cypher)
    cfg = paths(tmp_path)
    import_nvd_file(cfg, FIXTURES / "nvd_sample.json")
    model = tmp_path / "model.json"
    model.write_text(
        json.dumps(
            {
                "system_metadata": {"aa_id": "AA123456", "Application Name": "Payments"},
                "Spoofing": [],
                "dread_assessment": [],
                "_meta": {"artifact_id": "tm_AA123456_1", "aa_id": "AA123456"},
            }
        ),
        encoding="utf-8",
    )
    client = FakeClient()
    app = AppConfig(inference=build_inference_config("omlx"), paths=cfg)
    ScenarioWorkflow(app, client=client).run(model, "API Exposure Attack [New]", min_cvss=9.0)
    # CTI prompt carries the graph briefing alongside file packs
    assert "Graph Bear" in client.prompts[1]
    assert "CVE-2025-9999" in client.prompts[1]


def test_scenario_cti_survives_graph_outage(tmp_path, monkeypatch):
    import src.maintain.neo4j_graph as ng

    def boom(config, query, params=None, *, limit=100):
        raise ConnectionError("bolt unreachable")

    monkeypatch.setattr(ng, "run_cypher", boom)
    cfg = paths(tmp_path)
    import_nvd_file(cfg, FIXTURES / "nvd_sample.json")
    model = tmp_path / "model.json"
    model.write_text(
        json.dumps(
            {
                "system_metadata": {"aa_id": "AA123456", "Application Name": "Payments"},
                "Spoofing": [],
                "dread_assessment": [],
                "_meta": {"artifact_id": "tm_AA123456_1", "aa_id": "AA123456"},
            }
        ),
        encoding="utf-8",
    )
    client = FakeClient()
    app = AppConfig(inference=build_inference_config("omlx"), paths=cfg)
    path = ScenarioWorkflow(app, client=client).run(
        model, "API Exposure Attack [New]", min_cvss=9.0
    )
    assert path.is_file()  # file-pack baseline still produces a report


def test_geointel_offline_import_filters_unattributed(tmp_path):
    from src.intel.geointel import feed_keys, import_geointel_file

    cfg = paths(tmp_path)
    assert feed_keys() == ["msft-security", "securelist"]
    result = import_geointel_file(cfg, "securelist", FIXTURES / "geointel_sample.xml")
    assert result["written"] == 2  # product roundup carries no attribution
    packs = {pack["id"]: pack for pack in list_cti_packs(cfg)}
    lazarus = packs["securelist-lazarus-group-targets-defense-contractors-with-new-loader"]
    assert lazarus["source"] == "securelist"
    assert lazarus["actors"] == ["dprk-nexus"]
    volt = packs["securelist-volt-typhoon-living-off-the-land-campaign-hits-critical-infr"]
    assert volt["actors"] == ["prc-nexus"]
    assert "T1068" in volt["techniques"]  # privilege-escalation hint


def test_geointel_online_all_feeds_mock_transport(tmp_path):
    from src.intel.geointel import FEEDS, update_geointel_online

    cfg = paths(tmp_path)
    xml_text = (FIXTURES / "geointel_sample.xml").read_text()
    page_html = """
    <html><head><script>var x = 1;</script></head><body>
    <p>Full article: the actors used T1059 and T1203 after the initial access.</p>
    </body></html>
    """

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url in {feed["url"] for feed in FEEDS.values()}:
            return httpx.Response(200, text=xml_text)
        return httpx.Response(200, text=page_html)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = update_geointel_online(cfg, "all", client=client, limit=10)
    assert len(result["feeds"]) == 2
    assert result["written"] == 4  # 2 attributed items per feed
    packs = list_cti_packs(cfg)
    sources = {pack["source"] for pack in packs}
    assert sources == {"securelist", "msft-security"}
    lazarus = next(p for p in packs if "lazarus" in p["id"] and p["source"] == "securelist")
    # Body-only signals: explicit ATT&CK IDs mined from the article page.
    assert "T1059" in lazarus["techniques"]
    assert "T1203" in lazarus["techniques"]
    assert "Article body (excerpt)" in lazarus["notes"]


def test_geointel_replaces_only_its_own_source(tmp_path):
    from src.intel.geointel import import_geointel_file

    cfg = paths(tmp_path)
    import_geointel_file(cfg, "securelist", FIXTURES / "geointel_sample.xml")
    import_geointel_file(cfg, "msft-security", FIXTURES / "geointel_sample.xml")
    assert len(list_cti_packs(cfg)) == 4
    # re-importing one feed replaces its packs but leaves the other feed alone
    import_geointel_file(cfg, "securelist", FIXTURES / "geointel_sample.xml")
    packs = list_cti_packs(cfg)
    assert len(packs) == 4
    assert {pack["source"] for pack in packs} == {"securelist", "msft-security"}


def test_geointel_partial_failure_keeps_other_feeds(tmp_path):
    import pytest

    from src.intel.geointel import FEEDS, update_geointel_online

    cfg = paths(tmp_path)
    xml_text = (FIXTURES / "geointel_sample.xml").read_text()
    bad_url = FEEDS["msft-security"]["url"]

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == bad_url:
            return httpx.Response(403, text="blocked")
        if str(request.url) == FEEDS["securelist"]["url"]:
            return httpx.Response(200, text=xml_text)
        return httpx.Response(200, text="<html><body><p>article</p></body></html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = update_geointel_online(cfg, "all", client=client, limit=10)
    assert [row["feed"] for row in result["feeds"]] == ["securelist"]
    assert "msft-security" in result["errors"]

    def always_fail(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="down")

    failing = httpx.Client(transport=httpx.MockTransport(always_fail))
    with pytest.raises(RuntimeError, match="all feeds"):
        update_geointel_online(cfg, "all", client=failing, limit=10)
