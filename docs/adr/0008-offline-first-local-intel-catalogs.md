# 0008. Offline-first local intel catalogs (NVD SQLite, MITRE JSON, CTI pack files)

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

Scenario generation needs CVE, ATT&CK and CTI context. The source carried only a `--db-path` placeholder and a single demo CVE fixture. Tests and sandboxes have to work without network access.

## Decision

Intel lives under `output/workspace/intel/`, with a `manifest.json` status record:

- **NVD**: SQLite `nvd/cve.sqlite` (CVSS, CWEs, CPEs). It is filled from an offline JSON import or from NVD API 2.0 with optional `NVD_API_KEY` and paging/sleep. A demo seed is also available.
- **MITRE ATT&CK**: an enterprise STIX bundle reduced to `mitre/techniques.json`, excluding revoked and deprecated entries. Intrusion sets become `mitre-group-*` CTI packs through `uses` relationships.
- **CTI packs**: one JSON file per pack under `cti/`. Packs come from manual ingest, CISA KEV (individual + rollup), CISA advisories RSS (with a page-body fetch) and geopolitical research RSS (`msft-security`, `securelist`; unattributed items dropped). Each online source replaces only its own packs.
- Online refresh happens only when an operator runs a CLI or GUI command. Every online function takes an injectable `httpx.Client` so it can be tested with `MockTransport`.
- Scenarios use the NVD store when it is populated and otherwise fall back to the packaged demo CVE. CTI matching works on technique overlap.

## Consequences

### Positive
- Tests and demos are deterministic and offline. Real data is one command away.
- Each source refreshes independently. A partial geointel failure keeps the other feeds, and a total failure raises.

### Negative
- CTI packs are loose files with no index, so a scan costs O(packs) per query.
- The retained `--db-path` default (`cve_database.db`) usually does not exist and silently falls through to the default store. The CVE source label can then name a missing file.
- External feed URLs and HTML page scraping can break without warning.

## Alternatives considered
- Live API calls during each workflow run. Not chosen; runs read local catalogs only (inferred from the design).
- A single database for all intel. Not evidenced.

## Evidence
- `src/intel/nvd.py`, `src/intel/mitre.py`, `src/intel/cti.py`, `src/intel/advisories.py`, `src/intel/geointel.py`, `src/intel/manifest.py`, `src/intel/patch_catalog.py`; `src/scenario.py` `load_cves_for_scenario`
- `tests/test_intel.py`; `tests/fixtures/intel/*`; `README.md` "Workspace, intel, and lineage"
- Commits `38dd3fb`, `1be6f27` (CISA KEV packs), `95c4864` (MITRE groups, CISA advisories), `24fcb6b` (advisory page bodies), `baa8eb2` (geopolitical research feeds)
