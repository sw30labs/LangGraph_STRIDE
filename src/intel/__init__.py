"""Local intel catalogs: NVD/CVE, MITRE ATT&CK, and CTI packs.

I keep vulnerability and ATT&CK data on disk under output/workspace/intel/.
Online updates only run when the operator asks; tests always use offline
fixtures so the gate never needs the network.
"""


from __future__ import annotations

from src.intel.cti import (
    delete_cti_pack,
    ingest_cti_pack,
    list_cti_packs,
    matching_cti_packs,
    upsert_cti_pack,
)
from src.intel.manifest import intel_status, load_manifest, save_manifest
from src.intel.mitre import (
    import_mitre_file,
    search_techniques,
    technique_count,
    update_mitre_online,
)
from src.intel.nvd import (
    default_cve_db_path,
    import_nvd_file,
    query_cves,
    seed_demo_cves,
    update_nvd_online,
)

__all__ = [
    "default_cve_db_path",
    "delete_cti_pack",
    "import_mitre_file",
    "import_nvd_file",
    "ingest_cti_pack",
    "intel_status",
    "list_cti_packs",
    "load_manifest",
    "matching_cti_packs",
    "query_cves",
    "save_manifest",
    "search_techniques",
    "seed_demo_cves",
    "technique_count",
    "update_mitre_online",
    "update_nvd_online",
    "upsert_cti_pack",
]
