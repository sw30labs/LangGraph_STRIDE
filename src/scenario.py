"""CVE, CTI, and cyber-threat scenario workflow."""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, TypedDict

import yaml
from langgraph.graph import END, StateGraph

from src.config import AppConfig
from src.inference_client import OpenAICompatibleClient, client_from_config
from src.threat_model import STRIDE_CATEGORIES


class ScenarioState(TypedDict, total=False):
    json_file: str
    attack_template: str
    db_path: str
    cvss_score: str
    cmdb_info: dict[str, Any]
    selected_template: str
    selected_techniques: list[str]
    stride_data: str
    dread_data: str
    controls_data: str
    cve_report: str
    cve_feedback: dict[str, Any]
    cve_approved: bool
    cti_report: str
    cti_feedback: dict[str, Any]
    cti_approved: bool
    scenario_report: str
    scenario_feedback: dict[str, Any]
    scenario_approved: bool
    final_output_path: str
    complete: bool


def _escape_format(value: str) -> str:
    return value.replace("{", "{{").replace("}", "}}")


def load_controls(path: Path) -> dict[str, str]:
    """Load the current 20-row controls taxonomy without a pandas dependency."""
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return {
            row["ID"]: f"{row['ID']} - {row['Title']}: {row['Description']}"
            for row in csv.DictReader(handle)
        }


class ScenarioWorkflow:
    """One provider-neutral LangGraph flow for the source scenario stages."""

    def __init__(
        self,
        config: AppConfig,
        client: OpenAICompatibleClient | None = None,
    ) -> None:
        self.config = config
        self.client = client or client_from_config(config.inference)
        prompts = yaml.safe_load(
            (config.paths.prompts_dir / "scenario_prompts.yml").read_text(encoding="utf-8")
        )
        templates = yaml.safe_load(
            (config.paths.prompts_dir / "scenario_templates.yml").read_text(encoding="utf-8")
        )
        self.prompts = prompts["scenario_prompts"]
        self.templates = templates
        self.graph = self._build_graph()

    def _ask(self, prompt: str) -> str:
        return self.client.chat(
            [{"role": "user", "content": prompt}],
            max_tokens=self.config.inference.max_tokens,
            disable_thinking=self.config.inference.disable_thinking,
            require_complete=True,
        )

    def _select(self, state: ScenarioState) -> ScenarioState:
        path = Path(state["json_file"])
        data = json.loads(path.read_text(encoding="utf-8"))
        metadata = data.get("system_metadata")
        if not isinstance(metadata, dict):
            raise ValueError("JSON file is missing a system_metadata object")

        raw_platforms = metadata.get("Platform", metadata.get("PLatform", []))
        if isinstance(raw_platforms, str):
            raw_platforms = [part.strip() for part in raw_platforms.split(",")]
        platforms = [str(value) for value in raw_platforms if str(value).lower() != "llama.cpp"]
        cmdb_info = {
            "AA ID": metadata.get("aa_id", metadata.get("AA ID", "")),
            "Application Name": metadata.get("Application Name", ""),
            "SWC Description": metadata.get("SWC Description", ""),
            "Solution Description": metadata.get("Solution Description", ""),
            "SWC Responsible SDU/Stream": metadata.get("SWC Responsible SDU/Stream", ""),
            "Confidentiality": metadata.get("Confidentiality", ""),
            "Integrity": metadata.get("Integrity", ""),
            "Technology BCM": metadata.get("Technology BCM", ""),
            "Platform": ", ".join(platforms),
            "Externally facing": metadata.get("Externally facing", ""),
            "Development Category": metadata.get("Development Category", ""),
            "CID handling": metadata.get("CID handling", ""),
        }
        attack_templates = json.loads(
            (self.config.paths.data_dir / "predefined_attack_templates.json").read_text(
                encoding="utf-8"
            )
        )
        controls = load_controls(self.config.paths.data_dir / "control_taxonomy.csv")
        return {
            "cmdb_info": cmdb_info,
            "selected_template": "Default CVE Report Template",
            "selected_techniques": attack_templates.get(state["attack_template"], []),
            "stride_data": json.dumps(
                {category: data.get(category, []) for category in STRIDE_CATEGORIES}, indent=2
            ),
            "dread_data": json.dumps(data.get("dread_assessment", []), indent=2),
            "controls_data": "\n".join(f"{key}: {value}" for key, value in controls.items()),
        }

    def _generate_cve(self, state: ScenarioState) -> ScenarioState:
        vulnerabilities = json.loads(
            (self.config.paths.data_dir / "demo_critical_vulnerability.json").read_text(
                encoding="utf-8"
            )
        )
        template = self.prompts["scenario_menu_gen_system_message_cve_agent"]
        prompt = template.replace("- {cveinfo}", "```json\n{cveinfo}\n```").format(
            cvss_score=state["cvss_score"],
            selected_template=state["selected_template"],
            cmdb_info_Platform=state["cmdb_info"]["Platform"],
            cveinfo=_escape_format(json.dumps(vulnerabilities)),
        )
        prompt += "\n\nGenerate the CVE report following the specified format."
        return {"cve_report": self._ask(prompt)}

    @staticmethod
    def _qa_cve(_: ScenarioState) -> ScenarioState:
        return {"cve_feedback": {"approved": True, "feedback": "Approved"}, "cve_approved": True}

    def _generate_cti(self, state: ScenarioState) -> ScenarioState:
        template = self.prompts["scenario_menu_gen_system_message_cti_agent"]
        prompt = template.format(
            sample_risk_report=_escape_format(self.templates["risk_report"]["content"]),
            sample_cti_external_report=_escape_format(self.templates["cti_report"]["content"]),
            selected_template=state["selected_template"],
            stride=_escape_format(state["stride_data"]),
            dread=_escape_format(state["dread_data"]),
        )
        prompt += f"\n\nGenerate the CTI report using this CVE report:\n{state['cve_report']}"
        return {"cti_report": self._ask(prompt)}

    @staticmethod
    def _qa_cti(_: ScenarioState) -> ScenarioState:
        return {"cti_feedback": {"approved": True, "feedback": "Approved"}, "cti_approved": True}

    def _generate_scenario(self, state: ScenarioState) -> ScenarioState:
        info = state["cmdb_info"]
        template = self.prompts["scenario_menu_gen_system_message_reporting_agent_v2"]
        prompt = template.format(
            selected_techniques2="\n".join(state["selected_techniques"])
            or "No techniques provided",
            selected_template=state["selected_template"],
            sample_threat_scenario=_escape_format(self.templates["threat_scenario"]["content"]),
            sample_scenario_list="",
            cvss_score=state["cvss_score"],
            sample_risk_report=_escape_format(self.templates["risk_report"]["content"]),
            cmdb_info_AAID=info["AA ID"],
            cmdb_info_AAName=info["Application Name"],
            cmdb_info_SWC_Description=info["SWC Description"],
            cmdb_info_sol_description=info["Solution Description"],
            cmdb_info_dev_cat=info["Development Category"],
            cmdb_info_ext_fac=info["Externally facing"],
            cmdb_info_conf=info["Confidentiality"],
            cmdb_info_integrity=info["Integrity"],
            cmdb_info_BCM=info["Technology BCM"],
            cmdb_info_CID=info["CID handling"],
            cmdb_info_Platform=info["Platform"],
            controls_string=_escape_format(state["controls_data"]),
            stride=_escape_format(state["stride_data"]),
            dread=_escape_format(state["dread_data"]),
        )
        prompt += (
            "\n\nGenerate the Cyber Threat Scenario report using these inputs:"
            f"\nCVE Report:\n{state['cve_report']}\nCTI Report:\n{state['cti_report']}"
        )
        return {"scenario_report": self._ask(prompt)}

    @staticmethod
    def _qa_scenario(_: ScenarioState) -> ScenarioState:
        return {
            "scenario_feedback": {"approved": True, "feedback": "Approved"},
            "scenario_approved": True,
        }

    def _save(self, state: ScenarioState) -> ScenarioState:
        now = datetime.now()
        title = re.sub(r"[^A-Za-z0-9._-]+", "_", state["attack_template"]).strip("_")
        output_dir = self.config.paths.output_dir / "scenarios"
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / f"{title}_{state['cmdb_info']['AA ID']}_{now:%Y%m%d}.json"
        info = state["cmdb_info"]
        report = {
            "Attack_Template": state["attack_template"],
            "titleThreatScenario": title,
            "SWC_ID": info["AA ID"],
            "SWC_NAME": info["Application Name"],
            "SWC_Description": info["SWC Description"],
            "SWC_Solution_Description": info["Solution Description"],
            "SWC_Development_Category": info["Development Category"],
            "SWC_Externally_Facing": info["Externally facing"],
            "Confidentiality_Rating": info["Confidentiality"],
            "Integrity_Rating": info["Integrity"],
            "Availability_Rating": info["Technology BCM"],
            "CID_Handling": info["CID handling"],
            "CVSS_Tshld": state["cvss_score"],
            "Threat_Report_Date": now.strftime("%d %B %Y, %H:%M:%S"),
            "CVE_Report_Date": now.strftime("%d %B %Y, %H:%M:%S"),
            "CTI_Report_Date": now.strftime("%d %B %Y, %H:%M:%S"),
            "STRIDE_Threat_Model_Report": state["stride_data"],
            "DREAD_Assessment_Report": state["dread_data"],
            "Threat_Report": state["scenario_report"],
            "CTI_Report": state["cti_report"],
            "CVE_Report": state["cve_report"],
            "Provider": self.config.inference.backend.value,
            "Complete": True,
            "customer_platforms_supporting_the_customer_Application": info["Platform"],
        }
        output.write_text(json.dumps(report, indent=4), encoding="utf-8")
        return {"final_output_path": str(output), "complete": True}

    def _build_graph(self):
        workflow = StateGraph(ScenarioState)
        stages = (
            ("select", self._select),
            ("generate_cve", self._generate_cve),
            ("qa_cve", self._qa_cve),
            ("generate_cti", self._generate_cti),
            ("qa_cti", self._qa_cti),
            ("generate_scenario", self._generate_scenario),
            ("qa_scenario", self._qa_scenario),
            ("save", self._save),
        )
        for name, function in stages:
            workflow.add_node(name, function)
        workflow.set_entry_point(stages[0][0])
        for (name, _), (next_name, _) in zip(stages, stages[1:], strict=False):
            workflow.add_edge(name, next_name)
        workflow.add_edge("save", END)
        return workflow.compile()

    def run(
        self,
        json_file: Path,
        attack_template: str,
        *,
        min_cvss: float = 8.5,
        db_path: str = "cve_database.db",
    ) -> Path:
        if not attack_template.strip():
            raise ValueError("Attack template is required")
        initial: ScenarioState = {
            "json_file": str(json_file),
            "attack_template": attack_template,
            "db_path": db_path,
            "cvss_score": str(min_cvss),
        }
        result = self.graph.invoke(initial)
        return Path(result["final_output_path"])
