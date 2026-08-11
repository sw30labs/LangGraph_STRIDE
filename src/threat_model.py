"""STRIDE and DREAD threat-model workflow."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, TypedDict

import yaml
from langgraph.graph import END, StateGraph

from src.config import AppConfig
from src.inference_client import OpenAICompatibleClient, client_from_config
from src.workspace import get_cmdb_entry_legacy, now_iso


def _stage(name: str) -> None:
    # I print STAGE lines so the GUI live log can show progress without waiting
    # for the whole job to finish.
    print(f"STAGE: {name}", flush=True)

STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)


class ThreatModelState(TypedDict, total=False):
    aa_id: str
    system_desc: str
    cmdb_info: dict[str, Any]
    stride_data: dict[str, Any]
    dread_data: dict[str, Any]
    stride_feedback: dict[str, Any]
    dread_feedback: dict[str, Any]
    final_feedback: dict[str, Any]
    stride_iterations: int
    dread_iterations: int
    final_model: dict[str, Any]
    saved_path: str


def parse_json_object(value: str) -> dict[str, Any]:
    """Parse direct, fenced, or prose-wrapped JSON object output."""
    text = value.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for index, character in enumerate(text):
        if character != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("Inference response did not contain a JSON object")


def parse_stride_response(value: str) -> dict[str, list[dict[str, str]]]:
    """Validate and canonicalize the six STRIDE category lists."""
    payload = parse_json_object(value)
    by_name = {category.casefold(): category for category in STRIDE_CATEGORIES}
    result: dict[str, list[dict[str, str]]] = {category: [] for category in STRIDE_CATEGORIES}
    required = ("threat_name", "description", "impact", "mitigation")
    for raw_name, rows in payload.items():
        category = by_name.get(str(raw_name).casefold())
        if category is None or not isinstance(rows, list):
            continue
        valid = [
            {key: str(row[key]).strip() for key in required}
            for row in rows
            if isinstance(row, dict) and all(key in row for key in required)
        ]
        if len(valid) >= 3:
            result[category] = valid[:5]
    return result


def load_cmdb_entry(data_dir: Path, aa_id: str) -> dict[str, Any]:
    """Load one application record by its current-source `AA ID`."""
    payload = json.loads((data_dir / "cmdb.json").read_text(encoding="utf-8"))
    for row in payload:
        if isinstance(row, dict) and str(row.get("AA ID")) == aa_id:
            return row
    raise ValueError(f"No CMDB entry for AA ID: {aa_id}")


def load_prompts(prompts_dir: Path) -> dict[str, Any]:
    payload = yaml.safe_load((prompts_dir / "stride_prompts.yml").read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("STRIDE prompt file must contain a mapping")
    return payload


class ThreatModelWorkflow:
    """One host-neutral LangGraph flow for STRIDE, DREAD, QA, and persistence."""

    def __init__(
        self,
        config: AppConfig,
        client: OpenAICompatibleClient | None = None,
    ) -> None:
        self.config = config
        self.client = client or client_from_config(config.inference)
        self.prompts = load_prompts(config.paths.prompts_dir)
        self.graph = self._build_graph()

    def _ask(self, prompt: str) -> str:
        return self.client.chat(
            [{"role": "user", "content": prompt}],
            max_tokens=self.config.inference.max_tokens,
            disable_thinking=self.config.inference.disable_thinking,
            reasoning_strength=self.config.inference.reasoning_strength,
            require_complete=True,
        )

    def _generate_stride(self, state: ThreatModelState) -> ThreatModelState:
        _stage("generate_stride")
        template = self.prompts["stride"]["human_template"]
        context = "\n".join(f"{key}: {value}" for key, value in state["cmdb_info"].items() if value)
        prompt = f"{template}\n\n{state['system_desc']}\n\nSystem Context:\n{context}"
        if state.get("stride_feedback"):
            prompt += f"\n\nQA Feedback:\n{json.dumps(state['stride_feedback'], indent=2)}"
        return {"stride_data": parse_stride_response(self._ask(prompt))}

    def _qa_stride(self, state: ThreatModelState) -> ThreatModelState:
        _stage("qa_stride")
        template = self.prompts["qa_stride"]["human_template"]
        prompt = template.replace("{{stride_output}}", json.dumps(state["stride_data"], indent=2))
        try:
            feedback = parse_json_object(self._ask(prompt))
        except Exception as exc:
            feedback = {"pass": False, "error": str(exc)}
        return {
            "stride_feedback": feedback,
            "stride_iterations": state.get("stride_iterations", 0) + 1,
        }

    def _after_stride_qa(self, state: ThreatModelState) -> str:
        passed = bool(state["stride_feedback"].get("pass"))
        return (
            "generate_dread"
            if passed or state["stride_iterations"] >= self.config.workflow.qa_attempts
            else "generate_stride"
        )

    def _generate_dread(self, state: ThreatModelState) -> ThreatModelState:
        _stage("generate_dread")
        threats = [
            (row["threat_name"], category)
            for category, rows in state["stride_data"].items()
            if isinstance(rows, list)
            for row in rows
        ]
        template = self.prompts["dread"]["format_template"]
        prompt = template.replace("${threats}", json.dumps(threats, indent=2))
        if state.get("dread_feedback"):
            prompt += f"\n\nQA Feedback:\n{json.dumps(state['dread_feedback'], indent=2)}"
        parsed = parse_json_object(self._ask(prompt))
        return {"dread_data": parsed if parsed.get("Risk Assessment") else {"Risk Assessment": []}}

    def _qa_dread(self, state: ThreatModelState) -> ThreatModelState:
        _stage("qa_dread")
        template = self.prompts["qa_dread"]["human_template"]
        prompt = template.replace("{{dread_output}}", json.dumps(state["dread_data"], indent=2))
        try:
            feedback = parse_json_object(self._ask(prompt))
        except Exception as exc:
            feedback = {"pass": False, "error": str(exc)}
        return {
            "dread_feedback": feedback,
            "dread_iterations": state.get("dread_iterations", 0) + 1,
        }

    def _after_dread_qa(self, state: ThreatModelState) -> str:
        passed = bool(state["dread_feedback"].get("pass"))
        return (
            "final_qa"
            if passed or state["dread_iterations"] >= self.config.workflow.qa_attempts
            else "generate_dread"
        )

    def _final_qa(self, state: ThreatModelState) -> ThreatModelState:
        _stage("final_qa")
        model = {
            "system_metadata": {"aa_id": state["aa_id"], **state["cmdb_info"]},
            **state["stride_data"],
            "dread_assessment": state["dread_data"].get("Risk Assessment", []),
        }
        template = self.prompts["qa_final"]["human_template"]
        prompt = template.replace("{{threat_model}}", json.dumps(model, indent=2))
        try:
            final_model = parse_json_object(self._ask(prompt))
        except Exception:
            final_model = model
        return {
            "final_model": final_model,
            "final_feedback": {"pass": True, "message": "Final QA applied"},
        }

    def _save(self, state: ThreatModelState) -> ThreatModelState:
        _stage("save")
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        aa_id = state["aa_id"]
        artifact_id = f"tm_{aa_id}_{timestamp}"
        stride_dir = self.config.paths.output_dir / "stride"
        feedback_dir = self.config.paths.output_dir / "feedback"
        stride_dir.mkdir(parents=True, exist_ok=True)
        feedback_dir.mkdir(parents=True, exist_ok=True)
        for name in ("stride", "dread", "final"):
            feedback = state.get(f"{name}_feedback")
            if feedback:
                path = feedback_dir / f"{name}_feedback_{aa_id}_{timestamp}.json"
                path.write_text(json.dumps(feedback, indent=2), encoding="utf-8")
        final_model = dict(state["final_model"] or {})
        final_model["_meta"] = {
            "artifact_type": "threat_model",
            "artifact_id": artifact_id,
            "aa_id": aa_id,
            "created_at": now_iso(),
            "provider": self.config.inference.backend.value,
            "model": self.config.inference.model,
            "thinking_enabled": not self.config.inference.disable_thinking,
            "reasoning_strength": self.config.inference.reasoning_strength
            if not self.config.inference.disable_thinking
            else None,
        }
        output = stride_dir / f"security_assessment_{aa_id}_{timestamp}.json"
        output.write_text(json.dumps(final_model, indent=2), encoding="utf-8")
        return {"saved_path": str(output), "final_model": final_model}

    def _build_graph(self):
        workflow = StateGraph(ThreatModelState)
        workflow.add_node("generate_stride", self._generate_stride)
        workflow.add_node("qa_stride", self._qa_stride)
        workflow.add_node("generate_dread", self._generate_dread)
        workflow.add_node("qa_dread", self._qa_dread)
        workflow.add_node("final_qa", self._final_qa)
        workflow.add_node("save", self._save)
        workflow.set_entry_point("generate_stride")
        workflow.add_edge("generate_stride", "qa_stride")
        workflow.add_conditional_edges("qa_stride", self._after_stride_qa)
        workflow.add_edge("generate_dread", "qa_dread")
        workflow.add_conditional_edges("qa_dread", self._after_dread_qa)
        workflow.add_edge("final_qa", "save")
        workflow.add_edge("save", END)
        return workflow.compile()

    def run(self, aa_id: str) -> Path:
        try:
            cmdb_info = get_cmdb_entry_legacy(self.config.paths, aa_id)
        except ValueError:
            # Fall back to packaged data_dir only (pre-workspace callers/tests).
            cmdb_info = load_cmdb_entry(self.config.paths.data_dir, aa_id)
        initial: ThreatModelState = {
            "aa_id": aa_id,
            "system_desc": str(cmdb_info.get("Solution Description") or ""),
            "cmdb_info": cmdb_info,
            "stride_iterations": 0,
            "dread_iterations": 0,
        }
        result = self.graph.invoke(initial)
        return Path(result["saved_path"])
