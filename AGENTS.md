# Contributor and agent guide

## Structure and ownership

- `src/config.py` is the only platform-detection and default-resolution module.
- `src/inference_client.py` is the only provider seam. Both workflows use it unchanged.
- `src/threat_model.py` owns STRIDE/DREAD/QA/output behavior.
- `src/scenario.py` owns CVE/CTI/scenario/report behavior.
- `src/gui.py` owns the local HTTP API and background jobs; `src/web/` is static UI only.
- `src/data/` and `src/prompts/` are packaged, public, source-derived fixtures. Generated reports belong under gitignored `output/`.

Platform detection changes defaults, not code paths. Never add Darwin/Linux branches to workflow, GUI, or inference business logic.

## Build and test

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
./gate.sh
```

Use `python -m src.cli --help`, `info --json`, and the two `tests/run_contract_e2e.py` personas for focused diagnosis. Tests must mock inference, use temporary directories for writes, and run without CUDA, MPS, Docker, or network access. Real model/hardware checks belong in platform-helper `smoke` commands.

## Style and changes

Use four spaces, lowercase-underscore modules, `CamelCase` classes, useful type hints, concise public docstrings, `Path` for filesystem operations, and Pydantic for configuration. Parse LLM JSON tolerantly (direct, fenced, then the first valid object) and require complete output where truncation would corrupt a report.

Keep changes surgical. Update README and DGX documentation in the same commit when command, config, service, or output behavior changes. Use scoped Conventional Commits such as `feat(workflow): ...`, `fix(config): ...`, `test(gui): ...`, or `docs(readme): ...`.

Never read, copy, overwrite, or commit `.env`; never commit caches or generated reports; never stop an OpenAI-compatible service owned by another stack. The DGX helper may reuse an exact external model/context service but may manage only its own Compose container.
