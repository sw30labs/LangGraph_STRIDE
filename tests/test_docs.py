from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_readme_documents_every_cli_command():
    readme = (ROOT / "README.md").read_text()
    for command in ("info", "models", "smoke-inference", "threat-model", "scenario", "serve"):
        assert f"src.cli {command}" in readme


def test_required_document_set_and_karpathy_clause():
    for name in ("README.md", "AGENTS.md", "CLAUDE.md", "LICENSE", "docs/DGX_SPARK.md"):
        assert (ROOT / name).is_file()
    claude = (ROOT / "CLAUDE.md").read_text()
    assert "## Coding Guidelines" in claude
    assert "## 1. Think Before Coding" in claude
    assert "## 4. Goal-Driven Execution" in claude


def test_machine_readable_scenarios_cover_platforms_and_personas():
    cases = yaml.safe_load((ROOT / "tests" / "test_cases.yaml").read_text())
    assert len(cases["platform_defaults"]) == 3
    commands = [row["command"] for row in cases["automated_scenarios"]]
    assert any("--persona vllm" in command for command in commands)
    assert any("--persona omlx" in command for command in commands)


def test_runtime_assets_are_declared_as_package_data():
    metadata = (ROOT / "pyproject.toml").read_text()
    assert '"data/*"' in metadata
    assert '"prompts/*"' in metadata
    assert (ROOT / "src" / "data" / "cmdb.json").is_file()
    assert (ROOT / "src" / "prompts" / "stride_prompts.yml").is_file()
