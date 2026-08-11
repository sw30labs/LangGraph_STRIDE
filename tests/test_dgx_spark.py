import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_helper_scripts_are_valid_bash():
    for name in ("setup_and_run_dgx.sh", "setup_and_run_macos.sh", "gate.sh"):
        subprocess.run(["bash", "-n", str(ROOT / name)], check=True)


def test_dgx_helper_exposes_required_commands():
    text = (ROOT / "setup_and_run_dgx.sh").read_text()
    for command in (
        "doctor",
        "setup",
        "llm-up",
        "llm-wait",
        "llm-down",
        "llm-logs",
        "smoke",
        "run",
    ):
        assert command in text
    assert "load_repo_dotenv" in text
    assert "source .env" not in text
    assert 'TORCH_VERSION="2.11.0+cu130"' in text
    assert 'TORCHVISION_VERSION="0.26.0+cu130"' in text
    assert "VLLM_MAX_MODEL_LEN" in text
    assert "local_container_id" in text
    assert "is_python_312" in text
    assert "nvidia-smi -L" in text
    assert "docker --version" in text
    assert "docker compose version --short" in text


def test_macos_helper_preserves_env_and_defaults_to_web_console():
    text = (ROOT / "setup_and_run_macos.sh").read_text()
    assert "python=3.11" in text
    assert "REPO_ROOT}[dev,graph]" in text
    assert "set -- serve" in text
    assert "cp .env.example .env" not in text
    assert "setup_and_run_dgx.sh" in text


def test_compose_service_is_bounded_and_loopback_only():
    compose = yaml.safe_load((ROOT / "compose.dgx-spark.yaml").read_text())
    service = compose["services"]["llm"]
    command = service["command"]
    assert "@sha256:" in service["image"]
    assert service["restart"] == "no"
    assert service["ports"] == ["127.0.0.1:8000:8000"]
    assert "--max-num-seqs" in command
    assert command[command.index("--max-num-seqs") + 1] == "2"
    assert "--max-model-len" in command
