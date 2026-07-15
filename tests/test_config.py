from src import config as config_module
from src.config import AppConfig, InferenceBackend


def _clear_overrides(monkeypatch):
    for name in (
        "STRIDE_BACKEND",
        "LLM_PROVIDER",
        "STRIDE_DEVICE",
        "STRIDE_CONCURRENCY",
        "STRIDE_BATCH_SIZE",
    ):
        monkeypatch.delenv(name, raising=False)


def test_dgx_spark_defaults(monkeypatch):
    _clear_overrides(monkeypatch)
    monkeypatch.setattr(config_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(config_module.platform, "machine", lambda: "aarch64")
    config = AppConfig()
    assert config.inference.backend is InferenceBackend.vllm
    assert config.inference.device == "cuda"
    assert config.inference.concurrency == 2


def test_apple_silicon_defaults(monkeypatch):
    _clear_overrides(monkeypatch)
    monkeypatch.setattr(config_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(config_module.platform, "machine", lambda: "arm64")
    config = AppConfig()
    assert config.inference.backend is InferenceBackend.omlx
    assert config.inference.device == "mps"
    assert config.inference.concurrency == 4


def test_other_host_defaults(monkeypatch):
    _clear_overrides(monkeypatch)
    monkeypatch.setattr(config_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(config_module.platform, "machine", lambda: "x86_64")
    config = AppConfig()
    assert config.inference.backend is InferenceBackend.omlx
    assert config.inference.device == "cpu"
    assert config.inference.concurrency == 4


def test_environment_overrides_platform(monkeypatch):
    monkeypatch.setenv("STRIDE_BACKEND", "mlx")
    monkeypatch.setenv("STRIDE_DEVICE", "cpu")
    monkeypatch.setenv("STRIDE_CONCURRENCY", "7")
    config = AppConfig()
    assert config.inference.backend is InferenceBackend.omlx
    assert config.inference.device == "cpu"
    assert config.inference.concurrency == 7


def test_optional_metrics_port(monkeypatch):
    monkeypatch.setenv("STRIDE_METRICS_PORT", "9108")
    assert AppConfig().workflow.metrics_port == 9108
