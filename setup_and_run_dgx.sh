#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly COMPOSE_FILE="${REPO_ROOT}/compose.dgx-spark.yaml"
readonly VENV_DIR="${DGX_VENV_DIR:-${REPO_ROOT}/.venv-dgx}"
readonly PYTHON_BIN="${DGX_PYTHON_BIN:-python3.12}"
readonly VLLM_MODEL="${VLLM_MODEL:-nvidia/Qwen3.6-27B-NVFP4}"
readonly VLLM_BASE_URL="${VLLM_BASE_URL:-http://127.0.0.1:8000/v1}"
readonly VLLM_API_KEY="${VLLM_API_KEY:-local}"
readonly VLLM_START_TIMEOUT="${VLLM_START_TIMEOUT:-1800}"

log() { printf '[langgraph-stride] %s\n' "$*"; }
die() { printf '[langgraph-stride] error: %s\n' "$*" >&2; exit 1; }

usage() {
    printf '%s\n' \
        'Usage: ./setup_and_run_dgx.sh COMMAND [ARGS...]' \
        'Commands: doctor setup llm-up llm-wait llm-down llm-logs smoke run help'
}

compose_control() {
    COMPOSE_DISABLE_ENV_FILE=1 HF_TOKEN="${HF_TOKEN:-compose-control-only}" \
        docker compose --project-directory "${REPO_ROOT}" -f "${COMPOSE_FILE}" "$@"
}

endpoint_has_model() {
    python3 - "${VLLM_BASE_URL%/}/models" "${VLLM_MODEL}" "${VLLM_API_KEY}" <<'PY' \
        >/dev/null 2>&1
import json
import sys
import urllib.request

url, expected, api_key = sys.argv[1:]
request = urllib.request.Request(url, headers={"Authorization": f"Bearer {api_key}"})
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(request, timeout=3) as response:
    payload = json.load(response)
raise SystemExit(0 if expected in {row.get("id") for row in payload.get("data", [])} else 1)
PY
}

endpoint_answers() {
    python3 - "${VLLM_BASE_URL%/}/models" <<'PY' >/dev/null 2>&1
import sys
import urllib.request

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(sys.argv[1], timeout=3):
    pass
PY
}

cmd_doctor() {
    [[ "$(uname -s)" == "Linux" ]] || die 'DGX Spark requires Linux.'
    case "$(uname -m)" in aarch64|arm64) ;; *) die 'DGX Spark requires ARM64.' ;; esac
    command -v docker >/dev/null || die 'Docker is required.'
    docker compose version >/dev/null || die 'Docker Compose is required.'
    command -v nvidia-smi >/dev/null || die 'NVIDIA runtime is not visible.'
    log 'DGX Spark prerequisites are visible.'
}

cmd_setup() {
    command -v "${PYTHON_BIN}" >/dev/null || die 'Python 3.12 is required.'
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
    "${VENV_DIR}/bin/python" -m pip install --upgrade pip
    "${VENV_DIR}/bin/python" -m pip install --editable "${REPO_ROOT}[dev]"
    log "Installed ${VENV_DIR}."
}

cmd_llm_up() {
    if endpoint_has_model; then
        log "Reusing exact-model service at ${VLLM_BASE_URL}."
        return
    fi
    endpoint_answers && die 'The configured port answers with a different model; refusing to replace it.'
    [[ -n "${HF_TOKEN:-}" && "${HF_TOKEN}" != 'hf_replace_me' ]] || die 'Set HF_TOKEN.'
    mkdir -p "${DGX_HF_CACHE:-${REPO_ROOT}/.local-models/huggingface}"
    mkdir -p "${DGX_VLLM_CACHE:-${REPO_ROOT}/.local-models/vllm}"
    COMPOSE_DISABLE_ENV_FILE=1 docker compose --project-directory "${REPO_ROOT}" \
        -f "${COMPOSE_FILE}" up --detach llm
    cmd_llm_wait
}

cmd_llm_wait() {
    local deadline=$((SECONDS + VLLM_START_TIMEOUT))
    until endpoint_has_model; do
        (( SECONDS < deadline )) || die 'Timed out waiting for the exact vLLM model.'
        sleep 5
    done
    log "${VLLM_MODEL} is ready."
}

cmd_llm_down() { compose_control down; }
cmd_llm_logs() { compose_control logs --follow --tail "${VLLM_LOG_TAIL:-200}" llm; }

cmd_smoke() {
    "${VENV_DIR}/bin/python" -m src.cli smoke-inference --backend vllm \
        --inference-url "${VLLM_BASE_URL}" --inference-model "${VLLM_MODEL}" \
        --inference-api-key "${VLLM_API_KEY}"
}

cmd_run() {
    cmd_llm_up
    export STRIDE_BACKEND=vllm STRIDE_DEVICE=cuda STRIDE_CONCURRENCY=2
    exec "${VENV_DIR}/bin/python" -m src.cli "$@"
}

command="${1:-help}"
shift || true
case "${command}" in
    doctor) cmd_doctor "$@" ;;
    setup) cmd_setup "$@" ;;
    llm-up) cmd_llm_up "$@" ;;
    llm-wait) cmd_llm_wait "$@" ;;
    llm-down) cmd_llm_down "$@" ;;
    llm-logs) cmd_llm_logs "$@" ;;
    smoke) cmd_smoke "$@" ;;
    run) cmd_run "$@" ;;
    help|-h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac

