#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly COMPOSE_FILE="${REPO_ROOT}/compose.dgx-spark.yaml"

load_repo_dotenv() {
    local line key value first last
    local env_file="${REPO_ROOT}/.env"
    [[ -f "${env_file}" ]] || return 0
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line="${line%$'\r'}"
        [[ "${line}" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]] || continue
        key="${BASH_REMATCH[2]}"
        case "${key}" in
            HF_TOKEN|HF_HUB_DISABLE_XET|DGX_VENV_DIR|DGX_PYTHON_BIN|DGX_HF_CACHE|DGX_VLLM_CACHE|PYTORCH_DGX_INDEX_URL|VLLM_IMAGE|VLLM_MODEL|VLLM_MODEL_REVISION|VLLM_BASE_URL|VLLM_API_KEY|VLLM_GPU_MEMORY_UTILIZATION|VLLM_MAX_MODEL_LEN|VLLM_START_TIMEOUT|VLLM_LOG_TAIL) ;;
            *) continue ;;
        esac
        [[ -z "$(printenv "${key}" 2>/dev/null)" ]] || continue
        value="${BASH_REMATCH[3]}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        if [[ -n "${value}" ]]; then
            first="${value:0:1}"
            last="${value: -1}"
            if [[ "${first}" == '"' || "${first}" == "'" ]]; then
                [[ "${#value}" -ge 2 && "${last}" == "${first}" ]] || {
                    printf 'Invalid quote for %s in .env\n' "${key}" >&2
                    exit 1
                }
                value="${value:1:${#value}-2}"
            elif [[ "${value}" =~ [[:space:]]# ]]; then
                printf 'Use a separate comment line for %s in .env\n' "${key}" >&2
                exit 1
            fi
        fi
        printf -v "${key}" '%s' "${value}"
        export "${key}"
    done < "${env_file}"
}

load_repo_dotenv

readonly VENV_DIR="${DGX_VENV_DIR:-${REPO_ROOT}/.venv-dgx}"
readonly PYTHON_BIN="${DGX_PYTHON_BIN:-python3.12}"
readonly VLLM_MODEL="${VLLM_MODEL:-nvidia/Qwen3.6-27B-NVFP4}"
readonly VLLM_BASE_URL="${VLLM_BASE_URL:-http://127.0.0.1:8000/v1}"
readonly VLLM_API_KEY="${VLLM_API_KEY:-local}"
readonly VLLM_START_TIMEOUT="${VLLM_START_TIMEOUT:-1800}"
readonly VLLM_MAX_MODEL_LEN="${VLLM_MAX_MODEL_LEN:-262144}"
readonly DGX_HF_CACHE="${DGX_HF_CACHE:-${REPO_ROOT}/.local-models/huggingface}"
readonly DGX_VLLM_CACHE="${DGX_VLLM_CACHE:-${REPO_ROOT}/.local-models/vllm}"
readonly TORCH_VERSION="2.11.0+cu130"
readonly TORCHVISION_VERSION="0.26.0+cu130"
readonly TORCH_INDEX_URL="${PYTORCH_DGX_INDEX_URL:-https://download.pytorch.org/whl/cu130}"

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

compose_with_token() {
    [[ -n "${HF_TOKEN:-}" && "${HF_TOKEN}" != 'hf_replace_me' ]] || die 'Set HF_TOKEN.'
    COMPOSE_DISABLE_ENV_FILE=1 docker compose --project-directory "${REPO_ROOT}" \
        -f "${COMPOSE_FILE}" "$@"
}

endpoint_has_model() {
    python3 - "${VLLM_BASE_URL%/}/models" "${VLLM_MODEL}" "${VLLM_API_KEY}" \
        "${VLLM_MAX_MODEL_LEN}" <<'PY' \
        >/dev/null 2>&1
import json
import sys
import urllib.request

url, expected, api_key, required_context = sys.argv[1:]
request = urllib.request.Request(url, headers={"Authorization": f"Bearer {api_key}"})
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(request, timeout=3) as response:
    payload = json.load(response)
for row in payload.get("data", []):
    if row.get("id") != expected:
        continue
    try:
        advertised = int(row.get("max_model_len"))
    except (TypeError, ValueError):
        raise SystemExit(1)
    raise SystemExit(0 if advertised >= int(required_context) else 1)
raise SystemExit(1)
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

managed_endpoint() { [[ "${VLLM_BASE_URL%/}" == 'http://127.0.0.1:8000/v1' ]]; }
local_container_id() { compose_control ps --all -q llm 2>/dev/null; }
local_container_running() { [[ -n "$(compose_control ps --status running -q llm 2>/dev/null || true)" ]]; }

cmd_doctor() {
    [[ "$(uname -s)" == "Linux" ]] || die 'DGX Spark requires Linux.'
    case "$(uname -m)" in aarch64|arm64) ;; *) die 'DGX Spark requires ARM64.' ;; esac
    command -v docker >/dev/null || die 'Docker is required.'
    docker compose version >/dev/null || die 'Docker Compose is required.'
    command -v nvidia-smi >/dev/null || die 'NVIDIA runtime is not visible.'
    docker info >/dev/null || die 'Docker is not accessible.'
    if endpoint_has_model; then
        log "Exact model/context service is reusable at ${VLLM_BASE_URL}."
    elif endpoint_answers; then
        die 'The endpoint answers with a different model or smaller context.'
    elif [[ -z "${HF_TOKEN:-}" || "${HF_TOKEN}" == 'hf_replace_me' ]]; then
        die 'Set HF_TOKEN when no reusable service is ready.'
    fi
    log 'DGX Spark prerequisites are visible.'
}

cmd_setup() {
    command -v "${PYTHON_BIN}" >/dev/null || die 'Python 3.12 is required.'
    "${PYTHON_BIN}" -c 'import sys; raise SystemExit(sys.version_info[:2] != (3, 12))' || \
        die 'DGX setup requires Python 3.12 exactly.'
    [[ -x "${VENV_DIR}/bin/python" ]] || "${PYTHON_BIN}" -m venv "${VENV_DIR}"
    "${VENV_DIR}/bin/python" -m pip install --upgrade pip
    "${VENV_DIR}/bin/python" -m pip install --index-url "${TORCH_INDEX_URL}" \
        "torch==${TORCH_VERSION}" "torchvision==${TORCHVISION_VERSION}"
    "${VENV_DIR}/bin/python" -m pip install --editable "${REPO_ROOT}[dev]"
    "${VENV_DIR}/bin/python" -c \
        'import torch; assert torch.version.cuda == "13.0" and torch.cuda.is_available()'
    log "Installed ${VENV_DIR}."
}

cmd_llm_up() {
    if endpoint_has_model; then
        log "Reusing exact-model/context service at ${VLLM_BASE_URL}."
        return
    fi
    endpoint_answers && die 'The endpoint serves a different model or context; refusing to replace it.'
    managed_endpoint || die 'The configured external endpoint must be started by its owner.'
    mkdir -p "${DGX_HF_CACHE}" "${DGX_VLLM_CACHE}"
    compose_with_token up --detach --remove-orphans llm
    cmd_llm_wait
}

cmd_llm_wait() {
    local deadline=$((SECONDS + VLLM_START_TIMEOUT))
    until endpoint_has_model; do
        if endpoint_answers; then
            die 'A model service answered, but its model/context does not match.'
        fi
        if [[ -n "$(local_container_id || true)" ]] && ! local_container_running; then
            die "This repository's vLLM container exited while loading; run llm-logs."
        fi
        (( SECONDS < deadline )) || die 'Timed out waiting for the exact vLLM model.'
        sleep 5
    done
    log "${VLLM_MODEL} is ready."
}

cmd_llm_down() {
    [[ -n "$(local_container_id || true)" ]] || {
        log 'No repository-owned container exists; shared services are untouched.'
        return
    }
    compose_control down --remove-orphans
}

cmd_llm_logs() {
    [[ -n "$(local_container_id || true)" ]] || die 'No repository-owned container exists.'
    compose_control logs --follow --tail "${VLLM_LOG_TAIL:-200}" llm
}

cmd_smoke() {
    [[ -x "${VENV_DIR}/bin/python" ]] || die 'Run setup first.'
    cmd_llm_wait
    "${VENV_DIR}/bin/python" -m src.cli smoke-inference --backend vllm \
        --inference-url "${VLLM_BASE_URL}" --inference-model "${VLLM_MODEL}" \
        --inference-api-key "${VLLM_API_KEY}"
}

cmd_run() {
    [[ -x "${VENV_DIR}/bin/python" ]] || die 'Run setup first.'
    cmd_llm_up
    export STRIDE_BACKEND=vllm STRIDE_DEVICE=cuda STRIDE_CONCURRENCY=2
    [[ $# -gt 0 ]] || set -- serve
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
