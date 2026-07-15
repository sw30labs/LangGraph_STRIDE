#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ENV_NAME="${STRIDE_CONDA_ENV:-langgraph-stride}"

if [[ "$(uname -s)" == "Linux" ]] && [[ "$(uname -m)" =~ ^(aarch64|arm64)$ ]]; then
    printf '%s\n' 'DGX Spark detected; use ./setup_and_run_dgx.sh setup and run.' >&2
    exit 2
fi

find_conda() {
    local candidate
    [[ -n "${CONDA_EXE:-}" && -x "${CONDA_EXE}" ]] && { printf '%s\n' "${CONDA_EXE}"; return; }
    command -v conda >/dev/null && { command -v conda; return; }
    for candidate in "${HOME}/miniforge3/bin/conda" "${HOME}/miniconda3/bin/conda" \
        "${HOME}/anaconda3/bin/conda"; do
        [[ -x "${candidate}" ]] && { printf '%s\n' "${candidate}"; return; }
    done
    return 1
}

CONDA_BIN="$(find_conda)" || { printf '%s\n' 'Conda was not found.' >&2; exit 1; }
cd "${REPO_ROOT}"
if ! "${CONDA_BIN}" env list | awk -v name="${ENV_NAME}" '$1 == name { found=1 } END { exit !found }'; then
    "${CONDA_BIN}" create --yes --name "${ENV_NAME}" --channel conda-forge python=3.11 pip
fi
"${CONDA_BIN}" run --name "${ENV_NAME}" python -m pip install --editable "${REPO_ROOT}[dev]"
[[ $# -gt 0 ]] || set -- info
export STRIDE_BACKEND="${STRIDE_BACKEND:-omlx}" STRIDE_DEVICE="${STRIDE_DEVICE:-mps}"
exec "${CONDA_BIN}" run --no-capture-output --name "${ENV_NAME}" python -m src.cli "$@"

