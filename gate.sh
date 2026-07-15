#!/usr/bin/env bash
set -euo pipefail

python -m ruff format --check src/ tests/
python -m ruff check src/ tests/
python -m pytest tests/ -q
python -c "import src.cli"
python tests/run_contract_e2e.py --persona vllm
python tests/run_contract_e2e.py --persona omlx

