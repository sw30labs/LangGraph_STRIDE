# Contributor and agent guide

`src/config.py` owns platform detection and all defaults. `src/inference_client.py` is the only provider seam. Workflow modules must receive configuration and use the shared client; they must not branch on the host platform. Static web assets belong under `src/web/`, prompt assets under `prompts/`, and public sample inputs under `data/`.

Run `pip install -e ".[dev]"` and `./gate.sh` before committing. Use type hints where they clarify boundaries, `Path` for filesystem work, tolerant LLM JSON parsing, and small lowercase-underscore modules. Tests must mock inference and write only to temporary directories. Real GPU, MPS, and model checks belong in the launcher `smoke` commands.

Use Conventional Commits with a scope, such as `feat(workflow): port STRIDE graph` or `test(gui): cover safe file preview`. Never edit `.env`, model caches, user reports, or an OpenAI-compatible service owned by another stack. The DGX helper may reuse a matching external service but may stop only its own Compose service.

