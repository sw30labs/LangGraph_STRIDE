# 0012. Local standard-library GUI that runs CLI subprocess jobs

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

The source had a local GUI. The port needed a console for running workflows, browsing outputs, editing the CMDB and chains, managing intel and driving the Maintain studio, without adding a web framework.

## Decision

- `src/gui.py` uses `http.server.ThreadingHTTPServer`, defaults to `127.0.0.1:8765`, and serves packaged static assets from `src/web/` (exactly `index.html`, `app.js`, `styles.css`; plain JS, no build step).
- Long-running work (threat model, scenario, maintain, intel update, graph sync) runs as background `python -m src.cli …` subprocess jobs. Logs are captured and `STAGE:` lines are parsed for progress. The GUI and the CLI share one code path.
- Paths from the browser go through `ensure_repo_file`, which keeps them inside the project root. Request bodies are capped at 1 MB.
- The front end polls adaptively (about 2.5 s while jobs run, slower when idle, paused when the tab is hidden). It escapes HTML and does not refresh while the user is editing.

## Consequences

### Positive
- No extra server dependencies. Jobs fail in isolation, and the CLI stays canonical (`tests/test_gui.py` checks the commands it builds).
- The GUI never manages inference servers (ADR 0005).

### Negative
- There is no authentication and no CSRF protection. The JSON body parser does not check `Content-Type`. Safety depends on loopback binding, and `serve --host` can widen it.
- Path confinement has gaps:
  - `POST /api/maintain/commit` falls back to the raw supplied path when `ensure_repo_file` rejects it.
  - CTI pack ids are put into file paths without sanitising.
- Job state lives in memory and is lost on restart.

## Alternatives considered
- FastAPI, Flask or Streamlit. Not evidenced (inferred: stdlib keeps dependencies minimal).
- Run workflows in-process threads. Not chosen; jobs shell out to the CLI.

## Evidence
- `src/gui.py` (`GuiHandler`, `start_job`, `build_*_job`, `ensure_repo_file`, `MAX_BODY`); `src/web/app.js`, `src/web/index.html`, `src/web/styles.css`
- `tests/test_gui.py`; `README.md` "Local GUI"; `CLAUDE.md`
- Commits `da2424f` (port local workflow console), `0146606` (applications, navigator, intel, PDF), `2f62188` (Maintain pages), `2a8b39d`
