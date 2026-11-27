# 0013. Dependency-free PDF export

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

Operators wanted to share threat models and scenarios as PDF reports.

## Decision

`src/export_pdf.py` writes PDF 1.4 by hand in pure Python: built-in Helvetica, simple text layout and pagination. It flattens a threat-model or scenario JSON into sections. Output goes to `output/exports/{stem}_{stamp}.pdf`. It is available as a CLI command and as a GUI endpoint and download.

## Consequences

### Positive
- No native or third-party PDF dependency, so it behaves the same on DGX Spark and macOS.

### Negative
- Only basic typography: no Unicode beyond the Latin-1 base-14 font range, and no tables or images.
- A custom PDF writer is extra code that the project has to maintain.

## Alternatives considered
- ReportLab, WeasyPrint or headless browser printing. Not evidenced (inferred: avoiding native dependencies across both platforms).

## Evidence
- `src/export_pdf.py`; `src/cli.py` `export-pdf` command; `src/gui.py` `/api/export/pdf`
- `tests/test_export_pdf.py`
- Commit `c1e5c49` (PDF reports and STAGE progress lines)
