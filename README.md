# ad-audit-report

CLI tool that converts PingCastle and PlumHound output into a populated Excel report,
using a corporate xlsx template as the canvas.

## What it does

Given:
- `*.xml` from PingCastle (`HealthcheckData`)
- a directory or `*.zip` from PlumHound (HTML/CSV tables)
- an Excel template with a "Результаты" sheet shaped like:
  `№ | Дата | Объект тестирования | Сегмент сети | Тип | Описание | Подробности | Предлагаемые мероприятия | Примечания`

…the tool appends rows to "Результаты", and offloads long lists of affected
objects (admins, computers, kerberoastable users, etc.) into auto-created
appendix sheets (`Прил.N`), linked from column "Подробности".

The corporate template's existing data validations (drop-downs on Сегмент сети /
Тип), styles, named ranges and example rows are preserved — the tool edits the
xlsx via direct ZIP+XML manipulation, never round-trips through openpyxl.

## Install

```bash
git clone <this-repo>
cd ad-audit-report
python3 -m venv .venv
.venv/bin/pip install -e .
# .venv/bin/adreport is now on PATH inside the venv
```

If you prefer pipx (no venv activation):

```bash
pipx install -e .
adreport --help
```

## Quick start (per engagement)

```bash
# 0. One-time: strip confidential metadata from your corporate template
#    (auditor name, absPath, client name in A3) — produces a reusable clean template.
adreport sanitize-template /path/to/original-template.xlsx ./clean-template.xlsx \
    --title "Список выявленных недостатков ИБ"

# 1. Create a per-engagement directory and config
mkdir 2026-acme && cd 2026-acme
adreport init-config ./project.yaml

# 2. Edit project.yaml — set client name, audit date, paths to inputs:
#    inputs:
#      pingcastle: ./pingcastle/healthcheck.xml   # XML + .html sibling auto-detected
#      plumhound: ./plumhound/Reports.zip
#    template: ../clean-template.xlsx
#    output: ./acme-report.xlsx

# 3. (Optional) Dry-run — show what would be in the report, without writing xlsx
adreport validate ./project.yaml

# 4. (Optional) List rule coverage — what's in the catalog, what was matched in this scan
adreport list-rules ./project.yaml

# 5. Build the report
adreport build ./project.yaml
```

See `examples/project.yaml.example` for a complete example.

## Commands

| Command | Purpose |
|---|---|
| `adreport sanitize-template IN OUT --title T` | Strip auditor name / absPath / client name from a template. One-time per template. |
| `adreport init-config PATH` | Write a starter `project.yaml`. |
| `adreport validate project.yaml` | Parse inputs, show coverage stats. No xlsx write. |
| `adreport list-rules [project.yaml]` | List every RiskId known to the catalog; mark those present in the scan. |
| `adreport build project.yaml` | Build the populated report. |

## What sanitize-template removes

The corporate template typically contains metadata from the original author
that leaks into every report built from it:

- **`docProps/core.xml`** — `creator` (auditor's full name), `lastModifiedBy`
- **`xl/workbook.xml`** — `absPath` (filesystem path on the author's machine,
  e.g. `C:\Users\admin\Documents\…\CONFIDENTIAL_PROJECT\` — reveals project codename)
- **`xl/sharedStrings.xml`** — title in cell A3 that often embeds the
  auditor's company name — replaced with the value passed to `--title`.

Run sanitize once per template, then version-control / share the clean copy
freely. The output is a fully functional xlsx — all sheet structure, styles,
data validations, named ranges, tables, drawings, and printerSettings are
preserved.

### Real example output

On the bundled corporate template, the tool typically appends 20–40 finding
rows and 5–10 appendix sheets in under a second:

```
$ adreport build ./project.yaml
✓ Wrote ./demo-report.xlsx
  Findings: 30
  Appendices: 7
```

Each appendix is a new sheet named `Прил.N` listing affected objects
(admin users, kerberoastable accounts, MSSQL servers, etc.), and the
corresponding row in "Результаты" gets a clickable hyperlink in column G.

## How recommendations work

`src/adreport/catalog/recommendations.yaml` maps each PingCastle `RiskId` to
a Russian-language recommendation, severity type, target segment, and the list
of PlumHound HTML/CSV files that should populate the appendix (if any).

When the tool encounters a `RiskId` not in the catalog, it writes the row with
a generic recommendation and prints a warning — you grow the catalog
project-by-project.

PlumHound has findings that PingCastle does not surface as rules
(KRBTGT_Stale_Password, ADCS_ESC*, etc). These live under `synthetic_findings:`
in the same catalog and trigger when their source files contain non-empty data.

## Architecture

- `parsers/pingcastle.py` — XML → `RawRule[]` + top-level metrics
- `parsers/plumhound.py` — dir/zip → `dict[name, list[dict]]` (HTML primary, CSV fallback)
- `pipeline.py` — raw + catalog → `Finding[]`
- `renderer/xlsx_writer.py` — `Finding[]` → write rows into template xlsx via ZIP+XML
- `cli.py` — typer commands

## License

MIT
