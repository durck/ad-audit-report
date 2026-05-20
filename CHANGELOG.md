# Changelog

All notable changes to this project follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — Initial release

### Features
- Build Excel security audit reports from PingCastle (`*.xml` + `*.html`) and
  PlumHound (`*.zip` / directory) output.
- Bundled clean xlsx template — no client metadata, no auditor name, no
  filesystem paths. Build a report with no arguments beyond `project.yaml`.
- Catalog of **189 PingCastle RiskIds** + **45 PlumHound-only synthetic
  findings** — all with Russian title, recommendation, count-label.
- Per-rule detail tables: PingCastle HTML wrapper-divs and PlumHound HTML
  tables are parsed and spilled into auto-generated appendix sheets.
- **Multi-domain support** — scan multiple AD domains in one project.yaml and
  get a single merged report with `[Домен: …]` tags in column C and notes.
- `sanitize-template` CLI command to strip auditor name / absPath / client
  name from any corporate xlsx template you bring along.
- ZIP+XML renderer preserves template's data validations (drop-down menus on
  «Сегмент сети» / «Тип»), styles, tables, and named ranges intact.

### Safety
- Cell content sanitiser: every text passed into xlsx is stripped of XML 1.0
  control characters and truncated to Excel's 32 767-char cell limit.
- Orphan appendix sheets in legacy templates are dropped when example rows
  are cleared.
