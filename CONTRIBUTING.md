# Contributing

## Dev setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
```

## Adding a PingCastle rule

The catalog lives in `src/adreport/catalog/recommendations.yaml`. For a new
RiskId, append an entry under `recommendations:` with:

```yaml
P-NewRule:
  title: "Короткое описание на русском"
  type: Недостаток | Уязвимость | Возможно недостаток
  segment: Серверный | Пользовательский
  count_label: "затронутые объекты"   # used when only Rationale is available
  recommendation: |
    Многострочные рекомендации.
  plumhound:                           # optional: source of detail rows
    - file: SomePlumHoundTable
      cols: [Col1, Col2]
```

Then `adreport validate ./project.yaml` will pick it up automatically.

## Adding a PlumHound-only finding

For findings that PingCastle does not report (e.g. BloodHound ACL paths),
add to `synthetic_findings:` in the same yaml. They trigger when their
`triggers_on:` table is non-empty.

## Regenerating the bundled template

```bash
python tools/build_default_template.py
```

This rebuilds `src/adreport/templates/default.xlsx` from scratch with no
client metadata. Run after structural changes to the «Результаты» sheet.

## Running tests

```bash
.venv/bin/pytest -q
```

41 tests across parsers, pipeline, renderer, multi-domain, and bundled-template
guarantees. No tests rely on real client data — fixtures are minimal and
synthetic.

## Privacy

Never commit:
- Real PingCastle / PlumHound output from client engagements
- Templates with `creator` / `lastModifiedBy` metadata pointing at real people
- IP addresses, hostnames, account names from any real environment

If you encounter a corporate template with confidential metadata, run
`adreport sanitize-template IN OUT` before committing.
