"""Multi-domain support: when `domains:` is set in project.yaml, findings from
every domain are merged into one report and each row is tagged in column C."""

import re
import zipfile
from datetime import date
from pathlib import Path

import pytest
import yaml

from adreport.config import ProjectConfig

FIXTURES = Path(__file__).parent / "fixtures"


def _write_project_yaml(tmp_path: Path, domains_section: str) -> Path:
    p = tmp_path / "project.yaml"
    p.write_text(
        f"""\
client:
  name: 'ACME'
  audit_date: 2026-05-15
{domains_section}
output: ./out.xlsx
defaults:
  appendix_threshold: 2
""",
        encoding="utf-8",
    )
    return p


def test_load_single_domain_via_inputs():
    cfg = ProjectConfig(**yaml.safe_load((FIXTURES / "mini_pingcastle.xml").read_text())) if False else None
    # Direct python construct to avoid full Pydantic-yaml round-trip noise.
    cfg = ProjectConfig.model_validate(
        {
            "client": {"name": "ACME", "audit_date": date(2026, 5, 15)},
            "inputs": {"pingcastle": str(FIXTURES / "mini_pingcastle.xml")},
            "output": "./out.xlsx",
        }
    )
    domains = cfg.iter_domain_inputs()
    assert len(domains) == 1
    assert domains[0].name == ""  # single-domain sentinel


def test_load_multi_domain_via_domains():
    cfg = ProjectConfig.model_validate(
        {
            "client": {"name": "ACME", "audit_date": date(2026, 5, 15)},
            "domains": [
                {"name": "corp.example.com", "pingcastle": str(FIXTURES / "mini_pingcastle.xml")},
                {"name": "fleet.example.com", "pingcastle": str(FIXTURES / "mini_pingcastle.xml")},
            ],
            "output": "./out.xlsx",
        }
    )
    domains = cfg.iter_domain_inputs()
    assert len(domains) == 2
    assert {d.name for d in domains} == {"corp.example.com", "fleet.example.com"}


def test_inputs_and_domains_are_mutually_exclusive():
    cfg = ProjectConfig.model_validate(
        {
            "client": {"name": "ACME", "audit_date": date(2026, 5, 15)},
            "inputs": {"pingcastle": str(FIXTURES / "mini_pingcastle.xml")},
            "domains": [
                {"name": "x", "pingcastle": str(FIXTURES / "mini_pingcastle.xml")},
            ],
            "output": "./out.xlsx",
        }
    )
    with pytest.raises(ValueError, match="либо.*либо"):
        cfg.iter_domain_inputs()


def test_finding_carries_domain_through_pipeline(tmp_path):
    from adreport.catalog import Catalog
    from adreport.parsers import parse_pingcastle
    from adreport.pipeline import build_findings

    cfg = ProjectConfig.model_validate(
        {
            "client": {"name": "ACME", "audit_date": date(2026, 5, 15)},
            "inputs": {"pingcastle": str(FIXTURES / "mini_pingcastle.xml")},
            "output": "./out.xlsx",
        }
    )
    pc = parse_pingcastle(FIXTURES / "mini_pingcastle.xml")
    catalog = Catalog.load_default()
    result = build_findings(pc, None, catalog, cfg, domain="corp.example.com")
    assert all(f.domain == "corp.example.com" for f in result.findings)
    # Note has the [Домен: …] tag
    assert all("[Домен: corp.example.com]" in f.note for f in result.findings)


def test_render_writes_domain_in_column_c(tmp_path):
    from datetime import datetime

    from adreport.model import Finding
    from adreport.renderer import render_report

    findings = [
        Finding(
            title="A",
            type="Недостаток",
            segment="Серверный",
            details_text="d",
            recommendation="r",
            note="n",
            audit_date=datetime(2026, 5, 15),
            client="ACME",
            source_id="X",
            domain="corp.example.com",
        ),
        Finding(
            title="B",
            type="Уязвимость",
            segment="Серверный",
            details_text="d2",
            recommendation="r2",
            note="n2",
            audit_date=datetime(2026, 5, 15),
            client="ACME",
            source_id="Y",
            domain="fleet.example.com",
        ),
    ]
    out = tmp_path / "report.xlsx"
    render_report(FIXTURES / "template_minimal.xlsx", out, findings)
    with zipfile.ZipFile(out) as z:
        sheet1 = z.read("xl/worksheets/sheet1.xml").decode("utf-8")
    assert "ACME (corp.example.com)" in sheet1
    assert "ACME (fleet.example.com)" in sheet1


def test_render_writes_plain_client_when_no_domain(tmp_path):
    from datetime import datetime

    from adreport.model import Finding
    from adreport.renderer import render_report

    findings = [
        Finding(
            title="A",
            type="Недостаток",
            segment="Серверный",
            details_text="d",
            recommendation="r",
            note="n",
            audit_date=datetime(2026, 5, 15),
            client="ACME",
            source_id="X",
        ),
    ]
    out = tmp_path / "report.xlsx"
    render_report(FIXTURES / "template_minimal.xlsx", out, findings)
    with zipfile.ZipFile(out) as z:
        sheet1 = z.read("xl/worksheets/sheet1.xml").decode("utf-8")
    # Plain client name, no parens
    assert re.search(r"<t[^>]*>ACME</t>", sheet1)
