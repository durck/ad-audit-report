"""Regression: a domain with PlumHound output but no PingCastle XML must not
be skipped wholesale — PlumHound-only synthetic findings (ADCS, DCSync,
Kerberoasting, etc.) still need to fire."""

import zipfile
from datetime import date
from pathlib import Path

import pytest

from adreport.config import ProjectConfig

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def plum_zip(tmp_path: Path) -> Path:
    """Wrap the fixture mini_plum directory into a .zip so PlumHoundLoader can read it."""
    src = FIXTURES / "mini_plum"
    zp = tmp_path / "plum.zip"
    with zipfile.ZipFile(zp, "w") as z:
        for f in src.iterdir():
            z.write(f, arcname=f"nested/{f.name}")
    return zp


def test_pingcastle_optional_in_domain_input():
    """DomainInput must validate without pingcastle when plumhound is provided."""
    from adreport.config import DomainInput

    d = DomainInput(name="x.example.com", plumhound=Path("/tmp/dummy"))
    assert d.pingcastle is None
    assert d.plumhound == Path("/tmp/dummy")


def test_run_pipeline_skips_pingcastle_part_keeps_plumhound(tmp_path, plum_zip):
    """End-to-end: a domain with only PlumHound runs and yields synthetic findings."""
    from adreport.cli import _run_pipeline_for_domains, _load_project

    yaml_text = f"""\
client:
  name: 'ACME'
  audit_date: 2026-05-15
domains:
  - name: only-plum.example.com
    plumhound: {plum_zip.as_posix()}
output: ./out.xlsx
defaults:
  appendix_threshold: 2
"""
    p = tmp_path / "project.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    cfg, _ = _load_project(p)

    from adreport.catalog import Catalog
    findings, _ = _run_pipeline_for_domains(cfg, Catalog.load_default())

    # No PingCastle rules → no PingCastle findings. But PlumHound-only synthetics
    # (KRBTGT_Stale_Password is present in the fixture mini_plum) should fire.
    risk_ids = [f.source_id for f in findings]
    assert "PH-KRBTGT-Stale" in risk_ids, (
        f"Expected synthetic PH-KRBTGT-Stale to fire from PlumHound, "
        f"got source_ids={risk_ids}"
    )
    # All findings must be tagged with the domain
    assert all(f.domain == "only-plum.example.com" for f in findings)


def test_configured_pingcastle_missing_falls_back_to_plumhound(tmp_path, plum_zip, capsys):
    """Both pingcastle and plumhound configured, pingcastle file missing →
    PlumHound part still processed; user gets a clear warning."""
    from adreport.cli import _run_pipeline_for_domains, _load_project
    from adreport.catalog import Catalog

    yaml_text = f"""\
client:
  name: 'ACME'
  audit_date: 2026-05-15
domains:
  - name: half-missing.example.com
    pingcastle: /nonexistent/pc.xml
    plumhound: {plum_zip.as_posix()}
output: ./out.xlsx
defaults:
  appendix_threshold: 2
"""
    p = tmp_path / "project.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    cfg, _ = _load_project(p)
    findings, _ = _run_pipeline_for_domains(cfg, Catalog.load_default())

    # PlumHound synthetics still fire
    assert any(f.source_id == "PH-KRBTGT-Stale" for f in findings)
    # User sees an explicit warning naming the missing file
    captured = capsys.readouterr()
    assert "PingCastle XML configured but not found" in captured.out
    assert "/nonexistent/pc.xml" in captured.out


def test_configured_plumhound_missing_keeps_pingcastle(tmp_path, capsys):
    """Symmetric case: PingCastle works, PlumHound configured but missing."""
    from adreport.cli import _run_pipeline_for_domains, _load_project
    from adreport.catalog import Catalog

    pc_path = FIXTURES / "mini_pingcastle.xml"
    yaml_text = f"""\
client:
  name: 'ACME'
  audit_date: 2026-05-15
domains:
  - name: half-missing.example.com
    pingcastle: {pc_path.as_posix()}
    plumhound: /nonexistent/plum/
output: ./out.xlsx
defaults:
  appendix_threshold: 2
"""
    p = tmp_path / "project.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    cfg, _ = _load_project(p)
    findings, _ = _run_pipeline_for_domains(cfg, Catalog.load_default())

    # PingCastle rules still produce findings
    pc_findings = [f for f in findings if f.source_id.startswith(("P-", "S-", "A-"))]
    assert len(pc_findings) > 0
    captured = capsys.readouterr()
    assert "PlumHound output configured but not found" in captured.out
    assert "/nonexistent/plum" in captured.out


def test_run_pipeline_skips_domain_with_no_inputs(tmp_path, capsys):
    """When both sources are missing, the domain is skipped entirely with a warning."""
    from adreport.cli import _run_pipeline_for_domains, _load_project

    yaml_text = """\
client:
  name: 'ACME'
  audit_date: 2026-05-15
domains:
  - name: empty.example.com
    pingcastle: /nonexistent/pc.xml
    plumhound: /nonexistent/plum/
output: ./out.xlsx
"""
    p = tmp_path / "project.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    cfg, _ = _load_project(p)

    from adreport.catalog import Catalog
    findings, _ = _run_pipeline_for_domains(cfg, Catalog.load_default())
    assert findings == []
    captured = capsys.readouterr()
    assert "Skipping domain empty.example.com" in captured.out
    assert "neither PingCastle XML nor PlumHound" in captured.out
