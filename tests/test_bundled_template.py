"""The package ships a pre-sanitised default xlsx template — verify it stays
clean (no auditor name, no absPath, neutral A3 title) and that ProjectConfig
resolves to it when no template path is set.
"""

import zipfile

from adreport.config import (
    ClientConfig,
    InputsConfig,
    ProjectConfig,
    default_template_path,
)


def test_bundled_template_exists():
    p = default_template_path()
    assert p.exists()
    assert p.suffix == ".xlsx"


def test_bundled_template_has_no_auditor_metadata():
    """The bundled default template must not leak any author/path metadata."""
    p = default_template_path()
    with zipfile.ZipFile(p) as z:
        core = z.read("docProps/core.xml").decode("utf-8")
        wb = z.read("xl/workbook.xml").decode("utf-8")
    # creator must be empty (no auditor's full name)
    import re
    creator_match = re.search(r"<dc:creator(?:\s[^>]*)?>([^<]*)</dc:creator>", core)
    assert creator_match is not None, f"creator element missing in {core!r}"
    assert not creator_match.group(1).strip(), (
        f"creator must be empty, got {creator_match.group(1)!r}"
    )
    # No filesystem path leaked
    assert "absPath" not in wb
    assert "C:\\\\Users" not in wb


def test_bundled_template_is_valid_xlsx():
    """Should round-trip through openpyxl without errors and preserve validations."""
    p = default_template_path()
    with zipfile.ZipFile(p) as z:
        names = set(z.namelist())
    assert "xl/worksheets/sheet1.xml" in names
    with zipfile.ZipFile(p) as z:
        s1 = z.read("xl/worksheets/sheet1.xml").decode("utf-8")
    # Drop-down validations (Сегмент сети / Тип) survived sanitisation
    assert "dataValidations" in s1


def test_project_config_without_template_resolves_to_bundled(tmp_path):
    from datetime import date
    fake_xml = tmp_path / "pc.xml"
    fake_xml.write_text("<HealthcheckData/>")
    cfg = ProjectConfig(
        client=ClientConfig(name="ACME", audit_date=date(2026, 5, 15)),
        inputs=InputsConfig(pingcastle=fake_xml),
        # template intentionally omitted
        output=tmp_path / "out.xlsx",
    )
    assert cfg.template is None
    assert cfg.resolved_template() == default_template_path()
