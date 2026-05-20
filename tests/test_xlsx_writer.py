import zipfile
from datetime import datetime
from pathlib import Path

import pytest
from lxml import etree

from adreport.model import Appendix, Finding
from adreport.renderer import render_report

FIXTURES = Path(__file__).parent / "fixtures"
TEMPLATE = FIXTURES / "template_minimal.xlsx"

NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def _q(tag: str) -> str:
    return f"{{{NS_MAIN}}}{tag}"


@pytest.fixture
def sample_findings() -> list[Finding]:
    audit = datetime(2026, 5, 15)
    return [
        Finding(
            title="Привилегированные УЗ не в Protected Users",
            type="Недостаток",
            segment="Серверный",
            details_text="",
            recommendation="Добавить в Protected Users.",
            note="PingCastle: P-ProtectedUsers",
            audit_date=audit,
            client='ПАО "Тест"',
            source_id="P-ProtectedUsers",
            appendix=Appendix(
                title="Привилегированные УЗ вне Protected Users",
                columns=("User", "DisplayName"),
                rows=(
                    ("ADMIN1@T.LOCAL", "Иванов И."),
                    ("ADMIN2@T.LOCAL", "Петров П."),
                ),
            ),
        ),
        Finding(
            title="Windows Server 2012 вне поддержки",
            type="Уязвимость",
            segment="Серверный",
            details_text="Get-ADComputer -Filter {OperatingSystem -like '*2012*'}",
            recommendation="Мигрировать на 2019/2022.",
            note="PingCastle: S-OS-2012",
            audit_date=audit,
            client='ПАО "Тест"',
            source_id="S-OS-2012",
        ),
    ]


def test_output_is_valid_zip(tmp_path, sample_findings):
    out = tmp_path / "report.xlsx"
    render_report(TEMPLATE, out, sample_findings)
    assert out.exists()
    # Just checks the file is a valid zip and contains expected parts
    with zipfile.ZipFile(out) as z:
        names = set(z.namelist())
    assert "xl/workbook.xml" in names
    assert "xl/worksheets/sheet1.xml" in names


def test_data_validations_preserved(tmp_path, sample_findings):
    """The whole point of going ZIP+XML: dataValidations must survive."""
    out = tmp_path / "report.xlsx"
    render_report(TEMPLATE, out, sample_findings)
    with zipfile.ZipFile(out) as z:
        sheet1 = z.read("xl/worksheets/sheet1.xml").decode("utf-8")
    assert "dataValidations" in sheet1
    assert "Справочники" in sheet1  # named-range references intact


def test_new_rows_present(tmp_path, sample_findings):
    out = tmp_path / "report.xlsx"
    render_report(TEMPLATE, out, sample_findings)
    with zipfile.ZipFile(out) as z:
        sheet1 = z.read("xl/worksheets/sheet1.xml").decode("utf-8")
    # Both finding titles must appear in inline strings of sheet1
    assert "Привилегированные УЗ не в Protected Users" in sheet1
    assert "Windows Server 2012 вне поддержки" in sheet1
    # Hyperlink to new appendix must be wired.
    # With clear_example_rows=True (default), the template's Прил.1-3 orphans
    # are dropped, so numbering restarts at Прил.1.
    assert "Прил.1!A1" in sheet1


def test_appendix_sheet_created_with_rows(tmp_path, sample_findings):
    out = tmp_path / "report.xlsx"
    render_report(TEMPLATE, out, sample_findings)
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
    new_sheets = [n for n in names if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")]
    # Template had 5 sheets (Результаты + 3 Прил.* + Справочники). clear_example_rows
    # drops the 3 orphan appendices, leaving 2; then we add 1 → 3 total.
    assert len(new_sheets) == 3
    # Verify content of the new appendix
    with zipfile.ZipFile(out) as z:
        for n in new_sheets:
            xml = z.read(n).decode("utf-8")
            if "ADMIN1@T.LOCAL" in xml:
                assert "Иванов И." in xml
                assert "User" in xml and "DisplayName" in xml
                break
        else:
            pytest.fail("New appendix with admin data not found")


def test_workbook_lists_new_sheet(tmp_path, sample_findings):
    out = tmp_path / "report.xlsx"
    render_report(TEMPLATE, out, sample_findings)
    with zipfile.ZipFile(out) as z:
        workbook = z.read("xl/workbook.xml").decode("utf-8")
        rels = z.read("xl/_rels/workbook.xml.rels").decode("utf-8")
        ct = z.read("[Content_Types].xml").decode("utf-8")
    # With orphan-cleanup, our new appendix takes the Прил.1 slot.
    assert 'name="Прил.1"' in workbook
    assert "worksheets/sheet" in rels
    # ContentTypes must have an Override for every worksheet that workbook references.
    # The exact filename depends on which slots remain after orphan removal.
    import re
    sheet_files_in_ct = set(re.findall(r'/xl/(worksheets/sheet\d+\.xml)', ct))
    sheet_targets_in_rels = set(re.findall(r'Target="(worksheets/sheet\d+\.xml)"', rels))
    assert sheet_targets_in_rels.issubset(sheet_files_in_ct), (
        f"Some worksheet has no Override in [Content_Types].xml: "
        f"missing={sheet_targets_in_rels - sheet_files_in_ct}"
    )


def test_default_numbering_starts_from_one(tmp_path, sample_findings):
    """With clear_example_rows=True (default), numbering starts from 1."""
    import re
    out = tmp_path / "report.xlsx"
    render_report(TEMPLATE, out, sample_findings)
    with zipfile.ZipFile(out) as z:
        sheet1 = z.read("xl/worksheets/sheet1.xml")
    root = etree.fromstring(sheet1)
    sd = root.find(_q("sheetData"))
    a_pat = re.compile(r"^A\d+$")
    nums = []
    for row in sd.findall(_q("row")):
        for c in row.findall(_q("c")):
            if a_pat.match(c.get("r", "")):
                if c.get("t") == "s":
                    break
                v = c.find(_q("v"))
                if v is not None and (v.text or "").isdigit():
                    nums.append(int(v.text))
                break
    assert 1 in nums and 2 in nums, f"Expected 1 and 2 among column-A numbers, got {nums}"


def test_idempotent_run(tmp_path, sample_findings):
    """Running twice on the same output should not duplicate rows.

    Actually our impl overwrites the output file via shutil.copy at the top, so
    a second run produces the same output as a first run starting from template.
    """
    out = tmp_path / "report.xlsx"
    render_report(TEMPLATE, out, sample_findings)
    render_report(TEMPLATE, out, sample_findings)
    with zipfile.ZipFile(out) as z:
        sheet1 = z.read("xl/worksheets/sheet1.xml").decode("utf-8")
    # Title appears exactly once
    assert sheet1.count("Привилегированные УЗ не в Protected Users") == 1


def test_empty_findings_keeps_template_intact(tmp_path):
    """Empty findings list → output is a valid xlsx with data validations preserved."""
    out = tmp_path / "report.xlsx"
    render_report(TEMPLATE, out, [])
    with zipfile.ZipFile(out) as z:
        sheet1 = z.read("xl/worksheets/sheet1.xml").decode("utf-8")
    # Data validations still intact (the whole point of the ZIP+XML approach)
    assert "dataValidations" in sheet1
    # Header row (row 5) preserved
    assert 'r="5"' in sheet1
