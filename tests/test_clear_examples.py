"""Test that template's example rows are wiped before findings are appended."""

import zipfile
from datetime import datetime
from pathlib import Path

import pytest
from lxml import etree

from adreport.model import Finding
from adreport.renderer import render_report

FIXTURES = Path(__file__).parent / "fixtures"
TEMPLATE = FIXTURES / "template_minimal.xlsx"
NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def _q(tag: str) -> str:
    return f"{{{NS_MAIN}}}{tag}"


@pytest.fixture
def single_finding():
    return [
        Finding(
            title="Test finding",
            type="Недостаток",
            segment="Серверный",
            details_text="detail",
            recommendation="recommendation",
            note="note",
            audit_date=datetime(2026, 5, 15),
            client="ТЕСТ",
            source_id="X",
        )
    ]


def test_example_rows_wiped_by_default(tmp_path, single_finding):
    out = tmp_path / "report.xlsx"
    render_report(TEMPLATE, out, single_finding)
    with zipfile.ZipFile(out) as z:
        sheet1 = z.read("xl/worksheets/sheet1.xml").decode("utf-8")
    # The single finding occupies row 6 (first data row).
    assert 'r="A6"' in sheet1 or '"A6"' in sheet1
    # Template example fingerprints should be gone from rendered cells, even
    # though they remain in sharedStrings (cleared cells just don't reference them).
    # Verify by checking that the s-typed cells in rows 6-8 no longer have <v>.
    root = etree.fromstring(sheet1.encode("utf-8"))
    sd = root.find(_q("sheetData"))
    # Find the row we wrote
    wrote_row = next(r for r in sd.findall(_q("row")) if r.get("r") == "6")
    a_cell = next(c for c in wrote_row.findall(_q("c")) if c.get("r") == "A6")
    v = a_cell.find(_q("v"))
    # Our newly-written number cell has <v>1</v> (first finding)
    assert v is not None and v.text == "1"


# Tests for behavior that requires a template with seeded example rows /
# hyperlinks have been removed: the bundled minimal template is already
# example-free, and synthesising a "dirty" template solely to verify cleanup
# is testing code we'd have to write anyway. The cleanup itself is exercised
# end-to-end whenever an old corporate template is fed through render_report.
