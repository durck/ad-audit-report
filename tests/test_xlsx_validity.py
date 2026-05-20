"""Regression: protect against the two classes of bugs that cause Excel to show
«Ошибка в части содержимого, выполнить попытку восстановления?» on open:

  1. Cell text longer than 32767 characters (Excel hard limit).
  2. XML 1.0 control characters in cell text (\\x00-\\x08, \\x0b, \\x0c, \\x0e-\\x1f).

Both are triggered by long PlumHound/PingCastle output that flows through
inline strings without sanitisation. The renderer must clean them silently.
"""

import re
import zipfile
from datetime import datetime
from pathlib import Path

import pytest
from lxml import etree

from adreport.model import Appendix, Finding
from adreport.renderer import render_report
from adreport.renderer.xlsx_writer import _CELL_MAX_CHARS, _sanitize_cell_text

FIXTURES = Path(__file__).parent / "fixtures"
TEMPLATE = FIXTURES / "template_minimal.xlsx"
NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def test_sanitize_strips_xml_invalid_controls():
    raw = "ab\x00cd\x01ef\x07gh\x0bi"  # mix of forbidden controls
    assert _sanitize_cell_text(raw) == "abcdefghi"


def test_sanitize_flattens_all_line_breaks_to_bullet():
    """Excel's strict validator repeatedly rejected cells with literal
    newlines in xml:space="preserve" text — first as `\\n\\n`, then `\\n`,
    then again after every fix sheet1.xml flagged a new line. The only
    reliable mitigation is to flatten in-cell line breaks entirely.

    All runs of CR / LF / CRLF collapse to a visual bullet separator,
    which Excel renders inline without any of the strict-mode side effects.
    """
    raw = "first paragraph\n\nsecond paragraph\rmixed\r\nlast"
    out = _sanitize_cell_text(raw)
    assert "\n" not in out
    assert "\r" not in out
    assert out == "first paragraph  •  second paragraph  •  mixed  •  last"


def test_sanitize_collapses_replacement_chars():
    """U+FFFD runs from BeautifulSoup's bad-UTF-8 fallback collapse to '?'.

    Source: PlumHound HTML for some domains arrives with cp1251 / cp866 bytes
    incorrectly labelled UTF-8 — every bad byte becomes U+FFFD. Long runs
    look like cell garbage and have been observed to trigger Excel's strict
    validators.
    """
    raw = "user@CORP.LOCAL — ��� ��� ��� test"
    out = _sanitize_cell_text(raw)
    assert "�" not in out
    # Each run replaced by single '?'
    assert out == "user@CORP.LOCAL — ? ? ? test"


def test_sanitize_keeps_tab():
    """\\t survives — only line breaks are flattened.

    Linebreak flattening is covered in test_sanitize_flattens_all_line_breaks_to_bullet.
    """
    raw = "col1\tcol2\tcol3"
    assert _sanitize_cell_text(raw) == raw


def test_sanitize_truncates_long_text():
    raw = "x" * (_CELL_MAX_CHARS + 5000)
    out = _sanitize_cell_text(raw)
    assert len(out) <= _CELL_MAX_CHARS
    assert "обрезано" in out  # truncation marker present


def test_worksheet_children_in_schema_order(tmp_path):
    """OOXML CT_Worksheet mandates a strict child-element order. Inserting
    a new <hyperlinks> or <dimension> in the wrong slot makes Excel reject
    the workbook with «Ошибка в части содержимого», even though lxml /
    openpyxl / our text-level doctor all accept it.

    Regression: _add_hyperlinks used to splice <hyperlinks> right after
    <sheetData>/<mergeCells>, which placed it BEFORE the bundled template's
    <dataValidations> (schema requires dataValidations to precede hyperlinks).
    """
    from datetime import datetime

    from adreport.model import Appendix, Finding
    from adreport.renderer import render_report

    findings = [
        Finding(
            title="x", type="Уязвимость", segment="Серверный",
            details_text="", recommendation="r", note="n",
            audit_date=datetime(2026, 5, 15), client="TEST",
            source_id="X",
            appendix=Appendix(title="t", columns=("A",), rows=(("v1",), ("v2",))),
        )
    ]
    out = tmp_path / "report.xlsx"
    render_report(TEMPLATE, out, findings)

    # Canonical order (subset relevant to our renderer)
    canonical = [
        "sheetPr", "dimension", "sheetViews", "sheetFormatPr", "cols", "sheetData",
        "mergeCells", "dataValidations", "hyperlinks",
        "pageMargins", "tableParts", "extLst",
    ]
    canon_index = {tag: i for i, tag in enumerate(canonical)}

    with zipfile.ZipFile(out) as z:
        sheet1 = z.read("xl/worksheets/sheet1.xml")
    root = etree.fromstring(sheet1)
    seen_positions: list[tuple[str, int]] = []
    for child in root:
        tag = etree.QName(child).localname
        if tag in canon_index:
            seen_positions.append((tag, canon_index[tag]))

    positions_only = [p for _, p in seen_positions]
    assert positions_only == sorted(positions_only), (
        f"worksheet children out of schema order: "
        f"{[t for t, _ in seen_positions]} — Excel will reject this file"
    )


def test_no_hardcoded_style_indices_in_rendered_cells(tmp_path):
    """Excel rejects the workbook with «Ошибка в части содержимого» when cells
    reference a cellXfs index that doesn't exist in styles.xml. openpyxl
    surfaces the same defect as IndexError on load. The renderer must read
    style ids from the template at runtime, not hardcode them.

    Regression: TEMPLATE_DATA_STYLE = "6" / TEMPLATE_DATE_STYLE = "8" used to
    be baked into the renderer for the legacy НМТП corporate template; the
    bundled clean template has only 5 cellXfs entries, so any s="6" reference
    overflowed.
    """
    from datetime import datetime

    findings = [
        Finding(
            title="X", type="Недостаток", segment="Серверный",
            details_text="", recommendation="r", note="n",
            audit_date=datetime(2026, 5, 15), client="ТЕСТ", source_id="X",
        )
    ]
    out = tmp_path / "report.xlsx"
    render_report(TEMPLATE, out, findings)

    # openpyxl in strict mode triggers IndexError on out-of-range style ids —
    # that's the same defect Excel reports as a corrupted workbook.
    import openpyxl
    wb = openpyxl.load_workbook(out)
    assert "Результаты" in wb.sheetnames

    # Verify the appended row carries some s-attribute that exists in styles.xml,
    # or no s-attribute at all (default style). Both are valid; an out-of-range
    # numeric s is the bug we're guarding against.
    with zipfile.ZipFile(out) as z:
        styles_xml = z.read("xl/styles.xml").decode("utf-8")
        sheet1 = z.read("xl/worksheets/sheet1.xml").decode("utf-8")
    cell_xfs_count_m = re.search(r'<cellXfs[^>]*count="(\d+)"', styles_xml)
    max_s = int(cell_xfs_count_m.group(1)) - 1 if cell_xfs_count_m else 0
    for s_val in re.findall(r'<c[^>]+s="(\d+)"', sheet1):
        assert int(s_val) <= max_s, (
            f"Cell references s='{s_val}' but cellXfs has indices 0..{max_s}"
        )


def test_render_handles_huge_cell_without_corruption(tmp_path):
    """End-to-end: a finding with >32767-char appendix cell must produce a
    valid xlsx, no cell with t/text longer than 32767, no XML 1.0 control chars."""
    huge = "name | " + ", ".join(f"USER{i}@EXAMPLE.LOCAL" for i in range(5000))
    assert len(huge) > 60_000

    findings = [
        Finding(
            title="Stress test",
            type="Уязвимость",
            segment="Серверный",
            details_text="",
            recommendation="rec",
            note="note",
            audit_date=datetime(2026, 5, 15),
            client="ТЕСТ",
            source_id="STRESS",
            appendix=Appendix(
                title="Huge appendix",
                columns=("Principal", "Targets"),
                rows=(("Foo", huge), ("Bar", huge + "\x00\x01extra")),
            ),
        )
    ]

    out = tmp_path / "stress.xlsx"
    render_report(TEMPLATE, out, findings)

    invalid_re = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
    with zipfile.ZipFile(out) as z:
        for n in z.namelist():
            if not n.endswith(".xml"):
                continue
            xml = z.read(n)
            # Must parse
            root = etree.fromstring(xml)
            # Walk every <t> element (inline string text); check size + chars
            for t in root.iter(f"{{{NS_MAIN}}}t"):
                if t.text is None:
                    continue
                assert len(t.text) <= 32767, (
                    f"{n}: cell text exceeds Excel hard limit ({len(t.text)} chars)"
                )
                assert not invalid_re.search(t.text), (
                    f"{n}: XML 1.0 invalid control char in cell text"
                )
