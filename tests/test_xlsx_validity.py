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


def test_sanitize_keeps_tab_lf_cr():
    """\\t, \\n, \\r are XML 1.0 legal and must survive."""
    raw = "line1\nline2\tindented\rdone"
    assert _sanitize_cell_text(raw) == raw


def test_sanitize_truncates_long_text():
    raw = "x" * (_CELL_MAX_CHARS + 5000)
    out = _sanitize_cell_text(raw)
    assert len(out) <= _CELL_MAX_CHARS
    assert "обрезано" in out  # truncation marker present


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
