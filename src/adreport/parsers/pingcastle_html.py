"""Parse PingCastle HTML report and extract per-RiskId detail tables.

PingCastle's HTML output organises each rule under a wrapper element:

    <div id="rulesmaturity{N}{RiskId}" class="collapse">
        <div class="card-body">
            <h3>...rule title...</h3>
            ...sections (Description, Technical explanation, Advised solution)...
            <strong>Details:</strong>
            ...some rules: <div class="row"><table>...</table></div>...
        </div>
    </div>

The XML report only stores aggregates (Rationale = "Presence of X = 5"), but the
HTML usually contains the *actual list of affected objects* (DCs, GPOs, accounts,
registry keys). This parser walks the wrapper divs, finds the first non-trivial
<table>, and returns it as a PlumTable-shaped record so it can flow through the
same appendix pipeline as PlumHound tables.
"""

from __future__ import annotations

import re
from pathlib import Path

from bs4 import BeautifulSoup, Tag

from ..model import PlumTable

# Match wrapper divs: "rulesmaturity" + 1-2 digit maturity level + RiskId (P-..., S-..., A-..., T-...).
WRAPPER_ID_RE = re.compile(r"^rulesmaturity\d+([PSATCRY]-[A-Za-z0-9_-]+)$")


def load_pingcastle_details(html_path: Path | str) -> dict[str, PlumTable]:
    """Return {RiskId: PlumTable} for every rule wrapper that contains a table.

    Rules without an embedded data table (e.g. configuration rules whose only
    detail is the wrapper text "see settings section") are absent from the
    result — callers fall back to the rationale string in column G.
    """
    html = Path(html_path).read_text(encoding="utf-8", errors="replace")
    soup = BeautifulSoup(html, "lxml")
    out: dict[str, PlumTable] = {}
    for wrapper in soup.find_all("div", id=WRAPPER_ID_RE):
        match = WRAPPER_ID_RE.match(wrapper["id"])
        if not match:
            continue
        risk_id = match.group(1)
        if risk_id in out:
            # First occurrence wins — duplicates usually point at the same data.
            continue
        table = _extract_first_meaningful_table(wrapper)
        if table is None:
            continue
        out[risk_id] = table
    return out


def _extract_first_meaningful_table(wrapper: Tag) -> PlumTable | None:
    """Return the first <table> in the wrapper that holds data rows.

    Skips tables that look like the metadata header (Points / Documentation /
    Description bullet lists) by requiring at least one data row beyond the
    header.
    """
    for table_el in wrapper.find_all("table"):
        headers = tuple(
            th.get_text(strip=True) for th in table_el.find_all("th")
        )
        rows: list[dict[str, str]] = []
        for tr in table_el.find_all("tr"):
            tds = tr.find_all("td")
            if not tds:
                continue
            cells = [c.get_text(" ", strip=True) for c in tds]
            if headers:
                rec = {
                    h: (cells[i] if i < len(cells) else "")
                    for i, h in enumerate(headers)
                }
            else:
                rec = {f"col{i}": v for i, v in enumerate(cells)}
            rows.append(rec)
        if not rows:
            continue
        return PlumTable(
            name=f"pingcastle:{wrapper['id']}",
            source="pingcastle_html",
            columns=headers if headers else tuple(f"col{i}" for i in range(len(rows[0]))),
            rows=tuple(rows),
        )
    return None
