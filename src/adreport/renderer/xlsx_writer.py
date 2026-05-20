"""ZIP+XML xlsx renderer.

Opens a corporate template .xlsx, appends Finding rows into the "Результаты"
sheet, and spills appendices into new sheets — without round-tripping through
openpyxl, which strips x14:dataValidations (template drop-downs) and other
extension content.
"""

from __future__ import annotations

import datetime as dt
import re
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path

from lxml import etree

from ..model import Finding

# OOXML namespaces ----------------------------------------------------------
NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
NS_CT = "http://schemas.openxmlformats.org/package/2006/content-types"

NSMAP_SHEET = {"r": NS_REL}

# Style ids depend on the template's `xl/styles.xml`. We discover them at
# runtime by reading attributes from cells that already exist in the template's
# data rows (rows 6+). Hard-coding "6"/"8" was a leftover from the original
# corporate template and crashed Excel when the bundled minimal template
# happened to have fewer cellXfs entries.
FALLBACK_DATA_STYLE: str | None = None  # no `s` attribute → default style
FALLBACK_DATE_STYLE: str | None = None


@dataclass
class _SheetRef:
    rid: str
    sheet_id: str
    name: str
    target: str  # e.g. "worksheets/sheet1.xml" — normalised (no leading slash, no "xl/" prefix)


# =============================================================================== entry


def render_report(
    template_path: Path | str,
    output_path: Path | str,
    findings: list[Finding],
    main_sheet_name: str = "Результаты",
    clear_example_rows: bool = True,
    first_data_row: int = 6,
) -> None:
    """Render findings into a copy of the template, writing to output_path.

    The template is preserved verbatim except for:
      * new rows appended to sheetData of the main sheet
      * new hyperlinks added to that sheet's <hyperlinks>
      * new appendix sheets added (one per finding with .appendix set)
      * manifest files (workbook.xml, workbook.xml.rels, [Content_Types].xml) updated
    """
    template_path = Path(template_path)
    output_path = Path(output_path)
    shutil.copy(template_path, output_path)

    with zipfile.ZipFile(output_path) as zin:
        parts: dict[str, bytes] = {n: zin.read(n) for n in zin.namelist()}

    workbook_xml = etree.fromstring(parts["xl/workbook.xml"])
    wb_rels_xml = etree.fromstring(parts["xl/_rels/workbook.xml.rels"])
    ct_xml = etree.fromstring(parts["[Content_Types].xml"])

    sheets = _list_sheets(workbook_xml, wb_rels_xml)
    main_ref = next((s for s in sheets if s.name == main_sheet_name), None)
    if main_ref is None:
        raise ValueError(
            f"Template has no sheet named {main_sheet_name!r}; available: {[s.name for s in sheets]}"
        )

    main_sheet_path = f"xl/{main_ref.target}"
    main_sheet_xml = etree.fromstring(parts[main_sheet_path])
    main_sheet_rels_path = f"xl/worksheets/_rels/{Path(main_ref.target).name}.rels"

    if clear_example_rows:
        cleared_link_refs = _clear_template_data_rows(main_sheet_xml, min_row=first_data_row)
        if cleared_link_refs and main_sheet_rels_path in parts:
            # Drop the now-orphaned external hyperlinks rels of cleared cells.
            rels_root = etree.fromstring(parts[main_sheet_rels_path])
            _drop_orphaned_hyperlink_rels(main_sheet_xml, rels_root)
            parts[main_sheet_rels_path] = _serialize(rels_root)
        # Drop orphan appendix sheets (Прил.N from the template that only example
        # rows referenced — now nobody points at them).
        orphan_apx = _detect_orphan_appendix_sheets(main_sheet_xml, sheets)
        if orphan_apx:
            _drop_sheets(parts, workbook_xml, wb_rels_xml, ct_xml, sheets, orphan_apx)

    # Decide where to start appending: first row in sheetData with empty column A.
    start_row = _find_first_empty_row(main_sheet_xml, column_letter="A", min_row=first_data_row)
    next_number = _next_finding_number(main_sheet_xml, start_row)

    appendix_links: list[tuple[str, str]] = []  # (cell_ref, location) for hyperlinks
    new_sheet_specs: list[tuple[str, str, str, list[tuple[str, ...]], tuple[str, ...]]] = []
    # (sheet_name, sheet_filename_basename, appendix_title, rows, columns)

    next_sheet_id = max((int(s.sheet_id) for s in sheets), default=0) + 1
    next_rid_num = _max_rid_num(wb_rels_xml) + 1
    next_sheet_file_num = _max_sheet_filenum(parts) + 1
    next_appendix_idx = _next_appendix_index(sheets)

    for offset, finding in enumerate(findings):
        row_num = start_row + offset
        if finding.appendix is not None:
            apx_name = f"Прил.{next_appendix_idx}"
            apx_filename = f"sheet{next_sheet_file_num}.xml"
            # Prefix appendix title with domain so the tab content disambiguates
            # when several domains contribute appendices for the same rule.
            apx_title = (
                f"[{finding.domain}] {finding.appendix.title}"
                if finding.domain
                else finding.appendix.title
            )
            new_sheet_specs.append(
                (
                    apx_name,
                    apx_filename,
                    apx_title,
                    list(finding.appendix.rows),
                    finding.appendix.columns,
                )
            )
            # Register manifest entries
            sheets.append(
                _SheetRef(
                    rid=f"rId{next_rid_num}",
                    sheet_id=str(next_sheet_id),
                    name=apx_name,
                    target=f"worksheets/{apx_filename}",
                )
            )
            details_text = f"См. {apx_name}!A1"
            appendix_links.append((f"G{row_num}", f"{apx_name}!A1"))
            next_appendix_idx += 1
            next_sheet_file_num += 1
            next_rid_num += 1
            next_sheet_id += 1
        else:
            details_text = finding.details_text

        _set_row(
            main_sheet_xml,
            row_num,
            number=next_number + offset,
            finding=finding,
            details_text=details_text,
        )

    _add_hyperlinks(main_sheet_xml, appendix_links)
    _refresh_dimension(main_sheet_xml)

    parts[main_sheet_path] = _serialize(main_sheet_xml)

    # Write new appendix sheet xml parts.
    for apx_name, apx_filename, apx_title, rows, columns in new_sheet_specs:
        parts[f"xl/worksheets/{apx_filename}"] = _build_appendix_sheet_xml(apx_title, rows, columns)

    # Update manifests if we added new sheets OR removed orphans.
    if new_sheet_specs:
        _register_new_sheets(workbook_xml, wb_rels_xml, ct_xml, sheets, new_sheet_specs)
    if new_sheet_specs or (clear_example_rows):
        # clear_example_rows may have dropped orphan appendix sheets — re-emit manifests.
        parts["xl/workbook.xml"] = _serialize(workbook_xml)
        parts["xl/_rels/workbook.xml.rels"] = _serialize(wb_rels_xml)
        parts["[Content_Types].xml"] = _serialize(ct_xml)

    # Rewrite zip.
    # Pre-flight: every XML part must be well-formed before we write the zip.
    # Catches structural defects (malformed inline text, mismatched namespaces)
    # at build time instead of letting Excel report "Ошибка в части содержимого"
    # on the user's machine.
    _verify_parts_well_formed(parts)

    _write_zip(output_path, parts)


# =============================================================================== sheet edits


def _q(tag: str, ns: str = NS_MAIN) -> str:
    return f"{{{ns}}}{tag}"


def _clear_template_data_rows(sheet_xml: etree._Element, min_row: int) -> list[str]:
    """Wipe values from all populated data rows starting at min_row.

    Stops at the first fully empty row. Preserves cell styles (s="..."), removes
    only <v>/<is> content and the t="..." attribute so cells become blank. Also
    removes <hyperlinks><hyperlink ref="..."/></hyperlinks> entries that pointed
    into the cleared rows.

    Returns the list of cell refs whose hyperlinks (if any) were dropped — caller
    may use this to clean orphaned rels.
    """
    sheet_data = sheet_xml.find(_q("sheetData"))
    if sheet_data is None:
        return []
    cleared_refs: list[str] = []
    for row in list(sheet_data.findall(_q("row"))):
        r = int(row.get("r", "0"))
        if r < min_row:
            continue
        if not _row_is_populated(row):
            break
        for c in row.findall(_q("c")):
            if c.get("t") in ("s", "inlineStr", "str"):
                del c.attrib["t"]
            for child in list(c):
                c.remove(child)
            cleared_refs.append(c.get("r", ""))

    # Drop hyperlinks pointing into cleared cells.
    hl_el = sheet_xml.find(_q("hyperlinks"))
    if hl_el is not None:
        cleared_set = set(cleared_refs)
        for link in list(hl_el.findall(_q("hyperlink"))):
            if link.get("ref") in cleared_set:
                hl_el.remove(link)
        if len(hl_el) == 0:
            sheet_xml.remove(hl_el)
    return cleared_refs


def _row_is_populated(row: etree._Element) -> bool:
    for c in row.findall(_q("c")):
        v = c.find(_q("v"))
        if v is not None and (v.text or "").strip():
            return True
        if c.find(_q("is")) is not None:
            return True
    return False


def _detect_orphan_appendix_sheets(
    main_sheet_xml: etree._Element, sheets: list[_SheetRef]
) -> list[_SheetRef]:
    """Return Прил.N sheets that no surviving hyperlink in main sheet points at.

    Called after _clear_template_data_rows: the example rows (and their
    hyperlinks like G6→Прил.1!A1) are gone, leaving template appendices
    dangling. Они декоративный мусор — удаляем.
    """
    live_targets: set[str] = set()
    hl_el = main_sheet_xml.find(_q("hyperlinks"))
    if hl_el is not None:
        for link in hl_el.findall(_q("hyperlink")):
            loc = link.get("location") or ""
            if "!" in loc:
                live_targets.add(loc.split("!", 1)[0].strip("'"))
    orphans = []
    for s in sheets:
        if s.name.startswith("Прил.") and s.name not in live_targets:
            orphans.append(s)
    return orphans


def _drop_sheets(
    parts: dict[str, bytes],
    workbook_xml: etree._Element,
    wb_rels_xml: etree._Element,
    ct_xml: etree._Element,
    sheets_list: list[_SheetRef],
    to_remove: list[_SheetRef],
) -> None:
    """Remove sheets from workbook.xml, rels, [Content_Types].xml, parts dict and from sheets_list."""
    remove_rids = {s.rid for s in to_remove}
    remove_targets = {s.target for s in to_remove}

    sheets_el = workbook_xml.find(_q("sheets"))
    if sheets_el is not None:
        for s_el in list(sheets_el.findall(_q("sheet"))):
            if s_el.get(f"{{{NS_REL}}}id") in remove_rids:
                sheets_el.remove(s_el)

    for rel in list(wb_rels_xml.findall(_q("Relationship", NS_PKG_REL))):
        if rel.get("Id") in remove_rids:
            wb_rels_xml.remove(rel)

    for ov in list(ct_xml.findall(_q("Override", NS_CT))):
        part = ov.get("PartName", "").lstrip("/")
        for t in remove_targets:
            if part == f"xl/{t}":
                ct_xml.remove(ov)
                break

    for t in remove_targets:
        part_key = f"xl/{t}"
        parts.pop(part_key, None)
        # Drop sheet-rels file if present.
        from pathlib import PurePosixPath
        rels_key = f"xl/worksheets/_rels/{PurePosixPath(t).name}.rels"
        parts.pop(rels_key, None)

    for s in to_remove:
        if s in sheets_list:
            sheets_list.remove(s)


def _drop_orphaned_hyperlink_rels(sheet_xml: etree._Element, rels_root: etree._Element) -> None:
    """Remove relationship entries that are no longer referenced from <hyperlinks>."""
    live_ids: set[str] = set()
    hl_el = sheet_xml.find(_q("hyperlinks"))
    if hl_el is not None:
        for link in hl_el.findall(_q("hyperlink")):
            rid = link.get(f"{{{NS_REL}}}id")
            if rid:
                live_ids.add(rid)
    for rel in list(rels_root.findall(_q("Relationship", NS_PKG_REL))):
        rid = rel.get("Id", "")
        rel_type = rel.get("Type", "")
        if rel_type.endswith("/hyperlink") and rid not in live_ids:
            rels_root.remove(rel)


def _find_first_empty_row(sheet_xml: etree._Element, column_letter: str, min_row: int) -> int:
    """First row (>=min_row) whose cell in `column_letter` is empty or absent."""
    sheet_data = sheet_xml.find(_q("sheetData"))
    if sheet_data is None:
        return min_row
    occupied = set()
    for row in sheet_data.findall(_q("row")):
        r = row.get("r")
        if r is None:
            continue
        rn = int(r)
        for c in row.findall(_q("c")):
            ref = c.get("r", "")
            if ref.rstrip("0123456789") == column_letter:
                v = c.find(_q("v"))
                inline = c.find(_q("is"))
                if (v is not None and (v.text or "").strip()) or inline is not None:
                    occupied.add(rn)
                break
    rn = min_row
    while rn in occupied:
        rn += 1
    return rn


def _next_finding_number(sheet_xml: etree._Element, start_row: int) -> int:
    """Read the largest numeric value in column A above start_row and return +1.

    Cells with ``t="s"`` (sharedStrings index) and ``t="inlineStr"`` are skipped;
    we only count cells whose <v> is a real number.
    """
    sheet_data = sheet_xml.find(_q("sheetData"))
    if sheet_data is None:
        return 1
    max_num = 0
    for row in sheet_data.findall(_q("row")):
        r = row.get("r")
        if r is None or int(r) >= start_row:
            continue
        for c in row.findall(_q("c")):
            if c.get("r", "").rstrip("0123456789") != "A":
                continue
            if c.get("t") in ("s", "inlineStr", "str"):
                break
            v = c.find(_q("v"))
            if v is not None and (v.text or "").strip().isdigit():
                max_num = max(max_num, int(v.text))
            break
    return max_num + 1


def _refresh_dimension(sheet_xml: etree._Element) -> None:
    """Update ``<dimension ref="...">`` to span the actual populated data range.

    OOXML allows readers to use <dimension> as a hint for the used range. Stale
    dimensions (e.g. template's "A3:I5" still in place after adding 144 rows)
    don't always break Excel but raise warnings in stricter validators. Keep it
    consistent with reality.
    """
    sheet_data = sheet_xml.find(_q("sheetData"))
    if sheet_data is None:
        return
    max_row = 0
    max_col_letters = "A"
    import re as _re
    col_re = _re.compile(r"^([A-Z]+)\d+$")

    def _col_idx(letters: str) -> int:
        n = 0
        for ch in letters:
            n = n * 26 + (ord(ch) - ord("A") + 1)
        return n

    for row in sheet_data.findall(_q("row")):
        r_attr = row.get("r")
        if r_attr is None:
            continue
        rn = int(r_attr)
        if rn > max_row:
            max_row = rn
        for c in row.findall(_q("c")):
            m = col_re.match(c.get("r", ""))
            if m and _col_idx(m.group(1)) > _col_idx(max_col_letters):
                max_col_letters = m.group(1)

    if max_row == 0:
        return
    new_ref = f"A1:{max_col_letters}{max_row}"
    dim = sheet_xml.find(_q("dimension"))
    if dim is None:
        # Insert <dimension> right after <worksheet> opening (before sheetViews)
        dim = etree.Element(_q("dimension"))
        dim.set("ref", new_ref)
        sheet_xml.insert(0, dim)
    else:
        dim.set("ref", new_ref)


def _template_style_for_column(
    sheet_data: etree._Element,
    column: str,
    fallback: etree._Element | None = None,
) -> str | None:
    """Return the ``s`` attribute of any existing template-pre-populated cell in
    `column`, used to inherit the template's per-column styling for new rows.

    Strategy:
      1. If `fallback` (existing same-row element) has a cell in this column
         with `s`, return it — preserves customisations the user made.
      2. Otherwise scan sheetData top-down for the first cell in this column
         that carries `s` — that's the template's default styling.
      3. Otherwise return None — Excel will use the workbook default style.

    Crucially, indices are *not* hardcoded: they're read from styles.xml-indexed
    cellXfs entries that physically exist in the template's styles.xml. This
    keeps the renderer compatible with templates of any complexity.
    """
    # Helper: column-letter prefix from a cell ref like "A6" → "A"
    import re as _re
    _col_re = _re.compile(r"^([A-Z]+)\d+$")

    def _cell_col(c: etree._Element) -> str | None:
        m = _col_re.match(c.get("r", ""))
        return m.group(1) if m else None

    if fallback is not None:
        for c in fallback.findall(_q("c")):
            if _cell_col(c) == column:
                s = c.get("s")
                if s:
                    return s
                break
    for row in sheet_data.findall(_q("row")):
        for c in row.findall(_q("c")):
            if _cell_col(c) == column:
                s = c.get("s")
                if s:
                    return s
                break
    return None


def _set_row(
    sheet_xml: etree._Element,
    row_num: int,
    number: int,
    finding: Finding,
    details_text: str,
) -> None:
    """Insert or replace a <row r="row_num"> in sheetData with finding data."""
    sheet_data = sheet_xml.find(_q("sheetData"))
    assert sheet_data is not None, "sheetData missing"

    existing = None
    insert_before = None
    for row in sheet_data.findall(_q("row")):
        r = int(row.get("r", "0"))
        if r == row_num:
            existing = row
            break
        if r > row_num:
            insert_before = row
            break

    new_row = etree.Element(_q("row"))
    new_row.set("r", str(row_num))
    if existing is not None:
        # Preserve row attributes like custom height if present.
        for k, v in existing.attrib.items():
            new_row.set(k, v)
        new_row.set("r", str(row_num))
    # Let Excel recompute row height so wrap_text isn't clipped.
    # Removing customHeight/ht prevents the template's fixed height from
    # truncating multi-line content like recommendations.
    for attr in ("customHeight", "ht"):
        if attr in new_row.attrib:
            del new_row.attrib[attr]

    # Date as serial number (Excel 1900 system: days since 1900-01-01, offset by 2 for leap bug)
    date_serial = _excel_date_serial(finding.audit_date)

    # Column C: client name, suffixed with the domain when scanning multiple AD domains.
    client_cell = (
        f"{finding.client} ({finding.domain})" if finding.domain else finding.client
    )

    # Look up styles from any existing template row in the same column.
    # This avoids hard-coded indices that would point past the template's
    # cellXfs list (causing Excel to mark the workbook as corrupted).
    def _s_for(col: str, prefer_date: bool = False) -> str | None:
        return _template_style_for_column(sheet_data, col, fallback=existing)

    cells = [
        _cell_number(row_num, "A", number, style=_s_for("A")),
        _cell_number(row_num, "B", date_serial, style=_s_for("B", prefer_date=True)),
        _cell_inline(row_num, "C", client_cell, style=_s_for("C")),
        _cell_inline(row_num, "D", finding.segment, style=_s_for("D")),
        _cell_inline(row_num, "E", finding.type, style=_s_for("E")),
        _cell_inline(row_num, "F", finding.title, style=_s_for("F")),
        _cell_inline(row_num, "G", details_text, style=_s_for("G")),
        _cell_inline(row_num, "H", finding.recommendation, style=_s_for("H")),
        _cell_inline(row_num, "I", finding.note, style=_s_for("I")),
    ]
    for c in cells:
        new_row.append(c)

    if existing is not None:
        sheet_data.replace(existing, new_row)
    elif insert_before is not None:
        sheet_data.addprevious  # noqa: B018 — silence linter; we use index insertion below
        idx = list(sheet_data).index(insert_before)
        sheet_data.insert(idx, new_row)
    else:
        sheet_data.append(new_row)


# Excel hard limit on a cell value is 32767 chars; anything longer makes the
# workbook "have unreadable content" and Excel prompts to repair on open.
# We truncate slightly below the limit to leave room for the truncation marker.
_CELL_MAX_CHARS = 32700
# XML 1.0 disallows control characters (except \t \n \r) in element text;
# PlumHound HTML occasionally contains them and they corrupt the workbook.
_XML10_INVALID_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
# U+FFFD REPLACEMENT CHARACTER — what BeautifulSoup / lxml emit when input
# bytes can't be decoded as UTF-8. Valid Unicode and valid XML, but Excel's
# stricter validators have been observed to reject content with these. Also
# looks ugly in a security report ("��� ��� ��� @CORP.LOCAL"). Collapse runs
# of U+FFFD to a single "?" so cells stay readable.
_REPLACEMENT_RUN_RE = re.compile(r"�+")


def _sanitize_cell_text(text: str) -> str:
    """Strip XML-illegal control characters and truncate to Excel's cell limit.

    Also collapses runs of U+FFFD REPLACEMENT CHARACTER to a single "?".
    """
    if not text:
        return ""
    cleaned = _XML10_INVALID_RE.sub("", text)
    cleaned = _REPLACEMENT_RUN_RE.sub("?", cleaned)
    if len(cleaned) > _CELL_MAX_CHARS:
        marker = f"\n…[обрезано {len(cleaned) - _CELL_MAX_CHARS} символов]"
        cleaned = cleaned[: _CELL_MAX_CHARS - len(marker)] + marker
    return cleaned


def _cell_inline(row_num: int, col: str, text: str, style: str | None = None) -> etree._Element:
    c = etree.Element(_q("c"))
    c.set("r", f"{col}{row_num}")
    c.set("t", "inlineStr")
    if style is not None:
        c.set("s", style)
    is_el = etree.SubElement(c, _q("is"))
    t_el = etree.SubElement(is_el, _q("t"))
    t_el.text = _sanitize_cell_text(text or "")
    # Preserve leading/trailing whitespace.
    t_el.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    return c


def _cell_number(row_num: int, col: str, value: float, style: str | None = None) -> etree._Element:
    c = etree.Element(_q("c"))
    c.set("r", f"{col}{row_num}")
    if style is not None:
        c.set("s", style)
    v = etree.SubElement(c, _q("v"))
    # Strip trailing .0 for integer values
    if isinstance(value, float) and value.is_integer():
        v.text = str(int(value))
    else:
        v.text = str(value)
    return c


def _excel_date_serial(d: dt.datetime | dt.date) -> int:
    """Convert date to Excel's 1900-based serial number."""
    if isinstance(d, dt.datetime):
        d = d.date()
    epoch = dt.date(1899, 12, 30)  # Excel's 1900 leap bug origin
    return (d - epoch).days


# =============================================================================== hyperlinks


def _add_hyperlinks(sheet_xml: etree._Element, links: list[tuple[str, str]]) -> None:
    if not links:
        return
    hyperlinks_el = sheet_xml.find(_q("hyperlinks"))
    if hyperlinks_el is None:
        hyperlinks_el = etree.Element(_q("hyperlinks"))
        # Insert after sheetData / mergeCells, before pageMargins
        sheet_data_idx = list(sheet_xml).index(sheet_xml.find(_q("sheetData")))
        # Insert at index after sheetData (or after mergeCells if present)
        merge = sheet_xml.find(_q("mergeCells"))
        if merge is not None:
            insert_at = list(sheet_xml).index(merge) + 1
        else:
            insert_at = sheet_data_idx + 1
        sheet_xml.insert(insert_at, hyperlinks_el)
    for cell_ref, location in links:
        link = etree.SubElement(hyperlinks_el, _q("hyperlink"))
        link.set("ref", cell_ref)
        link.set("location", location)
        link.set("display", location)


# =============================================================================== appendix sheet


def _build_appendix_sheet_xml(
    title: str, rows: list[tuple[str, ...]], columns: tuple[str, ...]
) -> bytes:
    """Build a minimal valid worksheet xml for an appendix."""
    root = etree.Element(_q("worksheet"), nsmap={None: NS_MAIN, "r": NS_REL})
    dim = etree.SubElement(root, _q("dimension"))
    last_col_letter = _column_letter(max(len(columns), 1))
    last_row = max(len(rows) + 2, 1)
    dim.set("ref", f"A1:{last_col_letter}{last_row}")

    sheet_views = etree.SubElement(root, _q("sheetViews"))
    sheet_view = etree.SubElement(sheet_views, _q("sheetView"))
    sheet_view.set("workbookViewId", "0")

    etree.SubElement(root, _q("sheetFormatPr")).set("defaultRowHeight", "15")

    cols_el = etree.SubElement(root, _q("cols"))
    for i in range(max(len(columns), 1)):
        col = etree.SubElement(cols_el, _q("col"))
        col.set("min", str(i + 1))
        col.set("max", str(i + 1))
        col.set("width", "32")
        col.set("customWidth", "1")

    sheet_data = etree.SubElement(root, _q("sheetData"))

    # Row 1: title (bold via style 0; we don't have a header style guaranteed in template, leave plain)
    title_row = etree.SubElement(sheet_data, _q("row"))
    title_row.set("r", "1")
    title_row.append(_cell_inline(1, "A", title))

    # Row 2: column headers
    if columns:
        hdr_row = etree.SubElement(sheet_data, _q("row"))
        hdr_row.set("r", "2")
        for i, col_name in enumerate(columns):
            hdr_row.append(_cell_inline(2, _column_letter(i + 1), col_name))

    # Rows 3..N: data
    start_data_row = 3 if columns else 2
    for ri, row in enumerate(rows):
        r_el = etree.SubElement(sheet_data, _q("row"))
        r_el.set("r", str(start_data_row + ri))
        for ci, cell_value in enumerate(row):
            r_el.append(_cell_inline(start_data_row + ri, _column_letter(ci + 1), cell_value))

    etree.SubElement(root, _q("pageMargins")).attrib.update(
        {"left": "0.7", "right": "0.7", "top": "0.75", "bottom": "0.75",
         "header": "0.3", "footer": "0.3"}
    )

    return _serialize(root)


def _column_letter(n: int) -> str:
    """1 → A, 27 → AA."""
    s = ""
    while n > 0:
        n, rem = divmod(n - 1, 26)
        s = chr(65 + rem) + s
    return s


# =============================================================================== manifests


def _normalise_target(target: str | None) -> str:
    """Normalise a Relationship Target into ``worksheets/sheet1.xml``-shaped path.

    openpyxl writes absolute targets like ``/xl/worksheets/sheet1.xml``;
    Excel/Office hand-built templates typically use relative ``worksheets/sheet1.xml``.
    We strip both forms so callers can prefix uniformly with ``xl/``.
    """
    if not target:
        return ""
    t = target
    if t.startswith("/"):
        t = t[1:]
    if t.startswith("xl/"):
        t = t[len("xl/"):]
    return t


def _list_sheets(workbook_xml: etree._Element, wb_rels_xml: etree._Element) -> list[_SheetRef]:
    sheets_el = workbook_xml.find(_q("sheets"))
    out: list[_SheetRef] = []
    if sheets_el is None:
        return out
    rels = {
        rel.get("Id"): _normalise_target(rel.get("Target"))
        for rel in wb_rels_xml.findall(_q("Relationship", NS_PKG_REL))
    }
    for s in sheets_el.findall(_q("sheet")):
        rid = s.get(f"{{{NS_REL}}}id") or ""
        out.append(
            _SheetRef(
                rid=rid,
                sheet_id=s.get("sheetId", "0"),
                name=s.get("name", ""),
                target=rels.get(rid, ""),
            )
        )
    return out


def _max_rid_num(wb_rels_xml: etree._Element) -> int:
    max_n = 0
    for rel in wb_rels_xml.findall(_q("Relationship", NS_PKG_REL)):
        rid = rel.get("Id", "")
        if rid.startswith("rId"):
            try:
                max_n = max(max_n, int(rid[3:]))
            except ValueError:
                pass
    return max_n


def _max_sheet_filenum(parts: dict[str, bytes]) -> int:
    max_n = 0
    for name in parts:
        if name.startswith("xl/worksheets/sheet") and name.endswith(".xml"):
            tail = name[len("xl/worksheets/sheet") : -len(".xml")]
            if tail.isdigit():
                max_n = max(max_n, int(tail))
    return max_n


def _next_appendix_index(sheets: list[_SheetRef]) -> int:
    used = []
    for s in sheets:
        if s.name.startswith("Прил."):
            try:
                used.append(int(s.name.split(".", 1)[1]))
            except ValueError:
                pass
    return (max(used) if used else 0) + 1


def _register_new_sheets(
    workbook_xml: etree._Element,
    wb_rels_xml: etree._Element,
    ct_xml: etree._Element,
    sheet_refs: list[_SheetRef],
    new_specs: list[tuple[str, str, str, list, tuple]],
) -> None:
    sheets_el = workbook_xml.find(_q("sheets"))
    assert sheets_el is not None
    # The last len(new_specs) entries in sheet_refs correspond to the new sheets.
    new_refs = sheet_refs[-len(new_specs):]
    for ref in new_refs:
        s_el = etree.SubElement(sheets_el, _q("sheet"))
        s_el.set("name", ref.name)
        s_el.set("sheetId", ref.sheet_id)
        s_el.set(f"{{{NS_REL}}}id", ref.rid)

    for ref in new_refs:
        rel = etree.SubElement(wb_rels_xml, _q("Relationship", NS_PKG_REL))
        rel.set("Id", ref.rid)
        rel.set("Type", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet")
        rel.set("Target", ref.target)

    for ref in new_refs:
        ov = etree.SubElement(ct_xml, _q("Override", NS_CT))
        ov.set("PartName", f"/xl/{ref.target}")
        ov.set("ContentType", "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml")


# =============================================================================== zip i/o


def _serialize(el: etree._Element) -> bytes:
    return etree.tostring(el, xml_declaration=True, encoding="UTF-8", standalone=True)


def _verify_parts_well_formed(parts: dict[str, bytes]) -> None:
    """Parse every .xml / .rels part with lxml; raise on syntax errors.

    The error message includes the part name + line/column from the parser so
    that any introduced regression surfaces immediately at build time instead
    of as a vague Excel recovery-log entry.
    """
    for name, data in parts.items():
        if not (name.endswith(".xml") or name.endswith(".rels")):
            continue
        try:
            etree.fromstring(data)
        except etree.XMLSyntaxError as e:
            # Surface the part + offending line for debugging
            line_no = getattr(e, "lineno", None) or 1
            text_lines = data.decode("utf-8", errors="replace").splitlines()
            context_lo = max(0, line_no - 3)
            context_hi = min(len(text_lines), line_no + 2)
            context = "\n".join(
                f"  {i+1:>5}: {text_lines[i]}"
                for i in range(context_lo, context_hi)
            )
            raise RuntimeError(
                f"Generated XML is malformed in {name}:\n"
                f"  {e}\n"
                f"Context (line {line_no}):\n{context}\n\n"
                f"This is a bug in the renderer — please open an issue with this trace."
            ) from e


def _write_zip(path: Path, parts: dict[str, bytes]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)
    tmp.replace(path)
