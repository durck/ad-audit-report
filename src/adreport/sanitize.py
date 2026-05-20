"""Sanitize a corporate xlsx template — strip confidential metadata.

What gets cleaned:
  - docProps/core.xml: creator and lastModifiedBy → empty
  - docProps/app.xml: Company / AppVersion / Manager → empty
  - xl/workbook.xml: absPath (filesystem path on the original author's machine)
  - xl/worksheets/sheet1.xml: cell A3 (report title) replaced with a neutral
    placeholder so the auditor name doesn't leak

What is preserved:
  - All sheet structure, styles, data validations, formulas, named ranges,
    tables, drawings/images, printerSettings
  - Example rows (cleaning of those is done by render_report, not here)
"""

from __future__ import annotations

import re
import shutil
import zipfile
from pathlib import Path

from lxml import etree

NS_CORE = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
NS_DC = "http://purl.org/dc/elements/1.1/"
NS_DCTERMS = "http://purl.org/dc/terms/"
NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"

DEFAULT_TITLE = "Список недостатков конфигурации"


def sanitize_template(
    template_path: Path | str,
    output_path: Path | str,
    new_title: str = DEFAULT_TITLE,
) -> dict[str, str]:
    """Strip confidential metadata from an xlsx template.

    Returns a report dict of what was changed: {field: before → after}.
    """
    src = Path(template_path)
    dst = Path(output_path)
    shutil.copy(src, dst)

    changes: dict[str, str] = {}

    with zipfile.ZipFile(dst) as zin:
        parts: dict[str, bytes] = {n: zin.read(n) for n in zin.namelist()}

    # 1. core.xml — creator / lastModifiedBy
    if "docProps/core.xml" in parts:
        before, after, parts["docProps/core.xml"] = _clean_core_xml(parts["docProps/core.xml"])
        for k, (b, a) in before.items():
            changes[f"core/{k}"] = f"{b!r} → {a!r}"

    # 2. app.xml — Company / AppVersion / Manager
    if "docProps/app.xml" in parts:
        before, parts["docProps/app.xml"] = _clean_app_xml(parts["docProps/app.xml"])
        for k, b in before.items():
            changes[f"app/{k}"] = f"{b!r} → ''"

    # 3. workbook.xml — absPath
    if "xl/workbook.xml" in parts:
        before, parts["xl/workbook.xml"] = _strip_abspath(parts["xl/workbook.xml"])
        if before:
            changes["workbook/absPath"] = f"{before!r} → removed"

    # 4. sheet1.xml — A3 title (replace shared-string ref with inline text)
    if "xl/worksheets/sheet1.xml" in parts and "xl/sharedStrings.xml" in parts:
        before, parts["xl/worksheets/sheet1.xml"] = _replace_title_cell(
            parts["xl/worksheets/sheet1.xml"], parts["xl/sharedStrings.xml"], new_title
        )
        if before:
            changes["sheet1/A3"] = f"{before[:60]!r}... → {new_title!r}"

    _write_zip(dst, parts)
    return changes


# ----------------------------------------------------------------- core/app xml


def _clean_core_xml(xml_bytes: bytes) -> tuple[dict[str, tuple[str, str]], dict[str, tuple[str, str]], bytes]:
    """Clear creator and lastModifiedBy. Returns ({field: (before, after)}, ...)."""
    root = etree.fromstring(xml_bytes)
    changes: dict[str, tuple[str, str]] = {}
    targets = [
        (f"{{{NS_DC}}}creator", ""),
        (f"{{{NS_CORE}}}lastModifiedBy", ""),
        (f"{{{NS_DC}}}description", ""),
        (f"{{{NS_DC}}}subject", ""),
        (f"{{{NS_CORE}}}keywords", ""),
    ]
    for tag, new_value in targets:
        el = root.find(tag)
        if el is None:
            continue
        old = el.text or ""
        if old != new_value:
            changes[etree.QName(tag).localname] = (old, new_value)
            el.text = new_value
    return changes, changes, etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)


def _clean_app_xml(xml_bytes: bytes) -> tuple[dict[str, str], bytes]:
    """Clear Company / Manager from app.xml."""
    root = etree.fromstring(xml_bytes)
    ns_app = root.nsmap.get(None, "")
    changes: dict[str, str] = {}
    for local in ("Company", "Manager"):
        if not ns_app:
            continue
        el = root.find(f"{{{ns_app}}}{local}")
        if el is not None and (el.text or "").strip():
            changes[local] = el.text or ""
            el.text = ""
    return changes, etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)


# ----------------------------------------------------------------- workbook absPath


def _strip_abspath(xml_bytes: bytes) -> tuple[str, bytes]:
    """Remove <mc:AlternateContent> wrapper containing x15ac:absPath."""
    text = xml_bytes.decode("utf-8", errors="replace")
    match = re.search(r'absPath[^>]*url="([^"]+)"', text)
    before = match.group(1) if match else ""
    # Wholesale remove the <mc:AlternateContent>…</mc:AlternateContent> block when
    # it contains an absPath child.
    text = re.sub(
        r"<mc:AlternateContent\b[^>]*>(?:(?!</mc:AlternateContent>).)*?absPath(?:(?!</mc:AlternateContent>).)*?</mc:AlternateContent>",
        "",
        text,
        flags=re.S,
    )
    return before, text.encode("utf-8")


# ----------------------------------------------------------------- title cell


def _replace_title_cell(sheet1_bytes: bytes, shared_strings_bytes: bytes, new_title: str) -> tuple[str, bytes]:
    """Replace cell A3 with an inline-string holding new_title.

    Reads the original sharedStrings value at A3 for the before/after report.
    Does not touch sharedStrings.xml itself.
    """
    sst_root = etree.fromstring(shared_strings_bytes)
    sst_values = []
    for si in sst_root.findall(f"{{{NS_MAIN}}}si"):
        # collect concatenated text from <t> children
        text_parts = [t.text or "" for t in si.iter(f"{{{NS_MAIN}}}t")]
        sst_values.append("".join(text_parts))

    sheet_root = etree.fromstring(sheet1_bytes)
    sheet_data = sheet_root.find(f"{{{NS_MAIN}}}sheetData")
    if sheet_data is None:
        return "", sheet1_bytes

    before = ""
    for row in sheet_data.findall(f"{{{NS_MAIN}}}row"):
        if row.get("r") != "3":
            continue
        a3 = next(
            (c for c in row.findall(f"{{{NS_MAIN}}}c") if c.get("r") == "A3"),
            None,
        )
        if a3 is None:
            continue
        # Read old value: either shared-string index or inline
        if a3.get("t") == "s":
            v = a3.find(f"{{{NS_MAIN}}}v")
            if v is not None and (v.text or "").isdigit():
                idx = int(v.text)
                if 0 <= idx < len(sst_values):
                    before = sst_values[idx]
        # Rebuild cell as inline string
        style = a3.get("s")
        a3.clear()
        a3.set("r", "A3")
        a3.set("t", "inlineStr")
        if style is not None:
            a3.set("s", style)
        is_el = etree.SubElement(a3, f"{{{NS_MAIN}}}is")
        t_el = etree.SubElement(is_el, f"{{{NS_MAIN}}}t")
        t_el.text = new_title
        break

    return before, etree.tostring(sheet_root, xml_declaration=True, encoding="UTF-8", standalone=True)


# ----------------------------------------------------------------- zip


def _write_zip(path: Path, parts: dict[str, bytes]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)
    tmp.replace(path)
