"""Parse PlumHound output bundle (directory or .zip) into named tables.

HTML files are preferred when both .html and .csv are present:
PlumHound's CSV exports are often empty (2 bytes) or omit columns,
while HTML always contains the full populated table.
"""

from __future__ import annotations

import csv
import io
import re
import tempfile
import zipfile
from pathlib import Path

from bs4 import BeautifulSoup

from ..model import PlumTable


class PlumHoundLoader:
    """Loader resolving table names to PlumTable, HTML-first.

    Pass either a directory containing PlumHound output, or a path to a .zip
    archive (the loader extracts to a tempdir on first use).
    """

    def __init__(self, source: Path | str):
        self.source = Path(source)
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self.root = self._resolve_root(self.source)
        self._index = self._index_files(self.root)

    # ------------------------------------------------------------------ public

    def list_tables(self) -> list[str]:
        """Logical table names available in this bundle."""
        return sorted(self._index.keys())

    def load(self, name: str) -> PlumTable | None:
        """Load a table by logical name (e.g. 'AdminsWithout_ProtectedUsers').

        Tries .html first, then .csv. Returns None when the name is absent;
        returns a PlumTable with zero rows when present but empty.
        """
        entry = self._index.get(self._logical_name(name))
        if entry is None:
            return None
        html_path = entry.get("html")
        csv_path = entry.get("csv")
        if html_path is not None:
            tbl = self._load_html(html_path)
            if tbl is not None:
                return tbl
        if csv_path is not None:
            return self._load_csv(csv_path)
        return None

    def cleanup(self) -> None:
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None

    # ----------------------------------------------------------------- helpers

    def _resolve_root(self, source: Path) -> Path:
        """Return a directory containing flat PlumHound table files.

        Accepts:
        - a directory (recursively searches for the deepest dir containing tables)
        - a .zip archive (extracts to tempdir, then recurses)
        """
        if source.is_file() and source.suffix.lower() == ".zip":
            self._tmpdir = tempfile.TemporaryDirectory(prefix="plumhound_")
            with zipfile.ZipFile(source) as z:
                z.extractall(self._tmpdir.name)
            return self._find_table_dir(Path(self._tmpdir.name))
        if source.is_dir():
            return self._find_table_dir(source)
        raise FileNotFoundError(f"PlumHound source not found: {source}")

    @staticmethod
    def _find_table_dir(root: Path) -> Path:
        """Locate the directory that actually holds PlumHound table files.

        PlumHound bundles often nest under Users/User/Projects/<x>/plum/<domain>/.
        We descend until we hit a directory with at least one *.html or *.csv.
        """
        candidates = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in (".html", ".csv")]
        if not candidates:
            raise FileNotFoundError(f"No PlumHound .html/.csv files under {root}")
        # Choose the directory that contains the most table files (the leaf dir).
        from collections import Counter

        counts = Counter(c.parent for c in candidates)
        return counts.most_common(1)[0][0]

    @staticmethod
    def _logical_name(filename_or_logical: str) -> str:
        """Normalise filename → logical key. Strips repeated .html and .csv suffixes."""
        name = filename_or_logical
        # repeatedly strip known extensions; e.g. 'AdminsWithout_ProtectedUsers.html.csv'
        for _ in range(3):
            low = name.lower()
            if low.endswith(".html"):
                name = name[: -len(".html")]
            elif low.endswith(".csv"):
                name = name[: -len(".csv")]
            else:
                break
        return name

    def _index_files(self, dir_: Path) -> dict[str, dict[str, Path]]:
        index: dict[str, dict[str, Path]] = {}
        for p in dir_.iterdir():
            if not p.is_file():
                continue
            key = self._logical_name(p.name)
            kind: str | None
            if p.suffix.lower() == ".html":
                kind = "html"
            elif p.suffix.lower() == ".csv":
                kind = "csv"
            else:
                kind = None
            if kind is None:
                continue
            slot = index.setdefault(key, {})
            # Prefer larger file when duplicates exist (handles .html.html / .html.csv).
            existing = slot.get(kind)
            if existing is None or p.stat().st_size > existing.stat().st_size:
                slot[kind] = p
        return index

    @staticmethod
    def _load_html(path: Path) -> PlumTable | None:
        text = path.read_text(encoding="utf-8", errors="replace")
        soup = BeautifulSoup(text, "lxml")
        table = soup.find("table")
        if table is None:
            return PlumTable(
                name=PlumHoundLoader._logical_name(path.name),
                source="html",
                columns=(),
                rows=(),
            )
        headers = tuple(th.get_text(strip=True) for th in table.find_all("th"))
        rows: list[dict[str, str]] = []
        for tr in table.find_all("tr"):
            tds = tr.find_all("td")
            if not tds:
                continue
            cells = [c.get_text(strip=True) for c in tds]
            # Pad or trim to headers
            if headers:
                rec = {h: (cells[i] if i < len(cells) else "") for i, h in enumerate(headers)}
            else:
                rec = {f"col{i}": v for i, v in enumerate(cells)}
            rows.append(rec)
        return PlumTable(
            name=PlumHoundLoader._logical_name(path.name),
            source="html",
            columns=headers,
            rows=tuple(rows),
        )

    @staticmethod
    def _load_csv(path: Path) -> PlumTable:
        text = path.read_text(encoding="utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        rows = tuple(reader)
        return PlumTable(
            name=PlumHoundLoader._logical_name(path.name),
            source="csv",
            columns=tuple(reader.fieldnames or ()),
            rows=rows,
        )
