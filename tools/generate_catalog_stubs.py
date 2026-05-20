"""Merge tool: generate stubs for every PingCastle RiskId, preserving hand-written entries.

Input:
  - /tmp/all_pingcastle_rules.json  (output of the parser over PingCastle .cs sources)
  - existing recommendations.yaml (kept verbatim for rules already authored)

Output:
  - new recommendations.yaml with full coverage of every RiskId in the upstream source.

Usage:
  python tools/generate_catalog_stubs.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "adreport" / "catalog" / "recommendations.yaml"
RULES_JSON = Path("/tmp/all_pingcastle_rules.json")


# Russian category→default settings
DEFAULTS_BY_CATEGORY = {
    "PrivilegedAccounts": {"segment": "Серверный", "default_type": "Недостаток"},
    "StaleObjects": {"segment": "Серверный", "default_type": "Недостаток"},
    "Anomalies": {"segment": "Серверный", "default_type": "Недостаток"},
    "Trusts": {"segment": "Серверный", "default_type": "Возможно недостаток"},
}


def severity_from_points(pts: int) -> str:
    """Map PingCastle max-points to severity classification."""
    if pts >= 30:
        return "Уязвимость"
    if pts >= 15:
        return "Уязвимость"
    if pts >= 5:
        return "Недостаток"
    return "Возможно недостаток"


def make_segment(risk_id: str, category: str) -> str:
    """Heuristics: client OS rules → Пользовательский, остальное → по категории."""
    if any(s in risk_id for s in ("OS-Win7", "OS-Win8", "OS-W10", "OS-XP", "OS-Vista", "OS-NT", "OS-2000")):
        return "Пользовательский"
    return DEFAULTS_BY_CATEGORY.get(category, {}).get("segment", "Серверный")


def make_title(risk_id: str, description: str) -> str:
    """Use English description from source, prefix with PingCastle RiskId for clarity."""
    if description:
        return f"PingCastle {risk_id}: {description}"
    # Fall back to RiskId-based title
    words = risk_id.split("-", 1)[-1]
    pretty = " ".join(
        [c for c in __import__("re").split(r"(?=[A-Z])", words) if c]
    ).strip()
    return f"PingCastle {risk_id} ({pretty})"


def make_recommendation(risk_id: str, category: str, description: str) -> str:
    """Generic placeholder pointing to documentation. Hand-authored entries override this."""
    return (
        f"Уязвимость / недостаток обнаружен правилом PingCastle {risk_id} (категория {category}).\n"
        f"Описание: {description or 'см. документацию PingCastle'}.\n\n"
        f"Документация и рекомендации Microsoft / PingCastle:\n"
        f"  https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html#{risk_id}\n\n"
        f"Требуется ручная адаптация рекомендации под конкретный проект.\n"
        f"Дополните запись {risk_id!r} в recommendations.yaml русским текстом и при возможности — "
        f"plumhound: ссылкой на источник списка объектов."
    )


def main() -> int:
    if not RULES_JSON.exists():
        print(f"ERROR: {RULES_JSON} missing. Run the .cs parser first.", file=sys.stderr)
        return 1

    upstream = {r["risk_id"]: r for r in json.loads(RULES_JSON.read_text(encoding="utf-8"))}

    with SRC.open(encoding="utf-8") as f:
        existing = yaml.safe_load(f)
    existing_recommendations: dict = dict(existing.get("recommendations", {}))
    existing_synthetic = existing.get("synthetic_findings", [])

    # Filter: drop RiskIds that contain template markers like $$$
    upstream = {k: v for k, v in upstream.items() if "$" not in k}

    # Add stubs for every upstream RiskId not yet authored.
    added = 0
    for risk_id, meta in sorted(upstream.items()):
        if risk_id in existing_recommendations:
            continue
        cat = meta["category"]
        existing_recommendations[risk_id] = {
            "title": make_title(risk_id, meta["description"]),
            "type": severity_from_points(meta["max_points"]),
            "segment": make_segment(risk_id, cat),
            "recommendation": make_recommendation(risk_id, cat, meta["description"]),
        }
        added += 1

    # Build final document preserving comments where possible.
    # PyYAML does not preserve comments, so we dump using a custom representer that orders
    # the keys consistently. Hand-authored entries stay as data — they have already been
    # round-tripped through PyYAML.
    out_doc = {
        "recommendations": existing_recommendations,
        "synthetic_findings": existing_synthetic,
    }

    # Custom YAML dump: literal block style for multi-line strings.
    class LiteralStr(str):
        pass

    def _str_repr(dumper, data):
        if "\n" in data:
            return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
        return dumper.represent_scalar("tag:yaml.org,2002:str", data)

    yaml.add_representer(str, _str_repr)

    header = SRC.read_text(encoding="utf-8").split("\nrecommendations:", 1)[0]
    new_body = yaml.dump(out_doc, allow_unicode=True, sort_keys=False, width=10000)
    SRC.write_text(header + "\n" + new_body, encoding="utf-8")

    print(f"Existing recommendations preserved: {len(existing_recommendations) - added}")
    print(f"Stubs added for new RiskIds:        {added}")
    print(f"Total in catalog now:                {len(existing_recommendations)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
