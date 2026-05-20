"""Combine PingCastle + PlumHound + catalog → list of Finding."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from .catalog import Catalog, PlumSource, RecommendationEntry, SyntheticFinding
from .config import OverrideEntry, ProjectConfig
from .model import Appendix, Finding, PingCastleReport, PlumTable
from .parsers import PlumHoundLoader


@dataclass
class BuildResult:
    findings: list[Finding]
    unknown_risk_ids: list[str]
    """RiskIds present in PingCastle but absent from catalog — printed as warnings."""


def build_findings(
    pingcastle: PingCastleReport,
    plum: PlumHoundLoader | None,
    catalog: Catalog,
    config: ProjectConfig,
    pingcastle_details: dict[str, PlumTable] | None = None,
    domain: str = "",
) -> BuildResult:
    """Produce a sequence of Finding objects in the same order they should appear in the report.

    Detail-table resolution order for each PingCastle rule:
      1. PingCastle HTML (``pingcastle_details``) — same RiskId key.
      2. PlumHound (``plum``) — table names from the catalog entry.
      3. PingCastle XML Rationale — short summary text only.
    """
    findings: list[Finding] = []
    unknown: list[str] = []
    audit_dt = config.audit_datetime
    pingcastle_details = pingcastle_details or {}

    # Sort PingCastle rules: highest points first, stable order on ties.
    sorted_rules = sorted(pingcastle.rules, key=lambda r: (-r.points, r.risk_id))

    for rule in sorted_rules:
        override = config.overrides.get(rule.risk_id)
        if override and override.skip:
            continue
        entry = catalog.recommendations.get(rule.risk_id)
        if entry is None:
            unknown.append(rule.risk_id)
            # Generic placeholder — keeps the row in the report so it's not silently dropped.
            findings.append(_finding_from_unknown_rule(rule, config, audit_dt, pingcastle_details, domain))
            continue
        findings.append(
            _finding_from_known_rule(
                rule, entry, override, plum, config, audit_dt, pingcastle_details, domain
            )
        )

    # Synthetic findings — independent of PingCastle rules.
    for syn in catalog.synthetic_findings:
        override = config.overrides.get(syn.id)
        if override and override.skip:
            continue
        finding = _finding_from_synthetic(syn, override, plum, pingcastle, config, audit_dt, domain)
        if finding is not None:
            findings.append(finding)

    return BuildResult(findings=findings, unknown_risk_ids=unknown)


# ---------------------------------------------------------------------- helpers


def _apply_override(value: str, override: OverrideEntry | None, field: str) -> str:
    if override is None:
        return value
    new = getattr(override, field, None)
    return new if new is not None else value


def _finding_from_known_rule(
    rule,
    entry: RecommendationEntry,
    override: OverrideEntry | None,
    plum: PlumHoundLoader | None,
    config: ProjectConfig,
    audit_dt: datetime,
    pingcastle_details: dict[str, PlumTable],
    domain: str = "",
) -> Finding:
    title = _apply_override(entry.title, override, "title")
    f_type = _apply_override(entry.type, override, "type")
    segment = _apply_override(entry.segment, override, "segment")
    recommendation = _apply_override(entry.recommendation, override, "recommendation")
    threshold = (override.appendix_threshold if override else None) or config.defaults.appendix_threshold

    appendix, details_text, used_source = _resolve_details(
        title=title,
        risk_id=rule.risk_id,
        pingcastle_details=pingcastle_details,
        plumhound_sources=entry.plumhound,
        plum=plum,
        threshold=threshold,
        fallback_text=rule.rationale,
    )
    # When we fell back to rationale, prefer a compact "N {count_label}" over
    # the verbose English Rationale sentence.
    if used_source == "rationale":
        compact = _compact_rationale(rule.rationale, entry.count_label)
        if compact:
            details_text = compact
    # ldap_hint goes into the recommendation column so column G stays short — but
    # only when no concrete object list was found anywhere.
    if entry.ldap_hint and not appendix and used_source == "rationale":
        recommendation = recommendation.rstrip() + (
            "\n\nКоманда для выгрузки списка затронутых объектов:\n" + entry.ldap_hint.rstrip()
        )
    note_parts = []
    if domain:
        note_parts.append(f"[Домен: {domain}]")
    note_parts.append(f"PingCastle: {rule.risk_id} (Points={rule.points}, Category={rule.category})")
    note = " ".join(note_parts)

    return Finding(
        title=title,
        type=f_type,
        segment=segment,
        details_text=details_text,
        recommendation=recommendation.rstrip(),
        note=note,
        audit_date=audit_dt,
        client=config.client.name,
        appendix=appendix,
        source_id=rule.risk_id,
        domain=domain,
    )


def _finding_from_unknown_rule(
    rule,
    config: ProjectConfig,
    audit_dt: datetime,
    pingcastle_details: dict[str, PlumTable],
    domain: str = "",
) -> Finding:
    # Even unknown rules may have HTML details we can show.
    title = f"[Каталог не содержит описания для {rule.risk_id}]"
    table = pingcastle_details.get(rule.risk_id)
    if table and table.rows and len(table.rows) >= config.defaults.appendix_threshold:
        cols = table.columns
        rows = tuple(tuple(r.get(c, "") for c in cols) for r in table.rows)
        appendix = Appendix(title=title, columns=cols, rows=rows)
        details_text = ""
    elif table and table.rows:
        appendix = None
        lines = [", ".join(table.columns) + ":"]
        for r in table.rows:
            lines.append("  " + " | ".join(r.get(c, "") for c in table.columns))
        details_text = "\n".join(lines)
    else:
        appendix = None
        details_text = rule.rationale
    note_parts = []
    if domain:
        note_parts.append(f"[Домен: {domain}]")
    note_parts.append(f"PingCastle: {rule.risk_id} (нет в каталоге; Points={rule.points})")
    return Finding(
        title=title,
        type=config.defaults.type,
        segment=config.defaults.segment,
        details_text=details_text,
        recommendation=(
            f"Требуется ручная разработка рекомендации. Категория PingCastle: "
            f"{rule.category} / Model: {rule.model}. "
            f"Добавьте описание в recommendations.yaml под ключом {rule.risk_id!r}."
        ),
        note=" ".join(note_parts),
        audit_date=audit_dt,
        client=config.client.name,
        appendix=appendix,
        source_id=rule.risk_id,
        domain=domain,
    )


def _finding_from_synthetic(
    syn: SyntheticFinding,
    override: OverrideEntry | None,
    plum: PlumHoundLoader | None,
    pingcastle: PingCastleReport,
    config: ProjectConfig,
    audit_dt: datetime,
    domain: str = "",
) -> Finding | None:
    if not _synthetic_triggered(syn, plum, pingcastle):
        return None
    title = _apply_override(syn.title, override, "title")
    f_type = _apply_override(syn.type, override, "type")
    segment = _apply_override(syn.segment, override, "segment")
    recommendation = _apply_override(syn.recommendation, override, "recommendation")
    threshold = (override.appendix_threshold if override else None) or config.defaults.appendix_threshold

    appendix, details_text = _build_appendix(
        title, syn.plumhound, plum, threshold, fallback_text=_synthetic_fallback_text(syn, plum)
    )
    note_parts = []
    if domain:
        note_parts.append(f"[Домен: {domain}]")
    note_parts.append(f"PlumHound: {syn.triggers_on}")
    return Finding(
        title=title,
        type=f_type,
        segment=segment,
        details_text=details_text,
        recommendation=recommendation.rstrip(),
        note=" ".join(note_parts),
        audit_date=audit_dt,
        client=config.client.name,
        appendix=appendix,
        source_id=syn.id,
        domain=domain,
    )


def _synthetic_triggered(
    syn: SyntheticFinding, plum: PlumHoundLoader | None, pingcastle: PingCastleReport
) -> bool:
    trigger = syn.triggers_on
    if trigger.startswith("plumhound:"):
        if plum is None:
            return False
        table_name = trigger.split(":", 1)[1].strip()
        table = plum.load(table_name)
        return bool(table and table.rows)
    if trigger.startswith("metric:"):
        expr = trigger.split(":", 1)[1].strip()
        if "=" not in expr:
            return False
        key, expected = (s.strip() for s in expr.split("=", 1))
        actual = pingcastle.metrics.get(key, "")
        return actual.lower() == expected.lower()
    return False


def _synthetic_fallback_text(syn: SyntheticFinding, plum: PlumHoundLoader | None) -> str:
    if plum and syn.triggers_on.startswith("plumhound:"):
        table_name = syn.triggers_on.split(":", 1)[1].strip()
        t = plum.load(table_name)
        if t:
            return f"Источник: {t.name} ({t.source}), записей: {len(t.rows)}"
    return ""


_COUNT_RE = re.compile(r"\b(\d+)\b")


def _compact_rationale(rationale: str, count_label: str | None) -> str | None:
    """Replace verbose Rationale with "{N} — {count_label}" when both are present.

    Returns None when either no integer is extractable or no count_label is set —
    in either case the caller keeps the original Rationale text. This avoids
    misleading output for rules whose Rationale embeds a configuration value
    (e.g. ``MinimumPasswordLength=20``) rather than a count of affected objects.
    """
    if not rationale or not count_label:
        return None
    matches = _COUNT_RE.findall(rationale)
    if not matches:
        return None
    # PingCastle Rationale typically ends with "= N" or "N user(s)" — take the
    # last number to avoid catching e.g. CVE numbers.
    n = matches[-1]
    # Em-dash form avoids Russian case-agreement issues
    # ("33 серверов" vs "33 — серверы Windows Server 2012").
    return f"{n} — {count_label}"


def _resolve_details(
    *,
    title: str,
    risk_id: str,
    pingcastle_details: dict[str, PlumTable],
    plumhound_sources: list[PlumSource],
    plum: PlumHoundLoader | None,
    threshold: int,
    fallback_text: str,
) -> tuple[Appendix | None, str, str]:
    """Pick the best concrete-object source for one rule.

    Returns (appendix, details_text, used_source) where used_source is one of:
    ``"pingcastle_html"``, ``"plumhound"`` or ``"rationale"``.
    """
    # 1. PingCastle HTML — primary for PingCastle rules.
    table = pingcastle_details.get(risk_id)
    if table and table.rows:
        cols = table.columns
        rows = tuple(tuple(r.get(c, "") for c in cols) for r in table.rows)
        if len(rows) < threshold:
            lines = [", ".join(cols) + ":"]
            for r in rows:
                lines.append("  " + " | ".join(r))
            return None, "\n".join(lines), "pingcastle_html"
        return Appendix(title=title, columns=cols, rows=rows), "", "pingcastle_html"

    # 2. PlumHound — fallback.
    apx, text = _build_appendix(title, plumhound_sources, plum, threshold, fallback_text=fallback_text)
    if apx is not None:
        return apx, "", "plumhound"
    # Inline PlumHound text or empty fallback.
    if text and text != fallback_text:
        return None, text, "plumhound"

    # 3. Rationale-only.
    return None, fallback_text, "rationale"


def _build_appendix(
    title: str,
    sources: list[PlumSource],
    plum: PlumHoundLoader | None,
    threshold: int,
    fallback_text: str = "",
    ldap_hint: str | None = None,
) -> tuple[Appendix | None, str]:
    """Resolve PlumHound sources → either an Appendix or inline details text.

    Note: ``ldap_hint`` is intentionally NOT placed into column G here — it's
    routed into the recommendation (column H) by the caller. Column G stays
    short and either points at an appendix or shows the PingCastle rationale.
    """
    if plum is not None and sources:
        # First non-empty source wins.
        for src in sources:
            table = plum.load(src.file)
            if not table or not table.rows:
                continue
            cols = tuple(src.cols) if src.cols else table.columns
            rows = tuple(
                tuple(row.get(c, "") for c in cols) for row in table.rows
            )
            if len(rows) < threshold:
                # Inline as text — compact form, one row per line.
                lines = [f"{', '.join(cols)}:"]
                for r in rows:
                    lines.append("  " + " | ".join(r))
                return None, "\n".join(lines)
            return Appendix(title=title, columns=cols, rows=rows), ""

    return None, fallback_text
