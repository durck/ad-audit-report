"""Domain types passed between parser → pipeline → renderer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class RawRule:
    """Single <HealthcheckRiskRule> from PingCastle XML."""

    risk_id: str
    category: str
    model: str
    points: int
    rationale: str


@dataclass(frozen=True)
class PingCastleReport:
    domain: str
    generation_date: str
    global_score: int
    stale_objects_score: int
    privileged_group_score: int
    trust_score: int
    anomaly_score: int
    rules: tuple[RawRule, ...]
    # Top-level metrics that are not rules but feed synthetic findings.
    metrics: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PlumTable:
    """One PlumHound table — typically loaded from .html (preferred) or .csv (fallback)."""

    name: str  # e.g. "AdminsWithout_ProtectedUsers"
    source: str  # "html" | "csv"
    columns: tuple[str, ...]
    rows: tuple[dict[str, str], ...]

    def __bool__(self) -> bool:
        return bool(self.rows)


@dataclass
class Appendix:
    title: str
    columns: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]

    @property
    def is_empty(self) -> bool:
        return not self.rows


@dataclass
class Finding:
    """A single row to write into 'Результаты' sheet."""

    title: str  # column F — Описание
    type: str  # column E — Тип (Недостаток / Возможно недостаток / Уязвимость)
    segment: str  # column D — Сегмент сети
    details_text: str  # column G — Подробности (used when no appendix)
    recommendation: str  # column H — Предлагаемые мероприятия
    note: str  # column I — Примечания (e.g. "PingCastle: P-ProtectedUsers")
    audit_date: datetime
    client: str
    appendix: Appendix | None = None
    source_id: str = ""  # RiskId or synthetic id, for diagnostics
    domain: str = ""  # AD domain FQDN when scanning multiple domains; empty for single-domain
