"""Catalog of recommendations for PingCastle RiskIds and PlumHound-only findings."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class PlumSource(BaseModel):
    file: str
    """Logical PlumHound table name (without extension)."""

    cols: list[str] = Field(default_factory=list)
    """Columns to include in the appendix, in order. Empty = all columns."""


class RecommendationEntry(BaseModel):
    title: str
    """Human-readable description (column F — 'Описание')."""

    type: str = "Недостаток"
    """Severity classification (column E)."""

    segment: str = "Серверный"
    recommendation: str
    """Recommended remediation (column H — 'Предлагаемые мероприятия')."""

    plumhound: list[PlumSource] = Field(default_factory=list)
    """Source tables for the appendix. First non-empty table wins."""

    ldap_hint: str | None = None
    """Optional PowerShell/LDAP snippet inserted into details when no plumhound data."""

    count_label: str | None = None
    """Russian unit-of-measure for affected objects.

    Used when no concrete object list is available (PingCastle XML has only an
    aggregate count in Rationale). The pipeline extracts the integer from the
    Rationale and writes ``"{N} {count_label}"`` into column G — much shorter
    than the original English sentence.
    """


class SyntheticFinding(BaseModel):
    id: str
    title: str
    type: str = "Недостаток"
    segment: str = "Серверный"
    recommendation: str
    triggers_on: str
    """Either 'plumhound:<TableName>' (non-empty table) or 'metric:<MetricName>=<value>'."""

    plumhound: list[PlumSource] = Field(default_factory=list)


class Catalog(BaseModel):
    recommendations: dict[str, RecommendationEntry]
    synthetic_findings: list[SyntheticFinding] = Field(default_factory=list)

    @classmethod
    def load_default(cls) -> "Catalog":
        with resources.files("adreport.catalog").joinpath("recommendations.yaml").open(
            encoding="utf-8"
        ) as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)

    @classmethod
    def load_from(cls, path: Path | str) -> "Catalog":
        with Path(path).open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)


__all__ = ["Catalog", "RecommendationEntry", "PlumSource", "SyntheticFinding"]
