"""Parse PingCastle HealthcheckData XML into RawRule + top-level metrics."""

from __future__ import annotations

from pathlib import Path

from lxml import etree

from ..model import PingCastleReport, RawRule

TOP_LEVEL_METRICS = (
    "EngineVersion",
    "GenerationDate",
    "Level",
    "MaturityLevel",
    "DomainFQDN",
    "NetBIOSName",
    "ForestFQDN",
    "DomainFunctionalLevel",
    "ForestFunctionalLevel",
    "NumberOfDC",
    "GlobalScore",
    "StaleObjectsScore",
    "PrivilegiedGroupScore",
    "TrustScore",
    "AnomalyScore",
    "IsRecycleBinEnabled",
    "ExchangeInstall",
    "ExchangeSchemaVersion",
    "LAPSInstalled",
    "NewLAPSInstalled",
    "SCCMInstalled",
    "KrbtgtLastChangeDate",
    "KrbtgtLastVersion",
    "GuestEnabled",
    "MachineAccountQuota",
    "AdminLastLoginDate",
    "AzureADSSOLastPwdChange",
    "AzureADSSOVersion",
    "AzureADSSOEncryptionType",
    "DomainCreation",
    "SchemaVersion",
)


def _int_or_zero(text: str | None) -> int:
    try:
        return int(text or 0)
    except (TypeError, ValueError):
        return 0


def parse_pingcastle(xml_path: Path | str) -> PingCastleReport:
    """Load PingCastle XML and return structured report."""
    tree = etree.parse(str(xml_path))
    root = tree.getroot()

    rules: list[RawRule] = []
    for r in root.findall(".//RiskRules/HealthcheckRiskRule"):
        risk_id = r.findtext("RiskId") or ""
        if not risk_id:
            continue
        rules.append(
            RawRule(
                risk_id=risk_id,
                category=r.findtext("Category") or "",
                model=r.findtext("Model") or "",
                points=_int_or_zero(r.findtext("Points")),
                rationale=(r.findtext("Rationale") or "").strip(),
            )
        )

    metrics: dict[str, str] = {}
    for name in TOP_LEVEL_METRICS:
        node = root.find(f"./{name}")
        if node is not None and node.text is not None:
            metrics[name] = node.text.strip()

    return PingCastleReport(
        domain=metrics.get("DomainFQDN", ""),
        generation_date=metrics.get("GenerationDate", ""),
        global_score=_int_or_zero(metrics.get("GlobalScore")),
        stale_objects_score=_int_or_zero(metrics.get("StaleObjectsScore")),
        privileged_group_score=_int_or_zero(metrics.get("PrivilegiedGroupScore")),
        trust_score=_int_or_zero(metrics.get("TrustScore")),
        anomaly_score=_int_or_zero(metrics.get("AnomalyScore")),
        rules=tuple(rules),
        metrics=metrics,
    )
