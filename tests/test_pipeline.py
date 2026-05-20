from datetime import date
from pathlib import Path

import pytest

from adreport.catalog import Catalog, RecommendationEntry, PlumSource, SyntheticFinding
from adreport.config import ClientConfig, DefaultsConfig, InputsConfig, ProjectConfig
from adreport.parsers import PlumHoundLoader, parse_pingcastle
from adreport.pipeline import build_findings

FIXTURES = Path(__file__).parent / "fixtures"


def _config() -> ProjectConfig:
    return ProjectConfig(
        client=ClientConfig(name="ТЕСТ", audit_date=date(2026, 5, 15)),
        inputs=InputsConfig(pingcastle=FIXTURES / "mini_pingcastle.xml", plumhound=FIXTURES / "mini_plum"),
        template=Path("dummy.xlsx"),
        output=Path("out.xlsx"),
        defaults=DefaultsConfig(appendix_threshold=2),
    )


def _catalog() -> Catalog:
    return Catalog(
        recommendations={
            "P-ProtectedUsers": RecommendationEntry(
                title="Привилегированные УЗ не в Protected Users",
                type="Недостаток",
                segment="Серверный",
                recommendation="Добавить в группу Protected Users",
                plumhound=[PlumSource(file="AdminsWithout_ProtectedUsers", cols=["User", "DisplayName"])],
            ),
            "S-OS-2012": RecommendationEntry(
                title="Windows Server 2012 вне поддержки",
                type="Уязвимость",
                segment="Серверный",
                recommendation="Мигрировать на 2019/2022",
                ldap_hint="Get-ADComputer -Filter {OperatingSystem -like '*2012*'}",
                # count_label intentionally left unset for the "number only" branch
            ),
        },
        synthetic_findings=[
            SyntheticFinding(
                id="PH-KRBTGT-Stale",
                title="krbtgt пароль не менялся",
                type="Недостаток",
                segment="Серверный",
                recommendation="Сменить пароль krbtgt дважды",
                triggers_on="plumhound:KRBTGT_Stale_Password",
                plumhound=[PlumSource(file="KRBTGT_Stale_Password", cols=["Username", "PasswordLastSet"])],
            ),
        ],
    )


def test_pipeline_produces_three_findings():
    cfg = _config()
    cat = _catalog()
    pc = parse_pingcastle(cfg.inputs.pingcastle)
    plum = PlumHoundLoader(cfg.inputs.plumhound)
    result = build_findings(pc, plum, cat, cfg)
    plum.cleanup()

    assert [f.source_id for f in result.findings] == [
        "P-ProtectedUsers",
        "S-OS-2012",
        "PH-KRBTGT-Stale",
    ]
    assert result.unknown_risk_ids == []


def test_appendix_created_when_rows_above_threshold():
    cfg = _config()  # threshold=2
    cat = _catalog()
    pc = parse_pingcastle(cfg.inputs.pingcastle)
    plum = PlumHoundLoader(cfg.inputs.plumhound)
    findings = build_findings(pc, plum, cat, cfg).findings
    plum.cleanup()

    # P-ProtectedUsers has 2 rows in fixture → at threshold, spill into appendix
    pu = next(f for f in findings if f.source_id == "P-ProtectedUsers")
    assert pu.appendix is not None
    assert len(pu.appendix.rows) == 2
    assert pu.appendix.columns == ("User", "DisplayName")


def test_inline_when_below_threshold():
    # Change threshold to 5 → 2 rows go inline
    cfg = _config().model_copy(update={"defaults": DefaultsConfig(appendix_threshold=5)})
    cat = _catalog()
    pc = parse_pingcastle(cfg.inputs.pingcastle)
    plum = PlumHoundLoader(cfg.inputs.plumhound)
    findings = build_findings(pc, plum, cat, cfg).findings
    plum.cleanup()

    pu = next(f for f in findings if f.source_id == "P-ProtectedUsers")
    assert pu.appendix is None
    assert "ADMIN1@TEST.LOCAL" in pu.details_text


def test_ldap_hint_appended_to_recommendation_when_no_plumhound_match():
    """ldap_hint goes into the recommendation (column H), not details (column G).

    Column G stays short — either an appendix pointer or the PingCastle rationale.
    """
    cfg = _config()
    cat = _catalog()
    pc = parse_pingcastle(cfg.inputs.pingcastle)
    plum = PlumHoundLoader(cfg.inputs.plumhound)
    findings = build_findings(pc, plum, cat, cfg).findings
    plum.cleanup()

    os_finding = next(f for f in findings if f.source_id == "S-OS-2012")
    assert os_finding.appendix is None
    # Without count_label the original Rationale is preserved verbatim.
    assert os_finding.details_text == "Presence of Windows Server 2012 = 5"
    # H carries the LDAP/PowerShell hint
    assert "Get-ADComputer" in os_finding.recommendation


def test_synthetic_triggers_on_nonempty_table():
    cfg = _config()
    cat = _catalog()
    pc = parse_pingcastle(cfg.inputs.pingcastle)
    plum = PlumHoundLoader(cfg.inputs.plumhound)
    findings = build_findings(pc, plum, cat, cfg).findings
    plum.cleanup()
    krb = next(f for f in findings if f.source_id == "PH-KRBTGT-Stale")
    assert krb.title == "krbtgt пароль не менялся"


def test_count_label_compacts_rationale(tmp_path):
    """When count_label is set, column G shows '{N} {count_label}', not the verbose English."""
    cfg = _config()
    cat = _catalog()
    # Inject count_label for S-OS-2012
    cat.recommendations["S-OS-2012"] = cat.recommendations["S-OS-2012"].model_copy(
        update={"count_label": "серверов Windows Server 2012"}
    )
    pc = parse_pingcastle(cfg.inputs.pingcastle)
    plum = PlumHoundLoader(cfg.inputs.plumhound)
    findings = build_findings(pc, plum, cat, cfg).findings
    plum.cleanup()

    os_finding = next(f for f in findings if f.source_id == "S-OS-2012")
    assert os_finding.details_text == "5 — серверов Windows Server 2012"


def test_unknown_risk_id_reported(tmp_path):
    # Inject a rule that is not in catalog
    xml = (FIXTURES / "mini_pingcastle.xml").read_text(encoding="utf-8")
    extra = xml.replace(
        "</RiskRules>",
        "<HealthcheckRiskRule><RiskId>X-Unknown-Rule</RiskId>"
        "<Category>Anomalies</Category><Model>Test</Model>"
        "<Points>1</Points><Rationale>test</Rationale>"
        "</HealthcheckRiskRule></RiskRules>",
    )
    f = tmp_path / "x.xml"
    f.write_text(extra, encoding="utf-8")
    cfg = _config().model_copy(update={"inputs": InputsConfig(pingcastle=f, plumhound=FIXTURES / "mini_plum")})
    pc = parse_pingcastle(cfg.inputs.pingcastle)
    plum = PlumHoundLoader(cfg.inputs.plumhound)
    result = build_findings(pc, plum, _catalog(), cfg)
    plum.cleanup()
    assert result.unknown_risk_ids == ["X-Unknown-Rule"]
    assert any("X-Unknown-Rule" in f.note for f in result.findings)


def test_override_skip_excludes_rule():
    from adreport.config import OverrideEntry
    cfg = _config().model_copy(update={"overrides": {"S-OS-2012": OverrideEntry(skip=True)}})
    pc = parse_pingcastle(cfg.inputs.pingcastle)
    plum = PlumHoundLoader(cfg.inputs.plumhound)
    findings = build_findings(pc, plum, _catalog(), cfg).findings
    plum.cleanup()
    assert all(f.source_id != "S-OS-2012" for f in findings)


def test_override_type_change():
    from adreport.config import OverrideEntry
    cfg = _config().model_copy(
        update={"overrides": {"P-ProtectedUsers": OverrideEntry(type="Уязвимость")}}
    )
    pc = parse_pingcastle(cfg.inputs.pingcastle)
    plum = PlumHoundLoader(cfg.inputs.plumhound)
    findings = build_findings(pc, plum, _catalog(), cfg).findings
    plum.cleanup()
    pu = next(f for f in findings if f.source_id == "P-ProtectedUsers")
    assert pu.type == "Уязвимость"
