"""Project YAML config — what to build for a specific engagement."""

from __future__ import annotations

from datetime import date, datetime
from importlib import resources
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator


def default_template_path() -> Path:
    """Path to the bundled, pre-sanitised xlsx template."""
    with resources.as_file(resources.files("adreport.templates").joinpath("default.xlsx")) as p:
        return Path(p)


class ClientConfig(BaseModel):
    name: str
    audit_date: date


class InputsConfig(BaseModel):
    """Single-domain inputs (legacy / simplest case)."""

    pingcastle: Path
    pingcastle_html: Path | None = None
    """Detailed PingCastle HTML report — preferred source for per-rule object lists.

    If unset and a `.html` sibling of the XML exists (e.g. ``ad_hc.xml`` →
    ``ad_hc.html``), it is auto-detected in the CLI. PingCastle XML contains
    only aggregates; HTML contains the actual affected DCs, GPOs, users, etc.
    """

    plumhound: Path | None = None  # directory or .zip; absent → no appendix details

    @field_validator("pingcastle", "pingcastle_html", "plumhound")
    @classmethod
    def _expand(cls, v: Path | None) -> Path | None:
        if v is None:
            return None
        return Path(v).expanduser()


class DomainInput(BaseModel):
    """One AD domain's set of input files when scanning multiple domains."""

    name: str  # FQDN, e.g. "corp.example.com"
    pingcastle: Path
    pingcastle_html: Path | None = None
    plumhound: Path | None = None

    @field_validator("pingcastle", "pingcastle_html", "plumhound")
    @classmethod
    def _expand(cls, v: Path | None) -> Path | None:
        if v is None:
            return None
        return Path(v).expanduser()


class DefaultsConfig(BaseModel):
    segment: str = "Серверный"
    type: str = "Недостаток"
    appendix_threshold: int = 2
    """Minimum number of affected objects to spill into a separate Прил.N sheet.

    Lists below this size are inlined into the 'Подробности' column. Default
    is 2 — even small lists go into a separate sheet to keep column G readable.
    Set to a very large number (e.g. 1000) to disable appendix creation entirely.
    """

    clear_example_rows: bool = True
    """Wipe placeholder rows from the template before appending findings.

    The corporate template ships with a few example rows (admin:admin, SSH
    access, etc.) to show the format. They are not real findings and must not
    appear in the generated report. With this flag on (default), all populated
    rows from min_row down to the first fully-empty row are cleared, then new
    findings start from min_row.
    """


class OverrideEntry(BaseModel):
    type: str | None = None
    segment: str | None = None
    title: str | None = None
    recommendation: str | None = None
    appendix_threshold: int | None = None
    skip: bool = False


class ProjectConfig(BaseModel):
    client: ClientConfig
    inputs: InputsConfig | None = None
    """Single-domain inputs. Use either `inputs:` or `domains:`, not both."""

    domains: list[DomainInput] | None = None
    """Multi-domain inputs. All findings from every domain end up in the same
    report sheet — each row is tagged with its domain in column C and in the
    'Примечания' column for downstream grouping/filtering.
    """

    template: Path | None = None
    """Path to an xlsx template. If omitted, the bundled clean template is used.

    The bundled template ships with the package and is pre-sanitised — no
    auditor metadata, no absPath, neutral title in A3. Provide your own path
    only if you have a corporate-specific format.
    """

    output: Path
    defaults: DefaultsConfig = Field(default_factory=DefaultsConfig)
    overrides: dict[str, OverrideEntry] = Field(default_factory=dict)

    @field_validator("template", "output")
    @classmethod
    def _expand(cls, v: Path | None) -> Path | None:
        if v is None:
            return None
        return Path(v).expanduser()

    def resolved_template(self) -> Path:
        """Return the actual template path — user-provided or bundled default."""
        return self.template if self.template is not None else default_template_path()

    def iter_domain_inputs(self) -> list[DomainInput]:
        """Normalise either `inputs:` or `domains:` into a list of DomainInput.

        Single-domain configs become a one-element list with name='' so the rest
        of the pipeline can treat both shapes uniformly.
        """
        if self.domains and self.inputs:
            raise ValueError("project.yaml: укажите либо `inputs:` (один домен), либо `domains:` (несколько), но не оба сразу")
        if self.domains:
            return list(self.domains)
        if self.inputs:
            return [
                DomainInput(
                    name="",  # single-domain: no domain tag in cell C
                    pingcastle=self.inputs.pingcastle,
                    pingcastle_html=self.inputs.pingcastle_html,
                    plumhound=self.inputs.plumhound,
                )
            ]
        raise ValueError("project.yaml: ни `inputs:`, ни `domains:` не указаны")

    @property
    def audit_datetime(self) -> datetime:
        return datetime.combine(self.client.audit_date, datetime.min.time())

    @classmethod
    def load(cls, path: Path | str) -> "ProjectConfig":
        with Path(path).open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)


DEFAULT_PROJECT_YAML = """\
# adreport — project config
# All paths are relative to this file's directory.

client:
  name: "ПАО Заказчик"
  audit_date: 2026-05-15

# --- Single-domain ---
inputs:
  pingcastle: ./pingcastle.xml
  plumhound: ./plumhound/   # directory or .zip; remove if not available

# --- OR multi-domain (comment out `inputs:` above and uncomment below) ---
# domains:
#   - name: corp.example.com
#     pingcastle: ./pc/ad_hc_corp.example.com.xml      # .html sibling auto-detected
#     plumhound: ./plum/corp.example.com/
#   - name: fleet.ru
#     pingcastle: ./pc/ad_hc_fleet.ru.xml
#     plumhound: ./plum/fleet.ru/

# template: ./custom-template.xlsx   # optional — bundled clean template used by default
output: ./report.xlsx

defaults:
  segment: Серверный        # default value for column D (Сегмент сети)
  type: Недостаток          # default value for column E (Тип)
  appendix_threshold: 2     # ≥N affected objects → spill into separate sheet
  clear_example_rows: true  # wipe placeholder rows from the template before writing

# Override fields per RiskId. 'skip: true' excludes the rule from the report.
overrides:
  # S-OS-2012:
  #   type: Уязвимость
  # P-ProtectedUsers:
  #   appendix_threshold: 3
"""
