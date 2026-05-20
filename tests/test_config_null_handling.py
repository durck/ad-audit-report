"""Regression: YAML keys present with no body (`overrides:`, `defaults:`)
parse as None — must not crash ProjectConfig validation."""

from pathlib import Path

from adreport.config import DEFAULT_PROJECT_YAML, DefaultsConfig, ProjectConfig

FIXTURES = Path(__file__).parent / "fixtures"


def _base_yaml() -> str:
    pc = (FIXTURES / "mini_pingcastle.xml").as_posix()
    return f"""\
client:
  name: 'ACME'
  audit_date: 2026-05-15
inputs:
  pingcastle: {pc}
output: ./out.xlsx
"""


def test_overrides_null_body_becomes_empty_dict(tmp_path):
    """The init-config template ships with `overrides:` and only commented
    examples — when the user doesn't uncomment any, YAML emits None for the
    key. We must accept it as an empty dict, not crash."""
    yaml_text = _base_yaml() + "overrides:\n  # commented out only\n"
    p = tmp_path / "project.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    cfg = ProjectConfig.load(p)
    assert cfg.overrides == {}


def test_overrides_absent_is_also_empty_dict(tmp_path):
    """Sanity: when the key is missing entirely, default_factory still works."""
    p = tmp_path / "project.yaml"
    p.write_text(_base_yaml(), encoding="utf-8")
    cfg = ProjectConfig.load(p)
    assert cfg.overrides == {}


def test_defaults_null_body_falls_back_to_factory(tmp_path):
    """Same null-body trap applies to `defaults:` — fallback to DefaultsConfig()."""
    yaml_text = _base_yaml() + "defaults:\n"
    p = tmp_path / "project.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    cfg = ProjectConfig.load(p)
    assert isinstance(cfg.defaults, DefaultsConfig)
    assert cfg.defaults.appendix_threshold == DefaultsConfig().appendix_threshold


def test_overrides_with_real_entry_still_parses(tmp_path):
    """Don't regress the normal case — a populated overrides dict still works."""
    yaml_text = _base_yaml() + """\
overrides:
  S-OS-2012:
    type: Уязвимость
"""
    p = tmp_path / "project.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    cfg = ProjectConfig.load(p)
    assert "S-OS-2012" in cfg.overrides
    assert cfg.overrides["S-OS-2012"].type == "Уязвимость"


def test_default_init_config_template_parses(tmp_path):
    """The template emitted by `adreport init-config` must validate as-is
    (all examples commented). This was the exact user-reported regression."""
    # Substitute the placeholder pingcastle path with our real fixture so
    # validation doesn't fail on a different field.
    text = DEFAULT_PROJECT_YAML.replace(
        "./pingcastle.xml", (FIXTURES / "mini_pingcastle.xml").as_posix()
    )
    p = tmp_path / "project.yaml"
    p.write_text(text, encoding="utf-8")
    cfg = ProjectConfig.load(p)
    assert cfg.overrides == {}
