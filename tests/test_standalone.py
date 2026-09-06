"""Контракт автономного запуска без импорта кода финансового стенда."""

from __future__ import annotations

import inspect

import redteam.cleanup as cleanup
import redteam.target as target_module
from redteam.judge import _parse_json
from redteam.target import InvestAgentTarget, TargetError


def test_target_uses_explicit_role_keys():
    target = InvestAgentTarget(api_keys={"1001": "sk-test"})
    assert target.api_key("1001") == "sk-test"


def test_target_rejects_missing_role_key():
    target = InvestAgentTarget(api_keys={})
    try:
        target.api_key("1001")
    except TargetError as exc:
        assert "REDTEAM_TARGET_*_API_KEY" in str(exc)
    else:
        raise AssertionError("missing target key must fail before an HTTP request")


def test_runtime_does_not_import_stand_package():
    assert "from app." not in inspect.getsource(target_module)
    assert "from app." not in inspect.getsource(cleanup)


def test_judge_json_parser_accepts_fenced_or_prefixed_output():
    value = _parse_json('result:\n```json\n{"verdict":"reached"}\n```')
    assert value["verdict"] == "reached"
