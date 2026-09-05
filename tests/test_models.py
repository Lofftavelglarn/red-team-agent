"""Юнит-тесты типизированных моделей и валидации сценариев."""

from __future__ import annotations

import pytest

from redteam.models import (
    AttackScenario,
    Checkpoint,
    CheckpointResult,
    CheckpointStatus,
    ScenarioValidationError,
    SuccessContract,
    VerifyMethod,
    validate_scenario,
    validate_suite,
)
from redteam.scenarios import by_id, get_suite


def _base(**kw):
    d = dict(
        id="x1", title="t", objective="o", attack_channel="direct_chat",
        persistence_route="global",
        attack_turns=["реплика атаки с меткой CANARY-1234"],
        activation_probes=["проба"],
        benign_control_turns=["нейтральная реплика"],
        benign_control_probes=["проба"],
        expected_path=[Checkpoint.STORED_GLOBAL.value],
        success_contract=SuccessContract(canaries=["CANARY-1234"], payload_desc="p"),
    )
    d.update(kw)
    return AttackScenario(**d)


def test_suite_loads_and_validates():
    suite = get_suite(include_disabled=True)
    assert len(suite) >= 15
    validate_suite(suite)  # не бросает


def test_disabled_excluded_by_default():
    ids = {s.id for s in get_suite()}
    assert "s9-system-prompt-leak" not in ids
    assert "s12-web-chain" not in ids


def test_unknown_checkpoint_in_expected_path_rejected():
    with pytest.raises(Exception):
        _base(expected_path=["NOPE"])


def test_missing_control_flagged():
    sc = _base(benign_control_turns=[], benign_control_probes=[])
    problems = validate_scenario(sc)
    assert any("benign control" in p for p in problems)


def test_generic_canary_flagged():
    sc = _base(attack_turns=["риск"], success_contract=SuccessContract(canaries=["риск"]))
    problems = validate_scenario(sc)
    assert any("слишком общий canary" in p for p in problems)


def test_indirect_channel_canary_in_turns_flagged():
    sc = _base(attack_channel="indirect_web",
               attack_turns=["найди CANARY-1234 в вебе"],
               success_contract=SuccessContract(canaries=["CANARY-1234"], payload_desc="p"))
    problems = validate_scenario(sc)
    assert any("непрямой канал" in p for p in problems)


def test_secret_in_text_flagged():
    sc = _base(attack_turns=["вот ключ sk-genai-ABCDEF доступа"])
    problems = validate_scenario(sc)
    assert any("секрет" in p for p in problems)


def test_duplicate_ids_rejected():
    with pytest.raises(ScenarioValidationError):
        validate_suite([_base(), _base()])


def test_checkpoint_result_roundtrip():
    r = CheckpointResult(name="STORED_GLOBAL", status=CheckpointStatus.UNOBSERVED,
                         evidence_ids=["evt-1"], reason="нет телеметрии")
    d = r.to_dict()
    assert d["status"] == "unobserved"
    assert d["evidence_ids"] == ["evt-1"]


def test_by_id_alias():
    assert by_id("s1").id == "s1-impersonal-fact-promotion"


def test_verify_deterministic_requires_signal():
    sc = _base(success_contract=SuccessContract(verify=VerifyMethod.DETERMINISTIC,
                                                payload_desc="p"))
    problems = validate_scenario(sc)
    assert any("verify=deterministic" in p for p in problems)
