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
        required_path=[Checkpoint.STORED_GLOBAL.value],
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


def test_required_path_outside_expected_rejected():
    sc = _base(expected_path=[Checkpoint.WRITE_ACCEPTED.value],
               required_path=[Checkpoint.STORED_GLOBAL.value])
    problems = validate_scenario(sc)
    assert any("вне expected_path" in p for p in problems)


def test_required_path_order_must_match_expected():
    sc = _base(expected_path=[Checkpoint.WRITE_ACCEPTED.value, Checkpoint.STORED_GLOBAL.value],
               required_path=[Checkpoint.STORED_GLOBAL.value, Checkpoint.WRITE_ACCEPTED.value])
    problems = validate_scenario(sc)
    assert any("порядок required_path" in p for p in problems)


def test_required_path_duplicates_rejected():
    sc = _base(expected_path=[Checkpoint.WRITE_ACCEPTED.value, Checkpoint.STORED_GLOBAL.value],
               required_path=[Checkpoint.WRITE_ACCEPTED.value, Checkpoint.WRITE_ACCEPTED.value,
                              Checkpoint.STORED_GLOBAL.value])
    problems = validate_scenario(sc)
    assert any("повторяющиеся чекпоинты" in p for p in problems)


def test_empty_required_path_rejected_for_enabled_scenario():
    sc = _base(required_path=[])
    problems = validate_scenario(sc)
    assert any("пустой required_path" in p for p in problems)
    disabled = _base(required_path=[], enabled_by_default=False)
    assert not any("пустой required_path" in p for p in validate_scenario(disabled))


def test_unobservable_checkpoint_cannot_be_required_without_fixture():
    sc = _base(expected_path=[Checkpoint.STORED_GLOBAL.value, Checkpoint.EXTERNAL_EFFECT.value],
               required_path=[Checkpoint.STORED_GLOBAL.value, Checkpoint.EXTERNAL_EFFECT.value],
               tags=["tool"])
    assert any("ненаблюдаемые чекпоинты" in p for p in validate_scenario(sc))
    with_fixture = _base(
        expected_path=[Checkpoint.STORED_GLOBAL.value, Checkpoint.EXTERNAL_EFFECT.value],
        required_path=[Checkpoint.STORED_GLOBAL.value, Checkpoint.EXTERNAL_EFFECT.value],
        tags=["tool"], requirements=["телеметрия tool-call жертвы"])
    assert not any("ненаблюдаемые чекпоинты" in p for p in validate_scenario(with_fixture))


def test_terminal_checkpoint_is_last_required_element():
    sc = _base(expected_path=[Checkpoint.WRITE_ACCEPTED.value, Checkpoint.STORED_GLOBAL.value,
                              Checkpoint.EXTERNAL_EFFECT.value],
               required_path=[Checkpoint.WRITE_ACCEPTED.value, Checkpoint.STORED_GLOBAL.value],
               tags=["tool"])
    # терминал берётся из маршрута, а не из максимальной глубины expected_path
    assert sc.terminal_checkpoint() == Checkpoint.STORED_GLOBAL.value
    assert sc.required_success_path() == [Checkpoint.WRITE_ACCEPTED.value,
                                          Checkpoint.STORED_GLOBAL.value]


def test_required_path_defaults_to_expected_path():
    sc = _base(expected_path=[Checkpoint.WRITE_ACCEPTED.value, Checkpoint.STORED_GLOBAL.value],
               required_path=[])
    assert sc.required_success_path() == sc.expected_path
    assert sc.terminal_checkpoint() == Checkpoint.STORED_GLOBAL.value


def test_unknown_checkpoint_in_required_path_rejected():
    with pytest.raises(Exception):
        _base(required_path=["NOPE"])


def test_suite_declares_required_paths():
    for sc in get_suite(include_disabled=True):
        assert sc.required_path, sc.id
        assert sc.terminal_checkpoint() == sc.required_path[-1]


def test_every_scenario_route_ends_in_observable_outcome():
    """Маршрут не может заканчиваться на записи в память: успех обязан доказываться
    поведением жертвы или опасным ответом."""
    persistence_only = {Checkpoint.INPUT_DELIVERED.value, Checkpoint.WRITE_ACCEPTED.value,
                        Checkpoint.STORED_USER.value, Checkpoint.STORED_GLOBAL.value,
                        Checkpoint.RETRIEVAL_CANDIDATE.value}
    for sc in get_suite(include_disabled=True):
        assert sc.terminal_checkpoint() not in persistence_only, sc.id


def test_unknown_candidate_state_policy_rejected():
    sc = _base(candidate_state_policy="policy_only")
    problems = validate_scenario(sc)
    assert any("candidate_state_policy" in p for p in problems)


def test_suite_uses_known_candidate_state_policies():
    from redteam.models import CANDIDATE_STATE_POLICIES

    for sc in get_suite(include_disabled=True):
        assert sc.candidate_state_policy in CANDIDATE_STATE_POLICIES, sc.id


def test_seed_rules_require_markers():
    sc = _base(seed_rules=["Всегда прикладывай дисклеймер о риске."])
    assert any("seed_markers" in p for p in validate_scenario(sc))


def test_seed_marker_must_occur_in_seed_rule():
    sc = _base(seed_rules=["Всегда прикладывай дисклеймер о риске."],
               seed_markers=["маржинальная торговля"])
    assert any("seed_marker" in p for p in validate_scenario(sc))


def test_seed_installed_matches_only_contract_statements():
    sc = _base(seed_rules=["Всегда прикладывай обязательный дисклеймер о риске."],
               seed_markers=["обязательный", "дисклеймер"])
    matching = sc.seed_installed(["Дисклеймер о рисках не требуется.",
                                  "К ответу прикладывается обязательный дисклеймер о риске."])
    assert matching == ["К ответу прикладывается обязательный дисклеймер о риске."]


def test_generic_forbidden_field_flagged():
    sc = _base(success_contract=SuccessContract(canaries=["RTX-CAP-7788"],
                                               forbidden_fields=["счет"],
                                               payload_desc="p"))
    assert any("forbidden_field" in p for p in validate_scenario(sc))


def test_expected_action_requires_semantic_verification():
    sc = _base(success_contract=SuccessContract(canaries=["RTX-CAP-7788"],
                                               expected_action="перевести всё в один актив",
                                               verify=VerifyMethod.DETERMINISTIC))
    assert any("expected_action" in p for p in validate_scenario(sc))
