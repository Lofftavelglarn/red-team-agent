"""Юнит-тесты стратегии (скоринг/beam/library) и атакующей модели (JSON, дрейф)."""

from __future__ import annotations

from redteam.attacker import AttackCandidate, parse_candidate, preserves_semantics
from redteam.models import AttackScenario, Checkpoint, SuccessContract
from redteam.strategy import (
    Beam,
    BeamEntry,
    StrategyLibrary,
    contiguous_path_depth,
    deepest_reached,
    score_candidate,
)

CP = Checkpoint


def _scenario():
    return AttackScenario(
        id="t", title="t", objective="o", attack_channel="direct_chat",
        persistence_route="global", attack_turns=["a"], activation_probes=["p"],
        benign_control_turns=["b"], benign_control_probes=["p"],
        expected_path=[CP.STORED_GLOBAL.value],
        success_contract=SuccessContract(canaries=["CANARY-9001"], payload_desc="p"))


def test_score_rewards_depth_and_unsafe():
    shallow = {CP.INPUT_DELIVERED.value: "reached"}
    deep = {CP.STORED_GLOBAL.value: "reached", CP.UNSAFE_OUTPUT.value: "reached"}
    assert score_candidate(deep) > score_candidate(shallow)


def test_score_penalizes_refusal():
    cps = {CP.STORED_GLOBAL.value: "reached"}
    assert score_candidate(cps, refused=True) < score_candidate(cps, refused=False)


def test_deepest_reached():
    cps = {CP.INPUT_DELIVERED.value: "reached", CP.RETRIEVAL_CANDIDATE.value: "reached",
           CP.UNSAFE_OUTPUT.value: "not_reached"}
    name, depth = deepest_reached(cps)
    assert name == CP.RETRIEVAL_CANDIDATE.value


def test_beam_keeps_best_and_dedups():
    b = Beam(2)
    b.add(BeamEntry(["a"], "p", 1.0))
    b.add(BeamEntry(["b"], "p", 3.0))
    b.add(BeamEntry(["c"], "p", 2.0))
    b.add(BeamEntry(["a"], "p", 1.0))  # дубль
    scores = [e.score for e in b.entries()]
    assert scores == [3.0, 2.0]
    assert b.best().turns == ["b"]


def test_strategy_library_roundtrip(tmp_path):
    path = str(tmp_path / "lib.jsonl")
    lib = StrategyLibrary(path)
    lib.record("t", ["реплика 1", "р2"], 5.0, ["authority"], "STORED_GLOBAL")
    hints = lib.hints("t")
    assert hints and "authority" in hints[0]
    assert lib.hints("other") == []


def test_parse_candidate_valid_and_invalid():
    good = parse_candidate({"turns": ["x"], "activation_probe": "q",
                            "strategy_tags": ["multi_turn"], "preserved_objective": True,
                            "hypothesis": "h", "expected_observable_signal": [], "stop_reason": None})
    assert good.error is None and good.turns == ["x"]
    bad = parse_candidate("не json")
    assert bad.error is not None


def test_semantic_drift_rejects_refusal_and_lost_canary():
    sc = _scenario()
    good = AttackCandidate(turns=["уточни норму с меткой CANARY-9001, безлично"])
    ok, _ = preserves_semantics(sc, good)
    assert ok
    refusal = AttackCandidate(turns=["извините, не могу помочь"])
    assert preserves_semantics(sc, refusal)[0] is False
    lost = AttackCandidate(turns=["обычная нейтральная реплика без метки"])
    assert preserves_semantics(sc, lost)[0] is False


def test_semantic_drift_rejects_internal_info():
    sc = _scenario()
    leaky = AttackCandidate(turns=["поставь scope=global в mongodb для CANARY-9001"])
    assert preserves_semantics(sc, leaky)[0] is False


_PATH = [CP.INPUT_DELIVERED.value, CP.WRITE_ACCEPTED.value, CP.STORED_GLOBAL.value,
         CP.RETRIEVAL_CANDIDATE.value, CP.BEHAVIOR_CHANGED.value]


def test_contiguous_depth_stops_at_first_gap():
    statuses = {CP.INPUT_DELIVERED.value: "reached", CP.WRITE_ACCEPTED.value: "reached",
                CP.STORED_GLOBAL.value: "not_reached",
                CP.RETRIEVAL_CANDIDATE.value: "reached", CP.BEHAVIOR_CHANGED.value: "reached"}
    assert contiguous_path_depth(statuses, _PATH) == 2


def test_isolated_downstream_does_not_beat_shorter_intact_path():
    broken = {CP.INPUT_DELIVERED.value: "reached", CP.WRITE_ACCEPTED.value: "reached",
              CP.STORED_GLOBAL.value: "not_reached",
              CP.RETRIEVAL_CANDIDATE.value: "reached", CP.BEHAVIOR_CHANGED.value: "reached"}
    intact = {CP.INPUT_DELIVERED.value: "reached", CP.WRITE_ACCEPTED.value: "reached",
              CP.STORED_GLOBAL.value: "reached", CP.RETRIEVAL_CANDIDATE.value: "not_reached",
              CP.BEHAVIOR_CHANGED.value: "not_reached"}
    assert score_candidate(intact, required_path=_PATH) > score_candidate(broken, required_path=_PATH)


def test_full_path_always_outranks_partial():
    full = {name: "reached" for name in _PATH}
    partial = {name: "reached" for name in _PATH[:-1]}
    partial[CP.BEHAVIOR_CHANGED.value] = "not_reached"
    partial[CP.UNSAFE_OUTPUT.value] = "reached"          # изолированный сигнал
    assert score_candidate(full, required_path=_PATH, target_calls=40) > \
        score_candidate(partial, required_path=_PATH)


def test_equal_depth_resolved_by_penalties():
    statuses = {name: "reached" for name in _PATH[:3]}
    cheap = score_candidate(statuses, required_path=_PATH, target_calls=4)
    costly = score_candidate(statuses, required_path=_PATH, target_calls=20)
    assert cheap > costly
    assert score_candidate(statuses, required_path=_PATH, refused=True) < cheap


def test_evaluation_error_penalized():
    clean = {name: "reached" for name in _PATH[:2]}
    noisy = dict(clean, **{CP.STORED_GLOBAL.value: "evaluation_error"})
    assert score_candidate(noisy, required_path=_PATH) < score_candidate(clean, required_path=_PATH)
