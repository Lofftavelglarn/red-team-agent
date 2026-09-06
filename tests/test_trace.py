"""Юнит-тесты trace schema v2: сериализация, hashing, редакция, сохранение при исключении."""

from __future__ import annotations

import json
import os

from redteam.models import CheckpointResult, CheckpointStatus, RunStatus
from redteam.trace import SCHEMA_VERSION, TraceWriter, content_hash, redact


def _manifest():
    return {"config": {}, "scenario_id": "x", "run_id": "r"}


def test_content_hash_stable():
    assert content_hash("abc") == content_hash("abc")
    assert content_hash("abc") != content_hash("abd")


def test_redaction_hides_key_and_long_id():
    out = redact("ключ sk-genai-ABC123 счёт 10678901")
    assert "sk-genai-ABC123" not in out
    assert "10678901" not in out


def test_trace_serialized(tmp_path):
    d = str(tmp_path)
    with TraceWriter(d, "x", "r", _manifest()) as tw:
        eid = tw.event("target_response", "victim", "привет")
        tw.set_checkpoint(CheckpointResult("STORED_GLOBAL", CheckpointStatus.REACHED, [eid]))
        tw.run_status = RunStatus.COMPLETED
    trace = json.load(open(os.path.join(d, "trace.json"), encoding="utf-8"))
    assert trace["schema_version"] == SCHEMA_VERSION
    assert trace["run_status"] == "completed"
    assert trace["checkpoints"]["STORED_GLOBAL"]["evidence_ids"] == [eid]
    # events.jsonl append-only, монотонная sequence
    lines = open(os.path.join(d, "events.jsonl"), encoding="utf-8").read().strip().splitlines()
    seqs = [json.loads(l)["sequence"] for l in lines]
    assert seqs == sorted(seqs)


def test_trace_saved_on_exception(tmp_path):
    d = str(tmp_path)
    try:
        with TraceWriter(d, "x", "r", _manifest()) as tw:
            tw.event("target_request", "attacker", "payload")
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    # трасса и manifest сохранены, статус — инфраструктурная ошибка
    trace = json.load(open(os.path.join(d, "trace.json"), encoding="utf-8"))
    assert trace["run_status"] == "infra_error"
    manifest = json.load(open(os.path.join(d, "manifest.json"), encoding="utf-8"))
    assert manifest["run_status"] == "infra_error"


def test_large_payload_offloaded_to_artifact(tmp_path):
    d = str(tmp_path)
    big = "x" * 5000
    with TraceWriter(d, "x", "r", _manifest(), artifact_threshold=100) as tw:
        eid = tw.event("target_response", "victim", big)
        tw.run_status = RunStatus.COMPLETED
    assert os.path.exists(os.path.join(d, "artifacts", f"{eid}.txt"))
    raw = open(os.path.join(d, "artifacts", f"{eid}.txt"), encoding="utf-8").read()
    assert raw == big


def test_evaluation_error_serialized_with_error_field(tmp_path):
    d = str(tmp_path)
    with TraceWriter(d, "x", "r", _manifest()) as tw:
        tw.set_checkpoint(CheckpointResult(
            "BEHAVIOR_CHANGED", CheckpointStatus.EVALUATION_ERROR,
            reason="judge exception", evaluator="judge",
            error="RuntimeError('judge down')", matched=["фрагмент"]))
        tw.run_status = RunStatus.COMPLETED
    trace = json.load(open(os.path.join(d, "trace.json"), encoding="utf-8"))
    cp = trace["checkpoints"]["BEHAVIOR_CHANGED"]
    assert cp["status"] == "evaluation_error"
    assert cp["error"] == "RuntimeError('judge down')"
    assert cp["matched"] == ["фрагмент"]
    # результат прогона несёт ту же ошибку
    result = json.load(open(os.path.join(d, "result.json"), encoding="utf-8"))
    assert result["checkpoints"]["BEHAVIOR_CHANGED"]["error"] == "RuntimeError('judge down')"
    # и она присутствует в событии чекпоинта
    events = [json.loads(l) for l in
              open(os.path.join(d, "events.jsonl"), encoding="utf-8").read().strip().splitlines()]
    checkpoint_events = [e for e in events if e["kind"] == "checkpoint"]
    assert checkpoint_events[0]["labels"]["error"] == "RuntimeError('judge down')"
    assert checkpoint_events[0]["labels"]["evaluator"] == "judge"


def test_checkpoint_error_is_redacted(tmp_path):
    d = str(tmp_path)
    with TraceWriter(d, "x", "r", _manifest()) as tw:
        tw.set_checkpoint(CheckpointResult(
            "STORED_GLOBAL", CheckpointStatus.EVALUATION_ERROR,
            reason="judge exception", evaluator="judge",
            error="HTTPError(headers={'Authorization': Bearer sk-genai-SECRET123})"))
        tw.run_status = RunStatus.COMPLETED
    trace = json.load(open(os.path.join(d, "trace.json"), encoding="utf-8"))
    events = [json.loads(l) for l in
              open(os.path.join(d, "events.jsonl"), encoding="utf-8").read().strip().splitlines()]
    label_error = [e for e in events if e["kind"] == "checkpoint"][0]["labels"]["error"]
    assert "sk-genai-SECRET123" not in label_error
    # локальный result.json остаётся полным для отладки
    assert trace["checkpoints"]["STORED_GLOBAL"]["error"].startswith("HTTPError")
