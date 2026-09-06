"""Юнит-тесты trace schema v2: сериализация, hashing, редакция, сохранение при исключении."""

from __future__ import annotations

import json
import os

from redteam.models import CheckpointResult, CheckpointStatus, RunStatus
from redteam.trace import SCHEMA_VERSION, TraceWriter, content_hash, redact, validate_run


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
    assert os.path.exists(os.path.join(d, "artifacts", "raw", f"{eid}.txt"))
    raw = open(os.path.join(d, "artifacts", "raw", f"{eid}.txt"), encoding="utf-8").read()
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


def _run_dir_with_trace(tmp_path):
    manifest = {"scenario_id": "s1"}
    with TraceWriter(str(tmp_path), "s1", "r1", manifest) as tw:
        a = tw.event("target_request", "attacker", "первая реплика", session_id="sess")
        tw.event("target_response", "attacker", "ответ", session_id="sess",
                 parent_event_ids=[a])
        tw.set_checkpoint(CheckpointResult(name="INPUT_DELIVERED",
                                           status=CheckpointStatus.REACHED,
                                           evidence_ids=[a]))
        tw.run_status = RunStatus.COMPLETED
    return str(tmp_path)


def test_events_are_hash_chained(tmp_path):
    run_dir = _run_dir_with_trace(tmp_path)
    rows = [json.loads(line) for line in
            open(os.path.join(run_dir, "events.jsonl"), encoding="utf-8") if line.strip()]
    assert rows[0]["previous_event_hash"] == ""
    for prev, cur in zip(rows, rows[1:]):
        assert cur["previous_event_hash"] == prev["event_hash"]
    manifest = json.load(open(os.path.join(run_dir, "manifest.json"), encoding="utf-8"))
    assert manifest["event_count"] == len(rows)
    assert manifest["last_event_hash"] == rows[-1]["event_hash"]
    assert manifest["events_sha256"].startswith("sha256:")


def test_validate_accepts_intact_trace(tmp_path):
    report = validate_run(_run_dir_with_trace(tmp_path))
    assert report["ok"], report["problems"]
    assert report["checked"]["hash_chain"] is True


def test_validate_detects_deleted_event(tmp_path):
    run_dir = _run_dir_with_trace(tmp_path)
    path = os.path.join(run_dir, "events.jsonl")
    rows = [line for line in open(path, encoding="utf-8") if line.strip()]
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(rows[:1] + rows[2:])      # вырезали второе событие
    report = validate_run(run_dir)
    assert not report["ok"]
    assert any("цепочки" in p or "sequence" in p for p in report["problems"])


def test_validate_detects_edited_event(tmp_path):
    run_dir = _run_dir_with_trace(tmp_path)
    path = os.path.join(run_dir, "events.jsonl")
    rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    rows[0]["excerpt"] = "подменённый текст"
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    report = validate_run(run_dir)
    assert not report["ok"]
    assert any("event_hash" in p for p in report["problems"])


def test_validate_detects_missing_artifact(tmp_path):
    run_dir = str(tmp_path)
    with TraceWriter(run_dir, "s1", "r2", {}, artifact_threshold=10) as tw:
        tw.event("note", "harness", "очень длинный текст события для выноса в артефакт")
        tw.run_status = RunStatus.COMPLETED
    raw_dir = os.path.join(run_dir, "artifacts", "raw")
    os.remove(os.path.join(raw_dir, os.listdir(raw_dir)[0]))
    report = validate_run(run_dir)
    assert not report["ok"]
    assert any("артефакт" in p for p in report["problems"])


def test_validate_detects_checkpoint_pointing_nowhere(tmp_path):
    run_dir = _run_dir_with_trace(tmp_path)
    path = os.path.join(run_dir, "result.json")
    result = json.load(open(path, encoding="utf-8"))
    result["checkpoints"]["INPUT_DELIVERED"]["evidence_ids"] = ["evt-does-not-exist"]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False)
    report = validate_run(run_dir)
    assert not report["ok"]
    assert any("несуществующие события" in p for p in report["problems"])


def test_redacted_short_text_still_has_raw_artifact(tmp_path):
    """Обещание «полный текст доступен в raw» обязано выполняться и для коротких строк."""
    d = str(tmp_path)
    with TraceWriter(d, "x", "r", _manifest()) as tw:
        eid = tw.event("target_response", "victim", "счёт клиента 10678901 закрыт")
        tw.run_status = RunStatus.COMPLETED
    events = [json.loads(l) for l in
              open(os.path.join(d, "events.jsonl"), encoding="utf-8").read().strip().splitlines()]
    assert "<redacted-id>" in events[0]["excerpt"]          # выжимка редактирована
    raw = open(os.path.join(d, "artifacts", "raw", f"{eid}.txt"), encoding="utf-8").read()
    assert "10678901" in raw                               # полный текст сохранён


def test_credentials_never_reach_raw_artifacts(tmp_path):
    d = str(tmp_path)
    with TraceWriter(d, "x", "r", _manifest()) as tw:
        eid = tw.event("infra_error", "harness",
                       "HTTPError(headers={'Authorization': 'Bearer sk-genai-SECRET123'})")
        tw.run_status = RunStatus.COMPLETED
    raw = open(os.path.join(d, "artifacts", "raw", f"{eid}.txt"), encoding="utf-8").read()
    assert "SECRET123" not in raw and "<redacted>" in raw


def test_disabled_raw_storage_writes_no_artifacts(tmp_path):
    d = str(tmp_path)
    with TraceWriter(d, "x", "r", _manifest(), artifact_threshold=10, store_raw=False) as tw:
        tw.event("target_response", "victim", "счёт клиента 10678901 закрыт и это длинный текст")
        tw.run_status = RunStatus.COMPLETED
    manifest = json.load(open(os.path.join(d, "manifest.json"), encoding="utf-8"))
    assert manifest["raw_artifacts_enabled"] is False      # отчёт не обещает raw
    assert os.listdir(os.path.join(d, "artifacts", "raw")) == []


def test_purge_raw_removes_only_artifacts(tmp_path):
    from redteam.trace import purge_raw
    d = _run_dir_with_trace(tmp_path)
    with TraceWriter(d, "s1", "r3", _manifest(), artifact_threshold=5) as tw:
        tw.event("note", "harness", "длинный текст для артефакта")
        tw.run_status = RunStatus.COMPLETED
    assert purge_raw(d) >= 1
    assert os.listdir(os.path.join(d, "artifacts", "raw")) == []
    assert os.path.exists(os.path.join(d, "events.jsonl"))
