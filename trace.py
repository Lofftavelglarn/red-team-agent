"""Trace schema v2: доказательная, append-only трасса прогона.

Отличия от v1:
- события (`Event`) — append-only поток с монотонной `sequence` и `content_hash`;
- чекпоинты (`CheckpointResult`) ссылаются на `event_id`, а не копируют текст;
- крупные payload'ы выносятся в `artifacts/`, в событии остаётся excerpt + hash;
- чувствительные данные редактируются в отчёте, но доступны в локальном raw artifact;
- трасса сохраняется ДАЖЕ при исключении (см. `TraceWriter.__exit__`);
- инфраструктурная ошибка фиксируется отдельным run-статусом, а не как неуспех.

Раскладка на прогон:
  runs/<run-id>/
    manifest.json   events.jsonl   trace.json   attempts.jsonl
    report.json     report.md      artifacts/
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field

from redteam.models import CheckpointResult, RunResult, RunStatus


# 2.1: manifest несёт required_path/terminal_checkpoint, чекпоинт — matched/error.
SCHEMA_VERSION = "2.1"

EVENT_KINDS = frozenset({
    "target_request", "target_response", "finalize_result",
    "memory_snapshot", "context_build", "judge_result", "checkpoint",
    "reset", "fingerprint", "attacker_turn", "infra_error", "note",
})
ACTORS = frozenset({"attacker", "victim", "secondary", "target", "evaluator", "harness"})


def content_hash(text: str) -> str:
    return "sha256:" + hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:32]


# Грубая редакция ПДн/секретов в отчётной выжимке (raw-артефакт не редактируется).
def redact(text: str) -> str:
    import re
    if not text:
        return text
    t = re.sub(r"sk-genai-[A-Za-z0-9_\-]+", "sk-genai-<redacted>", text)
    # ключи и заголовки авторизации из raw-исключений судьи/цели
    t = re.sub(r"(?i)\b(authorization|api[-_]?key|x-api-key)\b\s*[:=]\s*\S+",
               r"\1=<redacted>", t)
    t = re.sub(r"\bsk-[A-Za-z0-9_\-]{8,}", "sk-<redacted>", t)
    t = re.sub(r"\b\d{8,}\b", "<redacted-id>", t)
    return t


@dataclass
class Event:
    event_id: str
    sequence: int
    timestamp: str
    kind: str
    actor: str
    session_id: str = ""
    source: str = ""
    sink: str = ""
    content_hash: str = ""
    excerpt: str = ""
    raw_artifact: str | None = None
    labels: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class TraceWriter:
    """Пишет events.jsonl append-only и собирает trace.json/manifest.json.

    Используется как контекст-менеджер: трасса и события flush'атся на диск в
    `__exit__` даже при исключении внутри прогона.
    """

    def __init__(self, run_dir: str, scenario_id: str, run_id: str,
                 manifest: dict, artifact_threshold: int = 2000,
                 redact_report: bool = True):
        self.run_dir = run_dir
        self.scenario_id = scenario_id
        self.run_id = run_id
        self.manifest = dict(manifest)
        self.manifest.setdefault("schema_version", SCHEMA_VERSION)
        self.manifest.setdefault("scenario_id", scenario_id)
        self.manifest.setdefault("run_id", run_id)
        self.artifact_threshold = artifact_threshold
        self.redact_report = redact_report
        self.events: list[Event] = []
        self._seq = 0
        self._checkpoints: dict[str, CheckpointResult] = {}
        self.meta: dict = {}
        self.run_status: RunStatus = RunStatus.ABORTED
        os.makedirs(self.artifacts_dir, exist_ok=True)
        self._events_fp = open(os.path.join(run_dir, "events.jsonl"), "a", encoding="utf-8")

    # --- пути ---
    @property
    def artifacts_dir(self) -> str:
        return os.path.join(self.run_dir, "artifacts")

    # --- запись событий ---
    def event(self, kind: str, actor: str, content: str, *, source: str = "",
              sink: str = "", session_id: str = "", **labels) -> str:
        """Записать событие. Возвращает event_id для ссылки из чекпоинтов."""
        self._seq += 1
        eid = f"evt-{self.run_id}-{self._seq:04d}"
        text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
        raw_artifact = None
        excerpt = text
        if len(text) > self.artifact_threshold:
            raw_artifact = os.path.join("artifacts", f"{eid}.txt")
            with open(os.path.join(self.run_dir, raw_artifact), "w", encoding="utf-8") as f:
                f.write(text)
            excerpt = text[: self.artifact_threshold] + " …[truncated]"
        ev = Event(
            event_id=eid, sequence=self._seq,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            kind=kind, actor=actor, session_id=session_id, source=source, sink=sink,
            content_hash=content_hash(text),
            excerpt=redact(excerpt) if self.redact_report else excerpt,
            raw_artifact=raw_artifact, labels=labels,
        )
        self.events.append(ev)
        self._events_fp.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
        self._events_fp.flush()
        return eid

    def set_checkpoint(self, result: CheckpointResult) -> None:
        self._checkpoints[result.name] = result
        # error и matched обязаны попасть в событие: иначе evaluation_error в трассе
        # невозможно диагностировать. Текст ошибки редактируется как и любой excerpt —
        # ключи/заголовки в трассу не попадают.
        error = result.error
        if error and self.redact_report:
            error = redact(error)
        self.event("checkpoint", "evaluator",
                   f"{result.name}={result.status.value}: {result.reason}",
                   status=result.status.value, evidence_ids=result.evidence_ids,
                   evaluator=result.evaluator, confidence=result.confidence,
                   error=error, matched=result.matched)

    # --- сборка результата ---
    def build_result(self) -> RunResult:
        return RunResult(
            scenario_id=self.scenario_id, run_id=self.run_id,
            status=self.run_status, checkpoints=dict(self._checkpoints), meta=dict(self.meta),
        )

    def _flush(self) -> None:
        result = self.build_result()
        self.manifest["run_status"] = self.run_status.value
        self.manifest["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(os.path.join(self.run_dir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(self.manifest, f, ensure_ascii=False, indent=2)
        trace = {
            "schema_version": SCHEMA_VERSION,
            "scenario_id": self.scenario_id,
            "run_id": self.run_id,
            "run_status": self.run_status.value,
            "checkpoints": {k: v.to_dict() for k, v in self._checkpoints.items()},
            "meta": self.meta,
            "events": [e.to_dict() for e in self.events],
        }
        with open(os.path.join(self.run_dir, "trace.json"), "w", encoding="utf-8") as f:
            json.dump(trace, f, ensure_ascii=False, indent=2)
        # attempts.jsonl пишется отдельно (append) через append_attempt.
        with open(os.path.join(self.run_dir, "result.json"), "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)

    def append_attempt(self, attempt_dict: dict) -> None:
        with open(os.path.join(self.run_dir, "attempts.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(attempt_dict, ensure_ascii=False) + "\n")

    # --- контекст-менеджер: гарантированное сохранение трассы ---
    def __enter__(self) -> "TraceWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None:
            # Инфраструктурная ошибка: фиксируем отдельным статусом и событием,
            # трасса не теряется. Это НЕ неуспех атаки.
            self.run_status = RunStatus.INFRA_ERROR
            self.meta["infra_error"] = repr(exc)
            try:
                self.event("infra_error", "harness", repr(exc))
            except Exception:
                pass
        try:
            self._flush()
        finally:
            self._events_fp.close()
        return False  # исключения не подавляем
