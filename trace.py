"""Trace schema v2: доказательная, append-only трасса прогона.

Отличия от v1:
- события (`Event`) — append-only поток с монотонной `sequence`, `content_hash` и
  hash-цепочкой (`previous_event_hash`/`event_hash`): удаление или перестановка строки
  events.jsonl обнаруживается `python -m redteam.trace validate <run-dir>`;
- чекпоинты (`CheckpointResult`) ссылаются на `event_id`, а не копируют текст;
- крупные payload'ы выносятся в `artifacts/`, в событии остаётся excerpt + hash;
- политика raw/redacted (одна и та же для всех событий, без исключений по длине):
  events.jsonl и trace.json ВСЕГДА содержат отредактированную выжимку; полный текст
  лежит в `artifacts/raw/`, если включён REDTEAM_STORE_RAW=1 (по умолчанию), и артефакт
  создаётся не только для длинных payload'ов, но и всегда, когда редакция изменила
  текст; из raw-артефакта убираются только credentials (ключи и заголовки авторизации);
  при REDTEAM_STORE_RAW=0 raw-артефактов нет вовсе и отчёт их не обещает;
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
import re
import time
from dataclasses import asdict, dataclass, field

from redteam.models import AttemptRecord, CheckpointResult, RunResult, RunStatus


# 2.2: события связаны hash-цепочкой, manifest несёт её границы и хеш events.jsonl.
SCHEMA_VERSION = "2.2"
# Версия схемы, начиная с которой в трассе есть hash-цепочка.
CHAIN_SINCE = "2.2"

EVENT_KINDS = frozenset({
    "target_request", "target_response", "finalize_result",
    "memory_snapshot", "context_build", "judge_result", "checkpoint",
    "reset", "fingerprint", "attacker_turn", "infra_error", "note",
})
ACTORS = frozenset({"attacker", "victim", "secondary", "target", "evaluator", "harness"})


def content_hash(text: str) -> str:
    return "sha256:" + hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:32]


# Credentials — единственное, что не сохраняется НИГДЕ, включая raw-артефакт.
def redact_secrets(text: str) -> str:
    if not text:
        return text
    t = re.sub(r"sk-genai-[A-Za-z0-9_\-]+", "sk-genai-<redacted>", text)
    t = re.sub(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]+",
               r"\1 <redacted>", t)
    # Значения заголовков и переменных встречаются и как env (`API_KEY=x`), и как
    # repr словаря (`'Authorization': 'Bearer x'`). Кавычки вокруг имени/значения
    # не должны мешать редакции.
    t = re.sub(
        r"(?i)(['\"]?(?:authorization|proxy-authorization|x-api-key|"
        r"api[-_]?key|access[-_]?token|client[-_]?secret|password)['\"]?\s*[:=]\s*)"
        r"(['\"]?)[^'\"\s,}\]]+\2",
        r"\1\2<redacted>\2", t,
    )
    # Credentials в URI (MongoDB/Redis/HTTP proxy и т.п.).
    t = re.sub(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s:]+:[^/@\s]+@",
               r"\1<redacted>@", t)
    return re.sub(r"\bsk-[A-Za-z0-9_\-]{8,}", "sk-<redacted>", t)


_SECRET_FIELD = re.compile(
    r"(?i)^(?:authorization|proxy_authorization|x[-_]?api[-_]?key|api[-_]?key|"
    r"access[-_]?token|refresh[-_]?token|client[-_]?secret|password|credentials?)$"
)


def sanitize_secrets(value, *, report_redaction: bool = False):
    """Рекурсивно удалить credentials из любого сериализуемого значения.

    Трасса содержит не только `excerpt`: произвольные данные приходят через labels,
    manifest, meta, checkpoints и attempts. Поэтому строковой regex только в event
    content не является границей безопасности.
    """
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            safe_key = redact_secrets(key) if isinstance(key, str) else key
            if isinstance(key, str) and _SECRET_FIELD.fullmatch(key):
                clean[safe_key] = "<redacted>" if item not in (None, "") else item
            else:
                clean[safe_key] = sanitize_secrets(item, report_redaction=report_redaction)
        return clean
    if isinstance(value, list):
        return [sanitize_secrets(v, report_redaction=report_redaction) for v in value]
    if isinstance(value, tuple):
        return tuple(sanitize_secrets(v, report_redaction=report_redaction) for v in value)
    if isinstance(value, str):
        return redact(value) if report_redaction else redact_secrets(value)
    return value


# Редакция отчётной выжимки: credentials + длинные идентификаторы (ПДн стенда).
def redact(text: str) -> str:
    if not text:
        return text
    return re.sub(r"\b\d{8,}\b", "<redacted-id>", redact_secrets(text))


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
    previous_event_hash: str = ""
    event_hash: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)


def event_hash(payload: dict) -> str:
    """Хеш события БЕЗ поля event_hash — над ним и строится цепочка."""
    body = {k: v for k, v in payload.items() if k != "event_hash"}
    return "sha256:" + hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


class TraceWriter:
    """Пишет events.jsonl append-only и собирает trace.json/manifest.json.

    Используется как контекст-менеджер: трасса и события flush'атся на диск в
    `__exit__` даже при исключении внутри прогона.
    """

    def __init__(self, run_dir: str, scenario_id: str, run_id: str,
                 manifest: dict, artifact_threshold: int = 2000,
                 redact_report: bool = True, store_raw: bool = True):
        self.run_dir = run_dir
        self.scenario_id = scenario_id
        self.run_id = run_id
        self.manifest = dict(manifest)
        self.manifest.setdefault("schema_version", SCHEMA_VERSION)
        self.manifest.setdefault("scenario_id", scenario_id)
        self.manifest.setdefault("run_id", run_id)
        self.artifact_threshold = artifact_threshold
        self.redact_report = redact_report
        self.store_raw = store_raw
        self.manifest["raw_artifacts_enabled"] = bool(store_raw)
        self.events: list[Event] = []
        self._seq = 0
        self._checkpoints: dict[str, CheckpointResult] = {}
        self._attempts: list[AttemptRecord] = []
        self.meta: dict = {}
        self.run_status: RunStatus = RunStatus.ABORTED
        self.closed = False
        # Цепочка целостности: каждое событие ссылается на хеш предыдущего, поэтому
        # удалённая или переставленная строка events.jsonl перестаёт сходиться.
        self._chain = ""
        self._events_digest = hashlib.sha256()
        os.makedirs(self.artifacts_dir, exist_ok=True)
        self._events_fp = open(os.path.join(run_dir, "events.jsonl"), "a", encoding="utf-8")

    # --- пути ---
    @property
    def artifacts_dir(self) -> str:
        return os.path.join(self.run_dir, "artifacts", "raw")

    # --- запись событий ---
    def event(self, kind: str, actor: str, content: str, *, source: str = "",
              sink: str = "", session_id: str = "", **labels) -> str:
        """Записать событие. Возвращает event_id для ссылки из чекпоинтов."""
        self._seq += 1
        eid = f"evt-{self.run_id}-{self._seq:04d}"
        text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
        raw_artifact = None
        excerpt = text
        truncated = len(text) > self.artifact_threshold
        # Артефакт нужен не только длинному тексту: если редакция изменила выжимку,
        # без него исходное содержимое события нельзя восстановить вообще.
        safe_text = redact_secrets(text)
        report_text = redact(text) if self.redact_report else safe_text
        if self.store_raw and (truncated or report_text != text):
            raw_artifact = os.path.join("artifacts", "raw", f"{eid}.txt")
            with open(os.path.join(self.run_dir, raw_artifact), "w", encoding="utf-8") as f:
                f.write(safe_text)
        if truncated:
            excerpt = text[: self.artifact_threshold] + " …[truncated]"
        ev = Event(
            event_id=eid, sequence=self._seq,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            kind=kind, actor=actor, session_id=session_id, source=source, sink=sink,
            content_hash=content_hash(text),
            excerpt=redact(excerpt) if self.redact_report else redact_secrets(excerpt),
            raw_artifact=raw_artifact,
            labels=sanitize_secrets(labels, report_redaction=self.redact_report),
            previous_event_hash=self._chain,
        )
        ev.event_hash = event_hash(ev.to_dict())
        self._chain = ev.event_hash
        self.events.append(ev)
        line = json.dumps(ev.to_dict(), ensure_ascii=False) + "\n"
        self._events_digest.update(line.encode("utf-8"))
        self._events_fp.write(line)
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
                   error=error, matched=result.matched, signals=result.signals)

    def set_attempts(self, attempts: list[AttemptRecord]) -> None:
        """Записать попытки ДО сброса на диск: иначе result.json уходит с пустым
        `attempts`, хотя attempts.jsonl заполнен."""
        self._attempts = list(attempts)

    # --- сборка результата ---
    def build_result(self) -> RunResult:
        return RunResult(
            scenario_id=self.scenario_id, run_id=self.run_id,
            status=self.run_status, checkpoints=dict(self._checkpoints),
            attempts=list(self._attempts), meta=dict(self.meta),
        )

    def _flush(self) -> None:
        result = self.build_result()
        self.manifest["run_status"] = self.run_status.value
        self.manifest["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # Границы цепочки и хеш файла событий: по ним validate проверяет, что трассу
        # не усекли и не переписали после прогона.
        self.manifest["event_count"] = len(self.events)
        self.manifest["first_event_hash"] = self.events[0].event_hash if self.events else None
        self.manifest["last_event_hash"] = self.events[-1].event_hash if self.events else None
        self.manifest["events_sha256"] = "sha256:" + self._events_digest.hexdigest()
        with open(os.path.join(self.run_dir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(sanitize_secrets(self.manifest), f, ensure_ascii=False, indent=2)
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
            json.dump(sanitize_secrets(trace), f, ensure_ascii=False, indent=2)
        # attempts.jsonl пишется отдельно (append) через append_attempt.
        with open(os.path.join(self.run_dir, "result.json"), "w", encoding="utf-8") as f:
            json.dump(sanitize_secrets(result.to_dict()), f, ensure_ascii=False, indent=2)

    def append_attempt(self, attempt_dict: dict) -> None:
        with open(os.path.join(self.run_dir, "attempts.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(sanitize_secrets(attempt_dict), ensure_ascii=False) + "\n")

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
            self.closed = True
        return False  # исключения не подавляем


# --- проверка целостности трассы ---
def _read_jsonl(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def validate_run(run_dir: str) -> dict:
    """Проверить целостность и согласованность трассы одного прогона.

    Возвращает {"ok": bool, "problems": [...], "checked": {...}}. Проверяется то, что
    отчёт обязан гарантировать: события не переставлены и не удалены, ссылки чекпоинтов
    ведут на существующие события, артефакты на месте, а manifest/result/trace говорят
    об одном и том же прогоне. Трассы схемы < 2.2 не содержат цепочки — для них она
    не проверяется, но остальные проверки выполняются.
    """
    problems: list[str] = []
    manifest_path = os.path.join(run_dir, "manifest.json")
    events_path = os.path.join(run_dir, "events.jsonl")
    if not os.path.exists(manifest_path):
        return {"ok": False, "problems": [f"{run_dir}: нет manifest.json"], "checked": {}}
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    events = _read_jsonl(events_path) if os.path.exists(events_path) else []
    if not events:
        problems.append("events.jsonl пуст или отсутствует")

    version = str(manifest.get("schema_version", "2.0"))
    has_chain = version >= CHAIN_SINCE

    seen: set[str] = set()
    previous = ""
    for i, ev in enumerate(events, start=1):
        if ev.get("sequence") != i:
            problems.append(f"событие {ev.get('event_id')}: sequence={ev.get('sequence')}, ожидалось {i}")
        eid = ev.get("event_id")
        if eid in seen:
            problems.append(f"повторяющийся event_id: {eid}")
        seen.add(eid)
        if has_chain:
            if ev.get("previous_event_hash", "") != previous:
                problems.append(f"{eid}: разрыв цепочки (previous_event_hash)")
            if ev.get("event_hash") != event_hash(ev):
                problems.append(f"{eid}: event_hash не совпадает с содержимым")
            previous = ev.get("event_hash", "")
        artifact = ev.get("raw_artifact")
        if artifact and not os.path.exists(os.path.join(run_dir, artifact)):
            problems.append(f"{eid}: артефакт {artifact} отсутствует")

    if has_chain:
        if manifest.get("event_count") not in (None, len(events)):
            problems.append(f"manifest.event_count={manifest.get('event_count')}, "
                            f"в events.jsonl {len(events)}")
        if events and manifest.get("last_event_hash") not in (None, events[-1].get("event_hash")):
            problems.append("manifest.last_event_hash не совпадает с последним событием")
        if events and manifest.get("first_event_hash") not in (None, events[0].get("event_hash")):
            problems.append("manifest.first_event_hash не совпадает с первым событием")

    result_path = os.path.join(run_dir, "result.json")
    result = None
    if os.path.exists(result_path):
        with open(result_path, encoding="utf-8") as f:
            result = json.load(f)
        if result.get("run_id") != manifest.get("run_id"):
            problems.append("run_id в result.json и manifest.json различаются")
        if manifest.get("run_status") and result.get("status") != manifest.get("run_status"):
            problems.append("run_status в result.json и manifest.json различаются")
        for name, cp in (result.get("checkpoints") or {}).items():
            missing = [e for e in (cp.get("evidence_ids") or []) if e not in seen]
            if missing:
                problems.append(f"чекпоинт {name} ссылается на несуществующие события: {missing}")
    else:
        problems.append("нет result.json")

    trace_path = os.path.join(run_dir, "trace.json")
    if os.path.exists(trace_path) and result is not None:
        with open(trace_path, encoding="utf-8") as f:
            trace = json.load(f)
        if trace.get("run_id") != result.get("run_id"):
            problems.append("run_id в trace.json и result.json различаются")
        if len(trace.get("events") or []) != len(events):
            problems.append("число событий в trace.json и events.jsonl различается")
        if set(trace.get("checkpoints") or {}) != set(result.get("checkpoints") or {}):
            problems.append("наборы чекпоинтов в trace.json и result.json различаются")

    return {"ok": not problems, "problems": problems,
            "checked": {"run_dir": run_dir, "events": len(events),
                        "schema_version": version, "hash_chain": has_chain}}


def validate_campaign(run_dir: str) -> dict:
    """Проверить все прогоны кампании (подкаталоги с manifest.json)."""
    reports = {}
    for entry in sorted(os.listdir(run_dir)):
        sub = os.path.join(run_dir, entry)
        if os.path.isdir(sub) and os.path.exists(os.path.join(sub, "manifest.json")):
            reports[entry] = validate_run(sub)
    failed = {k: v for k, v in reports.items() if not v["ok"]}
    return {"ok": not failed, "runs": len(reports), "failed": len(failed), "reports": reports}


def purge_raw(run_dir: str) -> int:
    """Удалить raw-артефакты прогона или кампании (retention вручную).

    Выжимка, чекпоинты и цепочка целостности остаются; validate после этого сообщит
    об отсутствующих артефактах — это ожидаемо и отражает реальную политику хранения."""
    removed = 0
    for current, _dirs, files in os.walk(run_dir):
        if os.path.basename(current) != "raw":
            continue
        for name in files:
            os.remove(os.path.join(current, name))
            removed += 1
    return removed


def main(argv: list[str]) -> None:
    if len(argv) >= 2 and argv[0] == "purge-raw":
        print(f"удалено raw-артефактов: {purge_raw(argv[1])}")
        return
    if not argv or argv[0] != "validate" or len(argv) < 2:
        print("использование: python -m redteam.trace validate|purge-raw <run-dir>")
        raise SystemExit(2)
    target = argv[1]
    report = (validate_run(target) if os.path.exists(os.path.join(target, "manifest.json"))
              else validate_campaign(target))
    if "reports" in report:
        for name, rep in report["reports"].items():
            mark = "ok" if rep["ok"] else "ОШИБКИ"
            print(f"  {name}: {mark} (событий {rep['checked'].get('events')})")
            for problem in rep["problems"]:
                print(f"    - {problem}")
        print(f"прогонов: {report['runs']}, с проблемами: {report['failed']}")
    else:
        for problem in report["problems"]:
            print(f"  - {problem}")
        print("трасса цела" if report["ok"] else "трасса НЕ прошла проверку")
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    import sys
    main(sys.argv[1:])
