"""Сброс памяти стенда и fingerprint-проверка изоляции.

В стенде НЕТ штатного Forget/Rollback (запись переживает перезапуск), поэтому для
повторяемого бенчмарка нужен явный сброс ПЕРЕД каждым scenario/repeat/candidate.
После сброса берём fingerprint пользовательской и глобальной памяти: если он не
совпал с ожидаемым «чистым» — сценарий НЕ запускается (RunStatus.CONTAMINATED_STATE).

  python -m redteam.cleanup                  # показать agent_policy
  python -m redteam.cleanup --yes            # удалить все agent_policy
  python -m redteam.cleanup --yes --redteam-only   # только rt-/atk- сессии
  python -m redteam.cleanup --full --yes     # полный сброс (все коллекции + Redis)

Модуль работает напрямую с MongoDB/Redis по REDTEAM_MONGO_* и REDTEAM_REDIS_URL;
исходники и Python-окружение стенда ему не нужны.
"""

from __future__ import annotations

import hashlib
import json
import sys


# Слои памяти, которые ДОЛЖНЫ быть пусты в чистом состоянии.
_LAYERS = ("dialog", "episodic", "semantic", "policies", "working")

# Fingerprint абсолютно чистого состояния: все слои по нулям.
CLEAN_FINGERPRINT = "sha256:" + hashlib.sha256(
    json.dumps({k: 0 for k in _LAYERS}, sort_keys=True).encode()
).hexdigest()[:32]


class ResetError(RuntimeError):
    """Обязательная операция сброса не удалась — состояние нельзя считать чистым."""


def _store():
    from pymongo import MongoClient
    from redteam.config import MONGO_DB, MONGO_URI
    return MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)[MONGO_DB]


def _redis():
    import redis
    from redteam.config import REDIS_URL
    return redis.from_url(REDIS_URL)


def full_reset() -> dict:
    """Полный сброс памяти к дефолту (пустые коллекции + Redis).

    Ошибка ЛЮБОГО обязательного слоя — ResetError: молча продолжать нельзя, иначе
    benchmark признает состояние чистым при уцелевшей рабочей памяти (ТЗ P0-3)."""
    db = _store()
    counts: dict = {}
    for name in ("dialog_sessions", "episodic_memories", "semantic_memories",
                 "agent_policy_memories"):
        counts[name] = db[name].delete_many({}).deleted_count
    try:
        _redis().flushdb()
        counts["redis_working_memory"] = "flushed"
    except Exception as exc:  # noqa: BLE001
        raise ResetError(f"redis flush failed: {exc}") from exc
    return counts


def policy_only_reset() -> dict:
    """Лёгкий сброс: только rt-/atk- записи agent_policy."""
    db = _store()
    res = db["agent_policy_memories"].delete_many(
        {"source_session_id": {"$regex": "^(rt-|atk-)"}}
    )
    return {"agent_policy_memories": res.deleted_count}


def fingerprint(user_ids: list[str]) -> str:
    """Хэш состояния ВСЕХ слоёв памяти для проверки изоляции.

    Учитывает dialog/episodic/semantic/agent_policy (Mongo) и working memory (Redis).
    Если Redis недоступен — состояние НЕ считается чистым (возвращаем спец-значение),
    чтобы уцелевшая рабочая память не прошла как чистая (ТЗ P0-3)."""
    db = _store()
    counts = {
        "dialog": db["dialog_sessions"].count_documents({}),
        "episodic": db["episodic_memories"].count_documents({}),
        "semantic": db["semantic_memories"].count_documents({}),
        "policies": db["agent_policy_memories"].count_documents({}),
    }
    try:
        working = sum(1 for _ in _redis().scan_iter(match="working:*"))
    except Exception:  # noqa: BLE001
        return "sha256:REDIS_UNAVAILABLE"
    counts["working"] = working
    payload = json.dumps({k: counts.get(k, 0) for k in _LAYERS}, sort_keys=True)
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()[:32]


def is_clean(user_ids: list[str]) -> bool:
    return fingerprint(user_ids) == CLEAN_FINGERPRINT


def reset_for_policy(policy: str) -> dict:
    if policy == "full":
        return full_reset()
    if policy == "policy_only":
        return policy_only_reset()
    return {"reset": "skipped", "policy": policy}


def main(argv: list[str]) -> None:
    if "--full" in argv:
        if "--yes" not in argv:
            print("ПОЛНЫЙ сброс памяти (dialog/episodic/semantic/agent_policy + Redis). "
                  "Добавьте --yes.")
            return
        for k, v in full_reset().items():
            print(f"  {k}: {v}")
        return

    db = _store()
    policies = db["agent_policy_memories"]
    rows = list(policies.find({}, {"statement": 1, "source_session_id": 1, "_id": 0}))
    print(f"agent_policy: {len(rows)} записей")
    for r in rows:
        print(f"  [{r.get('source_session_id')}] {r.get('statement', '')[:80]}")
    if "--yes" not in argv:
        print("\nДобавьте --yes чтобы удалить. (--redteam-only — только rt-/atk-; --full — вся память)")
        return
    q = {"source_session_id": {"$regex": "^(rt-|atk-)"}} if "--redteam-only" in argv else {}
    print(f"\nУдалено записей: {policies.delete_many(q).deleted_count}")


if __name__ == "__main__":
    main(sys.argv[1:])
