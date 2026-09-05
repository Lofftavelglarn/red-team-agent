"""Сброс памяти стенда и fingerprint-проверка изоляции.

В стенде НЕТ штатного Forget/Rollback (запись переживает перезапуск), поэтому для
повторяемого бенчмарка нужен явный сброс ПЕРЕД каждым scenario/repeat/candidate.
После сброса берём fingerprint пользовательской и глобальной памяти: если он не
совпал с ожидаемым «чистым» — сценарий НЕ запускается (RunStatus.CONTAMINATED_STATE).

  python -m redteam.cleanup                  # показать agent_policy
  python -m redteam.cleanup --yes            # удалить все agent_policy
  python -m redteam.cleanup --yes --redteam-only   # только rt-/atk- сессии
  python -m redteam.cleanup --full --yes     # полный сброс (все коллекции + Redis)

`app.*` импортируется лениво — модуль-константы (`clean_fingerprint`) доступны в тестах.
"""

from __future__ import annotations

import hashlib
import json
import sys


# Fingerprint абсолютно чистого состояния: пустые коллекции памяти.
CLEAN_FINGERPRINT = "sha256:" + hashlib.sha256(
    json.dumps({"user_facts": 0, "policies": 0}, sort_keys=True).encode()
).hexdigest()[:32]


def _store():
    from app.memory.mongo import MongoMemoryStore
    return MongoMemoryStore()


def full_reset() -> dict:
    """Полный сброс памяти агента к дефолту репозитория (пустые коллекции + Redis)."""
    from app.config import get_settings
    m = _store()
    counts: dict = {}
    for name, col in [("dialog_sessions", m.dialog.col),
                      ("episodic_memories", m.episodic.col),
                      ("semantic_memories", m.semantic.col),
                      ("agent_policy_memories", m.agent_policy.col)]:
        counts[name] = col.delete_many({}).deleted_count
    try:
        import redis
        r = redis.from_url(get_settings().redis_url)
        r.flushdb()
        counts["redis_working_memory"] = "flushed"
    except Exception as exc:  # noqa: BLE001
        counts["redis_working_memory"] = f"error: {exc}"
    return counts


def policy_only_reset() -> dict:
    """Лёгкий сброс: только rt-/atk- записи agent_policy."""
    m = _store()
    res = m.agent_policy.col.delete_many({"source_session_id": {"$regex": "^(rt-|atk-)"}})
    return {"agent_policy_memories": res.deleted_count}


def fingerprint(user_ids: list[str]) -> str:
    """Хэш «состояния памяти» для проверки изоляции: число user-фактов + глоб. политик.

    Чистое состояние = 0 user-фактов у наблюдаемых пользователей и 0 глобальных политик.
    """
    m = _store()
    policies = len(m.agent_policy.list_all(limit=500))
    user_facts = 0
    for uid in user_ids:
        user_facts += len([s for s in m.semantic.list_for_context(uid, limit=200)
                           if s.scope != "global"])
    payload = json.dumps({"user_facts": user_facts, "policies": policies}, sort_keys=True)
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

    m = _store()
    rows = list(m.agent_policy.col.find({}, {"statement": 1, "source_session_id": 1, "_id": 0}))
    print(f"agent_policy: {len(rows)} записей")
    for r in rows:
        print(f"  [{r.get('source_session_id')}] {r.get('statement', '')[:80]}")
    if "--yes" not in argv:
        print("\nДобавьте --yes чтобы удалить. (--redteam-only — только rt-/atk-; --full — вся память)")
        return
    q = {"source_session_id": {"$regex": "^(rt-|atk-)"}} if "--redteam-only" in argv else {}
    print(f"\nУдалено записей: {m.agent_policy.col.delete_many(q).deleted_count}")


if __name__ == "__main__":
    main(sys.argv[1:])
