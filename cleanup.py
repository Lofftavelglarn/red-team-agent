"""Ресет памяти стенда между прогонами бенчмарка.

В стенде НЕТ штатного механизма Forget/Rollback (находка NO_FORGET), поэтому для
повторяемого ASR нужен явный сброс. Операция деструктивная — требует флага --yes.

  python -m redteam.cleanup                  # показать записи agent_policy
  python -m redteam.cleanup --yes            # удалить ВСЕ записи agent_policy
  python -m redteam.cleanup --yes --redteam-only   # только rt-/atk- сессии
  python -m redteam.cleanup --full --yes     # ПОЛНЫЙ сброс до дефолта репозитория:
                                             # dialog/episodic/semantic/agent_policy + Redis
                                             # (api_keys не трогаем). Возвращает стенд в
                                             # состояние «пустая память всех пользователей».
"""

from __future__ import annotations

import sys

from app.config import get_settings
from app.memory.mongo import MongoMemoryStore


def full_reset() -> dict:
    """Полный сброс памяти агента к дефолту репозитория (пустые коллекции + Redis).

    Дефолт стенда = пустой agent_memory (сид-данные лежат только в Postgres invest-server,
    в память не пишутся). Чистит 4 коллекции памяти и рабочую память в Redis. api_keys
    сохраняем, чтобы не рвать выданные ключи текущего прогона.
    """
    m = MongoMemoryStore()
    counts: dict = {}
    for name, col in [("dialog_sessions", m.dialog.col),
                      ("episodic_memories", m.episodic.col),
                      ("semantic_memories", m.semantic.col),
                      ("agent_policy_memories", m.agent_policy.col)]:
        counts[name] = col.delete_many({}).deleted_count
    try:
        import redis  # redis-py — зависимость приложения
        r = redis.from_url(get_settings().redis_url)
        r.flushdb()
        counts["redis_working_memory"] = "flushed"
    except Exception as exc:
        counts["redis_working_memory"] = f"error: {exc}"
    return counts


def main(argv: list[str]) -> None:
    if "--full" in argv:
        if "--yes" not in argv:
            print("ПОЛНЫЙ сброс памяти (dialog/episodic/semantic/agent_policy + Redis). "
                  "Добавьте --yes для выполнения.")
            return
        print("Полный сброс памяти к дефолту репозитория:")
        for k, v in full_reset().items():
            print(f"  {k}: {v}")
        return

    mongo = MongoMemoryStore()
    col = mongo.agent_policy.col
    rows = list(col.find({}, {"statement": 1, "source_session_id": 1, "_id": 0}))
    print(f"agent_policy: {len(rows)} записей")
    for r in rows:
        print(f"  [{r.get('source_session_id')}] {r.get('statement', '')[:80]}")

    if "--yes" not in argv:
        print("\nДобавьте --yes чтобы удалить. (--redteam-only — только rt-/atk-; --full — вся память)")
        return

    if "--redteam-only" in argv:
        q = {"source_session_id": {"$regex": "^(rt-|atk-)"}}
    else:
        q = {}
    res = col.delete_many(q)
    print(f"\nУдалено записей: {res.deleted_count}")


if __name__ == "__main__":
    main(sys.argv[1:])
