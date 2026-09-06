"""Сброс памяти стенда, scoped-очистка артефактов кампании и fingerprint изоляции.

В стенде НЕТ штатного Forget/Rollback (запись переживает перезапуск), поэтому для
повторяемого бенчмарка нужно восстанавливать состояние ПЕРЕД каждой фазой опыта
(baseline / benign control / кандидат) и ПОСЛЕ кампании.

Режимы очистки (`cleanup_mode`):

- `scoped`  — режим по умолчанию: удаляются ТОЛЬКО артефакты текущей кампании, чужие
  записи и ручные тесты сохраняются;
- `full`    — полная очистка выделенной тестовой БД; требует явного opt-in;
- `disabled`— хранилища не изменяются, состояние только диагностируется.

Scoped-очистка опирается на реальные поля схемы стенда, а не на догадки:

| слой                    | поле привязки                                  |
|-------------------------|------------------------------------------------|
| `dialog_sessions`       | `session_id`                                   |
| `episodic_memories`     | `session_id` (даёт `episode_id`)               |
| `semantic_memories`     | `source_episode_id` эпизодов кампании,         |
|                         | плюс `user_id` red-team ролей с `created_at`   |
|                         | не раньше начала кампании                      |
| `agent_policy_memories` | `source_session_id`                            |
| Redis working memory    | ключ `working:<user_id>:<session_id>`          |

Все идентификаторы сессий кампании начинаются с `rt-<campaign_id>-`, поэтому одна
кампания никогда не удаляет артефакты другой. Условие держится на алфавите
`campaign_id` (`[A-Za-z0-9_]{4,32}`, см. `validate_campaign_id`): без дефисов префиксы
не вкладываются друг в друга, без метасимволов запрос не расширяется на чужие данные.

  python -m redteam.cleanup                  # показать agent_policy
  python -m redteam.cleanup --yes            # удалить все agent_policy
  python -m redteam.cleanup --yes --redteam-only   # только rt-/atk- сессии
  python -m redteam.cleanup --stale          # показать остатки прежних кампаний
  python -m redteam.cleanup --stale --yes    # удалить их
  python -m redteam.cleanup --full --yes     # полный сброс (нужен opt-in, см. ниже)

Модуль работает напрямую с MongoDB/Redis по REDTEAM_MONGO_* и REDTEAM_REDIS_URL;
исходники и Python-окружение стенда ему не нужны.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field

# Слои памяти стенда и их коллекции.
_LAYERS = ("dialog", "episodic", "semantic", "policies", "working")
_COLLECTIONS = {
    "dialog": "dialog_sessions",
    "episodic": "episodic_memories",
    "semantic": "semantic_memories",
    "policies": "agent_policy_memories",
}
# Стабильный идентификатор документа в каждом слое — по нему сортируем перед хэшированием.
_DOC_KEYS = {
    "dialog": "session_id",
    "episodic": "episode_id",
    "semantic": "fact_id",
    "policies": "policy_id",
}

# Fingerprint абсолютно чистого состояния: все слои по нулям. Оставлен для
# совместимости; актуальная проверка изоляции — сравнение с baseline кампании.
CLEAN_FINGERPRINT = "sha256:" + hashlib.sha256(
    json.dumps({k: 0 for k in _LAYERS}, sort_keys=True).encode()
).hexdigest()[:32]


class ResetError(RuntimeError):
    """Обязательная операция сброса не удалась — состояние нельзя считать чистым."""


class UnsafeResetError(ResetError):
    """Запрошено разрушительное действие без явного подтверждения."""


# Идентификатор кампании подставляется в имена сессий, в Mongo-regex и в Redis-glob,
# поэтому его алфавит ограничен. Метасимвол расширил бы scoped-очистку на чужие данные
# (`campaign_id="*"` удалил бы рабочую память ВСЕХ rt-кампаний), а дефис сделал бы
# префиксы вложенными: кампания `abc` считала бы своими артефакты кампании `abc-other`.
_CAMPAIGN_ID_RE = re.compile(r"^[A-Za-z0-9_]{4,32}$")


def validate_campaign_id(campaign_id: str) -> str:
    """Проверить идентификатор кампании до любых операций над памятью стенда."""
    text = str(campaign_id or "")
    if not _CAMPAIGN_ID_RE.match(text):
        raise ValueError(
            f"недопустимый campaign_id {campaign_id!r}: разрешены буквы, цифры и "
            "подчёркивание, длина 4-32. Дефисы и подстановочные знаки запрещены — "
            "они расширяют scoped-очистку на артефакты других кампаний.")
    return text


def session_prefix(campaign_id: str) -> str:
    """Префикс всех идентификаторов сессий кампании."""
    return f"rt-{validate_campaign_id(campaign_id)}-"


@dataclass
class CampaignScope:
    """Что именно принадлежит текущей кампании и может быть удалено."""

    campaign_id: str
    user_ids: list[str] = field(default_factory=list)
    started_at: str = ""       # ISO-8601 UTC; ограничивает удаление user-фактов

    def __post_init__(self) -> None:
        # Ни одна операция очистки не должна получить scope с непроверенным идентификатором.
        validate_campaign_id(self.campaign_id)

    @property
    def prefix(self) -> str:
        return session_prefix(self.campaign_id)

    @property
    def session_regex(self) -> str:
        return "^" + re.escape(self.prefix)

    def owns_session(self, session_id: str) -> bool:
        return str(session_id or "").startswith(self.prefix)


def _store():
    from pymongo import MongoClient
    from redteam.config import MONGO_DB, MONGO_URI
    return MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)[MONGO_DB]


def _redis():
    import redis
    from redteam.config import REDIS_URL
    return redis.from_url(REDIS_URL)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _digest(payload) -> str:
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


class MemoryAdmin:
    """Операции над памятью стенда: scoped/full очистка и fingerprint состояния."""

    def __init__(self, db=None, redis_client=None, *, doc_limit: int = 5000):
        self._db = db
        self._redis_client = redis_client
        self.doc_limit = doc_limit

    @property
    def db(self):
        if self._db is None:
            self._db = _store()
        return self._db

    @property
    def redis(self):
        if self._redis_client is None:
            self._redis_client = _redis()
        return self._redis_client

    # ---------- fingerprint ----------
    def layer_state(self) -> dict:
        """Состояние каждого слоя: количество документов И digest их содержимого.

        Только counts недостаточно: состояние с тем же числом записей, но другим
        содержанием, считалось бы восстановленным. Для working memory (Redis) в digest
        входят ИМЕНА ключей, но не значения: у рабочей памяти есть TTL, поэтому её
        содержимое меняется само по себе и не является признаком загрязнения.
        """
        state: dict = {}
        for layer, collection in _COLLECTIONS.items():
            docs = []
            for doc in self.db[collection].find({}, {"_id": 0}):
                docs.append(dict(doc))
                if len(docs) >= self.doc_limit:
                    break
            key = _DOC_KEYS[layer]
            docs.sort(key=lambda d: str(d.get(key, "")))
            state[layer] = {"count": len(docs), "digest": _digest(docs)}
        try:
            keys = sorted(_as_text(k) for k in self.redis.scan_iter(match="working:*"))
        except Exception as exc:  # noqa: BLE001 — уцелевшая рабочая память = грязное состояние
            raise ResetError(f"redis unavailable: {exc}") from exc
        state["working"] = {"count": len(keys), "digest": _digest(keys)}
        return state

    def fingerprint(self, user_ids: list[str] | None = None) -> str:
        """Короткий хэш состояния всех слоёв (counts + digests)."""
        try:
            return _digest(self.layer_state())
        except ResetError:
            return "sha256:REDIS_UNAVAILABLE"

    # ---------- scoped ----------
    def campaign_sessions(self, scope: CampaignScope) -> list[str]:
        """Идентификаторы сессий кампании, оставшихся в диалоговой/эпизодической памяти."""
        found = set()
        for collection in ("dialog_sessions", "episodic_memories"):
            for doc in self.db[collection].find({"session_id": {"$regex": scope.session_regex}},
                                                {"session_id": 1, "_id": 0}):
                found.add(str(doc.get("session_id")))
        return sorted(found)

    def scoped_reset(self, scope: CampaignScope) -> dict:
        """Удалить артефакты ТОЛЬКО этой кампании, сохранив все посторонние записи."""
        deleted: dict = {}
        session_query = {"session_id": {"$regex": scope.session_regex}}

        # эпизоды кампании нужны раньше удаления: по ним находятся производные факты
        episode_ids = [str(doc.get("episode_id"))
                       for doc in self.db["episodic_memories"].find(session_query,
                                                                    {"episode_id": 1, "_id": 0})
                       if doc.get("episode_id")]

        semantic_or: list[dict] = []
        if episode_ids:
            semantic_or.append({"source_episode_id": {"$in": episode_ids}})
        if scope.user_ids:
            # факты red-team ролей, записанные не раньше старта кампании; ручные записи
            # тех же пользователей, сделанные до кампании, не трогаем
            user_query: dict = {"user_id": {"$in": list(scope.user_ids)}}
            if scope.started_at:
                user_query["created_at"] = {"$gte": scope.started_at}
            semantic_or.append(user_query)

        deleted["dialog_sessions"] = self.db["dialog_sessions"].delete_many(
            session_query).deleted_count
        deleted["episodic_memories"] = self.db["episodic_memories"].delete_many(
            session_query).deleted_count
        deleted["semantic_memories"] = (
            self.db["semantic_memories"].delete_many({"$or": semantic_or}).deleted_count
            if semantic_or else 0)
        deleted["agent_policy_memories"] = self.db["agent_policy_memories"].delete_many(
            {"source_session_id": {"$regex": scope.session_regex}}).deleted_count

        try:
            keys = [k for k in self.redis.scan_iter(match=f"working:*:{scope.prefix}*")]
            if keys:
                self.redis.delete(*keys)
            deleted["redis_keys"] = len(keys)
        except Exception as exc:  # noqa: BLE001
            raise ResetError(f"redis scoped cleanup failed: {exc}") from exc
        return deleted

    # ---------- остатки прежних кампаний ----------
    def stale_campaigns(self, scope: CampaignScope) -> dict[str, int]:
        """Найти артефакты red-team кампаний, отличных от текущей.

        Аварийно остановленный контейнер не выполняет финальную очистку, поэтому его
        записи переживают запуск. Молча включить их в baseline нельзя: отравленное
        состояние стало бы «исходным». Автоматически они НЕ удаляются — чужой прогон
        может идти прямо сейчас.
        """
        found: dict[str, int] = {}

        def _count(session_id: str) -> None:
            text = str(session_id or "")
            if not text.startswith("rt-") or scope.owns_session(text):
                return
            campaign = text.split("-")[1] if len(text.split("-")) > 1 else "unknown"
            found[campaign] = found.get(campaign, 0) + 1

        for collection in ("dialog_sessions", "episodic_memories"):
            for doc in self.db[collection].find({"session_id": {"$regex": "^rt-"}},
                                                {"session_id": 1, "_id": 0}):
                _count(doc.get("session_id"))
        for doc in self.db["agent_policy_memories"].find(
                {"source_session_id": {"$regex": "^rt-"}}, {"source_session_id": 1, "_id": 0}):
            _count(doc.get("source_session_id"))
        try:
            for key in self.redis.scan_iter(match="working:*:rt-*"):
                _count(_as_text(key).split(":", 2)[-1])
        except Exception as exc:  # noqa: BLE001
            raise ResetError(f"redis unavailable: {exc}") from exc
        return dict(sorted(found.items()))

    def purge_campaign(self, campaign_id: str, user_ids: list[str] | None = None) -> dict:
        """Явно удалить артефакты указанной кампании (ручная операция оператора)."""
        return self.scoped_reset(CampaignScope(campaign_id=campaign_id,
                                               user_ids=list(user_ids or [])))

    # ---------- full ----------
    def full_reset(self, *, allow_full_reset: bool = False) -> dict:
        """Полная очистка выбранной БД. Требует явного подтверждения вызывающей стороны.

        Ошибка ЛЮБОГО обязательного слоя — ResetError: молча продолжать нельзя, иначе
        benchmark признает состояние чистым при уцелевшей рабочей памяти."""
        if not allow_full_reset:
            raise UnsafeResetError(
                "полная очистка запрещена: нужен REDTEAM_CLEANUP_MODE=full и "
                "REDTEAM_ALLOW_FULL_RESET=1")
        deleted: dict = {}
        for name in _COLLECTIONS.values():
            deleted[name] = self.db[name].delete_many({}).deleted_count
        try:
            self.redis.flushdb()
            deleted["redis_keys"] = "flushed"
        except Exception as exc:  # noqa: BLE001
            raise ResetError(f"redis flush failed: {exc}") from exc
        return deleted


def restore(admin: MemoryAdmin, scope: CampaignScope, *, operation: str,
            mode: str = "scoped", allow_full_reset: bool = False,
            expected_fingerprint: str | None = None, **labels) -> dict:
    """Выполнить очистку и вернуть структурированный cleanup receipt.

    Receipt пишется в трассу и в отчёт: без него нельзя установить, в каком состоянии
    выполнялась конкретная фаза опыта. Credentials в receipt не попадают.
    """
    receipt = {"operation": operation, "mode": mode, "campaign_id": scope.campaign_id,
               "started_at": _now(), "deleted": {}, "errors": []}
    receipt.update(labels)
    try:
        receipt["fingerprint_before"] = admin.fingerprint()
        if mode == "disabled":
            receipt["deleted"] = {}
        elif mode == "full":
            receipt["deleted"] = admin.full_reset(allow_full_reset=allow_full_reset)
        else:
            receipt["deleted"] = admin.scoped_reset(scope)
        receipt["fingerprint_after"] = admin.fingerprint()
    except Exception as exc:  # noqa: BLE001 — ошибку не глушим, она решает судьбу прогона
        receipt["errors"].append(repr(exc))
        receipt["fingerprint_after"] = None
    receipt["completed_at"] = _now()
    receipt["expected_fingerprint"] = expected_fingerprint
    receipt["restored"] = bool(
        not receipt["errors"]
        and (expected_fingerprint is None
             or receipt.get("fingerprint_after") == expected_fingerprint))
    return receipt


def _as_text(value) -> str:
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


# --- обратная совместимость: функции прежнего API ---
def full_reset(*, allow_full_reset: bool = False) -> dict:
    return MemoryAdmin().full_reset(allow_full_reset=allow_full_reset)


def fingerprint(user_ids: list[str] | None = None) -> str:
    return MemoryAdmin().fingerprint(user_ids)


def is_clean(user_ids: list[str] | None = None) -> bool:
    return fingerprint(user_ids) == CLEAN_FINGERPRINT


def main(argv: list[str]) -> None:
    from redteam.config import ALLOW_FULL_RESET

    if "--stale" in argv:
        admin = MemoryAdmin()
        scope = CampaignScope(campaign_id="__none__")
        stale = admin.stale_campaigns(scope)
        if not stale:
            print("остатков прежних red-team кампаний нет")
            return
        print("остатки прежних кампаний (campaign_id: записей):")
        for campaign, count in stale.items():
            print(f"  {campaign}: {count}")
        if "--yes" not in argv:
            print("\nДобавьте --yes чтобы удалить их, или --campaign <id> --yes для одной.")
            return
        targets = [argv[argv.index("--campaign") + 1]] if "--campaign" in argv else list(stale)
        for campaign in targets:
            print(f"  {campaign}: {admin.purge_campaign(campaign)}")
        return

    if "--full" in argv:
        if "--yes" not in argv:
            print("ПОЛНЫЙ сброс памяти (dialog/episodic/semantic/agent_policy + Redis). "
                  "Добавьте --yes.")
            return
        try:
            for k, v in full_reset(allow_full_reset=ALLOW_FULL_RESET).items():
                print(f"  {k}: {v}")
        except UnsafeResetError as exc:
            print(f"отказ: {exc}")
            raise SystemExit(2) from exc
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
