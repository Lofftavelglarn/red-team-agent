"""Фейковый стенд (target + memory observer + хранилища) для тестов.

Моделирует конвейер памяти без реального агента/Mongo: chat кладёт реплику в рабочую
память, finalize прогоняет фейковый экстрактор (реплика → факт с scope), observer
читает политики/факты/контекст жертвы. Поведение настраивается через responder/extractor.

`FakeMongo`/`FakeRedis` повторяют схему стенда (dialog_sessions/episodic_memories/
semantic_memories/agent_policy_memories и ключи `working:<user>:<session>`) настолько,
насколько это нужно cleanup-модулю: они позволяют проверить, что scoped-очистка удаляет
ТОЛЬКО артефакты кампании и не трогает чужие записи.
"""

from __future__ import annotations

import re
from collections import defaultdict

from redteam.target import TargetError


def default_extractor(messages):
    """По умолчанию НИЧЕГО не извлекает — конкретные тесты подменяют экстрактор."""
    return []


def default_responder(user, session, text, stand):
    return "нейтральный ответ агента"


class FakeStand:
    def __init__(self, extractor=None, responder=None):
        self.policies: list[str] = []
        self.user_facts: dict[str, list[str]] = defaultdict(list)
        self.working: dict[tuple, list[str]] = defaultdict(list)
        self.extractor = extractor or default_extractor
        self.responder = responder or default_responder
        self.finalize_error = False
        self.chat_error_on: set[str] = set()   # user_id, для которых chat кидает TargetError
        self.chat_log: list[tuple] = []

    # --- интерфейс InvestAgentTarget ---
    def chat(self, user_id, session_id, text, auth_mode="vulnerable", retries=2):
        if user_id in self.chat_error_on:
            raise TargetError(f"chat boom for {user_id}")
        self.working[(user_id, session_id)].append(text)
        self.chat_log.append((user_id, session_id, text))
        resp = self.responder(user_id, session_id, text, self)
        return {"content": resp, "latency_ms": 1, "http_status": 200,
                "tokens": 10, "retries": 0, "error": None}

    def finalize(self, user_id, session_id, retries=2):
        if self.finalize_error:
            raise TargetError("finalize boom")
        msgs = self.working.get((user_id, session_id), [])
        facts = self.extractor(msgs)
        for f in facts:
            if f["scope"] == "global":
                self.policies.append(f["fact"])
            else:
                self.user_facts[user_id].append(f["fact"])
        return {"episodes": [{"summary": "ep"}] if msgs else [], "facts": facts, "latency_ms": 1}

    # --- helpers для reset/fingerprint ---
    def reset(self):
        self.policies.clear()
        self.user_facts.clear()
        self.working.clear()

    def fingerprint(self):
        return "CLEAN" if not self.policies and not any(self.user_facts.values()) else "DIRTY"


class FakeObserver:
    """Интерфейс MemoryObserver поверх FakeStand."""

    def __init__(self, stand: FakeStand):
        self.stand = stand

    def policy_statements(self):
        return list(self.stand.policies)

    def new_policy_since(self, before):
        before_set = set(before)
        return [s for s in self.stand.policies if s not in before_set]

    def user_facts(self, user_id):
        return list(self.stand.user_facts.get(user_id, []))

    def victim_policy_section(self, victim_id, session_id="rt-probe"):
        if not self.stand.policies:
            return ""
        return "\n".join(f"- {p}" for p in self.stand.policies)

    def working_blob(self, user_id, session_id):
        return "\n".join(self.stand.working.get((user_id, session_id), []))

    def memory_size(self, user_ids):
        return {"policies": len(self.stand.policies)}


# --- минимальные двойники Mongo/Redis для проверки очистки ---
def _match_value(value, condition) -> bool:
    if isinstance(condition, dict):
        for op, operand in condition.items():
            if op == "$regex":
                if not re.search(operand, str(value or "")):
                    return False
            elif op == "$in":
                if value not in operand:
                    return False
            elif op == "$nin":
                if value in operand:
                    return False
            elif op == "$ne":
                if value == operand:
                    return False
            elif op == "$gte":
                if value is None or str(value) < str(operand):
                    return False
            elif op == "$exists":
                if (value is not None) != bool(operand):
                    return False
            else:
                raise NotImplementedError(f"оператор {op} не поддержан фейком")
        return True
    return value == condition


def _matches(doc: dict, query: dict | None) -> bool:
    if not query:
        return True
    for field, condition in query.items():
        if field == "$or":
            if not any(_matches(doc, sub) for sub in condition):
                return False
        elif not _match_value(doc.get(field), condition):
            return False
    return True


class _DeleteResult:
    def __init__(self, deleted_count: int):
        self.deleted_count = deleted_count


class FakeCollection:
    def __init__(self, docs=None):
        self.docs: list[dict] = [dict(d) for d in (docs or [])]

    def insert_one(self, doc: dict) -> None:
        self.docs.append(dict(doc))

    def insert_many(self, docs) -> None:
        for d in docs:
            self.insert_one(d)

    def find(self, query=None, projection=None):
        for doc in list(self.docs):
            if not _matches(doc, query):
                continue
            if projection:
                keep = {k for k, v in projection.items() if v and k != "_id"}
                out = {k: v for k, v in doc.items() if not keep or k in keep}
            else:
                out = dict(doc)
            out.pop("_id", None)
            yield out

    def count_documents(self, query=None) -> int:
        return sum(1 for doc in self.docs if _matches(doc, query))

    def delete_many(self, query) -> _DeleteResult:
        keep = [doc for doc in self.docs if not _matches(doc, query)]
        removed = len(self.docs) - len(keep)
        self.docs = keep
        return _DeleteResult(removed)


class FakeMongo:
    """Словарь коллекций с интерфейсом `db[name]`."""

    def __init__(self, collections=None):
        self._collections = {name: FakeCollection(docs)
                             for name, docs in (collections or {}).items()}

    def __getitem__(self, name: str) -> FakeCollection:
        return self._collections.setdefault(name, FakeCollection())

    def session_ids(self, collection: str) -> list[str]:
        return [d.get("session_id") for d in self[collection].docs]


class FakeRedis:
    def __init__(self, keys=None, fail: bool = False):
        self.store: dict[str, str] = dict(keys or {})
        self.fail = fail
        self.flushed = False

    def _guard(self):
        if self.fail:
            raise RuntimeError("redis down")

    def scan_iter(self, match: str = "*"):
        self._guard()
        pattern = re.compile("^" + re.escape(match).replace(r"\*", ".*") + "$")
        return [k for k in sorted(self.store) if pattern.match(k)]

    def delete(self, *keys) -> int:
        self._guard()
        removed = 0
        for key in keys:
            if self.store.pop(key, None) is not None:
                removed += 1
        return removed

    def flushdb(self) -> None:
        self._guard()
        self.store.clear()
        self.flushed = True
