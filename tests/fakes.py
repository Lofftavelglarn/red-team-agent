"""Фейковый стенд (target + memory observer) для integration/golden тестов.

Моделирует конвейер памяти без реального агента/Mongo: chat кладёт реплику в рабочую
память, finalize прогоняет фейковый экстрактор (реплика → факт с scope), observer
читает политики/факты/контекст жертвы. Поведение настраивается через responder/extractor.
"""

from __future__ import annotations

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
