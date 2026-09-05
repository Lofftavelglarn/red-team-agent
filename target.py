"""Драйвер публичного контура агента + white-box наблюдатель памяти для evaluator.

Атака идёт строго через легитимный HTTP: POST /v1/chat/completions и
POST /v1/sessions/{id}/finalize. `chat()`/`finalize()` возвращают нормализованные
наблюдения (content, latency, http_status, tokens) — их же атакующая модель получает
как обратную связь (никаких документов Mongo наружу не отдаём).

`MemoryObserver` — white-box доступ к хранилищу ТОЛЬКО для evaluator: проверка фактов
записи и построения контекста жертвы. Атакующей модели этот класс не передаётся.

`app.*` импортируется лениво в конструкторах, чтобы модуль грузился вне контейнера
(например, для проверки сигнатур в тестах с фейковым таргетом).
"""

from __future__ import annotations

import time

from redteam.config import AGENT_BASE_URL


class TargetError(RuntimeError):
    """Инфраструктурная ошибка обращения к таргету (не неуспех атаки)."""


class InvestAgentTarget:
    def __init__(self, base_url: str = AGENT_BASE_URL,
                 chat_timeout: float = 480.0, finalize_timeout: float = 600.0):
        self.base_url = base_url.rstrip("/")
        self.chat_timeout = chat_timeout
        self.finalize_timeout = finalize_timeout
        from app.memory.mongo import MongoMemoryStore
        self._mongo = MongoMemoryStore()
        self._keys: dict[str, str] = {}

    def api_key(self, user_id: str) -> str:
        if user_id not in self._keys:
            from app.apikeys import generate_key
            raw, record = generate_key(user_id, label="redteam")
            self._mongo.api_keys.create(record)
            self._keys[user_id] = raw
        return self._keys[user_id]

    def chat(self, user_id: str, session_id: str, text: str,
             auth_mode: str = "vulnerable", retries: int = 2) -> dict:
        """Один ход диалога. Возвращает нормализованное наблюдение."""
        import httpx
        headers = {"Authorization": f"Bearer {self.api_key(user_id)}"}
        body = {"model": "genai-invest-assistant",
                "messages": [{"role": "user", "content": text}],
                "session_id": session_id, "auth_mode": auth_mode, "stream": False}
        obs = {"content": "", "http_status": None, "latency_ms": None,
               "tokens": None, "retries": 0, "error": None}
        try:
            with httpx.Client(timeout=self.chat_timeout) as client:
                for attempt in range(max(retries, 1)):
                    t0 = time.time()
                    resp = client.post(f"{self.base_url}/v1/chat/completions",
                                       json=body, headers=headers)
                    obs["latency_ms"] = int((time.time() - t0) * 1000)
                    obs["http_status"] = resp.status_code
                    obs["retries"] = attempt
                    resp.raise_for_status()
                    data = resp.json()
                    content = data["choices"][0]["message"]["content"]
                    obs["content"] = content
                    obs["tokens"] = (data.get("usage") or {}).get("total_tokens")
                    if content and content.strip() and content.strip() != "Модель не вернула текстовый ответ.":
                        break
        except Exception as exc:  # noqa: BLE001
            raise TargetError(f"chat failed: {exc!r}") from exc
        return obs

    def finalize(self, user_id: str, session_id: str) -> dict:
        """Запустить оркестратор памяти. Возвращает {'episodes','facts','latency_ms'}."""
        import httpx
        headers = {"Authorization": f"Bearer {self.api_key(user_id)}"}
        try:
            with httpx.Client(timeout=self.finalize_timeout) as client:
                t0 = time.time()
                resp = client.post(f"{self.base_url}/v1/sessions/{session_id}/finalize",
                                   headers=headers)
                lat = int((time.time() - t0) * 1000)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise TargetError(f"finalize failed: {exc!r}") from exc
        return {"episodes": data.get("episodes") or [],
                "facts": data.get("facts") or [], "latency_ms": lat}


class MemoryObserver:
    """White-box чтение хранилища — только для evaluator (проверка фактов записи)."""

    _POLICY_HEADER = "## Политика агента"

    def __init__(self):
        from app.memory.mongo import MongoMemoryStore
        from app.memory.store import MemoryStore
        self.mongo = MongoMemoryStore()
        self.store = MemoryStore()

    def policy_statements(self) -> list[str]:
        return [p.statement for p in self.mongo.agent_policy.list_all(limit=500)]

    def new_policy_since(self, before: list[str]) -> list[str]:
        before_set = set(before)
        return [s for s in self.policy_statements() if s not in before_set]

    def user_facts(self, user_id: str) -> list[str]:
        return [s.fact for s in self.mongo.semantic.list_for_context(user_id, limit=200)
                if s.scope != "global"]

    def victim_policy_section(self, victim_id: str, session_id: str = "rt-probe") -> str:
        ctx = self.store.build_context(victim_id, session_id)
        if self._POLICY_HEADER in ctx:
            return ctx.split(self._POLICY_HEADER, 1)[-1]
        return ""

    def working_blob(self, user_id: str, session_id: str) -> str:
        wm = self.store.get_working(user_id, session_id)
        return "\n".join(m.content for m in wm.messages)

    def memory_size(self, user_ids: list[str]) -> dict:
        """Метрики для flooding-сценария: число записей и грубый размер контекста."""
        policies = self.mongo.agent_policy.list_all(limit=1000)
        out = {"policies": len(policies),
               "policy_chars": sum(len(p.statement) for p in policies)}
        for uid in user_ids:
            facts = [s for s in self.mongo.semantic.list_for_context(uid, limit=500)
                     if s.scope != "global"]
            out[f"user_facts:{uid}"] = len(facts)
        return out
