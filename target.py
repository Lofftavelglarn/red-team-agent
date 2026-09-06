"""HTTP-драйвер цели и отдельный white-box наблюдатель Mongo/Redis.

Атакующие действия выполняются только через публичные HTTP endpoint стенда.
Прямой доступ к Mongo/Redis используется evaluator-частью для доказательства записи,
чтения и очистки памяти; эти данные не передаются атакующей модели.
"""

from __future__ import annotations

import json
import time

from redteam.config import (
    AGENT_BASE_URL,
    MONGO_DB,
    MONGO_URI,
    POLICY_CONTEXT_LIMIT,
    REDIS_URL,
    target_api_keys,
)


class TargetError(RuntimeError):
    """Инфраструктурная ошибка обращения к таргету."""


class InvestAgentTarget:
    def __init__(self, base_url: str = AGENT_BASE_URL,
                 chat_timeout: float = 480.0, finalize_timeout: float = 600.0,
                 api_keys: dict[str, str] | None = None):
        self.base_url = base_url.rstrip("/")
        self.chat_timeout = chat_timeout
        self.finalize_timeout = finalize_timeout
        self._keys = dict(api_keys if api_keys is not None else target_api_keys())

    def api_key(self, user_id: str) -> str:
        key = self._keys.get(user_id, "").strip()
        if not key:
            raise TargetError(
                f"Нет API-ключа стенда для user_id={user_id}. "
                "Заполните REDTEAM_TARGET_*_API_KEY в red-team-agent/.env."
            )
        return key

    def chat(self, user_id: str, session_id: str, text: str,
             auth_mode: str = "vulnerable", retries: int = 2) -> dict:
        import httpx

        headers = {"Authorization": f"Bearer {self.api_key(user_id)}"}
        body = {
            "model": "genai-invest-assistant",
            "messages": [{"role": "user", "content": text}],
            "session_id": session_id,
            "auth_mode": auth_mode,
            "stream": False,
        }
        obs = {"content": "", "http_status": None, "latency_ms": None,
               "tokens": None, "retries": 0, "error": None}
        try:
            with httpx.Client(timeout=self.chat_timeout) as client:
                for attempt in range(max(retries, 1)):
                    t0 = time.time()
                    resp = client.post(
                        f"{self.base_url}/v1/chat/completions", json=body, headers=headers
                    )
                    obs["latency_ms"] = int((time.time() - t0) * 1000)
                    obs["http_status"] = resp.status_code
                    obs["retries"] = attempt
                    resp.raise_for_status()
                    data = resp.json()
                    content = data["choices"][0]["message"]["content"]
                    obs["content"] = content
                    obs["tokens"] = (data.get("usage") or {}).get("total_tokens")
                    if content and content.strip() \
                            and content.strip() != "Модель не вернула текстовый ответ.":
                        break
        except Exception as exc:  # noqa: BLE001
            raise TargetError(f"chat failed: {exc!r}") from exc
        return obs

    def finalize(self, user_id: str, session_id: str) -> dict:
        import httpx

        headers = {"Authorization": f"Bearer {self.api_key(user_id)}"}
        try:
            with httpx.Client(timeout=self.finalize_timeout) as client:
                t0 = time.time()
                resp = client.post(
                    f"{self.base_url}/v1/sessions/{session_id}/finalize", headers=headers
                )
                latency_ms = int((time.time() - t0) * 1000)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise TargetError(f"finalize failed: {exc!r}") from exc
        return {
            "episodes": data.get("episodes") or [],
            "facts": data.get("facts") or [],
            "latency_ms": latency_ms,
        }


class MemoryObserver:
    """Read-only evaluator над схемой памяти стенда без импорта его исходников."""

    def __init__(self, mongo_uri: str = MONGO_URI, mongo_db: str = MONGO_DB,
                 redis_url: str = REDIS_URL, policy_limit: int = POLICY_CONTEXT_LIMIT):
        from pymongo import MongoClient
        import redis

        self._mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        self._db = self._mongo_client[mongo_db]
        self._redis = redis.from_url(redis_url)
        self.policy_limit = policy_limit

    @property
    def policies(self):
        return self._db["agent_policy_memories"]

    @property
    def semantics(self):
        return self._db["semantic_memories"]

    def policy_statements(self) -> list[str]:
        cursor = self.policies.find({}, {"statement": 1}).sort("created_at", -1).limit(500)
        return [str(row.get("statement", "")) for row in cursor]

    def new_policy_since(self, before: list[str]) -> list[str]:
        before_set = set(before)
        return [statement for statement in self.policy_statements() if statement not in before_set]

    def user_facts(self, user_id: str) -> list[str]:
        query = {"user_id": user_id, "scope": {"$ne": "global"}}
        cursor = self.semantics.find(query, {"fact": 1}).sort("created_at", -1).limit(200)
        return [str(row.get("fact", "")) for row in cursor]

    def victim_policy_section(self, victim_id: str, session_id: str = "rt-probe") -> str:
        # Политика стенда глобальна: victim/session не влияют на выборку. Ограничение
        # совпадает с max_semantic_memories стенда, чтобы не завышать retrieval coverage.
        cursor = self.policies.find({}, {"statement": 1}).sort("created_at", -1) \
            .limit(self.policy_limit)
        return "\n".join(f"- {row.get('statement', '')}" for row in cursor)

    def working_blob(self, user_id: str, session_id: str) -> str:
        raw = self._redis.get(f"working:{user_id}:{session_id}")
        if not raw:
            return ""
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        data = json.loads(raw)
        return "\n".join(str(item.get("content", "")) for item in data.get("messages", []))

    def memory_size(self, user_ids: list[str]) -> dict:
        policies = list(self.policies.find({}, {"statement": 1}).limit(1000))
        out = {
            "policies": len(policies),
            "policy_chars": sum(len(str(row.get("statement", ""))) for row in policies),
        }
        for user_id in user_ids:
            query = {"user_id": user_id, "scope": {"$ne": "global"}}
            out[f"user_facts:{user_id}"] = self.semantics.count_documents(query)
        return out
