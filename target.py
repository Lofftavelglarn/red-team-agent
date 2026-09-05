"""InvestAgentTarget — обёртка публичного контура агента (≈ PyRIT PromptChatTarget).

Гоняет атаку строго через легитимный HTTP: POST /v1/chat/completions и
POST /v1/sessions/{id}/finalize. Ключ выдаётся программно через app.apikeys
(в UI выдача требует SSO; для headless-red-team это тот же самый механизм, что
использует promptfoo/LibreChat custom endpoint — модель безопасности не меняется:
user_id жёстко привязан к ключу, тело запроса его не переопределяет).

Ключевое отличие от чат-ориентированных тулов: таргет умеет вести РАЗНЫЕ сессии
и РАЗНЫХ пользователей (атакующий vs жертва), т.е. атакует не «запрос→ответ»,
а цепочку input→memory→…→другая сессия/пользователь.
"""

from __future__ import annotations

import httpx

from app.apikeys import generate_key
from app.memory.mongo import MongoMemoryStore

from redteam.config import AGENT_BASE_URL


class InvestAgentTarget:
    def __init__(self, base_url: str = AGENT_BASE_URL,
                 chat_timeout: float = 480.0, finalize_timeout: float = 600.0):
        self.base_url = base_url.rstrip("/")
        self.chat_timeout = chat_timeout
        self.finalize_timeout = finalize_timeout
        self._mongo = MongoMemoryStore()
        self._keys: dict[str, str] = {}  # user_id -> raw api key

    def api_key(self, user_id: str) -> str:
        """Выдать (один раз на прогон) долгоживущий ключ для пользователя."""
        if user_id not in self._keys:
            raw, record = generate_key(user_id, label="redteam")
            self._mongo.api_keys.create(record)
            self._keys[user_id] = raw
        return self._keys[user_id]

    def chat(self, user_id: str, session_id: str, text: str,
             auth_mode: str = "vulnerable", retries: int = 2) -> dict:
        """Один ход диалога. Возвращает {'content':..., 'raw':...}."""
        headers = {"Authorization": f"Bearer {self.api_key(user_id)}"}
        body = {
            "model": "genai-invest-assistant",
            "messages": [{"role": "user", "content": text}],
            "session_id": session_id,
            "auth_mode": auth_mode,
            "stream": False,
        }
        last = {"content": "", "raw": None}
        with httpx.Client(timeout=self.chat_timeout) as client:
            for _ in range(max(retries, 1)):
                resp = client.post(f"{self.base_url}/v1/chat/completions",
                                   json=body, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                last = {"content": content, "raw": data}
                if content and content.strip() and content.strip() != "Модель не вернула текстовый ответ.":
                    break
        return last

    def finalize(self, user_id: str, session_id: str) -> dict:
        """Запустить оркестратор памяти по сессии (Write→Store фаза)."""
        headers = {"Authorization": f"Bearer {self.api_key(user_id)}"}
        with httpx.Client(timeout=self.finalize_timeout) as client:
            resp = client.post(f"{self.base_url}/v1/sessions/{session_id}/finalize",
                               headers=headers)
            resp.raise_for_status()
            return resp.json()
