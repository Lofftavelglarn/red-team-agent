"""Read-only preflight для конфигурации standalone runner."""

from __future__ import annotations

import os


def _check(name: str, fn) -> bool:
    try:
        detail = fn()
        print(f"[ok]   {name}: {detail}")
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"[fail] {name}: {exc}")
        return False


def main() -> None:
    from redteam.config import (
        AGENT_BASE_URL,
        ALLOW_FULL_RESET,
        MONGO_DB,
        MONGO_URI,
        REDIS_URL,
        model_config,
        redis_db_number,
        safe_mongo_uri,
        target_api_keys,
    )

    def target_config():
        missing = [user_id for user_id, key in target_api_keys().items() if not key.strip()]
        if missing:
            raise RuntimeError(f"нет API-ключей стенда для user_id={missing}")
        return "ключи трёх ролей заданы"

    def model(role: str):
        cfg = model_config(role)
        cfg.validate()
        return f"{cfg.model} @ {cfg.base_url or 'default OpenAI endpoint'}"

    def agent():
        import httpx
        response = httpx.get(AGENT_BASE_URL, timeout=10, follow_redirects=False)
        if response.status_code >= 500:
            raise RuntimeError(f"HTTP {response.status_code}")
        return f"HTTP {response.status_code}"

    def mongo():
        from pymongo import MongoClient
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        return MONGO_DB

    def redis_check():
        import redis
        if not redis.from_url(REDIS_URL).ping():
            raise RuntimeError("PING returned false")
        return "PING"

    def cleanup_config():
        from redteam.config import resolve_cleanup_mode
        mode = resolve_cleanup_mode()
        return (f"mode={mode}, Mongo target={safe_mongo_uri()} / {MONGO_DB}, "
                f"Redis target=db {redis_db_number()}, "
                f"full reset allowed={'yes' if ALLOW_FULL_RESET else 'no'}")

    checks = [_check("cleanup config", cleanup_config),
              _check("target credentials", target_config)]
    if int(os.getenv("REDTEAM_LOOP", "0")) > 0:
        checks.append(_check("attacker model config", lambda: model("attacker")))
    checks.extend([
        _check("judge model config", lambda: model("judge")),
        _check("agent-api", agent),
        _check("MongoDB", mongo),
        _check("Redis", redis_check),
    ])
    raise SystemExit(0 if all(checks) else 1)


if __name__ == "__main__":
    main()
