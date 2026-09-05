"""Минимальный клиент независимых attacker/judge OpenAI-compatible моделей."""

from __future__ import annotations

from redteam.config import model_config


def complete(role: str, system_prompt: str, user_prompt: str) -> str:
    """Выполнить chat completion для указанной роли и вернуть текст ответа."""
    from openai import OpenAI

    cfg = model_config(role)
    cfg.validate()
    kwargs: dict = {"api_key": cfg.api_key, "timeout": cfg.timeout_s}
    if cfg.base_url:
        kwargs["base_url"] = cfg.base_url
    client = OpenAI(**kwargs)
    response = client.chat.completions.create(
        model=cfg.model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        max_tokens=cfg.max_tokens,
        temperature=cfg.temperature,
    )
    content = response.choices[0].message.content
    if not content:
        raise RuntimeError(f"{role} model returned empty content")
    return content
