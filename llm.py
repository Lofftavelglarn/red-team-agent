"""Минимальный клиент независимых attacker/judge OpenAI-compatible моделей."""

from __future__ import annotations

import sys
import time

from redteam.config import model_config


def _log(msg: str) -> None:
    """Логи llm-вызовов в stderr (видны в docker compose run, не мешают stdout-отчёту)."""
    print(f"[llm] {msg}", file=sys.stderr, flush=True)


def complete(role: str, system_prompt: str, user_prompt: str) -> str:
    """Выполнить chat completion для указанной роли и вернуть текст ответа."""
    from openai import OpenAI

    cfg = model_config(role)
    cfg.validate()
    kwargs: dict = {"api_key": cfg.api_key, "timeout": cfg.timeout_s}
    if cfg.base_url:
        kwargs["base_url"] = cfg.base_url
    client = OpenAI(**kwargs)
    create_kwargs: dict = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": cfg.max_tokens,
        "temperature": cfg.temperature,
    }
    if cfg.disable_thinking:
        # Qwen3/reasoning-модели (huihui и др.) уводят ответ в reasoning-блок и
        # оставляют content пустым. Глушим thinking на стороне vLLM-шаблона.
        # Только для ролей, где это явно включено (см. REDTEAM_<ROLE>_DISABLE_THINKING),
        # чтобы не слать extra_body провайдерам, которые его не принимают (напр. судья).
        create_kwargs["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}
    endpoint = cfg.base_url or "openai-default"
    think = "think:off" if cfg.disable_thinking else "think:on"
    _log(f"→ ждём {role}: {cfg.model} @ {endpoint} ({think}, timeout={cfg.timeout_s:g}s)…")
    started = time.monotonic()
    try:
        response = client.chat.completions.create(**create_kwargs)
    except Exception as exc:
        _log(f"✗ {role} ({cfg.model} @ {endpoint}) упал за {time.monotonic()-started:.1f}s: "
             f"{type(exc).__name__}: {exc}")
        raise
    message = response.choices[0].message
    # Фолбэк: если thinking всё же включён и content пуст — берём reasoning_content,
    # чтобы не терять ответ модели и не ронять attack-петлю на "empty content".
    content = message.content or getattr(message, "reasoning_content", None)
    src = "content" if message.content else "reasoning_content"
    _log(f"← {role} ({cfg.model}) ответил за {time.monotonic()-started:.1f}s: "
         f"{len(content or '')} симв. из {src}")
    if not content:
        raise RuntimeError(f"{role} model returned empty content")
    return content
