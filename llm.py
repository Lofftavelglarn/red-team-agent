"""Минимальный клиент независимых attacker/judge OpenAI-compatible моделей."""

from __future__ import annotations

import os
import random
import sys
import time

from redteam.config import model_config


def _log(msg: str) -> None:
    """Логи llm-вызовов в stderr (видны в docker compose run, не мешают stdout-отчёту)."""
    print(f"[llm] {msg}", file=sys.stderr, flush=True)


# HTTP-коды, при которых имеет смысл повторить запрос (перегрузка/временная недоступность).
_RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}


class ModelUnavailableError(BaseException):
    """Модель (attacker/judge) не ответила: сбой API после всех ретраев или пустой ответ.

    Наследуется от BaseException НАМЕРЕННО: так исключение пробивает `except Exception`
    в adjudicator/attacker/strategy/runner/campaign и обрывает всю кампанию (fail-fast),
    а не деградирует в evaluation_error с бесполезным отчётом. Поведение включается
    флагом REDTEAM_FAIL_FAST (по умолчанию 1); при REDTEAM_FAIL_FAST=0 сохраняется
    старое поведение (сбой модели → evaluation_error / attacker error)."""

    def __init__(self, role: str, model: str, endpoint: str, detail: str, attempts: int):
        self.role = role
        self.model = model
        self.endpoint = endpoint
        self.detail = detail
        self.attempts = attempts
        super().__init__(
            f"{role}-модель не отвечает: {model} @ {endpoint} — "
            f"после {attempts} попыт(ок): {detail}"
        )


def _fail_fast() -> bool:
    return os.getenv("REDTEAM_FAIL_FAST", "1").strip().lower() in {"1", "true", "yes", "on"}


def _retry_params(role: str) -> tuple[int, float, float]:
    """(max_retries, base_seconds, cap_seconds) — настраиваются REDTEAM_<ROLE>_RETRY*.

    По умолчанию 5 повторов с backoff 2s→30s: одиночный запрос к перегруженному
    провайдеру (503 capacity_unavailable / зависание) обычно проходит, если разнести
    попытки во времени. SDK ретраит лишь дважды с суб-секундной паузой — этого мало
    при burst-троттлинге, когда судья вызывается пачкой.
    """
    prefix = f"REDTEAM_{role.upper()}"
    try:
        n = int(os.getenv(f"{prefix}_MAX_RETRIES", "5"))
    except ValueError:
        n = 5
    try:
        base = float(os.getenv(f"{prefix}_RETRY_BASE", "2"))
    except ValueError:
        base = 2.0
    try:
        cap = float(os.getenv(f"{prefix}_RETRY_CAP", "30"))
    except ValueError:
        cap = 30.0
    return max(0, n), max(0.1, base), max(base, cap)


def _is_retryable(exc: Exception) -> bool:
    from openai import APIConnectionError, APIStatusError, APITimeoutError, RateLimitError

    if isinstance(exc, (APIConnectionError, APITimeoutError, RateLimitError)):
        return True
    if isinstance(exc, APIStatusError):
        return getattr(exc, "status_code", None) in _RETRYABLE_STATUS
    return False


def complete(role: str, system_prompt: str, user_prompt: str) -> str:
    """Выполнить chat completion для указанной роли и вернуть текст ответа."""
    from openai import OpenAI

    cfg = model_config(role)
    cfg.validate()
    # max_retries=0 — таймингом ретраев управляем сами (backoff ниже), чтобы не
    # накладывать суб-секундные ретраи SDK поверх наших пауз.
    kwargs: dict = {"api_key": cfg.api_key, "timeout": cfg.timeout_s, "max_retries": 0}
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
    max_retries, base, cap = _retry_params(role)
    _log(f"→ ждём {role}: {cfg.model} @ {endpoint} ({think}, timeout={cfg.timeout_s:g}s, "
         f"retries={max_retries})…")
    started = time.monotonic()
    attempt = 0
    while True:
        try:
            response = client.chat.completions.create(**create_kwargs)
            break
        except Exception as exc:
            waited = time.monotonic() - started
            if attempt < max_retries and _is_retryable(exc):
                delay = min(cap, base * (2 ** attempt)) + random.uniform(0, 1)
                _log(f"⟳ {role} ({cfg.model}) {type(exc).__name__} за {waited:.1f}s — "
                     f"повтор {attempt + 1}/{max_retries} через {delay:.1f}s")
                time.sleep(delay)
                attempt += 1
                continue
            _log(f"✗ {role} ({cfg.model} @ {endpoint}) упал за {waited:.1f}s "
                 f"(попыток {attempt + 1}): {type(exc).__name__}: {exc}")
            if _fail_fast():
                raise ModelUnavailableError(
                    role, cfg.model, endpoint, f"{type(exc).__name__}: {exc}", attempt + 1
                ) from exc
            raise
    message = response.choices[0].message
    # Фолбэк: если thinking всё же включён и content пуст — берём reasoning_content,
    # чтобы не терять ответ модели и не ронять attack-петлю на "empty content".
    content = message.content or getattr(message, "reasoning_content", None)
    src = "content" if message.content else "reasoning_content"
    _log(f"← {role} ({cfg.model}) ответил за {time.monotonic()-started:.1f}s: "
         f"{len(content or '')} симв. из {src}")
    if not content:
        if _fail_fast():
            raise ModelUnavailableError(
                role, cfg.model, endpoint, "пустой ответ модели (нет content/reasoning)", attempt + 1
            )
        raise RuntimeError(f"{role} model returned empty content")
    return content
