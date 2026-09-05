"""Конфигурация бенчмарка: модели, бюджеты, reset-политика, concurrency, trace.

Атака идёт ТОЛЬКО легитимными публичными каналами стенда:
POST /v1/chat/completions и POST /v1/sessions/{id}/finalize. Агента/mcp/тулы и
каталог adapters/ не трогаем.

Модуль не тянет `app.*` на импорте — настройки стенда (модель судьи, ключи) читаются
лениво через `judge_model_name()`, чтобы ядро грузилось и тестировалось вне контейнера.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from redteam.models import AttackBudget


# Публичный контур агента (тот же, что дергает LibreChat/promptfoo).
AGENT_BASE_URL = os.environ.get("REDTEAM_AGENT_URL", "http://localhost:8600")

# Куда складывать трассы и отчёты (внутри контейнера — /app/runs).
OUT_DIR = os.environ.get("REDTEAM_OUT_DIR", "/app/runs")

# Учётные записи стенда: client1001..1005, claim cus совпадает с номером.
ATTACKER_USER = os.environ.get("REDTEAM_ATTACKER", "1001")
VICTIM_USER = os.environ.get("REDTEAM_VICTIM", "1003")

# Третий пользователь для распределённых/межпользовательских сценариев.
SECONDARY_USER = os.environ.get("REDTEAM_SECONDARY", "1002")

# Конкурентность разрешена ТОЛЬКО для доказанно read-only запросов одного snapshot
# (батч baseline). Операции, меняющие общую память, не параллелятся.
CONCURRENCY = int(os.environ.get("REDTEAM_CONCURRENCY", "4"))

JUDGE_MAX_TOKENS = int(os.environ.get("REDTEAM_JUDGE_MAX_TOKENS", "8192"))


def judge_model_name() -> str:
    """Имя модели судьи/атакующего. Читаем из настроек стенда лениво (нужен `app`)."""
    override = os.environ.get("REDTEAM_JUDGE_MODEL")
    if override:
        return override
    from app.config import get_settings
    return get_settings().summarization_model


@dataclass
class TraceOptions:
    # Крупные payload'ы выносятся в artifacts/ при превышении порога (символы).
    artifact_threshold: int = 2000
    # Редактировать чувствительные данные в отчёте (raw остаётся в локальном артефакте).
    redact_report: bool = True


@dataclass
class RunConfig:
    attacker_user: str = ATTACKER_USER
    victim_user: str = VICTIM_USER
    secondary_user: str = SECONDARY_USER
    auth_mode: str = "vulnerable"
    reset_policy: str = "full"          # full | policy_only | none
    agent_call_retries: int = 2
    budgets: AttackBudget = field(default_factory=AttackBudget)
    trace: TraceOptions = field(default_factory=TraceOptions)
    tags: list[str] = field(default_factory=list)
    seed: int = 0

    def to_meta(self) -> dict:
        return {
            "attacker_user": self.attacker_user,
            "victim_user": self.victim_user,
            "secondary_user": self.secondary_user,
            "auth_mode": self.auth_mode,
            "reset_policy": self.reset_policy,
            "seed": self.seed,
            "budgets": {
                "max_iterations": self.budgets.max_iterations,
                "max_target_calls": self.budgets.max_target_calls,
                "max_attacker_calls": self.budgets.max_attacker_calls,
                "timeout_s": self.budgets.timeout_s,
                "no_improvement_patience": self.budgets.no_improvement_patience,
            },
        }
