"""Конфигурация standalone red-team runner из переменных окружения."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from redteam.models import AttackBudget


# При локальном запуске читается red-team-agent/.env. В Docker значения передаёт Compose.
try:
    from dotenv import load_dotenv
except ImportError:  # тесты чистого ядра могут запускаться без runtime-зависимостей
    pass
else:
    load_dotenv()


AGENT_BASE_URL = os.getenv("REDTEAM_AGENT_URL", "http://localhost:8600")
MONGO_URI = os.getenv("REDTEAM_MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("REDTEAM_MONGO_DB", "agent_memory")
REDIS_URL = os.getenv("REDTEAM_REDIS_URL", "redis://localhost:6379/0")
OUT_DIR = os.getenv("REDTEAM_OUT_DIR", "/app/runs")

ATTACKER_USER = os.getenv("REDTEAM_ATTACKER", "1001")
VICTIM_USER = os.getenv("REDTEAM_VICTIM", "1003")
SECONDARY_USER = os.getenv("REDTEAM_SECONDARY", "1002")

ATTACKER_TARGET_API_KEY = os.getenv("REDTEAM_TARGET_ATTACKER_API_KEY", "")
VICTIM_TARGET_API_KEY = os.getenv("REDTEAM_TARGET_VICTIM_API_KEY", "")
SECONDARY_TARGET_API_KEY = os.getenv("REDTEAM_TARGET_SECONDARY_API_KEY", "")

POLICY_CONTEXT_LIMIT = int(os.getenv("REDTEAM_POLICY_CONTEXT_LIMIT", "20"))


@dataclass(frozen=True)
class ModelConfig:
    """Настройки одной OpenAI-compatible модели без наследования конфигурации стенда."""

    role: str
    model: str
    api_key: str
    base_url: str | None
    max_tokens: int
    temperature: float
    timeout_s: float
    disable_thinking: bool

    def validate(self) -> None:
        missing = []
        if not self.model:
            missing.append(f"REDTEAM_{self.role.upper()}_MODEL")
        if not self.api_key:
            missing.append(f"REDTEAM_{self.role.upper()}_API_KEY")
        if missing:
            raise RuntimeError("Не заданы переменные модели: " + ", ".join(missing))


def model_config(role: str) -> ModelConfig:
    """Вернуть независимую конфигурацию attacker или judge."""
    normalized = role.lower()
    if normalized not in {"attacker", "judge"}:
        raise ValueError(f"unknown model role: {role}")
    prefix = f"REDTEAM_{normalized.upper()}"
    base_url = os.getenv(f"{prefix}_BASE_URL", "").strip() or None
    default_temperature = "0.7" if normalized == "attacker" else "0"
    # Reasoning-модели (Qwen3/huihui) без этого возвращают пустой content. По умолчанию
    # глушим thinking у атакующего и НЕ трогаем судью (его провайдер может не принимать
    # extra_body). Переопределяется REDTEAM_<ROLE>_DISABLE_THINKING=0/1.
    default_disable_thinking = "1" if normalized == "attacker" else "0"
    disable_thinking = os.getenv(
        f"{prefix}_DISABLE_THINKING", default_disable_thinking
    ).strip().lower() in {"1", "true", "yes", "on"}
    return ModelConfig(
        role=normalized,
        model=os.getenv(f"{prefix}_MODEL", "").strip(),
        api_key=os.getenv(f"{prefix}_API_KEY", "").strip(),
        base_url=base_url,
        max_tokens=int(os.getenv(f"{prefix}_MAX_TOKENS", "4096")),
        temperature=float(os.getenv(f"{prefix}_TEMPERATURE", default_temperature)),
        timeout_s=float(os.getenv(f"{prefix}_TIMEOUT", "120")),
        disable_thinking=disable_thinking,
    )


def target_api_keys() -> dict[str, str]:
    """API-ключи стенда по ролям; пустые значения проверяются при первом запросе."""
    return {
        ATTACKER_USER: ATTACKER_TARGET_API_KEY,
        VICTIM_USER: VICTIM_TARGET_API_KEY,
        SECONDARY_USER: SECONDARY_TARGET_API_KEY,
    }


@dataclass
class TraceOptions:
    artifact_threshold: int = 2000
    redact_report: bool = True


@dataclass
class RunConfig:
    attacker_user: str = ATTACKER_USER
    victim_user: str = VICTIM_USER
    secondary_user: str = SECONDARY_USER
    auth_mode: str = "vulnerable"
    reset_policy: str = "full"
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
