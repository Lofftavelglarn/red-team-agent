"""Конфигурация standalone red-team runner из переменных окружения."""

from __future__ import annotations

import os
import re
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

# Как кампания восстанавливает состояние стенда: scoped (по умолчанию) удаляет только
# артефакты кампании, full очищает всю выбранную БД, disabled ничего не меняет.
CLEANUP_MODES = ("scoped", "full", "disabled")
CLEANUP_MODE = os.getenv("REDTEAM_CLEANUP_MODE", "scoped").strip().lower() or "scoped"
# Полная очистка требует ВТОРОГО явного подтверждения — иначе она невозможна.
ALLOW_FULL_RESET = os.getenv("REDTEAM_ALLOW_FULL_RESET") == "1"
# Отладочный режим: не восстанавливать состояние после кампании.
KEEP_FINAL_STATE = os.getenv("REDTEAM_KEEP_FINAL_STATE") == "1"


def safe_mongo_uri(uri: str = MONGO_URI) -> str:
    """URI без credentials — для вывода в консоль, manifest и receipts."""
    return re.sub(r"://[^/@]*@", "://<redacted>@", uri)


def redis_db_number(url: str = REDIS_URL) -> str:
    """Номер Redis DB из URL (для подтверждения цели разрушительной операции)."""
    match = re.search(r"/(\d+)(?:\?|$)", url)
    return match.group(1) if match else "0"


def resolve_cleanup_mode(mode: str | None = None) -> str:
    """Проверить режим очистки и запретить full без второго флага."""
    value = (mode or CLEANUP_MODE).strip().lower()
    if value not in CLEANUP_MODES:
        raise RuntimeError(
            f"неизвестный REDTEAM_CLEANUP_MODE={value!r}; допустимо: {', '.join(CLEANUP_MODES)}")
    if value == "full" and not ALLOW_FULL_RESET:
        raise RuntimeError(
            "REDTEAM_CLEANUP_MODE=full удаляет ВСЕ данные из "
            f"{safe_mongo_uri()} (база {MONGO_DB}) и Redis db {redis_db_number()}. "
            "Подтвердите это REDTEAM_ALLOW_FULL_RESET=1 или используйте scoped.")
    return value


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
    return ModelConfig(
        role=normalized,
        model=os.getenv(f"{prefix}_MODEL", "").strip(),
        api_key=os.getenv(f"{prefix}_API_KEY", "").strip(),
        base_url=base_url,
        max_tokens=int(os.getenv(f"{prefix}_MAX_TOKENS", "4096")),
        temperature=float(os.getenv(f"{prefix}_TEMPERATURE", default_temperature)),
        timeout_s=float(os.getenv(f"{prefix}_TIMEOUT", "120")),
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
    # Как восстанавливается стенд (scoped|full|disabled) — не путать с candidate_state_policy
    # сценария, которая управляет только состоянием МЕЖДУ кандидатами.
    cleanup_mode: str = "scoped"
    campaign_id: str = ""
    agent_call_retries: int = 2
    budgets: AttackBudget = field(default_factory=AttackBudget)
    trace: TraceOptions = field(default_factory=TraceOptions)
    tags: list[str] = field(default_factory=list)
    seed: int = 0

    @property
    def user_ids(self) -> list[str]:
        return [self.attacker_user, self.victim_user, self.secondary_user]

    def to_meta(self) -> dict:
        return {
            "attacker_user": self.attacker_user,
            "victim_user": self.victim_user,
            "secondary_user": self.secondary_user,
            "auth_mode": self.auth_mode,
            "cleanup_mode": self.cleanup_mode,
            "campaign_id": self.campaign_id,
            "mongo_target": f"{safe_mongo_uri()} / {MONGO_DB}",
            "redis_target": f"db {redis_db_number()}",
            "seed": self.seed,
            "budgets": {
                "max_iterations": self.budgets.max_iterations,
                "max_target_calls": self.budgets.max_target_calls,
                "max_attacker_calls": self.budgets.max_attacker_calls,
                "timeout_s": self.budgets.timeout_s,
                "no_improvement_patience": self.budgets.no_improvement_patience,
            },
        }
