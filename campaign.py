"""Кампания: повторы, наборы и последовательный запуск изолированных прогонов.

Восстановление состояния перед каждым scenario/repeat/candidate, проверка fingerprint,
раздельные baseline/benign-control/attack, seed и фактический порядок запуска.
Операции, меняющие общую память, выполняются последовательно.

По умолчанию используется scoped-очистка: удаляются ТОЛЬКО артефакты этой кампании,
опознаваемые по префиксу сессий `rt-<campaign_id>-`. Полная очистка БД требует двух
явных подтверждений (REDTEAM_CLEANUP_MODE=full и REDTEAM_ALLOW_FULL_RESET=1).

Запуск (из отдельного контейнера red-team-agent):
  python -m redteam.campaign                       # весь enabled-набор, 1 повтор
  python -m redteam.campaign s1 s6                 # выбранные
  REDTEAM_REPEATS=5 python -m redteam.campaign     # 5 повторов -> ASR как частота
  REDTEAM_LOOP=3 python -m redteam.campaign s2     # адаптивная атака (до 3 мутаций)
  REDTEAM_RUN_DIR=/app/runs/bench python -m redteam.campaign
"""

from __future__ import annotations

import os
import random
import sys
import time
import uuid

from redteam.config import (
    ALLOW_FULL_RESET,
    CLEANUP_MODE,
    MONGO_DB,
    OUT_DIR,
    RunConfig,
    redis_db_number,
    resolve_cleanup_mode,
    safe_mongo_uri,
)
from redteam.models import AttackBudget, RunStatus


def build_components():
    from redteam.adjudicator import Adjudicator
    from redteam.target import InvestAgentTarget, MemoryObserver
    return InvestAgentTarget(), MemoryObserver(), Adjudicator()


def cleanup_summary(mode: str) -> dict:
    """Что и где будет изменено — без credentials, для консоли и manifest."""
    return {"cleanup_mode": mode, "mongo_target": f"{safe_mongo_uri()} / {MONGO_DB}",
            "redis_target": f"db {redis_db_number()}",
            "full_reset_allowed": bool(ALLOW_FULL_RESET)}


def run_campaign(scenario_ids: list[str], repeats: int, cfg: RunConfig,
                 run_dir: str, include_disabled: bool = False,
                 loop_iters: int = 0, seed: int = 0, fixtures_ready: bool = False,
                 admin=None, components=None) -> dict:
    from redteam.cleanup import CampaignScope, MemoryAdmin, restore
    from redteam.runner import run_scenario
    from redteam.scenarios import by_id, get_suite
    from redteam.strategy import StrategyLibrary

    # Режим очистки проверяется ДО любых обращений к хранилищам: full без второго
    # подтверждения не должен доходить до удаления данных.
    mode = resolve_cleanup_mode(cfg.cleanup_mode)
    summary = cleanup_summary(mode)
    print("  очистка: " + ", ".join(f"{k}={v}" for k, v in summary.items()), flush=True)
    admin = admin if admin is not None else MemoryAdmin()
    scope = CampaignScope(campaign_id=cfg.campaign_id,
                          user_ids=[cfg.attacker_user, cfg.victim_user, cfg.secondary_user],
                          started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    receipts: list[dict] = []

    os.makedirs(run_dir, exist_ok=True)
    scenarios = [by_id(i) for i in scenario_ids] if scenario_ids \
        else get_suite(include_disabled=include_disabled)

    # адаптивный бюджет: REDTEAM_LOOP переопределяет max_iterations сценария
    if loop_iters > 0:
        for sc in scenarios:
            sc.budgets = AttackBudget(
                max_iterations=loop_iters,
                max_target_calls=sc.budgets.max_target_calls,
                max_attacker_calls=sc.budgets.max_attacker_calls,
                timeout_s=sc.budgets.timeout_s,
                no_improvement_patience=sc.budgets.no_improvement_patience)

    user_ids = [cfg.attacker_user, cfg.victim_user, cfg.secondary_user]

    # Перемешивание порядка сценариев допустимо ТОЛЬКО при полной изоляции.
    order = list(scenarios)
    if seed:
        random.Random(seed).shuffle(order)
    actual_order = [s.id for s in order]

    target, observer, adj = components if components is not None else build_components()
    library = StrategyLibrary(os.path.join(run_dir, "strategy_library.jsonl"))

    def _restore(operation: str, **labels) -> dict:
        receipt = restore(admin, scope, operation=operation, mode=mode,
                          allow_full_reset=ALLOW_FULL_RESET, **labels)
        receipts.append(receipt)
        return receipt

    results = []
    for sc in order:
        for k in range(repeats):
            # PRE-RUN восстановление: снимаем артефакты предыдущего сценария этой кампании.
            pre = _restore("pre_scenario_restore", scenario_id=sc.id, repeat=k)
            if pre["errors"]:
                print(f"  reset warn: {pre['errors']}", flush=True)
            tag = f"{sc.id}" + (f" #{k+1}/{repeats}" if repeats > 1 else "")
            print(f"=== {tag} (loop={sc.budgets.max_iterations}) ===", flush=True)
            reset_fn = (lambda sid=sc.id, rep=k:
                        _restore("pre_candidate_restore", scenario_id=sid, repeat=rep))
            fp_fn = admin.fingerprint
            try:
                res = run_scenario(
                    target, observer, adj, sc, cfg, run_dir,
                    baseline_answer=None,  # baseline берётся в runner per-run (без кэша)
                    reset_fn=reset_fn, fingerprint_fn=fp_fn,
                    strategy_library=library, fixtures_ready=fixtures_ready, repeat=k)
            except Exception as exc:  # noqa: BLE001 — устойчивость: сбой одного не рушит кампанию
                print(f"  ОШИБКА прогона: {exc!r}", flush=True)
                continue
            results.append(res)
            line = " ".join(f"{n}={r.status.value}" for n, r in res.checkpoints.items()
                            if n in ("STORED_GLOBAL", "RETRIEVAL_CANDIDATE",
                                     "BEHAVIOR_CHANGED", "UNSAFE_OUTPUT"))
            print(f"  status={res.status.value} e2e={res.meta.get('end_to_end_reached')} | {line}", flush=True)

    from redteam.aggregate import aggregate
    report = aggregate(run_dir)
    report["seed"] = seed
    report["actual_order"] = actual_order
    report["n_completed"] = sum(1 for r in results if r.status == RunStatus.COMPLETED)
    report["cleanup"] = _cleanup_stats(summary, receipts)
    import json
    with open(os.path.join(run_dir, "campaign.json"), "w", encoding="utf-8") as f:
        json.dump({"campaign_id": cfg.campaign_id, "seed": seed,
                   "actual_order": actual_order, "repeats": repeats,
                   "loop_iters": loop_iters, "cleanup": summary,
                   "cleanup_receipts": receipts}, f, ensure_ascii=False, indent=2)
    return report


def _cleanup_stats(summary: dict, receipts: list[dict]) -> dict:
    """Сводка по всем операциям очистки кампании (без credentials)."""
    deleted: dict = {}
    for receipt in receipts:
        for name, count in (receipt.get("deleted") or {}).items():
            if isinstance(count, int):
                deleted[name] = deleted.get(name, 0) + count
    return {"mode": summary["cleanup_mode"],
            "operations": len(receipts),
            "failed_operations": sum(1 for r in receipts if r.get("errors")),
            "records_deleted": deleted,
            "initial_fingerprint": receipts[0].get("fingerprint_before") if receipts else None,
            "final_fingerprint": receipts[-1].get("fingerprint_after") if receipts else None}


def main(argv: list[str]) -> None:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    campaign_id = os.environ.get("REDTEAM_CAMPAIGN_ID") or uuid.uuid4().hex[:8]
    run_dir = os.environ.get("REDTEAM_RUN_DIR") or os.path.join(OUT_DIR, stamp)
    repeats = max(int(os.environ.get("REDTEAM_REPEATS", "1")), 1)
    loop_iters = int(os.environ.get("REDTEAM_LOOP", "0"))
    seed = int(os.environ.get("REDTEAM_SEED", "0"))
    include_disabled = os.environ.get("REDTEAM_INCLUDE_DISABLED") == "1"
    fixtures_ready = os.environ.get("REDTEAM_FIXTURES_READY") == "1"
    ids = [a for a in argv if not a.startswith("-")]

    cfg = RunConfig(auth_mode=os.environ.get("REDTEAM_AUTH_MODE", "vulnerable"),
                    cleanup_mode=CLEANUP_MODE, campaign_id=campaign_id, seed=seed)
    print(f"campaign_id={campaign_id}", flush=True)
    try:
        report = run_campaign(ids, repeats, cfg, run_dir, include_disabled, loop_iters, seed,
                              fixtures_ready)
    except RuntimeError as exc:      # небезопасная конфигурация очистки — до удаления данных
        print(f"кампания не запущена: {exc}", flush=True)
        raise SystemExit(2) from exc
    print(f"\nОтчёт и трассы: {run_dir}", flush=True)
    for c, v in report.get("rates", {}).items():
        print(f"  {c:26s} {v}", flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
