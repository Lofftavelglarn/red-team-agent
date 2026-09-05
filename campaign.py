"""Кампания: повторы, наборы и последовательный запуск изолированных прогонов.

ТЗ §9: полный reset перед каждым scenario/repeat/candidate, проверка fingerprint,
раздельные baseline/benign-control/attack, seed и фактический порядок запуска.
Операции, меняющие общую память, НЕ параллелятся; конкурентность разрешена только
для доказанно read-only батча baseline на одном снимке.

Запуск (внутри контейнера agent-api):
  python -m redteam.campaign                       # весь enabled-набор, 1 повтор
  python -m redteam.campaign s1 s6                 # выбранные
  REDTEAM_REPEATS=5 python -m redteam.campaign     # 5 повторов -> ASR как частота
  REDTEAM_LOOP=3 python -m redteam.campaign s2     # адаптивная атака (до 3 мутаций)
  REDTEAM_RUN_DIR=/app/runs/bench python -m redteam.campaign
"""

from __future__ import annotations

import concurrent.futures as cf
import os
import random
import sys
import time

from redteam.config import CONCURRENCY, OUT_DIR, RunConfig
from redteam.models import AttackBudget, RunStatus


def build_components():
    from redteam.adjudicator import Adjudicator
    from redteam.target import InvestAgentTarget, MemoryObserver
    return InvestAgentTarget(), MemoryObserver(), Adjudicator()


def _reset_and_fingerprint(policy: str, user_ids: list[str]):
    from redteam import cleanup
    cleanup.reset_for_policy(policy)
    return cleanup.fingerprint(user_ids)


def run_campaign(scenario_ids: list[str], repeats: int, cfg: RunConfig,
                 run_dir: str, include_disabled: bool = False,
                 loop_iters: int = 0, seed: int = 0) -> dict:
    from redteam import cleanup
    from redteam.runner import run_scenario
    from redteam.scenarios import by_id, get_suite
    from redteam.strategy import StrategyLibrary

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
    if cfg.reset_policy == "full" and seed:
        random.Random(seed).shuffle(order)
    actual_order = [s.id for s in order]

    target, observer, adj = build_components()
    library = StrategyLibrary(os.path.join(run_dir, "strategy_library.jsonl"))

    # Батч baseline: только для полного сброса (состояние идентично между прогонами),
    # только read-only, конкурентно, на ЧИСТОМ состоянии.
    baseline_cache: dict[str, str] = {}
    if cfg.reset_policy == "full":
        cleanup.full_reset()
        probes = sorted({s.primary_probe for s in order if s.primary_probe})

        def _cap(p):
            try:
                return p, target.chat(cfg.victim_user, f"rt-baseline-{abs(hash(p))%9999}", p,
                                      auth_mode=cfg.auth_mode, retries=cfg.agent_call_retries)["content"]
            except Exception as exc:  # noqa: BLE001
                return p, f"<<baseline error: {exc}>>"
        with cf.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
            for p, ans in ex.map(_cap, probes):
                baseline_cache[p] = ans

    results = []
    for sc in order:
        for k in range(repeats):
            _reset_and_fingerprint(sc.reset_policy, user_ids)
            tag = f"{sc.id}" + (f" #{k+1}/{repeats}" if repeats > 1 else "")
            print(f"=== {tag} (loop={sc.budgets.max_iterations}) ===", flush=True)
            reset_fn = (lambda p=sc.reset_policy: cleanup.reset_for_policy(p)) \
                if sc.reset_policy != "none" else None
            fp_fn = (lambda: cleanup.fingerprint(user_ids)) if sc.reset_policy == "full" else None
            try:
                res = run_scenario(
                    target, observer, adj, sc, cfg, run_dir,
                    baseline_answer=baseline_cache.get(sc.primary_probe),
                    reset_fn=reset_fn, fingerprint_fn=fp_fn,
                    clean_fingerprint=cleanup.CLEAN_FINGERPRINT, strategy_library=library)
            except Exception as exc:  # noqa: BLE001 — устойчивость: сбой одного не рушит кампанию
                print(f"  ОШИБКА прогона: {exc!r}", flush=True)
                continue
            results.append(res)
            line = " ".join(f"{n}={r.status.value}" for n, r in res.checkpoints.items()
                            if n in ("STORED_GLOBAL", "RETRIEVAL_CANDIDATE",
                                     "BEHAVIOR_CHANGED", "UNSAFE_OUTPUT"))
            print(f"  status={res.status.value} | {line}", flush=True)

    from redteam.aggregate import aggregate
    report = aggregate(run_dir)
    report["seed"] = seed
    report["actual_order"] = actual_order
    report["n_completed"] = sum(1 for r in results if r.status == RunStatus.COMPLETED)
    import json
    with open(os.path.join(run_dir, "campaign.json"), "w", encoding="utf-8") as f:
        json.dump({"seed": seed, "actual_order": actual_order,
                   "repeats": repeats, "loop_iters": loop_iters}, f, ensure_ascii=False, indent=2)
    return report


def main(argv: list[str]) -> None:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_dir = os.environ.get("REDTEAM_RUN_DIR") or os.path.join(OUT_DIR, stamp)
    repeats = max(int(os.environ.get("REDTEAM_REPEATS", "1")), 1)
    loop_iters = int(os.environ.get("REDTEAM_LOOP", "0"))
    seed = int(os.environ.get("REDTEAM_SEED", "0"))
    include_disabled = os.environ.get("REDTEAM_INCLUDE_DISABLED") == "1"
    ids = [a for a in argv if not a.startswith("-")]

    cfg = RunConfig(reset_policy=os.environ.get("REDTEAM_RESET_MODE", "full"), seed=seed)
    report = run_campaign(ids, repeats, cfg, run_dir, include_disabled, loop_iters, seed)
    print(f"\nОтчёт и трассы: {run_dir}", flush=True)
    for c, v in report.get("rates", {}).items():
        print(f"  {c:26s} {v}", flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
