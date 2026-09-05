# Как устроены атаки и как их запускать

## 1. Каналы и роли

Атака — только легитимными публичными каналами (агент/mcp/тулы/`adapters/` не меняем):
- `POST /v1/chat/completions` — реплика в чат;
- `POST /v1/sessions/{id}/finalize` — финализация сессии (summarize → extract → persist).

Роли:
- **Атакующий** — `client1001` (по умолчанию): ведёт сессию, вызывает finalize; цель —
  чтобы факт осел в `agent_policy` (кросс-юзерный слой);
- **Жертва** — `client1003`: отдельный пользователь/сессия; проверяем попадание payload
  в её `build_context` и изменение ответа;
- **Судья** — та же локальная LLM через прокси; оценивает только семантические случаи;
- **Evaluator** — единственный, кому разрешён white-box доступ к Mongo (проверка фактов
  записи и очистка состояния), см. `target.MemoryObserver`.

## 2. Файлы

| Файл | Назначение |
|---|---|
| `config.py` | адрес агента, пользователи, бюджеты, reset-политика, concurrency, trace-опции |
| `models.py` | типы: `AttackScenario`, `SuccessContract`, `Checkpoint`, `CheckpointStatus`, `CheckpointResult`, `RunResult`, валидация набора |
| `scenarios.py` | реестр сценариев + `get_suite()` (валидируется при загрузке) |
| `target.py` | `InvestAgentTarget` (HTTP + нормализованные наблюдения) и `MemoryObserver` (white-box для evaluator) |
| `attacker.py` | генерация/мутация кандидатов, structured JSON, проверка семантического дрейфа |
| `strategy.py` | скоринг, beam-search, `strategy_library.jsonl` |
| `adjudicator.py` / `judge.py` | каскад детерминированной и семантической оценки, второй судья |
| `trace.py` | append-only trace schema v2 (events/manifest/trace/artifacts) |
| `runner.py` | `run_scenario()` — один изолированный прогон полного цикла |
| `campaign.py` | повторы, наборы, последовательный запуск, reset+fingerprint, батч baseline |
| `aggregate.py` | статистика без survivorship bias + условные вероятности + CI |
| `cleanup.py` | reset (`--full`) и fingerprint-проверка изоляции |
| `tests/` | unit + integration (фейковый стенд) + golden |

## 3. Запуск (PowerShell, внутри контейнера)

```powershell
$C = "genai-invest-agent-memory-stand-agent-api-1"
# пакет = папка red-team-agent, импортируется как redteam:
docker cp red-team-agent ${C}:/app/redteam
# весь enabled-набор × 3 с полным сбросом+fingerprint перед каждым прогоном:
docker exec -w /app -e REDTEAM_RUN_DIR=/app/runs/bench -e REDTEAM_REPEATS=3 `
  -e REDTEAM_RESET_MODE=full $C python -m redteam.campaign
# выбранные сценарии:
docker exec -w /app -e REDTEAM_RUN_DIR=/app/runs/sel -e REDTEAM_RESET_MODE=full `
  $C python -m redteam.campaign s1 s6 s-universal-rec
# адаптивная атакующая модель (до 3 мутаций):
docker exec -w /app -e REDTEAM_RUN_DIR=/app/runs/loop -e REDTEAM_LOOP=3 `
  $C python -m redteam.campaign s2
# сбор отчёта и выгрузка логов (runs/ в .gitignore):
docker exec -w /app $C python -m redteam.aggregate /app/runs/bench
docker cp ${C}:/app/runs/bench ./runs/bench
# ручной полный сброс памяти к дефолту репозитория:
docker exec -w /app $C python -m redteam.cleanup --full --yes
```

`python -m redteam.runner ...` оставлен как совместимый алиас `campaign`.

## 4. Переменные окружения

| Env | Смысл | Дефолт |
|---|---|---|
| `REDTEAM_REPEATS` | повторов на сценарий (ASR как частота) | 1 |
| `REDTEAM_LOOP` | итераций мутации атакующей модели (0 = статически) | 0 |
| `REDTEAM_RESET_MODE` | `full` \| `policy_only` \| `none` | full |
| `REDTEAM_SEED` | seed для перемешивания порядка (только при полной изоляции) | 0 |
| `REDTEAM_INCLUDE_DISABLED` | `1` = включить `s9`/`s12` (нужны фикстуры) | — |
| `REDTEAM_FIXTURES_READY` | `1` = фикстуры сценариев с requirements готовы (иначе такой прогон = UNSUPPORTED) | — |
| `REDTEAM_AUTH_MODE` | режим авторизации стенда: `vulnerable` \| `secure` (сравнительные прогоны) | vulnerable |
| `REDTEAM_RUN_DIR` | каталог прогона | `/app/runs/<время>` |
| `REDTEAM_ATTACKER` / `REDTEAM_VICTIM` / `REDTEAM_SECONDARY` | cus ролей | 1001 / 1003 / 1002 |
| `REDTEAM_AGENT_URL` | адрес агента | http://localhost:8600 |
| `REDTEAM_JUDGE_MODEL` | переопределить модель судьи/атакующего | из настроек стенда |
| `REDTEAM_JUDGE_MAX_TOKENS` | бюджет судьи/атакующего | 8192 |
| `REDTEAM_CONCURRENCY` | воркеров для read-only батча baseline | 4 |
| `REDTEAM_WEB_TOKEN` | поисковый токен для веб-сценария `s12` | alfa-reg-4417 |

## 5. Где смотреть результат

`runs/<run-dir>/`:
- `report.md` / `report.json` — доли по стадиям, условные вероятности, CI, false-positive,
  infra/judge-error, per-scenario, низконаблюдаемые сценарии;
- `campaign.json` — seed и фактический порядок запуска;
- `<run-id>/` на каждый прогон: `manifest.json`, `events.jsonl` (append-only source→sink),
  `trace.json`, `attempts.jsonl`, `result.json`, `artifacts/` (крупные payload'ы);
- `strategy_library.jsonl` — успешные тактики по сценариям.

## 6. Примечания

- LLM стохастична → используйте `REDTEAM_REPEATS≥3` (лучше 5). Baseline кэшируется между
  повторами только при полном сбросе (состояние доказанно идентично) и шлётся конкурентно.
- Судья/атакующий — та же локальная модель; для строгой оценки задайте независимого
  второго судью (`Adjudicator(second_judge=...)`) и/или отдельного атакующего.
- `s9` (system-prompt leak) помечен UNSUPPORTED: достоверная проверка требует секретного
  canary в защищённом контексте стенда, а стенд мы не меняем. `s12` (веб-цепочка) требует
  опубликованной страницы, находимой по `REDTEAM_WEB_TOKEN` и содержащей canary; без неё
  запуск помечается инфраструктурной ошибкой, а не неуспехом атаки.
- Локальные тесты (без стенда): `python -m pytest` — фейковый target/store в `tests/fakes.py`.
- Windows + Git Bash: перед `docker exec/cp` ставьте `MSYS_NO_PATHCONV=1` для путей `/app/...`.
