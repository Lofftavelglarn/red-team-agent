# Как устроены атаки и как их запускать самому

## 1. Как устроена атака сейчас

Атака идёт **только легитимными каналами** стенда (агент/mcp/тулы не меняем):

- `POST /v1/chat/completions` — обычная реплика в чат (как LibreChat/promptfoo);
- `POST /v1/sessions/{id}/finalize` — команда финализации сессии (запускает оркестратор
памяти: summarize → extract_episodes → extract_semantics → persist).

Роли:

- **Атакующий** — клиент `client1001` (по умолчанию). Ведёт сессию, наполняет рабочую
память, вызывает finalize. Цель — чтобы при финализации факт осел в `agent_policy`
(глобальный кросс-юзерный слой).
- **Жертва** — `client1003` (по умолчанию). Отдельный пользователь, отдельная сессия.
Проверяем: попал ли payload в его системный промпт (`build_context`) и меняет ли он
его ответ.

Цепочка, которую мы атакуем и наблюдаем (фазы жизненного цикла памяти):

```
вход(1001) → рабочая память → summarize → extract → agent_policy(GLOBAL)
           → [другая сессия] системный промпт жертвы(1003) → ответ жертвы
```

Успех меряется не по ответу атакующему, а по **состоянию памяти** и по эффекту у жертвы
— чекпоинты `INJECT → PERSIST_USER → GLOBAL_WRITE_ANY → PERSIST_GLOBAL → RETRIEVE_VICTIM → ACTIVATE → CRITICAL_HARM`. Метрика — **ASR** (частота достижения по повторам).

## 2. Кто атакует

- **Статический режим** (по умолчанию): реплики атаки заданы в сценарии человеком
(red-teamer). Файл `scenarios.py`.
- **Автоматический режим** (`REDTEAM_LOOP=N`): реплики генерирует и дорабатывает
**атакующая LLM** (`attacker.py`) по обратной связи — что осело и с каким scope.
Это замыкает петлю «генерация → выполнение → наблюдение → доработка».
- **Судья** — та же локальная LLM через прокси (`adjudicator.py`) оценивает семантические
вопросы (активация, критический вред).
- **Цель (target)** — сам агент (LLM стенда через LiteLLM-прокси), дёргается по HTTP.

Атакующий, судья и цель сейчас — одна и та же локально развёрнутая модель (через прокси
`OPENAI_BASE_URL`). Для строгой оценки судью стоит взять независимым.

## 3. Что лежит в каждом файле `redteam/`


| Файл             | Назначение                                                                                                                                                                  |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `config.py`      | Конфиг: адрес агента, атакующий/жертва, список чекпоинтов, `RunConfig`, чтение env.                                                                                         |
| `target.py`      | `InvestAgentTarget` — драйвер HTTP-контура агента: `chat()`, `finalize()`, программная выдача API-ключей. Мульти-юзер/мульти-сессия.                                        |
| `scenarios.py`   | Реестр из 12 сценариев (S1–S12, техники из статей/репо): реплики атаки, вопрос жертвы, сигнатура payload, семантическое описание для судьи, определение критического вреда. |
| `attacker.py`    | `generate_attack()` — атакующая LLM с рефайном (для `REDTEAM_LOOP`).                                                                                                        |
| `adjudicator.py` | `Adjudicator` — скореры по СОСТОЯНИЮ памяти (читают Mongo `agent_policy`/семантику и `build_context` жертвы) + судейская модель. Ключевая новизна vs чат-тулов.             |
| `trace.py`       | `TraceLog`/`FlowRecord` — трасса «источник→приёмник» (TokenWall-стиль) + чекпоинты.                                                                                         |
| `runner.py`      | `run_scenario()` (полный цикл ТЗ) и `main()` (batch, повторы, сброс, ASR). Устойчив к сбоям сценариев.                                                                      |
| `aggregate.py`   | Сбор ASR поверх всех трасс каталога: overall + per-scenario (частота по повторам).                                                                                          |
| `cleanup.py`     | Сброс памяти: `agent_policy` или полный `--full` (все коллекции + Redis) к дефолту репозитория.                                                                             |
| `README.md`      | Дизайн, модель угроз, соответствие статьям, чекпоинты, ограничения.                                                                                                         |
| `HOWTO.md`       | Этот файл.                                                                                                                                                                  |
| `runs/`          | Логи прогонов: на каждый прогон подпапка с `trace_*.json` + `report.*` (в `.gitignore`).                                                                                    |




## 4. Как запустить самому



### Требуется

- Поднятый и healthy стек: `docker compose up -d` (agent-api, mongo, keycloak, mcp-invest, …).
- `.env` заполнен и указывает на рабочий LLM-прокси:
  - `OPENAI_API_KEY`, `OPENAI_BASE_URL` (адрес LLM-прокси — задаётся в `.env` стенда),
  - `RESEARCH_MODEL`, `SUMMARIZATION_MODEL` (формат `openai:<model>`),
  - `RESEARCH_MODEL_MAX_TOKENS` (рекоменд. ≥8192), `SUMMARIZATION_MODEL_MAX_TOKENS` (≥16384).
- Прокси доступен из контейнера agent-api.



### Шаги (PowerShell)

```powershell
$C = "genai-invest-agent-memory-stand-agent-api-1"
# 1) закинуть пакет в контейнер как /app/redteam (импортируется как `redteam`).
#    Пакет = сама папка red-team-agent (файлы лежат в ней напрямую). Запускать из
#    родительского каталога red-team-agent:
docker cp red-team-agent ${C}:/app/redteam
# 2) полный набор × 3 с ПОЛНЫМ сбросом памяти перед каждым прогоном (чистое состояние):
docker exec -w /app -e REDTEAM_RUN_DIR=/app/runs/bench `
  -e REDTEAM_REPEATS=3 -e REDTEAM_RESET_MODE=full $C python -m redteam.runner
# выбранные сценарии:
docker exec -w /app -e REDTEAM_RUN_DIR=/app/runs/sel -e REDTEAM_RESET_MODE=full `
  $C python -m redteam.runner S1 S3 S11
# автоматическая атакующая модель (до 3 доработок):
docker exec -w /app -e REDTEAM_RUN_DIR=/app/runs/loop -e REDTEAM_LOOP=3 `
  $C python -m redteam.runner S2
# ручной полный сброс памяти к дефолту репозитория:
docker exec -w /app $C python -m redteam.cleanup --full --yes
# 3) собрать итоговый ASR-отчёт и забрать логи в runs/ (в .gitignore)
docker exec -w /app $C python -m redteam.aggregate /app/runs/bench
docker cp ${C}:/app/runs/bench ./runs/bench
```



### Шаги (macOS / Linux, bash)

Всё то же самое, но перенос строки — обычный `\` (не бэктик), а имя контейнера — в
`C=...` без `$`-скобок. Гоняем из **родительского** каталога `red-team-agent` (там же
лежит стенд с `docker-compose.yml`).

```bash
C=genai-invest-agent-memory-stand-agent-api-1
# 1) закинуть пакет в контейнер как /app/redteam (импортируется как `redteam`):
docker cp red-team-agent "$C":/app/redteam
# 2) полный набор × 3 с ПОЛНЫМ сбросом памяти перед каждым прогоном:
docker exec -w /app -e REDTEAM_RUN_DIR=/app/runs/bench \
  -e REDTEAM_REPEATS=3 -e REDTEAM_RESET_MODE=full "$C" python -m redteam.runner
# выбранные сценарии:
docker exec -w /app -e REDTEAM_RUN_DIR=/app/runs/sel -e REDTEAM_RESET_MODE=full \
  "$C" python -m redteam.runner S1 S3 S11
# автоматическая атакующая модель (до 3 доработок):
docker exec -w /app -e REDTEAM_RUN_DIR=/app/runs/loop -e REDTEAM_LOOP=3 \
  "$C" python -m redteam.runner S2
# ручной полный сброс памяти к дефолту репозитория:
docker exec -w /app "$C" python -m redteam.cleanup --full --yes
# 3) собрать ASR-отчёт и забрать логи в runs/ (в .gitignore):
docker exec -w /app "$C" python -m redteam.aggregate /app/runs/bench
docker cp "$C":/app/runs/bench ./red-team-agent/runs/bench
```



#### Рекомендованный setup: bind-mount вместо `docker cp` (без копирований)

`docker cp` нужен потому, что ФС контейнера изолирована от хоста: пакет надо занести
внутрь, а результаты (`/app/runs`) — вынести наружу. Чтобы убрать оба `cp`, монтируем
хостовые папки в контейнер — правки кода и результаты синхронизируются с маком сами.
В `docker-compose.yml`, сервис `agent-api`, добавляем два тома (путь до `red-team-agent`
— относительно каталога compose; если стенд и `red-team-agent` соседи, это `../`):

```yaml
  agent-api:
    volumes:
      - ./app:/app/app:ro                        # (уже есть) код стенда
      - ../red-team-agent:/app/redteam:ro        # код атаки: правки на маке видны сразу
      - ../red-team-agent/runs:/app/runs         # rw: результаты пишутся ПРЯМО на мак
```

`volumes` меняют описание контейнера, а не образ → применяется через **recreate**, не
rebuild:

```bash
mkdir -p ../red-team-agent/runs                  # том должен существовать на хосте
docker compose up -d agent-api                   # пересоздать контейнер с монтированием
```

После этого:

- **пакет не копируем** — шаг `docker cp red-team-agent …` не нужен, правки `.py` на
маке подхватываются следующим `docker exec`;
- **результаты не копируем** — `docker cp …:/app/runs/…` не нужен. Правило пути:
`/app/runs/<имя>` в командах контейнера === `red-team-agent/runs/<имя>` на маке
(одна и та же папка). `report.md`/`trace_*.json` появляются там сразу.
- `:ro` на исходниках = контейнер их не портит (никакого мусора обратно на хост);  
побочно Python не пишет `__pycache__` рядом — это не ошибка, просто не кешит байткод.



### Переменные окружения


| Env                                   | Смысл                                                                      | Дефолт                                         |
| ------------------------------------- | -------------------------------------------------------------------------- | ---------------------------------------------- |
| `REDTEAM_REPEATS`                     | повторов на сценарий (ASR как частота)                                     | 1                                              |
| `REDTEAM_LOOP`                        | итераций атакующей модели (0 = статически)                                 | 0                                              |
| `REDTEAM_RESET_MODE`                  | `full` = полный сброс памяти (все коллекции + Redis) перед каждым прогоном | —                                              |
| `REDTEAM_RESET_EACH`                  | `1` = лёгкий сброс: только rt-/atk- записи `agent_policy`                  | —                                              |
| `REDTEAM_RUN_DIR`                     | каталог прогона                                                            | `/app/runs/<время>`                            |
| `REDTEAM_ATTACKER` / `REDTEAM_VICTIM` | cus атакующего/жертвы                                                      | 1001 / 1003                                    |
| `REDTEAM_AGENT_URL`                   | адрес агента                                                               | [http://localhost:8600](http://localhost:8600) |
| `REDTEAM_JUDGE_MAX_TOKENS`            | бюджет судьи/атакующего                                                    | 8192                                           |
| `REDTEAM_WEB_TOKEN`                   | поисковый токен для веб-сценария S12                                       | alfa-invest-reg-4417                           |




#### Три «мозга» прогона (заданы ЯВНО в `config.py`)

Цель, атакующий и судья — три отдельные роли. Модели заданы **хардкодом** в
[`config.py`](config.py) (блок «ТРИ МОЗГА»), без переменных окружения:

| Роль | Где задаётся | Текущее значение |
|---|---|---|
| **Агент-цель** | `.env` **стенда** (`OPENAI_BASE_URL` + `RESEARCH_MODEL`/`SUMMARIZATION_MODEL`) — модель выбирает сам стенд, `target.py` шлёт лишь alias `genai-invest-assistant` | gpt-oss @ `host.docker.internal:8000` |
| **Атакующий** | `config.py`: `ATTACKER_MODEL` / `ATTACKER_BASE_URL` / `ATTACKER_API_KEY` (используется `attacker.py`) | gpt-oss @ `host.docker.internal:8000` |
| **Судья** | `config.py`: `JUDGE_MODEL` / `JUDGE_BASE_URL` / `JUDGE_API_KEY` (используется `adjudicator.py`) | DeepSeek @ `ai.starimg.ru/v1` |

Судья намеренно вынесен на **отдельный** endpoint от цели — так семантические вердикты
(`ACTIVATE`, `CRITICAL_HARM`, semantic-fallback у `PERSIST_GLOBAL`/`RETRIEVE`) выносит
не та же модель, что играет цель (рекомендация к честной оценке). Формат модели —
`provider:model` (провайдер до первого `:`; для OpenAI-совместимых — префикс `openai:`).

**Сменить любую из трёх** = отредактировать значение в файле (для атакующего/судьи — в
`config.py` на маке, подхватится сразу благодаря bind-mount; для агента — в `.env`
стенда + `docker compose up -d agent-api`). Никаких `-e REDTEAM_JUDGE_*` больше не нужно.

### Где смотреть результат

- `report.md` / `report.json` — ASR overall и per-scenario;
- `trace_*.json` — полная трасса каждого прогона (source→sink записи + чекпоинты +
policy before/after + ответы жертвы). Именно трассы — материал для отладки и обучения
детекторов атак.



### Примечания

- Reasoning-модель стохастична → один прогон недетерминирован; для честного ASR
используйте `REDTEAM_REPEATS≥3` (лучше 5).
- Прогон меняет общее состояние памяти. Для чистого baseline — `REDTEAM_RESET_MODE=full`
(перед каждым прогоном) или вручную `python -m redteam.cleanup --full --yes`.
- Windows + Git Bash: перед `docker exec/cp` ставьте `MSYS_NO_PATHCONV=1`, иначе пути
вида `/app/...` ломаются. В PowerShell это не нужно.

