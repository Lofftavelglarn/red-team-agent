# Red-Team Agent — веб-консоль

Веб-интерфейс вокруг standalone red-team runner: выбор сценариев, параметры
`REDTEAM_LOOP` / `REDTEAM_REPEATS` / `REDTEAM_AUTH_MODE` / `REDTEAM_SEED`, запуск
кампании и отчёт.

## Запуск

```bash
red-team-agent/webui/run.sh          # http://127.0.0.1:8700
red-team-agent/webui/run.sh 9000     # другой порт
```

или напрямую (важно использовать venv проекта — нужен пакет `redteam` для каталога):

```bash
red-team-agent/.venv/bin/python webui/server.py --port 8700
```

## Что делает

- **Новый прогон** — таблица всех сценариев (severity, канал, теги; отключённые
  помечены как требующие фикстур). Фильтр по тексту/severity, быстрые пресеты
  (core / все включённые / все / очистить). Ползунки и поля для LOOP, REPEATS,
  переключатель AUTH_MODE, SEED. Кнопка **Preflight** гоняет `redteam.doctor`.
- **Запуск** — сервер выполняет ровно `docker compose run --rm ... red-team-agent <ids>`
  из каталога `red-team-agent`, прокидывая параметры через `-e REDTEAM_*` и
  `REDTEAM_RUN_DIR=/app/runs/<run_id>` (полный путь — не теряется под `--rm`).
  Прогоны идут по одному (память стенда общая).
- **Живой лог** — прогресс кампании построчно, с остановкой.
- **Отчёт** — читает `runs/<run_id>/report.json`: e2e ASR с CI, KPI по стадиям,
  kill-chain воронка с условными переходами, распределение точек обрыва маршрута,
  таблица по сценариям (сортируемая), качество/наблюдаемость, сырой JSON,
  скачивание report.md / report.json.

Лог и метаданные каждого прогона — в `webui/state/<run_id>.{log,meta.json}`.
Настройки цели и моделей берутся из `red-team-agent/.env` (секреты не отдаются в UI).
