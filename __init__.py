"""Red-team benchmark для атак на память финансового агента (стенд GenAI-инвестассистента).

Атака идёт только легитимными публичными каналами (chat + finalize). Модули:
  config/models/scenarios — типизированные определения и настройки;
  target — HTTP-контур и white-box наблюдатель памяти (только для evaluator);
  attacker/strategy — генерация, мутация и ранжирование кандидатов;
  adjudicator/judge — каскад детерминированной и семантической оценки;
  trace — доказательная append-only трасса schema v2;
  runner/campaign — оркестрация изолированного прогона и кампании;
  aggregate — статистика без survivorship bias;
  cleanup — reset и fingerprint-проверка изоляции.

См. README.md: отдельный Docker-запуск, конфигурация моделей, сценарии и результаты.
"""
