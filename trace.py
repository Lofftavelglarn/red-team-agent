"""Структурированная трасса в стиле TokenWall (2607.08395): каждое критичное
взаимодействие агента — это natural-language token flow «источник → приёмник».
Мы протоколируем все такие потоки, чтобы сторонние или наши детекторы могли
искать компрометацию не в финальном ответе, а во внутренней цепочке.

Трасса — самодостаточный JSON на прогон сценария: пригодна для offline-анализа,
обучения детекторов и ручного разбора.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field


# Типы источников/приёмников = точки жизненного цикла памяти и вызова тулов.
SOURCES = {
    "user_input", "assistant", "tool_result", "summarizer", "extractor",
    "memory_semantic", "memory_policy", "memory_working", "system_prompt",
}
SINKS = {
    "working_memory", "semantic_store", "agent_policy", "system_prompt",
    "tool_arg", "tool_call", "final_answer", "session_summary",
}


@dataclass
class FlowRecord:
    """Один поток «источник → приёмник» с полезным содержимым и метками."""
    seq: int
    checkpoint: str                    # к какой фазе жизненного цикла относится
    source: str                        # из SOURCES
    sink: str                          # из SINKS
    content: str
    labels: dict = field(default_factory=dict)  # scope, user_id, session_id, tool, ...
    ts: float = field(default_factory=time.time)


@dataclass
class TraceLog:
    scenario_id: str
    run_id: str
    config: dict
    records: list = field(default_factory=list)
    checkpoints: dict = field(default_factory=dict)   # checkpoint -> {"reached":bool,"evidence":...}
    meta: dict = field(default_factory=dict)
    _seq: int = 0

    def flow(self, checkpoint: str, source: str, sink: str, content: str, **labels) -> None:
        self._seq += 1
        self.records.append(FlowRecord(
            seq=self._seq, checkpoint=checkpoint, source=source, sink=sink,
            content=content if isinstance(content, str) else json.dumps(content, ensure_ascii=False),
            labels=labels,
        ))

    def set_checkpoint(self, name: str, reached: bool, **evidence) -> None:
        self.checkpoints[name] = {"reached": bool(reached), "evidence": evidence}

    def to_dict(self) -> dict:
        d = {
            "scenario_id": self.scenario_id,
            "run_id": self.run_id,
            "config": self.config,
            "checkpoints": self.checkpoints,
            "meta": self.meta,
            "records": [asdict(r) for r in self.records],
        }
        return d

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
