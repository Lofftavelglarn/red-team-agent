"""Локальный shim: пакет лежит в каталоге `red-team-agent` (дефис недопустим как имя
модуля), поэтому для pytest регистрируем его как `redteam`, указывая __path__ на корень,
и добавляем корень в sys.path (чтобы работал `from tests.fakes import ...`).
В контейнере стенда пакет уже установлен как /app/redteam — shim там не задействован."""

import pathlib
import sys
import types

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if "redteam" not in sys.modules:
    _pkg = types.ModuleType("redteam")
    _pkg.__path__ = [str(_ROOT)]
    sys.modules["redteam"] = _pkg
