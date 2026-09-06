"""Веб-интерфейс вокруг red-team-agent.

Лёгкий сервер только на стандартной библиотеке (без Flask/FastAPI). Запускать
через venv проекта, чтобы был доступен пакет `redteam` для живого каталога
сценариев:

    red-team-agent/.venv/bin/python webui/server.py            # http://localhost:8700
    red-team-agent/.venv/bin/python webui/server.py --port 8700

Кампании запускаются как подпроцесс `docker compose run --rm ...` из каталога
red-team-agent — ровно так, как описано в README. Результаты пишутся в
смонтированный каталог runs/, лог и метаданные каждого запуска — в webui/state/.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

WEBUI_DIR = pathlib.Path(__file__).resolve().parent
REPO_DIR = WEBUI_DIR.parent            # каталог red-team-agent (где docker-compose.yml)
STATIC_DIR = WEBUI_DIR / "static"
STATE_DIR = WEBUI_DIR / "state"
RUNS_DIR = REPO_DIR / "runs"
STATE_DIR.mkdir(exist_ok=True)

AUTH_MODES = {"vulnerable", "protected"}
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SCENARIO_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")

# ── Реестр активных прогонов (в памяти) ─────────────────────────────────────
_runs_lock = threading.Lock()
_active: dict[str, dict] = {}   # run_id -> {proc, status, thread, ...}


# ── Каталог сценариев ───────────────────────────────────────────────────────
def _load_scenarios() -> list[dict]:
    """Живой каталог из пакета redteam. Регистрируем shim как в tests/conftest.py."""
    if "redteam" not in sys.modules:
        if str(REPO_DIR) not in sys.path:
            sys.path.insert(0, str(REPO_DIR))
        pkg = types.ModuleType("redteam")
        pkg.__path__ = [str(REPO_DIR)]
        sys.modules["redteam"] = pkg
    from redteam.scenarios import get_suite  # noqa: WPS433

    rows = []
    for s in get_suite(include_disabled=True):
        rows.append(
            {
                "id": s.id,
                "title": s.title,
                "objective": s.objective,
                "severity": s.severity,
                "channel": s.attack_channel,
                "persistence": s.persistence_route,
                "tags": list(s.tags),
                "enabled": bool(s.enabled_by_default),
                "requirements": list(s.requirements),
            }
        )
    return rows


_SCENARIO_CACHE: list[dict] | None = None


def scenarios() -> list[dict]:
    global _SCENARIO_CACHE
    if _SCENARIO_CACHE is None:
        _SCENARIO_CACHE = _load_scenarios()
    return _SCENARIO_CACHE


def valid_scenario_ids() -> set[str]:
    return {s["id"] for s in scenarios()}


# ── Конфигурация цели (из .env, без секретов) ───────────────────────────────
def _read_env_file() -> dict[str, str]:
    env: dict[str, str] = {}
    p = REPO_DIR / ".env"
    if not p.exists():
        return env
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip()
    return env


def _mask(v: str) -> str:
    if not v:
        return ""
    if len(v) <= 8:
        return "•" * len(v)
    return f"{v[:4]}…{v[-3:]}"


def config_summary() -> dict:
    env = _read_env_file()
    secret = lambda k: _mask(env.get(k, ""))  # noqa: E731
    return {
        "target_url": env.get("REDTEAM_AGENT_URL", "http://host.docker.internal:8600"),
        "mongo": env.get("REDTEAM_MONGO_URI", ""),
        "redis": env.get("REDTEAM_REDIS_URL", ""),
        "attacker_model": env.get("REDTEAM_ATTACKER_MODEL", ""),
        "attacker_base_url": env.get("REDTEAM_ATTACKER_BASE_URL", ""),
        "judge_model": env.get("REDTEAM_JUDGE_MODEL", ""),
        "judge_base_url": env.get("REDTEAM_JUDGE_BASE_URL", ""),
        "defaults": {
            "loop": env.get("REDTEAM_LOOP", "0"),
            "repeats": env.get("REDTEAM_REPEATS", "1"),
            "auth_mode": env.get("REDTEAM_AUTH_MODE", "vulnerable"),
            "seed": env.get("REDTEAM_SEED", "0"),
        },
        "keys": {
            "attacker": bool(env.get("REDTEAM_TARGET_ATTACKER_API_KEY")),
            "victim": bool(env.get("REDTEAM_TARGET_VICTIM_API_KEY")),
            "secondary": bool(env.get("REDTEAM_TARGET_SECONDARY_API_KEY")),
            "attacker_model": secret("REDTEAM_ATTACKER_API_KEY"),
            "judge_model": secret("REDTEAM_JUDGE_API_KEY"),
        },
    }


# ── Метаданные прогонов (персистентные) ─────────────────────────────────────
def _meta_path(run_id: str) -> pathlib.Path:
    return STATE_DIR / f"{run_id}.meta.json"


def _log_path(run_id: str) -> pathlib.Path:
    return STATE_DIR / f"{run_id}.log"


def _write_meta(run_id: str, meta: dict) -> None:
    _meta_path(run_id).write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_meta(run_id: str) -> dict | None:
    p = _meta_path(run_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_json(path: pathlib.Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _run_summary(run_id: str) -> dict:
    meta = _read_meta(run_id) or {}
    rdir = RUNS_DIR / run_id
    report = _read_json(rdir / "report.json")
    campaign = _read_json(rdir / "campaign.json")
    status = meta.get("status")
    if status in (None, "running") and report is not None and run_id not in _active:
        # прогон извне webui или сервер перезапускался
        status = "completed"
    if status is None:
        status = "external" if report is not None else "unknown"
    e2e = None
    stages = {}
    if report:
        rates = report.get("rates", {})
        e2e = (rates.get("end_to_end") or {}).get("rate")
        for key in ("write_acceptance", "persistence_global", "retrieval_candidate",
                    "behavior_change", "unsafe_output"):
            r = rates.get(key) or {}
            stages[key] = r.get("rate")
    params = meta.get("params") or {}
    if not params and campaign:
        params = {
            "repeats": campaign.get("repeats"),
            "loop": campaign.get("loop_iters"),
            "seed": campaign.get("seed"),
        }
    started = meta.get("started_at")
    if started is None and rdir.exists():
        started = rdir.stat().st_mtime
    return {
        "run_id": run_id,
        "status": status,
        "source": meta.get("source", "external" if not meta else "webui"),
        "params": params,
        "scenarios": meta.get("params", {}).get("scenarios") if meta else None,
        "started_at": started,
        "ended_at": meta.get("ended_at"),
        "returncode": meta.get("returncode"),
        "has_report": report is not None,
        "n_runs": (report or {}).get("n_runs"),
        "e2e": e2e,
        "stages": stages,
    }


def list_runs() -> list[dict]:
    ids: set[str] = set()
    if RUNS_DIR.exists():
        for d in RUNS_DIR.iterdir():
            if d.is_dir() and (d / "report.json").exists():
                ids.add(d.name)
    for p in STATE_DIR.glob("*.meta.json"):
        ids.add(p.name[: -len(".meta.json")])
    ids.update(_active.keys())
    out = [_run_summary(r) for r in ids]
    out.sort(key=lambda r: (r.get("started_at") or 0), reverse=True)
    return out


# ── Запуск кампании ─────────────────────────────────────────────────────────
def _compose_available() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "docker не найден в PATH"
    try:
        subprocess.run(["docker", "compose", "version"], cwd=REPO_DIR,
                       capture_output=True, timeout=15, check=True)
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, f"docker compose недоступен: {exc}"


def _stream_process(run_id: str, cmd: list[str]) -> None:
    """Читает stdout подпроцесса построчно, пишет в лог и обновляет meta."""
    log = _log_path(run_id)
    with log.open("w", encoding="utf-8") as fh:
        fh.write(f"$ {' '.join(cmd)}\n\n")
        fh.flush()
        try:
            proc = subprocess.Popen(
                cmd, cwd=REPO_DIR, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )
        except Exception as exc:  # noqa: BLE001
            fh.write(f"\n[webui] не удалось запустить процесс: {exc}\n")
            _finish(run_id, None, "failed")
            return
        with _runs_lock:
            _active[run_id]["proc"] = proc
        assert proc.stdout is not None
        for line in proc.stdout:
            fh.write(line)
            fh.flush()
        proc.wait()
    status = "completed" if proc.returncode == 0 else (
        "stopped" if _active.get(run_id, {}).get("stopping") else "failed")
    _finish(run_id, proc.returncode, status)


def _finish(run_id: str, returncode, status: str) -> None:
    meta = _read_meta(run_id) or {}
    meta["status"] = status
    meta["returncode"] = returncode
    meta["ended_at"] = time.time()
    _write_meta(run_id, meta)
    with _runs_lock:
        _active.pop(run_id, None)


def start_run(payload: dict) -> dict:
    ok, why = _compose_available()
    if not ok:
        return {"error": why, "code": 400}

    with _runs_lock:
        if _active:
            busy = next(iter(_active))
            return {"error": f"уже выполняется прогон {busy}. Дождитесь его завершения "
                             f"(память стенда общая, прогоны идут последовательно).",
                    "code": 409}

    valid = valid_scenario_ids()
    sel = payload.get("scenarios") or []
    sel = [s for s in sel if isinstance(s, str) and SCENARIO_ID_RE.match(s) and s in valid]
    # loop/repeats/seed
    def _int(name, default, lo, hi):
        try:
            return max(lo, min(hi, int(payload.get(name, default))))
        except (TypeError, ValueError):
            return default

    loop = _int("loop", 0, 0, 50)
    repeats = _int("repeats", 1, 1, 100)
    seed = _int("seed", 0, 0, 2**31 - 1)
    auth_mode = payload.get("auth_mode", "vulnerable")
    if auth_mode not in AUTH_MODES:
        auth_mode = "vulnerable"
    include_disabled = bool(payload.get("include_disabled"))
    fail_fast = payload.get("fail_fast", True)
    fail_fast = bool(fail_fast) if not isinstance(fail_fast, str) else fail_fast.lower() in {"1", "true", "yes", "on"}
    # выбор отключённого сценария требует include_disabled
    disabled_selected = [s for s in sel if any(
        x["id"] == s and not x["enabled"] for x in scenarios())]
    if disabled_selected:
        include_disabled = True

    run_id = "webui-" + time.strftime("%Y%m%d-%H%M%S")
    cmd = ["docker", "compose", "run", "--rm", "-T",
           "-e", f"REDTEAM_LOOP={loop}",
           "-e", f"REDTEAM_REPEATS={repeats}",
           "-e", f"REDTEAM_AUTH_MODE={auth_mode}",
           "-e", f"REDTEAM_SEED={seed}",
           "-e", f"REDTEAM_INCLUDE_DISABLED={'1' if include_disabled else '0'}",
           "-e", f"REDTEAM_FAIL_FAST={'1' if fail_fast else '0'}",
           "-e", f"REDTEAM_RUN_DIR=/app/runs/{run_id}",
           "red-team-agent"]
    cmd += sel  # пустой список -> весь enabled-набор

    meta = {
        "run_id": run_id,
        "source": "webui",
        "status": "running",
        "started_at": time.time(),
        "ended_at": None,
        "returncode": None,
        "cmd": cmd,
        "params": {
            "scenarios": sel,
            "scenarios_label": "весь enabled-набор" if not sel else None,
            "loop": loop,
            "repeats": repeats,
            "auth_mode": auth_mode,
            "seed": seed,
            "include_disabled": include_disabled,
            "fail_fast": fail_fast,
        },
    }
    _write_meta(run_id, meta)
    with _runs_lock:
        _active[run_id] = {"proc": None, "status": "running", "stopping": False}
    t = threading.Thread(target=_stream_process, args=(run_id, cmd), daemon=True)
    with _runs_lock:
        _active[run_id]["thread"] = t
    t.start()
    return {"run_id": run_id, "status": "running", "params": meta["params"]}


def stop_run(run_id: str) -> dict:
    with _runs_lock:
        entry = _active.get(run_id)
        if not entry:
            return {"error": "прогон не выполняется", "code": 404}
        entry["stopping"] = True
        proc = entry.get("proc")
    if proc and proc.poll() is None:
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass
    return {"stopping": True, "run_id": run_id}


def run_doctor(loop: int) -> dict:
    ok, why = _compose_available()
    if not ok:
        return {"error": why, "code": 400}
    cmd = ["docker", "compose", "run", "--rm", "-T",
           "-e", f"REDTEAM_LOOP={max(0, loop)}",
           "--entrypoint", "python", "red-team-agent", "-m", "redteam.doctor"]
    try:
        proc = subprocess.run(cmd, cwd=REPO_DIR, capture_output=True, text=True, timeout=180)
        out = (proc.stdout or "") + (proc.stderr or "")
        return {"ok": proc.returncode == 0, "output": out, "cmd": " ".join(cmd)}
    except subprocess.TimeoutExpired:
        return {"error": "preflight превысил тайм-аут (180с)", "code": 504}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "code": 500}


# ── HTTP ────────────────────────────────────────────────────────────────────
CT = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
      ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
      ".svg": "image/svg+xml", ".ico": "image/x-icon"}


class Handler(BaseHTTPRequestHandler):
    server_version = "redteam-webui/1.0"

    def log_message(self, fmt, *args):  # тише в консоли
        return

    # helpers
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _err(self, obj) -> None:
        code = obj.get("code", 500) if isinstance(obj, dict) else 500
        self._json(obj, code)

    def _text(self, code: int, text: str, ctype="text/plain; charset=utf-8") -> None:
        self._send(code, text.encode("utf-8"), ctype)

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n <= 0:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # routing
    def do_GET(self):  # noqa: N802
        self.route("GET")

    def do_HEAD(self):  # noqa: N802
        self.route("GET")

    def do_POST(self):  # noqa: N802
        self.route("POST")

    def route(self, method: str):
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query)
        try:
            if path.startswith("/api/"):
                return self.api(method, path, q)
            return self.static(path)
        except BrokenPipeError:
            return
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": f"internal: {exc}", "code": 500}, 500)

    # static files
    def static(self, path: str):
        if path in ("/", ""):
            rel = "index.html"
        elif path.startswith("/static/"):
            rel = path[len("/static/"):]
        else:
            rel = path.lstrip("/")
        target = (STATIC_DIR / rel).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
            return self._text(404, "not found")
        ctype = CT.get(target.suffix, "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    # api
    def api(self, method: str, path: str, q: dict):
        if method == "GET" and path == "/api/scenarios":
            try:
                return self._json({"scenarios": scenarios()})
            except Exception as exc:  # noqa: BLE001
                return self._json({"scenarios": [], "error": f"каталог недоступен: {exc}"})

        if method == "GET" and path == "/api/config":
            return self._json(config_summary())

        if method == "GET" and path == "/api/runs":
            return self._json({"runs": list_runs(), "busy": bool(_active),
                               "active": list(_active.keys())})

        if method == "POST" and path == "/api/runs":
            res = start_run(self._body())
            return self._err(res) if "error" in res else self._json(res)

        if method == "POST" and path == "/api/doctor":
            loop = 1
            body = self._body()
            try:
                loop = int(body.get("loop", 1))
            except (TypeError, ValueError):
                loop = 1
            res = run_doctor(loop)
            return self._err(res) if "error" in res else self._json(res)

        m = re.match(r"^/api/runs/([^/]+)(/(log|report|report\.md|stop))?$", path)
        if m:
            run_id = m.group(1)
            if not RUN_ID_RE.match(run_id):
                return self._json({"error": "bad run id", "code": 400}, 400)
            sub = m.group(3)
            if method == "POST" and sub == "stop":
                r = stop_run(run_id)
                return self._err(r) if "error" in r else self._json(r)
            if method == "GET" and sub == "log":
                return self._log(run_id, q)
            if method == "GET" and sub == "report":
                rep = _read_json(RUNS_DIR / run_id / "report.json")
                return self._json(rep) if rep else self._json({"error": "нет отчёта", "code": 404}, 404)
            if method == "GET" and sub == "report.md":
                p = RUNS_DIR / run_id / "report.md"
                if p.exists():
                    return self._text(200, p.read_text(encoding="utf-8"),
                                      "text/markdown; charset=utf-8")
                return self._text(404, "нет report.md")
            if method == "GET" and sub is None:
                return self._run_detail(run_id)

        return self._json({"error": "not found", "code": 404}, 404)

    def _run_detail(self, run_id: str):
        summary = _run_summary(run_id)
        rdir = RUNS_DIR / run_id
        summary["report"] = _read_json(rdir / "report.json")
        summary["campaign"] = _read_json(rdir / "campaign.json")
        meta = _read_meta(run_id)
        if meta:
            summary["cmd"] = meta.get("cmd")
        return self._json(summary)

    def _log(self, run_id: str, q: dict):
        p = _log_path(run_id)
        try:
            offset = int(q.get("offset", ["0"])[0])
        except (TypeError, ValueError):
            offset = 0
        if not p.exists():
            done = run_id not in _active
            return self._json({"offset": 0, "chunk": "", "done": done,
                               "status": (_read_meta(run_id) or {}).get("status", "unknown")})
        data = p.read_bytes()
        chunk = data[offset:].decode("utf-8", errors="replace")
        running = run_id in _active
        return self._json({
            "offset": len(data), "chunk": chunk, "done": not running,
            "status": (_read_meta(run_id) or {}).get("status", "running" if running else "unknown"),
        })


def main():
    ap = argparse.ArgumentParser(description="Web UI для red-team-agent")
    ap.add_argument("--port", type=int, default=8700)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    # прогреваем каталог сценариев, чтобы ранние ошибки были видны в консоли
    try:
        n = len(scenarios())
        print(f"[webui] каталог сценариев: {n} шт.")
    except Exception as exc:  # noqa: BLE001
        print(f"[webui] ВНИМАНИЕ: каталог сценариев недоступен ({exc}). "
              f"Запустите сервер через red-team-agent/.venv/bin/python.")

    ok, why = _compose_available()
    print(f"[webui] docker compose: {'ok' if ok else why}")
    print(f"[webui] repo: {REPO_DIR}")
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"[webui] слушаю {url}  (Ctrl+C для остановки)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[webui] остановлено")


if __name__ == "__main__":
    main()
