"""A mesh worker: register, lease, run under MY OWN fence, submit, repeat. stdlib HTTP only.

The worker never trusts the hub with its fence: its authorised scope is its own configuration and is what it registers.
Tasks are executed by injected callables (`run_scan`, `run_enrich`), so this loop is the same whether the agent is a
container on a Linux box, a process on a laptop, or a unit test.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Callable

from .core import covered, ip_covered

logger = logging.getLogger("probe.mesh.worker")


class HubError(RuntimeError):
    pass


class HubClient:
    def __init__(self, url: str, token: str | None = None, timeout: float = 30.0):
        self.url, self.token, self.timeout = url.rstrip("/"), token, timeout

    def call(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={"Content-Type": "application/json"})
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            raise HubError(f"{method} {path}: {e.code} {e.read().decode()[:200]}") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            raise HubError(f"cannot reach hub {self.url}: {getattr(e, 'reason', e)}") from None


class Worker:
    def __init__(self, hub: HubClient, scope: list[str], *, run_scan: Callable[[dict], dict],
                 run_enrich: Callable[[dict], dict] | None = None, name: str | None = None, agent_id: str | None = None,
                 vantage: str | None = None, poll_s: float = 2.0, heartbeat_s: float = 10.0,
                 on_approved: Callable[[list[str]], None] | None = None, version: str = "1"):
        self.hub, self.scope, self.run_scan, self.run_enrich = hub, list(scope), run_scan, run_enrich
        self.name, self.agent_id, self.vantage = name, agent_id, vantage
        self.poll_s, self.heartbeat_s, self.on_approved, self.version = poll_s, heartbeat_s, on_approved, version
        self.caps = ["scan"] + (["enrich"] if run_enrich else [])
        self.stop = threading.Event()
        self.done = 0

    def register(self) -> None:
        r = self.hub.call("POST", "/mesh/register", {"agent_id": self.agent_id, "name": self.name, "scope": self.scope,
                                                     "vantage": self.vantage, "caps": self.caps, "version": self.version})
        self.agent_id = r["agent_id"]
        self.heartbeat_s = min(self.heartbeat_s, float(r.get("heartbeat_s", self.heartbeat_s)))
        logger.info("registered as %s (caps %s, scope %s)", self.agent_id, self.caps, self.scope)

    def _heartbeat_loop(self) -> None:
        while not self.stop.wait(self.heartbeat_s):
            try:
                r = self.hub.call("POST", "/mesh/heartbeat", {"agent_id": self.agent_id})
                self._approvals(r.get("approved", []))
            except HubError as e:
                logger.warning("heartbeat failed: %s", e)

    def _approvals(self, approved: list[str]) -> None:
        """Approvals release holds only inside MY scope; they can never widen my fence."""
        mine = [c for c in approved if covered(c, self.scope)]
        if mine and self.on_approved:
            self.on_approved(mine)

    def _safe_for_me(self, task: dict) -> bool:
        """Defence in depth: refuse any task that is not inside my own scope, whatever the hub says."""
        p = task["payload"]
        if task["type"] == "scan":
            return all(covered(c, self.scope) for c in p["cidrs"])
        if task["type"] == "enrich":
            return all(ip_covered(ip, self.scope) for ip in p["targets"])
        return False

    def run_once(self) -> bool:
        """Lease and execute at most one task. Returns True if a task was handled."""
        r = self.hub.call("POST", "/mesh/lease", {"agent_id": self.agent_id})
        self._approvals(r.get("approved", []))
        task = r.get("task")
        if not task:
            return False
        token = task["lease_token"]
        if not self._safe_for_me(task):
            self.hub.call("POST", "/mesh/fail", {"agent_id": self.agent_id, "key": task["key"],
                                                 "error": "task outside this worker's scope", "lease_token": token})
            logger.error("refused task %s: outside my own scope", task["key"])
            return True
        try:
            payload = self.run_scan(task) if task["type"] == "scan" else self.run_enrich(task)
        except Exception as e:                       # a failing task goes back to the queue; the worker lives on
            logger.exception("task %s failed", task["key"])
            self.hub.call("POST", "/mesh/fail", {"agent_id": self.agent_id, "key": task["key"], "error": repr(e), "lease_token": token})
            return True
        self.hub.call("POST", "/mesh/submit", {"agent_id": self.agent_id, "key": task["key"], "payload": payload, "lease_token": token})
        self.done += 1
        return True

    def run(self, max_tasks: int | None = None, idle_exit_s: float | None = None) -> int:
        self.register()
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        idle_since = None
        try:
            while not self.stop.is_set() and (max_tasks is None or self.done < max_tasks):
                try:
                    worked = self.run_once()
                except HubError as e:
                    logger.warning("%s; retrying", e)
                    worked = False
                if worked:
                    idle_since = None
                    continue
                idle_since = idle_since or time.time()
                if idle_exit_s is not None and time.time() - idle_since > idle_exit_s:
                    break
                self.stop.wait(self.poll_s)
        finally:
            self.stop.set()
        return self.done
