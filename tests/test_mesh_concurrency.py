"""Real concurrent exercises of probe/mesh/core.py's task-leasing, not sequential mock tests.

These use actual OS threads plus a Barrier to force many callers to race Hub.lease() at the same
instant, which is the only way to actually exercise the race the old code had (SELECT a pending task,
then UPDATE it to leased, without ever checking whether that UPDATE won). A sequential test can't
reproduce that: it would have to get the timing of two single-threaded calls to interleave by luck.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from probe.mesh.core import Hub, MeshError
from probe.store import Store


def _hub(tmp_path, *, scope=("10.20.30.0/24",), shards=1, enrich=False) -> Hub:
    store = Store(tmp_path / "mesh.db")
    hub = Hub(store, scope=list(scope))
    hub.plan(shard_size=256 // shards if shards > 1 else 256, enrich=enrich)
    return hub


def _register(hub: Hub, n: int) -> list[str]:
    return [hub.register({"agent_id": f"agent-{i}", "scope": hub.scope, "caps": ["scan", "enrich"]})["agent_id"]
            for i in range(n)]


def test_two_workers_racing_one_task_only_one_wins(tmp_path):
    hub = _hub(tmp_path, shards=1)
    agents = _register(hub, 8)
    barrier = threading.Barrier(len(agents))

    def go(aid):
        barrier.wait()
        return hub.lease(aid)

    with ThreadPoolExecutor(max_workers=len(agents)) as pool:
        results = list(pool.map(go, agents))

    winners = [r for r in results if r["task"] is not None]
    assert len(winners) == 1, "exactly one of eight simultaneous lease attempts for one task must win"
    # every winner must have a real, non-empty lease token -- the fencing credential
    assert winners[0]["task"]["lease_token"]


def test_four_pending_tasks_many_workers_no_duplicate_and_no_loss(tmp_path):
    hub = _hub(tmp_path, shards=4)
    tasks_total = len(hub.store.query("SELECT key FROM tasks"))
    assert tasks_total == 4
    agents = _register(hub, 12)          # more workers than tasks, like a real worker pool racing a small queue
    barrier = threading.Barrier(len(agents))
    lock = threading.Lock()
    claimed_keys: list[str] = []

    def go(aid):
        barrier.wait()
        r = hub.lease(aid)
        if r["task"] is not None:
            with lock:
                claimed_keys.append(r["task"]["key"])
        return r

    with ThreadPoolExecutor(max_workers=len(agents)) as pool:
        list(pool.map(go, agents))

    assert len(claimed_keys) == 4, "all four tasks should be claimed, each by exactly one worker"
    assert len(set(claimed_keys)) == 4, "no task key was claimed twice"


def test_expired_lease_is_reclaimed_by_another_worker(tmp_path):
    clock = {"t": 1000.0}
    store = Store(tmp_path / "mesh.db")
    hub = Hub(store, scope=["10.20.30.0/24"], now=lambda: clock["t"])
    hub.plan(shard_size=256)
    a1 = hub.register({"agent_id": "a1", "scope": hub.scope, "caps": ["scan"]})["agent_id"]
    a2 = hub.register({"agent_id": "a2", "scope": hub.scope, "caps": ["scan"]})["agent_id"]

    first = hub.lease(a1)
    assert first["task"] is not None

    clock["t"] += 9999  # well past LEASE_TTL with no heartbeat/renewal from a1
    second = hub.lease(a2)
    assert second["task"] is not None
    assert second["task"]["key"] == first["task"]["key"], "the expired lease's task must be reclaimable"
    assert second["task"]["lease_token"] != first["task"]["lease_token"], "a reclaim must mint a new lease token"


def test_stale_lease_holder_cannot_submit_after_reclaim(tmp_path):
    clock = {"t": 1000.0}
    store = Store(tmp_path / "mesh.db")
    hub = Hub(store, scope=["10.20.30.0/24"], now=lambda: clock["t"])
    hub.plan(shard_size=256)
    a1 = hub.register({"agent_id": "a1", "scope": hub.scope, "caps": ["scan"]})["agent_id"]
    a2 = hub.register({"agent_id": "a2", "scope": hub.scope, "caps": ["scan"]})["agent_id"]

    first = hub.lease(a1)
    key, stale_token = first["task"]["key"], first["task"]["lease_token"]

    clock["t"] += 9999
    second = hub.lease(a2)
    assert second["task"]["key"] == key

    # a1 is rejected either way: its lease_token is stale AND the task is no longer held by a1 at all --
    # either reason is a correct refusal, so this only needs to confirm a1 cannot possibly succeed.
    with pytest.raises(MeshError):
        hub.submit(a1, key, {"hosts": []}, stale_token)

    fresh_token = second["task"]["lease_token"]
    result = hub.submit(a2, key, {"hosts": []}, fresh_token)
    assert result["ok"] is True


def test_submit_with_wrong_token_is_rejected_even_from_the_right_agent(tmp_path):
    hub = _hub(tmp_path, shards=1)
    (aid,) = _register(hub, 1)
    leased = hub.lease(aid)
    key = leased["task"]["key"]

    with pytest.raises(MeshError, match="stale lease"):
        hub.submit(aid, key, {"hosts": []}, "not-the-real-token")

    # the correct token still works afterwards -- a wrong guess doesn't burn the real lease
    ok = hub.submit(aid, key, {"hosts": []}, leased["task"]["lease_token"])
    assert ok["ok"] is True


def test_fail_with_wrong_token_is_rejected(tmp_path):
    hub = _hub(tmp_path, shards=1)
    (aid,) = _register(hub, 1)
    leased = hub.lease(aid)
    key = leased["task"]["key"]

    with pytest.raises(MeshError, match="stale lease"):
        hub.fail(aid, key, "boom", "not-the-real-token")

    result = hub.fail(aid, key, "boom", leased["task"]["lease_token"])
    assert result["ok"] is True


def test_many_concurrent_claim_task_calls_never_oversell_a_single_task(tmp_path):
    """Hammer Store.claim_task directly (below Hub) with far more concurrent callers than pending tasks,
    the way many separate worker processes sharing one db file would. Every claim must still be unique."""
    hub = _hub(tmp_path, shards=1)
    barrier = threading.Barrier(40)
    winners: list[dict] = []
    lock = threading.Lock()

    def go(i):
        barrier.wait()
        t = hub.store.claim_task(lambda task: True, f"w{i}", 60.0, hub.now())
        if t is not None:
            with lock:
                winners.append(t)

    with ThreadPoolExecutor(max_workers=40) as pool:
        list(pool.map(go, range(40)))

    assert len(winners) == 1
    assert len({w["lease_token"] for w in winners}) == 1
