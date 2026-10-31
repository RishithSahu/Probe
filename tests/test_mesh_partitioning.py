"""Item 2 of the concurrency/scaling request: configurable Probe scope partitioning by worker count,
instead of split_scope()'s fixed /24-style default shard_size=256 (which turns a /24 into one task, leaving
a second worker nothing to do).
"""
from __future__ import annotations

import ipaddress

import pytest

from probe.mesh.core import Hub, shard_size_for_workers, split_scope
from probe.store import Store


def test_two_workers_on_a_24_get_two_disjoint_25_shards():
    shards = split_scope(["10.20.30.0/24"], shard_size_for_workers(["10.20.30.0/24"], 2))
    assert sorted(shards) == ["10.20.30.0/25", "10.20.30.128/25"]


def test_four_workers_on_a_24_get_four_disjoint_26_shards():
    shards = split_scope(["10.20.30.0/24"], shard_size_for_workers(["10.20.30.0/24"], 4))
    assert sorted(ipaddress.ip_network(s) for s in shards) == [
        ipaddress.ip_network(s) for s in ("10.20.30.0/26", "10.20.30.64/26", "10.20.30.128/26", "10.20.30.192/26")
    ]


def test_eight_workers_on_a_24_get_eight_disjoint_27_shards():
    shards = split_scope(["10.20.30.0/24"], shard_size_for_workers(["10.20.30.0/24"], 8))
    assert len(shards) == 8
    assert all(ipaddress.ip_network(s).prefixlen == 27 for s in shards)


@pytest.mark.parametrize("worker_count", [1, 2, 3, 4, 5, 7, 8, 16, 32])
def test_shards_are_disjoint_and_exactly_cover_the_scope(worker_count):
    scope = ["10.20.30.0/24"]
    shards = split_scope(scope, shard_size_for_workers(scope, worker_count))
    nets = [ipaddress.ip_network(s) for s in shards]

    # disjoint
    for i, a in enumerate(nets):
        for b in nets[i + 1:]:
            assert not a.overlaps(b), f"{a} and {b} overlap"

    # exact union coverage: every address in the original scope is in exactly one shard
    original_addresses = set(ipaddress.ip_network(scope[0]).hosts()) | {ipaddress.ip_network(scope[0]).network_address,
                                                                        ipaddress.ip_network(scope[0]).broadcast_address}
    shard_addresses = set()
    for n in nets:
        shard_addresses |= set(n)
    assert shard_addresses == set(ipaddress.ip_network(scope[0])), "shards must exactly cover the scope, no more, no less"

    # every shard stays inside the authorised scope
    assert all(n.subnet_of(ipaddress.ip_network(scope[0])) for n in nets)


def test_a_small_scope_does_not_explode_into_thousands_of_tiny_jobs_for_a_huge_worker_pool():
    scope = ["10.20.30.0/30"]  # 4 addresses
    shards = split_scope(scope, shard_size_for_workers(scope, worker_count=500))
    assert len(shards) <= 4, "a 4-address scope must never be split into more than 4 units of work"


def test_worker_count_one_or_absent_keeps_the_historical_default_shard_size():
    scope = ["10.20.30.0/24"]
    assert shard_size_for_workers(scope, 1) == 256
    assert split_scope(scope, shard_size_for_workers(scope, 1)) == split_scope(scope, 256)


def test_hub_plan_with_worker_count_produces_the_expected_shard_count(tmp_path):
    store = Store(tmp_path / "mesh.db")
    hub = Hub(store, scope=["10.20.30.0/24"])
    result = hub.plan(worker_count=4, enrich=False)
    assert len(result["shards"]) == 4
    assert sorted(ipaddress.ip_network(s) for s in result["shards"]) == [
        ipaddress.ip_network(s) for s in ("10.20.30.0/26", "10.20.30.64/26", "10.20.30.128/26", "10.20.30.192/26")
    ]


def test_hub_plan_explicit_shard_size_overrides_worker_count(tmp_path):
    store = Store(tmp_path / "mesh.db")
    hub = Hub(store, scope=["10.20.30.0/24"])
    result = hub.plan(shard_size=256, worker_count=4, enrich=False)
    assert len(result["shards"]) == 1, "an explicit shard_size must win over worker_count, not be combined with it"


def test_hub_plan_with_neither_shard_size_nor_worker_count_keeps_the_historical_default(tmp_path):
    store = Store(tmp_path / "mesh.db")
    hub = Hub(store, scope=["10.20.30.0/24"])
    result = hub.plan(enrich=False)
    assert len(result["shards"]) == 1  # a /24 at the historical default shard_size=256 is one shard
