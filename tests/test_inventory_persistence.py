"""Inventory imports must be repeatable without touching a live network."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core.exceptions import AssessmentNotFoundError, GraphValidationError
from app.core.schemas import (
    Assessment,
    NetworkGraph,
    NetworkGraphAssetRecord,
    NetworkGraphServiceRecord,
)
from app.database import repository
from app.database.models import AssetRecord, Base, ServiceRecord


@pytest.fixture
def engine(tmp_path):
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'inventory.db').as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as db, db.begin():
        for assessment_id in ("A-1", "A-2"):
            repository.create_assessment(db, Assessment(assessment_id=assessment_id, scope_id="S-1"))
    yield engine
    engine.dispose()


def host(asset_id="HOST-A", *, port=80, name="http", version=None, hostname=None):
    return NetworkGraphAssetRecord(
        asset_id=asset_id, ip="10.20.30.10", hostname=hostname,
        services=[NetworkGraphServiceRecord(
            asset_id=asset_id, service_id=f"{asset_id}:{port}/tcp", port=port,
            service_name=name, version=version,
        )],
    )


def graph(*assets, scope_id="S-1"):
    return NetworkGraph(scope_id=scope_id, assets=list(assets))


def save(engine, snapshot, assessment_id="A-1"):
    with Session(engine) as db, db.begin():
        repository.store_network_graph(db, assessment_id, snapshot)


def records(engine):
    with Session(engine) as db:
        return (
            list(db.scalars(select(AssetRecord).order_by(AssetRecord.id))),
            list(db.scalars(select(ServiceRecord).order_by(ServiceRecord.id))),
        )


def test_reimport_updates_existing_rows_and_preserves_database_ids(engine):
    save(engine, graph(host()))
    before_assets, before_services = records(engine)
    save(engine, graph(host(hostname="observed.lab", version="2.0")))
    assets, services = records(engine)
    assert len(assets) == len(services) == 1
    assert assets[0].id == before_assets[0].id
    assert services[0].id == before_services[0].id
    assert assets[0].hostname == "observed.lab"
    assert services[0].version == "2.0"


def test_partial_snapshot_retains_previous_inventory_without_targeting_it(engine):
    save(engine, graph(host(), host("HOST-B")))
    save(engine, graph(host("HOST-C", port=443, name="https")))
    assets, services = records(engine)
    assert {a.asset_id for a in assets} == {"HOST-A", "HOST-B", "HOST-C"}
    assert len(services) == 3
    with Session(engine) as db:
        latest = repository.load_network_graph(db, "A-1")
        assert [a.asset_id for a in latest.assets] == ["HOST-C"]


def test_missing_metadata_does_not_erase_previous_observations(engine):
    save(engine, graph(host(hostname="known.lab", version="1.0")))
    save(engine, graph(host(name=None)))
    assets, services = records(engine)
    assert len(assets) == len(services) == 1
    assert assets[0].hostname == "known.lab"
    assert services[0].service_name == "http"
    assert services[0].version == "1.0"


def test_new_service_is_separate_and_does_not_duplicate_existing_endpoint(engine):
    save(engine, graph(host()))
    changed = host()
    changed.services.extend(host(port=443, name="https").services)
    save(engine, graph(changed))
    save(engine, graph(changed))
    assets, services = records(engine)
    assert len(assets) == 1
    assert {s.port for s in services} == {80, 443}
    assert len(services) == 2


def test_same_identifiers_in_different_assessments_remain_separate(engine):
    save(engine, graph(host()))
    save(engine, graph(host(version="other")), assessment_id="A-2")
    save(engine, graph(host(version="updated")))
    assets, services = records(engine)
    assert len(assets) == len(services) == 2
    assert {a.assessment_id for a in assets} == {"A-1", "A-2"}
    assert {s.version for s in services} == {"other", "updated"}


@pytest.mark.parametrize("kind", ["scope", "duplicate_host", "foreign_service", "duplicate_service"])
def test_invalid_snapshot_is_rejected_before_inventory_is_changed(engine, kind):
    save(engine, graph(host()))
    changed = host(hostname="must-not-be-saved")
    invalid = graph(changed)
    if kind == "scope":
        invalid.scope_id = "OTHER-SCOPE"
    elif kind == "duplicate_host":
        invalid.assets.append(host())
    elif kind == "foreign_service":
        changed.services[0].asset_id = "HOST-OTHER"
    elif kind == "duplicate_service":
        changed.services.append(changed.services[0].model_copy())
    with pytest.raises(GraphValidationError):
        save(engine, invalid)
    assets, services = records(engine)
    assert len(assets) == len(services) == 1
    assert assets[0].hostname is None
    with Session(engine) as db:
        assert repository.load_network_graph(db, "A-1").scope_id == "S-1"


def test_service_identity_cannot_be_reassigned_to_another_endpoint(engine):
    save(engine, graph(host()))
    changed = host(hostname="not-saved")
    changed.services[0].port = 443
    with pytest.raises(GraphValidationError):
        save(engine, graph(changed))
    assets, services = records(engine)
    assert assets[0].hostname is None
    assert services[0].port == 80


def test_missing_assessment_cannot_create_orphan_inventory(engine):
    with pytest.raises(AssessmentNotFoundError):
        save(engine, graph(host()), assessment_id="DOES-NOT-EXIST")
    assert records(engine) == ([], [])


def test_transaction_rollback_retains_previous_graph_and_inventory(engine):
    save(engine, graph(host()))
    with pytest.raises(RuntimeError):
        with Session(engine) as db, db.begin():
            repository.store_network_graph(db, "A-1", graph(host("HOST-NEW")))
            raise RuntimeError("Simulated failure after import")
    assets, services = records(engine)
    assert [a.asset_id for a in assets] == ["HOST-A"]
    assert len(services) == 1
    with Session(engine) as db:
        assert repository.load_network_graph(db, "A-1").assets[0].asset_id == "HOST-A"


def test_concurrent_reimports_do_not_duplicate_inventory(engine):
    start = Barrier(2)

    def import_snapshot():
        start.wait(timeout=10)
        save(engine, graph(host()))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(import_snapshot) for _ in range(2)]
        for future in futures:
            future.result(timeout=15)
    assets, services = records(engine)
    assert len(assets) == len(services) == 1


def test_concurrent_snapshots_preserve_both_new_devices(engine):
    start = Barrier(2)

    def import_snapshot(name):
        start.wait(timeout=10)
        save(engine, graph(host(), host(name)))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(import_snapshot, name) for name in ("HOST-B", "HOST-C")]
        for future in futures:
            future.result(timeout=15)
    assets, services = records(engine)
    assert {a.asset_id for a in assets} == {"HOST-A", "HOST-B", "HOST-C"}
    assert len(services) == 3


def test_alias_change_does_not_silently_rebind_service_references(engine):
    save(engine, graph(host()))
    changed = host()
    changed.services[0].service_id = "DIFFERENT-ID-FOR-SAME-ENDPOINT"
    with pytest.raises(GraphValidationError):
        save(engine, graph(changed))
    assert records(engine)[1][0].service_id == "HOST-A:80/tcp"


def test_existing_duplicate_data_requires_explicit_repair(engine):
    save(engine, graph(host()))
    with Session(engine) as db, db.begin():
        db.add(AssetRecord(asset_id="HOST-A", assessment_id="A-1", asset_type="host"))
    with pytest.raises(GraphValidationError, match="explicit repair"):
        save(engine, graph(host()))
    # Never guess which legacy record to delete, or insert another duplicate.
    assert len(records(engine)[0]) == 2


def test_snapshot_retains_scope_holds_and_source_evidence_without_granting_permission(engine):
    observed = host()
    observed.held = True
    observed.verdict = "UNVERIFIED_CANDIDATE"
    observed.services[0].product = "ObservedProduct"
    observed.services[0].banner = "Recorded service observation"
    snapshot = graph(observed)
    snapshot.raw_source_ref = "evidence/observation.json"
    save(engine, snapshot)
    with Session(engine) as db:
        assert repository.load_network_graph(db, "A-1").model_dump() == snapshot.model_dump()
        policy = repository.get_assessment_policy(db, "A-1")
        assert not policy.allow_binary_analysis
        assert not policy.allow_active_web_verification
