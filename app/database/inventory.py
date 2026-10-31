"""Transactional inventory imports, independent of specialist-agent dispatch.

The graph is the latest observation snapshot; normalised device/service rows
are cumulative inventory. Absence from a partial snapshot never proves removal.
Persisting either representation does not grant permission for active work.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.exceptions import AssessmentNotFoundError, GraphValidationError
from app.core.schemas import DiscoverySource, NetworkGraph
from app.database.models import AssessmentRecord, AssetRecord, NetworkGraphRecord, ServiceRecord


def _validate_identities(graph: NetworkGraph) -> None:
    assets: set[str] = set()
    services: set[str] = set()
    for asset in graph.assets:
        if not asset.asset_id.strip() or asset.asset_id in assets:
            raise GraphValidationError("Inventory snapshot contains an empty or repeated asset ID")
        assets.add(asset.asset_id)
        endpoints: set[tuple[int, str]] = set()
        for service in asset.services:
            if service.asset_id != asset.asset_id:
                raise GraphValidationError("Inventory service does not belong to its containing asset")
            if not service.service_id.strip() or service.service_id in services:
                raise GraphValidationError("Inventory snapshot contains an empty or repeated service ID")
            services.add(service.service_id)
            endpoint = (service.port, service.protocol.lower())
            if not 0 <= service.port <= 65535 or not service.protocol.strip() or endpoint in endpoints:
                raise GraphValidationError("Inventory snapshot contains an invalid or repeated service endpoint")
            endpoints.add(endpoint)


def persist_network_graph(db: Session, assessment_id: str, graph: NetworkGraph) -> None:
    """Merge a snapshot without changing existing asset/service database IDs.

    The no-op parent UPDATE acquires a database write lock before reading the
    inventory (a row lock on PostgreSQL; SQLite serializes writers). Every
    importer through this entry point shares that lock until caller commit or
    rollback, preventing concurrent first imports from inserting duplicates.
    No schema migration or live database cleanup is performed here.
    """
    _validate_identities(graph)
    locked = db.execute(
        update(AssessmentRecord)
        .where(AssessmentRecord.assessment_id == assessment_id)
        .values(scope_id=AssessmentRecord.scope_id)
        .execution_options(synchronize_session=False)
    )
    if locked.rowcount != 1:
        raise AssessmentNotFoundError(f"assessment {assessment_id!r} not found")
    scope_id = db.scalar(select(AssessmentRecord.scope_id).where(AssessmentRecord.assessment_id == assessment_id))
    if graph.scope_id != scope_id:
        raise GraphValidationError("Inventory graph scope does not match its assessment")

    assets_by_id: dict[str, AssetRecord] = {}
    for record in db.scalars(select(AssetRecord).where(AssetRecord.assessment_id == assessment_id)):
        if record.asset_id in assets_by_id:
            raise GraphValidationError("Existing inventory contains duplicate asset IDs; explicit repair is required")
        assets_by_id[record.asset_id] = record

    services_by_id: dict[str, ServiceRecord] = {}
    services_by_endpoint: dict[tuple[int, int, str], ServiceRecord] = {}
    for record in db.scalars(
        select(ServiceRecord).join(AssetRecord).where(AssetRecord.assessment_id == assessment_id)
    ):
        if record.service_id in services_by_id:
            raise GraphValidationError("Existing inventory contains duplicate service IDs; explicit repair is required")
        services_by_id[record.service_id] = record
        endpoint = (record.asset_db_id, record.port, record.protocol.lower())
        if endpoint in services_by_endpoint:
            raise GraphValidationError("Existing inventory contains duplicate service endpoints; explicit repair is required")
        services_by_endpoint[endpoint] = record

    # Validate stable endpoint bindings before changing any inventory fields.
    # Findings reference logical IDs; repurposing one would change their meaning.
    for asset in graph.assets:
        existing_asset = assets_by_id.get(asset.asset_id)
        for service in asset.services:
            existing = services_by_id.get(service.service_id)
            if existing is not None and (
                existing_asset is None or existing.asset_db_id != existing_asset.id
                or existing.port != service.port or existing.protocol.lower() != service.protocol.lower()
            ):
                raise GraphValidationError("An existing service ID cannot be reassigned to a different asset or endpoint")
            if existing_asset is not None:
                prior_endpoint = services_by_endpoint.get((existing_asset.id, service.port, service.protocol.lower()))
                if prior_endpoint is not None and prior_endpoint.service_id != service.service_id:
                    raise GraphValidationError("An existing endpoint cannot silently change its service ID")

    try:
        discovery_source = DiscoverySource(graph.generated_by).value
    except ValueError:
        discovery_source = DiscoverySource.GRAPH_IMPORT.value

    snapshot = db.get(NetworkGraphRecord, assessment_id)
    if snapshot is None:
        snapshot = NetworkGraphRecord(assessment_id=assessment_id)
        db.add(snapshot)
    snapshot.scope_id = graph.scope_id
    snapshot.generated_by = graph.generated_by
    snapshot.raw_source_ref = graph.raw_source_ref
    snapshot.normalised_graph = graph.model_dump(mode="json")
    snapshot.loaded_at = datetime.now(UTC)

    for asset in graph.assets:
        record = assets_by_id.get(asset.asset_id)
        if record is None:
            record = AssetRecord(asset_id=asset.asset_id, assessment_id=assessment_id)
            db.add(record)
            assets_by_id[asset.asset_id] = record
        # Missing metadata is unknown, not evidence that a previous value vanished.
        if asset.ip is not None:
            record.ip = asset.ip
        if asset.hostname is not None:
            record.hostname = asset.hostname
        record.asset_type = asset.asset_type
        record.discovery_source = discovery_source
        db.flush()
        for service in asset.services:
            service_record = services_by_id.get(service.service_id)
            if service_record is None:
                service_record = ServiceRecord(
                    service_id=service.service_id, asset_db_id=record.id,
                    port=service.port, protocol=service.protocol,
                )
                db.add(service_record)
                services_by_id[service.service_id] = service_record
            if service.service_name is not None:
                service_record.service_name = service.service_name
            if service.version is not None:
                service_record.version = service.version
    db.flush()
