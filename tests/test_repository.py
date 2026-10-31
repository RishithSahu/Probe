"""Repository/persistence tests. Requires a reachable PostgreSQL instance
configured via APE_DATABASE_URL (see docker-compose.yml's `postgres` service
for the real deployment target). Skipped automatically if unreachable, so
the rest of the suite still runs on a machine without Docker/Postgres.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.schemas import (
    AgentId,
    Assessment,
    AssessmentPolicy,
    AssessmentStatus,
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    PtesPhase,
    Severity,
    Surface,
)
from app.database import repository
from app.database.models import Base

try:
    _engine = create_engine(settings.database_url, connect_args={"connect_timeout": 2}, pool_pre_ping=True)
    with _engine.connect() as _conn:
        _conn.execute(text("SELECT 1"))
    _DB_AVAILABLE = True
except OperationalError:
    _DB_AVAILABLE = False

pytestmark = pytest.mark.skipif(not _DB_AVAILABLE, reason="PostgreSQL not reachable at APE_DATABASE_URL")


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=_engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=_engine, future=True)
    session = Session()
    # Clean slate per test (small schema, truncate is cheap).
    for table in reversed(Base.metadata.sorted_tables):
        session.execute(table.delete())
    session.commit()
    yield session
    session.rollback()
    session.close()


def test_create_and_get_assessment(db_session):
    assessment = Assessment(
        assessment_id="ASSESSMENT-TEST-001",
        scope_id="SCOPE-TEST-01",
        assessment_policy=AssessmentPolicy(allow_binary_analysis=True),
    )
    repository.create_assessment(db_session, assessment)
    db_session.commit()

    record = repository.get_assessment(db_session, "ASSESSMENT-TEST-001")
    assert record.scope_id == "SCOPE-TEST-01"
    policy = repository.get_assessment_policy(db_session, "ASSESSMENT-TEST-001")
    assert policy.allow_binary_analysis is True


def test_update_assessment_status(db_session):
    repository.create_assessment(
        db_session, Assessment(assessment_id="ASSESSMENT-TEST-002", scope_id="SCOPE-X"),
    )
    db_session.commit()
    repository.update_assessment_status(db_session, "ASSESSMENT-TEST-002", AssessmentStatus.COMPLETED)
    db_session.commit()
    record = repository.get_assessment(db_session, "ASSESSMENT-TEST-002")
    assert record.status == "completed"


def test_store_and_list_findings(db_session):
    repository.create_assessment(db_session, Assessment(assessment_id="ASSESSMENT-TEST-003", scope_id="SCOPE-X"))
    db_session.commit()

    finding = Finding(
        finding_id="WEB-TEST-001",
        assessment_id="ASSESSMENT-TEST-003",
        agent_id=AgentId.WEB_SECURITY,
        surface=Surface.WEB,
        asset_id="HOST-001",
        title="Test finding",
        description="A test finding",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        status=FindingStatus.SUSPECTED,
        evidence_refs=["EVIDENCE-TEST-001"],
        ptes_phase=PtesPhase.VULNERABILITY_ANALYSIS,
    )
    evidence = Evidence(
        evidence_id="EVIDENCE-TEST-001",
        finding_id="WEB-TEST-001",
        evidence_type="http_response",
        source_tool="httpx",
        description="test evidence",
    )
    repository.store_findings(db_session, [finding], [evidence])
    db_session.commit()

    findings = repository.list_findings(db_session, "ASSESSMENT-TEST-003")
    assert len(findings) == 1
    schema_finding = repository.finding_to_schema(findings[0])
    assert schema_finding.finding_id == "WEB-TEST-001"
    assert schema_finding.status == FindingStatus.SUSPECTED


def test_update_finding_status_promotes_to_confirmed(db_session):
    repository.create_assessment(db_session, Assessment(assessment_id="ASSESSMENT-TEST-004", scope_id="SCOPE-X"))
    finding = Finding(
        finding_id="WEB-TEST-002",
        assessment_id="ASSESSMENT-TEST-004",
        agent_id=AgentId.WEB_SECURITY,
        surface=Surface.WEB,
        asset_id="HOST-001",
        title="Test",
        description="Test",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
    )
    repository.store_findings(db_session, [finding], [])
    db_session.commit()

    repository.update_finding_status(db_session, "WEB-TEST-002", "confirmed", verification_required=False)
    db_session.commit()
    findings = repository.list_findings(db_session, "ASSESSMENT-TEST-004")
    assert findings[0].status == "confirmed"
    assert findings[0].verification_required is False
