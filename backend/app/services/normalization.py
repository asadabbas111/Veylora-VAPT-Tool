"""Normalization layer: converts tool-agnostic RawFindings into the common
Finding schema, deduplicates equivalent findings and attaches evidence."""

import hashlib
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.asset import Asset, Service
from app.models.finding import Finding
from app.risk.engine import classify_cvss, classify_severity
from app.scanners.base import RawFinding
from app.services.evidence_service import evidence_store
from app.services.mitre_service import map_finding


def _fingerprint(assessment_id: int, asset_id: int, title: str, port: int | None, service: str | None, cve: str | None) -> str:
    key = f"{assessment_id}|{asset_id}|{title}|{port}|{service}|{cve}".lower()
    return hashlib.sha256(key.encode()).hexdigest()[:64]


def resolve_asset(db: Session, assessment_id: int, asset_key: str) -> Asset | None:
    """Find an asset by IP or hostname for the assessment. Returns None if not found."""
    asset_key = asset_key.strip()
    q = db.query(Asset).filter(Asset.assessment_id == assessment_id)
    asset = q.filter(Asset.ip_address == asset_key).first() or q.filter(Asset.hostname == asset_key).first()
    return asset


def resolve_service(db: Session, asset: Asset, port: int | None, service_name: str | None) -> Service | None:
    if port is None:
        return None
    return (
        db.query(Service)
        .filter(Service.asset_id == asset.id, Service.port == port)
        .first()
    )


def upsert_finding(db: Session, assessment_id: int, raw: RawFinding) -> Finding:
    """Normalize one raw finding into the common schema, deduplicating by
    fingerprint (same assessment, asset, title, port, service, cve)."""
    asset = resolve_asset(db, assessment_id, raw.asset_key)
    if not asset:
        # The asset may have been discovered by another adapter; skip quietly.
        raise LookupError(f"No asset registered for target key {raw.asset_key!r}")

    service = resolve_service(db, asset, raw.affected_port, raw.affected_service)
    fp = _fingerprint(assessment_id, asset.id, raw.title, raw.affected_port, raw.affected_service, raw.cve)

    finding = db.query(Finding).filter(
        Finding.assessment_id == assessment_id,
        Finding.asset_id == asset.id,
        Finding.fingerprint == fp,
    ).first()

    severity = raw.severity or classify_cvss(raw.cvss_score)
    if finding:
        # Merge & refresh window
        finding.last_seen = datetime.utcnow()
        finding.severity = severity
        finding.cvss_score = raw.cvss_score if raw.cvss_score is not None else finding.cvss_score
        finding.cvss_vector = raw.cvss_vector or finding.cvss_vector
        finding.confidence = max(finding.confidence, raw.confidence)
        finding.remediation = raw.remediation or finding.remediation
        if raw.evidence:
            _attach_evidence(db, assessment_id, finding, raw)
        db.add(finding)
        db.flush()
        return finding

    finding = Finding(
        assessment_id=assessment_id,
        asset_id=asset.id,
        service_id=service.id if service else None,
        external_id=raw.metadata.get("external_id"),
        title=raw.title,
        description=raw.description,
        cve=raw.cve,
        cwe=raw.cwe,
        cvss_score=raw.cvss_score,
        cvss_vector=raw.cvss_vector,
        severity=severity,
        affected_service=raw.affected_service,
        affected_port=raw.affected_port,
        protocol=raw.protocol,
        confidence=raw.confidence,
        detection_source=raw.source,
        remediation=raw.remediation,
        fingerprint=fp,
        metadata_json={
            "severity_from_cvss": classify_cvss(raw.cvss_score),
            "template_id": raw.metadata.get("template_id"),
            "techniques": raw.metadata.get("techniques", []),
        },
    )
    db.add(finding)
    db.flush()
    if raw.evidence:
        _attach_evidence(db, assessment_id, finding, raw)
    map_finding(db, finding)
    db.flush()
    return finding


def _attach_evidence(db: Session, assessment_id: int, finding: Finding, raw: RawFinding) -> None:
    """Store each raw evidence string as a hashed evidence record."""
    for text in raw.evidence:
        if not text:
            continue
        existing = db.query(Finding).filter(Finding.id == finding.id).first()
        for ev in existing.evidence:
            if ev.sha256 == hashlib.sha256(text.encode()).hexdigest():
                break
        else:
            evidence_store.save_content(
                db,
                assessment_id=assessment_id,
                finding_id=finding.id,
                content=text,
                category="scanner_output",
                source=raw.source,
                metadata={"adapter": raw.source},
            )


def recompute_severity(db: Session, finding: Finding, risk_score: float) -> None:
    finding.severity = classify_severity(risk_score)
    db.add(finding)