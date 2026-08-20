"""Assessment workflow pipeline.

Drives the stages of an authorized assessment as background jobs. Every stage
records its status/timestamps in the assessment's stage log, updates progress and
writes audit records. A stage never runs against a target that is outside the
authorized scope, and every stage honors the global kill switch.
"""

import ipaddress
import random
from datetime import datetime
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models.assessment import Assessment, AssessmentScope, AssessmentTarget
from app.models.asset import Asset, Service
from app.models.finding import Finding
from app.models.job import Job
from app.risk.engine import calculate_risk
from app.scanners.base import ScanTarget
from app.scanners.engine import scan_engine
from app.services.audit_service import audit
from app.services.mitre_service import map_finding, seed_techniques
from app.services.normalization import upsert_finding
from app.attack_graph.engine import build_graph, propagate_path_importance

StageFn = Callable[..., Any]

STAGES = [
    "asset_discovery",
    "service_enumeration",
    "vulnerability_scan",
    "vulnerability_normalization",
    "risk_calculation",
    "attack_path_analysis",
    "ai_analysis",
    "validation",
    "report_generation",
]

_current_stage_progress = {
    "asset_discovery": 10,
    "service_enumeration": 20,
    "vulnerability_scan": 45,
    "vulnerability_normalization": 55,
    "risk_calculation": 65,
    "attack_path_analysis": 75,
    "ai_analysis": 85,
    "validation": 92,
    "report_generation": 100,
}


def _db() -> Session:
    return SessionLocal()


def _fresh_assessment(db: Session, assessment_id: int) -> Assessment | None:
    return db.query(Assessment).filter(Assessment.id == assessment_id).first()


def _set_stage(db: Session, assessment: Assessment, stage: str, status: str, note: str = "") -> None:
    stage_log = dict(assessment.stage_log or {})
    stage_log[stage] = {
        "status": status,
        "started_at": datetime.utcnow().isoformat() if status == "running" else stage_log.get(stage, {}).get("started_at"),
        "finished_at": datetime.utcnow().isoformat() if status in ("completed", "failed") else None,
        "note": note,
    }
    assessment.stage_log = stage_log
    assessment.stage = stage
    assessment.progress = max(assessment.progress, _current_stage_progress.get(stage, 0))
    db.add(assessment)
    db.commit()


def _targets_for(db: Session, assessment_id: int) -> list[ScanTarget]:
    """Return the scope-validated in-scope targets as ScanTarget objects."""
    reqs = db.query(AssessmentTarget).filter(AssessmentTarget.assessment_id == assessment_id, AssessmentTarget.in_scope.is_(True)).all()
    scopes = db.query(AssessmentScope).filter(AssessmentScope.assessment_id == assessment_id).all()

    from app.services.scope_service import validate_target_against_scopes

    out: list[ScanTarget] = []
    for r in reqs:
        check = validate_target_against_scopes(r.target, scopes)
        if check.in_scope:
            out.append(ScanTarget(value=r.target, target_type=r.target_type))
    return out


# ---------------------------------------------------------------------------
# Stage: asset discovery
# ---------------------------------------------------------------------------
def stage_asset_discovery(
    assessment_id: int,
    _job_id: int | None = None,
    _job_log: Callable | None = None,
    _job_is_stopped: Callable | None = None,
) -> dict:
    db = _db()
    assessment = _fresh_assessment(db, assessment_id)
    if not assessment:
        return {"error": "assessment not found"}
    _set_stage(db, assessment, "asset_discovery", "running")
    targets = _targets_for(db, assessment_id)
    created = 0
    for t in targets:
        if _job_is_stopped and _job_is_stopped():
            _set_stage(db, assessment, "asset_discovery", "failed", "stopped")
            return {"created": created, "stopped": True}
        # Expand CIDR to /24-resolution hosts for a realistic asset inventory
        hosts = _expand_target(t.value, t.target_type)
        for host in hosts:
            existing = db.query(Asset).filter(
                Asset.assessment_id == assessment_id, Asset.ip_address == host
            ).first()
            if not existing:
                criticality = _crit_for(host)
                asset = Asset(
                    assessment_id=assessment_id,
                    ip_address=host,
                    ip_version="6" if ":" in host else "4",
                    hostname=_hostname_for(host),
                    mac_address=_mac_for(host),
                    os_name="Linux" if criticality else "Unknown",
                    os_version="2.6.24-16-server" if criticality else None,
                    criticality=criticality,
                    last_seen=datetime.utcnow(),
                    metadata_json={"discovered_by": "simulated-adapter", "vendor": "lab"},
                )
                db.add(asset)
                created += 1
    db.commit()
    _set_stage(db, assessment, "asset_discovery", "completed", f"{created} asset(s) registered")
    audit(db, assessment.owner_id, "Asset discovery completed", assessment_id=assessment_id,
          result="success", detail=f"{created} assets created")
    return {"created": created}


def _expand_target(value: str, target_type: str) -> list[str]:
    if target_type == "cidr":
        try:
            net = ipaddress.ip_network(value, strict=False)
            if net.num_addresses > 300:
                # avoid huge scans in a lab demo: sample /24
                net = ipaddress.ip_network(f"{net.network_address}/24", strict=False)
            hosts = [str(ip) for ip in net.hosts()]
            return hosts[:50] if len(hosts) > 50 else hosts
        except ValueError:
            return [value]
    return [value]


def _crit_for(host: str) -> float:
    # Lab convention: host database/backend nodes are higher value.
    rand = random.Random(host)
    if host.endswith(".105") or host.endswith(".110"):
        return 9.0
    if host.endswith(".106"):
        return 8.0
    return round(rand.uniform(1.0, 6.0), 1)


def _hostname_for(host: str) -> str:
    map_ = {".105": "web-server", ".106": "database-server", ".110": "jump-host", ".100": "kali"}
    for suffix, name in map_.items():
        if host.endswith(suffix):
            return f"{name}.lab"
    return f"host-{host.replace('.', '-')}.lab"


def _mac_for(host: str) -> str:
    r = random.Random(host)
    return "08:00:27:" + ":".join(f"{r.randint(0, 255):02x}" for _ in range(3))


# ---------------------------------------------------------------------------
# Stage: service enumeration + vulnerability scan + normalization
# ---------------------------------------------------------------------------
def stage_vulnerability_scan(
    assessment_id: int,
    _job_id: int | None = None,
    _job_log: Callable | None = None,
    _job_is_stopped: Callable | None = None,
) -> dict:
    db = _db()
    assessment = _fresh_assessment(db, assessment_id)
    if not assessment:
        return {"error": "assessment not found"}
    _set_stage(db, assessment, "vulnerability_scan", "running")

    targets = _targets_for(db, assessment_id)
    scan_results = scan_engine.scan(targets)
    finding_count = 0

    from app.services.normalization import resolve_asset

    for sr in scan_results:
        if _job_is_stopped and _job_is_stopped():
            _set_stage(db, assessment, "vulnerability_scan", "failed", "stopped")
            return {"stopped": True}

        asset_keys = {rf.asset_key for rf in sr.raw_findings}
        for key in asset_keys:
            if not resolve_asset(db, assessment_id, key):
                db.add(Asset(
                    assessment_id=assessment_id,
                    ip_address=key if ":" not in key else None,
                    hostname=key if ":" in key else None,
                    os_name="Unknown",
                    criticality=_crit_for(key.split(":")[0]) if ":" not in key else 3.0,
                    last_seen=datetime.utcnow(),
                ))
        db.commit()

        for rf in sr.raw_findings:
            if _job_is_stopped and _job_is_stopped():
                break
            try:
                finding = upsert_finding(db, assessment_id, rf)
                _ensure_service(db, assessment_id, finding, rf)
                finding_count += 1
            except LookupError:
                continue  # asset not registered for that adapter output
            except Exception:  # noqa: BLE001  - isolated adapter failures don't kill the stage
                continue

        if _job_is_stopped and _job_is_stopped():
            _set_stage(db, assessment, "vulnerability_scan", "failed", "stopped")
            return {"stopped": True}
        db.commit()

    db.commit()
    _set_stage(db, assessment, "service_enumeration", "completed", "services enumerated")
    _set_stage(db, assessment, "vulnerability_scan", "completed", f"{finding_count} findings collected")
    _set_stage(db, assessment, "vulnerability_normalization", "completed", "normalization applied")
    audit(db, assessment.owner_id, "Vulnerability scan completed", assessment_id=assessment_id,
          result="success", detail=f"{finding_count} normalized findings")
    _run_risk_calculation(db, assessment)
    return {"findings": finding_count}


def _ensure_service(db: Session, assessment_id: int, finding: Finding, rf) -> Service | None:
    """Create or update any missing service row for the finding."""
    if not finding.affected_port:
        return None
    asset = db.get(Asset, finding.asset_id)
    if not asset:
        return None
    service = db.query(Service).filter(Service.asset_id == asset.id, Service.port == finding.affected_port).first()
    if not service:
        service = Service(
            asset_id=asset.id,
            port=finding.affected_port,
            protocol=finding.protocol or "tcp",
            service_name=finding.affected_service,
            product=finding.affected_service,
            version=rf.metadata.get("version") if isinstance(rf.metadata, dict) else None,
            metadata_json={"detected_by": rf.source},
        )
        db.add(service)
        db.flush()
    elif finding.affected_service and not service.service_name:
        service.service_name = finding.affected_service
    find_svc_count = db.query(Service).filter(Service.asset_id == asset.id).count()
    return service


# ---------------------------------------------------------------------------
# Stage: risk calculation
# ---------------------------------------------------------------------------
def stage_risk_calculation(
    assessment_id: int,
    _job_id: int | None = None,
    _job_log: Callable | None = None,
    _job_is_stopped: Callable | None = None,
) -> dict:
    db = _db()
    assessment = _fresh_assessment(db, assessment_id)
    if not assessment:
        return {"error": "not found"}
    _run_risk_calculation(db, assessment, mark_stage=True)
    return {"status": "ok"}


def _run_risk_calculation(db: Session, assessment: Assessment, mark_stage: bool = False) -> None:
    if mark_stage:
        _set_stage(db, assessment, "risk_calculation", "running")
    findings = db.query(Finding).filter(Finding.assessment_id == assessment.id).all()
    assets = db.query(Asset).filter(Asset.assessment_id == assessment.id).all()
    asset_map = {a.id: a for a in assets}

    for f in findings:
        asset = asset_map.get(f.asset_id)
        criticality = asset.criticality if asset else 1.0
        importance = float((f.risk_breakdown or {}).get("attack_path_importance", 0) or 0)
        fp = 100 - f.confidence
        result = calculate_risk(
            cvss=f.cvss_score,
            criticality=criticality,
            cwe=f.cwe,
            cve=f.cve,
            ip=asset.ip_address if asset else None,
            hostname=asset.hostname if asset else None,
            port=f.affected_port,
            confidence=f.confidence,
            attack_path_importance=importance,
            false_positive_likelihood=fp,
        )
        f.risk_score = result.score
        f.risk_breakdown = {**result.breakdown, "total_score": result.score, "classification": result.classification,
                            "false_positive_penalty": round(fp, 2)}
        f.severity = result.classification
        db.add(f)
        if asset:
            num = db.query(Finding).filter(Finding.asset_id == asset.id).count()
            asset.risk_score = round(sum(f.risk_score for f in findings if f.asset_id == asset.id) / max(num, 1), 2)
            db.add(asset)
    db.commit()
    if mark_stage:
        _set_stage(db, assessment, "risk_calculation", "completed")


# ---------------------------------------------------------------------------
# Stage: attack path analysis
# ---------------------------------------------------------------------------
def stage_attack_paths(
    assessment_id: int,
    _job_id: int | None = None,
    _job_log: Callable | None = None,
    _job_is_stopped: Callable | None = None,
) -> dict:
    db = _db()
    assessment = _fresh_assessment(db, assessment_id)
    if not assessment:
        return {"error": "not found"}
    _set_stage(db, assessment, "attack_path_analysis", "running")
    result = build_graph(db, assessment)
    propagate_path_importance(db, assessment_id)
    # Recalculate risk now that path importance is known
    _run_risk_calculation(db, assessment)
    _set_stage(db, assessment, "attack_path_analysis", "completed",
               f"{result.info.path_count} path(s) found, {result.info.node_count} graph nodes")
    audit(db, assessment.owner_id, "Attack-path analysis completed", assessment_id=assessment_id,
          result="success", detail=str(result.info))
    return {"paths": result.info.path_count, "nodes": result.info.node_count}


# ---------------------------------------------------------------------------
# Stage: AI analysis
# ---------------------------------------------------------------------------
def stage_ai_analysis(
    assessment_id: int,
    _job_id: int | None = None,
    _job_log: Callable | None = None,
    _job_is_stopped: Callable | None = None,
) -> dict:
    db = _db()
    assessment = _fresh_assessment(db, assessment_id)
    if not assessment:
        return {"error": "not found"}
    from app.ai.analyst import ai_analyst

    _set_stage(db, assessment, "ai_analysis", "running")
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).order_by(Finding.risk_score.desc()).all()
    count = 0
    for f in findings:
        if _job_is_stopped and _job_is_stopped():
            break
        try:
            ai_analyst.analyze_finding(db, f)
            db.commit()
            count += 1
        except Exception:  # noqa: BLE001
            continue
    _set_stage(db, assessment, "ai_analysis", "completed", f"{count} findings analyzed")
    audit(db, assessment.owner_id, "AI analysis completed", assessment_id=assessment_id, result="success")
    return {"analyzed": count}


# ---------------------------------------------------------------------------
# Stage: report generation
# ---------------------------------------------------------------------------
def stage_report_generation(
    assessment_id: int,
    report_type: str = "full",
    _job_id: int | None = None,
    _job_log: Callable | None = None,
    _job_is_stopped: Callable | None = None,
) -> dict:
    from app.reports.generator import generate_report

    db = _db()
    assessment = _fresh_assessment(db, assessment_id)
    if not assessment:
        return {"error": "not found"}
    _set_stage(db, assessment, "report_generation", "running")
    path, sha, size = generate_report(db, assessment, report_type=report_type)
    _set_stage(db, assessment, "report_generation", "completed", f"report {path}")
    audit(db, assessment.owner_id, "Report generated", assessment_id=assessment_id, result="success")
    return {"path": path, "sha256": sha, "size": size}


PIPELINE_STAGES: dict[str, StageFn] = {
    "asset_discovery": stage_asset_discovery,
    "vulnerability_scan": stage_vulnerability_scan,
    "risk_calculation": stage_risk_calculation,
    "attack_path_analysis": stage_attack_paths,
    "ai_analysis": stage_ai_analysis,
    "report_generation": stage_report_generation,
}


def run_full_workflow(
    assessment_id: int,
    _job_id: int | None = None,
    _job_log: Callable | None = None,
    _job_is_stopped: Callable | None = None,
) -> dict:
    """Run the complete authorized-assessment workflow as a single job."""
    db = _db()
    assessment = _fresh_assessment(db, assessment_id)
    if not assessment:
        return {"error": "assessment not found"}
    if assessment.status == "draft":
        assessment.status = "running"
        db.add(assessment)
        db.commit()

    stages = ("asset_discovery", "vulnerability_scan", "risk_calculation",
              "attack_path_analysis", "ai_analysis", "report_generation")
    results: dict[str, Any] = {}
    for stage in stages:
        if _job_is_stopped and _job_is_stopped():
            _set_stage(db, assessment, stage, "failed", "workflow stopped")
            db.commit()
            return {**results, "stopped": True}
        fn = PIPELINE_STAGES[stage]
        try:
            results[stage] = fn(assessment_id, _job_id=_job_id, _job_log=_job_log, _job_is_stopped=_job_is_stopped)
        except Exception as exc:  # noqa: BLE001
            db = _db()
            assessment = _fresh_assessment(db, assessment_id)
            _set_stage(db, assessment, stage, "failed", str(exc))
            return {**results, "error": str(exc)}

    db = _db()
    assessment = _fresh_assessment(db, assessment_id)
    if assessment:
        assessment.status = "completed"
        assessment.stage = "report_generation" if not assessment.stage_log.get("report_generation") else "completed"
        assessment.progress = 100.0
        db.add(assessment)
        _mark_evidence_immutable(db, assessment_id)
        db.commit()
    return {"stage_results": results, "completed": True}


def _mark_evidence_immutable(db: Session, assessment_id: int) -> None:
    """Evidence is immutable after assessment completion."""
    from app.models.evidence import Evidence

    items = db.query(Evidence).filter(Evidence.assessment_id == assessment_id).all()
    for ev in items:
        ev.immutable = True
    db.commit()