from fastapi import APIRouter, HTTPException

from app.config import settings


from app.config import settings
from app.deps import CurrentUser, DbDep, require_permission, RequirePermission
from app.models.assessment import Assessment, AssessmentScope, AssessmentTarget
from app.models.user import User
from app.security.kill_switch import kill_switch
from app.security.passwords import hash_password
from app.services.audit_service import audit
from app.tasks.pipeline import run_full_workflow
from app.tasks.manager import task_manager
from app.models.job import Job

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users")
def list_users(db: DbDep, user: RequirePermission("manage_users")):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [
        {"id": u.id, "full_name": u.full_name, "email": u.email, "role": u.role,
         "is_active": u.is_active, "is_verified": u.is_verified, "created_at": u.created_at,
         "last_login_at": u.last_login_at}
        for u in users
    ]


@router.post("/users", status_code=201)
def create_user(payload: dict, db: DbDep, user: RequirePermission("manage_users")):
    from app.schemas.auth import RegisterRequest

    req = RegisterRequest(full_name=payload.get("full_name"), email=payload.get("email"),
                          password=payload.get("password"))
    if db.query(User).filter(User.email == req.email.lower()).first():
        raise HTTPException(status_code=409, detail="Email already registered.")
    u = User(full_name=req.full_name, email=req.email.lower(), password_hash=hash_password(req.password),
             role=payload.get("role", "viewer"), is_active=True, is_verified=True)
    db.add(u)
    db.commit()
    db.refresh(u)
    audit(db, user.id, "User created by admin", object_type="user", object_id=u.id, result="success", detail=req.email)
    return {"id": u.id, "email": u.email, "role": u.role}


@router.patch("/users/{user_id}")
def update_user(user_id: int, payload: dict, db: DbDep, user: RequirePermission("manage_users")):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")
    role = payload.get("role")
    if role and role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=422, detail="Invalid role.")
    if role:
        target.role = role
    if "disabled" in payload:
        target.disabled = bool(payload["disabled"])
    db.add(target)
    db.commit()
    db.refresh(target)
    audit(db, user.id, "User updated", object_type="user", object_id=user_id, result="success", detail=f"role={role}")
    return {"id": target.id, "email": target.email, "role": target.role, "disabled": target.disabled}


@router.post("/kill-switch/arm")
def arm_kill_switch(db: DbDep, user: RequirePermission("kill_switch")):
    kill_switch.arm()
    audit(db, user.id, "KILL SWITCH ARMED", result="success",
          detail="All active operations globally blocked.")
    return {"armed": True, "message": "Kill switch armed. All active operations are blocked."}


@router.post("/kill-switch/disarm")
def disarm_kill_switch(db: DbDep, user: RequirePermission("kill_switch")):
    kill_switch.disarm()
    audit(db, user.id, "Kill switch disarmed", result="success")
    return {"armed": False, "message": "Kill switch disarmed."}


@router.get("/kill-switch/status")
def kill_switch_status(db: DbDep, user: CurrentUser):
    return {"armed": kill_switch.is_armed}


@router.post("/seed-demo", status_code=201)
def seed_demo(db: DbDep, user: RequirePermission("run_scan")):
    """Create and run a full demonstration assessment against the authorized lab
    network so the dashboard and reports are populated immediately."""
    from datetime import date, timedelta

    existing = db.query(Assessment).filter(Assessment.name == "Metasploitable Lab Assessment").first()
    if existing:
        if existing.status == "completed":
            return {"assessment_id": existing.id, "message": "Demo assessment already completed."}
        if existing.status in ("running", "scoping"):
            return {"assessment_id": existing.id, "message": "Demo assessment is already running."}

    a = Assessment(
        name="Metasploitable Lab Assessment",
        description="Automated vulnerability assessment and controlled validation against the authorized Metasploitable lab network (simulated data source).",
        client_name="Cyber Security Research Lab",
        assessment_type="vulnerability_assessment",
        start_date=date.today(),
        end_date=date.today() + timedelta(days=7),
        rules_of_engagement="Non-destructive validation only. Active exploitation limited to controlled PoC inside the isolated lab network.",
        validation_level=1,
        status="draft",
        stage="created",
        stage_log={},
        owner_id=user.id,
    )
    db.add(a)
    db.commit()
    db.refresh(a)

    scope = AssessmentScope(assessment_id=a.id, target="192.168.56.0/24", target_type="cidr",
                            description="Authorized lab host-only network", created_by=user.id)
    db.add(scope)
    for ip in ("192.168.56.105", "192.168.56.106", "192.168.56.110"):
        db.add(AssessmentTarget(assessment_id=a.id, target=ip, target_type="ipv4",
                                in_scope=True, validation_note="Inside authorized 192.168.56.0/24 scope", added_by=user.id))
    db.commit()

    job = Job(assessment_id=a.id, task_type="full", status="pending", started_by=user.id, params_json={"demo": True})
    db.add(job)
    db.commit()
    db.refresh(job)
    task_manager.submit(job.id, run_full_workflow, a.id)
    audit(db, user.id, "Demo assessment seeded", assessment_id=a.id, object_type="assessment", object_id=a.id, result="success")
    return {"assessment_id": a.id, "job_id": job.id, "message": "Demo assessment started. It will populate assets, findings, risk, attack paths and AI analysis in the background."}