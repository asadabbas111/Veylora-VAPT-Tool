from fastapi import APIRouter

from app.api.routes import (
    admin, ai, assessments, assets, attack_paths, audit, auth,
    dashboard, findings, mitre, ml, remediation, reports, risk, validation,
)

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(admin.router)
api_router.include_router(assessments.router)
api_router.include_router(assets.router)
api_router.include_router(findings.router)
api_router.include_router(risk.router)
api_router.include_router(attack_paths.router)
api_router.include_router(ai.router)
api_router.include_router(validation.router)
api_router.include_router(remediation.router)
api_router.include_router(reports.router)
api_router.include_router(audit.router)
api_router.include_router(dashboard.router)
api_router.include_router(mitre.router)
api_router.include_router(ml.router)