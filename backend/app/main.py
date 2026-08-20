from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.router import api_router
from app.config import settings
from app.database import init_db
from app.security.rate_limit import rate_limiter

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Authorized vulnerability assessment and penetration-testing orchestration platform. "
        "All active operations are restricted to explicitly authorized assessment scopes."
    ),
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production lock this down to the deployed frontend origin.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client = request.client.host if request.client else "unknown"
    path = request.url.path
    # Authentication endpoints get a tighter budget to slow credential stuffing.
    budget = 20 if "/auth/" in path else settings.RATE_LIMIT_MAX
    if not rate_limiter.allow(f"{client}:{path}", max_requests=budget):
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Slow down."})
    return await call_next(request)


@app.on_event("startup")
def on_startup() -> None:
    from app.services.mitre_service import seed_techniques
    from app.security.passwords import hash_password
    from app.models.user import User
    from app.database import SessionLocal

    init_db()
    db = SessionLocal()
    try:
        seed_techniques(db)
        # Seed admin account
        admin = db.query(User).filter(User.email == settings.SEED_ADMIN_EMAIL).first()
        if not admin:
            admin = User(
                full_name="Platform Administrator",
                email=settings.SEED_ADMIN_EMAIL,
                password_hash=hash_password(settings.SEED_ADMIN_PASSWORD),
                role="admin",
                is_active=True,
                is_verified=True,
            )
            db.add(admin)
            db.commit()
            print(f"[startup] Seeded admin account: {settings.SEED_ADMIN_EMAIL}")
    finally:
        db.close()


app.include_router(api_router, prefix=settings.API_PREFIX)


@app.get("/")
def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/api/docs",
        "health": "ok",
    }