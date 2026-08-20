import faulthandler
import sys
import datetime as dt

sys.path.insert(0, ".")
faulthandler.dump_traceback_later(40, exit=True)

from app.database import init_db, SessionLocal
from app.models.assessment import Assessment, AssessmentScope, AssessmentTarget
from app.models.user import User
from app.security.passwords import hash_password

print("bootstrap", flush=True)
init_db()
print("init_db ok", flush=True)
db = SessionLocal()
u = User(full_name="T", email="t2@example.com", password_hash=hash_password("Admin12345"), role="admin", is_active=True, is_verified=True)
db.add(u)
print("adding user", flush=True)
db.commit()
print("user commit ok", flush=True)
db.refresh(u)
a = Assessment(name="Direct Test", start_date=dt.date.today(), end_date=None, validation_level=1, status="draft", stage="created", owner_id=u.id)
db.add(a)
db.commit()
db.refresh(a)
print("assessment", a.id, flush=True)
db.add(AssessmentScope(assessment_id=a.id, target="192.168.56.0/24", target_type="cidr", created_by=u.id))
for ip in ("192.168.56.105", "192.168.56.106", "192.168.56.110"):
    db.add(AssessmentTarget(assessment_id=a.id, target=ip, target_type="ipv4", in_scope=True, added_by=u.id))
db.commit()
print("scope ok", flush=True)

from app.tasks.pipeline import stage_asset_discovery
print("discovery start", flush=True)
r1 = stage_asset_discovery(a.id)
print("discovery done", r1, flush=True)

from app.tasks.pipeline import stage_vulnerability_scan
print("scan start", flush=True)
r2 = stage_vulnerability_scan(a.id)
print("scan done", r2, flush=True)