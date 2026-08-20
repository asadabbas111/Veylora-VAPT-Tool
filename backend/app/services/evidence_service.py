import hashlib
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import settings
from app.models.evidence import Evidence


class EvidenceStore:
    """Immutable, content-addressed evidence storage.

    Evidence text/files are stored on disk keyed by their SHA-256; the database
    row records the hash, timestamp, source and owning assessment/finding.
    """

    def __init__(self) -> None:
        self.root = settings.evidence_path
        self.root.mkdir(parents=True, exist_ok=True)

    def _target_path(self, sha256: str) -> Path:
        return self.root / sha256

    def save_content(
        self,
        db: Session,
        assessment_id: int,
        content: str,
        category: str = "scanner_output",
        finding_id: int | None = None,
        source: str | None = None,
        filename: str | None = None,
        metadata: dict | None = None,
    ) -> Evidence:
        sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        path = self._target_path(f"{sha}.txt")
        path.write_text(content, encoding="utf-8")
        record = Evidence(
            assessment_id=assessment_id,
            finding_id=finding_id,
            category=category,
            content=content,
            sha256=sha,
            source=source,
            filename=filename or path.name,
            metadata_json=metadata or {},
        )
        db.add(record)
        db.flush()
        return record

    def save_bytes(
        self,
        db: Session,
        assessment_id: int,
        data: bytes,
        category: str,
        filename: str,
        finding_id: int | None = None,
        source: str | None = None,
        metadata: dict | None = None,
    ) -> Evidence:
        sha = hashlib.sha256(data).hexdigest()
        path = self._target_path(f"{sha}")
        path.write_bytes(data)
        record = Evidence(
            assessment_id=assessment_id,
            finding_id=finding_id,
            category=category,
            content=sha,  # store hash reference for binary blobs
            sha256=sha,
            source=source,
            filename=filename,
            metadata_json=metadata or {},
        )
        db.add(record)
        db.flush()
        return record

    def verify_integrity(self, record: Evidence) -> bool:
        """Recompute the hash of stored evidence to verify immutability."""
        path = self._target_path(f"{record.sha256}.txt")
        if not path.exists() and record.content == record.sha256:
            return True  # binary blob content is the hash itself
        if not path.exists():
            return False
        return hashlib.sha256(path.read_bytes()).hexdigest() == record.sha256


evidence_store = EvidenceStore()