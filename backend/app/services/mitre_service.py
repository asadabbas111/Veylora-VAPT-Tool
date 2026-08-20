"""MITRE ATT&CK mapping. Maps normalized findings to techniques/tactics and
computes coverage statistics for the MITRE coverage dashboard."""

from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.mitre import MitreTechnique

# CWE -> primary technique mapping (best-effort academic mapping)
CWE_TO_TECHNIQUE: dict[str, tuple[str, str]] = {
    "CWE-78": ("T1059", "Command and Scripting Interpreter"),
    "CWE-94": ("T1059", "Command and Scripting Interpreter"),
    "CWE-89": ("T1190", "Exploit Public-Facing Application"),
    "CWE-22": ("T1083", "File and Directory Discovery"),
    "CWE-287": ("T1078", "Valid Accounts"),
    "CWE-798": ("T1110", "Brute Force"),
    "CWE-319": ("T1040", "Network Sniffing"),
    "CWE-327": ("T1557", "Adversary-in-the-Middle"),
    "CWE-200": ("T1592", "Gather Victim Host Information"),
    "CWE-93": ("T1566", "Phishing"),
}
# technique -> tactic
TECHNIQUE_TACTIC: dict[str, str] = {
    "T1059": "Execution",
    "T1190": "Initial Access",
    "T1083": "Discovery",
    "T1078": "Defense Evasion / Initial Access",
    "T1110": "Credential Access",
    "T1040": "Credential Access",
    "T1557": "Credential Access",
    "T1210": "Lateral Movement",
    "T1200": "Initial Access",
    "T1078.001": "Initial Access",
    "T1592": "Reconnaissance",
    "T1566": "Initial Access",
    "T1071": "Command and Control",
    "T1021": "Lateral Movement",
    "T1539": "Collection",
    "T1555": "Credential Access",
    "T1098": "Persistence",
}

KNWOWN_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
    "T1040": ("Network Sniffing", "Credential Access"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1078": ("Valid Accounts", "Defense Evasion / Initial Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1592": ("Gather Victim Host Information", "Reconnaissance"),
    "T1200": ("Hardware Additions", "Initial Access"),
}


def seed_techniques(db: Session) -> None:
    """Insert known techniques so coverage metrics are complete."""
    for tid, (name, tactic) in KNWOWN_TECHNIQUES.items():
        existing = db.query(MitreTechnique).filter(MitreTechnique.technique_id == tid).first()
        if not existing:
            db.add(MitreTechnique(technique_id=tid, name=name, tactic=tactic))
    db.commit()


def map_finding(db: Session, finding: Finding) -> list[MitreTechnique]:
    """Assign MitreTechniques to a finding using metadata or CWE heuristics."""
    seed_techniques(db)
    added: list[MitreTechnique] = []

    candidates = list((finding.metadata_json or {}).get("techniques", []) or [])
    if finding.cwe:
        cwe = (finding.cwe or "").upper()
        if cwe in CWE_TO_TECHNIQUE:
            tid, _ = CWE_TO_TECHNIQUE[cwe]
            candidates.append(tid)

    for tid in candidates:
        t = db.query(MitreTechnique).filter(MitreTechnique.technique_id == tid).first()
        if t:
            if t not in finding.mitre_techniques:
                finding.mitre_techniques.append(t)
                added.append(t)
    return added


def coverage_stats(db: Session, assessment_id: int) -> dict:
    """Coverage dashboard stats for an assessment."""
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    observed: set[str] = set()
    tactics: set[str] = set()
    for f in findings:
        for t in f.mitre_techniques or []:
            observed.add(t.technique_id)
            tactics.add(t.tactic)
    total = len(KNWOWN_TECHNIQUES)
    coverage = round(len(observed) / total * 100, 1) if total else 0
    return {
        "techniques_observed": sorted(observed),
        "technique_count": len(observed),
        "tactics_observed": sorted(tactics),
        "tactic_count": len(tactics),
        "coverage_percentage": coverage,
        "total_known": total,
    }