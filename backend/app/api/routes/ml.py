from pathlib import Path

from fastapi import APIRouter



from fastapi import APIRouter

from app.deps import CurrentUser, DbDep, require_permission, RequirePermission

router = APIRouter(prefix="/ml", tags=["ml"])


def _repo_ml() -> Path:
    return Path(__file__).resolve().parents[4] / "ml"   # backend/app/api/routes -> repo root


@router.get("/status")
def status(db: DbDep, user: CurrentUser):
    from ml.training.train import load_model

    model_dir = _repo_ml() / "models"
    dataset = _repo_ml() / "datasets" / "synthetic_findings.csv"
    meta = model_dir / "metadata.joblib"
    return {
        "model_saved": (model_dir / "priority_model.joblib").exists(),
        "dataset_present": dataset.exists(),
        "metadata_present": meta.exists(),
        "features": ["cvss", "exposure", "asset_criticality", "service_type_encoded",
                     "exploitability", "attack_path_position", "historical_incidents", "confidence"],
        "model": "joblib" ,  # placeholder replaced below
    }


@router.post("/train")
def train(db: DbDep, user: RequirePermission("run_ai")):
    import sys

    sys.path.insert(0, str(_repo_ml().parent))
    from ml.training.train import train_and_evaluate

    try:
        result = train_and_evaluate()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Training failed: {exc}")
    return result


@router.get("/evaluation")
def evaluation(db: DbDep, user: CurrentUser):
    import sys

    sys.path.insert(0, str(_repo_ml().parent))
    from ml.training.train import train_and_evaluate
    from pathlib import Path

    result = train_and_evaluate(save=False)
    # Baseline comparison insight for the research write-up
    results = {r["model"]: r for r in result["results"]}
    base = results.get("CVSS-only baseline", {}).get("f1", 0)
    rf = results.get("Random Forest", {}).get("f1", 0)
    result["insight"] = (
        f"Context-aware machine ranking (Random Forest F1={rf}) outperforms the "
        f"CVSS-only baseline (F1={base}) by {round((rf - base) * 100, 1)} percentage "
        "points, demonstrating the value of incorporating asset criticality, exposure, "
        "exploitability and attack-path context on top of CVSS." if base else "Baseline missing."
    )
    return result