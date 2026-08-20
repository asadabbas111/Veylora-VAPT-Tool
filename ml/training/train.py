"""Training + evaluation for the ML prioritization model.

Trains Logistic Regression, Random Forest and (optionally) XGBoost on the
synthetic dataset, reports accuracy / precision / recall / F1 / ROC-AUC for each,
plus the CVSS-only baseline for the research comparison.
"""

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.preprocessing import label_binarize
from sklearn.model_selection import train_test_split
import joblib

from ml.preprocessing.preprocess import FEATURES, TARGET

DATASET_PATH = Path(__file__).resolve().parent.parent / "datasets" / "synthetic_findings.csv"
MODEL_DIR = Path(__file__).resolve().parent.parent / "models"


def _xgboost_cls():
    try:
        from xgboost import XGBClassifier

        return XGBClassifier(n_estimators=120, max_depth=4, eval_metric="mlogloss", verbosity=0, random_state=0)
    except ImportError:
        return None


def _baseline_cvss(X, y):
    """CVSS-only baseline: predict class purely from the CVSS score."""
    y_pred = np.zeros_like(y)
    for i, (_, row) in enumerate(X.iterrows()):
        # crude bin mapping: cvss -> severity class
        c = row["cvss"]
        if c >= 9:
            y_pred[i] = 3
        elif c >= 7:
            y_pred[i] = 2
        elif c >= 4:
            y_pred[i] = 1
        else:
            y_pred[i] = 0
    return y_pred


def _report(name: str, y, y_pred, y_prob) -> dict:
    auc = 0.0
    try:
        n_classes = len(np.unique(y))
        if n_classes == 2:
            auc = float(roc_auc_score(y, y_pred))
        elif y_prob is not None and y_prob.shape[1] == n_classes:
            y_bin = label_binarize(y, classes=np.unique(y))
            auc = float(roc_auc_score(y_bin, y_prob, multi_class="ovr", average="weighted"))
    except Exception:  # noqa: BLE001
        auc = 0.0
    return {
        "model": name,
        "accuracy": round(float(accuracy_score(y, y_pred)), 4),
        "precision": round(float(precision_score(y, y_pred, average="weighted", zero_division=0)), 4),
        "recall": round(float(recall_score(y, y_pred, average="weighted", zero_division=0)), 4),
        "f1": round(float(f1_score(y, y_pred, average="weighted", zero_division=0)), 4),
        "roc_auc": round(auc, 4),
    }


def train_and_evaluate(dataset_path: Path | None = None, save: bool = True):
    path = dataset_path or DATASET_PATH
    if not path.exists():
        from ml.preprocessing.preprocess import build_dataset

        build_dataset(path)
    df = pd.read_csv(path)
    df = df.dropna(subset=FEATURES + [TARGET])
    X = df[FEATURES]
    y = df[TARGET].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=7, stratify=y)

    results: list[dict] = []
    best = None

    # CVSS-only baseline
    y_baseline = _baseline_cvss(X_test, y_test)
    results.append(_report("CVSS-only baseline", y_test, y_baseline, None))

    # Logistic Regression
    lr = LogisticRegression(max_iter=2000, random_state=0)
    lr.fit(X_train, y_train)
    yp = lr.predict(X_test)
    results.append(_report("Logistic Regression", y_test, yp, lr.predict_proba(X_test)))
    best = lr

    # Random Forest
    rf = RandomForestClassifier(n_estimators=200, max_depth=None, random_state=0)
    rf.fit(X_train, y_train)
    yp = rf.predict(X_test)
    results.append(_report("Random Forest", y_test, yp, rf.predict_proba(X_test)))
    if rf.score(X_test, y_test) > best.score(X_test, y_test):
        best = rf

    # XGBoost (optional)
    xgb = _xgboost_cls()
    if xgb is not None:
        xgb.fit(X_train, y_train)
        yp = xgb.predict(X_test)
        results.append(_report("XGBoost", y_test, yp, xgb.predict_proba(X_test)))
        if xgb.score(X_test, y_test) > best.score(X_test, y_test):
            best = xgb

    summary = {
        "dataset": str(path),
        "records": int(len(df)),
        "class_distribution": df[TARGET].value_counts().sort_index().to_dict(),
        "results": results,
    }
    if save and best is not None:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(best, MODEL_DIR / "priority_model.joblib")
        joblib.dump({"features": FEATURES, "model": results}, MODEL_DIR / "metadata.joblib")
        summary["saved_model"] = str(MODEL_DIR / "priority_model.joblib")
    return summary


def load_model():
    p = MODEL_DIR / "priority_model.joblib"
    if not p.exists():
        return None
    return joblib.load(p)


if __name__ == "__main__":
    import json

    res = train_and_evaluate()
    print(json.dumps(res, indent=2))