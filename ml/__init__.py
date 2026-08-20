"""ML research module for the FYP.

Research question:
    Can an AI-assisted risk engine prioritize vulnerabilities more effectively
    than traditional severity-only (CVSS) prioritization by incorporating asset
    criticality, exposure, exploitability and attack-path context?

This module implements a measurable ML component: a supervised priority-score
model trained on lab-derived vulnerability records. Three classifiers are
compared (Logistic Regression, Random Forest, XGBoost when available) and
evaluated against a CVSS-only baseline using accuracy, precision, recall, F1 and
ROC-AUC.

NOTE ON DATA: the packaged dataset is generated deterministically from the
documented lab scenarios (see ml/datasets/README.md). It mirrors realistic
distributions (CVSS, exposure, criticality, exploitability class, attack-path
position, detection confidence, historical incidents). In a live deployment the
same pipeline can be fed from exported assessment findings.
"""

import ml  # noqa: F401  (package marker, see __init__.py)