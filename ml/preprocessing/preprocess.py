"""Synthetic, documented lab dataset generator for the ML component.

Five assessment scenarios (A..E) described in docs/research.md are simulated:
A few high-value findings, many low-severity findings, one critical finding,
an attack-path-heavy scenario, and a false-positive-heavy scan.

Every generated record is deterministic (seeded) so evaluation is reproducible.
"""

import random
from pathlib import Path

import pandas as pd

FEATURES = [
    "cvss", "exposure", "asset_criticality", "service_type_encoded",
    "exploitability", "attack_path_position", "historical_incidents",
    "confidence",
]
TARGET = "priority_class"  # 0 = low, 1 = medium, 2 = high, 3 = critical

SEV_BOUNDS = {"info": (0, 19), "low": (20, 39), "medium": (40, 59), "high": (60, 79), "critical": (80, 100)}


def _servicetype():
    return random.choice(["web", "db", "ssh", "ftp", "smtp", "smb"])


def _sample(seed_base: int, n: int, profile: str) -> pd.DataFrame:
    rng = random.Random(seed_base)
    rows = []
    for i in range(n):
        cvss = rng.uniform(0, 10)
        exposure = rng.uniform(1, 20)
        criticality = rng.uniform(1, 10)
        exploitability = rng.uniform(0, 10)
        confidence = rng.uniform(5, 100)
        historical = rng.randint(0, 15)
        path_pos = 0.0

        if profile == "A":  # few severe findings
            cvss = rng.uniform(7, 10); exploitability = rng.uniform(7, 10)
            path_pos = rng.choice([0.0, 6.0, 10.0])
        elif profile == "B":  # many low findings
            cvss = rng.uniform(0.5, 4); exposure = rng.uniform(1, 6)
        elif profile == "C":  # one critical
            cvss = rng.uniform(9, 10); exposure = 20; criticality = rng.uniform(8, 10)
            path_pos = 10.0; exploitability = rng.uniform(8, 10)
        elif profile == "D":  # attack-path heavy
            path_pos = rng.uniform(2, 10); exploitability = rng.uniform(5, 10)
        elif profile == "E":  # false-positive heavy
            confidence = rng.uniform(5, 40)

        score = (
            cvss * 4                    # up to 40  (CVSS weight)
            + criticality * 1.2         # up to 12  (asset criticality)
            + exploitability * 0.8      # up to 8   (exploitability)
            + exposure * 0.8            # up to 16  (exposure)
            + confidence * 0.04         # up to 4   (detection confidence)
            + path_pos * 0.5            # up to 5   (attack-path position)
            + min(historical, 5) * 0.4  # up to 2   (historical incidents)
        )
        score = min(100, max(0, round(score, 1)))
        cls = 0
        for i_c, (_k, (lo, hi)) in enumerate(SEV_BOUNDS.items()):
            if lo <= score <= hi:
                cls = i_c
        rows.append({
            "cvss": round(cvss, 2), "exposure": round(exposure, 2),
            "asset_criticality": round(criticality, 2),
            "service_type_encoded": float(["web", "db", "ssh", "ftp", "smtp", "smb"].index(_servicetype())),
            "exploitability": round(exploitability, 2),
            "attack_path_position": round(path_pos, 1),
            "historical_incidents": historical, "confidence": round(confidence, 1),
            TARGET: cls,
            "scenario": profile,
        })
    return pd.DataFrame(rows)


def build_dataset(out_path: Path, n_per_scenario: int = 600) -> pd.DataFrame:
    frames = [_sample(i, n_per_scenario, p) for i, p in enumerate("ABCDE", start=42)]
    df = pd.concat(frames, ignore_index=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    return df


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "datasets" / "synthetic_findings.csv"
    df = build_dataset(out)
    print(f"Wrote {len(df)} rows -> {out}")
    print(df[TARGET].value_counts().sort_index())