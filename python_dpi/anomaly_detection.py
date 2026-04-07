from __future__ import annotations

from collections import defaultdict
import importlib
import subprocess
import sys
from typing import Any

from .types import AppType, DetectionMethod, Flow


def _load_isolation_forest():
    try:
        module = importlib.import_module("sklearn.ensemble")
        return getattr(module, "IsolationForest")
    except Exception:
        return None


def _probe_sklearn_available() -> bool:
    try:
        completed = subprocess.run(
            [sys.executable, "-c", "import sklearn.ensemble; print('ok')"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
        )
        if completed.returncode != 0:
            return False
        probe_output = f"{completed.stdout}\n{completed.stderr}"
        if "MINGW-W64" in probe_output or "CRASHES ARE TO BE EXPECTED" in probe_output:
            return False
        return True
    except Exception:
        return False


SKLEARN_AVAILABLE = False


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def _is_encrypted(flow: Flow) -> bool:
    if flow.detection_method in (DetectionMethod.TLS_SNI, DetectionMethod.DNS_CORRELATED):
        return True
    if flow.tuple.dst_port == 443 or flow.tuple.src_port == 443:
        return True
    return flow.app_type == AppType.HTTPS


def extract_flow_features(flow: Flow) -> dict[str, Any]:
    return {
        "packet_count": int(flow.packet_count),
        "byte_count": int(flow.byte_count),
        "duration": int(flow.duration_seconds),
        "avg_packet_size": float(flow.avg_packet_size),
        "protocol": int(flow.tuple.protocol),
        "app_type": int(flow.app_type),
        "is_encrypted": bool(_is_encrypted(flow)),
    }


def _vectorize(features: dict[str, Any]) -> list[float]:
    return [
        float(features["packet_count"]),
        float(features["byte_count"]),
        float(features["duration"]),
        float(features["avg_packet_size"]),
        float(features["protocol"]),
        float(features["app_type"]),
        1.0 if features["is_encrypted"] else 0.0,
    ]


def classify_risk(score: float) -> str:
    if score < 0.35:
        return "Low"
    if score < 0.70:
        return "Medium"
    return "High"


def compute_risk_score(flow: Flow) -> float:
    unknown_component = 1.0 if flow.app_type == AppType.UNKNOWN else 0.0
    suspicious_component = 1.0 if flow.is_suspicious else 0.0
    blocked_component = 1.0 if flow.blocked else 0.0

    weighted = (
        0.50 * _clamp01(float(flow.anomaly_score))
        + 0.20 * unknown_component
        + 0.20 * suspicious_component
        + 0.10 * blocked_component
    )
    return _clamp01(weighted)


def apply_ai_scoring(flows: dict) -> dict[str, Any]:
    flow_values = [flow for flow in flows.values() if isinstance(flow, Flow)]
    if not flow_values:
        return {"ai_enabled": SKLEARN_AVAILABLE, "risk_distribution": {"Low": 0, "Medium": 0, "High": 0}}

    for flow in flow_values:
        flow.anomaly_score = 0.5

    ai_enabled = False
    isolation_forest_cls = _load_isolation_forest() if SKLEARN_AVAILABLE else None
    if isolation_forest_cls is not None and len(flow_values) >= 8:
        try:
            model = isolation_forest_cls(contamination=0.10, random_state=42)
            vectors = [_vectorize(extract_flow_features(flow)) for flow in flow_values]
            model.fit(vectors)

            # Higher decision_function means less anomalous; invert and normalize to [0,1].
            decisions = list(model.decision_function(vectors))
            min_val = min(decisions)
            max_val = max(decisions)
            span = max_val - min_val
            for idx, flow in enumerate(flow_values):
                if span <= 1e-12:
                    normalized = 0.5
                else:
                    normalized = (max_val - decisions[idx]) / span
                flow.anomaly_score = _clamp01(float(normalized))
            ai_enabled = True
        except Exception:
            ai_enabled = False

    risk_distribution: dict[str, int] = defaultdict(int)
    for flow in flow_values:
        flow.risk_score = compute_risk_score(flow)
        risk_distribution[classify_risk(flow.risk_score)] += 1

    return {
        "ai_enabled": ai_enabled,
        "risk_distribution": {
            "Low": int(risk_distribution.get("Low", 0)),
            "Medium": int(risk_distribution.get("Medium", 0)),
            "High": int(risk_distribution.get("High", 0)),
        },
    }
