"""
Threat-Lens ML API (Python + FastAPI)

Receives the 17-feature vector from the Go WAF and returns an attack prediction.

Run:
    python ML_api.py
or:
    uvicorn ML_api:app --host 127.0.0.1 --port 8000

Environment:
    HOST         bind address            (default 127.0.0.1 - do not expose publicly)
    PORT         bind port               (default 8000)
    ML_API_KEY   if set, callers must send it in the X-API-Key header

Scoring:
    1. scale features with the persisted StandardScaler (and clip to +-CLIP)
    2. compute the distance to every K-Means centroid
    3. attack_score = softmax(-distance) weighted by each cluster's attack fraction
       (cluster -> attack fraction is stored in waf_model_meta.json)
    4. is_attack = attack_score >= 0.5; confidence = max(score, 1 - score)

If waf_model_meta.json is missing (legacy 2-cluster model) the old behaviour is
kept: cluster 1 == attack, no clipping.
"""
import hmac
import json
import os
from pathlib import Path

import joblib
import numpy as np
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from waf_features import FEATURE_NAMES

BASE = Path(__file__).parent
model = joblib.load(BASE / "waf_kmeans_model.pkl")
scaler = joblib.load(BASE / "waf_scaler.pkl")

_meta_path = BASE / "waf_model_meta.json"
if _meta_path.exists():
    META = json.loads(_meta_path.read_text())
    MODE = "kmeans"
    if META["feature_names"] != FEATURE_NAMES:
        raise RuntimeError("waf_model_meta.json feature order does not match waf_features.FEATURE_NAMES")
else:  # legacy artifacts from the first prototype
    META = {"clip": None, "temperature": 1.0, "cluster_attack_fraction": [0.0, 1.0]}
    MODE = "legacy"

ATTACK_FRACTION = np.asarray(META["cluster_attack_fraction"], dtype=float)
CLIP = META["clip"]
TEMPERATURE = float(META["temperature"])
if len(ATTACK_FRACTION) != model.n_clusters:
    raise RuntimeError("cluster_attack_fraction length does not match the K-Means model")

API_KEY = os.environ.get("ML_API_KEY")


def require_key(x_api_key: str = Header(default="")):
    if API_KEY and not hmac.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


app = FastAPI(
    title="ML-WAF Prediction API",
    description="Receives feature vectors from the Go WAF and returns attack predictions",
    version="0.2.0",
)

# Bounded fields: reject absurd values instead of letting them distort scaling.
_count = dict(ge=0, le=1_000_000)


class FeatureVector(BaseModel):
    """Must match internal/waf/features.go (json tags) and waf_features.FEATURE_NAMES."""
    url_length: float = Field(**_count)
    path_length: float = Field(**_count)
    query_length: float = Field(**_count)
    num_params: float = Field(**_count)
    num_quotes: float = Field(**_count)
    num_percent: float = Field(**_count)
    num_semicolons: float = Field(**_count)
    num_dashes: float = Field(**_count)
    num_slashes: float = Field(**_count)
    num_dots: float = Field(**_count)
    has_sql_keywords: float = Field(ge=0, le=1)
    has_xss_keywords: float = Field(ge=0, le=1)
    has_path_traversal: float = Field(ge=0, le=1)
    body_length: float = Field(ge=0, le=1_000_000_000)
    header_count: float = Field(ge=0, le=10_000)
    method_get: float = Field(ge=0, le=1)
    method_post: float = Field(ge=0, le=1)


class PredictionResponse(BaseModel):
    """What we send back to the Go WAF."""
    is_attack: bool
    cluster: int
    confidence: float
    attack_score: float


def score(vector: list) -> tuple:
    z = scaler.transform(np.asarray([vector], dtype=float))
    if CLIP is not None:
        z = np.clip(z, -CLIP, CLIP)
    d = np.linalg.norm(model.cluster_centers_ - z, axis=1)
    w = np.exp(-(d - d.min()) / TEMPERATURE)
    w /= w.sum()
    return int(d.argmin()), float(w @ ATTACK_FRACTION)


@app.post("/predict", response_model=PredictionResponse, dependencies=[Depends(require_key)])
def predict(data: FeatureVector):
    """Return whether the described request looks like an attack."""
    values = data.model_dump()
    cluster, attack_score = score([values[name] for name in FEATURE_NAMES])
    is_attack = attack_score >= 0.5
    return {
        "is_attack": bool(is_attack),
        "cluster": cluster,
        "confidence": round(max(attack_score, 1.0 - attack_score), 4),
        "attack_score": round(attack_score, 4),
    }


@app.get("/health")
def health():
    """Health check - the Go WAF uses this to verify the API is alive."""
    return {"status": "ok", "service": "ml-waf-api", "mode": MODE, "clusters": int(model.n_clusters)}


if __name__ == "__main__":
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")))
