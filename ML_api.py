"""
ML API (Python + FastAPI)


To run:
    python ml_api.py

Or with uvicorn:
    uvicorn ml_api:app --host 0.0.0.0 --port 8000 --reload
"""

from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
import joblib 
import numpy as np 


model = joblib.load("waf_kmeans_model.pkl")
scaler = joblib.load("waf_scaler.pkl")

app = FastAPI(
    title="ML-WAF Prediction API",
    description="Receives feature vectors from Go WAF and returns attack predictions",
    version="0.1.0"
)



class FeatureVector(BaseModel):
    """
    This MUST exactly match the FeatureVector struct in your Go code.
    Pydantic validates that all fields are present and are floats.
    """
    url_length: float
    path_length: float
    query_length: float
    num_params: float
    num_quotes: float
    num_percent: float
    num_semicolons: float
    num_dashes: float
    num_slashes: float
    num_dots: float
    has_sql_keywords: float
    has_xss_keywords: float
    has_path_traversal: float
    body_length: float
    header_count: float
    method_get: float
    method_post: float

class PredictionResponse(BaseModel):
    """What we send back to the Go WAF."""
    is_attack: bool
    cluster: int
    confidence: float

# ═══════════════════════════════════════════════════════════════
# PREDICTION ENDPOINT (Mock ML for now)
# ═══════════════════════════════════════════════════════════════

@app.post("/predict", response_model=PredictionResponse)
def predict(data: FeatureVector):
    """
    Receives a feature vector from the Go WAF and returns
    whether the request is an attack or not.
"""

    features = np.array([[data.url_length, data.path_length, ..., data.method_post]])
    features_scaled = scaler.transform(features)
    cluster = model.predict(features_scaled)[0]

    #Determine which cluster is "attack" 
    is_attack = (cluster == 1)
    confidence = 0.85  # Or calculate from distance to centroid
   
    return {"is_attack": bool(is_attack), "cluster": int(cluster), "confidence": confidence}

@app.get("/health")
def health():
    """Health check — Go WAF can use this to verify the API is alive."""
    return {"status": "ok", "service": "ml-waf-api", "mode": "mock"}

#main body

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)