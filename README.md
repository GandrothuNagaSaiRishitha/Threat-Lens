# Threat-Lens

### ML-Assisted Web Application Firewall Prototype

Threat-Lens is a prototype **Machine Learning-assisted Web Application Firewall (WAF)** designed to analyze HTTP request characteristics and identify potentially malicious traffic.

The project combines a lightweight Go HTTP service with a Python/FastAPI machine-learning service. HTTP request characteristics are represented as numerical features, normalized using a trained scaler, and evaluated using a pre-trained **K-Means clustering model** to identify traffic patterns associated with attacks.

> **Project status:** Prototype / Work in Progress
> The repository currently contains the ML inference service and supporting model/data artifacts, but the Go component is still a minimal HTTP-server demonstration rather than a fully integrated production WAF.

---

## Overview

Traditional rule-based WAFs rely heavily on predefined signatures and patterns such as SQL injection keywords, suspicious characters, path traversal sequences, and XSS payloads.

Threat-Lens explores a complementary approach:

```text
                 HTTP Request
                       │
                       ▼
              ┌─────────────────┐
              │ Request Features │
              │                 │
              │ URL / Path      │
              │ Query Parameters │
              │ Special Chars   │
              │ SQL / XSS Flags  │
              │ Request Method   │
              │ Body / Headers   │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Feature Scaler  │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ K-Means Model   │
              │                 │
              │ Cluster 0       │
              │ Cluster 1       │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Attack Decision │
              │                 │
              │ is_attack       │
              │ cluster         │
              │ confidence      │
              └─────────────────┘
```

The intended architecture separates HTTP traffic handling from ML inference so that the model can be developed and deployed independently of the Go application.

---

## Key Features

* **HTTP request feature extraction** based on structural and lexical properties of requests.
* **Machine-learning-based anomaly classification** using K-Means clustering.
* **Feature normalization** using a persisted scaler.
* **FastAPI inference service** for receiving feature vectors from an external WAF component.
* **Health-check endpoint** for service availability monitoring.
* **Serialized model artifacts** included in the repository for local inference.
* **Training dataset** containing benign and attack-oriented request feature patterns.
* **WAF logging schema** prepared for recording request and prediction information.

---

## Architecture

Threat-Lens is intended to operate as two cooperating services:

```text
                    ┌──────────────────────┐
                    │      HTTP Client      │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │      Go WAF Layer    │
                    │                      │
                    │ Request Handling     │
                    │ Feature Extraction   │
                    │ Rule-Based Checks    │
                    └──────────┬───────────┘
                               │
                     Feature Vector
                               │
                               ▼
                    ┌──────────────────────┐
                    │   FastAPI ML Service │
                    │       :8000          │
                    │                      │
                    │ Feature Scaling      │
                    │ K-Means Inference    │
                    │ Attack Classification│
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Prediction Response  │
                    │                      │
                    │ is_attack            │
                    │ cluster              │
                    │ confidence           │
                    └──────────────────────┘
```

### Current implementation

The Python ML service is implemented and exposes `/predict` and `/health`.

The Go component currently provides a simple `/hello` endpoint and demonstrates HTTP method, path, and query-parameter handling. It does **not yet perform the complete WAF workflow shown above**.

---

## Machine Learning Pipeline

### Input features

The model expects the following 17 numerical features:

| Feature              | Description                  |
| -------------------- | ---------------------------- |
| `url_length`         | Total URL length             |
| `path_length`        | URL path length              |
| `query_length`       | Query-string length          |
| `num_params`         | Number of query parameters   |
| `num_quotes`         | Number of quote characters   |
| `num_percent`        | Number of percent characters |
| `num_semicolons`     | Number of semicolons         |
| `num_dashes`         | Number of dashes             |
| `num_slashes`        | Number of slash characters   |
| `num_dots`           | Number of dots               |
| `has_sql_keywords`   | SQL-keyword indicator        |
| `has_xss_keywords`   | XSS-keyword indicator        |
| `has_path_traversal` | Path-traversal indicator     |
| `body_length`        | HTTP request-body length     |
| `header_count`       | Number of HTTP headers       |
| `method_get`         | GET-method indicator         |
| `method_post`        | POST-method indicator        |

These features are represented as floating-point values by the FastAPI request model.

---

## Model

Threat-Lens uses two serialized machine-learning artifacts:

```text
waf_scaler.pkl
waf_kmeans_model.pkl
```

### Feature scaling

The incoming feature vector is passed through the persisted scaler before inference.

### K-Means classification

The scaled vector is then passed to the K-Means model.

The current inference logic interprets:

```text
Cluster 0 → Benign
Cluster 1 → Attack
```

The predicted cluster is converted into an `is_attack` boolean.

### Important implementation note

The current model-serving code is a prototype. The prediction response currently uses a fixed:

```text
confidence = 0.85
```

This value is not calculated from the model's distance to a centroid or another calibrated probability measure.

For a production implementation, confidence should be derived from an appropriate statistical or distance-based metric and calibrated against a validation dataset.

---

## Dataset

The repository contains:

```text
waf_training_data.csv
```

The dataset contains request-level numerical features followed by:

* `label`
* `cluster`
* `predicted_label`

The data includes examples representing both benign and attack-oriented traffic patterns.

The attack examples contain combinations of characteristics such as:

* unusually long query strings
* multiple parameters
* quote characters
* dashes and semicolons
* SQL-related indicators
* XSS-related indicators
* path-traversal indicators
* unusual URL structures

The dataset is relatively small, so it should be considered suitable for experimentation and demonstration rather than production-grade model validation.

---

## API

The ML component is implemented using **FastAPI**.

### Start the ML service

```bash
python ML_api.py
```

Or using Uvicorn:

```bash
uvicorn ML_api:app --host 0.0.0.0 --port 8000
```

Once running, the API is available at:

```text
http://localhost:8000
```

FastAPI also provides interactive API documentation at:

```text
http://localhost:8000/docs
```

### Health Check

```http
GET /health
```

Example response:

```json
{
  "status": "ok",
  "service": "ml-waf-api",
  "mode": "mock"
}
```

### Prediction

```http
POST /predict
Content-Type: application/json
```

The endpoint accepts the 17-feature request vector and returns:

```json
{
  "is_attack": true,
  "cluster": 1,
  "confidence": 0.85
}
```

---

## Example Prediction Request

```json
{
  "url_length": 45,
  "path_length": 8,
  "query_length": 35,
  "num_params": 1,
  "num_quotes": 2,
  "num_percent": 0,
  "num_semicolons": 0,
  "num_dashes": 0,
  "num_slashes": 1,
  "num_dots": 0,
  "has_sql_keywords": 1,
  "has_xss_keywords": 0,
  "has_path_traversal": 0,
  "body_length": 0,
  "header_count": 8,
  "method_get": 1,
  "method_post": 0
}
```

The API returns the cluster selected by the K-Means model together with the current attack classification.

---

## Go HTTP Server

The repository also contains:

```text
goServer.go
```

The current Go program starts an HTTP server on port `8080` and exposes:

```text
GET /hello
```

It displays:

* HTTP method
* request path
* `name` query parameter
* `age` query parameter

Example:

```bash
go run goServer.go
```

Then:

```bash
curl "http://localhost:8080/hello?name=ThreatLens&age=1"
```

The current Go implementation is a minimal HTTP-server example. It does **not yet connect to the FastAPI ML service**, perform request-feature extraction, enforce WAF rules, or block malicious requests.

---

## Project Structure

```text
Threat-Lens/
│
├── ML_api.py
│   └── FastAPI ML inference service
│
├── goServer.go
│   └── Minimal Go HTTP server
│
├── tempCodeRunnerFile.go
│   └── Temporary/editor-generated Go file
│
├── waf_kmeans_model.pkl
│   └── Serialized K-Means model
│
├── waf_scaler.pkl
│   └── Serialized feature scaler
│
├── waf_training_data.csv
│   └── ML training/evaluation dataset
│
├── waf_logs.csv
│   └── WAF prediction log schema
│
├── requirements.txt
│   └── Python dependency file
│
├── .gitignore
│   └── Git ignore configuration
│
└── README.md
    └── Project documentation
```

---

## File-by-File Description

### `ML_api.py`

The main ML-serving component.

Responsibilities:

1. Load the serialized K-Means model.
2. Load the serialized feature scaler.
3. Define the expected HTTP-request feature schema using Pydantic.
4. Accept feature vectors through `/predict`.
5. Scale the incoming features.
6. Run K-Means inference.
7. Interpret cluster `1` as an attack.
8. Return the prediction to the caller.
9. Expose `/health` for service monitoring.

---

### `goServer.go`

A minimal Go HTTP server.

It demonstrates:

* HTTP server creation
* route registration
* HTTP request handling
* query-parameter extraction

It is currently not a functioning WAF engine.

---

### `tempCodeRunnerFile.go`

Contains only:

```go
package main
```

This appears to be a temporary file created by a development environment and has no functional role in the project.

It should normally be removed from the repository.

---

### `waf_kmeans_model.pkl`

Serialized machine-learning model used during inference.

It is loaded by `ML_api.py` using `joblib`.

---

### `waf_scaler.pkl`

Serialized preprocessing/scaling object used to normalize incoming feature vectors before they are passed to the K-Means model.

---

### `waf_training_data.csv`

Contains the feature vectors used by the ML workflow.

The schema contains request characteristics followed by:

```text
label
cluster
predicted_label
```

This file provides the data foundation for the current prototype.

---

### `waf_logs.csv`

Defines the intended structure for WAF request logs:

```text
timestamp
client_ip
method
url
url_length
path_length
query_length
num_params
num_quotes
num_percent
num_semicolons
num_dashes
num_slashes
num_dots
has_sql_keywords
has_xss_keywords
has_path_traversal
body_length
header_count
method_get
method_post
is_attack
confidence
```

At present, the committed file contains the header but no logged request records.

---

### `requirements.txt`

Intended to contain the Python dependencies required to run the ML API.

At present, the file is empty, so dependencies must currently be installed manually.

The Python source requires packages including:

```text
fastapi
pydantic
uvicorn
joblib
numpy
```

---

### `.gitignore`

The file currently contains no ignore rules.

For a real development project, it should at minimum exclude Python virtual environments, cache files, editor artifacts, generated logs, and other local files.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/GandrothuNagaSaiRishitha/Threat-Lens.git
cd Threat-Lens
```

### 2. Create a Python virtual environment

```bash
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows:

```powershell
.venv\Scripts\activate
```

### 3. Install Python dependencies

Because the current `requirements.txt` is empty, install the required packages directly:

```bash
pip install fastapi uvicorn pydantic joblib numpy
```

### 4. Start the ML API

```bash
python ML_api.py
```

The service starts on:

```text
http://localhost:8000
```

---

## Running the Go Component

Install Go and run:

```bash
go run goServer.go
```

The server listens on:

```text
http://localhost:8080
```

Test it with:

```bash
curl "http://localhost:8080/hello?name=ThreatLens&age=1"
```


---

## Recommended Production Architecture

A more complete implementation could evolve toward:

```text
                         Internet
                            │
                            ▼
                  ┌────────────────────┐
                  │ Reverse Proxy / LB │
                  └──────────┬─────────┘
                             │
                             ▼
                  ┌────────────────────┐
                  │      Go WAF        │
                  │                    │
                  │ Request Parsing    │
                  │ Rule Engine        │
                  │ Feature Extraction │
                  └──────────┬─────────┘
                             │
                    ┌────────┴────────┐
                    │                 │
                    ▼                 ▼
             Rule Detection      ML Service
                    │                 │
                    │          ┌──────┴──────┐
                    │          │ Scaler      │
                    │          │ ML Model    │
                    │          └──────┬──────┘
                    │                 │
                    └────────┬────────┘
                             ▼
                    ┌──────────────────┐
                    │ Decision Engine  │
                    │                  │
                    │ ALLOW            │
                    │ BLOCK            │
                    │ LOG / ALERT      │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Application      │
                    └──────────────────┘
```

---

## Security Considerations

Threat-Lens is a security research/prototyping project and should currently be treated as such.

Before production deployment:

1. Do not expose the ML API directly to the public Internet.
2. Authenticate service-to-service communication.
3. Validate and constrain incoming feature values.
4. Protect serialized model files from unauthorized replacement.
5. Log model decisions and request metadata securely.
6. Avoid logging sensitive request bodies or credentials.
7. Add rate limiting.
8. Run services with least-privilege permissions.
9. Use HTTPS/TLS for network communication.
10. Continuously evaluate false positives and false negatives.

---

## Technology Stack

### Backend

* **Go** — HTTP/WAF layer prototype
* **Python** — ML inference service
* **FastAPI** — REST API framework
* **Uvicorn** — ASGI server
* **Pydantic** — request/response validation

### Machine Learning

* **K-Means clustering**
* **Feature scaling**
* **NumPy**
* **Joblib** serialized model artifacts

### Data

* CSV-based training data
* CSV-based WAF logging schema

---

## Project Status

Threat-Lens currently demonstrates the core idea of separating a WAF/request-processing layer from an ML inference service.

The strongest implemented portion is the **model-serving interface and persisted ML artifacts**. The Go WAF integration, production request inspection, and complete prediction pipeline remain under development.

It should **not currently be considered a production-ready WAF**.

---
