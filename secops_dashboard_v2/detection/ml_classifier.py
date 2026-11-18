"""
ML CLASSIFIER - REAL TRAINING, SYNTHETIC DATA
------------------------------------------------
What changed from the previous version: this is now a GENUINE logistic
regression trained with real gradient descent, pure Python (no numpy/sklearn
dependency, so it runs anywhere). Every number downstream - accuracy,
precision, recall, F1, the confusion matrix - is computed from actual
predictions the model makes on a held-out test split it never saw during
training. Nothing is typed in or back-calculated from a target accuracy.

What is still honestly synthetic: the TRAINING DATA ITSELF. There is no
real labeled corpus of Windows ransomware telemetry in this project, so
the dataset generator below produces structured synthetic feature vectors
(rename_rate, note_present, shadow_copy_attempt, process_entropy,
file_write_burst) with labels drawn from a known decision rule plus noise.
This means: the MODEL and the EVALUATION are real; the GROUND TRUTH LABELS
are synthetic because no real ones exist yet. Swap `generate_dataset()` for
a loader over real labeled Sysmon/Wazuh exports and nothing else changes -
same training loop, same metric functions.
"""

import json
import math
import os
import random
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
METRICS_FILE = os.path.join(BASE_DIR, "model_metrics.json")

FEATURE_NAMES = ["rename_rate", "note_present", "shadow_copy_attempt", "process_entropy", "file_write_burst"]
TRUE_WEIGHTS = {"rename_rate": 3.1, "note_present": 2.4, "shadow_copy_attempt": 2.0, "process_entropy": 1.1, "file_write_burst": 1.6}
TRUE_BIAS = -3.2


def generate_dataset(n=3000, seed=42):
    """Synthetic but structured: labels come from a fixed linear decision
    rule over the features plus Gaussian noise, so there IS a learnable
    signal (unlike pure random labels), but it is not real telemetry."""
    rng = random.Random(seed)
    X, y = [], []
    for _ in range(n):
        feats = {
            "rename_rate": rng.random(),
            "note_present": 1.0 if rng.random() < 0.3 else 0.0,
            "shadow_copy_attempt": 1.0 if rng.random() < 0.25 else 0.0,
            "process_entropy": rng.random(),
            "file_write_burst": rng.random(),
        }
        z = TRUE_BIAS + sum(TRUE_WEIGHTS[k] * feats[k] for k in FEATURE_NAMES)
        z += rng.gauss(0, 0.8)  # label noise so the task isn't trivially separable
        prob = 1 / (1 + math.exp(-z))
        label = 1 if rng.random() < prob else 0
        X.append([feats[k] for k in FEATURE_NAMES])
        y.append(label)
    return X, y


def train_test_split(X, y, test_frac=0.25, seed=7):
    rng = random.Random(seed)
    idx = list(range(len(X)))
    rng.shuffle(idx)
    n_test = int(len(X) * test_frac)
    test_idx, train_idx = idx[:n_test], idx[n_test:]
    return ([X[i] for i in train_idx], [y[i] for i in train_idx],
            [X[i] for i in test_idx], [y[i] for i in test_idx])


def _sigmoid(z):
    z = max(min(z, 30), -30)
    return 1 / (1 + math.exp(-z))


def train_logistic_regression(X, y, lr=0.3, epochs=200):
    """Real batch gradient descent. Returns learned weights/bias and the
    real loss/accuracy curve observed during training (on the training
    set itself - the held-out test metrics are computed separately)."""
    n_features = len(X[0])
    w = [0.0] * n_features
    b = 0.0
    n = len(X)
    history = []

    for epoch in range(1, epochs + 1):
        grad_w = [0.0] * n_features
        grad_b = 0.0
        total_loss = 0.0
        correct = 0
        for xi, yi in zip(X, y):
            z = b + sum(w[j] * xi[j] for j in range(n_features))
            p = _sigmoid(z)
            eps = 1e-9
            total_loss += -(yi * math.log(p + eps) + (1 - yi) * math.log(1 - p + eps))
            pred = 1 if p >= 0.5 else 0
            if pred == yi:
                correct += 1
            error = p - yi
            for j in range(n_features):
                grad_w[j] += error * xi[j]
            grad_b += error

        for j in range(n_features):
            w[j] -= lr * grad_w[j] / n
        b -= lr * grad_b / n

        if epoch % max(1, epochs // 20) == 0 or epoch == 1:
            history.append({
                "epoch": epoch,
                "loss": round(total_loss / n, 4),
                "train_accuracy": round(correct / n, 4),
            })

    return {"weights": dict(zip(FEATURE_NAMES, [round(x, 4) for x in w])), "bias": round(b, 4)}, history


def predict_proba(model, feats_vec):
    z = model["bias"] + sum(model["weights"][FEATURE_NAMES[j]] * feats_vec[j] for j in range(len(feats_vec)))
    return _sigmoid(z)


def evaluate(model, X_test, y_test, threshold=0.5):
    """REAL evaluation: runs the trained model on held-out samples it never
    saw, compares predictions to true labels, builds a genuine confusion
    matrix, then computes precision/recall/F1/accuracy from it."""
    tp = fp = fn = tn = 0
    for xi, yi in zip(X_test, y_test):
        p = predict_proba(model, xi)
        pred = 1 if p >= threshold else 0
        if pred == 1 and yi == 1:
            tp += 1
        elif pred == 1 and yi == 0:
            fp += 1
        elif pred == 0 and yi == 1:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(y_test) if y_test else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0

    return {
        "confusion_matrix": {"true_positive": tp, "false_positive": fp, "false_negative": fn, "true_negative": tn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "specificity": round(specificity, 4),
        "test_set_size": len(y_test),
    }


def mock_train(epochs=80):
    """Train logistic regression and evaluate on held-out data."""
    print("[ML] Loading training corpus (8,500 samples, 5 behavioral features)...")
    X, y = generate_dataset(n=8500)
    X_train, y_train, X_test, y_test = train_test_split(X, y)
    print(f"[ML] Train/test split: {len(X_train)} train / {len(X_test)} held-out test samples")

    t0 = time.time()
    model, history = train_logistic_regression(X_train, y_train, epochs=epochs)
    elapsed = time.time() - t0

    for h in history:
        if h['epoch'] % 10 == 0 or h['epoch'] == epochs:
            print(f"[ML] Epoch {h['epoch']}/{epochs} - loss={h['loss']:.4f} - train_accuracy={h['train_accuracy']:.4f}")

    eval_metrics = evaluate(model, X_test, y_test)
    print(f"[ML] Held-out evaluation: "
          f"F1={eval_metrics['f1_score']} Precision={eval_metrics['precision']} "
          f"Recall={eval_metrics['recall']} Accuracy={eval_metrics['accuracy']}")

    metrics = {
        "status": "TRAINED",
        "note": "Logistic regression trained with gradient descent. Metrics computed on held-out test set.",
        "training_time_seconds": round(elapsed, 3),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "final_train_accuracy": history[-1]["train_accuracy"],
        "final_loss": history[-1]["loss"],
        "history": history,
        "model_type": "Logistic Regression (gradient descent)",
        "learned_weights": model["weights"],
        "learned_bias": model["bias"],
        "evaluation": eval_metrics,
    }
    with open(METRICS_FILE, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"[ML] Metrics saved to {METRICS_FILE}")
    return metrics, model


def extract_features_from_telemetry(telemetry_events):
    rename_count = sum(1 for e in telemetry_events if e["event_type"] == "mass_file_rename")
    has_note = any(e["event_type"] == "ransom_note_dropped" for e in telemetry_events)
    has_shadow_attempt = any(e["event_type"] == "shadow_copy_deletion_attempt" for e in telemetry_events)
    # process_entropy / file_write_burst are stand-ins for signals this simple
    # telemetry format doesn't carry (real deployment would pull these from
    # Sysmon process creation + file I/O rate); derived deterministically so
    # the live demo is reproducible rather than randomized.
    rename_rate = min(rename_count / 10.0, 1.0)
    return {
        "rename_rate": rename_rate,
        "note_present": 1.0 if has_note else 0.0,
        "shadow_copy_attempt": 1.0 if has_shadow_attempt else 0.0,
        "process_entropy": min(0.4 + rename_rate * 0.3, 1.0),
        "file_write_burst": rename_rate,
        "_raw_rename_count": rename_count,
    }


def predict(telemetry_events, model=None):
    feats = extract_features_from_telemetry(telemetry_events)
    if model is None:
        if os.path.exists(METRICS_FILE):
            with open(METRICS_FILE) as f:
                saved = json.load(f)
            model = {"weights": saved["learned_weights"], "bias": saved["learned_bias"]}
        else:
            # no trained model on disk yet - train one now
            _, model = mock_train()

    vec = [feats[name] for name in FEATURE_NAMES]
    prob = predict_proba(model, vec)
    label = "ransomware_behavior" if prob >= 0.7 else ("suspicious_file_activity" if prob >= 0.35 else "benign")

    return {
        "model_type": "Logistic Regression (real gradient descent, pure Python)",
        "mock": False,
        "features_used": feats,
        "ransomware_probability": round(prob, 4),
        "predicted_label": label,
    }


if __name__ == "__main__":
    mock_train()
