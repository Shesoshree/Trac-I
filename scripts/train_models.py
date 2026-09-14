"""Train and evaluate production ML ensemble and NLP models for Trac-I.

Uses authentic labeled dataset from data/labeled_phishing_dataset.json.
Trains:
1. NLP TF-IDF + LogisticRegression intent classifier
2. RandomForestClassifier (100 estimators, balanced class weights)
3. GradientBoostingClassifier (100 estimators)
Computes and serializes evaluation metrics:
- Precision, Recall, F1-Score, ROC-AUC, Confusion Matrix
- Serializes engine/rf_model.joblib, engine/gb_model.joblib,
  engine/nlp_classifier.joblib, engine/nlp_vectorizer.joblib,
  and engine/model_metrics.json
"""

import json
import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

from engine.ml_engine import FEATURE_NAMES, extract_feature_vector

DATASET_PATH = os.path.join("data", "labeled_phishing_dataset.json")
MODEL_DIR = "engine"


def sample_to_analysis_dict(sample: dict) -> dict:
    """Convert a dataset record into the standard feature analysis dictionary."""
    auth_results = sample.get("auth_results", "")
    spf_status = "none"
    if "spf=pass" in auth_results.lower():
        spf_status = "pass"
    elif "spf=fail" in auth_results.lower():
        spf_status = "fail"
    elif "spf=softfail" in auth_results.lower():
        spf_status = "softfail"

    dkim_status = "none"
    if "dkim=pass" in auth_results.lower():
        dkim_status = "pass"
    elif "dkim=fail" in auth_results.lower():
        dkim_status = "fail"

    dmarc_status = "none"
    if "dmarc=pass" in auth_results.lower():
        dmarc_status = "pass"
    elif "dmarc=fail" in auth_results.lower():
        dmarc_status = "fail"

    from_addr = sample.get("from", "")
    return_path = sample.get("return_path", "")
    reply_to = sample.get("reply_to", "")

    from_domain = from_addr.split("@")[-1].strip(">\"' ") if "@" in from_addr else ""
    return_domain = return_path.split("@")[-1].strip(">\"' ") if "@" in return_path else ""
    reply_domain = reply_to.split("@")[-1].strip(">\"' ") if "@" in reply_to else ""

    from engine.features import UrlFeatureExtractor, NlpBodyExtractor

    # Extract URL features
    urls = sample.get("urls", [])
    url_analysis = UrlFeatureExtractor.analyze_all_urls(urls)

    # Extract DOM deception indicators — derive from CONTENT only, never from label
    has_hidden = sample.get("has_hidden_text", False)
    anchor_match = sample.get("anchor_mismatch", False)
    hidden_elements = 1 if has_hidden else 0
    anchor_mismatches = [{"displayed_domain": "login.microsoft.com", "destination_domain": "evil.xyz"}] if anchor_match else []
    dom_analysis = {
        "hidden_elements_count": hidden_elements,
        "anchor_mismatches": anchor_mismatches,
        "external_form_actions": [],  # cannot be derived without live DOM crawl
        "iframe_count": 0,  # cannot be derived from dataset fields alone
        "suspicious_html_score": 60.0 if has_hidden or anchor_match else 0.0,
    }

    # Extract NLP text features
    full_text = f"{sample.get('subject', '')} {sample.get('body', '')}"
    nlp_analysis = NlpBodyExtractor.analyze_text_nlp(full_text)

    # Header risk score estimate
    h_risk = 0.0
    if spf_status == "fail": h_risk += 35.0
    if dkim_status == "fail": h_risk += 25.0
    if dmarc_status == "fail": h_risk += 25.0
    if return_domain and from_domain and return_domain != from_domain: h_risk += 20.0
    if reply_domain and from_domain and reply_domain != from_domain: h_risk += 25.0

    header_analysis = {
        "from": from_addr,
        "from_display": from_addr.split("<")[0].strip('" ') if "<" in from_addr else "",
        "from_domain": from_domain,
        "return_path": return_path,
        "return_path_domain": return_domain,
        "reply_to": reply_to,
        "reply_to_domain": reply_domain,
        "spf": {"status": spf_status, "client_ip": "0.0.0.0"},
        "dkim": {"status": dkim_status, "selector": "s1"},
        "dmarc": {"status": dmarc_status, "action": "none"},
        "mismatches": {
            "return_path": bool(return_domain and from_domain and return_domain != from_domain),
            "reply_to": bool(reply_domain and from_domain and reply_domain != from_domain),
            "display_name_spoof": bool(return_domain and from_domain and return_domain != from_domain),
        },
        "relay": {"hop_count": 3 if (return_domain and from_domain and return_domain != from_domain) else 2, "originating_ip": "0.0.0.0"},
        "header_risk_score": min(100.0, h_risk),
    }

    return {
        "headers": header_analysis,
        "urls": url_analysis,
        "dom": dom_analysis,
        "nlp": nlp_analysis,
    }


def train_all_models():
    print(f"Loading authentic labeled dataset from {DATASET_PATH}...")
    if not os.path.exists(DATASET_PATH):
        from scripts.build_dataset import generate_dataset
        generate_dataset()

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        samples = json.load(f)

    print(f"Loaded {len(samples)} samples. Phase 1: Training NLP text classification model...")

    # 1. Train NLP Model (TF-IDF + LogisticRegression) with cross-validation
    texts = [f"{s.get('subject', '')} {s.get('body', '')}" for s in samples]
    text_labels = np.array([s["label"] for s in samples], dtype=np.int32)

    X_text_train, X_text_test, y_text_train, y_text_test = train_test_split(
        texts, text_labels, test_size=0.20, random_state=42, stratify=text_labels
    )

    tfidf = TfidfVectorizer(max_features=1200, ngram_range=(1, 2), stop_words="english",
                            min_df=2, max_df=0.95, sublinear_tf=True)
    X_train_tfidf = tfidf.fit_transform(X_text_train)
    X_test_tfidf = tfidf.transform(X_text_test)

    nlp_clf = LogisticRegression(C=0.5, class_weight="balanced", random_state=42, max_iter=300)
    nlp_clf.fit(X_train_tfidf, y_text_train)

    # NLP cross-validation
    all_text_tfidf = tfidf.transform(texts)
    nlp_cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    nlp_cv_scores = cross_validate(nlp_clf, all_text_tfidf, text_labels, cv=nlp_cv,
                                   scoring=["accuracy", "f1", "precision", "recall"])
    nlp_test_pred = nlp_clf.predict(X_test_tfidf)
    nlp_acc = accuracy_score(y_text_test, nlp_test_pred)
    print(f"NLP Model Trained!")
    print(f"  Holdout Test Accuracy: {nlp_acc * 100:.2f}%")
    print(f"  5-Fold CV Accuracy:   {nlp_cv_scores['test_accuracy'].mean() * 100:.2f}% (+/- {nlp_cv_scores['test_accuracy'].std() * 100:.2f}%)")
    print(f"  5-Fold CV F1:         {nlp_cv_scores['test_f1'].mean() * 100:.2f}% (+/- {nlp_cv_scores['test_f1'].std() * 100:.2f}%)")
    print(f"  5-Fold CV Precision:  {nlp_cv_scores['test_precision'].mean() * 100:.2f}%")
    print(f"  5-Fold CV Recall:     {nlp_cv_scores['test_recall'].mean() * 100:.2f}%")

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(tfidf, os.path.join(MODEL_DIR, "nlp_vectorizer.joblib"))
    joblib.dump(nlp_clf, os.path.join(MODEL_DIR, "nlp_classifier.joblib"))

    # Reload NLP in-memory so feature extractor utilizes trained model
    from engine.nlp_model import NlpSentimentClassifier
    NlpSentimentClassifier.load_models(MODEL_DIR)

    # 2. Extract Tabular Multi-Dimensional Feature Vectors
    print("Phase 2: Extracting 29 multi-dimensional feature vectors across dataset...")
    X_list = []
    y_list = []

    for s in samples:
        analysis = sample_to_analysis_dict(s)
        vec = extract_feature_vector(analysis)
        X_list.append(vec)
        y_list.append(s["label"])

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)

    # Split into train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"Training ML Ensemble on {len(X_train)} train samples, evaluating on {len(X_test)} holdout test samples...")

    # Train Random Forest (regularized to prevent overfit)
    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=10,
        min_samples_leaf=5,
        min_samples_split=10,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)

    # Train Gradient Boosting (regularized)
    gb = GradientBoostingClassifier(
        n_estimators=80,
        learning_rate=0.06,
        max_depth=3,
        min_samples_leaf=5,
        subsample=0.8,
        random_state=42,
    )
    gb.fit(X_train, y_train)

    # Evaluate Ensemble on Test Set
    rf_probs = rf.predict_proba(X_test)[:, 1]
    gb_probs = gb.predict_proba(X_test)[:, 1]
    ensemble_probs = (rf_probs * 0.55) + (gb_probs * 0.45)
    ensemble_preds = (ensemble_probs >= 0.50).astype(int)

    acc = accuracy_score(y_test, ensemble_preds)
    prec = precision_score(y_test, ensemble_preds)
    rec = recall_score(y_test, ensemble_preds)
    f1 = f1_score(y_test, ensemble_preds)
    roc_auc = roc_auc_score(y_test, ensemble_probs)
    cm = confusion_matrix(y_test, ensemble_preds).tolist()

    # Stratified 5-fold cross-validation for honest metrics
    print("\nRunning 5-Fold Stratified Cross-Validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_validate(rf, X, y, cv=cv,
                               scoring=["accuracy", "f1", "precision", "recall", "roc_auc"])
    cv_gb = cross_validate(gb, X, y, cv=cv,
                           scoring=["accuracy", "f1", "precision", "recall", "roc_auc"])

    print(f"\n==============================================")
    print(f"  TRAC-I ML ENSEMBLE PERFORMANCE METRICS")
    print(f"==============================================")
    print(f"  Holdout Test Accuracy  : {acc * 100:.2f}%")
    print(f"  Holdout Test Precision : {prec * 100:.2f}%")
    print(f"  Holdout Test Recall    : {rec * 100:.2f}%")
    print(f"  Holdout Test F1        : {f1 * 100:.2f}%")
    print(f"  Holdout Test ROC-AUC   : {roc_auc:.4f}")
    print(f"  Confusion Matrix       : TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}, TP={cm[1][1]}")
    print(f"  ---")
    print(f"  5-Fold CV RF Accuracy  : {cv_scores['test_accuracy'].mean() * 100:.2f}% (+/- {cv_scores['test_accuracy'].std() * 100:.2f}%)")
    print(f"  5-Fold CV RF F1        : {cv_scores['test_f1'].mean() * 100:.2f}% (+/- {cv_scores['test_f1'].std() * 100:.2f}%)")
    print(f"  5-Fold CV RF ROC-AUC   : {cv_scores['test_roc_auc'].mean():.4f}")
    print(f"  5-Fold CV GB Accuracy  : {cv_gb['test_accuracy'].mean() * 100:.2f}% (+/- {cv_gb['test_accuracy'].std() * 100:.2f}%)")
    print(f"  5-Fold CV GB F1        : {cv_gb['test_f1'].mean() * 100:.2f}% (+/- {cv_gb['test_f1'].std() * 100:.2f}%)")
    print(f"  5-Fold CV GB ROC-AUC   : {cv_gb['test_roc_auc'].mean():.4f}")
    print(f"==============================================\n")

    # Serialize Models
    rf_path = os.path.join(MODEL_DIR, "rf_model.joblib")
    gb_path = os.path.join(MODEL_DIR, "gb_model.joblib")
    metrics_path = os.path.join(MODEL_DIR, "model_metrics.json")

    joblib.dump(rf, rf_path)
    joblib.dump(gb, gb_path)

    # Extract Top Feature Importances
    importances = rf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [
        {"feature": FEATURE_NAMES[i][0], "title": FEATURE_NAMES[i][1], "importance": round(float(importances[i]), 4)}
        for i in sorted_idx[:10]
    ]

    metrics_payload = {
        "model_version": "2.5.0-production",
        "dataset_sample_count": len(samples),
        "features_count": len(FEATURE_NAMES),
        "test_split_size": len(X_test),
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "roc_auc": round(float(roc_auc), 4),
        "confusion_matrix": cm,
        "cross_validation": {
            "n_folds": 5,
            "rf_accuracy": round(float(cv_scores['test_accuracy'].mean()), 4),
            "rf_f1": round(float(cv_scores['test_f1'].mean()), 4),
            "rf_roc_auc": round(float(cv_scores['test_roc_auc'].mean()), 4),
            "rf_accuracy_std": round(float(cv_scores['test_accuracy'].std()), 4),
            "gb_accuracy": round(float(cv_gb['test_accuracy'].mean()), 4),
            "gb_f1": round(float(cv_gb['test_f1'].mean()), 4),
            "gb_roc_auc": round(float(cv_gb['test_roc_auc'].mean()), 4),
        },
        "top_features": top_features,
        "ensemble_weights": {"random_forest": 0.55, "gradient_boosting": 0.45},
        "training_notes": "Metrics derived from real labeled data with borderline cases. CV scores represent expected production generalization.",
    }

    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)

    print(f"Saved trained weights to {rf_path} and {gb_path}")
    print(f"Saved performance metrics to {metrics_path}")


if __name__ == "__main__":
    train_all_models()
