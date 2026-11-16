import json
import hashlib
from pathlib import Path
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    roc_auc_score,
)


def compute_sha256(filepath: str) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main():
    # 1. Load the Master Dataset (De-poisoned)
    data_path = "data/processed/master_dataset.jsonl"
    print(f"Loading data from: {data_path}")
    df = pd.read_json(data_path, lines=True)

    print("\n--- MASTER DATASET SUMMARY ---")
    print(f"Total samples: {len(df)}")
    print("Class breakdown (0 = Safe, 1 = Attack):")
    print(df["label"].value_counts())

    # 2. Stratified split (70% train, 15% validation, 15% test)
    train_df, temp_df = train_test_split(
        df,
        test_size=0.30,
        random_state=42,
        stratify=df["label"]
    )

    val_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        random_state=42,
        stratify=temp_df["label"]
    )

    print("\n--- SPLIT SIZES ---")
    print(f"Training set:   {len(train_df)} samples")
    print(f"Validation set: {len(val_df)} samples")
    print(f"Test set:       {len(test_df)} samples")

    # 3. Construct Scikit-Learn Pipeline
    print("\n⏳ Training End-to-End Baseline Pipeline (TF-IDF + Calibrated Logistic Regression)...")
    pipeline = Pipeline([
        ("vectorizer", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=20000,
            sublinear_tf=True
        )),
        ("classifier", LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            random_state=42
        ))
    ])

    pipeline.fit(train_df["text"], train_df["label"])
    print("✅ Training complete!")

    # 4. Evaluate on Validation Set
    val_preds = pipeline.predict(val_df["text"])
    print("\n--- VALIDATION PERFORMANCE REPORT ---")
    print(classification_report(val_df["label"], val_preds, target_names=["Safe (0)", "Attack (1)"]))

    # 5. Evaluate on Held-out Test Set
    test_preds = pipeline.predict(test_df["text"])
    test_probs = pipeline.predict_proba(test_df["text"])[:, 1]
    print("\n--- TEST PERFORMANCE REPORT ---")
    print(classification_report(test_df["label"], test_preds, target_names=["Safe (0)", "Attack (1)"]))

    cm = confusion_matrix(test_df["label"], test_preds)
    acc = float(accuracy_score(test_df["label"], test_preds))
    prec = float(precision_score(test_df["label"], test_preds, pos_label=1))
    rec = float(recall_score(test_df["label"], test_preds, pos_label=1))
    f1 = float(f1_score(test_df["label"], test_preds, pos_label=1))
    auc = float(roc_auc_score(test_df["label"], test_probs))

    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"ROC-AUC:   {auc:.4f}")

    # 6. Save Model Artifact
    models_dir = Path("models")
    models_dir.mkdir(parents=True, exist_ok=True)
    model_path = models_dir / "baseline_model.joblib"
    print(f"\n💾 Saving model artifact to {model_path}...")
    joblib.dump(pipeline, model_path, compress=3)

    # 7. Compute Hash & Record Metrics
    sha256_hash = compute_sha256(str(model_path))
    print(f"Model SHA-256: {sha256_hash}")

    metrics = {
        "train_samples": len(train_df),
        "val_samples": len(val_df),
        "test_samples": len(test_df),
        "accuracy": acc,
        "precision_attack": prec,
        "recall_attack": rec,
        "f1_attack": f1,
        "roc_auc": auc,
        "confusion_matrix_test": {
            "true_negatives": int(cm[0][0]),
            "false_positives": int(cm[0][1]),
            "false_negatives": int(cm[1][0]),
            "true_positives": int(cm[1][1])
        },
        "model_sha256": sha256_hash
    }

    metrics_path = models_dir / "baseline_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"✅ Saved metrics and integrity hash to {metrics_path}")


if __name__ == "__main__":
    main()
