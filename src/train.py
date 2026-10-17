import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from .features import FEATURE_COLUMNS


def get_model_paths():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "training_data": os.path.join(base_dir, "dataset", "training_dataset.csv"),
        "models_dir": os.path.join(base_dir, "models"),
        "knn": os.path.join(base_dir, "models", "knn_model.pkl"),
        "random_forest": os.path.join(base_dir, "models", "random_forest_model.pkl")
    }


def compute_rates(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = (fp / (fp + tn)) * 100.0 if (fp + tn) > 0 else 0.0
    fnr = (fn / (fn + tp)) * 100.0 if (fn + tp) > 0 else 0.0
    return tn, fp, fn, tp, fpr, fnr


def train_models():
    paths = get_model_paths()
    data_path = paths["training_data"]

    if not os.path.exists(data_path):
        print(f"Error: Training dataset not found at {data_path}.")
        print("Please run 'python -m src.dataset' first to build training_dataset.csv.")
        return None, None

    df = pd.read_csv(data_path)
    if df.empty or "Label" not in df.columns:
        print("Error: Invalid or empty training dataset.")
        return None, None

    X = df[FEATURE_COLUMNS]
    y = df["Label"].astype(int)

    print("==================================================")
    print("        MACHINE LEARNING MODEL TRAINING           ")
    print("==================================================")
    print(f"Total dataset size : {len(df)} samples")
    print(f"Features ({len(FEATURE_COLUMNS)})        : {FEATURE_COLUMNS}")
    print(f"Target distribution:\n  Legitimate (0): {(y == 0).sum()}\n  Evil Twin (1) : {(y == 1).sum()}\n")

    # Group-aware splitting to prevent data leakage across train and test partitions
    # If Group column exists, split by group so same networks don't leak into test set
    if "Group" in df.columns and df["Group"].nunique() > 2:
        gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
        train_idx, test_idx = next(gss.split(X, y, groups=df["Group"]))
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
        print(f"Partition method   : GroupShuffleSplit (no network identity leakage)")
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )
        print(f"Partition method   : Stratified train_test_split")

    print(f"Training set size  : {len(X_train)} samples")
    print(f"Testing set size   : {len(X_test)} samples\n")

    # 1. K-Nearest Neighbors (KNN) with StandardScaler Pipeline
    knn = make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=5, weights="distance"))
    knn.fit(X_train, y_train)
    knn_pred = knn.predict(X_test)

    # 2. Random Forest Classifier with balanced class weights
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=5,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42
    )
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)

    # ----------------------------------------------------
    # Detailed Honest Evaluation Metrics
    # ----------------------------------------------------
    knn_acc = accuracy_score(y_test, knn_pred) * 100.0
    knn_prec = precision_score(y_test, knn_pred, zero_division=0) * 100.0
    knn_rec = recall_score(y_test, knn_pred, zero_division=0) * 100.0
    knn_f1 = f1_score(y_test, knn_pred, zero_division=0) * 100.0
    tn_k, fp_k, fn_k, tp_k, fpr_k, fnr_k = compute_rates(y_test, knn_pred)

    rf_acc = accuracy_score(y_test, rf_pred) * 100.0
    rf_prec = precision_score(y_test, rf_pred, zero_division=0) * 100.0
    rf_rec = recall_score(y_test, rf_pred, zero_division=0) * 100.0
    rf_f1 = f1_score(y_test, rf_pred, zero_division=0) * 100.0
    tn_r, fp_r, fn_r, tp_r, fpr_r, fnr_r = compute_rates(y_test, rf_pred)

    print("--------------------------------------------------")
    print("         HONEST MODEL EVALUATION METRICS          ")
    print("--------------------------------------------------")
    print(f"{'Metric':<22} {'KNN Model':<16} {'Random Forest':<16}")
    print("-" * 54)
    print(f"{'Accuracy':<22} {knn_acc:>8.2f}%       {rf_acc:>8.2f}%")
    print(f"{'Precision (Evil Twin)':<22} {knn_prec:>8.2f}%       {rf_prec:>8.2f}%")
    print(f"{'Recall (Evil Twin)':<22} {knn_rec:>8.2f}%       {rf_rec:>8.2f}%")
    print(f"{'F1-Score':<22} {knn_f1:>8.2f}%       {rf_f1:>8.2f}%")
    print(f"{'False Positive Rate':<22} {fpr_k:>8.2f}%       {fpr_r:>8.2f}%")
    print(f"{'False Negative Rate':<22} {fnr_k:>8.2f}%       {fnr_r:>8.2f}%")
    print("--------------------------------------------------\n")

    print("=== KNN Confusion Matrix ===")
    print(f"  True Legitimate (TN) : {tn_k:<4} | False Evil Twin (FP) : {fp_k:<4}")
    print(f"  False Legitimate (FN): {fn_k:<4} | True Evil Twin (TP)  : {tp_k:<4}\n")

    print("=== Random Forest Confusion Matrix ===")
    print(f"  True Legitimate (TN) : {tn_r:<4} | False Evil Twin (FP) : {fp_r:<4}")
    print(f"  False Legitimate (FN): {fn_r:<4} | True Evil Twin (TP)  : {tp_r:<4}\n")

    print("=== Random Forest Classification Report ===")
    print(classification_report(y_test, rf_pred, target_names=["Legitimate (0)", "Evil Twin (1)"], zero_division=0))

    # Feature Importance for Random Forest
    importances = rf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("=== Random Forest Feature Importances ===")
    for rank, idx in enumerate(sorted_idx, 1):
        print(f"  {rank}. {FEATURE_COLUMNS[idx]:<18}: {importances[idx] * 100:.2f}%")
    print()

    # Save models
    os.makedirs(paths["models_dir"], exist_ok=True)
    joblib.dump(knn, paths["knn"])
    joblib.dump(rf, paths["random_forest"])

    print(f"Models successfully serialized:")
    print(f"- KNN: {paths['knn']}")
    print(f"- RF : {paths['random_forest']}")
    print("==================================================")

    return knn, rf


if __name__ == "__main__":
    train_models()
