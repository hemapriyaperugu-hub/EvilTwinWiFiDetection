import os
import shutil
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score
)
from sklearn.model_selection import StratifiedGroupKFold, GroupShuffleSplit, train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from .features import FEATURE_COLUMNS


def get_model_paths():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "training_data": os.path.join(base_dir, "dataset", "training_dataset.csv"),
        "models_dir": os.path.join(base_dir, "models"),
        "knn": os.path.join(base_dir, "models", "knn_model.pkl"),
        "random_forest": os.path.join(base_dir, "models", "random_forest_model.pkl"),
        "isolation_forest": os.path.join(base_dir, "models", "isolation_forest_model.pkl"),
        "knn_v1_backup": os.path.join(base_dir, "models", "knn_model_v1_orig.pkl"),
        "rf_v1_backup": os.path.join(base_dir, "models", "random_forest_model_v1_orig.pkl")
    }


def compute_rates(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = (fp / (fp + tn)) * 100.0 if (fp + tn) > 0 else 0.0
    fnr = (fn / (fn + tp)) * 100.0 if (fn + tp) > 0 else 0.0
    return int(tn), int(fp), int(fn), int(tp), fpr, fnr


def _build_knn_pipeline():
    return make_pipeline(
        SimpleImputer(strategy="median"),
        StandardScaler(),
        KNeighborsClassifier(n_neighbors=5, weights="distance")
    )


def _build_rf_pipeline():
    return make_pipeline(
        SimpleImputer(strategy="median"),
        RandomForestClassifier(
            n_estimators=100,
            max_depth=5,
            min_samples_split=4,
            class_weight="balanced",
            random_state=42
        )
    )


def _build_isoforest_pipeline():
    return make_pipeline(
        SimpleImputer(strategy="median"),
        StandardScaler(),
        IsolationForest(
            n_estimators=150,
            contamination=0.02,
            random_state=42
        )
    )


def _eval_metrics(y_true, y_pred):
    acc = accuracy_score(y_true, y_pred) * 100.0
    prec = precision_score(y_true, y_pred, zero_division=0) * 100.0
    rec = recall_score(y_true, y_pred, zero_division=0) * 100.0
    f1 = f1_score(y_true, y_pred, zero_division=0) * 100.0
    tn, fp, fn, tp, fpr, fnr = compute_rates(y_true, y_pred)
    return {
        "accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
        "tn": tn, "fp": fp, "fn": fn, "tp": tp, "fpr": fpr, "fnr": fnr
    }


def _preserve_original_models(paths):
    if os.path.exists(paths["knn"]) and not os.path.exists(paths["knn_v1_backup"]):
        shutil.copy2(paths["knn"], paths["knn_v1_backup"])
    if os.path.exists(paths["random_forest"]) and not os.path.exists(paths["rf_v1_backup"]):
        shutil.copy2(paths["random_forest"], paths["rf_v1_backup"])


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

    missing_cols = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing_cols:
        print(f"Error: Missing feature columns in training dataset: {missing_cols}")
        return None, None

    X = df[FEATURE_COLUMNS]
    y = df["Label"].astype(int)

    print("==================================================")
    print("   CONTROLLED DATASET ML TRAINING & EVALUATION    ")
    print("==================================================")
    print(f"Total dataset size : {len(df)} samples")
    print(f"Features ({len(FEATURE_COLUMNS)})        : {FEATURE_COLUMNS}")
    print(f"Target distribution:\n  Legitimate (0): {(y == 0).sum()}\n  Evil Twin (1) : {(y == 1).sum()}\n")

    has_groups = "Group" in df.columns and df["Group"].nunique() >= 5
    if has_groups:
        groups = df["Group"]
        sgkf = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=42)
        folds = list(sgkf.split(X, y, groups))
        train_idx, test_idx = folds[0]
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
        print("Partition method   : StratifiedGroupKFold (no network identity leakage)")
    elif "Group" in df.columns and df["Group"].nunique() > 2:
        gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
        train_idx, test_idx = next(gss.split(X, y, groups=df["Group"]))
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
        folds = [(train_idx, test_idx)]
        print("Partition method   : GroupShuffleSplit")
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y
        )
        folds = []
        print("Partition method   : Stratified train_test_split")

    print(f"Holdout train size : {len(X_train)} samples (Evil Twin={int((y_train == 1).sum())})")
    print(f"Holdout test size  : {len(X_test)} samples (Evil Twin={int((y_test == 1).sum())})\n")

    knn = _build_knn_pipeline()
    knn.fit(X_train, y_train)
    knn_train_m = _eval_metrics(y_train, knn.predict(X_train))
    knn_test_m = _eval_metrics(y_test, knn.predict(X_test))

    rf = _build_rf_pipeline()
    rf.fit(X_train, y_train)
    rf_train_m = _eval_metrics(y_train, rf.predict(X_train))
    rf_test_m = _eval_metrics(y_test, rf.predict(X_test))

    # 3. Isolation Forest (unsupervised anomaly detector fit ONLY on Legitimate samples)
    X_train_legit = X_train[y_train == 0]
    iso = _build_isoforest_pipeline()
    iso.fit(X_train_legit)
    iso_test_binary = np.where(iso.predict(X_test) == -1, 1, 0)
    iso_test_m = _eval_metrics(y_test, iso_test_binary)

    print("-------------------------------------------------------------------")
    print("      HOLDOUT EVALUATION (CONTROLLED DATASET)                      ")
    print("-------------------------------------------------------------------")
    print(f"{'Metric':<24} {'RF Primary':<14} {'KNN Comp.':<14} {'IsoForest':<14}")
    print("-" * 67)
    print(f"{'Accuracy':<24} {rf_test_m['accuracy']:>8.2f}%     {knn_test_m['accuracy']:>8.2f}%     {iso_test_m['accuracy']:>8.2f}%")
    print(f"{'Precision (Evil Twin)':<24} {rf_test_m['precision']:>8.2f}%     {knn_test_m['precision']:>8.2f}%     {iso_test_m['precision']:>8.2f}%")
    print(f"{'Recall (Evil Twin)':<24} {rf_test_m['recall']:>8.2f}%     {knn_test_m['recall']:>8.2f}%     {iso_test_m['recall']:>8.2f}%")
    print(f"{'F1-Score':<24} {rf_test_m['f1']:>8.2f}%     {knn_test_m['f1']:>8.2f}%     {iso_test_m['f1']:>8.2f}%")
    print(f"{'False Positive Rate':<24} {rf_test_m['fpr']:>8.2f}%     {knn_test_m['fpr']:>8.2f}%     {iso_test_m['fpr']:>8.2f}%")
    print(f"{'False Negative Rate':<24} {rf_test_m['fnr']:>8.2f}%     {knn_test_m['fnr']:>8.2f}%     {iso_test_m['fnr']:>8.2f}%")
    print("-------------------------------------------------------------------")
    print(f"Overfitting check (Train vs Test Accuracy):")
    print(f"  RF  : Train={rf_train_m['accuracy']:.2f}% vs Test={rf_test_m['accuracy']:.2f}%")
    print(f"  KNN : Train={knn_train_m['accuracy']:.2f}% vs Test={knn_test_m['accuracy']:.2f}%\n")

    print("=== KNN Holdout Confusion Matrix ===")
    print(f"  True Legitimate (TN) : {knn_test_m['tn']:<4} | False Evil Twin (FP) : {knn_test_m['fp']:<4}")
    print(f"  False Legitimate (FN): {knn_test_m['fn']:<4} | True Evil Twin (TP)  : {knn_test_m['tp']:<4}\n")

    print("=== Random Forest Holdout Confusion Matrix ===")
    print(f"  True Legitimate (TN) : {rf_test_m['tn']:<4} | False Evil Twin (FP) : {rf_test_m['fp']:<4}")
    print(f"  False Legitimate (FN): {rf_test_m['fn']:<4} | True Evil Twin (TP)  : {rf_test_m['tp']:<4}\n")

    if len(folds) > 1:
        knn_cv_rec, knn_cv_acc = [], []
        rf_cv_rec, rf_cv_acc = [], []
        knn_cv_fnr, rf_cv_fnr = [], []
        for tr_i, te_i in folds:
            k_cv = _build_knn_pipeline().fit(X.iloc[tr_i], y.iloc[tr_i])
            r_cv = _build_rf_pipeline().fit(X.iloc[tr_i], y.iloc[tr_i])
            km = _eval_metrics(y.iloc[te_i], k_cv.predict(X.iloc[te_i]))
            rm = _eval_metrics(y.iloc[te_i], r_cv.predict(X.iloc[te_i]))
            knn_cv_acc.append(km["accuracy"])
            knn_cv_rec.append(km["recall"])
            knn_cv_fnr.append(km["fnr"])
            rf_cv_acc.append(rm["accuracy"])
            rf_cv_rec.append(rm["recall"])
            rf_cv_fnr.append(rm["fnr"])

        print(f"=== {len(folds)}-Fold Group Cross-Validation (Unseen AP Groups) ===")
        print(f"  KNN -> Acc: {np.mean(knn_cv_acc):.2f}% (±{np.std(knn_cv_acc):.2f}%), "
              f"Recall: {np.mean(knn_cv_rec):.2f}%, FNR: {np.mean(knn_cv_fnr):.2f}%")
        print(f"  RF  -> Acc: {np.mean(rf_cv_acc):.2f}% (±{np.std(rf_cv_acc):.2f}%), "
              f"Recall: {np.mean(rf_cv_rec):.2f}%, FNR: {np.mean(rf_cv_fnr):.2f}%\n")

    print("=== Random Forest Holdout Classification Report ===")
    print(classification_report(
        y_test, rf.predict(X_test),
        target_names=["Legitimate (0)", "Evil Twin (1)"],
        zero_division=0
    ))

    rf_est = rf.named_steps["randomforestclassifier"]
    importances = rf_est.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("=== Random Forest Feature Importances ===")
    for rank, idx in enumerate(sorted_idx, 1):
        print(f"  {rank}. {FEATURE_COLUMNS[idx]:<18}: {importances[idx] * 100:.2f}%")
    print()

    # Refit final deployable models on full labelled dataset after honest evaluation
    final_knn = _build_knn_pipeline()
    final_knn.fit(X, y)
    final_rf = _build_rf_pipeline()
    final_rf.fit(X, y)
    final_iso = _build_isoforest_pipeline()
    final_iso.fit(X[y == 0])

    os.makedirs(paths["models_dir"], exist_ok=True)
    _preserve_original_models(paths)
    joblib.dump(final_knn, paths["knn"])
    joblib.dump(final_rf, paths["random_forest"])
    joblib.dump(final_iso, paths["isolation_forest"])

    print("Models successfully serialized (original v1 models preserved as *_v1_orig.pkl):")
    print(f"- RF (Primary)       : {paths['random_forest']}")
    print(f"- KNN (Comparison)   : {paths['knn']}")
    print(f"- IsoForest (Anomaly): {paths['isolation_forest']}")
    print("==================================================")

    return final_knn, final_rf


if __name__ == "__main__":
    train_models()
