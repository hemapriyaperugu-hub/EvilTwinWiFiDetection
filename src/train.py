import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from .features import FEATURE_COLUMNS


def get_model_paths():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "training_data": os.path.join(base_dir, "dataset", "training_dataset.csv"),
        "models_dir": os.path.join(base_dir, "models"),
        "knn": os.path.join(base_dir, "models", "knn_model.pkl"),
        "random_forest": os.path.join(base_dir, "models", "random_forest_model.pkl")
    }


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
    print(f"Total dataset size: {len(df)} samples")
    print(f"Features ({len(FEATURE_COLUMNS)}): {FEATURE_COLUMNS}")
    print(f"Target distribution:\n  Legitimate (0): {(y == 0).sum()}\n  Evil Twin (1) : {(y == 1).sum()}\n")

    # Stratified Train/Test split (80% train, 20% test) to prevent data leakage
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"Training set size: {len(X_train)} samples")
    print(f"Testing set size : {len(X_test)} samples\n")

    # 1. K-Nearest Neighbors (KNN) with StandardScaler Pipeline
    # StandardScaler ensures that continuous features (Signal, Channel) and
    # binary indicator flags (BSSIDKnown, ChannelMatch, SecurityMatch) have balanced distance weights.
    knn = make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=3, weights="distance"))
    knn.fit(X_train, y_train)

    knn_pred = knn.predict(X_test)
    knn_acc = accuracy_score(y_test, knn_pred) * 100.0

    # 2. Random Forest Classifier
    rf = RandomForestClassifier(n_estimators=50, max_depth=6, random_state=42)
    rf.fit(X_train, y_train)

    rf_pred = rf.predict(X_test)
    rf_acc = accuracy_score(y_test, rf_pred) * 100.0

    # ----------------------------------------------------
    # Model Evaluation Reports
    # ----------------------------------------------------
    print("--------------------------------------------------")
    print("             MODEL EVALUATION RESULTS             ")
    print("--------------------------------------------------")
    print(f"1. K-Nearest Neighbors (KNN) Accuracy : {knn_acc:.2f}%")
    print(f"2. Random Forest Accuracy             : {rf_acc:.2f}%")
    print("--------------------------------------------------\n")

    # Target comparison
    TARGET = 98.0
    print(f"Target Accuracy : ~{TARGET:.1f}%")
    print(f"KNN vs Target   : {'Achieved' if knn_acc >= TARGET else f'Difference of {TARGET - knn_acc:.2f}%'}")
    print(f"RF vs Target    : {'Achieved' if rf_acc >= TARGET else f'Difference of {TARGET - rf_acc:.2f}%'}\n")

    # Detailed Confusion Matrix
    print("=== KNN Confusion Matrix ===")
    cm_knn = confusion_matrix(y_test, knn_pred)
    print(f"  True Legitimate: {cm_knn[0, 0]} | False Evil Twin: {cm_knn[0, 1] if cm_knn.shape[1] > 1 else 0}")
    print(f"  False Legitimate: {cm_knn[1, 0] if cm_knn.shape[0] > 1 else 0} | True Evil Twin: {cm_knn[1, 1] if cm_knn.shape[0] > 1 and cm_knn.shape[1] > 1 else 0}\n")

    print("=== Random Forest Confusion Matrix ===")
    cm_rf = confusion_matrix(y_test, rf_pred)
    print(f"  True Legitimate: {cm_rf[0, 0]} | False Evil Twin: {cm_rf[0, 1] if cm_rf.shape[1] > 1 else 0}")
    print(f"  False Legitimate: {cm_rf[1, 0] if cm_rf.shape[0] > 1 else 0} | True Evil Twin: {cm_rf[1, 1] if cm_rf.shape[0] > 1 and cm_rf.shape[1] > 1 else 0}\n")

    print("=== Random Forest Classification Report ===")
    print(classification_report(y_test, rf_pred, target_names=["Legitimate (0)", "Evil Twin (1)"]))

    # Save Models
    os.makedirs(paths["models_dir"], exist_ok=True)
    joblib.dump(knn, paths["knn"])
    joblib.dump(rf, paths["random_forest"])

    print(f"Models saved successfully:")
    print(f"- KNN Model          : {paths['knn']}")
    print(f"- Random Forest Model: {paths['random_forest']}")
    print("==================================================")

    return knn, rf


if __name__ == "__main__":
    train_models()
