# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [
    ("templates", "templates"),
    ("static", "static"),
    ("models/knn_model.pkl", "models"),
    ("models/random_forest_model.pkl", "models"),
    ("models/isolation_forest_model.pkl", "models"),
    ("dataset/network_history.csv", "dataset"),
    ("dataset/training_dataset.csv", "dataset"),
    ("README.md", "."),
    ("DETECTION_LOGIC.md", "."),
]
binaries = []
hiddenimports = [
    "gui",
    "sqlite3",
    "tkinter",
    "tkinter.ttk",
    "tkinter.messagebox",
    "src",
    "src.paths",
    "src.scanner",
    "src.system_profiles",
    "src.features",
    "src.history",
    "src.predict",
    "src.db_manager",
    "src.dataset",
    "src.train",
    "sklearn.ensemble",
    "sklearn.neighbors",
    "sklearn.impute",
    "sklearn.preprocessing",
    "sklearn.pipeline",
    "sklearn.utils._typedefs",
    "sklearn.neighbors._partition_nodes",
    "werkzeug.serving",
]

for pkg in ("sklearn", "flask", "joblib"):
    p_d, p_b, p_h = collect_all(pkg)
    datas += p_d
    binaries += p_b
    hiddenimports += p_h

a = Analysis(
    ["EvilTwinDetector.pyw"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="EvilTwinDetector",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon="static/app_icon.ico",
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="EvilTwinDetector",
)
