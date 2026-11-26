import os
import sys


def get_resource_dir():
    """Returns read-only application asset directory (handles PyInstaller frozen builds)."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return os.path.abspath(sys._MEIPASS)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_data_dir():
    """Returns writable application data directory (exe folder when frozen, project root otherwise)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
