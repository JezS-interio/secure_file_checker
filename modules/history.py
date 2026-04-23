import os
import json
import pandas as pd
from datetime import datetime

HISTORY_FILE = "analysis_history.json"


def load_history() -> list:
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def find_by_hash(file_hash: str) -> dict | None:
    for entry in load_history():
        if entry.get("sha256") == file_hash:
            return entry
    return None


def save_to_history(result: dict):
    history = load_history()

    entry = {
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "archivo": result.get("archivo", ""),
        "tipo": result.get("tipo", ""),
        "score": result.get("score", 0),
        "riesgo": result.get("riesgo", ""),
        "veredicto": result.get("veredicto", ""),
        "sha256": result.get("sha256", ""),
        "origen_riesgo": ", ".join(result.get("origen_riesgo", [])),
        "recomendacion": result.get("recomendacion", ""),
    }

    # Reemplazar si el hash ya existe, sino insertar al principio
    for idx, existing in enumerate(history):
        if existing.get("sha256") == entry["sha256"]:
            history[idx] = entry
            break
    else:
        history.insert(0, entry)

    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)


def clear_history():
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump([], f, ensure_ascii=False, indent=2)


def history_to_csv_bytes() -> bytes:
    df = pd.DataFrame(load_history())
    return df.to_csv(index=False).encode("utf-8")