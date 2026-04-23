import zipfile
import hashlib
import os

# ---------------------------------------------------------------------------
# Listas de clasificación
# ---------------------------------------------------------------------------

DANGEROUS_EXTENSIONS = [".exe", ".bat", ".vbs", ".ps1", ".scr", ".cmd", ".com", ".pif", ".reg"]
SUSPICIOUS_EXTENSIONS = [".js", ".jar", ".msi", ".hta", ".wsf", ".lnk"]
SENSITIVE_FILENAMES = [
    ".env", ".env.local", ".env.production", ".env.development",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "secrets.json", "credentials.json", "config.json",
    ".htpasswd", "shadow", "passwd",
]
SENSITIVE_EXTENSIONS = [".pem", ".key", ".pfx", ".p12", ".p8", ".cer", ".crt"]
OFFICE_EXTENSIONS = [".docx", ".xlsx", ".pptx"]

# ---------------------------------------------------------------------------
# Rangos de riesgo (alineados con la infografía)
# ---------------------------------------------------------------------------

def score_to_risk_level(score: int) -> tuple[str, str]:
    """
    Devuelve (riesgo, veredicto) según el score numérico.
    Rangos definidos en la infografía:
        BAJO     0 – 20   → Seguro
        MEDIO   21 – 49   → Sospechoso
        ALTO    50 – 79   → Bloquear
        CRÍTICO 80 – 100  → Bloquear (crítico)
    """
    if score <= 20:
        return "BAJO", "Seguro"
    elif score <= 49:
        return "MEDIO", "Sospechoso"
    elif score <= 79:
        return "ALTO", "Bloquear"
    else:
        return "CRÍTICO", "Bloquear"


def score_to_recommendation(score: int, findings_type: list[str]) -> str:
    if score <= 20:
        return "El archivo parece seguro. Podés descargarlo y abrirlo sin problemas."
    elif score <= 49:
        if "sensible" in findings_type:
            return "El archivo contiene información sensible. Revisá el contenido antes de compartirlo o descargarlo."
        return "El archivo presenta indicadores sospechosos. Se recomienda revisión manual antes de abrirlo."
    elif score <= 79:
        return "Riesgo elevado. No se recomienda descomprimir ni abrir el archivo. Revisión manual sugerida."
    else:
        return "Archivo peligroso. Bloquealo y eliminalo. No lo descargues ni lo abras bajo ningún motivo."


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def calculate_sha256(uploaded_file) -> str:
    uploaded_file.seek(0)
    sha256 = hashlib.sha256()
    while chunk := uploaded_file.read(8192):
        sha256.update(chunk)
    uploaded_file.seek(0)
    return sha256.hexdigest()


def get_file_extension(filename: str) -> str:
    return os.path.splitext(filename)[1].lower()


def has_double_extension(filename: str) -> bool:
    """
    Detecta doble extensión real (ej: factura.pdf.exe).
    Descarta casos legítimos como jquery.min.js o archivo.tar.gz.
    La doble extensión sospechosa ocurre cuando la penúltima extensión
    es una extensión de documento conocida y la última es ejecutable/script.
    """
    base = os.path.basename(filename)
    parts = base.split(".")
    if len(parts) < 3:
        return False

    penultimate_ext = f".{parts[-2].lower()}"
    last_ext = f".{parts[-1].lower()}"

    DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg",
                           ".png", ".mp3", ".mp4", ".avi", ".zip", ".rar"}
    EXEC_EXTENSIONS = set(DANGEROUS_EXTENSIONS + SUSPICIOUS_EXTENSIONS)

    return penultimate_ext in DOCUMENT_EXTENSIONS and last_ext in EXEC_EXTENSIONS


def is_hidden_file(filepath: str) -> bool:
    name = os.path.basename(filepath)
    return name.startswith(".") and len(name) > 1


def clamp_score(score: int) -> int:
    return max(0, min(100, score))


def get_severity_rank(status: str) -> int:
    return {"Seguro": 0, "Sensible": 1, "Sospechoso": 2, "Peligroso": 3}.get(status, 0)


def combine_status(current: str, new: str) -> str:
    return new if get_severity_rank(new) > get_severity_rank(current) else current


def get_actions(score: int, file_type: str) -> dict:
    has_decompress = file_type in ["ZIP", "DOCX", "XLSX", "PPTX"]

    if score >= 50:
        return {
            "descargar": "No",
            "abrir": "No",
            "descomprimir": "No" if has_decompress else "No aplica",
        }
    elif score >= 21:
        return {
            "descargar": "Con revisión",
            "abrir": "No recomendado",
            "descomprimir": "No recomendado" if has_decompress else "No aplica",
        }
    else:
        return {
            "descargar": "Sí",
            "abrir": "Sí",
            "descomprimir": "Sí" if has_decompress else "No aplica",
        }


# ---------------------------------------------------------------------------
# Análisis de contenedores (ZIP / Office)
# ---------------------------------------------------------------------------

# Pesos de cada indicador para el score interno del contenedor
INDICATOR_WEIGHTS = {
    "dangerous_ext": 40,      # .exe, .bat, etc. dentro del ZIP
    "suspicious_ext": 20,     # .js, .jar, etc.
    "sensitive_file": 12,     # .pem, id_rsa, etc.
    "double_ext": 15,         # factura.pdf.exe
    "hidden_file": 8,         # .archivo
    "vba_macro": 30,          # vbaProject.bin
    "embedded_obj": 15,       # embeddings / embedded
    "binary_internal": 8,     # .bin genérico
    "too_many_files": 15,     # más de 100 archivos
    "large_uncompressed": 20, # >50 MB descomprimido
    "bad_zip": 55,            # ZIP corrupto o inválido
}


def analyze_container_file(uploaded_file, file_info, score, motives, findings_type, container_label):
    internal_files_info = []
    container_score_delta = 0  # acumulado solo para este contenedor

    try:
        with zipfile.ZipFile(uploaded_file, "r") as zip_ref:
            internal_files = zip_ref.infolist()

            # --- Checks globales del contenedor ---
            if len(internal_files) > 100:
                container_score_delta += INDICATOR_WEIGHTS["too_many_files"]
                motives.append(f"{container_label} contiene una cantidad alta de archivos ({len(internal_files)})")
                findings_type.append("sospechoso")
                if f"contenido interno del {container_label}" not in file_info["origen_riesgo"]:
                    file_info["origen_riesgo"].append(f"contenido interno del {container_label}")

            total_uncompressed = sum(item.file_size for item in internal_files)
            if total_uncompressed > 50 * 1024 * 1024:
                container_score_delta += INDICATOR_WEIGHTS["large_uncompressed"]
                mb = round(total_uncompressed / (1024 * 1024), 1)
                motives.append(f"{container_label} tiene tamaño descomprimido elevado ({mb} MB)")
                findings_type.append("sospechoso")
                if f"contenido interno del {container_label}" not in file_info["origen_riesgo"]:
                    file_info["origen_riesgo"].append(f"contenido interno del {container_label}")

            # --- Análisis por archivo interno ---
            for item in internal_files:
                f = item.filename
                lower_f = f.lower()

                if lower_f.endswith("/"):
                    internal_files_info.append({
                        "archivo": f,
                        "estado": "Carpeta",
                        "motivos": "Directorio interno",
                        "origen": container_label,
                    })
                    continue

                status = "Seguro"
                reasons = []

                if any(lower_f.endswith(d) for d in DANGEROUS_EXTENSIONS):
                    container_score_delta += INDICATOR_WEIGHTS["dangerous_ext"]
                    status = combine_status(status, "Peligroso")
                    reasons.append("Extensión ejecutable o de script peligrosa")
                    motives.append(f"{container_label} contiene archivo peligroso: {f}")
                    findings_type.append("malicioso")
                    _add_origin(file_info, f"contenido interno del {container_label}")

                if any(lower_f.endswith(s) for s in SUSPICIOUS_EXTENSIONS):
                    container_score_delta += INDICATOR_WEIGHTS["suspicious_ext"]
                    status = combine_status(status, "Sospechoso")
                    reasons.append("Extensión potencialmente riesgosa")
                    motives.append(f"{container_label} contiene archivo sospechoso: {f}")
                    findings_type.append("sospechoso")
                    _add_origin(file_info, f"contenido interno del {container_label}")

                base_lower = os.path.basename(lower_f)
                if base_lower in SENSITIVE_FILENAMES or any(lower_f.endswith(se) for se in SENSITIVE_EXTENSIONS):
                    container_score_delta += INDICATOR_WEIGHTS["sensitive_file"]
                    status = combine_status(status, "Sensible")
                    reasons.append("Archivo sensible o con credenciales")
                    motives.append(f"{container_label} contiene archivo sensible: {f}")
                    findings_type.append("sensible")
                    _add_origin(file_info, f"contenido interno del {container_label}")

                if has_double_extension(lower_f):
                    container_score_delta += INDICATOR_WEIGHTS["double_ext"]
                    status = combine_status(status, "Sospechoso")
                    reasons.append("Nombre con doble extensión sospechosa")
                    motives.append(f"Doble extensión detectada: {f}")
                    findings_type.append("sospechoso")
                    _add_origin(file_info, f"contenido interno del {container_label}")

                if is_hidden_file(lower_f):
                    container_score_delta += INDICATOR_WEIGHTS["hidden_file"]
                    status = combine_status(status, "Sensible")
                    reasons.append("Archivo oculto")
                    motives.append(f"Archivo oculto detectado: {f}")
                    findings_type.append("sensible")
                    _add_origin(file_info, f"contenido interno del {container_label}")

                if "vbaproject.bin" in lower_f:
                    container_score_delta += INDICATOR_WEIGHTS["vba_macro"]
                    status = combine_status(status, "Sospechoso")
                    reasons.append("Macro VBA detectada")
                    motives.append(f"{container_label} contiene macro VBA: {f}")
                    findings_type.append("sospechoso")
                    _add_origin(file_info, f"contenido interno del {container_label}")

                if "embeddings" in lower_f or "/embeddings/" in lower_f or lower_f.endswith("embedded"):
                    container_score_delta += INDICATOR_WEIGHTS["embedded_obj"]
                    status = combine_status(status, "Sospechoso")
                    reasons.append("Contenido embebido detectado")
                    motives.append(f"{container_label} contiene objetos embebidos: {f}")
                    findings_type.append("sospechoso")
                    _add_origin(file_info, f"contenido interno del {container_label}")

                if lower_f.endswith(".bin") and "vbaproject" not in lower_f:
                    container_score_delta += INDICATOR_WEIGHTS["binary_internal"]
                    status = combine_status(status, "Sospechoso")
                    reasons.append("Archivo binario interno")
                    motives.append(f"{container_label} contiene binario: {f}")
                    findings_type.append("sospechoso")
                    _add_origin(file_info, f"contenido interno del {container_label}")

                internal_files_info.append({
                    "archivo": f,
                    "estado": status,
                    "motivos": " | ".join(reasons) if reasons else "Sin indicadores detectados",
                    "origen": container_label,
                })

    except zipfile.BadZipFile:
        container_score_delta += INDICATOR_WEIGHTS["bad_zip"]
        motives.append(f"{container_label} corrupto o con formato inválido")
        findings_type.append("malicioso")
        file_info["origen_riesgo"].append("archivo principal")

    score += container_score_delta
    return score, motives, findings_type, internal_files_info, file_info


def _add_origin(file_info: dict, origin: str):
    if origin not in file_info["origen_riesgo"]:
        file_info["origen_riesgo"].append(origin)


# ---------------------------------------------------------------------------
# Análisis principal
# ---------------------------------------------------------------------------

def analyze_uploaded_file(uploaded_file) -> dict:
    filename = uploaded_file.name
    lower_filename = filename.lower()
    file_size = getattr(uploaded_file, "size", 0)

    score = 0
    motives: list[str] = []
    internal_files_info: list[dict] = []
    findings_type: list[str] = []

    file_info = {
        "archivo": filename,
        "tipo": "OTRO",
        "score": 0,
        "riesgo": "BAJO",
        "veredicto": "Seguro",
        "motivos": [],
        "sha256": "",
        "contenido_zip": [],
        "recomendacion": "",
        "acciones": {},
        "tamano": file_size,
        "origen_riesgo": [],
    }

    file_info["sha256"] = calculate_sha256(uploaded_file)
    ext = get_file_extension(lower_filename)

    # --- Archivo vacío ---
    if file_size == 0:
        score += 15
        motives.append("Archivo vacío detectado")
        findings_type.append("sospechoso")
        file_info["origen_riesgo"].append("archivo principal")

    # --- Clasificación por tipo ---
    if ext == ".zip":
        file_info["tipo"] = "ZIP"
        score, motives, findings_type, internal_files_info, file_info = analyze_container_file(
            uploaded_file, file_info, score, motives, findings_type, "ZIP"
        )

    elif ext in OFFICE_EXTENSIONS:
        file_info["tipo"] = ext.upper().replace(".", "")
        score, motives, findings_type, internal_files_info, file_info = analyze_container_file(
            uploaded_file, file_info, score, motives, findings_type, file_info["tipo"]
        )

    elif ext == ".pdf":
        file_info["tipo"] = "PDF"
        content = uploaded_file.read()
        uploaded_file.seek(0)

        pdf_checks = [
            (b"/JavaScript", 30, "PDF contiene JavaScript embebido", "malicioso"),
            (b"/JS ",         30, "PDF contiene JavaScript embebido (forma corta)", "malicioso"),
            (b"/OpenAction",  20, "PDF con acción automática al abrir", "sospechoso"),
            (b"/Launch",      35, "PDF intenta ejecutar un proceso externo", "malicioso"),
            (b"/EmbeddedFile",20, "PDF contiene archivos embebidos", "sospechoso"),
            (b"/RichMedia",   15, "PDF contiene contenido multimedia embebido", "sospechoso"),
            (b"/XFA",         10, "PDF usa formularios XFA (formato legacy)", "sospechoso"),
            (b"/Encrypt",     10, "PDF cifrado (no se puede analizar completamente)", "sospechoso"),
        ]

        for marker, weight, description, ftype in pdf_checks:
            if marker in content:
                score += weight
                motives.append(description)
                findings_type.append(ftype)
                _add_origin(file_info, "archivo principal")

    else:
        file_info["tipo"] = ext.upper().replace(".", "") if ext else "OTRO"

        if any(lower_filename.endswith(d) for d in DANGEROUS_EXTENSIONS):
            score += 50
            motives.append(f"Extensión ejecutable peligrosa: {ext}")
            findings_type.append("malicioso")
            _add_origin(file_info, "archivo principal")

        elif any(lower_filename.endswith(s) for s in SUSPICIOUS_EXTENSIONS):
            score += 25
            motives.append(f"Extensión potencialmente riesgosa: {ext}")
            findings_type.append("sospechoso")
            _add_origin(file_info, "archivo principal")

        base_lower = os.path.basename(lower_filename)
        if base_lower in SENSITIVE_FILENAMES or any(lower_filename.endswith(se) for se in SENSITIVE_EXTENSIONS):
            score += 15
            motives.append(f"Archivo con información sensible o credenciales: {filename}")
            findings_type.append("sensible")
            _add_origin(file_info, "archivo principal")

        if has_double_extension(lower_filename):
            score += 20
            motives.append(f"Doble extensión sospechosa detectada: {filename}")
            findings_type.append("sospechoso")
            _add_origin(file_info, "archivo principal")

        if is_hidden_file(lower_filename):
            score += 10
            motives.append(f"Archivo oculto detectado: {filename}")
            findings_type.append("sensible")
            _add_origin(file_info, "archivo principal")

        if not findings_type:
            motives.append("No se encontraron indicadores de riesgo en este tipo de archivo")

    # --- Score final con tope en 100 ---
    score = clamp_score(score)
    risk, verdict = score_to_risk_level(score)

    # Caso especial: archivo sensible sin otros hallazgos → veredicto "Sensible"
    if verdict == "Sospechoso" and findings_type == ["sensible"]:
        verdict = "Sensible"

    file_info["score"] = score
    file_info["riesgo"] = risk
    file_info["veredicto"] = verdict
    file_info["motivos"] = list(dict.fromkeys(motives))
    file_info["contenido_zip"] = internal_files_info
    file_info["recomendacion"] = score_to_recommendation(score, findings_type)
    file_info["acciones"] = get_actions(score, file_info["tipo"])
    file_info["origen_riesgo"] = list(dict.fromkeys(file_info["origen_riesgo"]))

    return file_info