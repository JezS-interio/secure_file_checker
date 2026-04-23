import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib as mpl
from modules.analyzer import analyze_uploaded_file
from modules.history import (
    save_to_history,
    load_history,
    clear_history,
    history_to_csv_bytes,
    find_by_hash,
)

st.set_page_config(page_title="FileGuard — Analizador de Archivos", layout="wide", page_icon=None)

# ---------------------------------------------------------------------------
# CSS global — estilo técnico/industrial, tipografía IBM Plex
# ---------------------------------------------------------------------------
st.markdown("""
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:ital,wght@0,300;0,400;0,600;0,700;1,400&display=swap" rel="stylesheet">

<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html, body, [data-testid="stAppViewContainer"] {
    background-color: #0d1117 !important;
    color: #c9d1d9 !important;
    font-family: 'IBM Plex Sans', sans-serif !important;
}

[data-testid="stSidebar"] { background: #010409 !important; }

h1, h2, h3, h4 {
    font-family: 'IBM Plex Sans', sans-serif !important;
    font-weight: 700 !important;
    color: #e6edf3 !important;
    letter-spacing: -0.02em !important;
}

p, div, span, label {
    font-family: 'IBM Plex Sans', sans-serif !important;
    color: #c9d1d9 !important;
}

[data-testid="stMetric"] {
    background: #161b22 !important;
    border: 1px solid #21262d !important;
    border-radius: 8px !important;
    padding: 16px !important;
}
[data-testid="stMetricLabel"] {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.72rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.08em !important;
    color: #8b949e !important;
}
[data-testid="stMetricValue"] {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 1.3rem !important;
    color: #e6edf3 !important;
    font-weight: 600 !important;
}

[data-testid="stButton"] > button {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.8rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.05em !important;
    text-transform: uppercase !important;
    background: transparent !important;
    border: 1px solid #30363d !important;
    color: #c9d1d9 !important;
    border-radius: 6px !important;
    padding: 10px 20px !important;
    transition: all 0.15s ease !important;
}
[data-testid="stButton"] > button:hover {
    border-color: #58a6ff !important;
    color: #58a6ff !important;
    background: rgba(88,166,255,0.06) !important;
}
[data-testid="stButton"] > button[kind="primary"] {
    background: #1f6feb !important;
    border-color: #1f6feb !important;
    color: #fff !important;
}
[data-testid="stButton"] > button[kind="primary"]:hover {
    background: #388bfd !important;
    border-color: #388bfd !important;
    color: #fff !important;
}

[data-testid="stFileUploader"] {
    background: #161b22 !important;
    border: 1px dashed #30363d !important;
    border-radius: 10px !important;
    padding: 12px !important;
}

[data-testid="stSelectbox"] > div > div,
[data-testid="stTextInput"] > div > div > input {
    background: #161b22 !important;
    border: 1px solid #30363d !important;
    border-radius: 6px !important;
    color: #c9d1d9 !important;
    font-family: 'IBM Plex Sans', sans-serif !important;
}

[data-testid="stDataFrame"] {
    border: 1px solid #21262d !important;
    border-radius: 8px !important;
    overflow: hidden !important;
}

[data-testid="stCode"] {
    background: #161b22 !important;
    border: 1px solid #21262d !important;
    border-radius: 6px !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.82rem !important;
}

hr { border-color: #21262d !important; margin: 2rem 0 !important; }

[data-testid="stAlert"] {
    background: #161b22 !important;
    border: 1px solid #30363d !important;
    border-radius: 8px !important;
    font-size: 0.88rem !important;
}

[data-testid="stDownloadButton"] > button {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.78rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em !important;
    background: transparent !important;
    border: 1px solid #30363d !important;
    color: #8b949e !important;
    border-radius: 6px !important;
}
[data-testid="stDownloadButton"] > button:hover {
    border-color: #58a6ff !important;
    color: #58a6ff !important;
}

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #484f58; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Matplotlib — tema oscuro
# ---------------------------------------------------------------------------
mpl.rcParams.update({
    "figure.facecolor":  "#161b22",
    "axes.facecolor":    "#161b22",
    "axes.edgecolor":    "#30363d",
    "axes.labelcolor":   "#8b949e",
    "axes.titlecolor":   "#c9d1d9",
    "xtick.color":       "#8b949e",
    "ytick.color":       "#8b949e",
    "text.color":        "#c9d1d9",
    "grid.color":        "#21262d",
    "grid.linestyle":    "--",
    "grid.alpha":        0.6,
    "font.family":       "monospace",
    "axes.spines.top":   False,
    "axes.spines.right": False,
})

# ---------------------------------------------------------------------------
# Constantes de estilo
# ---------------------------------------------------------------------------
VERDICT_CFG = {
    "Seguro":     {"bg": "#0d1f17", "border": "#2ea043", "accent": "#2ea043", "label": "SEGURO"},
    "Sensible":   {"bg": "#1f1a0d", "border": "#d29922", "accent": "#d29922", "label": "SENSIBLE"},
    "Sospechoso": {"bg": "#1f150d", "border": "#d18616", "accent": "#d18616", "label": "SOSPECHOSO"},
    "Bloquear":   {"bg": "#1f0d0d", "border": "#f85149", "accent": "#f85149", "label": "BLOQUEAR"},
}

RISK_CFG = {
    "BAJO":    {"color": "#2ea043", "range": "0 - 20"},
    "MEDIO":   {"color": "#d29922", "range": "21 - 49"},
    "ALTO":    {"color": "#d18616", "range": "50 - 79"},
    "CRITICO": {"color": "#f85149", "range": "80 - 100"},
}

BAR_COLORS = {
    "Seguro": "#2ea043", "Sensible": "#d29922",
    "Sospechoso": "#d18616", "Bloquear": "#f85149",
}

# ---------------------------------------------------------------------------
# Helpers HTML
# ---------------------------------------------------------------------------

def tag(text: str, color: str) -> str:
    return (
        f'<span style="background:{color}22; border:1px solid {color}; color:{color};'
        f' font-family:\'IBM Plex Mono\',monospace; font-size:0.7rem; font-weight:600;'
        f' letter-spacing:0.08em; text-transform:uppercase; padding:3px 10px;'
        f' border-radius:4px; display:inline-block;">{text}</span>'
    )


def score_bar_html(score: int, risk: str) -> str:
    cfg = RISK_CFG.get(risk, RISK_CFG["CRITICO"])
    color = cfg["color"]
    stops = [
        (20,  RISK_CFG["BAJO"]["color"],   "BAJO"),
        (49,  RISK_CFG["MEDIO"]["color"],  "MEDIO"),
        (79,  RISK_CFG["ALTO"]["color"],   "ALTO"),
        (100, RISK_CFG["CRITICO"]["color"],"CRITICO"),
    ]
    markers = "".join(
        f'<div style="position:absolute;left:{p}%;top:-4px;width:1px;height:22px;background:{c}55;"></div>'
        for p, c, _ in stops
    )
    labels = "".join(
        f'<span style="position:absolute;left:{p}%;transform:translateX(-50%);color:{c};'
        f'font-size:0.62rem;font-family:\'IBM Plex Mono\',monospace;font-weight:600;">{l}</span>'
        for p, c, l in stops
    )
    return f"""
    <div style="margin:20px 0 32px;">
        <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px;">
            <span style="font-family:'IBM Plex Mono',monospace;font-size:0.7rem;text-transform:uppercase;
                         letter-spacing:0.1em;color:#8b949e;">Puntuacion de riesgo</span>
            <span style="font-family:'IBM Plex Mono',monospace;font-size:1.9rem;font-weight:600;color:{color};">
                {score}<span style="font-size:1rem;color:#484f58;">/100</span>
            </span>
        </div>
        <div style="position:relative;height:12px;background:#21262d;border-radius:2px;overflow:visible;">
            {markers}
            <div style="position:absolute;left:0;top:0;width:{score}%;height:100%;
                background:linear-gradient(90deg,{color}88,{color});border-radius:2px;"></div>
        </div>
        <div style="position:relative;height:18px;margin-top:5px;">{labels}</div>
    </div>
    """


def section_header(title: str) -> str:
    return (
        f'<div style="display:flex;align-items:center;gap:10px;margin:28px 0 14px;'
        f'border-bottom:1px solid #21262d;padding-bottom:8px;">'
        f'<span style="font-family:\'IBM Plex Mono\',monospace;font-size:0.68rem;font-weight:600;'
        f'text-transform:uppercase;letter-spacing:0.14em;color:#8b949e;">{title}</span></div>'
    )


def risk_legend_html() -> str:
    items = "".join(
        f'<div style="display:flex;align-items:center;gap:8px;">'
        f'<div style="width:7px;height:7px;border-radius:50%;background:{cfg["color"]};"></div>'
        f'<span style="font-family:\'IBM Plex Mono\',monospace;font-size:0.72rem;color:#8b949e;">'
        f'{lvl} <span style="color:#484f58;">({cfg["range"]})</span></span></div>'
        for lvl, cfg in RISK_CFG.items()
    )
    return (
        f'<div style="display:flex;gap:24px;flex-wrap:wrap;background:#161b22;'
        f'border:1px solid #21262d;border-radius:8px;padding:12px 18px;margin-bottom:24px;">'
        f'{items}</div>'
    )


# ---------------------------------------------------------------------------
# Render resultado
# ---------------------------------------------------------------------------

def render_result(result: dict, previous: dict | None = None):
    cfg = VERDICT_CFG.get(result["veredicto"], VERDICT_CFG["Bloquear"])
    risk_key = result["riesgo"].replace("CRÍTICO", "CRITICO")
    risk_cfg = RISK_CFG.get(risk_key, RISK_CFG["CRITICO"])

    if previous:
        st.markdown(
            f'<div style="background:#161b22;border:1px solid #30363d;border-left:3px solid #58a6ff;'
            f'border-radius:6px;padding:12px 16px;margin-bottom:16px;font-size:0.85rem;color:#8b949e;">'
            f'Archivo analizado previamente &mdash; '
            f'Ultimo registro: <strong style="color:#c9d1d9;">{previous.get("fecha","?")}</strong> &mdash; '
            f'Veredicto anterior: <strong style="color:#c9d1d9;">{previous.get("veredicto","?")}</strong></div>',
            unsafe_allow_html=True,
        )

    st.markdown(f"""
    <div style="background:{cfg['bg']};border:1px solid {cfg['border']};
                border-left:4px solid {cfg['accent']};border-radius:8px;padding:24px 28px;margin-bottom:8px;">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
            <div>
                <div style="font-family:'IBM Plex Mono',monospace;font-size:0.63rem;font-weight:600;
                            text-transform:uppercase;letter-spacing:0.14em;color:{cfg['accent']}88;margin-bottom:4px;">
                    Veredicto</div>
                <div style="font-family:'IBM Plex Sans',sans-serif;font-size:1.9rem;font-weight:700;
                            color:{cfg['accent']};letter-spacing:-0.02em;">{cfg['label']}</div>
            </div>
            <div style="text-align:right;">
                <div style="font-family:'IBM Plex Mono',monospace;font-size:0.63rem;font-weight:600;
                            text-transform:uppercase;letter-spacing:0.14em;color:#8b949e;margin-bottom:4px;">
                    Nivel de riesgo</div>
                <div style="font-family:'IBM Plex Mono',monospace;font-size:1.1rem;font-weight:600;color:{risk_cfg['color']};">
                    {result['riesgo']} <span style="color:#484f58;font-size:0.8rem;">({risk_cfg['range']})</span>
                </div>
            </div>
        </div>
        <div style="margin-top:16px;padding-top:16px;border-top:1px solid {cfg['border']}44;
                    font-size:0.9rem;color:#c9d1d9;line-height:1.6;">{result['recomendacion']}</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(score_bar_html(result["score"], result["riesgo"]), unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Tipo", result["tipo"])
    c2.metric("Score", f"{result['score']} / 100")
    c3.metric("Nivel", result["riesgo"])
    c4.metric("Tamano", f"{result['tamano']:,} B")

    st.markdown(section_header("Acciones recomendadas"), unsafe_allow_html=True)
    a1, a2, a3 = st.columns(3)
    a1.metric("Descargar", result["acciones"]["descargar"])
    a2.metric("Abrir", result["acciones"]["abrir"])
    a3.metric("Descomprimir", result["acciones"]["descomprimir"])

    st.markdown(section_header("Origen del riesgo"), unsafe_allow_html=True)
    origs = result["origen_riesgo"]
    if isinstance(origs, str):
        origs = [o.strip() for o in origs.split(",") if o.strip()]
    if origs:
        tags_html = " ".join(tag(o, cfg["accent"]) for o in origs)
        st.markdown(f'<div style="display:flex;gap:8px;flex-wrap:wrap;">{tags_html}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<span style="color:#484f58;font-size:0.88rem;">Sin hallazgos de riesgo.</span>', unsafe_allow_html=True)

    st.markdown(section_header("Indicadores detectados"), unsafe_allow_html=True)
    if result["motivos"]:
        rows = "".join(
            f'<div style="display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid #21262d;">'
            f'<div style="width:4px;height:4px;border-radius:50%;background:{cfg["accent"]};margin-top:8px;flex-shrink:0;"></div>'
            f'<span style="font-size:0.88rem;color:#c9d1d9;line-height:1.5;">{m}</span></div>'
            for m in result["motivos"]
        )
        st.markdown(f'<div style="border-top:1px solid #21262d;">{rows}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<span style="color:#484f58;font-size:0.88rem;">No se encontraron indicadores.</span>', unsafe_allow_html=True)

    st.markdown(section_header("Hash SHA-256"), unsafe_allow_html=True)
    st.code(result["sha256"], language="text")

    if result["tipo"] in ["ZIP", "DOCX", "XLSX", "PPTX"]:
        st.markdown(section_header(f"Contenido interno — {result['tipo']}"), unsafe_allow_html=True)
        if result["contenido_zip"]:
            st.dataframe(pd.DataFrame(result["contenido_zip"]), use_container_width=True, hide_index=True)
        else:
            st.markdown('<span style="color:#484f58;font-size:0.88rem;">No se encontro contenido interno.</span>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Graficos del historial
# ---------------------------------------------------------------------------

def render_charts(df: pd.DataFrame):
    st.markdown(section_header("Dashboard — Historial"), unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown('<p style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;color:#8b949e;font-family:\'IBM Plex Mono\',monospace;margin-bottom:8px;">Archivos por veredicto</p>', unsafe_allow_html=True)
        counts = df["veredicto"].value_counts()
        colors = [BAR_COLORS.get(v, "#484f58") for v in counts.index]
        fig, ax = plt.subplots(figsize=(5, 3.5))
        bars = ax.bar(counts.index, counts.values, color=colors, width=0.5)
        ax.bar_label(bars, fmt="%d", color="#c9d1d9", fontsize=9, padding=3)
        ax.set_axisbelow(True); ax.yaxis.grid(True)
        ax.set_ylabel("Cantidad", fontsize=8)
        fig.tight_layout(); st.pyplot(fig); plt.close(fig)

    with c2:
        st.markdown('<p style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;color:#8b949e;font-family:\'IBM Plex Mono\',monospace;margin-bottom:8px;">Archivos por tipo</p>', unsafe_allow_html=True)
        counts2 = df["tipo"].value_counts().head(10)
        fig2, ax2 = plt.subplots(figsize=(5, 3.5))
        bars2 = ax2.bar(counts2.index, counts2.values, color="#388bfd", width=0.5)
        ax2.bar_label(bars2, fmt="%d", color="#c9d1d9", fontsize=9, padding=3)
        ax2.set_axisbelow(True); ax2.yaxis.grid(True)
        ax2.set_ylabel("Cantidad", fontsize=8)
        fig2.tight_layout(); st.pyplot(fig2); plt.close(fig2)

    st.markdown('<p style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;color:#8b949e;font-family:\'IBM Plex Mono\',monospace;margin:20px 0 8px;">Distribucion de scores</p>', unsafe_allow_html=True)
    fig3, ax3 = plt.subplots(figsize=(9, 3))
    ax3.hist(df["score"], bins=20, color="#388bfd", alpha=0.85, edgecolor="#161b22")
    for i, (thresh, lbl) in enumerate([(20, "BAJO"), (49, "MEDIO"), (79, "ALTO")]):
        c = list(RISK_CFG.values())[i]["color"]
        ax3.axvline(x=thresh, color=c, linestyle="--", linewidth=1, alpha=0.8)
        ax3.text(thresh + 1, ax3.get_ylim()[1] * 0.85, lbl, color=c, fontsize=7, va="top")
    ax3.set_axisbelow(True); ax3.yaxis.grid(True)
    ax3.set_xlabel("Score (0 - 100)", fontsize=8); ax3.set_ylabel("Archivos", fontsize=8)
    ax3.set_xlim(0, 100); fig3.tight_layout(); st.pyplot(fig3); plt.close(fig3)


# ---------------------------------------------------------------------------
# Header de la app
# ---------------------------------------------------------------------------

st.markdown("""
<div style="margin-bottom:32px;">
    <div style="font-family:'IBM Plex Mono',monospace;font-size:0.68rem;font-weight:600;
                text-transform:uppercase;letter-spacing:0.2em;color:#388bfd;margin-bottom:6px;">
        FileGuard / Herramienta de analisis</div>
    <h1 style="font-size:2.1rem!important;font-weight:700!important;color:#e6edf3!important;
               letter-spacing:-0.03em!important;margin-bottom:8px!important;">
        Analizador de Archivos</h1>
    <p style="color:#8b949e;font-size:0.9rem;max-width:540px;">
        Analiza documentos, archivos comprimidos o ejecutables para detectar
        indicadores de riesgo antes de abrirlos o distribuirlos.
    </p>
</div>
""", unsafe_allow_html=True)

st.markdown(risk_legend_html(), unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Uploader y analisis
# ---------------------------------------------------------------------------

uploaded_file = st.file_uploader(
    "Seleccionar archivo",
    type=["pdf", "zip", "docx", "xlsx", "pptx", "txt", "exe", "js", "bat", "vbs", "ps1", "pem", "key"],
    label_visibility="collapsed",
)

if uploaded_file:
    st.markdown(
        f'<div style="display:flex;gap:20px;align-items:center;background:#161b22;border:1px solid #21262d;'
        f'border-radius:6px;padding:12px 18px;margin:12px 0 16px;'
        f'font-family:\'IBM Plex Mono\',monospace;font-size:0.82rem;">'
        f'<span style="color:#e6edf3;font-weight:600;">{uploaded_file.name}</span>'
        f'<span style="color:#484f58;">|</span>'
        f'<span style="color:#8b949e;">{uploaded_file.size:,} bytes</span></div>',
        unsafe_allow_html=True,
    )
    if st.button("Analizar archivo", type="primary"):
        with st.spinner("Analizando..."):
            result = analyze_uploaded_file(uploaded_file)
            previous = find_by_hash(result["sha256"])
            save_to_history(result)
        render_result(result, previous)

# ---------------------------------------------------------------------------
# Historial
# ---------------------------------------------------------------------------

st.markdown("<hr>", unsafe_allow_html=True)

st.markdown("""
<div style="margin-bottom:20px;">
    <div style="font-family:'IBM Plex Mono',monospace;font-size:0.68rem;font-weight:600;
                text-transform:uppercase;letter-spacing:0.16em;color:#8b949e;margin-bottom:4px;">
        Registro</div>
    <h2 style="font-size:1.3rem!important;color:#e6edf3!important;margin:0!important;">
        Historial de analisis</h2>
</div>
""", unsafe_allow_html=True)

history = load_history()

btn1, btn2 = st.columns([1, 1])
with btn1:
    if st.button("Borrar historial"):
        clear_history()
        st.success("Historial borrado.")
        st.rerun()
with btn2:
    if history:
        st.download_button("Exportar CSV", data=history_to_csv_bytes(),
                           file_name="historial_analisis.csv", mime="text/csv")

if history:
    history_df = pd.DataFrame(history)

    st.markdown(section_header("Filtros"), unsafe_allow_html=True)
    f1, f2, f3 = st.columns(3)
    with f1:
        v_opts = ["Todos"] + sorted(history_df["veredicto"].dropna().unique().tolist())
        sel_v = st.selectbox("Veredicto", v_opts)
    with f2:
        t_opts = ["Todos"] + sorted(history_df["tipo"].dropna().unique().tolist())
        sel_t = st.selectbox("Tipo de archivo", t_opts)
    with f3:
        search = st.text_input("Buscar por nombre")

    filtered = history_df.copy()
    if sel_v != "Todos":
        filtered = filtered[filtered["veredicto"] == sel_v]
    if sel_t != "Todos":
        filtered = filtered[filtered["tipo"] == sel_t]
    if search.strip():
        filtered = filtered[filtered["archivo"].str.contains(search.strip(), case=False, na=False)]

    st.markdown(section_header("Resumen"), unsafe_allow_html=True)
    r1, r2, r3, r4, r5 = st.columns(5)
    r1.metric("Total", len(filtered))
    r2.metric("Bloqueados", len(filtered[filtered["veredicto"] == "Bloquear"]))
    r3.metric("Sospechosos", len(filtered[filtered["veredicto"] == "Sospechoso"]))
    r4.metric("Sensibles", len(filtered[filtered["veredicto"] == "Sensible"]))
    avg = round(filtered["score"].mean(), 1) if not filtered.empty else 0
    r5.metric("Score promedio", avg)

    if not filtered.empty:
        render_charts(filtered)

    st.markdown(section_header("Registros"), unsafe_allow_html=True)
    st.dataframe(filtered, use_container_width=True, hide_index=True)

else:
    st.markdown("""
    <div style="background:#161b22;border:1px dashed #21262d;border-radius:8px;
                padding:32px;text-align:center;color:#484f58;font-size:0.88rem;
                font-family:'IBM Plex Mono',monospace;">
        Sin registros &mdash; subi un archivo para comenzar
    </div>
    """, unsafe_allow_html=True)