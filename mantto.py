import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import bcrypt
import logging
import plotly.graph_objects as go
from datetime import datetime, timedelta
from sqlalchemy import create_engine, text
from io import BytesIO
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Configurar logging interno para no mostrar trazas de error al usuario
logging.basicConfig(level=logging.INFO)

# Hash de relleno para prevenir Timing Attacks si el usuario no existe
DUMMY_HASH = bcrypt.hashpw(b"dummy_password", bcrypt.gensalt(rounds=12)).decode('utf-8')

st.set_page_config(
    page_title="Mantenimiento Bombas & Motores",
    page_icon="🌊",
    layout="wide"
)

# ---------------------------------------------------------
# CONEXIÓN A NEON POSTGRESQL (CON AUTORECUPERACIÓN)
# ---------------------------------------------------------
@st.cache_resource
def get_db_engine():
    db_url = st.secrets["postgres"]["url"]
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    
    if "sslmode" not in db_url:
        separador = "&" if "?" in db_url else "?"
        db_url += f"{separador}sslmode=require"

    return create_engine(
        db_url,
        pool_pre_ping=True,  # Chequea si la conexión sigue viva
        pool_recycle=300,     # Recicla la conexión cada 5 min
        pool_timeout=30,
        connect_args={
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 5
        }
    )

engine = get_db_engine()

# ---------------------------------------------------------
# CONTROL DE SEGURIDAD & BCRYPT
# ---------------------------------------------------------
def hash_password(password: str) -> str:
    """Genera un hash seguro usando Bcrypt con salting automático (rounds=12)."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(password: str, hashed_password: str) -> bool:
    """Compara una contraseña introducida con el hash de la BD de forma segura."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

# Inicializar tablas en Neon
def inicializar_bd():
    tablas = [
        """
        CREATE TABLE IF NOT EXISTS inspecciones_bombas (
            id SERIAL PRIMARY KEY,
            fecha DATE,
            equipo VARCHAR(100), -- Almacena el no_serie del motor
            tipo VARCHAR(50),
            v_ab FLOAT, v_bc FLOAT, v_ca FLOAT,
            desbalance_v_ff FLOAT,
            v_an FLOAT, v_bn FLOAT, v_cn FLOAT,
            desbalance_v_fn FLOAT,
            i_a FLOAT, i_b FLOAT, i_c FLOAT,
            desbalance_i FLOAT,
            v_n_tierra FLOAT DEFAULT 0.0,
            factor_carga FLOAT DEFAULT 0.0,
            estado VARCHAR(20),
            tecnico VARCHAR(100),
            observaciones TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            nombre VARCHAR(100),
            rol VARCHAR(20) DEFAULT 'tecnico',
            intentos_fallidos INT DEFAULT 0,
            bloqueado_hasta TIMESTAMP WITHOUT TIME ZONE DEFAULT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS registro_eventos (
            id SERIAL PRIMARY KEY,
            fecha_hora TIMESTAMP,
            equipo VARCHAR(100), -- Almacena el no_serie del motor
            tipo_evento VARCHAR(100),
            severidad VARCHAR(20),
            descripcion TEXT,
            accion_tomada TEXT,
            estatus VARCHAR(30),
            reportado_por VARCHAR(100)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS catalogo_equipos (
            id SERIAL PRIMARY KEY,
            codigo_equipo VARCHAR(100) NOT NULL, -- Posición funcional / Área (ej. M-16)
            ubicacion VARCHAR(150),
            marca_modelo VARCHAR(100),
            no_serie VARCHAR(100) UNIQUE NOT NULL, -- Llave maestra del activo físico
            frame VARCHAR(50),
            balero_superior VARCHAR(50),
            balero_inferior VARCHAR(50),
            potencia_hp FLOAT,
            voltaje_nom FLOAT,
            corriente_nom FLOAT,
            rpm INT,
            factor_servicio FLOAT,
            breaker_amp FLOAT,
            overload_setting FLOAT,
            calibre_cable VARCHAR(50),
            material_conductor VARCHAR(50),
            conductores_por_fase INT DEFAULT 1,
            distancia_m FLOAT,
            estatus VARCHAR(30) DEFAULT 'Operativo',
            observaciones TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS inspecciones_termograficas (
            id SERIAL PRIMARY KEY,
            equipo_id VARCHAR(100) NOT NULL, -- Almacena no_serie
            fecha_inspeccion DATE NOT NULL,
            punto_medicion VARCHAR(100) NOT NULL,
            hot_spot NUMERIC(5, 2) NOT NULL,
            spot_1 NUMERIC(5, 2),
            spot_2 NUMERIC(5, 2),
            spot_3 NUMERIC(5, 2),
            desbalance_max NUMERIC(5, 2),
            delta_hotspot NUMERIC(5, 2),
            estado VARCHAR(20) NOT NULL,
            observaciones TEXT,
            tecnico VARCHAR(100)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS pruebas_aislamiento (
            id SERIAL PRIMARY KEY,
            fecha_hora TIMESTAMP,
            equipo VARCHAR(100), -- Almacena no_serie
            voltaje_prueba_v INT,
            temp_devanado_c FLOAT,
            r_30s_mohm FLOAT,
            r_1min_mohm FLOAT,
            r_10min_mohm FLOAT,
            r_40c_mohm FLOAT,
            dar FLOAT,
            pi FLOAT,
            diagnostico VARCHAR(100),
            observaciones TEXT,
            realizado_por VARCHAR(100)
        );
        """
    ]

    for query in tablas:
        with engine.begin() as conn:
            conn.execute(text(query))

    columnas_extra = [
        "ALTER TABLE inspecciones_bombas ADD COLUMN IF NOT EXISTS v_n_tierra FLOAT DEFAULT 0.0;",
        "ALTER TABLE inspecciones_bombas ADD COLUMN IF NOT EXISTS factor_carga FLOAT DEFAULT 0.0;",
        "ALTER TABLE usuarios ALTER COLUMN password_hash TYPE VARCHAR(255);",
        "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS intentos_fallidos INT DEFAULT 0;",
        "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS bloqueado_hasta TIMESTAMP WITHOUT TIME ZONE DEFAULT NULL;",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS frame VARCHAR(50);",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS balero_superior VARCHAR(50);",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS balero_inferior VARCHAR(50);"
    ]
    for col_query in columnas_extra:
        try:
            with engine.begin() as conn:
                conn.execute(text(col_query))
        except Exception:
            pass

    admin_pass = st.secrets.get("admin", {}).get("initial_password", "CambiarCredencialEnSecretos123!")

    with engine.begin() as conn:
        res = conn.execute(text("SELECT COUNT(*) FROM usuarios;")).scalar()
        if res == 0:
            pass_default = hash_password(admin_pass)
            conn.execute(
                text("INSERT INTO usuarios (username, password_hash, nombre, rol) VALUES (:u, :p, :n, :r);"),
                {"u": "admin", "p": pass_default, "n": "Administrador Principal", "r": "admin"}
            )

try:
    inicializar_bd()
except Exception as e:
    st.error(f"Error inicializando la base de datos: {e}")

# ---------------------------------------------------------
# CONTROL Y FUNCIONES DE SESIÓN
# ---------------------------------------------------------
if "sesion_valida" not in st.session_state:
    st.session_state["sesion_valida"] = False
    st.session_state["usuario_actual"] = None
    st.session_state["username_actual"] = None
    st.session_state["rol_actual"] = None

def logout():
    for key in ["sesion_valida", "usuario_actual", "username_actual", "rol_actual"]:
        st.session_state[key] = None
    st.session_state["sesion_valida"] = False
    st.rerun()

def es_admin() -> bool:
    return st.session_state.get("sesion_valida", False) and st.session_state.get("rol_actual") == "admin"

MAX_INTENTOS = 3
TIEMPO_BLOQUEO_MINUTOS = 15

def login(usuario: str, password: str):
    try:
        with engine.begin() as conn:
            q_user = text("""
                SELECT username, password_hash, nombre, rol, intentos_fallidos, bloqueado_hasta 
                FROM usuarios 
                WHERE username = :u;
            """)
            result = conn.execute(q_user, {"u": usuario}).fetchone()

            if not result:
                check_password(password, DUMMY_HASH)
                return False, "❌ Usuario o contraseña incorrectos."

            username, pass_hash, nombre, rol, intentos, bloqueado_hasta = result
            intentos = intentos or 0

            if bloqueado_hasta and datetime.now() < bloqueado_hasta:
                tiempo_restante = int((bloqueado_hasta - datetime.now()).total_seconds() / 60) + 1
                return False, f"🚫 Cuenta bloqueada por seguridad. Reintenta en {tiempo_restante} min."

            if check_password(password, pass_hash):
                q_reset = text("""
                    UPDATE usuarios 
                    SET intentos_fallidos = 0, bloqueado_hasta = NULL 
                    WHERE username = :u;
                """)
                conn.execute(q_reset, {"u": usuario})

                st.session_state["sesion_valida"] = True
                st.session_state["username_actual"] = username
                st.session_state["usuario_actual"] = nombre
                st.session_state["rol_actual"] = rol
                return True, "¡Bienvenido al sistema!"
            else:
                nuevos_intentos = intentos + 1
                if nuevos_intentos >= MAX_INTENTOS:
                    bloqueo = datetime.now() + timedelta(minutes=TIEMPO_BLOQUEO_MINUTOS)
                    q_block = text("""
                        UPDATE usuarios 
                        SET intentos_fallidos = :i, bloqueado_hasta = :b 
                        WHERE username = :u;
                    """)
                    conn.execute(q_block, {"i": nuevos_intentos, "b": bloqueo, "u": usuario})
                    return False, f"🚫 Límite de {MAX_INTENTOS} intentos superado. Cuenta bloqueada por {TIEMPO_BLOQUEO_MINUTOS} minutos."
                else:
                    q_update = text("UPDATE usuarios SET intentos_fallidos = :i WHERE username = :u;")
                    conn.execute(q_update, {"i": nuevos_intentos, "u": usuario})
                    intentos_restantes = MAX_INTENTOS - nuevos_intentos
                    return False, f"❌ Usuario o contraseña incorrectos. Te quedan {intentos_restantes} intento(s)."

    except Exception as err:
        logging.error(f"Error de autenticación: {err}")
        return False, "⚠️ Error de conexión con el servicio de autenticación."

# ---------------------------------------------------------
# PANTALLA DE LOGIN
# ---------------------------------------------------------
if not st.session_state["sesion_valida"]:
    st.markdown("""
        <style>
        header {visibility: hidden;}
        footer {visibility: hidden;}
        .stApp {
            background: radial-gradient(circle at 15% 30%, #a2c4e3 0%, transparent 40%),
                        radial-gradient(circle at 85% 70%, #92b6db 0%, transparent 45%),
                        radial-gradient(circle at 50% 50%, #dbe7f3 0%, transparent 60%),
                        linear-gradient(135deg, #e4ecf5 0%, #cbdcf0 100%);
            background-attachment: fixed;
        }
        [data-testid="stVerticalBlockBorderWrapper"] {
            background: rgba(255, 255, 255, 0.45) !important;
            backdrop-filter: blur(16px) saturate(180%) !important;
            -webkit-backdrop-filter: blur(16px) saturate(180%) !important;
            border-radius: 24px !important;
            border: 1px solid rgba(255, 255, 255, 0.6) !important;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.08), 
                        inset 0 1px 2px rgba(255, 255, 255, 0.8) !important;
            padding: 35px 30px !important;
        }
        .stTextInput > div > div {
            background-color: rgba(255, 255, 255, 0.5) !important;
            border: 1px solid rgba(200, 215, 230, 0.7) !important;
            border-radius: 12px !important;
            color: #1e293b !important;
        }
        .stButton > button {
            background: linear-gradient(135deg, #475569 0%, #1e293b 100%) !important;
            color: white !important;
            border: none !important;
            border-radius: 14px !important;
            padding: 12px 24px !important;
            font-weight: 600 !important;
            letter-spacing: 1px !important;
            box-shadow: 0 4px 12px rgba(30, 41, 59, 0.2) !important;
            transition: all 0.3s ease !important;
        }
        .stButton > button:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 6px 15px rgba(30, 41, 59, 0.3) !important;
        }
        .app-title {
            text-align: center; color: #1e293b; font-size: 1.8rem; font-weight: 800; letter-spacing: -0.5px; margin-bottom: 2px;
        }
        .app-subtitle {
            text-align: center; color: #475569; font-size: 0.85rem; font-weight: 500; margin-bottom: 25px; letter-spacing: 0.5px;
        }
        .login-badge {
            text-align: center; font-size: 0.75rem; color: #64748b; font-weight: 600; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 15px;
        }
        .footer-tag { text-align: center; font-size: 0.7rem; color: #64748b; margin-top: 15px; }
        </style>
    """, unsafe_allow_html=True)

    st.markdown("<br><br>", unsafe_allow_html=True)
    col_l1, col_l2, col_l3 = st.columns([1, 1.2, 1])

    with col_l2:
        with st.container(border=True):
            st.markdown("<div class='app-title'>🌊 HYDRO-MOTOR</div>", unsafe_allow_html=True)
            st.markdown("<div class='app-subtitle'>Mantenimiento Preventivo & Diagnóstico</div>", unsafe_allow_html=True)
            st.markdown("<div class='login-badge'>— Iniciar Sesión —</div>", unsafe_allow_html=True)

            with st.form("form_login", clear_on_submit=False):
                usr_input = st.text_input("👤 Usuario", placeholder="Ej. operador1")
                pass_input = st.text_input("🔒 Contraseña", type="password", placeholder="••••••••")
                st.markdown("<br>", unsafe_allow_html=True)
                btn_login = st.form_submit_button("INGRESAR AL SISTEMA", use_container_width=True)

                if btn_login:
                    if not usr_input.strip() or not pass_input.strip():
                        st.warning("⚠️ Por favor ingresa usuario y contraseña.")
                    else:
                        exito, mensaje = login(usr_input.strip(), pass_input)
                        if exito:
                            st.success(mensaje)
                            st.rerun()
                        else:
                            st.error(mensaje)

            st.markdown("<div class='footer-tag'>v2.0 • Neon PostgreSQL Active 🟢</div>", unsafe_allow_html=True)

    st.stop()

# ---------------------------------------------------------
# BARRA LATERAL (MENÚ PRINCIPAL)
# ---------------------------------------------------------
opciones_menu = [
    "Dashboard & KPIs", 
    "Catálogo de Equipos",
    "Nueva Inspección Eléctrica", 
    "🔥 Inspección Termográfica (FLIR)",
    "Registro de Eventos", 
    "Historial de Mediciones",
    "Pruebas de Aislamiento",
    "Mi Perfil"
]

if st.session_state.get("rol_actual") == "admin":
    opciones_menu.append("Gestión de Usuarios")

opcion = st.sidebar.radio("Menú Principal", opciones_menu)

st.sidebar.markdown("---")
st.sidebar.markdown(f"👤 **{st.session_state.get('usuario_actual', 'Usuario')}**")
st.sidebar.caption(f"Rol: **{str(st.session_state.get('rol_actual', '')).upper()}**")

if st.sidebar.button("🚪 Cerrar Sesión", use_container_width=True, key="btn_logout_unico"):
    logout()

# ---------------------------------------------------------
# FUNCIONES AUXILIARES & CONSULTAS DE ACTIVOS
# ---------------------------------------------------------

def selector_equipo_por_serie(df_equipos_cat, key_widget="sel_eq_general"):
    """Crea una etiqueta limpia (Posición + S/N) pero retorna el número de serie único."""
    if df_equipos_cat.empty:
        return None, None
    
    df_copy = df_equipos_cat.copy()
    df_copy['label_display'] = (
        df_copy['codigo_equipo'].astype(str).str.strip() + 
        " — [S/N: " + df_copy['no_serie'].astype(str).str.strip() + 
        "] (" + df_copy['ubicacion'].fillna('N/A').astype(str).str.strip() + ")"
    )
    
    opciones = df_copy['label_display'].tolist()
    seleccion = st.selectbox("Seleccionar Equipo / Motor *", opciones, key=key_widget)
    
    row_sel = df_copy[df_copy['label_display'] == seleccion].iloc[0]
    return str(row_sel['no_serie']).strip(), str(row_sel['codigo_equipo']).strip()

def generar_pdf_catalogo_general(df_equipos):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(letter), 
        rightMargin=20, leftMargin=20, topMargin=25, bottomMargin=25
    )
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=16, textColor=colors.HexColor('#1E293B'), spaceAfter=4)
    subtitle_style = ParagraphStyle('SubTitleStyle', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#64748B'), spaceAfter=15)
    cell_style = ParagraphStyle('CellStyle', parent=styles['Normal'], fontSize=7, leading=8)
    cell_header = ParagraphStyle('HeaderStyle', parent=styles['Normal'], fontSize=7.5, leading=9, fontName='Helvetica-Bold', textColor=colors.white)

    fecha_hoy = datetime.now().strftime("%d/%m/%Y %H:%M")
    story.append(Paragraph("📋 CATÁLOGO GENERAL DE EQUIPOS E INSTALACIONES ELÉCTRICAS", title_style))
    story.append(Paragraph(f"Fecha de reporte: {fecha_hoy} | Total de activos: {len(df_equipos)}", subtitle_style))

    headers = [
        Paragraph("Código", cell_header),
        Paragraph("S/N (Serie)", cell_header),
        Paragraph("Ubicación", cell_header),
        Paragraph("Marca / Modelo", cell_header),
        Paragraph("Frame", cell_header),
        Paragraph("HP", cell_header),
        Paragraph("FLA (A)", cell_header),
        Paragraph("Breaker", cell_header),
        Paragraph("Cable / Mat.", cell_header),
        Paragraph("Estatus", cell_header)
    ]
    
    table_data = [headers]

    for _, row in df_equipos.iterrows():
        hilos = int(row.get('conductores_por_fase', 1) or 1)
        cal = str(row.get('calibre_cable', '') or '-').strip()
        mat = str(row.get('material_conductor', '') or '').replace("Cobre (Cu)", "Cu").replace("Aluminio (Al)", "Al")
        cable_fmt = f"{hilos}x {cal} ({mat})" if cal != '-' else '-'

        fila = [
            Paragraph(str(row.get('codigo_equipo', '')), cell_style),
            Paragraph(str(row.get('no_serie', '')), cell_style),
            Paragraph(str(row.get('ubicacion', '') or 'N/A'), cell_style),
            Paragraph(str(row.get('marca_modelo', '') or 'N/A'), cell_style),
            Paragraph(str(row.get('frame', '') or '-'), cell_style),
            Paragraph(f"{row.get('potencia_hp', 0)}", cell_style),
            Paragraph(f"{row.get('corriente_nom', 0)} A", cell_style),
            Paragraph(f"{row.get('breaker_amp', 0)} A", cell_style),
            Paragraph(cable_fmt, cell_style),
            Paragraph(str(row.get('estatus', 'Operativo')), cell_style)
        ]
        table_data.append(fila)

    col_widths = [60, 80, 100, 95, 45, 35, 45, 45, 90, 60]
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
    ]))
    
    story.append(t)
    doc.build(story)
    buffer.seek(0)
    return buffer

def calcular_desbalance(v1: float, v2: float, v3: float) -> float:
    promedio = (v1 + v2 + v3) / 3.0
    if promedio == 0:
        return 0.0
    max_desviacion = max(abs(v1 - promedio), abs(v2 - promedio), abs(v3 - promedio))
    return round((max_desviacion / promedio) * 100, 2)

def aplicar_filtros_tabla(df: pd.DataFrame, col_fecha: str = "fecha", key_suffix: str = "default") -> pd.DataFrame:
    if df.empty:
        return df

    c1, c2, c3 = st.columns(3)
    col_equipo = "equipo" if "equipo" in df.columns else ("codigo_equipo" if "codigo_equipo" in df.columns else None)
    if col_equipo:
        lista_equipos = ["Todos"] + sorted([str(x) for x in df[col_equipo].dropna().unique()])
        equipo_sel = c1.selectbox("Filtrar por Serie / Equipo:", lista_equipos, key=f"f_eq_{key_suffix}")
        if equipo_sel != "Todos":
            df = df[df[col_equipo].astype(str) == equipo_sel]

    col_estado = "estado" if "estado" in df.columns else ("estatus" if "estatus" in df.columns else None)
    if col_estado:
        lista_estados = ["Todos"] + sorted([str(x) for x in df[col_estado].dropna().unique()])
        estado_sel = c2.selectbox("Filtrar por Estado:", lista_estados, key=f"f_est_{key_suffix}")
        if estado_sel != "Todos":
            df = df[df[col_estado].astype(str) == estado_sel]

    if col_fecha in df.columns:
        df[col_fecha] = pd.to_datetime(df[col_fecha])
        fecha_min = df[col_fecha].min().date()
        fecha_max = df[col_fecha].max().date()

        rango_fechas = c3.date_input(
            "Rango de Fechas:",
            value=(fecha_min, fecha_max),
            min_value=fecha_min,
            max_value=fecha_max,
            key=f"f_fcha_{key_suffix}"
        )

        if isinstance(rango_fechas, (list, tuple)) and len(rango_fechas) == 2:
            f_inicio, f_fin = rango_fechas
            df = df[(df[col_fecha].dt.date >= f_inicio) & (df[col_fecha].dt.date <= f_fin)]

    return df

@st.cache_data(ttl=300)
def obtener_datos():
    """Consulta e inspecciones vinculadas por Número de Serie (no_serie)."""
    query = """
    SELECT 
        i.*,
        c.corriente_nom as corriente_nominal_cat,
        c.voltaje_nom as voltaje_nominal_cat,
        c.codigo_equipo as posicion_actual,
        c.ubicacion as area_actual
    FROM inspecciones_bombas i
    LEFT JOIN catalogo_equipos c ON TRIM(i.equipo) = TRIM(c.no_serie)
    ORDER BY i.fecha DESC, i.id DESC;
    """
    df = pd.read_sql_query(query, engine)
    
    if not df.empty:
        df['equipo'] = df['equipo'].astype(str).str.strip()
        df['i_promedio'] = (df['i_a'] + df['i_b'] + df['i_c']) / 3.0
        df['v_promedio'] = (df['v_ab'] + df['v_bc'] + df['v_ca']) / 3.0
        
        fla_ref = np.where(
            (df['corriente_nominal_cat'].notnull()) & (df['corriente_nominal_cat'] > 0),
            df['corriente_nominal_cat'], 65.0
        )
        df['factor_carga'] = ((df['i_promedio'] / fla_ref) * 100).round(2)
        
        i_matrix = df[['i_a', 'i_b', 'i_c']].values
        i_prom = df['i_promedio'].values
        i_prom_safe = np.where(i_prom == 0, np.nan, i_prom)
        max_dev_i = np.max(np.abs(i_matrix - i_prom[:, np.newaxis]), axis=1)
        df['desbalance_i'] = np.nan_to_num((max_dev_i / i_prom_safe) * 100).round(2)
        df['potencia_kw'] = ((np.sqrt(3) * df['v_promedio'] * df['i_promedio'] * 0.85 * 0.90) / 1000.0).round(2)
        
    return df

@st.cache_data
def obtener_termografias():
    try:
        query = text("SELECT * FROM inspecciones_termograficas ORDER BY fecha_inspeccion DESC;")
        with engine.connect() as conn:
            return pd.read_sql(query, conn)
    except Exception as e:
        st.warning(f"No se pudieron cargar inspecciones termográficas: {e}")
        return pd.DataFrame()

@st.cache_data(ttl=300)
def obtener_eventos():
    query = "SELECT * FROM registro_eventos ORDER BY fecha_hora DESC, id DESC;"
    return pd.read_sql_query(query, engine)

@st.cache_data(ttl=300)
def obtener_equipos():
    query = "SELECT * FROM catalogo_equipos ORDER BY codigo_equipo ASC;"
    return pd.read_sql_query(query, engine)

def obtener_pruebas_aislamiento():
    try:
        query = text("SELECT * FROM pruebas_aislamiento ORDER BY fecha_hora DESC;")
        with engine.connect() as conn:
            return pd.read_sql_query(query, conn)
    except Exception as e:
        st.error(f"Error al cargar historial de aislamiento: {e}")
        return pd.DataFrame()

def formatear_df_porcentajes(df):
    df_fmt = df.copy()
    if "desbalance_v_ff" in df_fmt.columns:
        df_fmt["desbalance_v_ff"] = df_fmt["desbalance_v_ff"].map(lambda x: f"{x:.2f}%" if pd.notnull(x) else "")
    if "desbalance_v_fn" in df_fmt.columns:
        df_fmt["desbalance_v_fn"] = df_fmt["desbalance_v_fn"].map(lambda x: f"{x:.2f}%" if pd.notnull(x) else "")
    if "desbalance_i" in df_fmt.columns:
        df_fmt["desbalance_i"] = df_fmt["desbalance_i"].map(lambda x: f"{x:.2f}%" if pd.notnull(x) else "")
    if "factor_carga" in df_fmt.columns:
        df_fmt["factor_carga"] = df_fmt["factor_carga"].map(lambda x: f"{x:.1f}%" if pd.notnull(x) else "")
    if "potencia_kw" in df_fmt.columns:
        df_fmt["potencia_kw"] = df_fmt["potencia_kw"].map(lambda x: f"{x:.2f} kW" if pd.notnull(x) else "")
        
    df_fmt = df_fmt.rename(columns={
        "equipo": "S/N Motor",
        "posicion_actual": "Posición Actual",
        "desbalance_v_ff": "Desbal. V_FF (%)",
        "desbalance_v_fn": "Desbal. V_FN (%)",
        "desbalance_i": "Desbal. I (%)",
        "factor_carga": "Factor Carga (%)",
        "potencia_kw": "Potencia Est. (kW)",
        "v_n_tierra": "V Neutro-Tierra (V)"
    })
    return df_fmt

# ---------------------------------------------------------
# 1. DASHBOARD & KPIS
# ---------------------------------------------------------
if opcion == "Dashboard & KPIs":
    st.title("🌊 Monitoreo Eléctrico & KPIs de Confiabilidad")
    st.caption("Métricas evaluadas bajo estándares NEMA MG 1 e IEEE 141")

    st.markdown("""
        <style>
        .kpi-card { background: rgba(255, 255, 255, 0.65); backdrop-filter: blur(10px); border-radius: 16px; padding: 20px; border: 1px solid rgba(255, 255, 255, 0.8); box-shadow: 0 10px 25px rgba(0,0,0,0.05); text-align: center; }
        .kpi-title { font-size: 0.85rem; color: #64748b; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .kpi-value { font-size: 1.8rem; font-weight: 800; color: #1e293b; margin: 8px 0; }
        .kpi-status { font-size: 0.8rem; font-weight: 600; border-radius: 12px; padding: 4px 12px; display: inline-block; }
        .status-ok { background-color: #dcfce7; color: #166534; }
        .status-warning { background-color: #fef9c3; color: #854d0e; }
        .status-danger { background-color: #fee2e2; color: #991b1b; }
        .status-info { background-color: #e0f2fe; color: #0369a1; }
        .equipment-card { background: rgba(255, 255, 255, 0.5); border-radius: 14px; padding: 15px; border-left: 6px solid #cbd5e1; margin-bottom: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
        .eq-border-ok { border-left-color: #22c55e !important; }
        .eq-border-warning { border-left-color: #eab308 !important; }
        .eq-border-danger { border-left-color: #ef4444 !important; }
        .eq-border-standby { border-left-color: #0284c7 !important; }
        </style>
    """, unsafe_allow_html=True)

    with st.container():
        col_f1, col_f2, col_f3 = st.columns([1.5, 1.5, 1])
        with col_f1:
            fecha_inicio = st.date_input("Fecha Inicio", datetime.now() - timedelta(days=90))
        with col_f2:
            fecha_fin = st.date_input("Fecha Fin", datetime.now())
        with col_f3:
            st.markdown("<br>", unsafe_allow_html=True)
            btn_actualizar = st.button("🔄 Actualizar Datos", use_container_width=True)

    try:
        with engine.connect() as conn:
            df_elec = pd.read_sql(text("SELECT * FROM inspecciones_bombas WHERE fecha BETWEEN :i AND :f ORDER BY fecha DESC;"), conn, params={"i": fecha_inicio, "f": fecha_fin})
            df_termo = pd.read_sql(text("SELECT * FROM inspecciones_termograficas WHERE fecha_inspeccion BETWEEN :i AND :f;"), conn, params={"i": fecha_inicio, "f": fecha_fin})
            df_equipos = pd.read_sql(text("SELECT * FROM catalogo_equipos;"), conn)
            df_eventos_kpi = pd.read_sql(text("SELECT * FROM registro_eventos;"), conn)
    except Exception as e:
        st.error(f"Error al cargar datos del Dashboard: {e}")
        df_elec, df_termo, df_equipos, df_eventos_kpi = pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    eventos_activos_kpi = pd.DataFrame()
    if not df_eventos_kpi.empty and 'equipo' in df_eventos_kpi.columns:
        df_eventos_kpi['estatus_norm'] = df_eventos_kpi['estatus'].astype(str).str.lower().str.strip()
        eventos_activos_kpi = df_eventos_kpi[~df_eventos_kpi['estatus_norm'].isin(['resuelto', 'cerrado', 'finalizado'])]

    # ---------------------------------------------------------
    # CÁLCULO UNIFICADO Y REAL DE KPIS Y SEMÁFORO
    # ---------------------------------------------------------
    total_equipos = len(df_equipos) if not df_equipos.empty else 0
    equipos_standby, equipos_fuera = 0, 0
    alertas_criticas, alertas_advertencia = 0, 0

    # 1. Obtener eventos activos de la bitácora (incluyendo S/N y códigos de posición)
    try:
        with engine.connect() as conn:
            df_ev_activos = pd.read_sql(text("SELECT equipo, severidad FROM registro_eventos WHERE estatus IN ('Abierto', 'En Revisión');"), conn)
    except Exception:
        df_ev_activos = pd.DataFrame()

    ids_con_incidencia = set(df_ev_activos['equipo'].astype(str).str.strip().unique()) if not df_ev_activos.empty else set()

    # 2. Recorrido unificado idéntico a la jerarquía del semáforo visual
    if not df_equipos.empty:
        for _, row in df_equipos.iterrows():
            est_cat = str(row.get('estatus', '')).lower().strip()
            serial = str(row.get('no_serie', '')).strip()
            codigo = str(row.get('codigo_equipo', '')).strip()

            # Jerarquía 1: Fuera de servicio (Rojo)
            if "fuera" in est_cat or "baja" in est_cat or "paro" in est_cat:
                equipos_fuera += 1
            # Jerarquía 2: Standby (Azul)
            elif "standby" in est_cat or "reserva" in est_cat:
                equipos_standby += 1
            # Jerarquía 3: Operando pero con incidencia abierta (Naranja / Alerta)
            elif serial in ids_con_incidencia or codigo in ids_con_incidencia:
                sev_row = df_ev_activos[
                    (df_ev_activos['equipo'].astype(str).str.strip() == serial) | 
                    (df_ev_activos['equipo'].astype(str).str.strip() == codigo)
                ]
                if not sev_row.empty and any(sev_row['severidad'].isin(['Alta', 'Crítica'])):
                    alertas_criticas += 1
                else:
                    alertas_advertencia += 1

    total_alertas_activas = alertas_criticas + alertas_advertencia

    if total_equipos > 0:
        penalizacion = ((alertas_criticas * 20) + (alertas_advertencia * 8) + (equipos_fuera * 15)) / total_equipos
        salud_global = max(0, min(100, int(100 - penalizacion)))
    else:
        salud_global = 100

    # --- RENDERIZADO DE TARJETAS SUPERIORES (KPIs) ---
    st.markdown("<br>", unsafe_allow_html=True)
    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    with kpi1:
        st.markdown(f"<div class='kpi-card'><div class='kpi-title'>Salud Global</div><div class='kpi-value'>{salud_global}%</div><span class='kpi-status status-ok'>🟢 Óptimo</span></div>", unsafe_allow_html=True)
    with kpi2:
        st.markdown(f"<div class='kpi-card'><div class='kpi-title'>Total Activos</div><div class='kpi-value'>{total_equipos}</div><span class='kpi-status status-ok'>⚙️ Registrados</span></div>", unsafe_allow_html=True)
    with kpi3:
        st.markdown(f"<div class='kpi-card'><div class='kpi-title'>Standby</div><div class='kpi-value' style='color:#0284c7;'>{equipos_standby}</div><span class='kpi-status status-info'>⏸️ Reserva</span></div>", unsafe_allow_html=True)
    with kpi4:
        st.markdown(f"<div class='kpi-card'><div class='kpi-title'>Fuera de Servicio</div><div class='kpi-value' style='color:#ef4444;'>{equipos_fuera}</div><span class='kpi-status status-danger'>🔴 Inactivos</span></div>", unsafe_allow_html=True)
    with kpi5:
        st.markdown(f"<div class='kpi-card'><div class='kpi-title'>Alertas Activas</div><div class='kpi-value' style='color:#eab308;'>{total_alertas_activas}</div><span class='kpi-status status-warning'>⚠️ Pendientes</span></div>", unsafe_allow_html=True)

    st.markdown("<br><br>", unsafe_allow_html=True)
    
    # --- CREACIÓN DE PESTAÑAS ---
    tab_fleet, tab_radar, tab_scatter = st.tabs(["🎛️ Estado de Equipos (Semáforo)", "📐 Diagrama Fasorial", "📈 Factor de Carga vs. Salud"])

    with tab_fleet:
        st.subheader("Estado de Salud por Área y Posición Operativa")
        if df_equipos.empty:
            st.info("No hay equipos registrados en el catálogo.")
        else:
            try:
                with engine.connect() as conn:
                    df_ev_activos = pd.read_sql(text("SELECT equipo, severidad, tipo_evento FROM registro_eventos WHERE estatus IN ('Abierto', 'En Revisión');"), conn)
                
                identificadores_con_eventos = set(df_ev_activos['equipo'].astype(str).str.strip().unique()) if not df_ev_activos.empty else set()
            except Exception:
                identificadores_con_eventos = set()

            df_equipos['ubicacion'] = df_equipos['ubicacion'].fillna("Sin Ubicación").astype(str).str.strip()
            ubicaciones = sorted(df_equipos['ubicacion'].unique())
            
            for ub in ubicaciones:
                df_grupo = df_equipos[df_equipos['ubicacion'] == ub]
                with st.expander(f"📍 Área: {ub} ({len(df_grupo)} activos)", expanded=True):
                    cols_grid = st.columns(3)
                    for idx, row in df_grupo.reset_index(drop=True).iterrows():
                        col_idx = idx % 3
                        serial = str(row['no_serie']).strip()
                        codigo = str(row['codigo_equipo']).strip()
                        estatus_cat = str(row.get('estatus', '')).lower().strip()
                        
                        if "fuera" in estatus_cat or "baja" in estatus_cat or "paro" in estatus_cat:
                            st_color = "eq-border-danger"
                            badge_txt = "🔴 Fuera de Servicio"
                        elif "standby" in estatus_cat or "reserva" in estatus_cat:
                            st_color = "eq-border-standby"
                            badge_txt = "⏸️ Standby"
                        elif serial in identificadores_con_eventos or codigo in identificadores_con_eventos:
                            st_color = "eq-border-warning"
                            badge_txt = "⚠️ En Alerta / Incidencia"
                        else:
                            st_color = "eq-border-ok"
                            badge_txt = f"🟢 {row.get('estatus', 'Operativo')}"

                        with cols_grid[col_idx]:
                            st.markdown(f"""
                                <div class='equipment-card {st_color}'>
                                    <strong style='font-size: 1.1rem; color: #1e293b;'>{codigo}</strong> 
                                    <span style='font-size: 0.8rem; color: #64748b;'>(S/N: {serial})</span><br>
                                    <span style='font-size: 0.85rem; color: #475569;'>{row.get('marca_modelo', 'N/A')} | {row.get('potencia_hp', 0)} HP</span><br>
                                    <div style='margin-top: 8px;'>
                                        <span class='kpi-status' style='background: #f1f5f9; color: #334155;'>FLA: {row.get('corriente_nom', 0)} A</span>
                                        <span style='float: right; font-size:0.8rem; font-weight:bold;'>{badge_txt}</span>
                                    </div>
                                </div>
                            """, unsafe_allow_html=True)

# ---------------------------------------------------------
# 2. CATÁLOGO DE EQUIPOS
# ---------------------------------------------------------
elif opcion == "Catálogo de Equipos":
    st.title("🏷️ Catálogo General de Activos e Instalación Eléctrica")

    tab1, tab2, tab3 = st.tabs([
        "📋 Lista de Equipos Registrados", 
        "➕ Registrar Nuevo Motor / Bomba",
        "🛠️ Modificar / Reubicar Activo"
    ])

    with tab1:
        df_eq = obtener_equipos()
        if df_eq.empty:
            st.info("No hay equipos en el catálogo.")
        else:
            col_t1, col_t2 = st.columns([3, 1])
            with col_t1:
                st.subheader("📍 Activos Organizados por Ubicación / Área")
            with col_t2:
                pdf_bytes = generar_pdf_catalogo_general(df_eq)
                st.download_button("📄 Exportar PDF Catálogo", data=pdf_bytes, file_name=f"catalogo_{datetime.now().strftime('%Y%m%d')}.pdf", mime="application/pdf", use_container_width=True)

            df_eq['ubicacion'] = df_eq['ubicacion'].fillna("Sin Ubicación").astype(str).str.strip()
            for ub in sorted(df_eq['ubicacion'].unique()):
                df_grupo = df_eq[df_eq['ubicacion'] == ub]
                with st.expander(f"📍 Área: {ub} ({len(df_grupo)} activos registrados)", expanded=True):
                    st.dataframe(df_grupo, use_container_width=True)

    with tab2:
        st.subheader("Alta de Equipo por Número de Serie")
        with st.form("form_nuevo_equipo", clear_on_submit=True):
            st.markdown("##### ⚙️ 1. Placa de Datos del Motor / Bomba")
            c_e1, c_e2 = st.columns(2)
            with c_e1:
                no_serie = st.text_input("Número de Serie (Llave Máster) *", placeholder="Ej. SN-8894021")
                cod_eq = st.text_input("Posición Operativa / Área *", placeholder="Ej. M-16, Pozo-01")
                ubic = st.text_input("Ubicación Física en Planta", placeholder="Ej. Carcamo Vaso Nuevo")
                marca_m = st.text_input("Marca / Modelo", placeholder="Ej. Siemens / WEG")
                frame_m = st.text_input("Armazón / Frame", placeholder="Ej. 326T")
                balero_sup = st.text_input("Balero Superior", placeholder="Ej. 6219 C3")
                balero_inf = st.text_input("Balero Inferior", placeholder="Ej. 7226 2P7A")
                estatus_e = st.selectbox("Estatus Operativo Inicial", ["Operativo", "En Mantenimiento", "Fuera de Servicio", "Standby"])

            with c_e2:
                pot_hp = st.number_input("Potencia (HP)", value=175.0, step=5.0)
                v_nom = st.number_input("Voltaje Nominal (V)", value=440.0, step=10.0)
                i_nom = st.number_input("Corriente Nominal / FLA (A) *", value=220.0, step=1.0)
                rpm_e = st.number_input("RPM", value=1750, step=50)
                fs_e = st.number_input("Factor de Servicio (F.S.)", value=1.15, step=0.05)

            st.divider()
            st.markdown("##### ⚡ 2. Protecciones y CCM")
            c_p1, c_p2 = st.columns(2)
            breaker_a = c_p1.number_input("ITM Principal (A)", value=350.0, step=5.0)
            sobrecarga_a = c_p2.number_input("Ajuste Protección / Fusible (A)", value=220.0, step=1.0)

            st.markdown("##### 🔌 3. Alimentación")
            c_c1, c_c2 = st.columns(2)
            calibre_c = c_c1.text_input("Calibre Conductor", value="3/0 AWG")
            material_c = c_c1.selectbox("Material Conductor", ["Cobre (Cu)", "Aluminio (Al)"])
            hilos_fase = c_c2.number_input("Conductores por Fase", value=1, min_value=1, max_value=6)
            dist_m = c_c2.number_input("Distancia a CCM (m)", value=35.0, step=5.0)

            obs_eq = st.text_area("Observaciones Adicionales")

            c_b1, c_b2 = st.columns(2)
            btn_guardar_eq = c_b1.form_submit_button("💾 Guardar en Catálogo", use_container_width=True)
            btn_cancelar_eq = c_b2.form_submit_button("❌ Cancelar", type="secondary", use_container_width=True)

            if btn_cancelar_eq:
                st.warning("Registro cancelado.")
                st.rerun()

            if btn_guardar_eq:
                if not no_serie.strip() or not cod_eq.strip():
                    st.error("El Número de Serie y la Posición Operativa son obligatorios.")
                else:
                    q_ins_eq = text("""
                    INSERT INTO catalogo_equipos (
                        codigo_equipo, ubicacion, marca_modelo, no_serie, frame, 
                        balero_superior, balero_inferior, potencia_hp, voltaje_nom, corriente_nom, rpm, factor_servicio, 
                        estatus, breaker_amp, overload_setting, calibre_cable, material_conductor,
                        conductores_por_fase, distancia_m, observaciones
                    ) VALUES (
                        :cod, :ub, :mm, :ns, :fr, :bsup, :binf, :php, :vnom, :inom, :rpm, :fs, 
                        :est, :brk, :ovl, :cal, :mat, :hilos, :dist, :obs
                    );
                    """)
                    try:
                        with engine.begin() as conn:
                            conn.execute(q_ins_eq, {
                                "cod": cod_eq.strip(), "ub": ubic, "mm": marca_m, "ns": no_serie.strip(),
                                "fr": frame_m, "bsup": balero_sup.strip(), "binf": balero_inf.strip(),
                                "php": pot_hp, "vnom": v_nom, "inom": i_nom, "rpm": rpm_e, "fs": fs_e,
                                "est": estatus_e, "brk": breaker_a, "ovl": sobrecarga_a, "cal": calibre_c,
                                "mat": material_c, "hilos": hilos_fase, "dist": dist_m, "obs": obs_eq
                            })
                        st.cache_data.clear()
                        st.success(f"✅ Motor con S/N **{no_serie.strip()}** guardado correctamente.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error al guardar en base de datos: {e}")

    with tab3:
        df_eq = obtener_equipos()
        if df_eq.empty:
            st.info("No hay activos registrados para editar.")
        else:
            st.subheader("🛠️ Gestor de Activos y Reubicaciones (Por Número de Serie)")
            
            df_eq['label_gestor'] = "S/N: " + df_eq['no_serie'].astype(str).str.strip() + " | Posición Actual: " + df_eq['codigo_equipo'].astype(str).str.strip()
            label_sel = st.selectbox("Selecciona el Activo:", df_eq['label_gestor'].tolist(), key="sel_gestor_sn")
            
            eq_reg = df_eq[df_eq['label_gestor'] == label_sel].iloc[0]
            target_sn = str(eq_reg['no_serie']).strip()

            c_edit, c_del = st.columns(2)

            with c_edit:
                with st.expander("✏️ Editar Ficha o Cambiar de Posición (Reubicar)", expanded=True):
                    with st.form(f"form_edit_sn_{target_sn}"):
                        # Permitir editar o asignar un S/N interno (vital para motores reconstruidos sin placa como M-28)
                        edit_no_serie = st.text_input("Número de Serie Master (S/N) *", value=target_sn)
                        
                        edit_pos = st.text_input("Posición Operativa / Código (ej. M-29)", value=str(eq_reg.get('codigo_equipo', '') or ""))
                        edit_ubic = st.text_input("Ubicación en Planta", value=str(eq_reg.get('ubicacion', '') or ""))
                        edit_marca = st.text_input("Marca / Modelo", value=str(eq_reg.get('marca_modelo', '') or ""))
                        edit_frame = st.text_input("Armazón / Frame", value=str(eq_reg.get('frame', '') or ""))
                        edit_bsup = st.text_input("Balero Superior", value=str(eq_reg.get('balero_superior', '') or ""))
                        edit_binf = st.text_input("Balero Inferior", value=str(eq_reg.get('balero_inferior', '') or ""))
                        
                        estatus_op = ["Operativo", "En Mantenimiento", "Fuera de Servicio", "Standby"]
                        val_est = eq_reg.get('estatus', 'Operativo')
                        idx_est = estatus_op.index(val_est) if val_est in estatus_op else 0
                        edit_estatus = st.selectbox("Estatus Operativo", estatus_op, index=idx_est)

                        c_eq1, c_eq2 = st.columns(2)
                        edit_pot = c_eq1.number_input("Potencia (HP)", value=float(eq_reg.get('potencia_hp', 0.0) or 0.0))
                        edit_vnom = c_eq2.number_input("Voltaje (V)", value=float(eq_reg.get('voltaje_nom', 0.0) or 0.0))
                        
                        c_eq3, c_eq4 = st.columns(2)
                        edit_inom = c_eq3.number_input("Corriente Nominal (A)", value=float(eq_reg.get('corriente_nom', 0.0) or 0.0))
                        edit_rpm = c_eq4.number_input("RPM", value=int(eq_reg.get('rpm', 0) or 0))

                        edit_obs = st.text_area("Observaciones Adicionales / Historial de Movimiento", value=str(eq_reg.get('observaciones', '') or ""))

                        c_btn1, c_btn2 = st.columns(2)
                        btn_upd = c_btn1.form_submit_button("💾 Guardar Cambios", use_container_width=True)
                        btn_can = c_btn2.form_submit_button("❌ Cancelar", type="secondary", use_container_width=True)

                        if btn_can:
                            st.warning("Edición cancelada.")
                            st.rerun()

                        if btn_upd:
                            q_upd_eq = text("""
                            UPDATE catalogo_equipos SET
                                no_serie = :nuevo_ns,
                                codigo_equipo = :cod,
                                ubicacion = :ub,
                                marca_modelo = :mm,
                                frame = :fr,
                                balero_superior = :bsup,
                                balero_inferior = :binf,
                                potencia_hp = :php,
                                voltaje_nom = :vnom,
                                corriente_nom = :inom,
                                rpm = :rpm,
                                estatus = :est,
                                observaciones = :obs
                            WHERE TRIM(no_serie) = TRIM(:ns) OR (no_serie IS NULL OR no_serie = '');
                            """)
                            try:
                                with engine.begin() as conn:
                                    conn.execute(q_upd_eq, {
                                        "nuevo_ns": edit_no_serie.strip(),
                                        "cod": edit_pos.strip(), "ub": edit_ubic, "mm": edit_marca,
                                        "fr": edit_frame, "bsup": edit_bsup.strip(), "binf": edit_binf.strip(),
                                        "php": edit_pot, "vnom": edit_vnom, "inom": edit_inom,
                                        "rpm": edit_rpm, "est": edit_estatus, "obs": edit_obs, "ns": target_sn
                                    })
                                st.cache_data.clear()
                                st.success(f"✅ Motor S/N **{target_sn}** reubicado / actualizado correctamente a **{edit_pos}**.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ Error al actualizar en BD: {e}")

            with c_del:
                with st.expander("🗑️ Eliminar Activo del Catálogo", expanded=True):
                    st.warning(f"⚠️ ¿Eliminar permanentemente el S/N **{target_sn}**?")
                    st.write(f"**Posición Actual:** {eq_reg.get('codigo_equipo')}")
                    st.write(f"**Ubicación:** {eq_reg.get('ubicacion')}")

                    if st.button("❌ Confirmar Eliminación", key=f"del_sn_{target_sn}"):
                        q_del = text("DELETE FROM catalogo_equipos WHERE TRIM(no_serie) = TRIM(:ns);")
                        try:
                            with engine.begin() as conn:
                                conn.execute(q_del, {"ns": target_sn})
                            st.cache_data.clear()
                            st.success(f"🗑️ Motor S/N **{target_sn}** eliminado del catálogo.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error al eliminar: {e}")

# ---------------------------------------------------------
# 3. NUEVA INSPECCIÓN ELÉCTRICA
# ---------------------------------------------------------
elif opcion == "Nueva Inspección Eléctrica":
    st.title("📋 Lectura Electromecánica en Campo")

    df_equipos_cat = obtener_equipos()

    if not df_equipos_cat.empty and 'estatus' in df_equipos_cat.columns:
        df_activos = df_equipos_cat[df_equipos_cat['estatus'].isin(['Operativo', 'En Revisión'])]
    else:
        df_activos = df_equipos_cat.copy()

    with st.form("form_bomba", clear_on_submit=True):
        st.subheader("📌 Datos Generales del Registro")
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            fecha_insp = st.date_input("Fecha de Inspección", value=datetime.today().date())
            
            if not df_activos.empty:
                no_serie_sel, codigo_pos = selector_equipo_por_serie(df_activos, key_widget="sel_eq_insp")
            else:
                no_serie_sel = st.text_input("Número de Serie *", value="SN-001").strip()

        with col_f2:
            tipo_equipo = st.selectbox("Tipo de Motor", ["Sumergible", "Vertical (Eje Largo)", "Centrífuga Horizontal"])
            tecnico = st.text_input("Técnico Inspector", value=st.session_state.get("usuario_actual", "Técnico"))

        st.markdown("---")
        st.markdown("#### ⚡ Voltajes Fase - Fase ($V_{FF}$)")
        vf_1, vf_2, vf_3 = st.columns(3)
        v_ab = vf_1.number_input("V_ab (V)", value=440.0)
        v_bc = vf_2.number_input("V_bc (V)", value=440.0)
        v_ca = vf_3.number_input("V_ca (V)", value=440.0)

        st.markdown("#### 📐 Voltajes Fase - Neutro ($V_{FN}$) y Puesta a Tierra")
        vn_1, vn_2, vn_3, vn_4 = st.columns(4)
        v_an = vn_1.number_input("V_an (V)", value=254.0)
        v_bn = vn_2.number_input("V_bn (V)", value=254.0)
        v_cn = vn_3.number_input("V_cn (V)", value=254.0)
        v_n_tierra = vn_4.number_input("V Neutro-Tierra (V)", value=0.5)

        st.markdown("#### 🔌 Consumos de Corriente por Fase")
        i_col1, i_col2, i_col3 = st.columns(3)
        i_a = i_col1.number_input("Fase A (A)", value=50.0)
        i_b = i_col2.number_input("Fase B (A)", value=50.0)
        i_c = i_col3.number_input("Fase C (A)", value=50.0)

        observaciones = st.text_area("Observaciones adicionales")

        c_btn1, c_btn2 = st.columns(2)
        enviado = c_btn1.form_submit_button("💾 Guardar Registro", use_container_width=True)
        btn_can = c_btn2.form_submit_button("❌ Cancelar", type="secondary", use_container_width=True)

        if btn_can:
            st.warning("Inspección cancelada.")
            st.rerun()

        if enviado:
            desb_v_ff = calcular_desbalance(v_ab, v_bc, v_ca)
            desb_v_fn = calcular_desbalance(v_an, v_bn, v_cn)
            desb_i = calcular_desbalance(i_a, i_b, i_c)
            i_prom = (i_a + i_b + i_c) / 3.0
            
            corriente_nom = 65.0
            if not df_equipos_cat.empty and no_serie_sel in df_equipos_cat["no_serie"].values:
                corriente_nom = df_equipos_cat[df_equipos_cat["no_serie"] == no_serie_sel]["corriente_nom"].values[0]
            
            factor_carga_calc = round((i_prom / corriente_nom) * 100, 2) if corriente_nom > 0 else 0.0

            if desb_v_ff > 2.0 or desb_v_fn > 2.0 or desb_i > 10.0 or v_n_tierra > 5.0 or factor_carga_calc > 115.0:
                estado_eval = "Crítico"
            elif desb_v_ff > 1.0 or desb_v_fn > 1.0 or desb_i > 5.0 or v_n_tierra > 2.0 or factor_carga_calc > 100.0:
                estado_eval = "Advertencia"
            else:
                estado_eval = "Normal"

            insert_query = text("""
            INSERT INTO inspecciones_bombas 
            (fecha, equipo, tipo, v_ab, v_bc, v_ca, desbalance_v_ff, v_an, v_bn, v_cn, desbalance_v_fn, i_a, i_b, i_c, desbalance_i, v_n_tierra, factor_carga, estado, tecnico, observaciones)
            VALUES 
            (:fecha, :equipo, :tipo, :v_ab, :v_bc, :v_ca, :desbalance_v_ff, :v_an, :v_bn, :v_cn, :desbalance_v_fn, :i_a, :i_b, :i_c, :desbalance_i, :v_n_tierra, :factor_carga, :estado, :tecnico, :observaciones);
            """)

            try:
                with engine.begin() as conn:
                    conn.execute(insert_query, {
                        "fecha": fecha_insp, "equipo": str(no_serie_sel).strip(), "tipo": str(tipo_equipo),
                        "v_ab": v_ab, "v_bc": v_bc, "v_ca": v_ca, "desbalance_v_ff": desb_v_ff,
                        "v_an": v_an, "v_bn": v_bn, "v_cn": v_cn, "desbalance_v_fn": desb_v_fn,
                        "i_a": i_a, "i_b": i_b, "i_c": i_c, "desbalance_i": desb_i,
                        "v_n_tierra": v_n_tierra, "factor_carga": factor_carga_calc,
                        "estado": estado_eval, "tecnico": tecnico, "observaciones": observaciones
                    })
                st.success(f"✅ Lectura guardada para el motor S/N **{no_serie_sel}** (Estado: {estado_eval}).")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Error al insertar datos: {e}")

# ---------------------------------------------------------
# 4. INSPECCIÓN TERMOGRÁFICA (FLIR)
# ---------------------------------------------------------
elif opcion == "🔥 Inspección Termográfica (FLIR)":
    st.title("🔥 Registro Termográfico Completo (Vacitado FLIR)")
    df_equipos_cat = obtener_equipos()

    tab_termo_nuevo, tab_termo_historial = st.tabs(["➕ Vaciar Inspección Completa", "📜 Historial Térmico"])

    with tab_termo_nuevo:
        with st.form("form_termografia_completa", clear_on_submit=True):
            col_eq, col_fecha = st.columns(2)
            with col_eq:
                if not df_equipos_cat.empty:
                    no_serie_termo, _ = selector_equipo_por_serie(df_equipos_cat, key_widget="sel_termo_eq")
                else:
                    no_serie_termo = st.text_input("Número de Serie", value="SN-001").strip()
            with col_fecha:
                fecha_termo = st.date_input("Fecha de Inspección", value=datetime.today().date())

            st.markdown("---")
            st.subheader("⚙️ 1. Motor (Mecánico / Térmico)")
            m1, m2, m3 = st.columns(3)
            t_bal_sup = m1.number_input("🔩 Balero Superior (°C)", value=40.0, step=0.1)
            t_bal_inf = m2.number_input("🔩 Balero Inferior (°C)", value=40.0, step=0.1)
            t_carcasa = m3.number_input("📦 Carcasa (°C)", value=40.0, step=0.1)

            st.subheader("⚡ 2. ITM")
            i1, i2, i3 = st.columns(3)
            t_itm_a = i1.number_input("Fase A (°C)", value=35.0, step=0.1)
            t_itm_b = i2.number_input("Fase B (°C)", value=35.0, step=0.1)
            t_itm_c = i3.number_input("Fase C (°C)", value=35.0, step=0.1)

            observaciones_gen = st.text_area("Observaciones Generales")
            btn_guardar_termo = st.form_submit_button("💾 Guardar Inspección Completa")

            if btn_guardar_termo:
                componentes = [
                    {"punto": "Motor (Mecánico/Térmico)", "t1": t_bal_sup, "t2": t_bal_inf, "t3": t_carcasa, "es_motor": True},
                    {"punto": "ITM (Interruptor Termomagnético)", "t1": t_itm_a, "t2": t_itm_b, "t3": t_itm_c, "es_motor": False}
                ]
                q_ins = text("""
                INSERT INTO inspecciones_termograficas 
                (equipo_id, fecha_inspeccion, punto_medicion, hot_spot, spot_1, spot_2, spot_3, desbalance_max, delta_hotspot, estado, observaciones, tecnico)
                VALUES (:eq, :f, :p, :hot, :s1, :s2, :s3, :desbal, :delta, :est, :obs, :tec);
                """)
                tec_actual = st.session_state.get("usuario_actual", "Sistema")
                try:
                    with engine.begin() as conn:
                        for item in componentes:
                            t1, t2, t3 = item["t1"], item["t2"], item["t3"]
                            hot = max(t1, t2, t3)
                            desbal = hot - min(t1, t2, t3)
                            delta = hot - ((t1 + t2 + t3) / 3.0)
                            est = "CRITICO" if hot >= 85 or desbal >= 15 else ("ADVERTENCIA" if hot >= 70 or desbal >= 5 else "NORMAL")
                            
                            conn.execute(q_ins, {
                                "eq": str(no_serie_termo).strip(), "f": fecha_termo, "p": item["punto"],
                                "hot": hot, "s1": t1, "s2": t2, "s3": t3, "desbal": desbal,
                                "delta": delta, "est": est, "obs": observaciones_gen, "tec": tec_actual
                            })
                    st.success(f"✅ Inspección registrada para S/N **{no_serie_termo}**.")
                except Exception as e:
                    st.error(f"❌ Error al guardar termografía: {e}")

    with tab_termo_historial:
        df_termo = obtener_termografias()
        if not df_termo.empty:
            df_termo_filt = aplicar_filtros_tabla(df_termo, col_fecha="fecha_inspeccion", key_suffix="hist_termo")
            st.dataframe(df_termo_filt, use_container_width=True)

# ---------------------------------------------------------
# 5. REGISTRO DE EVENTOS (BITÁCORA DE EXPANDERS)
# ---------------------------------------------------------
elif opcion == "Registro de Eventos":
    st.title("🚨 Bitácora y Registro de Eventos")

    df_equipos_cat = obtener_equipos()

    tab_nuevo, tab_historial, tab_gestion = st.tabs([
        "➕ Registrar Evento", 
        "📋 Bitácora de Eventos", 
        "🛠️ Editar / Eliminar Evento"
    ])

    with tab_nuevo:
        with st.form("form_evento", clear_on_submit=True):
            col1, col2 = st.columns(2)

            with col1:
                col_f_ev, col_h_ev = st.columns(2)
                with col_f_ev:
                    fecha_ev = st.date_input("Fecha del Evento *", value=datetime.today().date())
                with col_h_ev:
                    hora_ev = st.time_input("Hora del Evento *", value=datetime.now().time())

                if not df_equipos_cat.empty:
                    no_serie_ev, _ = selector_equipo_por_serie(df_equipos_cat, key_widget="sel_eq_evento_n")
                else:
                    no_serie_ev = st.text_input("Número de Serie Afectado *", value="SN-001")

                tipo_ev = st.selectbox(
                    "Tipo de Evento *",
                    [
                        "Desconexión por daño mecánico",
                        "Falla eléctrica / Sobrevoltaje",
                        "Paro de emergencia",
                        "Mantenimiento no programado",
                        "Fuga o Sobrecalentamiento",
                        "Otro"
                    ]
                )

            with col2:
                severidad_ev = st.select_slider("Nivel de Severidad", options=["Baja", "Media", "Alta", "Crítica"])
                descripcion_ev = st.text_area("Descripción / Causa Raíz", placeholder="Detalla qué sucedió exactamente...")
                accion_ev = st.text_input("Acción Inmediata Tomada", placeholder="Ej. Se aisló el equipo y notificó...")
                estatus_ev = st.selectbox("Estatus del Evento", ["Abierto", "En Revisión", "Resuelto"])

            st.divider()

            col_b_ev1, col_b_ev2 = st.columns(2)
            btn_evento = col_b_ev1.form_submit_button("💾 Guardar Evento en BD", use_container_width=True)
            btn_cancelar_ev = col_b_ev2.form_submit_button("❌ Cancelar", type="secondary", use_container_width=True)

            if btn_cancelar_ev:
                st.warning("Registro de evento cancelado.")
                st.rerun()

            if btn_evento:
                fecha_hora_completa = datetime.combine(fecha_ev, hora_ev)
                usuario_actual = st.session_state.get("usuario_actual", "Sistema")

                q_ins_ev = text("""
                    INSERT INTO registro_eventos (fecha_hora, equipo, tipo_evento, severidad, descripcion, accion_tomada, estatus, reportado_por)
                    VALUES (:fh, :eq, :te, :sev, :desc, :acc, :est, :rep);
                """)

                params_ev = {
                    "fh": fecha_hora_completa,
                    "eq": str(no_serie_ev).strip(), 
                    "te": tipo_ev,
                    "sev": severidad_ev,
                    "desc": descripcion_ev,
                    "acc": accion_ev,
                    "est": estatus_ev,
                    "rep": usuario_actual
                }

                # Mapeo correcto para el semáforo del catálogo
                if estatus_ev == "Resuelto":
                    estado_catalogo = "Operativo"
                elif estatus_ev == "En Revisión":
                    estado_catalogo = "En Mantenimiento"
                else:
                    estado_catalogo = "Fuera de Servicio"

                q_upd_equipo = text("""
                    UPDATE catalogo_equipos 
                    SET estatus = :est 
                    WHERE TRIM(no_serie) = TRIM(:eq) OR TRIM(codigo_equipo) = TRIM(:eq);
                """)

                try:
                    with engine.begin() as conn:
                        conn.execute(q_ins_ev, params_ev)
                        conn.execute(q_upd_equipo, {"est": estado_catalogo, "eq": str(no_serie_ev).strip()})

                    st.cache_data.clear()
                    st.success(f"✅ Evento registrado para el S/N **{no_serie_ev}** y estado actualizado a '{estado_catalogo}'.")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Error al guardar el evento: {e}")

    with tab_historial:
        df_eventos = obtener_eventos()
        df_cat = obtener_equipos()
        
        if df_eventos.empty:
            st.info("Aún no hay eventos ni incidentes registrados.")
        else:
            map_serie_a_pos = dict(zip(df_cat['no_serie'].str.strip(), df_cat['codigo_equipo'].str.strip())) if not df_cat.empty else {}
            df_eventos['posicion_mostrada'] = df_eventos['equipo'].map(map_serie_a_pos).fillna(df_eventos['equipo'])

            df_evt_filtered = aplicar_filtros_tabla(df_eventos, col_fecha="fecha_hora", key_suffix="registro_eventos")

            f_col1, f_col2 = st.columns(2)
            with f_col1:
                filtro_eq = st.multiselect("Filtrar por Motor / S/N:", df_eventos["equipo"].dropna().unique())
            with f_col2:
                filtro_sev = st.multiselect("Filtrar por Severidad:", df_eventos["severidad"].dropna().unique())

            if filtro_eq:
                df_evt_filtered = df_evt_filtered[df_evt_filtered["equipo"].isin(filtro_eq)]
            if filtro_sev:
                df_evt_filtered = df_evt_filtered[df_evt_filtered["severidad"].isin(filtro_sev)]

            st.markdown(f"### 📋 Historial de Bitácora ({len(df_evt_filtered)} eventos encontrados)")
            st.divider()

            for _, row in df_evt_filtered.iterrows():
                estatus = row.get('estatus', 'Abierto')
                icono_est = "🟢" if estatus == "Resuelto" else ("🟡" if estatus == "En Revisión" else "🔴")
                
                pos_txt = row['posicion_mostrada']
                serial_txt = row['equipo']
                titulo_tarjeta = f"{icono_est} ID #{row['id']} | **Pos: {pos_txt}** (S/N: {serial_txt}) — {row['tipo_evento']} [{estatus}]"
                
                with st.expander(titulo_tarjeta):
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.markdown(f"**📅 Fecha y Hora:**\n{row['fecha_hora']}")
                    with c2:
                        st.markdown(f"**⚡ Severidad:**\n{row['severidad']}")
                    with c3:
                        st.markdown(f"**👤 Reportado por:**\n{row.get('reportado_por', 'N/A')}")
                    
                    st.markdown("---")
                    st.markdown("**📝 Descripción / Causa Raíz:**")
                    st.info(row['descripcion'] if row['descripcion'] else "Sin descripción.")
                    
                    st.markdown("**🛠️ Acciones Tomadas e Historial de Cierre:**")
                    accion_texto = row['accion_tomada'] if row['accion_tomada'] else "Sin acciones registradas aún."
                    st.success(accion_texto)

            st.divider()
            csv_ev = df_evt_filtered.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Exportar Eventos a CSV", data=csv_ev, file_name=f"eventos_{datetime.now().strftime('%Y%m%d')}.csv", mime="text/csv")

    with tab_gestion:
        df_eventos = obtener_eventos()
        df_cat_ges = obtener_equipos()

        if df_eventos.empty:
            st.info("No hay eventos registrados para modificar o eliminar.")
        else:
            st.subheader("🛠️ Administrar o Reconectar / Cerrar Eventos")
            
            map_s_p = dict(zip(df_cat_ges['no_serie'].str.strip(), df_cat_ges['codigo_equipo'].str.strip())) if not df_cat_ges.empty else {}

            opciones_eventos = {}
            for _, row in df_eventos.iterrows():
                serial_val = str(row['equipo']).strip()
                pos_val = map_s_p.get(serial_val, serial_val)
                label_opt = f"ID #{row['id']} | Pos: {pos_val} (S/N: {serial_val}) | {row['tipo_evento']} [{row['estatus']}]"
                opciones_eventos[label_opt] = row['id']
            
            label_evt_sel = st.selectbox("Selecciona el evento a gestionar:", list(opciones_eventos.keys()))
            id_evt_sel = opciones_eventos[label_evt_sel]
            evt_registro = df_eventos[df_eventos['id'] == id_evt_sel].iloc[0]

            col_cerrar_evt, col_edit_evt, col_del_evt = st.columns(3)

            with col_cerrar_evt:
                with st.expander("⚡ Reconectar Motor / Cerrar Evento", expanded=True):
                    if evt_registro['estatus'] == "Resuelto":
                        st.success(f"✅ El evento ID #{id_evt_sel} ya se encuentra resuelto/cerrado.")
                    else:
                        with st.form(f"form_cerrar_evt_{id_evt_sel}", clear_on_submit=True):
                            st.caption(f"**Motor S/N:** {evt_registro['equipo']}")
                            st.caption(f"**Causa inicial:** {evt_registro['tipo_evento']}")
                            
                            nuevo_estatus = st.selectbox("Nuevo Estatus", ["Resuelto", "En Revisión"])
                            fecha_cierre = st.date_input("Fecha de Reconexión/Cierre", value=datetime.today().date())
                            accion_reconexion = st.text_area("Detalle de la Reconexión / Solución", placeholder="Ej. Se corrigió la falla de aislamiento...")

                            col_bc1, col_bc2 = st.columns(2)
                            btn_reconectar = col_bc1.form_submit_button("💾 Guardar y Cerrar", use_container_width=True)
                            btn_cancelar_close = col_bc2.form_submit_button("❌ Cancelar", type="secondary", use_container_width=True)

                            if btn_cancelar_close:
                                st.warning("Operación de cierre cancelada.")
                                st.rerun()

                            if btn_reconectar:
                                if not accion_reconexion.strip():
                                    st.warning("⚠️ Debes ingresar el detalle de la acción realizada.")
                                else:
                                    usuario_actual = st.session_state.get("usuario_actual", "Sistema")
                                    accion_previa = str(evt_registro['accion_tomada'] or "").strip()
                                    registro_cierre = f"[{fecha_cierre.strftime('%d/%m/%Y')} - {usuario_actual}]: {accion_reconexion.strip()}"
                                    accion_final = f"{accion_previa}\n\n{registro_cierre}".strip()

                                    q_close_evt = text("""
                                        UPDATE registro_eventos SET estatus = :est, accion_tomada = :acc WHERE id = :id;
                                    """)
                                    
                                    if nuevo_estatus == "Resuelto":
                                        estado_equipo = "Operativo"
                                    else:
                                        estado_equipo = "En Mantenimiento"

                                    q_upd_eq_close = text("""
                                        UPDATE catalogo_equipos SET estatus = :est WHERE TRIM(no_serie) = TRIM(:eq) OR TRIM(codigo_equipo) = TRIM(:eq);
                                    """)

                                    try:
                                        with engine.begin() as conn:
                                            conn.execute(q_close_evt, {"est": nuevo_estatus, "acc": accion_final, "id": int(id_evt_sel)})
                                            conn.execute(q_upd_eq_close, {"est": estado_equipo, "eq": str(evt_registro['equipo']).strip()})
                                        
                                        st.cache_data.clear()
                                        st.success(f"✅ Evento #{id_evt_sel} cerrado y equipo actualizado.")
                                        st.rerun()
                                    except Exception as e:
                                        st.error(f"❌ Error al actualizar evento: {e}")

            with col_edit_evt:
                with st.expander("✏️ Modificar Evento Seleccionado"):
                    with st.form(f"form_edit_evt_{id_evt_sel}"):
                        fh_val = evt_registro['fecha_hora']
                        if isinstance(fh_val, str):
                            fh_val = datetime.strptime(fh_val, "%Y-%m-%d %H:%M:%S")

                        edit_f_ev = st.date_input("Fecha", value=fh_val.date())
                        edit_h_ev = st.time_input("Hora", value=fh_val.time())
                        
                        # Selector seguro de número de serie en lugar de texto libre para evitar errores
                        if not df_cat_ges.empty:
                            lista_sn_opt = df_cat_ges['no_serie'].astype(str).str.strip().tolist()
                            current_sn = str(evt_registro['equipo']).strip()
                            idx_sn = lista_sn_opt.index(current_sn) if current_sn in lista_sn_opt else 0
                            edit_eq_ev = st.selectbox("S/N Motor Correcto", lista_sn_opt, index=idx_sn)
                        else:
                            edit_eq_ev = st.text_input("S/N Motor", value=str(evt_registro['equipo'])).strip()

                        tipos_evt_lista = ["Desconexión por daño mecánico", "Falla eléctrica / Sobrevoltaje", "Paro de emergencia", "Mantenimiento no programado", "Fuga o Sobrecalentamiento", "Otro"]
                        idx_tipo_evt = tipos_evt_lista.index(evt_registro['tipo_evento']) if evt_registro['tipo_evento'] in tipos_evt_lista else 0
                        edit_tipo_ev = st.selectbox("Tipo de Evento", tipos_evt_lista, index=idx_tipo_evt)

                        edit_desc_ev = st.text_area("Descripción", value=str(evt_registro['descripcion'] or ""))
                        edit_acc_ev = st.text_area("Acción Tomada", value=str(evt_registro['accion_tomada'] or ""))

                        estatus_lista = ["Abierto", "En Revisión", "Resuelto"]
                        idx_est = estatus_lista.index(evt_registro['estatus']) if evt_registro['estatus'] in estatus_lista else 0
                        edit_est_ev = st.selectbox("Estatus", estatus_lista, index=idx_est)

                        st.divider()
                        col_be1, col_be2 = st.columns(2)
                        btn_update_evt = col_be1.form_submit_button("💾 Guardar Cambios", use_container_width=True)
                        btn_cancelar_edit_evt = col_be2.form_submit_button("❌ Cancelar", type="secondary", use_container_width=True)

                        if btn_cancelar_edit_evt:
                            st.warning("Edición cancelada.")
                            st.rerun()

                        if btn_update_evt:
                            new_fh = datetime.combine(edit_f_ev, edit_h_ev)
                            q_upd_evt = text("""
                                UPDATE registro_eventos SET fecha_hora = :fh, equipo = :eq, tipo_evento = :te, descripcion = :desc, accion_tomada = :acc, estatus = :est WHERE id = :id;
                            """)
                            
                            if edit_est_ev == "Resuelto":
                                estado_cat = "Operativo"
                            elif edit_est_ev == "En Revisión":
                                estado_cat = "En Mantenimiento"
                            else:
                                estado_cat = "Fuera de Servicio"

                            q_upd_eq_cat = text("""
                                UPDATE catalogo_equipos SET estatus = :est WHERE TRIM(no_serie) = TRIM(:eq) OR TRIM(codigo_equipo) = TRIM(:eq);
                            """)

                            try:
                                with engine.begin() as conn:
                                    conn.execute(q_upd_evt, {"fh": new_fh, "eq": edit_eq_ev, "te": edit_tipo_ev, "desc": edit_desc_ev, "acc": edit_acc_ev, "est": edit_est_ev, "id": int(id_evt_sel)})
                                    conn.execute(q_upd_eq_cat, {"est": estado_cat, "eq": edit_eq_ev})
                                st.cache_data.clear()
                                st.success(f"✅ Evento #{id_evt_sel} actualizado.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ Error al actualizar: {e}")

            with col_del_evt:
                with st.expander("🗑️ Eliminar Evento Seleccionado"):
                    st.warning(f"⚠️ ¿Eliminar registro **ID #{id_evt_sel}**?")
                    if st.button("❌ Confirmar Eliminación", key=f"del_evt_{id_evt_sel}"):
                        q_del_evt = text("DELETE FROM registro_eventos WHERE id = :id;")
                        q_upd_eq_del = text("UPDATE catalogo_equipos SET estatus = 'Operativo' WHERE TRIM(no_serie) = TRIM(:eq) OR TRIM(codigo_equipo) = TRIM(:eq);")
                        try:
                            with engine.begin() as conn:
                                conn.execute(q_del_evt, {"id": int(id_evt_sel)})
                                conn.execute(q_upd_eq_del, {"eq": str(evt_registro['equipo']).strip()})
                            st.cache_data.clear()
                            st.success(f"✅ Evento #{id_evt_sel} eliminado.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error al eliminar: {e}")
                            
# ---------------------------------------------------------
# 6. HISTORIAL DE MEDICIONES
# ---------------------------------------------------------
elif opcion == "Historial de Mediciones":
    st.title("📊 Historial y Gestión de Inspecciones Eléctricas")
    df = obtener_datos()

    if df.empty:
        st.info("No hay registros en la base de datos.")
    else:
        st.subheader("📋 Registros Existentes")
        df_filtrado = aplicar_filtros_tabla(df, col_fecha="fecha", key_suffix="historial_mediciones")
        st.dataframe(formatear_df_porcentajes(df_filtrado), use_container_width=True)

        st.markdown("---")
        st.subheader("🛠️ Modificar o Eliminar un Registro")
        lista_ids = df_filtrado['id'].tolist() if not df_filtrado.empty else df['id'].tolist()
        id_seleccionado = st.selectbox("Selecciona ID del registro:", lista_ids)
        registro = df[df['id'] == id_seleccionado].iloc[0]

        col_accion1, col_accion2 = st.columns(2)
        with col_accion1:
            with st.expander("✏️ Editar Registro Seleccionado"):
                with st.form(f"form_editar_{id_seleccionado}"):
                    edit_equipo = st.text_input("S/N Motor", value=str(registro['equipo'])).strip()
                    edit_v_ab = st.number_input("V_ab", value=float(registro['v_ab']))
                    edit_v_bc = st.number_input("V_bc", value=float(registro['v_bc']))
                    edit_v_ca = st.number_input("V_ca", value=float(registro['v_ca']))
                    edit_i_a = st.number_input("I_a", value=float(registro['i_a']))
                    edit_i_b = st.number_input("I_b", value=float(registro['i_b']))
                    edit_i_c = st.number_input("I_c", value=float(registro['i_c']))
                    edit_obs = st.text_area("Observaciones", value=str(registro['observaciones'] or ""))

                    btn_act = st.form_submit_button("💾 Guardar Cambios")
                    if btn_act:
                        new_desb_v = calcular_desbalance(edit_v_ab, edit_v_bc, edit_v_ca)
                        new_desb_i = calcular_desbalance(edit_i_a, edit_i_b, edit_i_c)
                        update_query = text("""
                        UPDATE inspecciones_bombas SET
                            equipo = :equipo, v_ab = :v_ab, v_bc = :v_bc, v_ca = :v_ca,
                            desbalance_v_ff = :desb_v, i_a = :i_a, i_b = :i_b, i_c = :i_c,
                            desbalance_i = :desb_i, observaciones = :obs WHERE id = :id;
                        """)
                        try:
                            with engine.begin() as conn:
                                conn.execute(update_query, {
                                    "equipo": edit_equipo, "v_ab": edit_v_ab, "v_bc": edit_v_bc, "v_ca": edit_v_ca,
                                    "desb_v": new_desb_v, "i_a": edit_i_a, "i_b": edit_i_b, "i_c": edit_i_c,
                                    "desb_i": new_desb_i, "obs": edit_obs, "id": int(id_seleccionado)
                                })
                            st.success(f"✅ Registro #{id_seleccionado} actualizado.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error al actualizar: {e}")

        with col_accion2:
            with st.expander("🗑️ Eliminar Registro Seleccionado"):
                if st.button("❌ Confirmar Eliminación", key=f"del_med_{id_seleccionado}"):
                    try:
                        with engine.begin() as conn:
                            conn.execute(text("DELETE FROM inspecciones_bombas WHERE id = :id;"), {"id": int(id_seleccionado)})
                        st.success(f"🗑️ Registro #{id_seleccionado} eliminado.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error al eliminar: {e}")

# ---------------------------------------------------------
# 7. PRUEBAS DE AISLAMIENTO (IEEE Std 43)
# ---------------------------------------------------------
elif opcion == "Pruebas de Aislamiento":
    st.title("⚡ Pruebas de Resistencia de Aislamiento (IEEE Std 43)")
    df_equipos_cat = obtener_equipos()

    tab_nueva_p, tab_hist_p = st.tabs(["🧪 Registrar Nueva Prueba", "📋 Historial y Tendencias"])

    with tab_nueva_p:
        with st.form("form_prueba_aislamiento", clear_on_submit=True):
            c_a1, c_a2 = st.columns(2)
            with c_a1:
                f_prueba = st.date_input("Fecha", value=datetime.today().date())
                h_prueba = st.time_input("Hora", value=datetime.now().time())
                if not df_equipos_cat.empty:
                    no_serie_p, _ = selector_equipo_por_serie(df_equipos_cat, key_widget="sel_aisla_eq")
                else:
                    no_serie_p = st.text_input("Número de Serie *", value="SN-001")
                v_aplicado = st.selectbox("Tensión de Prueba CD (Megger)", [500, 1000, 2500, 5000])
                temp_c = st.number_input("Temperatura Devanado (°C)", value=25.0)

            with c_a2:
                r_30s = st.number_input("Resistencia 30s (MΩ)", value=0.0)
                r_1min = st.number_input("Resistencia 1 min (MΩ) *", value=15.0)
                r_10min = st.number_input("Resistencia 10 min (MΩ)", value=0.0)
                obs_prueba = st.text_area("Observaciones")

            btn_evaluar = st.form_submit_button("📊 Evaluar e Guardar")

            if btn_evaluar:
                if r_1min <= 0:
                    st.error("⚠️ La lectura a 1 minuto debe ser mayor a 0 MΩ.")
                else:
                    r_40c = r_1min * (0.5 ** ((40.0 - temp_c) / 10.0))
                    dar_val = round(r_1min / r_30s, 2) if r_30s > 0 else None
                    pi_val = round(r_10min / r_1min, 2) if r_10min > 0 else None
                    diag_est = "CRÍTICO" if r_40c < 1.0 else ("ALERTA" if r_40c < 5.0 else ("ACEPTABLE" if r_40c < 100.0 else "EXCELENTE"))

                    q_ins_p = text("""
                    INSERT INTO pruebas_aislamiento (fecha_hora, equipo, voltaje_prueba_v, temp_devanado_c, r_30s_mohm, r_1min_mohm, r_10min_mohm, r_40c_mohm, dar, pi, diagnostico, observaciones, realizado_por)
                    VALUES (:fh, :eq, :v, :temp, :r30, :r1m, :r10m, :r40, :dar, :pi, :diag, :obs, :rep);
                    """)
                    try:
                        with engine.begin() as conn:
                            conn.execute(q_ins_p, {
                                "fh": datetime.combine(f_prueba, h_prueba), "eq": str(no_serie_p).strip(),
                                "v": v_aplicado, "temp": temp_c, "r30": r_30s if r_30s > 0 else None,
                                "r1m": r_1min, "r10m": r_10min if r_10min > 0 else None, "r40": round(r_40c, 2),
                                "dar": dar_val, "pi": pi_val, "diag": diag_est, "obs": obs_prueba, "rep": st.session_state.usuario_actual
                            })
                        st.success(f"✅ Prueba guardada para S/N **{no_serie_p}** (Diagnóstico: {diag_est}).")
                    except Exception as e:
                        st.error(f"❌ Error al guardar en BD: {e}")

    with tab_hist_p:
        df_p = obtener_pruebas_aislamiento()
        if not df_p.empty:
            st.dataframe(df_p, use_container_width=True)

# ---------------------------------------------------------
# 8. MI PERFIL
# ---------------------------------------------------------
elif opcion == "Mi Perfil":
    st.title("👤 Configuración de Perfil")
    st.write(f"**Nombre Actual:** {st.session_state.usuario_actual}")
    st.write(f"**Usuario:** {st.session_state.username_actual}")
    st.write(f"**Rol:** {st.session_state.rol_actual}")
    
    st.subheader("Cambiar Contraseña")
    with st.form("form_cambiar_pass", clear_on_submit=True):
        pass_actual = st.text_input("Contraseña Actual", type="password")
        pass_nueva = st.text_input("Nueva Contraseña", type="password")
        pass_confirm = st.text_input("Confirmar Nueva Contraseña", type="password")
        btn_pass = st.form_submit_button("Actualizar Contraseña")

        if btn_pass:
            if not pass_actual or not pass_nueva or not pass_confirm:
                st.warning("Por favor completa todos los campos.")
            elif pass_nueva != pass_confirm:
                st.error("La nueva contraseña y su confirmación no coinciden.")
            else:
                with engine.connect() as conn:
                    user_db = conn.execute(text("SELECT password_hash FROM usuarios WHERE username = :u;"), {"u": st.session_state.username_actual}).fetchone()
                
                if user_db and check_password(pass_actual, user_db.password_hash):
                    with engine.begin() as conn:
                        conn.execute(text("UPDATE usuarios SET password_hash = :p WHERE username = :u;"), {"p": hash_password(pass_nueva), "u": st.session_state.username_actual})
                    st.success("✅ Contraseña actualizada correctamente.")
                else:
                    st.error("❌ La contraseña actual es incorrecta.")

# ---------------------------------------------------------
# 9. GESTIÓN DE USUARIOS (ADMIN)
# ---------------------------------------------------------
if opcion == "Gestión de Usuarios":
    if not es_admin():
        st.error("🚫 No tienes permisos para acceder a este módulo.")
        st.stop()

    st.title("👥 Gestión de Usuarios y Permisos")
    tab_crear, tab_listar = st.tabs(["➕ Crear Nuevo Usuario", "📋 Usuarios Registrados"])

    with tab_crear:
        with st.form("form_crear_usuario", clear_on_submit=True):
            c1, c2 = st.columns(2)
            with c1:
                nuevo_username = st.text_input("Nombre de Usuario", placeholder="ej. jperez").strip().lower()
                nombre_completo = st.text_input("Nombre Completo", placeholder="ej. Juan Pérez")
            with c2:
                nuevo_pass = st.text_input("Contraseña Temporal", type="password")
                rol_seleccionado = st.selectbox("Rol", ["tecnico", "operador", "admin"])

            btn_crear = st.form_submit_button("Guardar Usuario")
            if btn_crear:
                if not nuevo_username or not nuevo_pass or not nombre_completo:
                    st.warning("⚠️ Todos los campos son obligatorios.")
                else:
                    try:
                        pass_hash = hash_password(nuevo_pass)
                        with engine.begin() as conn:
                            user_exists = conn.execute(text("SELECT COUNT(*) FROM usuarios WHERE username = :u;"), {"u": nuevo_username}).scalar()
                            if user_exists > 0:
                                st.error(f"❌ El usuario '{nuevo_username}' ya existe.")
                            else:
                                conn.execute(text("INSERT INTO usuarios (username, password_hash, nombre, rol) VALUES (:u, :p, :n, :r);"), {"u": nuevo_username, "p": pass_hash, "n": nombre_completo, "r": rol_seleccionado})
                                st.success(f"✅ Usuario **{nuevo_username}** creado exitosamente.")
                    except Exception as err:
                        st.error(f"Error al guardar: {err}")

    with tab_listar:
        try:
            with engine.connect() as conn:
                df_usr = pd.read_sql(text("SELECT id, username, nombre, rol, intentos_fallidos FROM usuarios ORDER BY id ASC;"), conn)
            st.dataframe(df_usr, use_container_width=True)
        except Exception as err:
            st.error(f"Error al consultar usuarios: {err}")
