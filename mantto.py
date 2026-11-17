import logging
from datetime import datetime, timedelta, timezone
from html import escape as esc_html
from io import BytesIO
from xml.sax.saxutils import escape as esc_xml

import bcrypt
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from sqlalchemy import create_engine, text

try:
    from zoneinfo import ZoneInfo
    TZ_LOCAL = ZoneInfo("America/Monterrey")
except Exception:  # sin tzdata: Monterrey es UTC-6 fijo desde 2022
    TZ_LOCAL = timezone(timedelta(hours=-6))

st.set_page_config(
    page_title="Mantenimiento Bombas & Motores",
    page_icon="🌊",
    layout="wide"
)

# Configurar logging interno para no mostrar trazas de error al usuario
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mantto")


# ---------------------------------------------------------
# CONSTANTES Y UMBRALES (un solo lugar para ajustarlos)
# ---------------------------------------------------------
UMBRALES = {
    # Desbalance de voltaje: NEMA MG 1 (>1% exige derateo del motor)
    "desb_v_adv": 1.0,
    "desb_v_crit": 2.0,
    # Desbalance de corriente: criterio práctico de planta (no es límite NEMA)
    "desb_i_adv": 5.0,
    "desb_i_crit": 10.0,
    # Voltaje neutro-tierra
    "v_nt_adv": 2.0,
    "v_nt_crit": 5.0,
    # Factor de carga: crítico = factor de servicio del motor (115% si no hay dato)
    "fc_adv": 100.0,
    "fc_crit_default": 115.0,
    # Termografía (°C)
    "termo_hot_adv": 70.0,
    "termo_hot_crit": 85.0,
    "termo_spread_adv": 5.0,
    "termo_spread_crit": 15.0,
    # Aislamiento (IEEE Std 43) - validar mínimos con el tipo de devanado
    "aisl_r40_crit": 1.0,
    "aisl_r40_alerta": 5.0,
    "aisl_r40_excelente": 100.0,
    "aisl_pi_min": 2.0,
    "aisl_pi_crit": 1.0,
    "aisl_pi_ignorar_si_r1min_mayor": 5000.0,
}

ESTATUS_CATALOGO = ["Operativo", "En Mantenimiento", "Fuera de Servicio", "Standby", "Baja"]
ESTATUS_EVENTO_ACTIVO = ("Abierto", "En Revisión")
TIPOS_EVENTO = [
    "Desconexión por daño mecánico",
    "Falla eléctrica / Sobrevoltaje",
    "Paro de emergencia",
    "Mantenimiento no programado",
    "Fuga o Sobrecalentamiento",
    "Otro",
]
SEVERIDADES = ["Baja", "Media", "Alta", "Crítica"]
MAX_INTENTOS = 3
TIEMPO_BLOQUEO_MINUTOS = 15


# ---------------------------------------------------------
# UTILIDADES GENERALES
# ---------------------------------------------------------
def ahora() -> datetime:
    """Fecha/hora local de Monterrey (sin tzinfo, para guardar en la BD)."""
    return datetime.now(TZ_LOCAL).replace(tzinfo=None)


def hoy():
    return ahora().date()


def _f(valor, default=0.0) -> float:
    """Convierte a float; si es None/NaN regresa el default."""
    try:
        v = float(valor)
    except (TypeError, ValueError):
        return default
    return default if np.isnan(v) else v


def _s(valor) -> str:
    """Convierte a texto; None/NaN -> cadena vacía."""
    if valor is None:
        return ""
    try:
        if pd.isna(valor):
            return ""
    except (TypeError, ValueError):
        pass
    return str(valor)


def flash(mensaje: str, tipo: str = "success"):
    """Guarda un mensaje para mostrarlo después del st.rerun()."""
    st.session_state["_flash"] = (tipo, mensaje)


def mostrar_flash():
    item = st.session_state.pop("_flash", None)
    if item:
        tipo, mensaje = item
        getattr(st, tipo, st.info)(mensaje)


def form_key(base: str) -> str:
    """Llave de formulario con contador: al incrementarlo el formulario se limpia."""
    return f"{base}_{st.session_state.get(f'_n_{base}', 0)}"


def reset_form(base: str):
    st.session_state[f"_n_{base}"] = st.session_state.get(f"_n_{base}", 0) + 1


def limpiar_cache():
    st.cache_data.clear()
    st.session_state.pop("pdf_catalogo", None)


def validar_password(pwd: str):
    """Devuelve un mensaje de error o None si la contraseña es aceptable."""
    if len(pwd) < 8:
        return "La contraseña debe tener al menos 8 caracteres."
    if not any(c.isalpha() for c in pwd) or not any(c.isdigit() for c in pwd):
        return "La contraseña debe incluir letras y números."
    return None


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
        pool_pre_ping=True,   # Chequea si la conexión sigue viva
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
@st.cache_resource
def get_dummy_hash() -> str:
    """Hash de relleno (se calcula una sola vez) contra Timing Attacks."""
    return bcrypt.hashpw(b"dummy_password", bcrypt.gensalt(rounds=12)).decode("utf-8")


def hash_password(password: str) -> str:
    """Genera un hash seguro usando Bcrypt con salting automático (rounds=12)."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def check_password(password: str, hashed_password: str) -> bool:
    """Compara una contraseña introducida con el hash de la BD de forma segura."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


# ---------------------------------------------------------
# INICIALIZACIÓN DE LA BASE DE DATOS (se ejecuta UNA vez por proceso)
# ---------------------------------------------------------
@st.cache_resource
def inicializar_bd():
    tablas = [
        """
        CREATE TABLE IF NOT EXISTS inspecciones_bombas (
            id SERIAL PRIMARY KEY,
            fecha DATE,
            equipo VARCHAR(100),
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
            bloqueado_hasta TIMESTAMP WITHOUT TIME ZONE DEFAULT NULL,
            activo BOOLEAN DEFAULT TRUE
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS registro_eventos (
            id SERIAL PRIMARY KEY,
            fecha_hora TIMESTAMP,
            equipo VARCHAR(100),
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
            codigo_equipo VARCHAR(100) NOT NULL,
            ubicacion VARCHAR(150),
            marca_modelo VARCHAR(100),
            no_serie VARCHAR(100) UNIQUE NOT NULL,
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
            equipo_id VARCHAR(100) NOT NULL,
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
            tecnico VARCHAR(100),
            etiquetas VARCHAR(200),
            temp_ambiente NUMERIC(5, 2),
            emisividad NUMERIC(3, 2),
            delta_ambiente NUMERIC(5, 2)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS pruebas_aislamiento (
            id SERIAL PRIMARY KEY,
            fecha_hora TIMESTAMP,
            equipo VARCHAR(100),
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
        """,
        """
        CREATE TABLE IF NOT EXISTS movimientos_equipo (
            id SERIAL PRIMARY KEY,
            fecha_hora TIMESTAMP,
            no_serie VARCHAR(100) NOT NULL,
            tipo_movimiento VARCHAR(40),
            posicion_anterior VARCHAR(100),
            posicion_nueva VARCHAR(100),
            ubicacion_anterior VARCHAR(150),
            ubicacion_nueva VARCHAR(150),
            motivo TEXT,
            realizado_por VARCHAR(100)
        );
        """
    ]

    for query in tablas:
        with engine.begin() as conn:
            conn.execute(text(query))

    # Migraciones ligeras para bases creadas con versiones anteriores
    columnas_extra = [
        # Tablas creadas con versiones viejas pueden no tener 'id'. SERIAL lo rellena en las filas existentes.
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS id SERIAL;",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS ubicacion VARCHAR(150);",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS marca_modelo VARCHAR(100);",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS potencia_hp FLOAT;",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS voltaje_nom FLOAT;",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS corriente_nom FLOAT;",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS rpm INT;",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS factor_servicio FLOAT;",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS breaker_amp FLOAT;",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS overload_setting FLOAT;",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS calibre_cable VARCHAR(50);",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS material_conductor VARCHAR(50);",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS conductores_por_fase INT DEFAULT 1;",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS distancia_m FLOAT;",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS estatus VARCHAR(30) DEFAULT 'Operativo';",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS observaciones TEXT;",
        "ALTER TABLE inspecciones_bombas ADD COLUMN IF NOT EXISTS v_n_tierra FLOAT DEFAULT 0.0;",
        "ALTER TABLE inspecciones_bombas ADD COLUMN IF NOT EXISTS factor_carga FLOAT DEFAULT 0.0;",
        "ALTER TABLE usuarios ALTER COLUMN password_hash TYPE VARCHAR(255);",
        "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS intentos_fallidos INT DEFAULT 0;",
        "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS bloqueado_hasta TIMESTAMP WITHOUT TIME ZONE DEFAULT NULL;",
        "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS activo BOOLEAN DEFAULT TRUE;",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS frame VARCHAR(50);",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS balero_superior VARCHAR(50);",
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS balero_inferior VARCHAR(50);",
        "ALTER TABLE inspecciones_termograficas ADD COLUMN IF NOT EXISTS etiquetas VARCHAR(200);",
        "ALTER TABLE inspecciones_termograficas ADD COLUMN IF NOT EXISTS temp_ambiente NUMERIC(5, 2);",
        "ALTER TABLE inspecciones_termograficas ADD COLUMN IF NOT EXISTS emisividad NUMERIC(3, 2);",
        "ALTER TABLE inspecciones_termograficas ADD COLUMN IF NOT EXISTS delta_ambiente NUMERIC(5, 2);",
    ]
    for col_query in columnas_extra:
        try:
            with engine.begin() as conn:
                conn.execute(text(col_query))
        except Exception as err:
            logger.warning(f"Migración omitida ({col_query[:60]}...): {err}")

    # Verificación: sin 'id' en el catálogo no se puede editar por llave primaria
    with engine.connect() as conn:
        tiene_id = conn.execute(text(
            "SELECT COUNT(*) FROM information_schema.columns "
            "WHERE table_name = 'catalogo_equipos' AND column_name = 'id';"
        )).scalar()
    if not tiene_id:
        raise RuntimeError(
            "La tabla catalogo_equipos no tiene la columna 'id' y no se pudo crear automáticamente. "
            "Ejecuta en Neon: ALTER TABLE catalogo_equipos ADD COLUMN id SERIAL;"
        )

    # Índices para consultas por equipo / fecha
    indices = [
        "CREATE INDEX IF NOT EXISTS idx_insp_equipo_fecha ON inspecciones_bombas (equipo, fecha);",
        "CREATE INDEX IF NOT EXISTS idx_eventos_equipo_estatus ON registro_eventos (equipo, estatus);",
        "CREATE INDEX IF NOT EXISTS idx_termo_equipo_fecha ON inspecciones_termograficas (equipo_id, fecha_inspeccion);",
        "CREATE INDEX IF NOT EXISTS idx_aisla_equipo_fecha ON pruebas_aislamiento (equipo, fecha_hora);",
        "CREATE INDEX IF NOT EXISTS idx_mov_serie_fecha ON movimientos_equipo (no_serie, fecha_hora);",
        # 'id' como identificador único de fila (la llave primaria vieja es codigo_equipo)
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_catalogo_id ON catalogo_equipos (id);",
        # El S/N no puede repetirse entre motores (los vacíos se permiten mientras se capturan)
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_catalogo_no_serie ON catalogo_equipos (UPPER(TRIM(no_serie))) "
        "WHERE no_serie IS NOT NULL AND TRIM(no_serie) <> '';",
    ]
    for idx_query in indices:
        try:
            with engine.begin() as conn:
                conn.execute(text(idx_query))
        except Exception as err:
            logger.warning(f"Índice omitido: {err}")

    # Usuario administrador inicial (solo si no existe ningún usuario)
    with engine.begin() as conn:
        total_usuarios = conn.execute(text("SELECT COUNT(*) FROM usuarios;")).scalar()
        if total_usuarios == 0:
            admin_pass = st.secrets.get("admin", {}).get("initial_password")
            if not admin_pass or len(str(admin_pass)) < 8:
                # La excepción evita que se cachee un arranque incompleto
                raise RuntimeError(
                    "No hay usuarios en la BD y falta [admin] initial_password "
                    "(mínimo 8 caracteres) en los secretos de Streamlit."
                )
            conn.execute(
                text("INSERT INTO usuarios (username, password_hash, nombre, rol) VALUES (:u, :p, :n, :r);"),
                {"u": "admin", "p": hash_password(str(admin_pass)), "n": "Administrador Principal", "r": "admin"}
            )
    return True


try:
    inicializar_bd()
except Exception as e:
    logger.error(f"Error inicializando la base de datos: {e}")
    st.error(f"Error inicializando la base de datos: {e}")
    st.stop()


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


def login(usuario: str, password: str):
    try:
        with engine.begin() as conn:
            q_user = text("""
                SELECT username, password_hash, nombre, rol, intentos_fallidos, bloqueado_hasta, activo
                FROM usuarios
                WHERE username = :u;
            """)
            result = conn.execute(q_user, {"u": usuario}).fetchone()

            if not result:
                check_password(password, get_dummy_hash())
                return False, "❌ Usuario o contraseña incorrectos."

            username, pass_hash, nombre, rol, intentos, bloqueado_hasta, activo = result
            intentos = intentos or 0

            if activo is not None and not activo:
                check_password(password, get_dummy_hash())
                return False, "❌ Usuario o contraseña incorrectos."

            if bloqueado_hasta and ahora() < bloqueado_hasta:
                tiempo_restante = int((bloqueado_hasta - ahora()).total_seconds() / 60) + 1
                return False, f"🚫 Cuenta bloqueada por seguridad. Reintenta en {tiempo_restante} min."

            if check_password(password, pass_hash):
                conn.execute(
                    text("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE username = :u;"),
                    {"u": usuario}
                )
                st.session_state["sesion_valida"] = True
                st.session_state["username_actual"] = username
                st.session_state["usuario_actual"] = nombre
                st.session_state["rol_actual"] = rol
                return True, "¡Bienvenido al sistema!"

            nuevos_intentos = intentos + 1
            if nuevos_intentos >= MAX_INTENTOS:
                bloqueo = ahora() + timedelta(minutes=TIEMPO_BLOQUEO_MINUTOS)
                conn.execute(
                    text("UPDATE usuarios SET intentos_fallidos = :i, bloqueado_hasta = :b WHERE username = :u;"),
                    {"i": nuevos_intentos, "b": bloqueo, "u": usuario}
                )
                return False, f"🚫 Límite de {MAX_INTENTOS} intentos superado. Cuenta bloqueada por {TIEMPO_BLOQUEO_MINUTOS} minutos."

            conn.execute(
                text("UPDATE usuarios SET intentos_fallidos = :i WHERE username = :u;"),
                {"i": nuevos_intentos, "u": usuario}
            )
            intentos_restantes = MAX_INTENTOS - nuevos_intentos
            return False, f"❌ Usuario o contraseña incorrectos. Te quedan {intentos_restantes} intento(s)."

    except Exception as err:
        logger.error(f"Error de autenticación: {err}")
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
                            st.rerun()
                        else:
                            st.error(mensaje)

            st.markdown("<div class='footer-tag'>v2.1 • Neon PostgreSQL Active 🟢</div>", unsafe_allow_html=True)

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

mostrar_flash()


# ---------------------------------------------------------
# LÓGICA DE EVALUACIÓN (funciones puras, fáciles de probar)
# ---------------------------------------------------------
def calcular_desbalance(v1: float, v2: float, v3: float) -> float:
    promedio = (v1 + v2 + v3) / 3.0
    if promedio == 0:
        return 0.0
    max_desviacion = max(abs(v1 - promedio), abs(v2 - promedio), abs(v3 - promedio))
    return round((max_desviacion / promedio) * 100, 2)


def limite_critico_fc(fs) -> float:
    """Límite crítico de factor de carga: factor de servicio del motor, o 115% si no hay dato."""
    fs = _f(fs, 0.0)
    return round(fs * 100.0, 2) if fs > 0 else UMBRALES["fc_crit_default"]


def evaluar_estado_electrico(desb_v_ff, desb_v_fn, desb_i, v_n_tierra, factor_carga, fs=None):
    """Devuelve (estado, motivos). Se usa al insertar y al editar una inspección."""
    criticos, advertencias = [], []

    def revisar(valor, lim_adv, lim_crit, nombre, unidad):
        if valor is None or pd.isna(valor):
            return
        if valor > lim_crit:
            criticos.append(f"{nombre} {valor:.2f}{unidad}")
        elif valor > lim_adv:
            advertencias.append(f"{nombre} {valor:.2f}{unidad}")

    revisar(desb_v_ff, UMBRALES["desb_v_adv"], UMBRALES["desb_v_crit"], "Desbalance V (F-F)", "%")
    revisar(desb_v_fn, UMBRALES["desb_v_adv"], UMBRALES["desb_v_crit"], "Desbalance V (F-N)", "%")
    revisar(desb_i, UMBRALES["desb_i_adv"], UMBRALES["desb_i_crit"], "Desbalance I", "%")
    revisar(v_n_tierra, UMBRALES["v_nt_adv"], UMBRALES["v_nt_crit"], "V Neutro-Tierra", " V")
    revisar(factor_carga, UMBRALES["fc_adv"], limite_critico_fc(fs), "Factor de carga", "%")

    if criticos:
        return "Crítico", criticos + advertencias
    if advertencias:
        return "Advertencia", advertencias
    return "Normal", []


def evaluar_termografia(t1, t2, t3, es_motor: bool):
    """Devuelve (hot_spot, desbalance_max, delta_vs_media, estado).
    En el motor las 3 lecturas son puntos distintos (balero sup/inf, carcasa), así que
    solo se evalúa la temperatura absoluta. En el ITM se compara además la diferencia entre fases."""
    hot = max(t1, t2, t3)
    spread = hot - min(t1, t2, t3)
    delta_media = hot - ((t1 + t2 + t3) / 3.0)

    crit = hot >= UMBRALES["termo_hot_crit"]
    adv = hot >= UMBRALES["termo_hot_adv"]
    if not es_motor:
        crit = crit or spread >= UMBRALES["termo_spread_crit"]
        adv = adv or spread >= UMBRALES["termo_spread_adv"]

    estado = "CRITICO" if crit else ("ADVERTENCIA" if adv else "NORMAL")
    return hot, spread, delta_media, estado


def diagnostico_aislamiento(r40, r_1min, pi_val):
    """Diagnóstico con R40 y Índice de Polarización (IEEE Std 43)."""
    pi_aplica = pi_val is not None and r_1min < UMBRALES["aisl_pi_ignorar_si_r1min_mayor"]
    if r40 < UMBRALES["aisl_r40_crit"] or (pi_aplica and pi_val < UMBRALES["aisl_pi_crit"]):
        return "CRÍTICO"
    if r40 < UMBRALES["aisl_r40_alerta"] or (pi_aplica and pi_val < UMBRALES["aisl_pi_min"]):
        return "ALERTA"
    if r40 < UMBRALES["aisl_r40_excelente"]:
        return "ACEPTABLE"
    return "EXCELENTE"


def clasificar_equipo(row, ids_criticos: set, ids_con_evento: set) -> str:
    """Semáforo de un equipo. El estatus del catálogo es manual; las alertas se derivan de los eventos abiertos."""
    est_cat = str(row.get("estatus", "") or "").lower().strip()
    serial = _s(row.get("no_serie")).strip()
    codigo = _s(row.get("codigo_equipo")).strip()

    if "fuera" in est_cat or "baja" in est_cat or "paro" in est_cat:
        return "fuera"
    if "standby" in est_cat or "reserva" in est_cat:
        return "standby"
    # Los eventos pertenecen al motor (S/N), nunca a la posición donde esté instalado
    if serial and serial in ids_criticos:
        return "critico"
    if serial and serial in ids_con_evento:
        return "alerta"
    if "mantenimiento" in est_cat:
        return "mantenimiento"
    return "ok"


# ---------------------------------------------------------
# CONSULTAS
# ---------------------------------------------------------
@st.cache_data(ttl=300)
def obtener_datos():
    """Inspecciones eléctricas cruzadas con el catálogo SOLO por número de serie (llave única)."""
    query = """
    SELECT
        i.*,
        c.corriente_nom AS corriente_nominal_cat,
        c.voltaje_nom AS voltaje_nominal_cat,
        c.factor_servicio AS fs_cat,
        COALESCE(c.codigo_equipo, i.equipo) AS posicion_actual,
        COALESCE(c.ubicacion, 'N/A') AS area_actual
    FROM inspecciones_bombas i
    LEFT JOIN catalogo_equipos c ON TRIM(i.equipo) = TRIM(c.no_serie)
    ORDER BY i.fecha DESC, i.id DESC;
    """
    df = pd.read_sql_query(query, engine)

    if not df.empty:
        df["equipo"] = df["equipo"].astype(str).str.strip()
        df["i_promedio"] = (df["i_a"] + df["i_b"] + df["i_c"]) / 3.0
        df["v_promedio"] = (df["v_ab"] + df["v_bc"] + df["v_ca"]) / 3.0

        # Sin FLA en el catálogo => factor de carga vacío (no se inventa un valor)
        fla = pd.to_numeric(df["corriente_nominal_cat"], errors="coerce")
        fla = fla.where(fla > 0)
        df["factor_carga"] = ((df["i_promedio"] / fla) * 100).round(2)

        i_matrix = df[["i_a", "i_b", "i_c"]].values
        i_prom = df["i_promedio"].values
        i_prom_safe = np.where(i_prom == 0, np.nan, i_prom)
        max_dev_i = np.max(np.abs(i_matrix - i_prom[:, np.newaxis]), axis=1)
        df["desbalance_i"] = np.nan_to_num((max_dev_i / i_prom_safe) * 100).round(2)
        df["potencia_kw"] = ((np.sqrt(3) * df["v_promedio"] * df["i_promedio"] * 0.85 * 0.90) / 1000.0).round(2)

    return df


@st.cache_data(ttl=300)
def obtener_termografias():
    try:
        query = text("SELECT * FROM inspecciones_termograficas ORDER BY fecha_inspeccion DESC, id DESC;")
        with engine.connect() as conn:
            return pd.read_sql(query, conn)
    except Exception as e:
        st.warning(f"No se pudieron cargar inspecciones termográficas: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=300)
def obtener_eventos():
    query = "SELECT * FROM registro_eventos ORDER BY fecha_hora DESC, id DESC;"
    return pd.read_sql_query(query, engine)


@st.cache_data(ttl=60)
def obtener_eventos_activos():
    query = text("SELECT equipo, severidad, tipo_evento FROM registro_eventos WHERE estatus IN ('Abierto', 'En Revisión');")
    with engine.connect() as conn:
        return pd.read_sql(query, conn)


@st.cache_data(ttl=300)
def obtener_equipos():
    query = "SELECT * FROM catalogo_equipos ORDER BY codigo_equipo ASC;"
    df = pd.read_sql_query(query, engine)
    if not df.empty:
        # Un motor sin S/N queda con texto vacío (nunca "None"/"nan")
        df["no_serie"] = df["no_serie"].fillna("").astype(str).str.strip()
    return df


def obtener_pruebas_aislamiento():
    try:
        query = text("SELECT * FROM pruebas_aislamiento ORDER BY fecha_hora DESC;")
        with engine.connect() as conn:
            return pd.read_sql_query(query, conn)
    except Exception as e:
        st.error(f"Error al cargar historial de aislamiento: {e}")
        return pd.DataFrame()


def params_equipo(df_cat, no_serie):
    """Devuelve (FLA, factor de servicio, voltaje nominal) del catálogo; None si no hay dato."""
    if df_cat is None or df_cat.empty or not no_serie:
        return None, None, None
    fila = df_cat[df_cat["no_serie"].astype(str).str.strip() == str(no_serie).strip()]
    if fila.empty:
        return None, None, None
    r = fila.iloc[0]

    def _pos(v):
        v = _f(v, 0.0)
        return v if v > 0 else None

    return _pos(r.get("corriente_nom")), _pos(r.get("factor_servicio")), _pos(r.get("voltaje_nom"))


def contar_historial(conn, no_serie: str) -> int:
    """Cuenta registros históricos ligados a un número de serie."""
    total = 0
    consultas = [
        "SELECT COUNT(*) FROM inspecciones_bombas WHERE TRIM(equipo) = TRIM(:s)",
        "SELECT COUNT(*) FROM registro_eventos WHERE TRIM(equipo) = TRIM(:s)",
        "SELECT COUNT(*) FROM inspecciones_termograficas WHERE TRIM(equipo_id) = TRIM(:s)",
        "SELECT COUNT(*) FROM pruebas_aislamiento WHERE TRIM(equipo) = TRIM(:s)",
    ]
    for q in consultas:
        total += conn.execute(text(q), {"s": no_serie}).scalar() or 0
    return int(total)


@st.cache_data(ttl=300)
def obtener_movimientos():
    """Bitácora de altas, reubicaciones, reemplazos y bajas (ordenada de la más antigua a la más reciente)."""
    try:
        with engine.connect() as conn:
            return pd.read_sql(text("SELECT * FROM movimientos_equipo ORDER BY fecha_hora ASC, id ASC;"), conn)
    except Exception as e:
        logger.warning(f"No se pudieron cargar los movimientos: {e}")
        return pd.DataFrame()


def registrar_movimiento(conn, no_serie, tipo, pos_ant, pos_nueva, ubic_ant, ubic_nueva, motivo="", fecha_hora=None):
    """Registra un movimiento del motor (se llama dentro de la misma transacción que el cambio)."""
    conn.execute(
        text("""
            INSERT INTO movimientos_equipo
            (fecha_hora, no_serie, tipo_movimiento, posicion_anterior, posicion_nueva, ubicacion_anterior, ubicacion_nueva, motivo, realizado_por)
            VALUES (:fh, :sn, :tipo, :pa, :pn, :ua, :un, :mot, :rep);
        """),
        {
            "fh": fecha_hora or ahora(), "sn": str(no_serie).strip(), "tipo": tipo,
            "pa": pos_ant or None, "pn": pos_nueva or None,
            "ua": ubic_ant or None, "un": ubic_nueva or None,
            "mot": motivo or None, "rep": st.session_state.get("usuario_actual", "Sistema"),
        }
    )


def posicion_en_fecha(df_mov, no_serie, fecha, actual, fin_de_dia=False):
    """Posición (nombre) que tenía el motor en una fecha, según la bitácora de movimientos.
    Si el motor no tiene movimientos registrados, devuelve la posición actual."""
    if df_mov is None or df_mov.empty:
        return actual
    movs = df_mov[df_mov["no_serie"].astype(str).str.strip() == str(no_serie).strip()]
    if movs.empty:
        return actual
    fecha = pd.to_datetime(fecha)
    if fin_de_dia:
        fecha = fecha + timedelta(days=1) - timedelta(seconds=1)
    previos = movs[pd.to_datetime(movs["fecha_hora"]) <= fecha]
    previos = previos[previos["posicion_nueva"].notna()]
    if not previos.empty:
        return str(previos.iloc[-1]["posicion_nueva"])
    anterior = movs.iloc[0]["posicion_anterior"]
    return str(anterior) if pd.notna(anterior) and str(anterior).strip() else actual


# ---------------------------------------------------------
# FUNCIONES AUXILIARES DE UI
# ---------------------------------------------------------
def equipos_seleccionables(df_cat: pd.DataFrame) -> pd.DataFrame:
    """Equipos que se pueden medir/inspeccionar (todos menos los dados de baja)."""
    if df_cat.empty or "estatus" not in df_cat.columns:
        return df_cat.copy()
    df_ok = df_cat[~df_cat["estatus"].fillna("").str.lower().str.contains("baja")]
    # La trazabilidad es por S/N: un motor sin S/N no se puede inspeccionar hasta asignárselo
    df_ok = df_ok[df_ok["no_serie"].fillna("").astype(str).str.strip() != ""]
    return df_ok.copy()


def selector_equipo_por_serie(df_equipos_cat, key_widget="sel_eq_general"):
    """Crea una etiqueta limpia (Posición + S/N) pero retorna el número de serie único."""
    if df_equipos_cat.empty:
        return None, None

    df_copy = df_equipos_cat.copy()
    df_copy["label_display"] = (
        df_copy["codigo_equipo"].astype(str).str.strip() +
        " — [S/N: " + df_copy["no_serie"].astype(str).str.strip() +
        "] (" + df_copy["ubicacion"].fillna("N/A").astype(str).str.strip() + ")"
    )

    opciones = df_copy["label_display"].tolist()
    seleccion = st.selectbox("Seleccionar Equipo / Motor *", opciones, key=key_widget)

    row_sel = df_copy[df_copy["label_display"] == seleccion].iloc[0]
    return str(row_sel["no_serie"]).strip(), str(row_sel["codigo_equipo"]).strip()


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

    def celda(valor):
        return Paragraph(esc_xml(_s(valor)), cell_style)

    fecha_hoy = ahora().strftime("%d/%m/%Y %H:%M")
    # Sin emojis: la fuente Helvetica del PDF no los dibuja
    story.append(Paragraph("CATÁLOGO GENERAL DE EQUIPOS E INSTALACIONES ELÉCTRICAS", title_style))
    story.append(Paragraph(f"Fecha de reporte: {fecha_hoy} | Total de activos: {len(df_equipos)}", subtitle_style))

    headers = [Paragraph(h, cell_header) for h in
               ["Código", "S/N (Serie)", "Ubicación", "Marca / Modelo", "Frame", "HP", "FLA (A)", "Breaker", "Cable / Mat.", "Estatus"]]
    table_data = [headers]

    for _, row in df_equipos.iterrows():
        hilos = int(_f(row.get('conductores_por_fase'), 1) or 1)
        cal = _s(row.get('calibre_cable')).strip() or '-'
        mat = _s(row.get('material_conductor')).replace("Cobre (Cu)", "Cu").replace("Aluminio (Al)", "Al")
        cable_fmt = f"{hilos}x {cal} ({mat})" if cal != '-' else '-'

        table_data.append([
            celda(row.get('codigo_equipo')),
            celda(row.get('no_serie')),
            celda(_s(row.get('ubicacion')) or 'N/A'),
            celda(_s(row.get('marca_modelo')) or 'N/A'),
            celda(_s(row.get('frame')) or '-'),
            celda(f"{_f(row.get('potencia_hp')):g}"),
            celda(f"{_f(row.get('corriente_nom')):g} A"),
            celda(f"{_f(row.get('breaker_amp')):g} A"),
            celda(cable_fmt),
            celda(_s(row.get('estatus')) or 'Operativo'),
        ])

    col_widths = [60, 80, 100, 95, 45, 35, 45, 45, 90, 60]
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))

    story.append(t)
    doc.build(story)
    buffer.seek(0)
    return buffer


def aplicar_filtros_tabla(df: pd.DataFrame, col_fecha: str = "fecha", key_suffix: str = "default") -> pd.DataFrame:
    if df.empty:
        return df

    df = df.copy()  # evita SettingWithCopyWarning y no altera el DataFrame original
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

    if col_fecha in df.columns and not df.empty:
        df[col_fecha] = pd.to_datetime(df[col_fecha])
        if df[col_fecha].notna().any():
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


def formatear_df_porcentajes(df):
    df_fmt = df.copy()
    for col in ["desbalance_v_ff", "desbalance_v_fn", "desbalance_i"]:
        if col in df_fmt.columns:
            df_fmt[col] = df_fmt[col].map(lambda x: f"{x:.2f}%" if pd.notnull(x) else "")
    if "factor_carga" in df_fmt.columns:
        df_fmt["factor_carga"] = df_fmt["factor_carga"].map(lambda x: f"{x:.1f}%" if pd.notnull(x) else "Sin FLA")
    if "potencia_kw" in df_fmt.columns:
        df_fmt["potencia_kw"] = df_fmt["potencia_kw"].map(lambda x: f"{x:.2f} kW" if pd.notnull(x) else "")

    df_fmt = df_fmt.rename(columns={
        "equipo": "S/N Motor",
        "posicion_actual": "Posición Actual",
        "posicion_en_fecha": "Posición a la fecha",
        "desbalance_v_ff": "Desbal. V_FF (%)",
        "desbalance_v_fn": "Desbal. V_FN (%)",
        "desbalance_i": "Desbal. I (%)",
        "factor_carga": "Factor Carga (%)",
        "potencia_kw": "Potencia Est. (kW)",
        "v_n_tierra": "V Neutro-Tierra (V)"
    })
    return df_fmt


# =========================================================
# 1. DASHBOARD & KPIS
# =========================================================
if opcion == "Dashboard & KPIs":
    st.title("🌊 Monitoreo Eléctrico & KPIs de Confiabilidad")
    st.caption(
        "Desbalance de voltaje según NEMA MG 1 · Aislamiento según IEEE Std 43 · "
        "Los límites de corriente y temperatura son criterios de planta (ajustables en UMBRALES)."
    )

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
            fecha_inicio = st.date_input("Fecha Inicio", hoy() - timedelta(days=90))
        with col_f2:
            fecha_fin = st.date_input("Fecha Fin", hoy())
        with col_f3:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🔄 Actualizar Datos", use_container_width=True):
                limpiar_cache()
                st.rerun()

    if fecha_inicio > fecha_fin:
        st.error("La fecha de inicio no puede ser posterior a la fecha fin.")
        st.stop()

    try:
        df_equipos_todos = obtener_equipos()
        df_ev_activos = obtener_eventos_activos()
    except Exception as e:
        st.error(f"Error al cargar datos del Dashboard: {e}")
        df_equipos_todos, df_ev_activos = pd.DataFrame(), pd.DataFrame()

    # Los motores dados de baja conservan su historial pero ya no cuentan como activos instalados
    if df_equipos_todos.empty:
        df_equipos = df_equipos_todos
    else:
        df_equipos = df_equipos_todos[~df_equipos_todos["estatus"].fillna("").str.lower().str.contains("baja")].copy()

    # ---------------------------------------------------------
    # KPIS Y SEMÁFORO (el estado se DERIVA de los eventos abiertos)
    # ---------------------------------------------------------
    if df_ev_activos.empty:
        ids_criticos, ids_con_evento = set(), set()
    else:
        ids_con_evento = set(df_ev_activos["equipo"].astype(str).str.strip())
        ids_criticos = set(
            df_ev_activos.loc[df_ev_activos["severidad"].isin(["Alta", "Crítica"]), "equipo"].astype(str).str.strip()
        )

    conteo = {"fuera": 0, "standby": 0, "critico": 0, "alerta": 0, "mantenimiento": 0, "ok": 0}
    clasificacion = {}
    if not df_equipos.empty:
        for _, row in df_equipos.iterrows():
            cat = clasificar_equipo(row, ids_criticos, ids_con_evento)
            clasificacion[str(row["no_serie"]).strip()] = cat
            conteo[cat] += 1

    if ids_con_evento:
        seriales_cat = set(df_equipos_todos["no_serie"].astype(str).str.strip()) if not df_equipos_todos.empty else set()
        huerfanos = sorted(ids_con_evento - seriales_cat)
        if huerfanos:
            st.warning(
                "Hay eventos abiertos ligados a un identificador que no es un S/N del catálogo "
                f"({', '.join(huerfanos)}). No se asignan a ningún motor; edítalos en Registro de Eventos."
            )

    total_equipos = len(df_equipos)
    alertas_criticas = conteo["critico"]
    alertas_advertencia = conteo["alerta"]
    equipos_fuera = conteo["fuera"]
    equipos_standby = conteo["standby"]
    total_alertas_activas = alertas_criticas + alertas_advertencia

    if total_equipos > 0:
        penalizacion = ((alertas_criticas * 20) + (alertas_advertencia * 8) + (equipos_fuera * 15)) / total_equipos
        salud_global = max(0, min(100, int(100 - penalizacion)))
    else:
        salud_global = 100

    if salud_global >= 85:
        salud_clase, salud_txt = "status-ok", "🟢 Óptimo"
    elif salud_global >= 60:
        salud_clase, salud_txt = "status-warning", "🟡 Atención"
    else:
        salud_clase, salud_txt = "status-danger", "🔴 Crítico"

    st.markdown("<br>", unsafe_allow_html=True)
    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    with kpi1:
        st.markdown(f"<div class='kpi-card'><div class='kpi-title'>Salud Global</div><div class='kpi-value'>{salud_global}%</div><span class='kpi-status {salud_clase}'>{salud_txt}</span></div>", unsafe_allow_html=True)
    with kpi2:
        st.markdown(f"<div class='kpi-card'><div class='kpi-title'>Total Activos</div><div class='kpi-value'>{total_equipos}</div><span class='kpi-status status-ok'>⚙️ Registrados</span></div>", unsafe_allow_html=True)
    with kpi3:
        st.markdown(f"<div class='kpi-card'><div class='kpi-title'>Standby</div><div class='kpi-value' style='color:#0284c7;'>{equipos_standby}</div><span class='kpi-status status-info'>⏸️ Reserva</span></div>", unsafe_allow_html=True)
    with kpi4:
        st.markdown(f"<div class='kpi-card'><div class='kpi-title'>Fuera de Servicio</div><div class='kpi-value' style='color:#ef4444;'>{equipos_fuera}</div><span class='kpi-status status-danger'>🔴 Inactivos</span></div>", unsafe_allow_html=True)
    with kpi5:
        st.markdown(f"<div class='kpi-card'><div class='kpi-title'>Alertas Activas</div><div class='kpi-value' style='color:#eab308;'>{total_alertas_activas}</div><span class='kpi-status status-warning'>⚠️ {alertas_criticas} crítica(s)</span></div>", unsafe_allow_html=True)

    st.markdown("<br><br>", unsafe_allow_html=True)

    tab_fleet, tab_radar, tab_scatter = st.tabs(["🎛️ Estado de Equipos (Semáforo)", "📐 Diagrama Fasorial", "📈 Factor de Carga vs. Salud"])

    # --- Semáforo por área ---
    with tab_fleet:
        st.subheader("Estado de Salud por Área y Posición Operativa")
        if df_equipos.empty:
            st.info("No hay equipos registrados en el catálogo.")
        else:
            df_eq_view = df_equipos.copy()
            df_eq_view["ubicacion"] = df_eq_view["ubicacion"].fillna("Sin Ubicación").astype(str).str.strip()

            estilos = {
                "fuera": ("eq-border-danger", None),
                "standby": ("eq-border-standby", "⏸️ Standby"),
                "critico": ("eq-border-danger", "🚨 Alerta crítica (evento abierto)"),
                "alerta": ("eq-border-warning", "⚠️ Evento abierto"),
                "mantenimiento": ("eq-border-warning", "🛠️ En Mantenimiento"),
                "ok": ("eq-border-ok", None),
            }

            for ub in sorted(df_eq_view["ubicacion"].unique()):
                df_grupo = df_eq_view[df_eq_view["ubicacion"] == ub]
                with st.expander(f"📍 Área: {ub} ({len(df_grupo)} activos)", expanded=True):
                    cols_grid = st.columns(3)
                    for idx, row in df_grupo.reset_index(drop=True).iterrows():
                        serial = str(row["no_serie"]).strip()
                        codigo = str(row["codigo_equipo"]).strip()
                        cat = clasificacion.get(serial, "ok")
                        st_color, badge_txt = estilos[cat]
                        if badge_txt is None:
                            icono = "🔴" if cat == "fuera" else "🟢"
                            badge_txt = f"{icono} {_s(row.get('estatus')) or 'Operativo'}"

                        with cols_grid[idx % 3]:
                            st.markdown(f"""
                                <div class='equipment-card {st_color}'>
                                    <strong style='font-size: 1.1rem; color: #1e293b;'>{esc_html(codigo)}</strong>
                                    <span style='font-size: 0.8rem; color: #64748b;'>(S/N: {esc_html(serial)})</span><br>
                                    <span style='font-size: 0.85rem; color: #475569;'>{esc_html(_s(row.get('marca_modelo')) or 'N/A')} | {_f(row.get('potencia_hp')):g} HP</span><br>
                                    <div style='margin-top: 8px;'>
                                        <span class='kpi-status' style='background: #f1f5f9; color: #334155;'>FLA: {_f(row.get('corriente_nom')):g} A</span>
                                        <span style='float: right; font-size:0.8rem; font-weight:bold;'>{esc_html(badge_txt)}</span>
                                    </div>
                                </div>
                            """, unsafe_allow_html=True)

    # --- Datos de inspección dentro del rango de fechas seleccionado ---
    df_insp_all = obtener_datos()
    if df_insp_all.empty:
        df_rango = df_insp_all
    else:
        df_rango = df_insp_all.copy()
        df_rango["fecha_dt"] = pd.to_datetime(df_rango["fecha"])
        df_rango = df_rango[(df_rango["fecha_dt"].dt.date >= fecha_inicio) & (df_rango["fecha_dt"].dt.date <= fecha_fin)]

    def ultimo_por_equipo(df_in: pd.DataFrame) -> pd.DataFrame:
        """Última lectura de cada equipo (fila completa, no mezcla columnas de distintos días)."""
        return df_in.sort_values(["fecha_dt", "id"]).drop_duplicates("equipo", keep="last").reset_index(drop=True)

    with tab_radar:
        st.subheader("📐 Diagrama Fasorial Trifásico")
        if df_rango.empty:
            st.info("No hay registros de inspección en el rango de fechas seleccionado.")
        else:
            df_reciente = ultimo_por_equipo(df_rango)
            col_eq, col_tipo = st.columns([2, 1])
            with col_eq:
                equipo_sel = st.selectbox("Selecciona S/N Motor:", df_reciente["equipo"].tolist(), key="select_fasorial")
            with col_tipo:
                tipo_param = st.radio("Parámetro:", ["Corriente (A)", "Voltaje (V)"], horizontal=True, key="radio_fasorial")

            datos_eq = df_reciente[df_reciente["equipo"] == equipo_sel].iloc[0]
            if tipo_param == "Corriente (A)":
                magnitudes = [_f(datos_eq.get("i_a")), _f(datos_eq.get("i_b")), _f(datos_eq.get("i_c"))]
                unidad = "A"
            else:
                magnitudes = [_f(datos_eq.get("v_ab")), _f(datos_eq.get("v_bc")), _f(datos_eq.get("v_ca"))]
                unidad = "V"

            st.caption(f"Última lectura: {pd.to_datetime(datos_eq['fecha']).strftime('%d/%m/%Y')}")
            fig_vector = go.Figure()
            for ang, mag, fase, color in zip([0, 120, 240], magnitudes, ["Fase A", "Fase B", "Fase C"], ["#e74c3c", "#f1c40f", "#3498db"]):
                fig_vector.add_trace(go.Scatterpolar(r=[0, mag], theta=[ang, ang], mode="lines+markers", name=f"{fase}: {mag:.1f} {unidad}", line=dict(color=color, width=4)))

            fig_vector.update_layout(polar=dict(radialaxis=dict(visible=True), angularaxis=dict(tickvals=[0, 120, 240], ticktext=["0° (L1)", "120° (L2)", "240° (L3)"])), height=400)
            st.plotly_chart(fig_vector, use_container_width=True)

    with tab_scatter:
        st.subheader("📈 Análisis de Parámetros Operativos")
        st.caption(
            "Factor de carga: crítico por encima del factor de servicio de cada motor (115% si no está capturado). "
            "Desbalance de corriente: 5% / 10% son criterios de planta; NEMA MG 1 define límites para desbalance de voltaje."
        )
        if df_rango.empty:
            st.info("No hay registros de inspección en el rango de fechas seleccionado.")
        else:
            df_graf = ultimo_por_equipo(df_rango)

            def clasif_desbalance(val):
                if val > UMBRALES["desb_i_crit"]:
                    return "Crítico (>10%)"
                if val > UMBRALES["desb_i_adv"]:
                    return "Advertencia (5-10%)"
                return "Normal (<5%)"

            def clasif_fc(row):
                fc = row["factor_carga"]
                if pd.isna(fc):
                    return "Sin FLA"
                crit = limite_critico_fc(row.get("fs_cat"))
                if fc > crit:
                    return "Sobrecarga Crítica (> F.S.)"
                if fc > UMBRALES["fc_adv"]:
                    return "Sobrecarga Leve (100% a F.S.)"
                if fc >= 70.0:
                    return "Óptimo (70-100%)"
                return "Subcarga (<70%)"

            df_graf["semaforo_desbal"] = df_graf["desbalance_i"].apply(clasif_desbalance)
            df_graf["semaforo_fc"] = df_graf.apply(clasif_fc, axis=1)

            color_map_db = {"Normal (<5%)": "#22c55e", "Advertencia (5-10%)": "#eab308", "Crítico (>10%)": "#ef4444"}
            color_map_fc = {
                "Subcarga (<70%)": "#0284c7",
                "Óptimo (70-100%)": "#22c55e",
                "Sobrecarga Leve (100% a F.S.)": "#eab308",
                "Sobrecarga Crítica (> F.S.)": "#ef4444",
            }

            sin_fla = df_graf[df_graf["factor_carga"].isna()]["equipo"].tolist()
            if sin_fla:
                st.warning(f"Sin FLA en el catálogo (no se calcula factor de carga): {', '.join(sin_fla)}")

            c_g1, c_g2 = st.columns(2)
            with c_g1:
                df_fc = df_graf.dropna(subset=["factor_carga"])
                if df_fc.empty:
                    st.info("Ningún equipo con inspección tiene FLA registrado.")
                else:
                    fig_fc = px.bar(
                        df_fc, x="equipo", y="factor_carga", color="semaforo_fc",
                        color_discrete_map=color_map_fc,
                        title="Factor de Carga (%) vs. Factor de Servicio"
                    )
                    fig_fc.add_hline(y=100, line_dash="dash", line_color="#eab308", annotation_text="Nominal (100%)")
                    st.plotly_chart(fig_fc, use_container_width=True)

            with c_g2:
                fig_db = px.bar(
                    df_graf, x="equipo", y="desbalance_i", color="semaforo_desbal",
                    color_discrete_map=color_map_db,
                    title="Desbalance de Corriente (%)"
                )
                fig_db.add_hline(y=UMBRALES["desb_i_adv"], line_dash="dash", line_color="#eab308", annotation_text="Alerta (5%)")
                fig_db.add_hline(y=UMBRALES["desb_i_crit"], line_dash="dash", line_color="#ef4444", annotation_text="Crítico (10%)")
                st.plotly_chart(fig_db, use_container_width=True)


# =========================================================
# 2. CATÁLOGO DE EQUIPOS
# =========================================================
elif opcion == "Catálogo de Equipos":
    st.title("🏷️ Catálogo General de Activos e Instalación Eléctrica")

    tab1, tab2, tab3, tab4 = st.tabs([
        "📋 Lista de Equipos Registrados",
        "➕ Registrar Nuevo Motor / Bomba",
        "🛠️ Modificar / Reubicar Activo",
        "🔄 Reemplazar Motor"
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
                # El PDF solo se genera cuando se pide (no en cada recarga)
                if st.button("📄 Generar PDF Catálogo", use_container_width=True):
                    st.session_state["pdf_catalogo"] = generar_pdf_catalogo_general(df_eq).getvalue()
                if st.session_state.get("pdf_catalogo"):
                    st.download_button(
                        "⬇️ Descargar PDF", data=st.session_state["pdf_catalogo"],
                        file_name=f"catalogo_{ahora().strftime('%Y%m%d')}.pdf",
                        mime="application/pdf", use_container_width=True
                    )

            sin_serie = df_eq[df_eq["no_serie"] == ""]["codigo_equipo"].astype(str).tolist()
            if sin_serie:
                st.warning(
                    f"{len(sin_serie)} motor(es) sin S/N: {', '.join(sin_serie)}. "
                    "No se pueden inspeccionar ni llevar historial hasta asignarles su S/N "
                    "(pestaña «Modificar / Reubicar Activo»)."
                )

            df_eq["ubicacion"] = df_eq["ubicacion"].fillna("Sin Ubicación").astype(str).str.strip()
            for ub in sorted(df_eq["ubicacion"].unique()):
                df_grupo = df_eq[df_eq["ubicacion"] == ub]
                with st.expander(f"📍 Área: {ub} ({len(df_grupo)} activos registrados)", expanded=True):
                    st.dataframe(df_grupo, use_container_width=True)

    with tab2:
        st.subheader("Alta de Equipo por Número de Serie")
        with st.form(form_key("form_nuevo_equipo"), clear_on_submit=False):
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
                estatus_e = st.selectbox("Estatus Operativo Inicial", ESTATUS_CATALOGO[:4])

            with c_e2:
                pot_hp = st.number_input("Potencia (HP)", value=175.0, step=5.0)
                v_nom = st.number_input("Voltaje Nominal (V)", value=440.0, step=10.0)
                i_nom = st.number_input("Corriente Nominal / FLA (A) *", value=None, step=1.0)
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
                reset_form("form_nuevo_equipo")
                st.rerun()

            if btn_guardar_eq:
                if not no_serie.strip() or not cod_eq.strip():
                    st.error("El Número de Serie y la Posición Operativa son obligatorios.")
                elif i_nom is None or i_nom <= 0:
                    st.error("La Corriente Nominal (FLA) es obligatoria y debe ser mayor a 0.")
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
                            existe = conn.execute(
                                text("SELECT COUNT(*) FROM catalogo_equipos WHERE UPPER(TRIM(no_serie)) = UPPER(TRIM(:ns));"),
                                {"ns": no_serie.strip()}
                            ).scalar()
                            if existe:
                                st.error(f"❌ Ya existe un equipo con S/N {no_serie.strip()}.")
                                st.stop()
                            pos_existe = conn.execute(
                                text("SELECT COUNT(*) FROM catalogo_equipos WHERE UPPER(TRIM(codigo_equipo)) = UPPER(TRIM(:c));"),
                                {"c": cod_eq.strip()}
                            ).scalar()
                            if pos_existe:
                                st.error(f"❌ La posición «{cod_eq.strip()}» ya la tiene otro equipo. "
                                         "Si es un cambio de motor, usa la pestaña «Reemplazar Motor».")
                                st.stop()
                            conn.execute(q_ins_eq, {
                                "cod": cod_eq.strip(), "ub": ubic.strip(), "mm": marca_m.strip(), "ns": no_serie.strip(),
                                "fr": frame_m.strip(), "bsup": balero_sup.strip(), "binf": balero_inf.strip(),
                                "php": pot_hp, "vnom": v_nom, "inom": i_nom, "rpm": rpm_e, "fs": fs_e,
                                "est": estatus_e, "brk": breaker_a, "ovl": sobrecarga_a, "cal": calibre_c.strip(),
                                "mat": material_c, "hilos": hilos_fase, "dist": dist_m, "obs": obs_eq
                            })
                            registrar_movimiento(conn, no_serie.strip(), "Alta", None, cod_eq.strip(), None, ubic.strip(), "Alta en el catálogo")
                        limpiar_cache()
                        reset_form("form_nuevo_equipo")
                        flash(f"✅ Motor con S/N **{no_serie.strip()}** guardado correctamente.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error al guardar en base de datos: {e}")

    with tab3:
        df_eq = obtener_equipos()
        if df_eq.empty:
            st.info("No hay activos registrados para editar.")
        else:
            st.subheader("🛠️ Gestor de Activos y Reubicaciones (Por Número de Serie)")

            sn_etiqueta = df_eq["no_serie"].replace("", "⚠️ SIN S/N")
            df_eq["label_gestor"] = "S/N: " + sn_etiqueta + " | Posición Actual: " + df_eq["codigo_equipo"].astype(str).str.strip()
            label_sel = st.selectbox("Selecciona el Activo:", df_eq["label_gestor"].tolist(), key="sel_gestor_sn")

            eq_reg = df_eq[df_eq["label_gestor"] == label_sel].iloc[0]
            target_sn = _s(eq_reg["no_serie"]).strip()
            target_id = int(eq_reg["id"])
            sin_sn = target_sn == ""
            pos_prev = _s(eq_reg.get("codigo_equipo")).strip()

            c_edit, c_del = st.columns(2)

            with c_edit:
                with st.expander("✏️ Editar Ficha o Cambiar de Posición (Reubicar)", expanded=True):
                    with st.form(f"form_edit_sn_{target_id}"):
                        if sin_sn:
                            nuevo_sn_asignado = st.text_input("Número de Serie (S/N) del motor", value="",
                                                              placeholder="Captura el S/N de la placa para activar su trazabilidad")
                            ligar_historial = st.checkbox(
                                f"Ligar a este motor el historial antiguo capturado con el nombre «{pos_prev}»",
                                value=True,
                                help="Las lecturas, eventos, termografías y pruebas guardadas con el nombre de la posición pasan a este S/N."
                            )
                            st.caption("Este motor no tiene S/N. Asígnaselo una sola vez: después ya no se puede cambiar.")
                        else:
                            nuevo_sn_asignado, ligar_historial = "", False
                            st.text_input("Número de Serie (S/N) — identidad del motor", value=target_sn, disabled=True)
                            st.caption("El S/N identifica al motor y su historial le pertenece: no se puede editar ni se mueve a otro motor. Para reubicarlo cambia solo la Posición Operativa.")

                        edit_pos = st.text_input("Posición Operativa / Código (ej. M-29)", value=_s(eq_reg.get("codigo_equipo")))
                        edit_ubic = st.text_input("Ubicación en Planta", value=_s(eq_reg.get("ubicacion")))
                        edit_marca = st.text_input("Marca / Modelo", value=_s(eq_reg.get("marca_modelo")))
                        edit_frame = st.text_input("Armazón / Frame", value=_s(eq_reg.get("frame")))
                        edit_bsup = st.text_input("Balero Superior", value=_s(eq_reg.get("balero_superior")))
                        edit_binf = st.text_input("Balero Inferior", value=_s(eq_reg.get("balero_inferior")))

                        val_est = _s(eq_reg.get("estatus")) or "Operativo"
                        idx_est = ESTATUS_CATALOGO.index(val_est) if val_est in ESTATUS_CATALOGO else 0
                        edit_estatus = st.selectbox("Estatus Operativo", ESTATUS_CATALOGO, index=idx_est)

                        c_eq1, c_eq2 = st.columns(2)
                        edit_pot = c_eq1.number_input("Potencia (HP)", value=_f(eq_reg.get("potencia_hp")))
                        edit_vnom = c_eq2.number_input("Voltaje (V)", value=_f(eq_reg.get("voltaje_nom")))

                        c_eq3, c_eq4 = st.columns(2)
                        edit_inom = c_eq3.number_input("Corriente Nominal (A)", value=_f(eq_reg.get("corriente_nom")))
                        edit_rpm = c_eq4.number_input("RPM", value=int(_f(eq_reg.get("rpm"))))

                        c_eq5, c_eq6, c_eq7 = st.columns(3)
                        edit_fs = c_eq5.number_input("Factor de Servicio", value=_f(eq_reg.get("factor_servicio")), step=0.05)
                        edit_brk = c_eq6.number_input("ITM Principal (A)", value=_f(eq_reg.get("breaker_amp")))
                        edit_ovl = c_eq7.number_input("Ajuste Protección (A)", value=_f(eq_reg.get("overload_setting")))

                        edit_obs = st.text_area("Observaciones Adicionales / Historial de Movimiento", value=_s(eq_reg.get("observaciones")))
                        motivo_mov = st.text_input("Motivo de la reubicación (si cambias posición o ubicación)")

                        c_btn1, c_btn2 = st.columns(2)
                        btn_upd = c_btn1.form_submit_button("💾 Guardar Cambios", use_container_width=True)
                        btn_can = c_btn2.form_submit_button("❌ Cancelar", type="secondary", use_container_width=True)

                        if btn_can:
                            st.rerun()

                        if btn_upd:
                            error_edit = None
                            sn_final = target_sn
                            asignando_sn = sin_sn and nuevo_sn_asignado.strip() != ""
                            if asignando_sn:
                                sn_final = nuevo_sn_asignado.strip()

                            if not edit_pos.strip():
                                error_edit = "La Posición Operativa es obligatoria."
                            else:
                                try:
                                    with engine.connect() as conn:
                                        if edit_pos.strip() != pos_prev:
                                            pos_ocupada = conn.execute(
                                                text("SELECT COUNT(*) FROM catalogo_equipos WHERE UPPER(TRIM(codigo_equipo)) = UPPER(TRIM(:c)) AND id <> :id;"),
                                                {"c": edit_pos.strip(), "id": target_id}
                                            ).scalar()
                                            if pos_ocupada:
                                                error_edit = (f"La posición «{edit_pos.strip()}» ya la tiene otro equipo. "
                                                              "Si es un cambio de motor, usa la pestaña «Reemplazar Motor».")
                                        if not error_edit and asignando_sn:
                                            sn_dup = conn.execute(
                                                text("SELECT COUNT(*) FROM catalogo_equipos WHERE UPPER(TRIM(no_serie)) = UPPER(TRIM(:n)) AND id <> :id;"),
                                                {"n": sn_final, "id": target_id}
                                            ).scalar()
                                            if sn_dup:
                                                error_edit = f"Ya existe otro motor con el S/N {sn_final}."
                                except Exception as e:
                                    error_edit = f"No se pudo validar los datos: {e}"

                            if error_edit:
                                st.error(error_edit)
                            else:
                                q_upd_eq = text(f"""
                                UPDATE catalogo_equipos SET
                                    {"no_serie = :nuevo_sn," if asignando_sn else ""}
                                    codigo_equipo = :cod, ubicacion = :ub,
                                    marca_modelo = :mm, frame = :fr, balero_superior = :bsup, balero_inferior = :binf,
                                    potencia_hp = :php, voltaje_nom = :vnom, corriente_nom = :inom, rpm = :rpm,
                                    factor_servicio = :fs, breaker_amp = :brk, overload_setting = :ovl,
                                    estatus = :est, observaciones = :obs
                                WHERE id = :id;
                                """)
                                try:
                                    params_upd = {
                                        "cod": edit_pos.strip(), "ub": edit_ubic.strip(),
                                        "mm": edit_marca.strip(), "fr": edit_frame.strip(),
                                        "bsup": edit_bsup.strip(), "binf": edit_binf.strip(),
                                        "php": edit_pot, "vnom": edit_vnom, "inom": edit_inom, "rpm": edit_rpm,
                                        "fs": edit_fs if edit_fs > 0 else None, "brk": edit_brk, "ovl": edit_ovl,
                                        "est": edit_estatus, "obs": edit_obs, "id": target_id
                                    }
                                    if asignando_sn:
                                        params_upd["nuevo_sn"] = sn_final
                                    with engine.begin() as conn:
                                        conn.execute(q_upd_eq, params_upd)
                                        ubic_prev = _s(eq_reg.get("ubicacion")).strip()

                                        # Motor que recibe su primer S/N: el historial antiguo (capturado con el nombre de la posición) se liga a él
                                        if asignando_sn and ligar_historial:
                                            for tabla, col in [
                                                ("inspecciones_bombas", "equipo"),
                                                ("registro_eventos", "equipo"),
                                                ("inspecciones_termograficas", "equipo_id"),
                                                ("pruebas_aislamiento", "equipo"),
                                            ]:
                                                conn.execute(
                                                    text(f"UPDATE {tabla} SET {col} = :sn WHERE TRIM({col}) = TRIM(:pos);"),
                                                    {"sn": sn_final, "pos": pos_prev}
                                                )
                                        if asignando_sn:
                                            registrar_movimiento(conn, sn_final, "Asignación de S/N", pos_prev, edit_pos.strip(),
                                                                 ubic_prev, edit_ubic.strip(), "Primer registro con S/N")
                                        elif sn_final and (edit_pos.strip() != pos_prev or edit_ubic.strip() != ubic_prev):
                                            registrar_movimiento(
                                                conn, sn_final, "Reubicación", pos_prev, edit_pos.strip(),
                                                ubic_prev, edit_ubic.strip(), motivo_mov.strip()
                                            )
                                    limpiar_cache()
                                    etiqueta_sn = f"S/N **{sn_final}**" if sn_final else f"**{edit_pos.strip()}** (aún sin S/N)"
                                    flash(f"✅ Motor {etiqueta_sn} actualizado (posición: **{edit_pos.strip()}**).")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"❌ Error al actualizar en BD: {e}")

            with c_del:
                with st.expander("🗑️ Dar de baja / Eliminar Activo", expanded=True):
                    st.write(f"**Posición Actual:** {_s(eq_reg.get('codigo_equipo'))}")
                    st.write(f"**Ubicación:** {_s(eq_reg.get('ubicacion'))}")

                    st.caption("Dar de baja conserva el historial del motor y lo oculta de las listas de captura.")
                    if st.button("📦 Dar de baja (conserva historial)", key=f"baja_{target_id}"):
                        try:
                            nota = f"[{ahora().strftime('%d/%m/%Y')} - {st.session_state.get('usuario_actual', 'Sistema')}] Dado de baja."
                            with engine.begin() as conn:
                                conn.execute(
                                    text("UPDATE catalogo_equipos SET estatus = 'Baja', observaciones = TRIM(COALESCE(observaciones, '') || E'\\n' || :nota) WHERE id = :id;"),
                                    {"nota": nota, "id": target_id}
                                )
                                if target_sn:
                                    registrar_movimiento(
                                        conn, target_sn, "Baja", _s(eq_reg.get("codigo_equipo")), None,
                                        _s(eq_reg.get("ubicacion")), None, "Dado de baja"
                                    )
                            limpiar_cache()
                            flash(f"📦 Motor {('S/N **' + target_sn + '**') if target_sn else '**' + pos_prev + '** (sin S/N)'} dado de baja.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error al dar de baja: {e}")

                    st.divider()
                    if not es_admin():
                        st.info("Solo un administrador puede eliminar activos definitivamente.")
                    else:
                        try:
                            with engine.connect() as conn:
                                n_hist = contar_historial(conn, target_sn)
                        except Exception:
                            n_hist = -1

                        if n_hist != 0:
                            st.warning(
                                f"Este motor tiene {n_hist if n_hist > 0 else 'posibles'} registros de historial. "
                                "Para no dejarlos huérfanos, usa «Dar de baja»."
                            )
                        else:
                            st.warning(f"⚠️ ¿Eliminar permanentemente el S/N **{target_sn}**?")
                            if st.button("❌ Confirmar Eliminación", key=f"del_sn_{target_id}"):
                                try:
                                    with engine.begin() as conn:
                                        conn.execute(text("DELETE FROM movimientos_equipo WHERE TRIM(no_serie) = TRIM(:s);"), {"s": target_sn})
                                        conn.execute(text("DELETE FROM catalogo_equipos WHERE id = :id;"), {"id": target_id})
                                    limpiar_cache()
                                    flash(f"🗑️ Motor S/N **{target_sn}** eliminado del catálogo.")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"❌ Error al eliminar: {e}")

    with tab4:
        st.subheader("🔄 Reemplazo de motor en una posición")
        st.caption(
            "El historial pertenece al S/N del motor. Al reemplazar, el motor retirado conserva todo su historial "
            "y el motor nuevo toma el nombre de la posición e inicia el suyo desde cero."
        )
        df_rep_todos = obtener_equipos()
        df_rep_act = equipos_seleccionables(df_rep_todos)

        if df_rep_act.empty:
            st.info("No hay motores activos para reemplazar.")
        else:
            st.markdown("##### 1. Motor que se retira (dañado)")
            sn_viejo, pos_vieja = selector_equipo_por_serie(df_rep_act, key_widget="sel_reemplazo_viejo")
            viejo = df_rep_act[df_rep_act["no_serie"].astype(str).str.strip() == sn_viejo].iloc[0]
            id_viejo = int(viejo["id"])
            ubic_vieja = _s(viejo.get("ubicacion")).strip()

            with st.form(form_key("form_reemplazo") + f"_{id_viejo}", clear_on_submit=False):
                st.markdown(f"##### 2. Motor nuevo que toma el nombre **{pos_vieja}**")
                c_r1, c_r2 = st.columns(2)
                with c_r1:
                    nuevo_sn_rep = st.text_input("S/N del motor nuevo *", placeholder="Número de serie de la placa")
                    fecha_rep = st.date_input("Fecha del reemplazo", value=hoy())
                    marca_rep = st.text_input("Marca / Modelo", value=_s(viejo.get("marca_modelo")))
                    frame_rep = st.text_input("Armazón / Frame", value=_s(viejo.get("frame")))
                    bsup_rep = st.text_input("Balero Superior", value=_s(viejo.get("balero_superior")))
                    binf_rep = st.text_input("Balero Inferior", value=_s(viejo.get("balero_inferior")))
                    estatus_nuevo = st.selectbox("Estatus del motor nuevo", ["Operativo", "Standby", "En Mantenimiento"])
                with c_r2:
                    hp_rep = st.number_input("Potencia (HP)", value=_f(viejo.get("potencia_hp")), step=5.0)
                    vnom_rep = st.number_input("Voltaje Nominal (V)", value=_f(viejo.get("voltaje_nom")) or 440.0, step=10.0)
                    fla_rep = st.number_input("Corriente Nominal / FLA (A) *", value=None, step=1.0,
                                              help="Dato de la placa del motor nuevo.")
                    rpm_rep = st.number_input("RPM", value=int(_f(viejo.get("rpm")) or 1750), step=50)
                    fs_rep = st.number_input("Factor de Servicio (F.S.)", value=_f(viejo.get("factor_servicio")) or 1.15, step=0.05)

                st.caption("Protecciones y alimentación (ITM, ajuste, cable, distancia) pertenecen a la posición: se conservan del motor retirado.")

                st.markdown("##### 3. Destino del motor retirado")
                c_d1, c_d2, c_d3 = st.columns(3)
                destino_viejo = c_d1.selectbox("Estatus del motor retirado", ["Baja", "En Mantenimiento", "Standby"],
                                               help="«Baja»: desechado. «En Mantenimiento»: va a reparación. «Standby»: queda de reserva.")
                nombre_viejo = c_d2.text_input("Nuevo nombre del motor retirado", value=f"RETIRADO {pos_vieja}")
                ubic_viejo_nueva = c_d3.text_input("Ubicación del motor retirado", value="Taller / Almacén")

                motivo_rep = st.text_area("Motivo del reemplazo / falla *", placeholder="Ej. Devanado quemado, balero colapsado...")
                cerrar_eventos = st.checkbox("Cerrar como «Resuelto» los eventos abiertos del motor retirado")

                btn_reemplazar = st.form_submit_button("🔄 Confirmar Reemplazo", use_container_width=True)

                if btn_reemplazar:
                    nuevo_sn_rep = nuevo_sn_rep.strip()
                    error_rep = None
                    if not nuevo_sn_rep:
                        error_rep = "El S/N del motor nuevo es obligatorio."
                    elif nuevo_sn_rep.upper() == sn_viejo.upper():
                        error_rep = "El motor nuevo no puede tener el mismo S/N que el retirado."
                    elif fla_rep is None or fla_rep <= 0:
                        error_rep = "La Corriente Nominal (FLA) del motor nuevo es obligatoria."
                    elif not motivo_rep.strip():
                        error_rep = "Escribe el motivo del reemplazo."
                    elif not nombre_viejo.strip() or nombre_viejo.strip().upper() == pos_vieja.upper():
                        error_rep = "El motor retirado debe quedar con un nombre distinto al de la posición."

                    if not error_rep:
                        try:
                            with engine.connect() as conn:
                                ya_existe = conn.execute(
                                    text("SELECT COUNT(*) FROM catalogo_equipos WHERE UPPER(TRIM(no_serie)) = UPPER(TRIM(:n));"),
                                    {"n": nuevo_sn_rep}
                                ).scalar()
                            if ya_existe:
                                error_rep = f"Ya existe un motor con S/N {nuevo_sn_rep}. Si ese motor ya está en el catálogo, reubícalo en lugar de darlo de alta."
                            else:
                                with engine.connect() as conn:
                                    nombre_ocupado = conn.execute(
                                        text("SELECT COUNT(*) FROM catalogo_equipos WHERE UPPER(TRIM(codigo_equipo)) = UPPER(TRIM(:c)) AND id <> :id;"),
                                        {"c": nombre_viejo.strip(), "id": id_viejo}
                                    ).scalar()
                                if nombre_ocupado:
                                    error_rep = f"El nombre «{nombre_viejo.strip()}» ya lo usa otro equipo. Elige otro nombre para el motor retirado."
                        except Exception as e:
                            error_rep = f"No se pudo verificar el S/N: {e}"

                    if error_rep:
                        st.error(error_rep)
                    else:
                        fh_rep = datetime.combine(fecha_rep, ahora().time())
                        nota_fecha = fecha_rep.strftime("%d/%m/%Y")
                        usuario_rep = st.session_state.get("usuario_actual", "Sistema")
                        try:
                            with engine.begin() as conn:
                                # 1) Motor retirado: conserva su S/N e historial, cambia de nombre/destino
                                conn.execute(
                                    text("""
                                        UPDATE catalogo_equipos SET
                                            codigo_equipo = :nom, ubicacion = :ub, estatus = :est,
                                            observaciones = TRIM(COALESCE(observaciones, '') || E'\\n' || :nota)
                                        WHERE id = :id;
                                    """),
                                    {
                                        "nom": nombre_viejo.strip(), "ub": ubic_viejo_nueva.strip(), "est": destino_viejo,
                                        "nota": f"[{nota_fecha} - {usuario_rep}] Retirado de {pos_vieja} (reemplazado por S/N {nuevo_sn_rep}). Motivo: {motivo_rep.strip()}",
                                        "id": id_viejo
                                    }
                                )
                                # 2) Motor nuevo: toma el nombre de la posición y empieza historial limpio
                                conn.execute(
                                    text("""
                                        INSERT INTO catalogo_equipos (
                                            codigo_equipo, ubicacion, marca_modelo, no_serie, frame,
                                            balero_superior, balero_inferior, potencia_hp, voltaje_nom, corriente_nom, rpm, factor_servicio,
                                            estatus, breaker_amp, overload_setting, calibre_cable, material_conductor,
                                            conductores_por_fase, distancia_m, observaciones
                                        ) VALUES (
                                            :cod, :ub, :mm, :ns, :fr, :bsup, :binf, :php, :vnom, :inom, :rpm, :fs,
                                            :est, :brk, :ovl, :cal, :mat, :hilos, :dist, :obs
                                        );
                                    """),
                                    {
                                        "cod": pos_vieja, "ub": ubic_vieja, "mm": marca_rep.strip(), "ns": nuevo_sn_rep,
                                        "fr": frame_rep.strip(), "bsup": bsup_rep.strip(), "binf": binf_rep.strip(),
                                        "php": hp_rep, "vnom": vnom_rep, "inom": fla_rep, "rpm": rpm_rep, "fs": fs_rep,
                                        "est": estatus_nuevo,
                                        "brk": _f(viejo.get("breaker_amp"), None), "ovl": _f(viejo.get("overload_setting"), None),
                                        "cal": _s(viejo.get("calibre_cable")), "mat": _s(viejo.get("material_conductor")),
                                        "hilos": int(_f(viejo.get("conductores_por_fase"), 1) or 1),
                                        "dist": _f(viejo.get("distancia_m"), None),
                                        "obs": f"[{nota_fecha} - {usuario_rep}] Instalado en {pos_vieja} en reemplazo del S/N {sn_viejo}."
                                    }
                                )
                                # 3) Trazabilidad: un movimiento por motor
                                registrar_movimiento(
                                    conn, sn_viejo, "Retiro (reemplazo)", pos_vieja, nombre_viejo.strip(),
                                    ubic_vieja, ubic_viejo_nueva.strip(),
                                    f"Reemplazado por S/N {nuevo_sn_rep}. {motivo_rep.strip()}", fh_rep
                                )
                                registrar_movimiento(
                                    conn, nuevo_sn_rep, "Instalación (reemplazo)", None, pos_vieja,
                                    None, ubic_vieja, f"Reemplaza al S/N {sn_viejo}. {motivo_rep.strip()}", fh_rep
                                )
                                # 4) Opcional: cerrar eventos abiertos del motor retirado
                                if cerrar_eventos:
                                    conn.execute(
                                        text("""
                                            UPDATE registro_eventos SET estatus = 'Resuelto',
                                                accion_tomada = TRIM(COALESCE(accion_tomada, '') || E'\\n' || :nota)
                                            WHERE TRIM(equipo) = TRIM(:sn) AND estatus IN ('Abierto', 'En Revisión');
                                        """),
                                        {"sn": sn_viejo, "nota": f"[{nota_fecha} - {usuario_rep}]: Cerrado por reemplazo del motor (nuevo S/N {nuevo_sn_rep})."}
                                    )
                            limpiar_cache()
                            reset_form("form_reemplazo")
                            flash(f"✅ Reemplazo registrado: S/N **{nuevo_sn_rep}** ahora es **{pos_vieja}**. "
                                  f"El S/N **{sn_viejo}** conserva su historial como «{nombre_viejo.strip()}».")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error al registrar el reemplazo: {e}")

        # --- Trayectoria / hoja de vida de cualquier motor (incluye dados de baja) ---
        st.markdown("---")
        st.subheader("📜 Trayectoria de un motor (por S/N)")
        if df_rep_todos.empty:
            st.info("No hay motores en el catálogo.")
        else:
            sn_tray, _p = selector_equipo_por_serie(df_rep_todos, key_widget="sel_trayectoria")
            df_mov_all = obtener_movimientos()
            df_mov_sn = df_mov_all[df_mov_all["no_serie"].astype(str).str.strip() == sn_tray] if not df_mov_all.empty else df_mov_all
            try:
                with engine.connect() as conn:
                    n_reg = contar_historial(conn, sn_tray)
                st.caption(f"Registros de historial ligados a este S/N (inspecciones, eventos, termografías y aislamiento): **{n_reg}**")
            except Exception:
                pass
            if df_mov_sn.empty:
                st.info("Este motor aún no tiene movimientos registrados (posición única desde el alta).")
            else:
                st.dataframe(
                    df_mov_sn.drop(columns=["id", "no_serie"]).rename(columns={
                        "fecha_hora": "Fecha", "tipo_movimiento": "Movimiento",
                        "posicion_anterior": "Posición anterior", "posicion_nueva": "Posición nueva",
                        "ubicacion_anterior": "Ubicación anterior", "ubicacion_nueva": "Ubicación nueva",
                        "motivo": "Motivo", "realizado_por": "Registró"
                    }),
                    use_container_width=True
                )


# =========================================================
# 3. NUEVA INSPECCIÓN ELÉCTRICA
# =========================================================
elif opcion == "Nueva Inspección Eléctrica":
    st.title("📋 Lectura Electromecánica en Campo")

    df_equipos_cat = obtener_equipos()
    df_activos = equipos_seleccionables(df_equipos_cat)

    with st.form(form_key("form_bomba"), clear_on_submit=False):
        st.subheader("📌 Datos Generales del Registro")
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            fecha_insp = st.date_input("Fecha de Inspección", value=hoy())

            if not df_activos.empty:
                no_serie_sel, codigo_pos = selector_equipo_por_serie(df_activos, key_widget="sel_eq_insp")
            else:
                no_serie_sel = st.text_input("Número de Serie *").strip()

        with col_f2:
            tipo_equipo = st.selectbox("Tipo de Motor", ["Sumergible", "Vertical (Eje Largo)", "Centrífuga Horizontal"])
            tecnico = st.text_input("Técnico Inspector", value=st.session_state.get("usuario_actual", "Técnico"))

        st.markdown("---")
        st.caption("Todas las lecturas son obligatorias (captura 0 si el valor realmente es 0).")
        st.markdown("#### ⚡ Voltajes Fase - Fase ($V_{FF}$)")
        vf_1, vf_2, vf_3 = st.columns(3)
        v_ab = vf_1.number_input("V_ab (V)", value=None, min_value=0.0)
        v_bc = vf_2.number_input("V_bc (V)", value=None, min_value=0.0)
        v_ca = vf_3.number_input("V_ca (V)", value=None, min_value=0.0)

        st.markdown("#### 📐 Voltajes Fase - Neutro ($V_{FN}$) y Puesta a Tierra")
        vn_1, vn_2, vn_3, vn_4 = st.columns(4)
        v_an = vn_1.number_input("V_an (V)", value=None, min_value=0.0)
        v_bn = vn_2.number_input("V_bn (V)", value=None, min_value=0.0)
        v_cn = vn_3.number_input("V_cn (V)", value=None, min_value=0.0)
        v_n_tierra = vn_4.number_input("V Neutro-Tierra (V)", value=None, min_value=0.0)

        st.markdown("#### 🔌 Consumos de Corriente por Fase")
        i_col1, i_col2, i_col3 = st.columns(3)
        i_a = i_col1.number_input("Fase A (A)", value=None, min_value=0.0)
        i_b = i_col2.number_input("Fase B (A)", value=None, min_value=0.0)
        i_c = i_col3.number_input("Fase C (A)", value=None, min_value=0.0)

        observaciones = st.text_area("Observaciones adicionales")
        confirmar = st.checkbox("Confirmo las lecturas marcadas como inusuales / guardar de todos modos")

        c_btn1, c_btn2 = st.columns(2)
        enviado = c_btn1.form_submit_button("💾 Guardar Registro", use_container_width=True)
        btn_can = c_btn2.form_submit_button("❌ Cancelar", type="secondary", use_container_width=True)

        if btn_can:
            reset_form("form_bomba")
            st.rerun()

        if enviado:
            lecturas = [v_ab, v_bc, v_ca, v_an, v_bn, v_cn, v_n_tierra, i_a, i_b, i_c]
            if not no_serie_sel:
                st.error("Selecciona o captura el número de serie del equipo.")
            elif any(x is None for x in lecturas):
                st.error("Faltan lecturas por capturar. No se permiten campos vacíos.")
            else:
                fla, fs, vnom = params_equipo(df_equipos_cat, no_serie_sel)

                # Validaciones de coherencia (detectan dedazos tipo 4400 V en vez de 440 V)
                avisos = []
                if vnom:
                    for nombre, val in (("V_ab", v_ab), ("V_bc", v_bc), ("V_ca", v_ca)):
                        if abs(val - vnom) / vnom > 0.25:
                            avisos.append(f"{nombre} = {val:g} V difiere más de 25% del nominal ({vnom:g} V).")
                if fla:
                    for nombre, val in (("Fase A", i_a), ("Fase B", i_b), ("Fase C", i_c)):
                        if val > 2 * fla:
                            avisos.append(f"{nombre} = {val:g} A supera 2 veces el FLA ({fla:g} A).")
                try:
                    with engine.connect() as conn:
                        dup = conn.execute(
                            text("SELECT COUNT(*) FROM inspecciones_bombas WHERE TRIM(equipo) = TRIM(:e) AND fecha = :f;"),
                            {"e": str(no_serie_sel).strip(), "f": fecha_insp}
                        ).scalar()
                    if dup:
                        avisos.append(f"Ya existe una lectura de este motor con fecha {fecha_insp.strftime('%d/%m/%Y')}.")
                except Exception as e:
                    logger.warning(f"No se pudo verificar duplicados: {e}")

                if avisos and not confirmar:
                    st.error("Revisa los datos antes de guardar:\n\n" + "\n".join(f"- {a}" for a in avisos) +
                             "\n\nSi son correctos, marca la casilla de confirmación y guarda de nuevo.")
                else:
                    desb_v_ff = calcular_desbalance(v_ab, v_bc, v_ca)
                    desb_v_fn = calcular_desbalance(v_an, v_bn, v_cn)
                    desb_i = calcular_desbalance(i_a, i_b, i_c)
                    i_prom = (i_a + i_b + i_c) / 3.0
                    factor_carga_calc = round((i_prom / fla) * 100, 2) if fla else None

                    estado_eval, motivos = evaluar_estado_electrico(desb_v_ff, desb_v_fn, desb_i, v_n_tierra, factor_carga_calc, fs)

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
                        limpiar_cache()
                        reset_form("form_bomba")
                        detalle = f" — {', '.join(motivos)}" if motivos else ""
                        aviso_fla = "" if fla else " (el motor no tiene FLA en el catálogo: sin factor de carga)"
                        flash(f"✅ Lectura guardada para el motor S/N **{no_serie_sel}** (Estado: {estado_eval}){detalle}{aviso_fla}.",
                              "success" if estado_eval == "Normal" else "warning")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error al insertar datos: {e}")


# =========================================================
# 4. INSPECCIÓN TERMOGRÁFICA (FLIR)
# =========================================================
elif opcion == "🔥 Inspección Termográfica (FLIR)":
    st.title("🔥 Registro Termográfico Completo (Vaciado FLIR)")
    df_equipos_cat = obtener_equipos()
    df_sel_termo = equipos_seleccionables(df_equipos_cat)

    tab_termo_nuevo, tab_termo_historial = st.tabs(["➕ Vaciar Inspección Completa", "📜 Historial Térmico"])

    with tab_termo_nuevo:
        with st.form(form_key("form_termografia_completa"), clear_on_submit=False):
            col_eq, col_fecha = st.columns(2)
            with col_eq:
                if not df_sel_termo.empty:
                    no_serie_termo, _ = selector_equipo_por_serie(df_sel_termo, key_widget="sel_termo_eq")
                else:
                    no_serie_termo = st.text_input("Número de Serie *").strip()
            with col_fecha:
                fecha_termo = st.date_input("Fecha de Inspección", value=hoy())

            c_amb1, c_amb2 = st.columns(2)
            t_amb = c_amb1.number_input("🌡️ Temperatura ambiente (°C) *", value=None, step=0.1)
            emisividad = c_amb2.number_input("Emisividad configurada en la cámara", value=0.95, min_value=0.01, max_value=1.0, step=0.01)

            st.markdown("---")
            st.caption("Todas las temperaturas son obligatorias.")
            st.subheader("⚙️ 1. Motor (Mecánico / Térmico)")
            m1, m2, m3 = st.columns(3)
            t_bal_sup = m1.number_input("🔩 Balero Superior (°C)", value=None, step=0.1)
            t_bal_inf = m2.number_input("🔩 Balero Inferior (°C)", value=None, step=0.1)
            t_carcasa = m3.number_input("📦 Carcasa (°C)", value=None, step=0.1)

            st.subheader("⚡ 2. ITM")
            i1, i2, i3 = st.columns(3)
            t_itm_a = i1.number_input("Fase A (°C)", value=None, step=0.1)
            t_itm_b = i2.number_input("Fase B (°C)", value=None, step=0.1)
            t_itm_c = i3.number_input("Fase C (°C)", value=None, step=0.1)

            observaciones_gen = st.text_area("Observaciones Generales")
            btn_guardar_termo = st.form_submit_button("💾 Guardar Inspección Completa")

            if btn_guardar_termo:
                temps = [t_amb, t_bal_sup, t_bal_inf, t_carcasa, t_itm_a, t_itm_b, t_itm_c]
                if not no_serie_termo:
                    st.error("Selecciona o captura el número de serie del equipo.")
                elif any(t is None for t in temps):
                    st.error("Faltan temperaturas por capturar.")
                else:
                    componentes = [
                        {"punto": "Motor (Mecánico/Térmico)", "t": (t_bal_sup, t_bal_inf, t_carcasa),
                         "etiquetas": "Balero sup. / Balero inf. / Carcasa", "es_motor": True},
                        {"punto": "ITM (Interruptor Termomagnético)", "t": (t_itm_a, t_itm_b, t_itm_c),
                         "etiquetas": "Fase A / Fase B / Fase C", "es_motor": False},
                    ]
                    q_ins = text("""
                    INSERT INTO inspecciones_termograficas
                    (equipo_id, fecha_inspeccion, punto_medicion, hot_spot, spot_1, spot_2, spot_3, desbalance_max, delta_hotspot,
                     estado, observaciones, tecnico, etiquetas, temp_ambiente, emisividad, delta_ambiente)
                    VALUES (:eq, :f, :p, :hot, :s1, :s2, :s3, :desbal, :delta, :est, :obs, :tec, :etq, :amb, :emi, :dam);
                    """)
                    tec_actual = st.session_state.get("usuario_actual", "Sistema")
                    try:
                        estados = []
                        with engine.begin() as conn:
                            for item in componentes:
                                t1, t2, t3 = item["t"]
                                hot, desbal, delta, est = evaluar_termografia(t1, t2, t3, item["es_motor"])
                                estados.append(f"{item['punto'].split(' ')[0]}: {est}")
                                conn.execute(q_ins, {
                                    "eq": str(no_serie_termo).strip(), "f": fecha_termo, "p": item["punto"],
                                    "hot": hot, "s1": t1, "s2": t2, "s3": t3, "desbal": desbal,
                                    "delta": delta, "est": est, "obs": observaciones_gen, "tec": tec_actual,
                                    "etq": item["etiquetas"], "amb": t_amb, "emi": emisividad,
                                    "dam": round(hot - t_amb, 2)
                                })
                        limpiar_cache()
                        reset_form("form_termografia_completa")
                        flash(f"✅ Inspección registrada para S/N **{no_serie_termo}** ({' | '.join(estados)}).")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error al guardar termografía: {e}")

    with tab_termo_historial:
        df_termo = obtener_termografias()
        if df_termo.empty:
            st.info("Aún no hay inspecciones termográficas registradas.")
        else:
            df_termo_filt = aplicar_filtros_tabla(df_termo, col_fecha="fecha_inspeccion", key_suffix="hist_termo")
            st.dataframe(df_termo_filt, use_container_width=True)
            st.caption("delta_hotspot = punto más caliente − promedio de los 3 puntos · delta_ambiente = punto más caliente − temperatura ambiente (registros nuevos).")


# =========================================================
# 5. REGISTRO DE EVENTOS (BITÁCORA)
# =========================================================
elif opcion == "Registro de Eventos":
    st.title("🚨 Bitácora y Registro de Eventos")

    df_equipos_cat = obtener_equipos()

    tab_nuevo, tab_historial, tab_gestion = st.tabs([
        "➕ Registrar Evento",
        "📋 Bitácora de Eventos",
        "🛠️ Editar / Eliminar Evento"
    ])

    with tab_nuevo:
        st.caption("El semáforo del dashboard se calcula con los eventos abiertos: no necesitas cambiar el estatus del equipo a mano.")
        with st.form(form_key("form_evento"), clear_on_submit=False):
            col1, col2 = st.columns(2)

            with col1:
                col_f_ev, col_h_ev = st.columns(2)
                with col_f_ev:
                    fecha_ev = st.date_input("Fecha del Evento *", value=hoy())
                with col_h_ev:
                    hora_ev = st.time_input("Hora del Evento *", value=ahora().time())

                if not df_equipos_cat.empty:
                    no_serie_ev, _ = selector_equipo_por_serie(df_equipos_cat, key_widget="sel_eq_evento_n")
                else:
                    no_serie_ev = st.text_input("Número de Serie Afectado *")

                tipo_ev = st.selectbox("Tipo de Evento *", TIPOS_EVENTO)

            with col2:
                severidad_ev = st.select_slider("Nivel de Severidad", options=SEVERIDADES)
                descripcion_ev = st.text_area("Descripción / Causa Raíz", placeholder="Detalla qué sucedió exactamente...")
                accion_ev = st.text_input("Acción Inmediata Tomada", placeholder="Ej. Se aisló el equipo y notificó...")
                estatus_ev = st.selectbox("Estatus del Evento", ["Abierto", "En Revisión", "Resuelto"])

            sacar_servicio = st.checkbox("Además, marcar el equipo como «Fuera de Servicio» en el catálogo")

            st.divider()
            col_b_ev1, col_b_ev2 = st.columns(2)
            btn_evento = col_b_ev1.form_submit_button("💾 Guardar Evento en BD", use_container_width=True)
            btn_cancelar_ev = col_b_ev2.form_submit_button("❌ Cancelar", type="secondary", use_container_width=True)

            if btn_cancelar_ev:
                reset_form("form_evento")
                st.rerun()

            if btn_evento:
                if not no_serie_ev:
                    st.error("Selecciona o captura el número de serie del equipo.")
                else:
                    q_ins_ev = text("""
                        INSERT INTO registro_eventos (fecha_hora, equipo, tipo_evento, severidad, descripcion, accion_tomada, estatus, reportado_por)
                        VALUES (:fh, :eq, :te, :sev, :desc, :acc, :est, :rep);
                    """)
                    params_ev = {
                        "fh": datetime.combine(fecha_ev, hora_ev),
                        "eq": str(no_serie_ev).strip(),
                        "te": tipo_ev, "sev": severidad_ev,
                        "desc": descripcion_ev, "acc": accion_ev, "est": estatus_ev,
                        "rep": st.session_state.get("usuario_actual", "Sistema")
                    }
                    try:
                        with engine.begin() as conn:
                            conn.execute(q_ins_ev, params_ev)
                            if sacar_servicio:
                                conn.execute(
                                    text("UPDATE catalogo_equipos SET estatus = 'Fuera de Servicio' WHERE TRIM(no_serie) = TRIM(:eq);"),
                                    {"eq": str(no_serie_ev).strip()}
                                )
                        limpiar_cache()
                        reset_form("form_evento")
                        extra = " El equipo quedó «Fuera de Servicio»." if sacar_servicio else ""
                        flash(f"✅ Evento registrado para el S/N **{no_serie_ev}**.{extra}")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error al guardar el evento: {e}")

    with tab_historial:
        df_eventos = obtener_eventos()
        df_cat = obtener_equipos()

        if df_eventos.empty:
            st.info("Aún no hay eventos ni incidentes registrados.")
        else:
            df_eventos = df_eventos.copy()
            map_serie_a_pos = dict(zip(df_cat["no_serie"].astype(str).str.strip(), df_cat["codigo_equipo"].astype(str).str.strip())) if not df_cat.empty else {}
            # La posición se muestra como estaba el motor AL MOMENTO del evento (según la bitácora de movimientos)
            df_mov_ev = obtener_movimientos()
            df_eventos["posicion_mostrada"] = df_eventos.apply(
                lambda r: posicion_en_fecha(
                    df_mov_ev, r["equipo"], r["fecha_hora"],
                    map_serie_a_pos.get(str(r["equipo"]).strip(), str(r["equipo"]))
                ), axis=1
            )

            df_evt_filtered = aplicar_filtros_tabla(df_eventos, col_fecha="fecha_hora", key_suffix="registro_eventos")

            filtro_sev = st.multiselect("Filtrar por Severidad:", df_eventos["severidad"].dropna().unique())
            if filtro_sev:
                df_evt_filtered = df_evt_filtered[df_evt_filtered["severidad"].isin(filtro_sev)]

            st.markdown(f"### 📋 Historial de Bitácora ({len(df_evt_filtered)} eventos encontrados)")
            st.divider()

            for _, row in df_evt_filtered.iterrows():
                estatus = row.get("estatus", "Abierto")
                icono_est = "🟢" if estatus == "Resuelto" else ("🟡" if estatus == "En Revisión" else "🔴")

                titulo_tarjeta = f"{icono_est} ID #{row['id']} | **Pos: {row['posicion_mostrada']}** (S/N: {row['equipo']}) — {row['tipo_evento']} [{estatus}]"

                with st.expander(titulo_tarjeta):
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.markdown(f"**📅 Fecha y Hora:**\n{row['fecha_hora']}")
                    with c2:
                        st.markdown(f"**⚡ Severidad:**\n{row['severidad']}")
                    with c3:
                        st.markdown(f"**👤 Reportado por:**\n{_s(row.get('reportado_por')) or 'N/A'}")

                    st.markdown("---")
                    st.markdown("**📝 Descripción / Causa Raíz:**")
                    st.info(_s(row["descripcion"]) or "Sin descripción.")

                    st.markdown("**🛠️ Acciones Tomadas e Historial de Cierre:**")
                    st.success(_s(row["accion_tomada"]) or "Sin acciones registradas aún.")

            st.divider()
            csv_ev = df_evt_filtered.to_csv(index=False).encode("utf-8")
            st.download_button("📥 Exportar Eventos a CSV", data=csv_ev, file_name=f"eventos_{ahora().strftime('%Y%m%d')}.csv", mime="text/csv")

    with tab_gestion:
        df_eventos = obtener_eventos()
        df_cat_ges = obtener_equipos()

        if df_eventos.empty:
            st.info("No hay eventos registrados para modificar o eliminar.")
        else:
            st.subheader("🛠️ Administrar o Reconectar / Cerrar Eventos")

            map_s_p = dict(zip(df_cat_ges["no_serie"].astype(str).str.strip(), df_cat_ges["codigo_equipo"].astype(str).str.strip())) if not df_cat_ges.empty else {}

            opciones_eventos = {}
            for _, row in df_eventos.iterrows():
                serial_val = str(row["equipo"]).strip()
                pos_val = map_s_p.get(serial_val, serial_val)
                label_opt = f"ID #{row['id']} | Pos: {pos_val} (S/N: {serial_val}) | {row['tipo_evento']} [{row['estatus']}]"
                opciones_eventos[label_opt] = int(row["id"])

            label_evt_sel = st.selectbox("Selecciona el evento a gestionar:", list(opciones_eventos.keys()))
            id_evt_sel = opciones_eventos[label_evt_sel]
            evt_registro = df_eventos[df_eventos["id"] == id_evt_sel].iloc[0]

            col_cerrar_evt, col_edit_evt, col_del_evt = st.columns(3)

            with col_cerrar_evt:
                with st.expander("⚡ Reconectar Motor / Cerrar Evento", expanded=True):
                    if evt_registro["estatus"] == "Resuelto":
                        st.success(f"✅ El evento ID #{id_evt_sel} ya se encuentra resuelto/cerrado.")
                    else:
                        with st.form(f"form_cerrar_evt_{id_evt_sel}", clear_on_submit=False):
                            st.caption(f"**Motor S/N:** {evt_registro['equipo']}")
                            st.caption(f"**Causa inicial:** {evt_registro['tipo_evento']}")

                            nuevo_estatus = st.selectbox("Nuevo Estatus", ["Resuelto", "En Revisión"])
                            fecha_cierre = st.date_input("Fecha de Reconexión/Cierre", value=hoy())
                            accion_reconexion = st.text_area("Detalle de la Reconexión / Solución", placeholder="Ej. Se corrigió la falla de aislamiento...")
                            regresar_operativo = st.checkbox(
                                "Al resolver, regresar el equipo a «Operativo» (solo si estaba Fuera de Servicio / En Mantenimiento y no tiene otros eventos abiertos)",
                                value=True
                            )

                            col_bc1, col_bc2 = st.columns(2)
                            btn_reconectar = col_bc1.form_submit_button("💾 Guardar y Cerrar", use_container_width=True)
                            btn_cancelar_close = col_bc2.form_submit_button("❌ Cancelar", type="secondary", use_container_width=True)

                            if btn_cancelar_close:
                                st.rerun()

                            if btn_reconectar:
                                if not accion_reconexion.strip():
                                    st.warning("⚠️ Debes ingresar el detalle de la acción realizada.")
                                else:
                                    usuario_actual = st.session_state.get("usuario_actual", "Sistema")
                                    accion_previa = _s(evt_registro["accion_tomada"]).strip()
                                    registro_cierre = f"[{fecha_cierre.strftime('%d/%m/%Y')} - {usuario_actual}]: {accion_reconexion.strip()}"
                                    accion_final = f"{accion_previa}\n\n{registro_cierre}".strip()

                                    q_close_evt = text("UPDATE registro_eventos SET estatus = :est, accion_tomada = :acc WHERE id = :id;")
                                    q_regresar = text("""
                                        UPDATE catalogo_equipos SET estatus = 'Operativo'
                                        WHERE TRIM(no_serie) = TRIM(:eq)
                                          AND estatus IN ('Fuera de Servicio', 'En Mantenimiento')
                                          AND NOT EXISTS (
                                              SELECT 1 FROM registro_eventos e
                                              WHERE e.id <> :id AND TRIM(e.equipo) = TRIM(:eq)
                                                AND e.estatus IN ('Abierto', 'En Revisión')
                                          );
                                    """)
                                    try:
                                        with engine.begin() as conn:
                                            conn.execute(q_close_evt, {"est": nuevo_estatus, "acc": accion_final, "id": int(id_evt_sel)})
                                            if nuevo_estatus == "Resuelto" and regresar_operativo:
                                                conn.execute(q_regresar, {"eq": str(evt_registro["equipo"]).strip(), "id": int(id_evt_sel)})
                                        limpiar_cache()
                                        flash(f"✅ Evento #{id_evt_sel} actualizado a «{nuevo_estatus}».")
                                        st.rerun()
                                    except Exception as e:
                                        st.error(f"❌ Error al actualizar evento: {e}")

            with col_edit_evt:
                with st.expander("✏️ Modificar Evento Seleccionado"):
                    with st.form(f"form_edit_evt_{id_evt_sel}"):
                        fh_val = pd.to_datetime(evt_registro["fecha_hora"]).to_pydatetime()

                        edit_f_ev = st.date_input("Fecha", value=fh_val.date())
                        edit_h_ev = st.time_input("Hora", value=fh_val.time())

                        if not df_cat_ges.empty:
                            lista_sn_opt = [s for s in df_cat_ges["no_serie"].astype(str).str.strip().tolist() if s]
                            current_sn = str(evt_registro["equipo"]).strip()
                            idx_sn = lista_sn_opt.index(current_sn) if current_sn in lista_sn_opt else 0
                            edit_eq_ev = st.selectbox("S/N Motor Correcto", lista_sn_opt, index=idx_sn)
                        else:
                            edit_eq_ev = st.text_input("S/N Motor", value=str(evt_registro["equipo"])).strip()

                        idx_tipo_evt = TIPOS_EVENTO.index(evt_registro["tipo_evento"]) if evt_registro["tipo_evento"] in TIPOS_EVENTO else 0
                        edit_tipo_ev = st.selectbox("Tipo de Evento", TIPOS_EVENTO, index=idx_tipo_evt)

                        idx_sev = SEVERIDADES.index(evt_registro["severidad"]) if evt_registro["severidad"] in SEVERIDADES else 0
                        edit_sev_ev = st.selectbox("Severidad", SEVERIDADES, index=idx_sev)

                        edit_desc_ev = st.text_area("Descripción", value=_s(evt_registro["descripcion"]))
                        edit_acc_ev = st.text_area("Acción Tomada", value=_s(evt_registro["accion_tomada"]))

                        estatus_lista = ["Abierto", "En Revisión", "Resuelto"]
                        idx_est = estatus_lista.index(evt_registro["estatus"]) if evt_registro["estatus"] in estatus_lista else 0
                        edit_est_ev = st.selectbox("Estatus", estatus_lista, index=idx_est)

                        st.divider()
                        col_be1, col_be2 = st.columns(2)
                        btn_update_evt = col_be1.form_submit_button("💾 Guardar Cambios", use_container_width=True)
                        btn_cancelar_edit_evt = col_be2.form_submit_button("❌ Cancelar", type="secondary", use_container_width=True)

                        if btn_cancelar_edit_evt:
                            st.rerun()

                        if btn_update_evt:
                            new_fh = datetime.combine(edit_f_ev, edit_h_ev)
                            q_upd_evt = text("""
                                UPDATE registro_eventos
                                SET fecha_hora = :fh, equipo = :eq, tipo_evento = :te, severidad = :sev,
                                    descripcion = :desc, accion_tomada = :acc, estatus = :est
                                WHERE id = :id;
                            """)
                            try:
                                with engine.begin() as conn:
                                    conn.execute(q_upd_evt, {
                                        "fh": new_fh, "eq": edit_eq_ev, "te": edit_tipo_ev, "sev": edit_sev_ev,
                                        "desc": edit_desc_ev, "acc": edit_acc_ev, "est": edit_est_ev, "id": int(id_evt_sel)
                                    })
                                limpiar_cache()
                                flash(f"✅ Evento #{id_evt_sel} actualizado.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ Error al actualizar: {e}")

            with col_del_evt:
                with st.expander("🗑️ Eliminar Evento Seleccionado"):
                    if not es_admin():
                        st.info("Solo un administrador puede eliminar eventos.")
                    else:
                        st.warning(f"⚠️ ¿Eliminar registro **ID #{id_evt_sel}**?")
                        if st.button("❌ Confirmar Eliminación", key=f"del_evt_{id_evt_sel}"):
                            try:
                                with engine.begin() as conn:
                                    conn.execute(text("DELETE FROM registro_eventos WHERE id = :id;"), {"id": int(id_evt_sel)})
                                limpiar_cache()
                                flash(f"✅ Evento #{id_evt_sel} eliminado.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ Error al eliminar: {e}")


# =========================================================
# 6. HISTORIAL DE MEDICIONES
# =========================================================
elif opcion == "Historial de Mediciones":
    st.title("📊 Historial y Gestión de Inspecciones Eléctricas")
    df = obtener_datos()
    df_cat_hist = obtener_equipos()

    if df.empty:
        st.info("No hay registros en la base de datos.")
    else:
        st.subheader("📋 Registros Existentes")
        df_filtrado = aplicar_filtros_tabla(df, col_fecha="fecha", key_suffix="historial_mediciones")
        if not df_filtrado.empty:
            # Posición que tenía el motor el día de la lectura (el historial sigue al S/N)
            df_mov_med = obtener_movimientos()
            df_filtrado = df_filtrado.copy()
            df_filtrado["posicion_en_fecha"] = df_filtrado.apply(
                lambda r: posicion_en_fecha(df_mov_med, r["equipo"], r["fecha"], r["posicion_actual"], fin_de_dia=True), axis=1
            )
        st.dataframe(formatear_df_porcentajes(df_filtrado), use_container_width=True)

        st.markdown("---")
        st.subheader("🛠️ Modificar o Eliminar un Registro")
        lista_ids = df_filtrado["id"].tolist() if not df_filtrado.empty else df["id"].tolist()
        id_seleccionado = int(st.selectbox("Selecciona ID del registro:", lista_ids))
        registro = df[df["id"] == id_seleccionado].iloc[0]

        col_accion1, col_accion2 = st.columns(2)
        with col_accion1:
            with st.expander("✏️ Editar Registro Seleccionado"):
                with st.form(f"form_editar_{id_seleccionado}"):
                    edit_fecha = st.date_input("Fecha", value=pd.to_datetime(registro["fecha"]).date())
                    sns_cat = [s for s in df_cat_hist["no_serie"].astype(str).str.strip().tolist() if s] if not df_cat_hist.empty else []
                    sn_actual = str(registro["equipo"]).strip()
                    if sn_actual not in sns_cat:
                        sns_cat = [sn_actual] + sns_cat
                    edit_equipo = st.selectbox("S/N Motor (solo para corregir una lectura asignada al motor equivocado)", sns_cat, index=sns_cat.index(sn_actual))
                    e1, e2, e3 = st.columns(3)
                    edit_v_ab = e1.number_input("V_ab", value=_f(registro["v_ab"]))
                    edit_v_bc = e2.number_input("V_bc", value=_f(registro["v_bc"]))
                    edit_v_ca = e3.number_input("V_ca", value=_f(registro["v_ca"]))
                    e4, e5, e6, e7 = st.columns(4)
                    edit_v_an = e4.number_input("V_an", value=_f(registro["v_an"]))
                    edit_v_bn = e5.number_input("V_bn", value=_f(registro["v_bn"]))
                    edit_v_cn = e6.number_input("V_cn", value=_f(registro["v_cn"]))
                    edit_v_nt = e7.number_input("V N-T", value=_f(registro["v_n_tierra"]))
                    e8, e9, e10 = st.columns(3)
                    edit_i_a = e8.number_input("I_a", value=_f(registro["i_a"]))
                    edit_i_b = e9.number_input("I_b", value=_f(registro["i_b"]))
                    edit_i_c = e10.number_input("I_c", value=_f(registro["i_c"]))
                    edit_obs = st.text_area("Observaciones", value=_s(registro["observaciones"]))

                    btn_act = st.form_submit_button("💾 Guardar Cambios")
                    if btn_act:
                        if not edit_equipo:
                            st.error("El S/N del motor es obligatorio.")
                        else:
                            # Se recalcula TODO (desbalances, factor de carga y estado) con la misma lógica que al insertar
                            fla, fs, _vn = params_equipo(df_cat_hist, edit_equipo)
                            new_desb_v_ff = calcular_desbalance(edit_v_ab, edit_v_bc, edit_v_ca)
                            new_desb_v_fn = calcular_desbalance(edit_v_an, edit_v_bn, edit_v_cn)
                            new_desb_i = calcular_desbalance(edit_i_a, edit_i_b, edit_i_c)
                            i_prom_e = (edit_i_a + edit_i_b + edit_i_c) / 3.0
                            new_fc = round((i_prom_e / fla) * 100, 2) if fla else None
                            new_estado, _motivos = evaluar_estado_electrico(new_desb_v_ff, new_desb_v_fn, new_desb_i, edit_v_nt, new_fc, fs)

                            update_query = text("""
                            UPDATE inspecciones_bombas SET
                                fecha = :fecha, equipo = :equipo,
                                v_ab = :v_ab, v_bc = :v_bc, v_ca = :v_ca, desbalance_v_ff = :desb_vff,
                                v_an = :v_an, v_bn = :v_bn, v_cn = :v_cn, desbalance_v_fn = :desb_vfn,
                                v_n_tierra = :vnt,
                                i_a = :i_a, i_b = :i_b, i_c = :i_c, desbalance_i = :desb_i,
                                factor_carga = :fc, estado = :estado, observaciones = :obs
                            WHERE id = :id;
                            """)
                            try:
                                with engine.begin() as conn:
                                    conn.execute(update_query, {
                                        "fecha": edit_fecha, "equipo": edit_equipo,
                                        "v_ab": edit_v_ab, "v_bc": edit_v_bc, "v_ca": edit_v_ca, "desb_vff": new_desb_v_ff,
                                        "v_an": edit_v_an, "v_bn": edit_v_bn, "v_cn": edit_v_cn, "desb_vfn": new_desb_v_fn,
                                        "vnt": edit_v_nt,
                                        "i_a": edit_i_a, "i_b": edit_i_b, "i_c": edit_i_c, "desb_i": new_desb_i,
                                        "fc": new_fc, "estado": new_estado, "obs": edit_obs, "id": id_seleccionado
                                    })
                                limpiar_cache()
                                flash(f"✅ Registro #{id_seleccionado} actualizado (estado recalculado: {new_estado}).")
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ Error al actualizar: {e}")

        with col_accion2:
            with st.expander("🗑️ Eliminar Registro Seleccionado"):
                if not es_admin():
                    st.info("Solo un administrador puede eliminar mediciones.")
                elif st.button("❌ Confirmar Eliminación", key=f"del_med_{id_seleccionado}"):
                    try:
                        with engine.begin() as conn:
                            conn.execute(text("DELETE FROM inspecciones_bombas WHERE id = :id;"), {"id": id_seleccionado})
                        limpiar_cache()
                        flash(f"🗑️ Registro #{id_seleccionado} eliminado.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error al eliminar: {e}")


# =========================================================
# 7. PRUEBAS DE AISLAMIENTO (IEEE Std 43)
# =========================================================
elif opcion == "Pruebas de Aislamiento":
    st.title("⚡ Pruebas de Resistencia de Aislamiento (IEEE Std 43)")
    df_equipos_cat = obtener_equipos()
    df_sel_aisla = equipos_seleccionables(df_equipos_cat)

    tab_nueva_p, tab_hist_p = st.tabs(["🧪 Registrar Nueva Prueba", "📋 Historial y Tendencias"])

    with tab_nueva_p:
        with st.form(form_key("form_prueba_aislamiento"), clear_on_submit=False):
            c_a1, c_a2 = st.columns(2)
            with c_a1:
                f_prueba = st.date_input("Fecha", value=hoy())
                h_prueba = st.time_input("Hora", value=ahora().time())
                if not df_sel_aisla.empty:
                    no_serie_p, _ = selector_equipo_por_serie(df_sel_aisla, key_widget="sel_aisla_eq")
                else:
                    no_serie_p = st.text_input("Número de Serie *").strip()
                v_aplicado = st.selectbox("Tensión de Prueba CD (Megger)", [500, 1000, 2500, 5000])
                temp_c = st.number_input("Temperatura Devanado (°C) *", value=None, step=0.5)

            with c_a2:
                r_30s = st.number_input("Resistencia 30s (MΩ)", value=None, min_value=0.0)
                r_1min = st.number_input("Resistencia 1 min (MΩ) *", value=None, min_value=0.0)
                r_10min = st.number_input("Resistencia 10 min (MΩ)", value=None, min_value=0.0)
                obs_prueba = st.text_area("Observaciones")

            btn_evaluar = st.form_submit_button("📊 Evaluar y Guardar")

            if btn_evaluar:
                if not no_serie_p:
                    st.error("Selecciona o captura el número de serie del equipo.")
                elif temp_c is None:
                    st.error("⚠️ Captura la temperatura del devanado (se necesita para corregir a 40 °C).")
                elif r_1min is None or r_1min <= 0:
                    st.error("⚠️ La lectura a 1 minuto es obligatoria y debe ser mayor a 0 MΩ.")
                else:
                    r_30s_v = r_30s if r_30s and r_30s > 0 else None
                    r_10min_v = r_10min if r_10min and r_10min > 0 else None

                    r_40c = r_1min * (0.5 ** ((40.0 - temp_c) / 10.0))
                    dar_val = round(r_1min / r_30s_v, 2) if r_30s_v else None
                    pi_val = round(r_10min_v / r_1min, 2) if r_10min_v else None
                    diag_est = diagnostico_aislamiento(r_40c, r_1min, pi_val)

                    q_ins_p = text("""
                    INSERT INTO pruebas_aislamiento (fecha_hora, equipo, voltaje_prueba_v, temp_devanado_c, r_30s_mohm, r_1min_mohm, r_10min_mohm, r_40c_mohm, dar, pi, diagnostico, observaciones, realizado_por)
                    VALUES (:fh, :eq, :v, :temp, :r30, :r1m, :r10m, :r40, :dar, :pi, :diag, :obs, :rep);
                    """)
                    try:
                        with engine.begin() as conn:
                            conn.execute(q_ins_p, {
                                "fh": datetime.combine(f_prueba, h_prueba), "eq": str(no_serie_p).strip(),
                                "v": v_aplicado, "temp": temp_c, "r30": r_30s_v,
                                "r1m": r_1min, "r10m": r_10min_v, "r40": round(r_40c, 2),
                                "dar": dar_val, "pi": pi_val, "diag": diag_est, "obs": obs_prueba,
                                "rep": st.session_state.get("usuario_actual", "Sistema")
                            })
                        reset_form("form_prueba_aislamiento")
                        pi_txt = f", PI = {pi_val}" if pi_val is not None else ", PI no calculado (falta lectura a 10 min)"
                        flash(f"✅ Prueba guardada para S/N **{no_serie_p}** (R40 = {r_40c:.1f} MΩ{pi_txt} → {diag_est}).",
                              "success" if diag_est in ("ACEPTABLE", "EXCELENTE") else "warning")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error al guardar en BD: {e}")

    with tab_hist_p:
        df_p = obtener_pruebas_aislamiento()
        if df_p.empty:
            st.info("Aún no hay pruebas de aislamiento registradas.")
        else:
            equipos_p = ["Todos"] + sorted(df_p["equipo"].dropna().astype(str).str.strip().unique().tolist())
            equipo_f = st.selectbox("Filtrar por S/N:", equipos_p, key="f_aisla_eq")
            df_p_f = df_p if equipo_f == "Todos" else df_p[df_p["equipo"].astype(str).str.strip() == equipo_f]

            st.dataframe(df_p_f, use_container_width=True)

            df_graf_p = df_p_f.dropna(subset=["r_40c_mohm"]).sort_values("fecha_hora")
            if not df_graf_p.empty:
                fig_aisla = px.line(
                    df_graf_p, x="fecha_hora", y="r_40c_mohm", color="equipo", markers=True,
                    log_y=True, title="Tendencia de Resistencia de Aislamiento corregida a 40 °C (MΩ, escala log)"
                )
                fig_aisla.add_hline(y=UMBRALES["aisl_r40_alerta"], line_dash="dash", line_color="#eab308", annotation_text="Alerta (5 MΩ)")
                fig_aisla.add_hline(y=UMBRALES["aisl_r40_crit"], line_dash="dash", line_color="#ef4444", annotation_text="Crítico (1 MΩ)")
                st.plotly_chart(fig_aisla, use_container_width=True)

            df_pi = df_p_f.dropna(subset=["pi"]).sort_values("fecha_hora")
            if not df_pi.empty:
                fig_pi = px.line(df_pi, x="fecha_hora", y="pi", color="equipo", markers=True, title="Índice de Polarización (PI)")
                fig_pi.add_hline(y=UMBRALES["aisl_pi_min"], line_dash="dash", line_color="#eab308", annotation_text="Mínimo recomendado (2.0)")
                st.plotly_chart(fig_pi, use_container_width=True)


# =========================================================
# 8. MI PERFIL
# =========================================================
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
            elif validar_password(pass_nueva):
                st.error(validar_password(pass_nueva))
            else:
                with engine.connect() as conn:
                    user_db = conn.execute(text("SELECT password_hash FROM usuarios WHERE username = :u;"), {"u": st.session_state.username_actual}).fetchone()

                if user_db and check_password(pass_actual, user_db.password_hash):
                    with engine.begin() as conn:
                        conn.execute(text("UPDATE usuarios SET password_hash = :p WHERE username = :u;"), {"p": hash_password(pass_nueva), "u": st.session_state.username_actual})
                    st.success("✅ Contraseña actualizada correctamente.")
                else:
                    st.error("❌ La contraseña actual es incorrecta.")


# =========================================================
# 9. GESTIÓN DE USUARIOS (ADMIN)
# =========================================================
elif opcion == "Gestión de Usuarios":
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
                elif validar_password(nuevo_pass):
                    st.error(validar_password(nuevo_pass))
                else:
                    try:
                        pass_hash = hash_password(nuevo_pass)
                        with engine.begin() as conn:
                            user_exists = conn.execute(text("SELECT COUNT(*) FROM usuarios WHERE username = :u;"), {"u": nuevo_username}).scalar()
                            if user_exists > 0:
                                st.error(f"❌ El usuario '{nuevo_username}' ya existe.")
                            else:
                                conn.execute(
                                    text("INSERT INTO usuarios (username, password_hash, nombre, rol) VALUES (:u, :p, :n, :r);"),
                                    {"u": nuevo_username, "p": pass_hash, "n": nombre_completo, "r": rol_seleccionado}
                                )
                                st.success(f"✅ Usuario **{nuevo_username}** creado exitosamente.")
                    except Exception as err:
                        st.error(f"Error al guardar: {err}")

    with tab_listar:
        try:
            with engine.connect() as conn:
                df_usr = pd.read_sql(
                    text("SELECT id, username, nombre, rol, activo, intentos_fallidos, bloqueado_hasta FROM usuarios ORDER BY id ASC;"),
                    conn
                )
            st.dataframe(df_usr, use_container_width=True)

            st.markdown("---")
            st.subheader("🔧 Administrar usuario")
            usuario_obj = st.selectbox("Usuario:", df_usr["username"].tolist(), key="sel_usuario_admin")
            fila_u = df_usr[df_usr["username"] == usuario_obj].iloc[0]
            es_activo = bool(fila_u["activo"]) if pd.notna(fila_u["activo"]) else True
            es_propio = usuario_obj == st.session_state.get("username_actual")

            col_u1, col_u2, col_u3 = st.columns(3)

            with col_u1:
                st.markdown("**Desbloquear cuenta**")
                if st.button("🔓 Desbloquear", key="btn_unlock", use_container_width=True):
                    with engine.begin() as conn:
                        conn.execute(text("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE username = :u;"), {"u": usuario_obj})
                    flash(f"🔓 Cuenta de {usuario_obj} desbloqueada.")
                    st.rerun()

            with col_u2:
                st.markdown("**Resetear contraseña**")
                with st.form("form_reset_pass", clear_on_submit=True):
                    nueva_temp = st.text_input("Nueva contraseña temporal", type="password")
                    if st.form_submit_button("🔑 Resetear", use_container_width=True):
                        error_pw = validar_password(nueva_temp)
                        if error_pw:
                            st.error(error_pw)
                        else:
                            with engine.begin() as conn:
                                conn.execute(
                                    text("UPDATE usuarios SET password_hash = :p, intentos_fallidos = 0, bloqueado_hasta = NULL WHERE username = :u;"),
                                    {"p": hash_password(nueva_temp), "u": usuario_obj}
                                )
                            st.success(f"✅ Contraseña de {usuario_obj} restablecida.")

            with col_u3:
                st.markdown("**Activar / Desactivar**")
                if es_propio:
                    st.info("No puedes desactivar tu propia cuenta.")
                else:
                    etiqueta = "⛔ Desactivar" if es_activo else "✅ Activar"
                    if st.button(etiqueta, key="btn_toggle_activo", use_container_width=True):
                        with engine.begin() as conn:
                            conn.execute(text("UPDATE usuarios SET activo = :a WHERE username = :u;"), {"a": (not es_activo), "u": usuario_obj})
                        flash(f"Usuario {usuario_obj} {'desactivado' if es_activo else 'activado'}.")
                        st.rerun()
        except Exception as err:
            st.error(f"Error al consultar usuarios: {err}")
