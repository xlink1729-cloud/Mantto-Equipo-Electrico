import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime, timedelta
from sqlalchemy import create_engine, text
import bcrypt
import logging
import plotly.graph_objects as go

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
            bloqueado_hasta TIMESTAMP WITHOUT TIME ZONE DEFAULT NULL
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
            codigo_equipo VARCHAR(100) UNIQUE NOT NULL,
            ubicacion VARCHAR(150),
            marca_modelo VARCHAR(100),
            no_serie VARCHAR(100),
            frame VARCHAR(50),
            potencia_hp FLOAT,
            voltaje_nom FLOAT,
            corriente_nom FLOAT,
            rpm INT,
            factor_servicio FLOAT,
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
            tecnico VARCHAR(100)
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
        "ALTER TABLE catalogo_equipos ADD COLUMN IF NOT EXISTS frame VARCHAR(50);"
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
    """Limpia de forma segura el estado de la sesión."""
    for key in ["sesion_valida", "usuario_actual", "username_actual", "rol_actual"]:
        st.session_state[key] = None
    st.session_state["sesion_valida"] = False
    st.rerun()

def es_admin() -> bool:
    """Verifica de forma segura si el usuario actual tiene rol de administrador."""
    return st.session_state.get("sesion_valida", False) and st.session_state.get("rol_actual") == "admin"

MAX_INTENTOS = 3
TIEMPO_BLOQUEO_MINUTOS = 15

def login(usuario: str, password: str):
    """Valida credenciales, previene Timing Attacks y aplica bloqueo contra fuerza bruta."""
    try:
        # Usamos engine.begin() para manejar la transacción de escritura/lectura en Neon
        with engine.begin() as conn:
            q_user = text("""
                SELECT username, password_hash, nombre, rol, intentos_fallidos, bloqueado_hasta 
                FROM usuarios 
                WHERE username = :u;
            """)
            result = conn.execute(q_user, {"u": usuario}).fetchone()

            # Mitigación de Timing Attack: Si el usuario no existe, validamos contra DUMMY_HASH
            if not result:
                check_password(password, DUMMY_HASH)
                return False, "❌ Usuario o contraseña incorrectos."

            username, pass_hash, nombre, rol, intentos, bloqueado_hasta = result
            intentos = intentos or 0

            # 1. Verificar si la cuenta está en periodo de bloqueo
            if bloqueado_hasta and datetime.now() < bloqueado_hasta:
                tiempo_restante = int((bloqueado_hasta - datetime.now()).total_seconds() / 60) + 1
                return False, f"🚫 Cuenta bloqueada por seguridad. Reintenta en {tiempo_restante} min."

            # 2. Comprobar contraseña
            if check_password(password, pass_hash):
                # Restablecer intentos al acertar
                q_reset = text("""
                    UPDATE usuarios 
                    SET intentos_fallidos = 0, bloqueado_hasta = NULL 
                    WHERE username = :u;
                """)
                conn.execute(q_reset, {"u": usuario})

                # Guardar datos en la sesión activa
                st.session_state["sesion_valida"] = True
                st.session_state["username_actual"] = username
                st.session_state["usuario_actual"] = nombre
                st.session_state["rol_actual"] = rol
                return True, "¡Bienvenido al sistema!"

            else:
                # Incremento de intentos fallidos
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
        # Registrar el error técnico en logs de servidor y responder algo genérico al usuario
        logging.error(f"Error de autenticación: {err}")
        return False, "⚠️ Error de conexión con el servicio de autenticación."

# ---------------------------------------------------------
# PANTALLA DE LOGIN (MEJORADA)
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
            text-align: center;
            color: #1e293b;
            font-size: 1.8rem;
            font-weight: 800;
            letter-spacing: -0.5px;
            margin-bottom: 2px;
        }
        .app-subtitle {
            text-align: center;
            color: #475569;
            font-size: 0.85rem;
            font-weight: 500;
            margin-bottom: 25px;
            letter-spacing: 0.5px;
        }
        .login-badge {
            text-align: center;
            font-size: 0.75rem;
            color: #64748b;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 15px;
        }
        .footer-tag {
            text-align: center;
            font-size: 0.7rem;
            color: #64748b;
            margin-top: 15px;
        }
        </style>
    """, unsafe_allow_html=True)

    # Espaciador superior para centrar verticalmente la tarjeta
    st.markdown("<br><br>", unsafe_allow_html=True)

    col_l1, col_l2, col_l3 = st.columns([1, 1.2, 1])

    with col_l2:
        with st.container(border=True):
            # Encabezado con Marca / Título
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
# FUNCIONES AUXILIARES & CONSULTAS ELECTROMECÁNICAS
# ---------------------------------------------------------

def optimizar_dataframe_inspecciones(df: pd.DataFrame) -> pd.DataFrame:
    """Aplica cálculos vectorizados para termografía."""
    if df.empty:
        return df

    spot_cols = ['spot_1', 'spot_2', 'spot_3']
    for col in spot_cols:
        if col in df.columns:
            df[col] = df[col].fillna(0)

    spots_matrix = df[['spot_1', 'spot_2', 'spot_3']].values
    promedios = np.mean(spots_matrix, axis=1)
    promedios_safe = np.where(promedios == 0, np.nan, promedios)

    desviaciones = np.abs(spots_matrix - promedios[:, np.newaxis])
    max_desviaciones = np.max(desviaciones, axis=1)

    df['desbalance_max'] = (max_desviaciones / promedios_safe) * 100
    df['desbalance_max'] = df['desbalance_max'].fillna(0).round(2)

    if 'corriente_medida' in df.columns and 'corriente_nominal' in df.columns:
        corr_nominal_safe = np.where(df['corriente_nominal'] == 0, np.nan, df['corriente_nominal'])
        df['factor_carga'] = (df['corriente_medida'] / corr_nominal_safe) * 100
        df['factor_carga'] = df['factor_carga'].fillna(0).round(2)

    return df

@st.cache_data(ttl=300)
def obtener_datos():
    """Consulta e inspecciones de bombas con cálculos totalmente vectorizados."""
    query = """
    SELECT 
        i.*,
        c.corriente_nom as corriente_nominal_cat,
        c.voltaje_nom as voltaje_nominal_cat
    FROM inspecciones_bombas i
    LEFT JOIN catalogo_equipos c ON TRIM(i.equipo) = TRIM(c.codigo_equipo)
    ORDER BY i.fecha DESC, i.id DESC;
    """
    df = pd.read_sql_query(query, engine)
    
    if not df.empty:
        df['equipo'] = df['equipo'].astype(str).str.strip()
        
        # Promedios vectorizados
        df['i_promedio'] = (df['i_a'] + df['i_b'] + df['i_c']) / 3.0
        df['v_promedio'] = (df['v_ab'] + df['v_bc'] + df['v_ca']) / 3.0
        
        # Factor de carga vectorizado
        fla_ref = np.where(
            (df['corriente_nominal_cat'].notnull()) & (df['corriente_nominal_cat'] > 0),
            df['corriente_nominal_cat'],
            65.0
        )
        df['factor_carga'] = ((df['i_promedio'] / fla_ref) * 100).round(2)
        
        # Desbalance de corriente vectorizado (reemplaza .apply)
        i_matrix = df[['i_a', 'i_b', 'i_c']].values
        i_prom = df['i_promedio'].values
        i_prom_safe = np.where(i_prom == 0, np.nan, i_prom)
        max_dev_i = np.max(np.abs(i_matrix - i_prom[:, np.newaxis]), axis=1)
        df['desbalance_i'] = np.nan_to_num((max_dev_i / i_prom_safe) * 100).round(2)

        # Potencia vectorizada (reemplaza .apply)
        # Formula: (sqrt(3) * v_prom * i_prom * fp * eficiencia) / 1000.0
        df['potencia_kw'] = ((np.sqrt(3) * df['v_promedio'] * df['i_promedio'] * 0.85 * 0.90) / 1000.0).round(2)
        
    return df

@st.cache_data(ttl=300)
def obtener_termografias():
    """Consulta termografías con vectorización aplicada."""
    query = """
    SELECT i.*, e.corriente_nominal 
    FROM inspecciones_termograficas i
    LEFT JOIN catalogo_equipos e ON i.equipo_id = e.id
    ORDER BY i.fecha_inspeccion DESC, i.id DESC;
    """
    df = pd.read_sql_query(query, con=engine)
    return optimizar_dataframe_inspecciones(df)

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
            df = pd.read_sql_query(query, conn)
        return df
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
        "desbalance_v_ff": "Desbal. V_FF (%)",
        "desbalance_v_fn": "Desbal. V_FN (%)",
        "desbalance_i": "Desbal. I (%)",
        "factor_carga": "Factor Carga (%)",
        "potencia_kw": "Potencia Est. (kW)",
        "v_n_tierra": "V Neutro-Tierra (V)"
    })
    return df_fmt

# ---------------------------------------------------------
# VISTA: DASHBOARD & KPIS (VISUALLY ENGAGING)
# ---------------------------------------------------------
if opcion == "Dashboard & KPIs":
    st.title("🌊 Monitoreo Eléctrico & KPIs de Confiabilidad")
    st.caption("Métricas evaluadas bajo estándares NEMA MG 1 e IEEE 141")

    # Estilos CSS específicos para la vista del Dashboard (Cards y Badges)
    st.markdown("""
        <style>
        .kpi-card {
            background: rgba(255, 255, 255, 0.65);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.8);
            box-shadow: 0 10px 25px rgba(0,0,0,0.05);
            text-align: center;
        }
        .kpi-title {
            font-size: 0.85rem;
            color: #64748b;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .kpi-value {
            font-size: 1.8rem;
            font-weight: 800;
            color: #1e293b;
            margin: 8px 0;
        }
        .kpi-status {
            font-size: 0.8rem;
            font-weight: 600;
            border-radius: 12px;
            padding: 4px 12px;
            display: inline-block;
        }
        .status-ok { background-color: #dcfce7; color: #166534; }
        .status-warning { background-color: #fef9c3; color: #854d0e; }
        .status-danger { background-color: #fee2e2; color: #991b1b; }
        
        .equipment-card {
            background: rgba(255, 255, 255, 0.5);
            border-radius: 14px;
            padding: 15px;
            border-left: 6px solid #cbd5e1;
            margin-bottom: 10px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.03);
        }
        .eq-border-ok { border-left-color: #22c55e !important; }
        .eq-border-warning { border-left-color: #eab308 !important; }
        .eq-border-danger { border-left-color: #ef4444 !important; }
        </style>
    """, unsafe_allow_html=True)

    # 1. FILTROS GLOBALES EN LA PARTE SUPERIOR
    with st.container():
        col_f1, col_f2, col_f3 = st.columns([1.5, 1.5, 1])
        with col_f1:
            fecha_inicio = st.date_input("Fecha Inicio", datetime.now() - timedelta(days=90))
        with col_f2:
            fecha_fin = st.date_input("Fecha Fin", datetime.now())
        with col_f3:
            st.markdown("<br>", unsafe_allow_html=True)
            btn_actualizar = st.button("🔄 Actualizar Datos", use_container_width=True)

    # Cargar Datos desde Neon BD de forma segura
    try:
        with engine.connect() as conn:
            df_elec = pd.read_sql(
                text("SELECT * FROM inspecciones_bombas WHERE fecha BETWEEN :i AND :f ORDER BY fecha DESC;"),
                conn, params={"i": fecha_inicio, "f": fecha_fin}
            )
            df_termo = pd.read_sql(
                text("SELECT * FROM inspecciones_termograficas WHERE fecha_inspeccion BETWEEN :i AND :f;"),
                conn, params={"i": fecha_inicio, "f": fecha_fin}
            )
            df_equipos = pd.read_sql(text("SELECT * FROM catalogo_equipos;"), conn)

    except Exception as e:
        st.error(f"Error al cargar datos del Dashboard: {e}")
        df_elec, df_termo, df_equipos = pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    # 2. CÁLCULO DE KPIS GLOBALES
    total_equipos = len(df_equipos) if not df_equipos.empty else 0
    
    # Evaluar alertas
    alertas_criticas = 0
    alertas_advertencia = 0
    
    if not df_elec.empty:
        alertas_criticas += len(df_elec[df_elec['desbalance_i'] > 10.0])
        alertas_advertencia += len(df_elec[(df_elec['desbalance_i'] >= 5.0) & (df_elec['desbalance_i'] <= 10.0)])
    
    if not df_termo.empty:
        alertas_criticas = len(df_termo[df_termo['estado'].str.upper() == 'CRITICO'])
        alertas_advertencia = len(df_termo[df_termo['estado'].str.upper() == 'ADVERTENCIA'])

    # Índice de Salud Estimado (0 - 100%)
    if total_equipos > 0:
        salud_global = max(0, min(100, int(100 - (alertas_criticas * 15 + alertas_advertencia * 5) / total_equipos)))
    else:
        salud_global = 100

    st.markdown("<br>", unsafe_allow_html=True)

    # Render de Tarjetas KPI estilo Glassmorphism
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)

    with kpi1:
        st.markdown(f"""
            <div class='kpi-card'>
                <div class='kpi-title'>Salud Global</div>
                <div class='kpi-value'>{salud_global}%</div>
                <span class='kpi-status {"status-ok" if salud_global > 85 else "status-warning" if salud_global > 70 else "status-danger"}'>
                    {"🟢 Óptimo" if salud_global > 85 else "🟡 Atención" if salud_global > 70 else "🔴 Riesgo"}
                </span>
            </div>
        """, unsafe_allow_html=True)

    with kpi2:
        st.markdown(f"""
            <div class='kpi-card'>
                <div class='kpi-title'>Total de Equipos</div>
                <div class='kpi-value'>{total_equipos}</div>
                <span class='kpi-status status-ok'>⚙️ Monitoreados</span>
            </div>
        """, unsafe_allow_html=True)

    with kpi3:
        st.markdown(f"""
            <div class='kpi-card'>
                <div class='kpi-title'>Alertas Críticas</div>
                <div class='kpi-value' style='color: #ef4444;'>{alertas_criticas}</div>
                <span class='kpi-status {"status-danger" if alertas_criticas > 0 else "status-ok"}'>
                    {"🔴 Acción Inmediata" if alertas_criticas > 0 else "🟢 Ninguna"}
                </span>
            </div>
        """, unsafe_allow_html=True)

    with kpi4:
        st.markdown(f"""
            <div class='kpi-card'>
                <div class='kpi-title'>Advertencias</div>
                <div class='kpi-value' style='color: #eab308;'>{alertas_advertencia}</div>
                <span class='kpi-status {"status-warning" if alertas_advertencia > 0 else "status-ok"}'>
                    {"🟡 Bajo Observación" if alertas_advertencia > 0 else "🟢 Ninguna"}
                </span>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<br><br>", unsafe_allow_html=True)

    # 3. SEMÁFORO Y PANELES DE DIAGNÓSTICO
    tab_fleet, tab_radar, tab_scatter = st.tabs([
        "🚨 Vista de Flota (Semáforo)", 
        "📐 Diagrama Fasorial (Vectores)", 
        "📈 Factor de Carga vs. Salud"
    ])

    # TAB 1: GRID DE EQUIPOS (SEMÁFORO Visual)
    with tab_fleet:
        st.subheader("Estado de Salud por Equipo")
    
    if df_equipos.empty:
        st.info("No hay equipos registrados en el catálogo.")
    else:
        cols_grid = st.columns(3)
        for idx, row in df_equipos.iterrows():
            col_idx = idx % 3
            eq_code = row['codigo_equipo']
            estatus_actual = row.get('estatus', 'Operativo')
            
            # 1. EVALUAR ESTATUS OPERATIVO DEL CATÁLOGO
            if estatus_actual == "Standby":
                st_color = "eq-border-warning"
                badge_txt = "⏸️ Standby"
            elif estatus_actual in ["Fuera de Servicio", "En Mantenimiento"]:
                st_color = "eq-border-danger"
                badge_txt = "🔴 Fuera de Servicio"
            else:
                # 2. SI ESTÁ OPERATIVO, EVALUAR DESBALANCE
                st_color = "eq-border-ok"
                badge_txt = "🟢 Normal"
                
                if not df_elec.empty:
                    eq_data = df_elec[df_elec['equipo'] == eq_code]
                    if not eq_data.empty:
                        last_desb = eq_data.iloc[0]['desbalance_i'] or 0
                        if last_desb > 10.0:
                            st_color = "eq-border-danger"
                            badge_txt = f"🔴 Desbalance I: {last_desb:.1f}%"
                        elif last_desb >= 5.0:
                            st_color = "eq-border-warning"
                            badge_txt = f"🟡 Desbalance I: {last_desb:.1f}%"

            with cols_grid[col_idx]:
                st.markdown(f"""
                    <div class='equipment-card {st_color}'>
                        <strong style='font-size: 1.1rem; color: #1e293b;'>{eq_code}</strong><br>
                        <span style='font-size: 0.85rem; color: #64748b;'>{row.get('marca_modelo', 'Modelo N/A')} | {row.get('potencia_hp', 0)} HP</span><br>
                        <div style='margin-top: 8px;'>
                            <span class='kpi-status' style='font-size:0.75rem; background: #f1f5f9; color: #334155;'>
                                Ubicación: {row.get('ubicacion', 'N/A')}
                            </span>
                            <span style='float: right; font-size:0.8rem; font-weight:bold;'>{badge_txt}</span>
                        </div>
                    </div>
                """, unsafe_allow_html=True)

    # TAB 2: DIAGRAMA FASORIAL / VECTORES (VOLTAJE Y CORRIENTE)
    with tab_radar:
        st.subheader("📐 Diagrama Fasorial Trifásico")
        
        df_insp = obtener_datos()
        
        if df_insp is None or df_insp.empty:
            st.info("No hay registros de inspección disponibles.")
        else:
            # Filtrar última lectura por equipo
            df_reciente = df_insp.sort_values('fecha').groupby('equipo').last().reset_index()
            
            # Layout de controles arriba del gráfico
            col_eq, col_tipo = st.columns([2, 1])
            
            with col_eq:
                equipos_disponibles = df_reciente['equipo'].unique().tolist()
                equipo_sel = st.selectbox("Selecciona equipo:", equipos_disponibles)
                
            with col_tipo:
                tipo_param = st.radio("Métrica a evaluar:", ["Corriente (A)", "Voltaje (V)"], horizontal=True)
            
            # Extraer fila del equipo seleccionado
            datos_eq = df_reciente[df_reciente['equipo'] == equipo_sel].iloc[0]
            
            # Mapeo según la selección del usuario
            if tipo_param == "Corriente (A)":
                f1 = float(datos_eq.get('i_a', datos_eq.get('i_l1', 0)))
                f2 = float(datos_eq.get('i_b', datos_eq.get('i_l2', 0)))
                f3 = float(datos_eq.get('i_c', datos_eq.get('i_l3', 0)))
                unidad = "A"
                titulo_graf = f"Vectores de Corriente - {equipo_sel}"
            else:
                f1 = float(datos_eq.get('v_ab', datos_eq.get('v_l1', 0)))
                f2 = float(datos_eq.get('v_bc', datos_eq.get('v_l2', 0)))
                f3 = float(datos_eq.get('v_ca', datos_eq.get('v_l3', 0)))
                unidad = "V"
                titulo_graf = f"Vectores de Voltaje - {equipo_sel}"
            
            # Ángulos estándar trifásicos (0°, 120°, 240°)
            angulos = [0, 120, 240]
            magnitudes = [f1, f2, f3]
            fases = ['Fase A (L1)', 'Fase B (L2)', 'Fase C (L3)']
            colores = ['#e74c3c', '#f1c40f', '#3498db']  # Rojo, Amarillo, Azul
            
            fig_vector = go.Figure()
            
            for ang, mag, fase, color in zip(angulos, magnitudes, fases, colores):
                fig_vector.add_trace(go.Scatterpolar(
                    r=[0, mag],
                    theta=[ang, ang],
                    mode='lines+markers',
                    name=f"{fase}: {mag:.1f} {unidad}",
                    line=dict(color=color, width=4),
                    marker=dict(size=8, symbol='arrow-bar-up')
                ))
            
            fig_vector.update_layout(
                polar=dict(
                    radialaxis=dict(
                        visible=True, 
                        range=[0, max(magnitudes) * 1.15 if max(magnitudes) > 0 else 10],
                        title=f"Magnitud ({unidad})"
                    ),
                    angularaxis=dict(
                        tickmode='array',
                        tickvals=[0, 120, 240],
                        ticktext=['0° (L1)', '120° (L2)', '240° (L3)'],
                        direction="counterclockwise"
                    )
                ),
                height=450,
                title=titulo_graf,
                showlegend=True,
                legend=dict(orientation="h", y=-0.1)
            )
            
            st.plotly_chart(fig_vector, use_container_width=True)

    # TAB 3: SECCIÓN DE GRÁFICAS SEPARADAS Y DEDUPLICADAS
    with tab_scatter:
        st.subheader("📈 Análisis de Parámetros Operativos")

        df_insp = obtener_datos()
        
        if df_insp is None or df_insp.empty:
            st.info("No hay registros de inspección disponibles.")
        else:
            # 💡 DEDUPLICACIÓN: Tomar sólo la última lectura por equipo
            df_graficas = df_insp.sort_values('fecha').groupby('equipo').last().reset_index()

            col_g1, col_g2 = st.columns(2)

            # --- GRÁFICA 1: FACTOR DE CARGA (%) ---
            with col_g1:
                st.markdown("##### ⚡ Factor de Carga (%) por Equipo")
                
                fig_fc = px.bar(
                    df_graficas,
                    x='equipo',
                    y='factor_carga',
                    color='factor_carga',
                    color_continuous_scale='Blues',
                    text_auto='.1f',
                    labels={'factor_carga': 'Factor Carga (%)', 'equipo': 'Equipo'},
                    title="Carga Operativa Actual vs Capacidad Nom."
                )
                
                fig_fc.add_hline(y=100.0, line_dash="dash", line_color="red", annotation_text="100% Carga Nom.")
                fig_fc.add_hline(y=50.0, line_dash="dot", line_color="orange", annotation_text="Sub-operación (<50%)")
                
                fig_fc.update_layout(showlegend=False, height=380)
                st.plotly_chart(fig_fc, use_container_width=True)

            # --- GRÁFICA 2: DESBALANCE DE CORRIENTE (%) ---
            with col_g2:
                st.markdown("##### ⚖️ Desbalance de Corriente (%) por Equipo")
                
                fig_desb = px.bar(
                    df_graficas,
                    x='equipo',
                    y='desbalance_i',
                    color='desbalance_i',
                    color_continuous_scale='Reds',
                    text_auto='.1f',
                    labels={'desbalance_i': 'Desbalance (%)', 'equipo': 'Equipo'},
                    title="Desbalance Eléctrico Trifásico Actual"
                )
                
                fig_desb.add_hline(y=5.0, line_dash="dash", line_color="orange", annotation_text="Alarma IEEE (5%)")
                fig_desb.add_hline(y=10.0, line_dash="dash", line_color="red", annotation_text="Crítico NEMA (10%)")
                
                fig_desb.update_layout(showlegend=False, height=380)
                st.plotly_chart(fig_desb, use_container_width=True)

# ---------------------------------------------------------
# 2. CATÁLOGO DE EQUIPOS
# ---------------------------------------------------------
elif opcion == "Catálogo de Equipos":
    st.title("🏷️ Catálogo de Placas de Datos e Instalación Eléctrica")

    tab1, tab2, tab3 = st.tabs([
        "📋 Lista de Equipos Registrados", 
        "➕ Registrar Equipo e Instalación",
        "🛠️ Modificar / Eliminar Equipo"
    ])

    with tab1:
        df_eq = obtener_equipos()
        if df_eq.empty:
            st.info("No hay equipos registrados en el catálogo.")
        else:
            st.dataframe(df_eq, width="stretch")

    # --- TAB 2: ALTA DE EQUIPO Y DATOS DE INSTALACIÓN ---
    with tab2:
        st.subheader("Alta de Equipo, Placa y Parámetros Eléctricos")
        with st.form("form_nuevo_equipo", clear_on_submit=True):
            
            # SECCIÓN 1: DATOS DE PLACA
            st.markdown("##### 🏷️ Datos Placa de Motor")
            col_e1, col_e2 = st.columns(2)
            
            with col_e1:
                cod_eq = st.text_input("Identificador del Equipo *", placeholder="Ej. Pozo-01, Motor-Bomba-A")
                ubic = st.text_input("Ubicación en Planta / Área *", placeholder="Ej. Pozo Profundo No. 3, Estación B")
                marca_m = st.text_input("Marca / Modelo del Motor", placeholder="Ej. US Motors / Siemens 1LA")
                no_serie = st.text_input("Número de Serie", placeholder="Ej. SN-8894021")
                frame_m = st.text_input("Armazón / Frame (NEMA/IEC)", placeholder="Ej. 326T, 256TC")
                estatus_e = st.selectbox("Estatus Operativo", ["Operativo", "En Mantenimiento", "Fuera de Servicio", "Standby"])

            with col_e2:
                pot_hp = st.number_input("Potencia (HP)", value=50.0, step=5.0)
                v_nom = st.number_input("Voltaje Nominal (V)", value=440.0, step=10.0)
                i_nom = st.number_input("Corriente Nominal / FLA (A) *", value=65.0, step=1.0)
                rpm_e = st.number_input("Velocidad Nominal (RPM)", value=1750, step=50)
                fs_e = st.number_input("Factor de Servicio (F.S.)", value=1.0, step=0.05)

            st.divider()

            # SECCIÓN 2: PROTECCIONES Y ALIMENTACIÓN
            st.markdown("##### ⚡ Protecciones y Cableado de Alimentación")
            col_p1, col_p2 = st.columns(2)

            with col_p1:
                breaker_a = st.number_input("Capacidad Interruptor / Breaker (A)", value=100.0, step=5.0, help="Capacidad nominal del MCCB/Guardamotor")
                sobrecarga_a = st.number_input("Ajuste Termomagnético / Relevador (A)", value=65.0, step=1.0, help="Corriente de disparo ajustada en campo")
                dist_m = st.number_input("Distancia desde CCM / Tablero (m)", value=25.0, step=5.0, help="Distancia lineal de cableado")

            with col_p2:
                calibre_c = st.text_input("Calibre de Conductor", placeholder="Ej. 3/0 AWG, 250 kcmil, 8 AWG")
                material_c = st.selectbox("Material del Conductor", ["Cobre (Cu)", "Aluminio (Al)"])
                hilos_fase = st.number_input("Conductores por Fase", value=1, min_value=1, max_value=6, step=1, help="Número de cables en paralelo por fase")

            obs_eq = st.text_area("Observaciones Adicionales (Placa o Instalación)")
            btn_guardar_eq = st.form_submit_button("💾 Guardar en Catálogo")

            if btn_guardar_eq:
                if not cod_eq.strip():
                    st.error("El Identificador del Equipo es obligatorio.")
                else:
                    q_ins_eq = text("""
                    INSERT INTO catalogo_equipos (
                        codigo_equipo, ubicacion, marca_modelo, no_serie, frame, 
                        potencia_hp, voltaje_nom, corriente_nom, rpm, factor_servicio, 
                        estatus, breaker_amp, overload_setting, calibre_cable, material_conductor,
                        conductores_por_fase, distancia_m, observaciones
                    ) VALUES (
                        :cod, :ub, :mm, :ns, :fr, 
                        :php, :vnom, :inom, :rpm, :fs, 
                        :est, :brk, :ovl, :cal, :mat,
                        :hilos, :dist, :obs
                    );
                    """)
                    
                    try:
                        with engine.begin() as conn:
                            conn.execute(q_ins_eq, {
                                "cod": cod_eq.strip(), "ub": ubic, "mm": marca_m, "ns": no_serie,
                                "fr": frame_m, "php": pot_hp, "vnom": v_nom, "inom": i_nom, 
                                "rpm": rpm_e, "fs": fs_e, "est": estatus_e,
                                "brk": breaker_a, "ovl": sobrecarga_a, "cal": calibre_c,
                                "mat": material_c, "hilos": hilos_fase, "dist": dist_m,
                                "obs": obs_eq
                            })
                        st.success(f"✅ Equipo **{cod_eq.strip()}** guardado exitosamente.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error al guardar en la base de datos: {e}")

    # --- TAB 3: EDICIÓN Y ELIMINACIÓN DE REGISTROS ---
    with tab3:
        df_eq = obtener_equipos()
        if df_eq.empty:
            st.info("No hay equipos en el catálogo para editar o eliminar.")
        else:
            st.subheader("🛠️ Gestor de Placas e Instalaciones Registradas")
            lista_codigos = df_eq['codigo_equipo'].tolist()
            eq_sel_cod = st.selectbox("Selecciona el Identificador del Equipo:", lista_codigos)

            eq_registro = df_eq[df_eq['codigo_equipo'] == eq_sel_cod].iloc[0]

            col_edit_eq, col_del_eq = st.columns(2)

            with col_edit_eq:
                with st.expander("✏️ Editar Ficha del Equipo e Instalación", expanded=True):
                    with st.form(f"form_edit_eq_{eq_registro['id']}"):
                        
                        st.markdown("##### 🏷️ 1. Placa de Datos del Motor")
                        edit_ubic = st.text_input("Ubicación en Planta / Área", value=str(eq_registro.get('ubicacion', '') or ""))
                        edit_marca_m = st.text_input("Marca / Modelo", value=str(eq_registro.get('marca_modelo', '') or ""))
                        edit_no_serie = st.text_input("Número de Serie", value=str(eq_registro.get('no_serie', '') or ""))
                        
                        val_frame = str(eq_registro.get('frame', '')) if pd.notna(eq_registro.get('frame', '')) else ""
                        edit_frame = st.text_input("Armazón / Frame (NEMA/IEC)", value=val_frame)
                        
                        estatus_op = ["Operativo", "En Mantenimiento", "Fuera de Servicio", "Standby"]
                        val_est = eq_registro.get('estatus', 'Operativo')
                        idx_est = estatus_op.index(val_est) if val_est in estatus_op else 0
                        edit_estatus = st.selectbox("Estatus Operativo", estatus_op, index=idx_est)

                        c_eq1, c_eq2 = st.columns(2)
                        edit_pot_hp = c_eq1.number_input("Potencia (HP)", value=float(eq_registro.get('potencia_hp', 0.0) or 0.0), step=5.0)
                        edit_v_nom = c_eq2.number_input("Voltaje Nominal (V)", value=float(eq_registro.get('voltaje_nom', 0.0) or 0.0), step=10.0)
                        
                        c_eq3, c_eq4 = st.columns(2)
                        edit_i_nom = c_eq3.number_input("Corriente Nominal / FLA (A)", value=float(eq_registro.get('corriente_nom', 0.0) or 0.0), step=1.0)
                        edit_rpm = c_eq4.number_input("RPM", value=int(eq_registro.get('rpm', 0) or 0), step=50)

                        edit_fs = st.number_input("Factor de Servicio (F.S.)", value=float(eq_registro.get('factor_servicio', 1.0) or 1.0), step=0.05)

                        st.divider()

                        st.markdown("##### ⚡ 2. Protecciones y Cableado")
                        c_p1, c_p2 = st.columns(2)
                        edit_brk = c_p1.number_input("Breaker / MCCB (A)", value=float(eq_registro.get('breaker_amp', 0.0) or 0.0), step=5.0)
                        edit_ovl = c_p2.number_input("Ajuste Sobrecarga (A)", value=float(eq_registro.get('overload_setting', 0.0) or 0.0), step=1.0)
                        
                        c_p3, c_p4 = st.columns(2)
                        edit_cal = c_p3.text_input("Calibre Conductor", value=str(eq_registro.get('calibre_cable', '') or ""))
                        
                        mat_op = ["Cobre (Cu)", "Aluminio (Al)"]
                        val_mat = str(eq_registro.get('material_conductor', 'Cobre (Cu)'))
                        idx_mat = mat_op.index(val_mat) if val_mat in mat_op else 0
                        edit_mat = c_p4.selectbox("Material Conductor", mat_op, index=idx_mat)

                        c_p5, c_p6 = st.columns(2)
                        edit_hilos = c_p5.number_input("Conductores por Fase", value=int(eq_registro.get('conductores_por_fase', 1) or 1), min_value=1, max_value=6, step=1)
                        edit_dist = c_p6.number_input("Distancia a CCM (m)", value=float(eq_registro.get('distancia_m', 0.0) or 0.0), step=5.0)

                        st.divider()

                        edit_obs = st.text_area("Observaciones Adicionales", value=str(eq_registro.get('observaciones', '') or ""))

                        btn_update_eq = st.form_submit_button("💾 Guardar Cambios en Ficha")

                        if btn_update_eq:
                            q_upd_eq = text("""
                            UPDATE catalogo_equipos SET
                                ubicacion = :ub,
                                marca_modelo = :mm,
                                no_serie = :ns,
                                frame = :fr,
                                potencia_hp = :php,
                                voltaje_nom = :vnom,
                                corriente_nom = :inom,
                                rpm = :rpm,
                                factor_servicio = :fs,
                                estatus = :est,
                                breaker_amp = :brk,
                                overload_setting = :ovl,
                                calibre_cable = :cal,
                                material_conductor = :mat,
                                conductores_por_fase = :hilos,
                                distancia_m = :dist,
                                observaciones = :obs
                            WHERE id = :id;
                            """)

                            params_upd_eq = {
                                "ub": edit_ubic, "mm": edit_marca_m, "ns": edit_no_serie, "fr": edit_frame,
                                "php": edit_pot_hp, "vnom": edit_v_nom, "inom": edit_i_nom, "rpm": edit_rpm,
                                "fs": edit_fs, "est": edit_estatus, "brk": edit_brk, "ovl": edit_ovl,
                                "cal": edit_cal, "mat": edit_mat, "hilos": edit_hilos, "dist": edit_dist, 
                                "obs": edit_obs, "id": int(eq_registro['id'])
                            }

                            try:
                                with engine.begin() as conn:
                                    conn.execute(q_upd_eq, params_upd_eq)
                                st.success(f"✅ Ficha del equipo **{eq_sel_cod}** actualizada correctamente.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ Error al actualizar en base de datos: {e}")

            with col_del_eq:
                with st.expander("🗑️ Eliminar Equipo del Catálogo", expanded=True):
                    st.warning(f"⚠️ ¿Deseas eliminar **{eq_sel_cod}** del catálogo?")
                    st.write(f"**Ubicación:** {eq_registro.get('ubicacion', 'N/A')}")
                    st.write(f"**FLA:** {eq_registro.get('corriente_nom', 0)} A")
                    st.write(f"**Breaker:** {eq_registro.get('breaker_amp', 0)} A")
                    st.write(f"**Alimentación:** {eq_registro.get('conductores_por_fase', 1)}x {eq_registro.get('calibre_cable', 'N/A')} ({eq_registro.get('material_conductor', 'Cu')})")
                    st.write(f"**Distancia:** {eq_registro.get('distancia_m', 0)} m")

                    if st.button("❌ Confirmar Eliminación", key=f"del_eq_{eq_registro['id']}"):
                        q_del_eq = text("DELETE FROM catalogo_equipos WHERE id = :id;")
                        try:
                            with engine.begin() as conn:
                                conn.execute(q_del_eq, {"id": int(eq_registro['id'])})
                            st.success(f"🗑️ Equipo **{eq_sel_cod}** eliminado con éxito.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error al eliminar el equipo: {e}")

# ---------------------------------------------------------
# 3. NUEVA INSPECCIÓN ELÉCTRICA
# ---------------------------------------------------------
elif opcion == "Nueva Inspección Eléctrica":
    st.title("📋 Lectura Electromecánica en Campo")

    df_equipos_cat = obtener_equipos()

    # FILTRAR SOLO EQUIPOS CON ESTATUS OPERATIVO
    if not df_equipos_cat.empty and 'estatus' in df_equipos_cat.columns:
        df_equipos_activos = df_equipos_cat[df_equipos_cat['estatus'] == 'Operativo']
    else:
        df_equipos_activos = df_equipos_cat.copy()

    with st.form("form_bomba", clear_on_submit=True):
        st.subheader("📌 Datos Generales del Registro")
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            fecha_insp = st.date_input("Fecha de la Inspección", value=datetime.today().date())
            
            # SECCIÓN DE SELECCIÓN DE EQUIPO FILTRADO
            if not df_equipos_activos.empty:
                opciones_eq = df_equipos_activos.apply(lambda row: f"{row['codigo_equipo']} ({row['ubicacion']})", axis=1).tolist()
                eq_seleccionado = st.selectbox("Seleccionar Equipo del Catálogo (Solo Operativos)", opciones_eq)
                equipo = eq_seleccionado.split(" (")[0].strip()
            else:
                st.warning("⚠️ No hay equipos en estatus 'Operativo'. Se muestra campo manual.")
                equipo = st.text_input("Identificador del Equipo / Pozo", value="Bomba Pozo 01").strip()

        with col_f2:
            tipo_equipo = st.selectbox("Tipo de Motor", ["Sumergible", "Vertical (Eje Largo)", "Centrífuga Horizontal"])
            tecnico = st.text_input("Técnico Inspector", value=st.session_state.usuario_actual)

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
        v_n_tierra = vn_4.number_input("V Neutro-Tierra (V)", value=0.5, help="Norma IEEE 141: Recomendado < 2.0 V")

        st.markdown("#### 🔌 Consumos de Corriente por Fase")
        i_col1, i_col2, i_col3 = st.columns(3)
        i_a = i_col1.number_input("Fase A (A)", value=50.0)
        i_b = i_col2.number_input("Fase B (A)", value=50.0)
        i_c = i_col3.number_input("Fase C (A)", value=50.0)

        observaciones = st.text_area("Observaciones adicionales")

        enviado = st.form_submit_button("Guardar Registro")

        if enviado:
            desb_v_ff = calcular_desbalance(v_ab, v_bc, v_ca)
            desb_v_fn = calcular_desbalance(v_an, v_bn, v_cn)
            desb_i = calcular_desbalance(i_a, i_b, i_c)

            i_prom = (i_a + i_b + i_c) / 3.0
            corriente_nom = 65.0
            if not df_equipos_cat.empty and equipo in df_equipos_cat["codigo_equipo"].values:
                corriente_nom = df_equipos_cat[df_equipos_cat["codigo_equipo"] == equipo]["corriente_nom"].values[0]
            
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

            datos_insertar = {
                "fecha": fecha_insp,
                "equipo": str(equipo).strip(),
                "tipo": str(tipo_equipo),
                "v_ab": float(v_ab), "v_bc": float(v_bc), "v_ca": float(v_ca),
                "desbalance_v_ff": float(desb_v_ff),
                "v_an": float(v_an), "v_bn": float(v_bn), "v_cn": float(v_cn),
                "desbalance_v_fn": float(desb_v_fn),
                "i_a": float(i_a), "i_b": float(i_b), "i_c": float(i_c),
                "desbalance_i": float(desb_i),
                "v_n_tierra": float(v_n_tierra),
                "factor_carga": float(factor_carga_calc),
                "estado": str(estado_eval),
                "tecnico": str(tecnico),
                "observaciones": str(observaciones)
            }

            try:
                with engine.begin() as conn:
                    conn.execute(insert_query, datos_insertar)
                st.success(
                    f"✅ Registro guardado con éxito. "
                    f"Factor de Carga NEMA: **{factor_carga_calc}%**, "
                    f"Desbalance V_FF: **{desb_v_ff}%**, "
                    f"Estado evaluado: **{estado_eval}**."
                )
            except Exception as e:
                st.error(f"❌ Error al insertar datos en la base de datos: {e}")

# ---------------------------------------------------------
# 4. INSPECCIÓN TERMOGRÁFICA (FLIR ONE PRO) - CAPTURA COMPLETA
# ---------------------------------------------------------
elif opcion == "🔥 Inspección Termográfica (FLIR)":
    st.title("🔥 Registro Termográfico Completo (Vacitado FLIR)")
    st.caption("Vacía la información de todos los puntos medidos en la inspección y guárdalos con un solo clic.")

    df_equipos_cat = obtener_equipos()

    tab_termo_nuevo, tab_termo_historial = st.tabs(["➕ Vaciar Inspección Completa", "📜 Historial Térmico"])

    with tab_termo_nuevo:
        with st.form("form_termografia_completa", clear_on_submit=True):
            col_eq, col_fecha = st.columns(2)
            
            with col_eq:
                if not df_equipos_cat.empty:
                    equipo_id = st.selectbox("Seleccionar Equipo", df_equipos_cat["codigo_equipo"].tolist())
                else:
                    equipo_id = st.text_input("Identificador del Equipo", value="Motor-Bomba-01").strip()
            
            with col_fecha:
                fecha_termo = st.date_input("Fecha de Inspección", value=datetime.today().date())

            st.markdown("---")
            
            st.subheader("⚙️ 1. Motor (Mecánico / Térmico)")
            col_m1, col_m2, col_m3 = st.columns(3)
            with col_m1:
                t_bal_sup = st.number_input("🔩 Balero Superior (°C)", value=40.0, step=0.1)
            with col_m2:
                t_bal_inf = st.number_input("🔩 Balero Inferior (°C)", value=40.0, step=0.1)
            with col_m3:
                t_carcasa = st.number_input("📦 Carcasa (°C)", value=40.0, step=0.1)

            st.markdown("---")

            st.subheader("⚡ 2. ITM (Interruptor Termomagnético)")
            col_i1, col_i2, col_i3 = st.columns(3)
            with col_i1:
                t_itm_a = st.number_input("Fase A - ITM (°C)", value=35.0, step=0.1)
            with col_i2:
                t_itm_b = st.number_input("Fase B - ITM (°C)", value=35.0, step=0.1)
            with col_i3:
                t_itm_c = st.number_input("Fase C - ITM (°C)", value=35.0, step=0.1)

            st.markdown("---")

            st.subheader("🔌 3. Fusibles")
            col_f1, col_f2, col_f3 = st.columns(3)
            with col_f1:
                t_fus_a = st.number_input("Fase A - Fusible (°C)", value=35.0, step=0.1)
            with col_f2:
                t_fus_b = st.number_input("Fase B - Fusible (°C)", value=35.0, step=0.1)
            with col_f3:
                t_fus_c = st.number_input("Fase C - Fusible (°C)", value=35.0, step=0.1)

            st.markdown("---")

            st.subheader("🎛️ 4. Arrancador / Contactor")
            col_a1, col_a2, col_a3 = st.columns(3)
            with col_a1:
                t_arr_a = st.number_input("Fase A - Arrancador (°C)", value=35.0, step=0.1)
            with col_a2:
                t_arr_b = st.number_input("Fase B - Arrancador (°C)", value=35.0, step=0.1)
            with col_a3:
                t_arr_c = st.number_input("Fase C - Arrancador (°C)", value=35.0, step=0.1)

            st.markdown("---")
            observaciones_gen = st.text_area(
                "Observaciones Generales de la Rutina", 
                placeholder="Ej. Inspección de rutina realizada tras 4 horas de operación continua. Sin anomalías detectadas."
            )

            btn_guardar_todo = st.form_submit_button("💾 Guardar Inspección Completa (4 Componentes)")

            if btn_guardar_todo:
                componentes_datos = [
                    {
                        "punto": "Motor (Mecánico/Térmico)",
                        "t1": t_bal_sup, "t2": t_bal_inf, "t3": t_carcasa,
                        "obs": f"Balero Sup: {t_bal_sup}°C | Balero Inf: {t_bal_inf}°C | Carcasa: {t_carcasa}°C. {observaciones_gen}".strip(),
                        "es_motor": True
                    },
                    {
                        "punto": "ITM (Interruptor Termomagnético)",
                        "t1": t_itm_a, "t2": t_itm_b, "t3": t_itm_c,
                        "obs": f"Fase A: {t_itm_a}°C | Fase B: {t_itm_b}°C | Fase C: {t_itm_c}°C. {observaciones_gen}".strip(),
                        "es_motor": False
                    },
                    {
                        "punto": "Fusibles",
                        "t1": t_fus_a, "t2": t_fus_b, "t3": t_fus_c,
                        "obs": f"Fase A: {t_fus_a}°C | Fase B: {t_fus_b}°C | Fase C: {t_fus_c}°C. {observaciones_gen}".strip(),
                        "es_motor": False
                    },
                    {
                        "punto": "Arrancador / Contactor",
                        "t1": t_arr_a, "t2": t_arr_b, "t3": t_arr_c,
                        "obs": f"Fase A: {t_arr_a}°C | Fase B: {t_arr_b}°C | Fase C: {t_arr_c}°C. {observaciones_gen}".strip(),
                        "es_motor": False
                    }
                ]

                q_ins_termo = text("""
                INSERT INTO inspecciones_termograficas 
                (equipo_id, fecha_inspeccion, punto_medicion, hot_spot, spot_1, spot_2, spot_3, desbalance_max, delta_hotspot, estado, observaciones, tecnico)
                VALUES (:eq, :f, :p, :hot, :s1, :s2, :s3, :desbal, :delta, :est, :obs, :tec);
                """)

                try:
                    with engine.begin() as conn:
                        for item in componentes_datos:
                            t1, t2, t3 = item["t1"], item["t2"], item["t3"]
                            hot_spot = max(t1, t2, t3)
                            desbal = max(t1, t2, t3) - min(t1, t2, t3)
                            delta = hot_spot - ((t1 + t2 + t3) / 3.0)

                            if item["es_motor"]:
                                if hot_spot >= 90.0 or desbal >= 15.0:
                                    estado = "CRITICO"
                                elif hot_spot >= 75.0 or desbal >= 8.0:
                                    estado = "ADVERTENCIA"
                                else:
                                    estado = "NORMAL"
                            else:
                                if desbal >= 15.0 or hot_spot >= 85.0:
                                    estado = "CRITICO"
                                elif desbal >= 4.0 or hot_spot >= 70.0:
                                    estado = "ADVERTENCIA"
                                else:
                                    estado = "NORMAL"

                            params = {
                                "eq": str(equipo_id).strip(),
                                "f": fecha_termo,
                                "p": item["punto"],
                                "hot": float(hot_spot),
                                "s1": float(t1),
                                "s2": float(t2),
                                "s3": float(t3),
                                "desbal": float(desbal),
                                "delta": float(delta),
                                "est": estado,
                                "obs": item["obs"],
                                "tec": str(st.session_state.usuario_actual)
                            }

                            conn.execute(q_ins_termo, params)

                    st.success(f"✅ Se vaciaron y guardaron exitosamente las lecturas de los 4 componentes para **{equipo_id}**.")
                except Exception as e:
                    st.error(f"❌ Error al guardar la inspección: {e}")

    with tab_termo_historial:
        df_termo = obtener_termografias()
        if df_termo.empty:
            st.info("No hay lecturas termográficas en la base de datos.")
        else:
            eq_termo_filtro = st.selectbox("Filtrar por Equipo:", ["Todos"] + list(df_termo["equipo_id"].unique()))
            if eq_termo_filtro != "Todos":
                df_mostrar_termo = df_termo[df_termo["equipo_id"] == eq_termo_filtro]
            else:
                df_mostrar_termo = df_termo
            st.dataframe(df_mostrar_termo, use_container_width=True)

# ---------------------------------------------------------
# 5. REGISTRO DE EVENTOS
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
                    equipo_ev = st.selectbox("Equipo / Motor Afectado *", df_equipos_cat["codigo_equipo"].tolist())
                else:
                    equipo_ev = st.text_input("Equipo / Motor Afectado *", value="Bomba Pozo 01")

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
                severidad_ev = st.select_slider(
                    "Nivel de Severidad",
                    options=["Baja", "Media", "Alta", "Crítica"]
                )
                descripcion_ev = st.text_area("Descripción / Causa Raíz", placeholder="Detalla qué sucedió exactamente...")
                accion_ev = st.text_input("Acción Inmediata Tomada", placeholder="Ej. Se aisló el equipo y notificó...")
                estatus_ev = st.selectbox("Estatus del Evento", ["Abierto", "En Revisión", "Resuelto"])

            btn_evento = st.form_submit_button("💾 Guardar Evento en BD")

            if btn_evento:
                fecha_hora_completa = datetime.combine(fecha_ev, hora_ev)

                q_ins_ev = text("""
                INSERT INTO registro_eventos (fecha_hora, equipo, tipo_evento, severidad, descripcion, accion_tomada, estatus, reportado_por)
                VALUES (:fh, :eq, :te, :sev, :desc, :acc, :est, :rep);
                """)
                
                params_ev = {
                    "fh": fecha_hora_completa,
                    "eq": str(equipo_ev).strip(),
                    "te": tipo_ev,
                    "sev": severidad_ev,
                    "desc": descripcion_ev,
                    "acc": accion_ev,
                    "est": estatus_ev,
                    "rep": st.session_state.usuario_actual
                }

                try:
                    with engine.begin() as conn:
                        conn.execute(q_ins_ev, params_ev)

                    st.success(f"✅ Evento registrado con fecha **{fecha_hora_completa.strftime('%d/%m/%Y %H:%M')}**.")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Error al guardar el evento: {e}")

    with tab_historial:
        df_eventos = obtener_eventos()

        if df_eventos.empty:
            st.info("Aún no hay eventos ni incidentes registrados.")
        else:
            f_col1, f_col2 = st.columns(2)
            with f_col1:
                filtro_eq = st.multiselect("Filtrar por Equipo:", df_eventos["equipo"].unique())
            with f_col2:
                filtro_sev = st.multiselect("Filtrar por Severidad:", df_eventos["severidad"].unique())

            df_evt_filtered = df_eventos.copy()
            if filtro_eq:
                df_evt_filtered = df_evt_filtered[df_evt_filtered["equipo"].isin(filtro_eq)]
            if filtro_sev:
                df_evt_filtered = df_evt_filtered[df_evt_filtered["severidad"].isin(filtro_sev)]

            st.dataframe(df_evt_filtered, use_container_width=True)

            csv_ev = df_evt_filtered.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Exportar Eventos a CSV",
                data=csv_ev,
                file_name=f"eventos_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )

    with tab_gestion:
        df_eventos = obtener_eventos()

        if df_eventos.empty:
            st.info("No hay eventos registrados para modificar o eliminar.")
        else:
            st.subheader("🛠️ Administrar o Reconectar / Cerrar Eventos")
            
            opciones_eventos = {
                f"ID #{row['id']} | {row['equipo']} | {row['tipo_evento']} [{row['estatus']}]": row['id']
                for _, row in df_eventos.iterrows()
            }
            
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
                            st.caption(f"**Equipo:** {evt_registro['equipo']}")
                            st.caption(f"**Causa inicial:** {evt_registro['tipo_evento']}")
                            
                            nuevo_estatus = st.selectbox("Nuevo Estatus", ["Resuelto", "En Revisión"])
                            fecha_cierre = st.date_input("Fecha de Reconexión/Cierre", value=datetime.today().date())
                            
                            accion_reconexion = st.text_area(
                                "Detalle de la Reconexión / Solución",
                                placeholder="Ej. Se corrigió la falla de aislamiento, se realizaron pruebas de rotación y megger. Motor reconectado y operando en norma."
                            )

                            btn_reconectar = st.form_submit_button("💾 Guardar Reconexión y Cerrar")

                            if btn_reconectar:
                                if not accion_reconexion.strip():
                                    st.warning("⚠️ Debes ingresar el detalle de la acción realizada.")
                                else:
                                    accion_previa = str(evt_registro['accion_tomada'] or "").strip()
                                    registro_cierre = f"[{fecha_cierre.strftime('%d/%m/%Y')} - {st.session_state.usuario_actual}]: {accion_reconexion.strip()}"
                                    accion_final = f"{accion_previa}\n\n{registro_cierre}".strip()

                                    q_close_evt = text("""
                                    UPDATE registro_eventos SET
                                        estatus = :est,
                                        accion_tomada = :acc
                                    WHERE id = :id;
                                    """)

                                    try:
                                        with engine.begin() as conn:
                                            conn.execute(q_close_evt, {
                                                "est": nuevo_estatus,
                                                "acc": accion_final,
                                                "id": int(id_evt_sel)
                                            })
                                        st.success(f"✅ Evento #{id_evt_sel} marcado como '{nuevo_estatus}'.")
                                        st.rerun()
                                    except Exception as e:
                                        st.error(f"❌ Error al actualizar el evento: {e}")

            with col_edit_evt:
                with st.expander("✏️ Modificar Evento Seleccionado"):
                    with st.form(f"form_edit_evt_{id_evt_sel}"):
                        fh_val = evt_registro['fecha_hora']
                        if isinstance(fh_val, str):
                            fh_val = datetime.strptime(fh_val, "%Y-%m-%d %H:%M:%S")

                        edit_f_ev = st.date_input("Fecha", value=fh_val.date())
                        edit_h_ev = st.time_input("Hora", value=fh_val.time())
                        edit_eq_ev = st.text_input("Equipo", value=str(evt_registro['equipo'])).strip()

                        tipos_evt_lista = [
                            "Desconexión por daño mecánico",
                            "Falla eléctrica / Sobrevoltaje",
                            "Paro de emergencia",
                            "Mantenimiento no programado",
                            "Fuga o Sobrecalentamiento",
                            "Otro"
                        ]
                        idx_tipo_evt = tipos_evt_lista.index(evt_registro['tipo_evento']) if evt_registro['tipo_evento'] in tipos_evt_lista else 0
                        edit_tipo_ev = st.selectbox("Tipo de Evento", tipos_evt_lista, index=idx_tipo_evt)

                        sev_lista = ["Baja", "Media", "Alta", "Crítica"]
                        idx_sev = sev_lista.index(evt_registro['severidad']) if evt_registro['severidad'] in sev_lista else 0
                        edit_sev_ev = st.select_slider("Severidad", options=sev_lista, value=sev_lista[idx_sev])

                        edit_desc_ev = st.text_area("Descripción", value=str(evt_registro['descripcion'] or ""))
                        edit_acc_ev = st.text_area("Acción Tomada", value=str(evt_registro['accion_tomada'] or ""))

                        estatus_lista = ["Abierto", "En Revisión", "Resuelto"]
                        idx_est = estatus_lista.index(evt_registro['estatus']) if evt_registro['estatus'] in estatus_lista else 0
                        edit_est_ev = st.selectbox("Estatus", estatus_lista, index=idx_est)

                        btn_update_evt = st.form_submit_button("💾 Guardar Cambios")

                        if btn_update_evt:
                            new_fh = datetime.combine(edit_f_ev, edit_h_ev)

                            q_upd_evt = text("""
                            UPDATE registro_eventos SET
                                fecha_hora = :fh,
                                equipo = :eq,
                                tipo_evento = :te,
                                severidad = :sev,
                                descripcion = :desc,
                                accion_tomada = :acc,
                                estatus = :est
                            WHERE id = :id;
                            """)

                            params_upd_evt = {
                                "fh": new_fh,
                                "eq": edit_eq_ev,
                                "te": edit_tipo_ev,
                                "sev": edit_sev_ev,
                                "desc": edit_desc_ev,
                                "acc": edit_acc_ev,
                                "est": edit_est_ev,
                                "id": int(id_evt_sel)
                            }

                            try:
                                with engine.begin() as conn:
                                    conn.execute(q_upd_evt, params_upd_evt)
                                st.success(f"✅ Evento #{id_evt_sel} actualizado correctamente.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ Error al actualizar el evento: {e}")

            with col_del_evt:
                with st.expander("🗑️ Eliminar Evento Seleccionado"):
                    st.warning(f"⚠️ ¿Deseas borrar permanentemente el registro **ID #{id_evt_sel}**?")
                    st.write(f"**Equipo:** {evt_registro['equipo']}")
                    st.write(f"**Fecha:** {evt_registro['fecha_hora']}")
                    st.write(f"**Detalle:** {evt_registro['tipo_evento']}")

                    if st.button("❌ Confirmar Eliminación", key=f"del_evt_{id_evt_sel}"):
                        q_del_evt = text("DELETE FROM registro_eventos WHERE id = :id;")
                        try:
                            with engine.begin() as conn:
                                conn.execute(q_del_evt, {"id": int(id_evt_sel)})
                            st.success(f"🗑️ Evento #{id_evt_sel} eliminado con éxito.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error al eliminar evento: {e}")

# ---------------------------------------------------------
# 6. HISTORIAL DE MEDICIONES
# ---------------------------------------------------------
elif opcion == "Historial de Mediciones":
    st.title("📊 Historial y Gestión de Inspecciones Eléctricas")

    df = obtener_datos()

    if df.empty:
        st.info("No hay registros almacenados en la base de datos.")
    else:
        st.subheader("📋 Registros Existentes")
        st.dataframe(formatear_df_porcentajes(df), use_container_width=True)

        st.markdown("---")
        st.subheader("🛠️ Modificar o Eliminar un Registro")

        lista_ids = df['id'].tolist()
        id_seleccionado = st.selectbox("Selecciona el ID del registro que deseas gestionar:", lista_ids)

        registro = df[df['id'] == id_seleccionado].iloc[0]

        col_accion1, col_accion2 = st.columns(2)

        with col_accion1:
            with st.expander("✏️ Editar Registro Seleccionado"):
                with st.form(f"form_editar_{id_seleccionado}"):
                    fecha_val = registro['fecha']
                    if hasattr(fecha_val, 'date'):
                        fecha_val = fecha_val.date()
                    elif isinstance(fecha_val, str):
                        fecha_val = datetime.strptime(fecha_val, "%Y-%m-%d").date()

                    edit_fecha = st.date_input("Fecha", value=fecha_val)
                    edit_equipo = st.text_input("Equipo", value=str(registro['equipo'])).strip()
                    
                    tipos_opciones = ["Sumergible", "Vertical (Eje Largo)", "Centrífuga Horizontal"]
                    idx_tipo = tipos_opciones.index(registro['tipo']) if registro['tipo'] in tipos_opciones else 0
                    edit_tipo = st.selectbox("Tipo", tipos_opciones, index=idx_tipo)
                    
                    st.markdown("**Voltajes FF (V)**")
                    c1, c2, c3 = st.columns(3)
                    edit_v_ab = c1.number_input("V_ab", value=float(registro['v_ab']))
                    edit_v_bc = c2.number_input("V_bc", value=float(registro['v_bc']))
                    edit_v_ca = c3.number_input("V_ca", value=float(registro['v_ca']))

                    st.markdown("**Voltajes FN (V)**")
                    c4, c5, c6 = st.columns(3)
                    edit_v_an = c4.number_input("V_an", value=float(registro['v_an']))
                    edit_v_bn = c5.number_input("V_bn", value=float(registro['v_bn']))
                    edit_v_cn = c6.number_input("V_cn", value=float(registro['v_cn']))

                    st.markdown("**Corrientes (A)**")
                    c7, c8, c9 = st.columns(3)
                    edit_i_a = c7.number_input("I_a", value=float(registro['i_a']))
                    edit_i_b = c8.number_input("I_b", value=float(registro['i_b']))
                    edit_i_c = c9.number_input("I_c", value=float(registro['i_c']))

                    edit_v_n_t = st.number_input("V Neutro-Tierra", value=float(registro.get('v_n_tierra', 0.0)))
                    edit_obs = st.text_area("Observaciones", value=str(registro['observaciones'] or ""))

                    btn_actualizar = st.form_submit_button("💾 Guardar Cambios")

                    if btn_actualizar:
                        new_desb_v_ff = calcular_desbalance(edit_v_ab, edit_v_bc, edit_v_ca)
                        new_desb_v_fn = calcular_desbalance(edit_v_an, edit_v_bn, edit_v_cn)
                        new_desb_i = calcular_desbalance(edit_i_a, edit_i_b, edit_i_c)

                        if new_desb_v_ff > 2.0 or new_desb_v_fn > 2.0 or new_desb_i > 10.0 or edit_v_n_t > 5.0:
                            new_estado = "Crítico"
                        elif new_desb_v_ff > 1.0 or new_desb_v_fn > 1.0 or new_desb_i > 5.0 or edit_v_n_t > 2.0:
                            new_estado = "Advertencia"
                        else:
                            new_estado = "Normal"

                        update_query = text("""
                        UPDATE inspecciones_bombas SET
                            fecha = :fecha,
                            equipo = :equipo,
                            tipo = :tipo,
                            v_ab = :v_ab, v_bc = :v_bc, v_ca = :v_ca,
                            desbalance_v_ff = :desb_v_ff,
                            v_an = :v_an, v_bn = :v_bn, v_cn = :v_cn,
                            desbalance_v_fn = :desb_v_fn,
                            i_a = :i_a, i_b = :i_b, i_c = :i_c,
                            desbalance_i = :desb_i,
                            v_n_tierra = :v_n_t,
                            estado = :estado,
                            observaciones = :observaciones
                        WHERE id = :id;
                        """)

                        params_update = {
                            "fecha": edit_fecha,
                            "equipo": str(edit_equipo).strip(),
                            "tipo": str(edit_tipo),
                            "v_ab": float(edit_v_ab), "v_bc": float(edit_v_bc), "v_ca": float(edit_v_ca),
                            "desb_v_ff": float(new_desb_v_ff),
                            "v_an": float(edit_v_an), "v_bn": float(edit_v_bn), "v_cn": float(edit_v_cn),
                            "desb_v_fn": float(new_desb_v_fn),
                            "i_a": float(edit_i_a), "i_b": float(edit_i_b), "i_c": float(edit_i_c),
                            "desb_i": float(new_desb_i),
                            "v_n_t": float(edit_v_n_t),
                            "estado": str(new_estado),
                            "observaciones": str(edit_obs),
                            "id": int(id_seleccionado)
                        }

                        try:
                            with engine.begin() as conn:
                                conn.execute(update_query, params_update)
                            st.success(f"✅ Registro #{id_seleccionado} actualizado correctamente.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error al actualizar: {e}")

        with col_accion2:
            with st.expander("🗑️ Eliminar Registro Seleccionado"):
                st.warning(f"⚠️ ¿Deseas eliminar permanentemente el registro **ID #{id_seleccionado}**?")
                
                if st.button("❌ Confirmar Eliminación", key=f"del_{id_seleccionado}"):
                    delete_query = text("DELETE FROM inspecciones_bombas WHERE id = :id;")
                    try:
                        with engine.begin() as conn:
                            conn.execute(delete_query, {"id": int(id_seleccionado)})
                        st.success(f"🗑️ Registro #{id_seleccionado} eliminado exitosamente.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error al eliminar: {e}")

# ---------------------------------------------------------
# PRUEBAS DE AISLAMIENTO (IEEE Std 43)
# ---------------------------------------------------------
elif opcion == "Pruebas de Aislamiento":
    st.title("⚡ Pruebas de Resistencia de Aislamiento (IEEE Std 43)")

    df_equipos_cat = obtener_equipos()

    tab_nueva_p, tab_hist_p = st.tabs([
        "🧪 Registrar Nueva Prueba", 
        "📋 Historial y Tendencias"
    ])

    with tab_nueva_p:
        st.subheader("Evaluación Térmica y Dieléctrica de Estator")
        
        with st.form("form_prueba_aislamiento", clear_on_submit=True):
            col_a1, col_a2 = st.columns(2)

            with col_a1:
                f_prueba = st.date_input("Fecha de la Prueba", value=datetime.today().date())
                h_prueba = st.time_input("Hora de la Prueba", value=datetime.now().time())

                if not df_equipos_cat.empty:
                    equipo_p = st.selectbox("Seleccionar Equipo / Motor *", df_equipos_cat["codigo_equipo"].tolist())
                else:
                    equipo_p = st.text_input("Identificador del Equipo *", value="Bomba-01")

                v_aplicado = st.selectbox("Tensión de Prueba Aplicada en CD (Megger) *", [500, 1000, 2500, 5000], index=0, help="500V o 1000V recomendados para motores <1000V (IEEE 43)")
                temp_c = st.number_input("Temperatura del Devanado / Carcasa (°C) *", value=25.0, step=1.0, help="Dato clave para calcular la corrección R40")

            with col_a2:
                st.markdown("**Lecturas de Resistencia (MΩ)**")
                r_30s = st.number_input("Resistencia a los 30 segundos (MΩ)", value=0.0, step=1.0, help="Opcional: Requerido para índice DAR")
                r_1min = st.number_input("Resistencia a 1 minuto (MΩ) *", value=15.0, step=1.0, help="Obligatorio para la norma IEEE 43")
                r_10min = st.number_input("Resistencia a los 10 minutos (MΩ)", value=0.0, step=1.0, help="Opcional: Requerido para índice PI")

                obs_prueba = st.text_area("Observaciones / Estado del Motor", placeholder="Ej. Motor en stand-by con calefacción encendida. Sin humedad aparente en caja de bornes.")

            btn_calcular_guardar = st.form_submit_button("📊 Evaluar según IEEE 43 y Guardar")

            if btn_calcular_guardar:
                if r_1min <= 0:
                    st.error("⚠️ La lectura de Resistencia a 1 minuto debe ser mayor a 0 MΩ.")
                else:
                    r_40c = r_1min * (0.5 ** ((40.0 - temp_c) / 10.0))
                    dar_val = round(r_1min / r_30s, 2) if r_30s > 0 else None
                    pi_val = round(r_10min / r_1min, 2) if r_10min > 0 else None

                    if r_40c < 1.0:
                        diag_est = "CRÍTICO (Peligro de Falla a Tierra)"
                    elif 1.0 <= r_40c < 5.0:
                        diag_est = "ALERTA (Presencia de Humedad / Suciedad)"
                    elif 5.0 <= r_40c < 100.0:
                        diag_est = "ACEPTABLE (Apto para Operación)"
                    else:
                        diag_est = "EXCELENTE (Devanado Seco y Limpio)"

                    fh_completa = datetime.combine(f_prueba, h_prueba)
                    q_ins_p = text("""
                    INSERT INTO pruebas_aislamiento 
                    (fecha_hora, equipo, voltaje_prueba_v, temp_devanado_c, r_30s_mohm, r_1min_mohm, r_10min_mohm, r_40c_mohm, dar, pi, diagnostico, observaciones, realizado_por)
                    VALUES (:fh, :eq, :v, :temp, :r30, :r1m, :r10m, :r40, :dar, :pi, :diag, :obs, :rep);
                    """)

                    params_p = {
                        "fh": fh_completa, "eq": str(equipo_p).strip(), "v": v_aplicado,
                        "temp": temp_c, "r30": r_30s if r_30s > 0 else None, "r1m": r_1min,
                        "r10m": r_10min if r_10min > 0 else None, "r40": round(r_40c, 2),
                        "dar": dar_val, "pi": pi_val, "diag": diag_est,
                        "obs": obs_prueba, "rep": st.session_state.usuario_actual
                    }

                    try:
                        with engine.begin() as conn:
                            conn.execute(q_ins_p, params_p)
                        
                        st.success("✅ Prueba registrada exitosamente.")
                        
                        st.markdown("### 📋 Resultados del Diagnóstico IEEE 43")
                        mc1, mc2, mc3, mc4 = st.columns(4)
                        mc1.metric("Lectura Directa (1 min)", f"{r_1min} MΩ")
                        mc2.metric("Corregida a 40 °C (R40)", f"{round(r_40c, 2)} MΩ")
                        mc3.metric("Índice DAR", f"{dar_val if dar_val else 'N/A'}")
                        mc4.metric("Índice PI", f"{pi_val if pi_val else 'N/A'}")

                        if r_40c < 5.0:
                            st.error(f" **Diagnóstico:** {diag_est}")
                        else:
                            st.success(f" **Diagnóstico:** {diag_est}")

                    except Exception as e:
                        st.error(f"❌ Error al guardar en base de datos: {e}")

    with tab_hist_p:
        df_p = obtener_pruebas_aislamiento()

        if df_p.empty:
            st.info("Aún no se han registrado pruebas de aislamiento.")
        else:
            st.subheader("📋 Registro Histórico de Pruebas")

            eq_unicos = df_p["equipo"].unique().tolist()
            f_eq_p = st.multiselect("Filtrar por Equipo:", eq_unicos, default=eq_unicos)

            df_p_filt = df_p[df_p["equipo"].isin(f_eq_p)]

            st.dataframe(df_p_filt, use_container_width=True)

            csv_p = df_p_filt.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Exportar Pruebas de Aislamiento a CSV",
                data=csv_p,
                file_name=f"pruebas_aislamiento_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )

# ---------------------------------------------------------
# 7. MI PERFIL
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
                query_check = text("SELECT password_hash FROM usuarios WHERE username = :u;")
                
                with engine.connect() as conn:
                    user_db = conn.execute(query_check, {"u": st.session_state.username_actual}).fetchone()
                
                if user_db and check_password(pass_actual, user_db.password_hash):
                    update_q = text("""
                        UPDATE usuarios 
                        SET password_hash = :p 
                        WHERE username = :u;
                    """)
                    with engine.begin() as conn:
                        conn.execute(update_q, {
                            "p": hash_password(pass_nueva),
                            "u": st.session_state.username_actual
                        })
                    st.success("✅ Contraseña actualizada correctamente.")
                else:
                    st.error("❌ La contraseña actual es incorrecta.")

# ---------------------------------------------------------
# VISTA: GESTIÓN DE USUARIOS (SOLO ADMINS)
# ---------------------------------------------------------
if opcion == "Gestión de Usuarios":
    if not es_admin():
        st.error("🚫 No tienes permisos para acceder a este módulo.")
        st.stop()

    st.title("👥 Gestión de Usuarios y Permisos")
    st.markdown("---")

    tab_crear, tab_listar = st.tabs(["➕ Crear Nuevo Usuario", "📋 Usuarios Registrados y Permisos"])

    # 1. CREAR USUARIO
    with tab_crear:
        st.subheader("Registrar nuevo usuario")
        with st.form("form_crear_usuario", clear_on_submit=True):
            col1, col2 = st.columns(2)
            with col1:
                nuevo_username = st.text_input("Nombre de Usuario (Login)", placeholder="ej. jperez").strip().lower()
                nombre_completo = st.text_input("Nombre Completo", placeholder="ej. Juan Pérez")
            with col2:
                nuevo_pass = st.text_input("Contraseña Temporal", type="password")
                rol_seleccionado = st.selectbox("Rol en el Sistema", ["tecnico", "operador", "admin"])

            btn_crear = st.form_submit_button("Guardar Usuario")

            if btn_crear:
                if not nuevo_username or not nuevo_pass or not nombre_completo:
                    st.warning("⚠️ Todos los campos son obligatorios.")
                elif len(nuevo_pass) < 8:
                    st.warning("⚠️ La contraseña debe tener al menos 8 caracteres.")
                else:
                    try:
                        pass_hash = hash_password(nuevo_pass)
                        with engine.begin() as conn:
                            # Verificar disponibilidad de username
                            user_exists = conn.execute(
                                text("SELECT COUNT(*) FROM usuarios WHERE username = :u;"),
                                {"u": nuevo_username}
                            ).scalar()

                            if user_exists > 0:
                                st.error(f"❌ El usuario '{nuevo_username}' ya existe.")
                            else:
                                conn.execute(
                                    text("""
                                        INSERT INTO usuarios (username, password_hash, nombre, rol)
                                        VALUES (:u, :p, :n, :r);
                                    """),
                                    {"u": nuevo_username, "p": pass_hash, "n": nombre_completo, "r": rol_seleccionado}
                                )
                                st.success(f"✅ Usuario **{nuevo_username}** creado exitosamente.")
                    except Exception as err:
                        st.error(f"Error al guardar en la base de datos: {err}")

    # 2. LISTAR Y ADMINISTRAR USUARIOS
    with tab_listar:
        st.subheader("Administración de Cuentas")
        try:
            with engine.connect() as conn:
                df_usuarios = pd.read_sql(
                    text("SELECT id, username, nombre, rol, intentos_fallidos, bloqueado_hasta FROM usuarios ORDER BY id ASC;"),
                    conn
                )

            if not df_usuarios.empty:
                # Mostrar tabla con estado de bloqueo
                df_usuarios["Estado"] = df_usuarios["bloqueado_hasta"].apply(
                    lambda x: "🚫 Bloqueado" if pd.notnull(x) and datetime.now() < x else "🟢 Activo"
                )
                
                st.dataframe(
                    df_usuarios[["id", "username", "nombre", "rol", "Estado", "intentos_fallidos"]],
                    use_container_width=True
                )

                st.markdown("---")
                col_acc1, col_acc2 = st.columns(2)

                # Accion: Desbloquear o Restablecer Pass
                with col_acc1:
                    st.markdown("##### 🔓 Desbloquear / Restablecer Contraseña")
                    user_select = st.selectbox("Seleccionar Usuario", df_usuarios["username"].tolist(), key="sb_user_reset")
                    new_pass_admin = st.text_input("Nueva Contraseña", type="password", key="pass_reset_admin")
                    
                    if st.button("Actualizar Contraseña y Desbloquear"):
                        if not new_pass_admin or len(new_pass_admin) < 8:
                            st.warning("⚠️ Ingresa una contraseña válida de al menos 8 caracteres.")
                        else:
                            with engine.begin() as conn:
                                pass_h = hash_password(new_pass_admin)
                                conn.execute(
                                    text("""
                                        UPDATE usuarios 
                                        SET password_hash = :p, intentos_fallidos = 0, bloqueado_hasta = NULL 
                                        WHERE username = :u;
                                    """),
                                    {"p": pass_h, "u": user_select}
                                )
                                st.success(f"✅ Contraseña restablecida y usuario **{user_select}** desbloqueado.")
                                st.rerun()

                # Accion: Eliminar Usuario
                with col_acc2:
                    st.markdown("##### 🗑️ Eliminar Usuario")
                    user_delete = st.selectbox("Usuario a Eliminar", df_usuarios["username"].tolist(), key="sb_user_del")
                    
                    if st.button("⚠️ Eliminar Usuario", type="primary"):
                        if user_delete == st.session_state.get("username_actual"):
                            st.error("❌ No puedes eliminar tu propia cuenta en sesión.")
                        else:
                            with engine.begin() as conn:
                                conn.execute(text("DELETE FROM usuarios WHERE username = :u;"), {"u": user_delete})
                                st.success(f"Usuario **{user_delete}** eliminado.")
                                st.rerun()

        except Exception as e:
            st.error(f"Error al cargar la lista de usuarios: {e}")
