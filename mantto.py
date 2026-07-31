import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy import create_engine, text
import hashlib

st.set_page_config(
    page_title="Mantenimiento Bombas & Motores",
    page_icon="🌊",
    layout="wide"
)

# ---------------------------------------------------------
# CONEXIÓN A NEON POSTGRESQL
# ---------------------------------------------------------
@st.cache_resource
def get_db_engine():
    db_url = st.secrets["postgres"]["url"]
    return create_engine(db_url)

engine = get_db_engine()

def hash_password(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

# Inicializar tablas de Usuarios e Inspecciones en Neon
def inicializar_bd():
    query_inspecciones = text("""
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
        v_n_tierra FLOAT,
        aislamiento_megger FLOAT,
        estado VARCHAR(20),
        tecnico VARCHAR(100),
        observaciones TEXT
    );
    """)
    
    query_usuarios = text("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(64) NOT NULL,
        nombre VARCHAR(100),
        rol VARCHAR(20) DEFAULT 'tecnico'
    );
    """)

    with engine.begin() as conn:
        conn.execute(query_inspecciones)
        conn.execute(query_usuarios)
        
        # Crear un usuario administrador por defecto si no existen usuarios
        res = conn.execute(text("SELECT COUNT(*) FROM usuarios;")).scalar()
        if res == 0:
            pass_default = hash_password("mantto2026")
            conn.execute(
                text("INSERT INTO usuarios (username, password_hash, nombre, rol) VALUES (:u, :p, :n, :r);"),
                {"u": "admin", "p": pass_default, "n": "Administrador Mantto", "r": "admin"}
            )

inicializar_bd()

# ---------------------------------------------------------
# AUTENTICACIÓN Y SESIONES
# ---------------------------------------------------------
if "autenticado" not in st.session_state:
    st.session_state.autenticado = False
    st.session_state.usuario_actual = None
    st.session_state.rol_actual = None

def login(usuario, password):
    pass_hash = hash_password(password)
    query = text("SELECT username, nombre, rol FROM usuarios WHERE username = :u AND password_hash = :p;")
    with engine.connect() as conn:
        result = conn.execute(query, {"u": usuario, "p": pass_hash}).fetchone()
        if result:
            st.session_state.autenticado = True
            st.session_state.usuario_actual = result.nombre
            st.session_state.rol_actual = result.rol
            return True
        return False

def logout():
    st.session_state.autenticado = False
    st.session_state.usuario_actual = None
    st.session_state.rol_actual = None

# ---------------------------------------------------------
# PANTALLA DE LOGIN
# ---------------------------------------------------------
if not st.session_state.autenticado:
    st.title("🔒 Acceso al Sistema de Mantenimiento")
    st.caption("Ingresa con tus credenciales asignadas")

    with st.form("form_login"):
        user_input = st.text_input("Usuario")
        pass_input = st.text_input("Contraseña", type="password")
        btn_ingresar = st.form_submit_button("Iniciar Sesión")

        if btn_ingresar:
            if login(user_input, pass_input):
                st.success("Acceso concedido.")
                st.rerun()
            else:
                st.error("Usuario o contraseña incorrectos.")
    st.info("💡 **Usuario por defecto:** `admin` | **Contraseña:** `mantto2026` (Cambiar al iniciar).")
    st.stop()  # Detiene la ejecución del script aquí si no está autenticado

# ---------------------------------------------------------
# APLICACIÓN PRINCIPAL (SOLO ACCESIBLE CON LOGIN)
# ---------------------------------------------------------
st.sidebar.write(f"👤 **Usuario:** {st.session_state.usuario_actual}")
st.sidebar.write(f"🔰 **Rol:** {st.session_state.rol_actual.capitalize()}")
if st.sidebar.button("Cerrar Sesión"):
    logout()
    st.rerun()

st.title("🌊 Monitoreo Eléctrico: Bombas y Motores Verticales")

# [AQUÍ Sigue el menú principal con el Dashboard, Formulario e Historial]