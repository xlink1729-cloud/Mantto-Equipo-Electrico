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

# Inicializar tablas en Neon
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

    query_eventos = text("""
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
    """)

    with engine.begin() as conn:
        conn.execute(query_inspecciones)
        conn.execute(query_usuarios)
        conn.execute(query_eventos)
        
        # Crear usuario administrador por defecto si no hay usuarios
        res = conn.execute(text("SELECT COUNT(*) FROM usuarios;")).scalar()
        if res == 0:
            pass_default = hash_password("mantto2026")
            conn.execute(
                text("INSERT INTO usuarios (username, password_hash, nombre, rol) VALUES (:u, :p, :n, :r);"),
                {"u": "admin", "p": pass_default, "n": "Administrador Principal", "r": "admin"}
            )

inicializar_bd()

# ---------------------------------------------------------
# CONTROL DE SESIÓN BLOQUEANTE (FORZADO)
# ---------------------------------------------------------
if "sesion_valida" not in st.session_state:
    st.session_state["sesion_valida"] = False
    st.session_state["usuario_actual"] = None
    st.session_state["username_actual"] = None
    st.session_state["rol_actual"] = None

def login(usuario, password):
    pass_hash = hash_password(password)
    query = text("SELECT username, nombre, rol FROM usuarios WHERE username = :u AND password_hash = :p;")
    with engine.connect() as conn:
        result = conn.execute(query, {"u": usuario, "p": pass_hash}).fetchone()
        if result:
            st.session_state["sesion_valida"] = True
            st.session_state["username_actual"] = result.username
            st.session_state["usuario_actual"] = result.nombre
            st.session_state["rol_actual"] = result.rol
            return True
        return False

def logout():
    st.session_state["sesion_valida"] = False
    st.session_state["usuario_actual"] = None
    st.session_state["username_actual"] = None
    st.session_state["rol_actual"] = None
    st.rerun()

# ---------------------------------------------------------
# PANTALLA DE LOGIN (BLOQUEANTE)
# ---------------------------------------------------------
if not st.session_state["sesion_valida"]:
    st.title("🔒 Acceso al Sistema de Mantenimiento")
    st.caption("Ingresa con tus credenciales para continuar")

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

    st.stop()

# ---------------------------------------------------------
# BARRA LATERAL (NAVEGACIÓN)
# ---------------------------------------------------------
st.sidebar.markdown(f"### 👤 {st.session_state.usuario_actual}")
st.sidebar.caption(f"Rol: **{st.session_state.rol_actual.upper()}**")

if st.sidebar.button("🔴 Cerrar Sesión"):
    logout()

st.sidebar.markdown("---")

# Opciones del menú según el rol
opciones_menu = [
    "Dashboard de Operación", 
    "Nueva Inspección", 
    "Registro de Eventos", 
    "Historial de Mediciones", 
    "Mi Perfil"
]

if st.session_state.rol_actual == "admin":
    opciones_menu.append("Gestión de Usuarios")

opcion = st.sidebar.radio("Menú Principal", opciones_menu)

# ---------------------------------------------------------
# FUNCIONES AUXILIARES
# ---------------------------------------------------------
def calcular_desbalance(v1, v2, v3):
    promedio = (v1 + v2 + v3) / 3
    if promedio == 0:
        return 0.0
    max_desviacion = max(abs(v1 - promedio), abs(v2 - promedio), abs(v3 - promedio))
    return round((max_desviacion / promedio) * 100, 2)

def obtener_datos():
    query = "SELECT * FROM inspecciones_bombas ORDER BY fecha DESC, id DESC;"
    return pd.read_sql_query(query, engine)

def obtener_eventos():
    query = "SELECT * FROM registro_eventos ORDER BY fecha_hora DESC, id DESC;"
    return pd.read_sql_query(query, engine)

# ---------------------------------------------------------
# 1. DASHBOARD
# ---------------------------------------------------------
if opcion == "Dashboard de Operación":
    st.title("🌊 Monitoreo Eléctrico: Bombas y Motores Verticales")
    df = obtener_datos()

    if df.empty:
        st.info("Aún no hay registros en la base de datos. Agrega uno en 'Nueva Inspección'.")
    else:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Inspecciones", len(df))
        c2.metric("Sistemas Normales", len(df[df["estado"] == "Normal"]))
        c3.metric("En Advertencia", len(df[df["estado"] == "Advertencia"]))
        c4.metric("Estado Crítico", len(df[df["estado"] == "Crítico"]), delta_color="inverse")

        st.markdown("---")
        st.write("### Últimos Registros Guardados")
        st.dataframe(df, use_container_width=True)

# ---------------------------------------------------------
# 2. NUEVA INSPECCIÓN
# ---------------------------------------------------------
elif opcion == "Nueva Inspección":
    st.title("📋 Lectura Electromecánica en Campo")

    with st.form("form_bomba", clear_on_submit=True):
        col_info1, col_info2, col_info3 = st.columns(3)
        with col_info1:
            equipo = st.text_input("Identificador del Equipo / Pozo", value="Bomba Pozo 01")
        with col_info2:
            tipo_equipo = st.selectbox("Tipo de Motor", ["Sumergible", "Vertical (Eje Largo)", "Centrífuga Horizontal"])
        with col_info3:
            tecnico = st.text_input("Técnico Inspector", value=st.session_state.usuario_actual)

        st.markdown("#### ⚡ Voltajes Fase - Fase ($V_{FF}$)")
        vf_1, vf_2, vf_3 = st.columns(3)
        v_ab = vf_1.number_input("V_ab (V)", value=440.0)
        v_bc = vf_2.number_input("V_bc (V)", value=440.0)
        v_ca = vf_3.number_input("V_ca (V)", value=440.0)

        st.markdown("#### 📐 Voltajes Fase - Neutro / Tierra ($V_{FN}$)")
        vn_1, vn_2, vn_3, vn_4 = st.columns(4)
        v_an = vn_1.number_input("V_an (V)", value=254.0)
        v_bn = vn_2.number_input("V_bn (V)", value=254.0)
        v_cn = vn_3.number_input("V_cn (V)", value=254.0)
        v_n_tierra = vn_4.number_input("V Neutro - Tierra (V)", value=1.0)

        st.markdown("#### 🔌 Consumos de Corriente por Fase")
        i_col1, i_col2, i_col3 = st.columns(3)
        i_a = i_col1.number_input("Fase A (A)", value=50.0)
        i_b = i_col2.number_input("Fase B (A)", value=50.0)
        i_c = i_col3.number_input("Fase C (A)", value=50.0)

        observaciones = st.text_area("Observaciones adicionales")

        enviado = st.form_submit_button("Guardar Registro en Neon")

        if enviado:
            desb_v_ff = calcular_desbalance(v_ab, v_bc, v_ca)
            desb_v_fn = calcular_desbalance(v_an, v_bn, v_cn)
            desb_i = calcular_desbalance(i_a, i_b, i_c)

            if desb_v_ff > 2.0 or desb_v_fn > 2.0 or desb_i > 10.0 or v_n_tierra > 5.0:
                estado_eval = "Crítico"
            elif desb_v_ff > 1.0 or desb_v_fn > 1.0 or desb_i > 5.0 or v_n_tierra > 2.0:
                estado_eval = "Advertencia"
            else:
                estado_eval = "Normal"

            insert_query = text("""
            INSERT INTO inspecciones_bombas 
            (fecha, equipo, tipo, v_ab, v_bc, v_ca, desbalance_v_ff, v_an, v_bn, v_cn, desbalance_v_fn, i_a, i_b, i_c, desbalance_i, v_n_tierra, estado, tecnico, observaciones)
            VALUES 
            (:fecha, :equipo, :tipo, :v_ab, :v_bc, :v_ca, :desb_v_ff, :v_an, :v_bn, :v_cn, :desb_v_fn, :i_a, :i_b, :i_c, :desb_i, :v_n_tierra, :estado, :tecnico, :obs);
            """)

            datos_insertar = {
                "fecha": datetime.today().strftime('%Y-%m-%d'),
                "equipo": equipo,
                "tipo": tipo_equipo,
                "v_ab": v_ab, "v_bc": v_bc, "v_ca": v_ca,
                "desb_v_ff": desb_v_ff,
                "v_an": v_an, "v_bn": v_bn, "v_cn": v_cn,
                "desb_v_fn": desb_v_fn,
                "i_a": i_a, "i_b": i_b, "i_c": i_c,
                "desb_i": desb_i,
                "v_n_tierra": v_n_tierra,
                "estado": estado_eval,
                "tecnico": tecnico,
                "obs": observaciones
            }

            with engine.begin() as conn:
                conn.execute(insert_query, datos_insertar)

            st.success(f"✅ Registro guardado exitosamente. Estado evaluado: **{estado_eval}**.")

# ---------------------------------------------------------
# 3. REGISTRO DE EVENTOS
# ---------------------------------------------------------
elif opcion == "Registro de Eventos":
    st.title("🚨 Bitácora y Registro de Eventos")

    with st.expander("➕ Registrar Nuevo Evento / Incidente", expanded=True):
        with st.form("form_evento", clear_on_submit=True):
            col1, col2 = st.columns(2)

            with col1:
                equipo_ev = st.text_input("Equipo / Motor Afectado", value="Bomba Pozo 01")
                tipo_ev = st.selectbox(
                    "Tipo de Evento",
                    [
                        "Desconexión por daño mecánico",
                        "Falla eléctrica / Sobrevoltaje",
                        "Paro de emergencia",
                        "Mantenimiento no programado",
                        "Fuga o Sobrecalentamiento",
                        "Otro"
                    ]
                )
                severidad_ev = st.select_slider(
                    "Nivel de Severidad",
                    options=["Baja", "Media", "Alta", "Crítica"]
                )

            with col2:
                descripcion_ev = st.text_area("Descripción / Causa Raíz", placeholder="Detalla qué sucedió exactamente...")
                accion_ev = st.text_input("Acción Inmediata Tomada", placeholder="Ej. Se aisló el equipo y notificó...")
                estatus_ev = st.selectbox("Estatus del Evento", ["Abierto", "En Revisión", "Resuelto"])

            btn_evento = st.form_submit_button("Guardar Evento en BD")

            if btn_evento:
                q_ins_ev = text("""
                INSERT INTO registro_eventos (fecha_hora, equipo, tipo_evento, severidad, descripcion, accion_tomada, estatus, reportado_por)
                VALUES (:fh, :eq, :te, :sev, :desc, :acc, :est, :rep);
                """)
                
                params_ev = {
                    "fh": datetime.now(),
                    "eq": equipo_ev,
                    "te": tipo_ev,
                    "sev": severidad_ev,
                    "desc": descripcion_ev,
                    "acc": accion_ev,
                    "est": estatus_ev,
                    "rep": st.session_state.usuario_actual
                }

                with engine.begin() as conn:
                    conn.execute(q_ins_ev, params_ev)

                st.success("✅ Evento registrado exitosamente en la base de datos.")

    st.markdown("---")

    # Mostrar Bitácora Completa
    st.subheader("📋 Bitácora de Eventos Registrados")
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

# ---------------------------------------------------------
# 4. HISTORIAL DE MEDICIONES
# ---------------------------------------------------------
elif opcion == "Historial de Mediciones":
    st.title("📊 Historial de Mediciones")
    df = obtener_datos()
    st.dataframe(df, use_container_width=True)

# ---------------------------------------------------------
# 5. MI PERFIL (CAMBIO DE CONTRASEÑA)
# ---------------------------------------------------------
elif opcion == "Mi Perfil":
    st.title("👤 Configuración de Perfil")
    st.write(f"**Nombre:** {st.session_state.usuario_actual}")
    st.write(f"**Usuario:** {st.session_state.username_actual}")
    
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
                update_q = text("""
                    UPDATE usuarios 
                    SET password_hash = :p 
                    WHERE username = :u AND password_hash = :pa;
                """)
                with engine.begin() as conn:
                    res = conn.execute(update_q, {
                        "p": hash_password(pass_nueva),
                        "u": st.session_state.username_actual,
                        "pa": hash_password(pass_actual)
                    })
                    if res.rowcount > 0:
                        st.success("✅ Contraseña actualizada correctamente.")
                    else:
                        st.error("❌ La contraseña actual es incorrecta.")

# ---------------------------------------------------------
# 6. GESTIÓN DE USUARIOS (SOLO ADMINISTRADOR)
# ---------------------------------------------------------
elif opcion == "Gestión de Usuarios" and st.session_state.rol_actual == "admin":
    st.title("⚙️ Administración de Usuarios")

    col_crear, col_lista = st.columns([1, 1])

    with col_crear:
        st.subheader("➕ Registrar Nuevo Usuario")
        with st.form("form_nuevo_usuario", clear_on_submit=True):
            nuevo_user = st.text_input("Nombre de usuario (ej. jsmith)")
            nuevo_nombre = st.text_input("Nombre Completo (ej. Juan Smith)")
            nuevo_pass = st.text_input("Contraseña", type="password")
            nuevo_rol = st.selectbox("Rol de Acceso", ["tecnico", "admin"])
            
            btn_crear = st.form_submit_button("Crear Usuario")

            if btn_crear:
                if not nuevo_user or not nuevo_pass or not nuevo_nombre:
                    st.warning("Todos los campos son obligatorios.")
                else:
                    try:
                        q_insert = text("""
                        INSERT INTO usuarios (username, password_hash, nombre, rol)
                        VALUES (:u, :p, :n, :r);
                        """)
                        with engine.begin() as conn:
                            conn.execute(q_insert, {
                                "u": nuevo_user,
                                "p": hash_password(nuevo_pass),
                                "n": nuevo_nombre,
                                "r": nuevo_rol
                            })
                        st.success(f"Usuario '{nuevo_user}' creado exitosamente.")
                    except Exception as e:
                        st.error("Error al crear usuario (quizá el nombre de usuario ya existe).")

    with col_lista:
        st.subheader("👥 Usuarios Registrados")
        usuarios_df = pd.read_sql_query("SELECT id, username, nombre, rol FROM usuarios;", engine)
        st.dataframe(usuarios_df, use_container_width=True)