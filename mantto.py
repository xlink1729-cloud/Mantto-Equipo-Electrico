import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy import create_engine, text

st.set_page_config(
    page_title="Mantenimiento Bombas & Motores",
    page_icon="🌊",
    layout="wide"
)

# ---------------------------------------------------------
# CONEXIÓN A LA BASE DE DATOS (NEON POSTGRESQL)
# ---------------------------------------------------------
@st.cache_resource
def get_db_engine():
    # Obtiene la URL guardada en st.secrets
    db_url = st.secrets["postgres"]["url"]
    return create_engine(db_url)

engine = get_db_engine()

# Inicializar tabla en Neon si no existe
def inicializar_bd():
    query = text("""
    CREATE TABLE IF NOT EXISTS inspecciones_bombas (
        id SERIAL PRIMARY KEY,
        fecha DATE,
        equipo VARCHAR(100),
        tipo VARCHAR(50),
        v_ab FLOAT, v_bc FLOAT, v_ca FLOAT,
        desbalance_v FLOAT,
        i_a FLOAT, i_b FLOAT, i_c FLOAT,
        desbalance_i FLOAT,
        v_n FLOAT,
        aislamiento_megger FLOAT,
        estado VARCHAR(20),
        tecnico VARCHAR(100),
        observaciones TEXT
    );
    """)
    with engine.begin() as conn:
        conn.execute(query)

inicializar_bd()

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

# ---------------------------------------------------------
# INTERFAZ
# ---------------------------------------------------------
st.title("🌊 Monitoreo Eléctrico: Bombas y Motores Verticales")

opcion = st.sidebar.radio(
    "Menú",
    ["Dashboard de Operación", "Nueva Inspección", "Historial de Mediciones"]
)

# 1. DASHBOARD
if opcion == "Dashboard de Operación":
    st.subheader("Indicadores Generales del Sistema (Base de Datos Neon)")
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

# 2. NUEVA INSPECCIÓN
elif opcion == "Nueva Inspección":
    st.subheader("Lectura Electromecánica en Campo")

    with st.form("form_bomba", clear_on_submit=True):
        col_info1, col_info2, col_info3 = st.columns(3)
        with col_info1:
            equipo = st.text_input("Identificador del Equipo / Pozo", value="Bomba Pozo 01")
        with col_info2:
            tipo_equipo = st.selectbox("Tipo de Motor", ["Sumergible", "Vertical (Eje Largo)", "Centrífuga Horizontal"])
        with col_info3:
            tecnico = st.text_input("Técnico Inspector")

        # VOLTAJES FASE A FASE
        st.markdown("#### ⚡ Voltajes Fase - Fase ($V_{FF}$)")
        vf_1, vf_2, vf_3 = st.columns(3)
        v_ab = vf_1.number_input("V_ab (V)", value=440.0)
        v_bc = vf_2.number_input("V_bc (V)", value=440.0)
        v_ca = vf_3.number_input("V_ca (V)", value=440.0)

        # VOLTAJES FASE A NEUTRO / TIERRA
        st.markdown("#### 📐 Voltajes Fase - Neutro / Tierra ($V_{FN}$)")
        vn_1, vn_2, vn_3, vn_4 = st.columns(4)
        v_an = vn_1.number_input("V_an (V)", value=254.0)
        v_bn = vn_2.number_input("V_bn (V)", value=254.0)
        v_cn = vn_3.number_input("V_cn (V)", value=254.0)
        v_n_tierra = vn_4.number_input("V Neutro - Tierra (V)", value=1.0, help="Diferencia de potencial entre neutro y tierra física")

        st.markdown("#### 🔌 Consumos de Corriente por Fase y Aislamiento")
        i_col1, i_col2, i_col3, i_col4 = st.columns(4)
        i_a = i_col1.number_input("Fase A (A)", value=50.0)
        i_b = i_col2.number_input("Fase B (A)", value=50.0)
        i_c = i_col3.number_input("Fase C (A)", value=50.0)
        aislamiento = i_col4.number_input("Aislamiento Megger (MΩ)", value=100.0)

        observaciones = st.text_area("Observaciones adicionales")

        enviado = st.form_submit_button("Guardar en Base de Datos Neon")

        if enviado:
            desb_v = calcular_desbalance(v_ab, v_bc, v_ca)
            desb_i = calcular_desbalance(i_a, i_b, i_c)

            if desb_v > 2.0 or desb_i > 10.0 or aislamiento < 10.0:
                estado_eval = "Crítico"
            elif desb_v > 1.0 or desb_i > 5.0 or aislamiento < 50.0:
                estado_eval = "Advertencia"
            else:
                estado_eval = "Normal"

            # Insertar registro directamente en Neon
            insert_query = text("""
            INSERT INTO inspecciones_bombas 
            (fecha, equipo, tipo, v_ab, v_bc, v_ca, desbalance_v, i_a, i_b, i_c, desbalance_i, v_n, aislamiento_megger, estado, tecnico, observaciones)
            VALUES 
            (:fecha, :equipo, :tipo, :v_ab, :v_bc, :v_ca, :desb_v, :i_a, :i_b, :i_c, :desb_i, :v_n, :aislamiento, :estado, :tecnico, :obs);
            """)

            datos_insertar = {
                "fecha": datetime.today().strftime('%Y-%m-%d'),
                "equipo": equipo,
                "tipo": tipo_equipo,
                "v_ab": v_ab, "v_bc": v_bc, "v_ca": v_ca,
                "desb_v": desb_v,
                "i_a": i_a, "i_b": i_b, "i_c": i_c,
                "desb_i": desb_i,
                "v_n": v_n,
                "aislamiento": aislamiento,
                "estado": estado_eval,
                "tecnico": tecnico,
                "obs": observaciones
            }

            with engine.begin() as conn:
                conn.execute(insert_query, datos_insertar)

            st.success(f"✅ Registro guardado permanentemente en Neon para '{equipo}'. Estado: {estado_eval}.")

# 3. HISTORIAL
elif opcion == "Historial de Mediciones":
    st.subheader("Consultar Registros")
    df = obtener_datos()
    st.dataframe(df, use_container_width=True)