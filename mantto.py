import streamlit as st
import pandas as pd
from datetime import datetime

st.set_page_config(
    page_title="Mantenimiento Bombas & Motores",
    page_icon="🌊",
    layout="wide"
)

# Base de datos simulada en memoria
if "registros_bombas" not in st.session_state:
    st.session_state.registros_bombas = pd.DataFrame([
        {
            "Fecha": "2026-07-28",
            "Equipo": "Bomba Sumergible Pozo 01",
            "Tipo": "Sumergible",
            "V_ab": 440, "V_bc": 442, "V_ca": 438,
            "Desbalance V (%)": 0.45,
            "I_a": 85.0, "I_b": 86.5, "I_c": 84.5,
            "Desbalance I (%)": 1.4,
            "Vn (V)": 1.2,
            "Aislamiento (MΩ)": 150.0,
            "Estado": "Normal",
            "Técnico": "Carlos R."
        },
        {
            "Fecha": "2026-07-30",
            "Equipo": "Motor Vertical Turbina MV-02",
            "Tipo": "Vertical",
            "V_ab": 440, "V_bc": 420, "V_ca": 445,
            "Desbalance V (%)": 3.4,
            "I_a": 110.0, "I_b": 128.0, "I_c": 112.0,
            "Desbalance I (%)": 9.7,
            "Vn (V)": 4.5,
            "Aislamiento (MΩ)": 8.5,
            "Estado": "Crítico",
            "Técnico": "Ana P."
        }
    ])

st.title("🌊 Monitoreo Eléctrico: Bombas y Motores Verticales")

opcion = st.sidebar.radio(
    "Menú",
    ["Dashboard de Operación", "Nueva Inspección", "Historial de Mediciones"]
)

# ---------------------------------------------------------
# FUNCIONES AUXILIARES DE CÁLCULO
# ---------------------------------------------------------
def calcular_desbalance(v1, v2, v3):
    promedio = (v1 + v2 + v3) / 3
    if promedio == 0:
        return 0.0
    max_desviacion = max(abs(v1 - promedio), abs(v2 - promedio), abs(v3 - promedio))
    return round((max_desviacion / promedio) * 100, 2)

# ---------------------------------------------------------
# 1. DASHBOARD
# ---------------------------------------------------------
if opcion == "Dashboard de Operación":
    st.subheader("Indicadores Generales del Sistema")
    df = st.session_state.registros_bombas

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Inspecciones", len(df))
    c2.metric("Sistemas Normales", len(df[df["Estado"] == "Normal"]))
    c3.metric("En Advertencia", len(df[df["Estado"] == "Advertencia"]))
    c4.metric("Estado Crítico", len(df[df["Estado"] == "Crítico"]), delta_color="inverse")

    st.markdown("---")
    st.write("### Resumen de Equipos Medidos")
    st.dataframe(df, use_container_width=True)

# ---------------------------------------------------------
# 2. NUEVA INSPECCIÓN
# ---------------------------------------------------------
elif opcion == "Nueva Inspección":
    st.subheader("Lectura Electromecánica en Campo")

    with st.form("form_bomba", clear_on_submit=True):
        col_info1, col_info2, col_info3 = st.columns(3)
        with col_info1:
            equipo = st.text_input("Identificador del Equipo / Pozo", value="Bomba Pozo 02")
        with col_info2:
            tipo_equipo = st.selectbox("Tipo de Motor", ["Sumergible", "Vertical (Eje Largo)", "Centrífuga Horizontal"])
        with col_info3:
            tecnico = st.text_input("Técnico Inspector")

        st.markdown("#### ⚡ Lecturas de Voltaje (Fase - Fase y Neutro)")
        v_col1, v_col2, v_col3, v_col4 = st.columns(4)
        with v_col1:
            v_ab = st.number_input("V_ab (V)", value=440.0)
        with v_col2:
            v_bc = st.number_input("V_bc (V)", value=440.0)
        with v_col3:
            v_ca = st.number_input("V_ca (V)", value=440.0)
        with v_col4:
            v_n = st.number_input("V_n / Neutro (V)", value=1.0)

        st.markdown("#### 🔌 Consumos de Corriente por Fase y Aislamiento")
        i_col1, i_col2, i_col3, i_col4 = st.columns(4)
        with i_col1:
            i_a = st.number_input("Fase A (A)", value=50.0)
        with i_col2:
            i_b = st.number_input("Fase B (A)", value=50.0)
        with i_col3:
            i_c = st.number_input("Fase C (A)", value=50.0)
        with i_col4:
            aislamiento = st.number_input("Aislamiento Megger (MΩ)", value=100.0, help="Lectura de aislamiento a tierra")

        enviado = st.form_submit_button("Calcular Indicadores y Guardar")

        if enviado:
            # Cálculos automáticos
            desb_v = calcular_desbalance(v_ab, v_bc, v_ca)
            desb_i = calcular_desbalance(i_a, i_b, i_c)

            # Evaluación de criterios de seguridad (Ejemplo NEMA)
            # - Desbalance V > 2% o Desbalance I > 10% o Megger < 10MΩ -> Crítico
            # - Desbalance V > 1% o Desbalance I > 5% o Megger < 50MΩ -> Advertencia
            if desb_v > 2.0 or desb_i > 10.0 or aislamiento < 10.0:
                estado_eval = "Crítico"
            elif desb_v > 1.0 or desb_i > 5.0 or aislamiento < 50.0:
                estado_eval = "Advertencia"
            else:
                estado_eval = "Normal"

            nuevo_reg = {
                "Fecha": datetime.today().strftime('%Y-%m-%d'),
                "Equipo": equipo,
                "Tipo": tipo_equipo,
                "V_ab": v_ab, "V_bc": v_bc, "V_ca": v_ca,
                "Desbalance V (%)": desb_v,
                "I_a": i_a, "I_b": i_b, "I_c": i_c,
                "Desbalance I (%)": desb_i,
                "Vn (V)": v_n,
                "Aislamiento (MΩ)": aislamiento,
                "Estado": estado_eval,
                "Técnico": tecnico
            }

            st.session_state.registros_bombas = pd.concat(
                [st.session_state.registros_bombas, pd.DataFrame([nuevo_reg])],
                ignore_index=True
            )

            # Mostrar alertas al guardar
            if estado_eval == "Crítico":
                st.error(f"⚠️ **Atención:** El registro indica un estado **CRÍTICO**. Desbalance de Voltaje: {desb_v}%, Desbalance de Corriente: {desb_i}%, Megger: {aislamiento} MΩ.")
            elif estado_eval == "Advertencia":
                st.warning(f"⚡ **Advertencia:** Parámetros fuera de rango óptimo. Desbalance V: {desb_v}%, Desbalance I: {desb_i}%.")
            else:
                st.success("✅ Registro guardado. Todos los valores están dentro del rango operativo seguro.")

# ---------------------------------------------------------
# 3. HISTORIAL
# ---------------------------------------------------------
elif opcion == "Historial de Mediciones":
    st.subheader("Consultar Registros")
    st.dataframe(st.session_state.registros_bombas, use_container_width=True)