import time
import pandas as pd
import streamlit as st
from scorer import score_window

st.set_page_config(
    page_title="AI DDoS Sentinel Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("Dual-Engine DDoS Sentinel (Real-Time Detection & XAI)")
st.caption("Stage 1: Isolation Forest (Zero-Day Discovery) | Stage 2: Random Forest (Sub-Type Classification) | TreeSHAP Explainability")


kpi1, kpi2, kpi3, kpi4 = st.columns(4)
metric_total = kpi1.empty()
metric_critical = kpi2.empty()
metric_zeroday = kpi3.empty()
metric_normal = kpi4.empty()

metric_total.metric("Windows Analyzed", "0")
metric_critical.metric("Critical Attacks", "0", delta_color="inverse")  
metric_zeroday.metric("Zero-Day Anomalies", "0", delta_color="inverse")
metric_normal.metric("Benign Traffic", "0")

st.divider()

col_stream, col_alert = st.columns([1.1, 1.4])

with col_stream:
    st.subheader("Ingested Traffic Stream (5-Second Windows)")
    stream_placeholder = st.empty()

with col_alert:
    st.subheader("Dual-Engine Alert & Explainability (XAI)")
    alert_placeholder = st.empty()

if st.button("Start Live Network Monitor", type="primary"):
    total_count, critical_count, zeroday_count, normal_count = 0, 0, 0, 0
    stream_history = []
    last_processed_idx = -1
    
    st.toast("Listening for live traffic...")

    while True:
        try:
            df_live = pd.read_csv("live_stream.csv")
            
            if len(df_live) - 1 > last_processed_idx:
                last_processed_idx += 1
                row = df_live.iloc[last_processed_idx]
                
                features = row.to_dict()
                verdict = score_window(features)

                total_count += 1
                stream_history.append(features)
                stream_placeholder.dataframe(pd.DataFrame(stream_history[-8:]), width=1200, height=320)
                
                with alert_placeholder.container():
                    if verdict["is_alert"]:
                        severity = verdict["severity"]
                        threat = verdict["threat_class"]

                        if severity in ["critical", "high"]:
                            critical_count += 1
                            st.error(f"🚨 **CRITICAL THREAT DETECTED: {threat.upper()}**\n\n- **Confidence:** {verdict['confidence_score']:.2f}")
                            chart_df = pd.DataFrame(list(verdict["supporting_evidence"].items()), columns=["Feature", "Weight"]).set_index("Feature")
                            st.bar_chart(chart_df, height=180)
                        else:
                            zeroday_count += 1
                            st.warning(f"⚠️ **ZERO-DAY ANOMALY DETECTED: {threat.upper()}**\n\n- **Anomaly Score:** {verdict['anomaly_score']:.3f}")
                            chart_df = pd.DataFrame(list(verdict["supporting_evidence"].items()), columns=["Feature", "Sigma"]).set_index("Feature")
                            st.bar_chart(chart_df, height=180)
                    else:
                        normal_count += 1
                        st.success(f"✅ **NORMAL TRAFFIC** | Anomaly Score: {verdict['anomaly_score']:.3f}")

                metric_total.metric("Windows Analyzed", total_count)
                metric_critical.metric("Critical Attacks", critical_count)
                metric_zeroday.metric("Zero-Day Anomalies", zeroday_count)
                metric_normal.metric("Benign Traffic", normal_count)

        except FileNotFoundError:
            pass 
        time.sleep(1) 