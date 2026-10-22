"""ExplainIDS dashboard (Streamlit). Run: streamlit run dashboard/app.py

Talks to the API at EXPLAINIDS_API (default http://localhost:8000). The "Replay demo traffic"
button sends synthetic flows so the layout can be reviewed before real models exist.
"""
from __future__ import annotations

import os

import httpx
import pandas as pd
import plotly.express as px
import streamlit as st

from ids.synthetic import make_flows

API = os.environ.get("EXPLAINIDS_API", "http://localhost:8000")
HEADERS = {"X-API-Key": os.environ["EXPLAINIDS_API_KEY"]} if os.environ.get("EXPLAINIDS_API_KEY") else {}

st.set_page_config(page_title="ExplainIDS", layout="wide")
st.title("ExplainIDS")
st.caption("Explainable intrusion detection with candidate MITRE ATT&CK context. Alerts need analyst confirmation.")

with st.sidebar:
    st.header("Controls")
    if st.button("Replay demo traffic"):
        flows = make_flows(20, seed=int(pd.Timestamp.now().timestamp()) % 10_000).drop(columns=["Label"])
        httpx.post(f"{API}/predict", json={"flows": flows.to_dict("records")}, headers=HEADERS, timeout=60)
    severity = st.multiselect("Severity", ["Critical", "High", "Medium"], default=["Critical", "High", "Medium"])

try:
    alerts = httpx.get(f"{API}/alerts", headers=HEADERS, timeout=30).json()
    incidents = httpx.get(f"{API}/incidents", headers=HEADERS, timeout=30).json()
except httpx.HTTPError as exc:
    st.error(f"API not reachable at {API}: {exc}")
    st.stop()

df = pd.DataFrame(alerts)
k1, k2, k3, k4 = st.columns(4)
k1.metric("Alerts", len(df))
k2.metric("High or critical", int(df["severity"].isin(["High", "Critical"]).sum()) if len(df) else 0)
k3.metric("Aggregated incidents", len(incidents))
k4.metric("Outliers", int(df["outlier"].sum()) if len(df) else 0)

if df.empty:
    st.info("No alerts yet. Use 'Replay demo traffic' in the sidebar.")
    st.stop()

df = df[df["severity"].isin(severity)]
df["technique"] = df["attack"].map(lambda a: a.get("technique_id") or a.get("technique"))
left, right = st.columns([2, 1])
with left:
    st.subheader("Alert feed")
    st.dataframe(df[["time", "source", "predicted_class", "severity", "technique", "status"]], use_container_width=True, height=320)
    c1, c2 = st.columns(2)
    c1.plotly_chart(px.histogram(df, x="predicted_class", title="Attack distribution"), use_container_width=True)
    c2.plotly_chart(px.histogram(df, x="severity", title="Severity"), use_container_width=True)
with right:
    st.subheader("Alert detail")
    pick = st.selectbox("Alert", df["alert_id"], format_func=lambda i: df.set_index("alert_id").loc[i, "predicted_class"])
    a = df.set_index("alert_id").loc[pick]
    st.write(a["summary"])
    att = a["attack"]
    st.markdown(f"**ATT&CK (candidate):** {att.get('technique_id') or '-'} {att.get('technique')}  \n**Tactic:** {att.get('tactic')}")
    st.markdown(f"**Recommended response:** {att.get('guidance')}")
    if a["explanation"]:
        st.bar_chart(pd.DataFrame(a["explanation"]).set_index("feature")["contribution"])
    b1, b2 = st.columns(2)
    for col, status in ((b1, "confirmed"), (b2, "dismissed")):
        if col.button(status.title()):
            httpx.post(f"{API}/alerts/{pick}/status", params={"status": status}, headers=HEADERS, timeout=30)
            st.rerun()

st.subheader("Aggregated incidents")
st.dataframe(pd.DataFrame(incidents), use_container_width=True)
