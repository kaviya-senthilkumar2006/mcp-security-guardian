
import streamlit as st
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest


# ============================================================
# PAGE SETTINGS
# ============================================================

st.set_page_config(
    page_title="MCP Security Guardian",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# SECURITY POLICY
# ============================================================

ALLOWED_TOOLS = {
    "read_public_file": True,
    "read_confidential_file": False,
    "delete_file": False,
    "send_email": False
}


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_risk(tool_name, permission_allowed):

    dangerous_tools = {
        "delete_file": 50,
        "send_email": 40,
        "read_confidential_file": 60
    }

    risk_score = dangerous_tools.get(tool_name, 10)

    if not permission_allowed:
        risk_score += 30

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return risk_score, risk_level


# ============================================================
# ML ANOMALY DETECTION
# ============================================================

normal_events = []

for _ in range(40):
    normal_events.append([10, 0])

for _ in range(10):
    normal_events.append([20, 0])

training_df = pd.DataFrame(
    normal_events,
    columns=["risk_score", "permission_denied"]
)

anomaly_model = IsolationForest(
    contamination=0.1,
    random_state=42
)

anomaly_model.fit(
    training_df[["risk_score", "permission_denied"]]
)


# ============================================================
# SECURITY GUARDIAN
# ============================================================

def security_guardian(agent_id, tool_name):

    permission_allowed = ALLOWED_TOOLS.get(
        tool_name,
        False
    )

    risk_score, risk_level = calculate_risk(
        tool_name,
        permission_allowed
    )

    permission_denied = (
        0 if permission_allowed else 1
    )

    ml_input = pd.DataFrame(
        [[risk_score, permission_denied]],
        columns=[
            "risk_score",
            "permission_denied"
        ]
    )

    prediction = anomaly_model.predict(
        ml_input
    )[0]

    ml_status = (
        "ANOMALY"
        if prediction == -1
        else "NORMAL"
    )

    if risk_score >= 70 or ml_status == "ANOMALY":
        action = "BLOCK"

    elif risk_score >= 50:
        action = "REVIEW"

    else:
        action = "ALLOW"

    return {
        "time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "agent": agent_id,
        "tool": tool_name,
        "permission": permission_allowed,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "ml_status": ml_status,
        "action": action
    }


# ============================================================
# SESSION LOG
# ============================================================

if "security_logs" not in st.session_state:

    st.session_state.security_logs = [
        {
            "time": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "agent": "agent_01",
            "tool": "read_public_file",
            "permission": True,
            "risk_score": 10,
            "risk_level": "LOW",
            "ml_status": "NORMAL",
            "action": "ALLOW"
        }
    ]


# ============================================================
# TITLE
# ============================================================

st.title("🛡️ MCP Security Guardian")

st.subheader(
    "Agentic AI Security Monitoring System"
)

st.markdown(
    """
    The MCP Security Guardian monitors AI agent
    tool usage, calculates risk, detects anomalies
    and makes security decisions.
    """
)


# ============================================================
# TOOL TESTING PANEL
# ============================================================

st.divider()

st.header("🔍 Test MCP Tool Activity")

col1, col2 = st.columns(2)

with col1:

    agent_id = st.selectbox(
        "Select AI Agent",
        [
            "agent_01",
            "agent_02",
            "agent_03"
        ]
    )


with col2:

    tool_name = st.selectbox(
        "Select MCP Tool",
        [
            "read_public_file",
            "read_confidential_file",
            "delete_file",
            "send_email"
        ]
    )


if st.button(
    "🛡️ Analyze Tool Activity",
    use_container_width=True
):

    result = security_guardian(
        agent_id,
        tool_name
    )

    st.session_state.security_logs.append(
        result
    )

    if result["action"] == "BLOCK":

        st.error(
            f"🚨 ACTION BLOCKED\n\n"
            f"Tool: {tool_name}\n\n"
            f"Risk Score: {result['risk_score']}\n\n"
            f"Risk Level: {result['risk_level']}\n\n"
            f"ML Status: {result['ml_status']}"
        )

    elif result["action"] == "REVIEW":

        st.warning(
            f"⚠️ HUMAN REVIEW REQUIRED\n\n"
            f"Tool: {tool_name}\n\n"
            f"Risk Score: {result['risk_score']}"
        )

    else:

        st.success(
            f"✅ ACTION ALLOWED\n\n"
            f"Tool: {tool_name}\n\n"
            f"Risk Score: {result['risk_score']}"
        )


# ============================================================
# CREATE DATAFRAME
# ============================================================

df = pd.DataFrame(
    st.session_state.security_logs
)


# ============================================================
# DASHBOARD METRICS
# ============================================================

st.divider()

st.header("📊 Security Dashboard")

total_events = len(df)

threats = len(
    df[df["ml_status"] == "ANOMALY"]
)

blocked = len(
    df[df["action"] == "BLOCK"]
)

average_risk = round(
    df["risk_score"].mean(),
    2
)


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Events",
    total_events
)

col2.metric(
    "🚨 Threats",
    threats
)

col3.metric(
    "🔒 Blocked",
    blocked
)

col4.metric(
    "📊 Average Risk",
    average_risk
)


# ============================================================
# SECURITY EVENTS TABLE
# ============================================================

st.divider()

st.header("🔍 Security Events")

st.dataframe(
    df,
    use_container_width=True
)


# ============================================================
# RISK CHART
# ============================================================

st.header("📈 Risk Scores")

chart_data = df[
    ["tool", "risk_score"]
].copy()

chart_data = chart_data.set_index(
    "tool"
)

st.bar_chart(
    chart_data
)


# ============================================================
# SECURITY ALERTS
# ============================================================

st.header("🚨 Security Alerts")

for _, row in df.iterrows():

    if row["action"] == "BLOCK":

        st.error(
            f"🚨 BLOCKED: {row['agent']} attempted "
            f"to use `{row['tool']}` | "
            f"Risk Score: {row['risk_score']} | "
            f"ML: {row['ml_status']}"
        )

    elif row["action"] == "REVIEW":

        st.warning(
            f"⚠️ REVIEW: {row['agent']} attempted "
            f"to use `{row['tool']}` | "
            f"Risk Score: {row['risk_score']}"
        )

    else:

        st.success(
            f"✅ ALLOWED: {row['agent']} used "
            f"`{row['tool']}` | "
            f"Risk Score: {row['risk_score']}"
        )


# ============================================================
# RESET BUTTON
# ============================================================

st.divider()

if st.button("🗑️ Clear Security Logs"):

    st.session_state.security_logs = []

    st.rerun()
