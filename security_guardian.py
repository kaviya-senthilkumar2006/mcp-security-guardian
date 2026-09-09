import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime


# ==========================================
# MCP TOOL PERMISSION POLICY
# ==========================================

ALLOWED_TOOLS = {
    "read_public_file": True,
    "read_confidential_file": False,
    "delete_file": False,
    "send_email": False
}


# ==========================================
# RISK CALCULATION
# ==========================================

def calculate_risk(tool_name, permission_allowed):

    dangerous_tools = {
        "delete_file": 50,
        "send_email": 40,
        "read_confidential_file": 60
    }

    # Base risk
    risk_score = dangerous_tools.get(tool_name, 10)

    # Increase risk if permission is denied
    if not permission_allowed:
        risk_score += 30

    # Maximum risk = 100
    risk_score = min(risk_score, 100)

    # Risk level
    if risk_score >= 70:
        risk_level = "CRITICAL"

    elif risk_score >= 50:
        risk_level = "HIGH"

    elif risk_score >= 30:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return risk_score, risk_level


# ==========================================
# MACHINE LEARNING ANOMALY DETECTOR
# ==========================================

normal_events = []

# Normal activity
for _ in range(40):
    normal_events.append([10, 0])

# Slightly higher but still normal activity
for _ in range(10):
    normal_events.append([20, 0])


training_df = pd.DataFrame(
    normal_events,
    columns=[
        "risk_score",
        "permission_denied"
    ]
)


# Train Isolation Forest
anomaly_model = IsolationForest(
    contamination=0.1,
    random_state=42
)

anomaly_model.fit(
    training_df[
        [
            "risk_score",
            "permission_denied"
        ]
    ]
)


# ==========================================
# MAIN SECURITY GUARDIAN
# ==========================================

def security_guardian(agent_id, tool_name):

    # --------------------------------------
    # 1. Check permission
    # --------------------------------------

    permission_allowed = ALLOWED_TOOLS.get(
        tool_name,
        False
    )


    # --------------------------------------
    # 2. Calculate risk
    # --------------------------------------

    risk_score, risk_level = calculate_risk(
        tool_name,
        permission_allowed
    )


    # --------------------------------------
    # 3. Prepare ML input
    # --------------------------------------

    permission_denied = (
        0 if permission_allowed else 1
    )


    ml_input = pd.DataFrame(
        [[
            risk_score,
            permission_denied
        ]],
        columns=[
            "risk_score",
            "permission_denied"
        ]
    )


    # --------------------------------------
    # 4. Detect anomaly
    # --------------------------------------

    prediction = anomaly_model.predict(
        ml_input
    )[0]


    if prediction == -1:
        ml_status = "ANOMALY"

    else:
        ml_status = "NORMAL"


    # --------------------------------------
    # 5. Make security decision
    # --------------------------------------

    if (
        risk_score >= 70
        or ml_status == "ANOMALY"
    ):
        action = "BLOCK"

    elif risk_score >= 50:
        action = "REVIEW"

    else:
        action = "ALLOW"


    # --------------------------------------
    # 6. Return security report
    # --------------------------------------

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
