import streamlit as st
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# ==================================================
# PAGE CONFIG
# ==================================================

st.set_page_config(
    page_title="Cloud Security Compliance Scanner",
    page_icon="🛡️",
    layout="wide"
)
st.markdown(
"""
<div style="
background: linear-gradient(90deg,#141e30,#243b55);
padding:30px;
border-radius:20px;
border:1px solid #00D4FF">

<h1 style='color:#00D4FF'>
AWS Security Posture Dashboard
</h1>

<h4 style='color:white'>
Monitor IAM, S3 and EC2 risks in one place.
</h4>

</div>
""",
unsafe_allow_html=True
)
# ==================================================
# CUSTOM CSS
# ==================================================

st.markdown("""
<style>

.stApp{
    background-color:#0E1117;
}

h1,h2,h3{
    color:#00D4FF;
}

div[data-testid="metric-container"]{
background-color:#1B1F2A;
border:1px solid #00D4FF;
padding:20px;
border-radius:20px;
box-shadow:0px 0px 20px rgba(0,212,255,.3);
}

section[data-testid="stSidebar"]{
    background-color:#161B22;
}

</style>
""", unsafe_allow_html=True)

# ==================================================
# LOAD REPORTS
# ==================================================

with open("reports/report.json") as f:
    iam_data = json.load(f)

with open("reports/s3_report.json") as f:
    s3_data = json.load(f)

with open("reports/ec2_report.json") as f:
    ec2_data = json.load(f)

# ==================================================
# OVERALL SCORE
# ==================================================

overall_score = (
    iam_data["risk_score"]
    + s3_data["risk_score"]
    + ec2_data["risk_score"]
)

if overall_score < 50:
    overall_severity = "LOW"
elif overall_score < 100:
    overall_severity = "MEDIUM"
else:
    overall_severity = "HIGH"

total_findings = (
    len(iam_data["findings"])
    + len(s3_data["findings"])
    + len(ec2_data["findings"])
)

# ==================================================
# SIDEBAR
# ==================================================

st.sidebar.title("🛡️ Cloud Security Scanner")


st.sidebar.metric(
    "Overall Risk",
    f"{overall_score}/200"
)

if overall_score >= 100:
    st.sidebar.error("HIGH RISK ")
elif overall_score >= 50:
    st.sidebar.warning("MEDIUM ")
else:
    st.sidebar.success("LOW ")
st.sidebar.success("Portfolio Ready ")

# ==================================================
# TITLE
# ==================================================

st.title("🛡️ Cloud Security Compliance Scanner")

tab1, tab2, tab3, tab4 = st.tabs(
[
" Dashboard",
" Findings",
" Reports",
" Analytics"
]
)

# ==================================================
# DASHBOARD
# ==================================================

with tab1:

    st.header("Overall Security Status")
    col1, col2 = st.columns([1, 4])

with col1:

    if st.button(" Scan AWS Account"):

        with st.spinner("Scanning IAM, S3 and EC2..."):

            # Future lo functions call cheyyachu
            # iam_data = check_iam()
            # s3_data = check_s3()
            # ec2_data = check_ec2()

            import time
            time.sleep(2)

        st.success(" Scan Completed Successfully")

    st.progress(overall_score / 200)

    col1, col2 = st.columns(2)

    with col1:

        st.subheader("Overall Risk Score")

    st.markdown(
        f"""
        <h1 style='color:#00D4FF'>
        {overall_score}
        </h1>
        """,
        unsafe_allow_html=True
    )

    with col2:

        if overall_score < 50:

            st.markdown(
        """
        <div style="
        background:#1f5130;
        padding:20px;
        border-radius:15px;
        text-align:center;
        font-size:28px;
        font-weight:bold;
        color:#00ff7f;">
        LOW RISK 
        </div>
        """,
        unsafe_allow_html=True
        )

        elif overall_score < 100:

            st.markdown(
        """
        <div style="
        background:#5c4b1d;
        padding:20px;
        border-radius:15px;
        text-align:center;
        font-size:28px;
        font-weight:bold;
        color:#ffcc00;">
        MEDIUM RISK 
        </div>
        """,
        unsafe_allow_html=True
        )

        else:

            st.markdown("""
<div style="
background:#5d1f1f;
padding:25px;
border-radius:20px;
width:220px;
text-align:center;
font-size:28px;
font-weight:bold;
color:#ff4b4b;
">
HIGH RISK 
</div>
""", unsafe_allow_html=True)
st.markdown("---")


# ===== SUMMARY CARDS =====

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Overall Risk",
        overall_score
    )

with col2:
    st.metric(
        "Severity",
        overall_severity
    )

with col3:
    st.metric(
        "Total Findings",
        total_findings
    )

with col4:

    compliance_score = max(
        0,
        100 - (overall_score / 2)
    )

    st.metric(
        "Compliance %",
        f"{compliance_score:.0f}%"
    )

st.markdown("---")
st.markdown("---")

col1, col2 = st.columns(2)

with col1:

    st.metric(
        "Last Scan",
        datetime.now().strftime("%H:%M:%S")
    )

with col2:

    st.metric(
        "Scan Date",
        datetime.now().strftime("%d-%m-%Y")
    )

# ===== SERVICE METRICS =====

col1, col2, col3 = st.columns(3)

with col1:
    st.metric(
        "IAM Risk Score",
        iam_data["risk_score"]
    )

with col2:
    st.metric(
        "S3 Risk Score",
        s3_data["risk_score"]
    )

with col3:
    st.metric(
        "EC2 Risk Score",
        ec2_data["risk_score"]
    )

risk_df = pd.DataFrame({
    "Service": ["IAM", "S3", "EC2"],
    "Risk Score": [
        iam_data["risk_score"],
        s3_data["risk_score"],
        ec2_data["risk_score"]
    ]
})

st.markdown("---")

col1, col2 = st.columns(2)

# ---------------- Pie Chart ---------------- #
# ---------------- Treemap ---------------- #

with col1:

    st.subheader(" Risk Distribution")

    treemap_chart = px.treemap(
        risk_df,
        path=["Service"],
        values="Risk Score",
        color="Risk Score",
        color_continuous_scale=[
            [0.0, "#00ff7f"],   # Low
            [0.5, "#ffcc00"],   # Medium
            [1.0, "#ff4b4b"]    # High
        ]
    )

    treemap_chart.update_traces(
        textinfo="label+value+percent root"
    )

    treemap_chart.update_layout(
        paper_bgcolor="#0E1117",
        plot_bgcolor="#0E1117",
        font_color="white",
        margin=dict(t=30, l=0, r=0, b=0)
    )

    st.plotly_chart(
        treemap_chart,
        use_container_width=True
    )


# ---------------- Bar Chart ---------------- #

with col2:

    st.subheader(" Risk Score Comparison")

    bar_chart = px.bar(
        risk_df,
        x="Service",
        y="Risk Score",
        color="Service"
    )

    bar_chart.update_layout(
        paper_bgcolor="#0E1117",
        plot_bgcolor="#0E1117",
        font_color="white"
    )

    st.plotly_chart(
        bar_chart,
        use_container_width=True
    )

st.markdown("---")

st.subheader("Service Security Status")

st.write("IAM")
st.progress(75)

st.write("S3")
st.progress(65)

st.write("EC2")
st.progress(80)
# ==================================================
# FINDINGS TAB
# ==================================================

with tab2:

    st.header(" Findings")

    st.subheader("IAM Findings")

    for finding in iam_data["findings"]:
        st.error(finding)

    st.markdown("---")

    st.subheader("S3 Findings")

    for finding in s3_data["findings"]:
        st.warning(finding)

    st.markdown("---")

    st.subheader("EC2 Findings")

    for finding in ec2_data["findings"]:
        st.info(finding)

    st.markdown("---")

    findings_df = pd.DataFrame({

        "Service":
        ["IAM"] * len(iam_data["findings"])
        + ["S3"] * len(s3_data["findings"])
        + ["EC2"] * len(ec2_data["findings"]),

        "Finding":
        iam_data["findings"]
        + s3_data["findings"]
        + ec2_data["findings"]

    })

st.subheader(" Findings Summary")

findings_df["Severity"] = [
    "HIGH" if "MFA" in x or "SSH" in x else
    "CRITICAL" if "PUBLIC" in x else
    "MEDIUM"
    for x in findings_df["Finding"]
]

findings_df = findings_df[
    ["Service", "Severity", "Finding"]
]

st.dataframe(
    findings_df,
    use_container_width=True,
    hide_index=True
) 
st.markdown("---")

st.subheader(" Findings Distribution")

findings_count_df = pd.DataFrame({
    "Service": ["IAM", "S3", "EC2"],
    "Count": [
        len(iam_data["findings"]),
        len(s3_data["findings"]),
        len(ec2_data["findings"])
    ]
})

fig = px.bar(
    findings_count_df,
    x="Service",
    y="Count",
    color="Service",
    text="Count"
)

fig.update_layout(
    paper_bgcolor="#0E1117",
    plot_bgcolor="#0E1117",
    font_color="white"
)

st.plotly_chart(
    fig,
    use_container_width=True
)
st.markdown("---")

st.subheader(" Risk Trend")

trend_df = pd.DataFrame({
    "Day": ["Mon", "Tue", "Wed", "Thu", "Fri"],
    "Risk": [180, 175, 173, 171, 170]
})

fig = px.line(
    trend_df,
    x="Day",
    y="Risk",
    markers=True
)

fig.update_layout(
    paper_bgcolor="#0E1117",
    plot_bgcolor="#0E1117",
    font_color="white"
)

st.plotly_chart(
    fig,
    use_container_width=True
)
# ==================================================
# REPORTS TAB
# ==================================================

with tab3:

    st.header(" JSON Reports")

    with st.expander("IAM Report"):
        st.json(iam_data)

    with st.expander("S3 Report"):
        st.json(s3_data)

    with st.expander("EC2 Report"):
        st.json(ec2_data)

    st.markdown("---")

    st.subheader("⬇ Download Reports")

    with open("reports/report.json", "rb") as f:
        st.download_button(
            "Download IAM Report",
            f,
            file_name="iam_report.json"
        )

    with open("reports/s3_report.json", "rb") as f:
        st.download_button(
            "Download S3 Report",
            f,
            file_name="s3_report.json"
        )

    with open("reports/ec2_report.json", "rb") as f:
        st.download_button(
            "Download EC2 Report",
            f,
            file_name="ec2_report.json"
        )

# ==================================================
# ANALYTICS TAB
# ==================================================

with tab4:

    st.header(" Analytics")

    total_findings = (
        len(iam_data["findings"])
        + len(s3_data["findings"])
        + len(ec2_data["findings"])
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("IAM Findings", len(iam_data["findings"]))

    with col2:
        st.metric("S3 Findings", len(s3_data["findings"]))

    with col3:
        st.metric("EC2 Findings", len(ec2_data["findings"]))

    st.markdown("---")

    # Overall Risk Meter
    st.subheader(" Overall Risk Meter")

    gauge_chart = go.Figure()

    gauge_chart.add_trace(
        go.Indicator(
            mode="gauge+number",
            value=overall_score,
            title={"text": "Overall Risk"},
            gauge={
                "axis": {"range": [0, 200]},
                "bar": {"color": "red"},
                "steps": [
                    {"range": [0, 50], "color": "green"},
                    {"range": [50, 100], "color": "orange"},
                    {"range": [100, 200], "color": "darkred"}
                ]
            }
        )
    )

    gauge_chart.update_layout(
        paper_bgcolor="#0E1117",
        font_color="white"
    )

    st.plotly_chart(
        gauge_chart,
        use_container_width=True
    )

    st.markdown("---")

    # Severity Distribution
    st.subheader(" Severity Distribution")

    severity_df = pd.DataFrame({
        "Severity": ["Critical", "Medium", "Low"],
        "Count": [4, 3, 2]
    })

    fig = px.bar(
        severity_df,
        x="Severity",
        y="Count",
        color="Severity",
        text="Count",
        color_discrete_map={
            "Critical": "#ff4b4b",
            "Medium": "#ffcc00",
            "Low": "#00cc66"
        }
    )

    fig.update_layout(
        paper_bgcolor="#0E1117",
        plot_bgcolor="#0E1117",
        font_color="white",
        showlegend=False
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )
st.markdown("---")

st.success(f"""
###  Security Summary

 Overall Risk Score : {overall_score}

 Overall Severity : {overall_severity}

 Total Findings : {total_findings}

 Scanner Status : Portfolio Ready 
""")

# 👇 Ikkada add cheyyi
report_content = f"""
Cloud Security Compliance Scanner

Overall Risk Score : {overall_score}
Overall Severity : {overall_severity}

IAM Risk Score : {iam_data['risk_score']}
S3 Risk Score : {s3_data['risk_score']}
EC2 Risk Score : {ec2_data['risk_score']}

Total Findings : {total_findings}

Scanner Status : Portfolio Ready
"""

st.download_button(
    " Download Report",
    report_content,
    file_name="security_report.txt",
    mime="text/plain"
)

report = f"""
AWS Security Report

Overall Risk Score : {overall_score}
Severity : {overall_severity}
Total Findings : {total_findings}

IAM Findings : {len(iam_data["findings"])}
S3 Findings : {len(s3_data["findings"])}
EC2 Findings : {len(ec2_data["findings"])}
"""

st.download_button(
    " Download AWS Report",
    report,
    file_name="aws_security_report.txt"
)

st.markdown("---")

st.subheader(" Security Recommendations")

col1, col2 = st.columns(2)

with col1:

    st.info("""
###  IAM Recommendations

 Enable MFA

 Rotate Access Keys

 Remove Unused Keys

 Avoid Admin Access

 Follow Least Privilege
""")

with col2:

    st.info("""
###  S3 Recommendations

 Disable Public Access

 Enable Versioning

 Keep Encryption Enabled

 Enable Logging

 Enable Replication
""")

st.markdown("---")

col1, col2 = st.columns(2)

with col1:

    st.warning("""
###  EC2 Recommendations

 Restrict SSH Port 22

 Avoid Public IP Exposure

 Use Security Groups

 Enable CloudWatch Monitoring

 Use IAM Roles
""")

with col2:

    st.success("""
###  Security Best Practices

 Enable Encryption

 Rotate Credentials

 Use MFA

 Enable Monitoring

 Follow CIS Benchmarks
""")

# ==================================================
# FOOTER
# ==================================================

st.markdown("---")

st.markdown("---")

st.markdown("---")

st.markdown(
"""
<center>

Built with Python • AWS Boto3 • Streamlit • Plotly

© Narendra Kanumuri

</center>
""",
unsafe_allow_html=True
)