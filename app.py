import streamlit as st
import os
import re
import urllib.parse
import requests
import json
import stripe
import plotly.express as px

from openai import OpenAI
from dotenv import load_dotenv
from email import policy
from email.parser import BytesParser

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO


# -----------------------------
# LOAD ENV VARIABLES
# -----------------------------
load_dotenv()

OPENAI_KEY = os.getenv("OPENAI_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
STRIPE_KEY = os.getenv("STRIPE_SECRET_KEY")

client = OpenAI(api_key=OPENAI_KEY)

if STRIPE_KEY:
    stripe.api_key = STRIPE_KEY


st.set_page_config(page_title="ThreatLens AI", page_icon="🛡️")


# -----------------------------
# HISTORY DATABASE
# -----------------------------
HISTORY_FILE = "scan_history.json"

if not os.path.exists(HISTORY_FILE):
    with open(HISTORY_FILE, "w") as f:
        json.dump([], f)


def load_history():

    with open(HISTORY_FILE, "r") as f:
        return json.load(f)


def save_scan(scan):

    history = load_history()
    history.append(scan)

    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)


# -----------------------------
# LOGIN SYSTEM
# -----------------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False


if not st.session_state.authenticated:

    st.title("ThreatLens Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):

        if username == "admin" and password == "StrongPassword123":

            st.session_state.authenticated = True
            st.rerun()

        else:
            st.error("Invalid credentials")

    st.stop()


# -----------------------------
# NAVIGATION
# -----------------------------
page = st.sidebar.selectbox(
    "ThreatLens Menu",
    ["Dashboard", "Scan Email", "Reports"]
)


st.sidebar.write("Logged in")


# -----------------------------
# DASHBOARD
# -----------------------------
if page == "Dashboard":

    st.title("ThreatLens Security Dashboard")

    history = load_history()

    if len(history) == 0:

        st.info("No scans yet")

    else:

        total = len(history)

        high_risk = len([h for h in history if h["risk"] >= 70])
        medium_risk = len([h for h in history if 40 <= h["risk"] < 70])
        low_risk = len([h for h in history if h["risk"] < 40])

        col1, col2, col3 = st.columns(3)

        col1.metric("Emails Scanned", total)
        col2.metric("High Risk", high_risk)
        col3.metric("Medium Risk", medium_risk)


        risk_data = {
            "Risk Level": ["High", "Medium", "Low"],
            "Count": [high_risk, medium_risk, low_risk]
        }

        fig = px.bar(
            risk_data,
            x="Risk Level",
            y="Count",
            title="Phishing Risk Distribution"
        )

        st.plotly_chart(fig)


        scores = [h["risk"] for h in history]

        fig2 = px.line(
            y=scores,
            title="Threat Score Trend"
        )

        st.plotly_chart(fig2)


# -----------------------------
# URL SCANNER
# -----------------------------
def scan_urls(text):

    urls = re.findall(r'(https?://[^\s]+)', text)

    findings = []
    ips = []

    for url in urls:

        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc

        if re.match(r"\d+\.\d+\.\d+\.\d+", domain):

            findings.append(f"IP address detected: {url}")
            ips.append(domain)

        suspicious_tlds = [".ru", ".tk", ".xyz", ".top"]

        for tld in suspicious_tlds:

            if domain.endswith(tld):

                findings.append(f"Suspicious TLD detected: {domain}")

        shorteners = ["bit.ly", "tinyurl", "t.co"]

        for short in shorteners:

            if short in domain:

                findings.append(f"Shortened URL detected: {url}")

    return urls, findings, ips


# -----------------------------
# HEURISTIC DETECTION
# -----------------------------
def heuristic_score(subject, sender, body):

    score = 0
    indicators = []

    text = (subject + body).lower()

    urgent_words = [
        "urgent",
        "verify",
        "immediately",
        "suspended",
        "click now",
        "account locked"
    ]

    for word in urgent_words:

        if word in text:

            score += 15
            indicators.append(f"Urgent language detected: {word}")

    if "paypa1" in sender.lower():

        score += 25
        indicators.append("Possible spoofed sender detected")

    return min(score, 100), indicators


# -----------------------------
# ABUSEIPDB CHECK
# -----------------------------
def check_ip_reputation(ip):

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSE_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:

        data = response.json()

        score = data["data"]["abuseConfidenceScore"]

        if score > 50:

            return f"IP {ip} reported malicious ({score})"

    return None


# -----------------------------
# PDF REPORT
# -----------------------------
def generate_report(score, analysis):

    buffer = BytesIO()

    pdf = canvas.Canvas(buffer, pagesize=letter)

    pdf.drawString(50, 750, "ThreatLens Security Report")
    pdf.drawString(50, 730, f"Risk Score: {score}/100")

    y = 700

    for line in analysis.split("\n"):

        pdf.drawString(60, y, line)

        y -= 15

    pdf.save()

    buffer.seek(0)

    return buffer


# -----------------------------
# SCAN EMAIL PAGE
# -----------------------------
if page == "Scan Email":

    st.title("Scan Email")

    subject = st.text_input("Email Subject")
    sender = st.text_input("Sender")
    body = st.text_area("Email Body")

    if st.button("Analyze Email"):

        heuristic, indicators = heuristic_score(subject, sender, body)

        urls, url_findings, ips = scan_urls(body)

        threatintel = []

        for ip in ips:

            result = check_ip_reputation(ip)

            if result:
                threatintel.append(result)


        prompt = f"""
Analyze this email for phishing risk.

Subject: {subject}
Sender: {sender}
Body: {body}

Return risk score (0-100) and explanation.
"""

        response = client.chat.completions.create(

            model="gpt-4o-mini",

            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst"},
                {"role": "user", "content": prompt}
            ]
        )

        ai_result = response.choices[0].message.content

        score_match = re.search(r"\d+", ai_result)

        ai_score = int(score_match.group()) if score_match else 50

        final_score = int((ai_score + heuristic) / 2)


        st.subheader("Detection Results")

        st.write(ai_result)

        for f in url_findings:

            st.write(f)

        for i in indicators:

            st.write(i)

        for t in threatintel:

            st.write(t)


        save_scan({
            "sender": sender,
            "subject": subject,
            "risk": final_score
        })


        report = generate_report(final_score, ai_result)

        st.download_button(
            "Download Security Report",
            report,
            "threatlens_report.pdf",
            "application/pdf"
        )

        st.link_button("Upgrade to Business Plan", "https://stripe.com")


# -----------------------------
# REPORTS PAGE
# -----------------------------
if page == "Reports":

    st.title("Scan History")

    history = load_history()

    st.json(history)
