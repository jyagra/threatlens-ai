import streamlit as st
import os
import re
import urllib.parse
import requests
import yaml
import stripe

from openai import OpenAI
from dotenv import load_dotenv
from yaml.loader import SafeLoader
from email import policy
from email.parser import BytesParser
import streamlit_authenticator as stauth

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO

# Load environment variables
load_dotenv()

OPENAI_KEY = os.getenv("OPENAI_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
STRIPE_KEY = os.getenv("STRIPE_SECRET_KEY")

client = OpenAI(api_key=OPENAI_KEY)

# Stripe setup
if STRIPE_KEY:
    stripe.api_key = STRIPE_KEY

st.set_page_config(page_title="ThreatLens AI", page_icon="🛡️")

# -----------------------------
# LOGIN SYSTEM
# -----------------------------
with open("users.yaml") as file:
    config = yaml.load(file, Loader=SafeLoader)

authenticator = stauth.Authenticate(
    config["credentials"],
    config["cookie"]["name"],
    config["cookie"]["key"],
    config["cookie"]["expiry_days"],
)

name, authentication_status, username = authenticator.login("Login", "main")

if authentication_status is False:
    st.error("Incorrect username or password")

if authentication_status is None:
    st.warning("Enter your login credentials")

if authentication_status:

    authenticator.logout("Logout", "sidebar")
    st.sidebar.write(f"Welcome {name}")

    st.title("🛡️ ThreatLens AI")
    st.subheader("Email Phishing Detection Platform")

    subject = st.text_input("Email Subject")
    sender = st.text_input("Sender Email Address")
    body = st.text_area("Email Body")

    uploaded_email = st.file_uploader("Upload Email (.eml)", type=["eml"])

    # -----------------------------
    # EMAIL FILE PARSING
    # -----------------------------
    if uploaded_email is not None:

        msg = BytesParser(policy=policy.default).parse(uploaded_email)

        subject = msg["subject"]
        sender = msg["from"]

        if msg.is_multipart():

            body = ""

            for part in msg.walk():

                if part.get_content_type() == "text/plain":
                    body += part.get_content()

        else:
            body = msg.get_content()

        st.success("Email loaded successfully")

    # -----------------------------
    # SCAN LIMIT (FREE TIER)
    # -----------------------------
    if "scan_count" not in st.session_state:
        st.session_state.scan_count = 0

    if st.session_state.scan_count >= 20:
        st.warning("Free tier limit reached. Upgrade to continue scanning.")
        st.stop()

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

                findings.append(f"IP address link detected: {url}")
                ips.append(domain)

            suspicious_tlds = [".ru", ".tk", ".xyz", ".top"]

            for tld in suspicious_tlds:

                if domain.endswith(tld):
                    findings.append(f"Suspicious domain TLD detected: {domain}")

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
            indicators.append("Possible domain typo (paypa1 vs paypal)")

        return min(score,100), indicators

    # -----------------------------
    # ABUSEIPDB LOOKUP
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
                return f"IP {ip} reported malicious (confidence score {score})"

        return None

    # -----------------------------
    # PDF REPORT
    # -----------------------------
    def generate_report(score, ai_text, heuristics, url_flags, threatintel):

        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)

        pdf.drawString(50,750,"ThreatLens Security Report")
        pdf.drawString(50,730,f"Risk Score: {score}/100")

        y=700

        for line in ai_text.split("\n"):
            pdf.drawString(60,y,line)
            y-=15

        pdf.save()

        buffer.seek(0)
        return buffer

    # -----------------------------
    # ANALYZE BUTTON
    # -----------------------------
    if st.button("Analyze Email"):

        st.session_state.scan_count += 1

        heuristic, heuristic_indicators = heuristic_score(subject,sender,body)

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

Return:

Risk Score (0-100)
Risk Level
Short Explanation
"""

        response = client.chat.completions.create(

            model="gpt-4o-mini",

            messages=[
                {"role":"system","content":"You are a cybersecurity analyst"},
                {"role":"user","content":prompt}
            ]
        )

        ai_result = response.choices[0].message.content

        ai_score_match = re.search(r"\d+",ai_result)

        ai_score = int(ai_score_match.group()) if ai_score_match else 50

        final_score = int((ai_score + heuristic)/2)

        st.subheader("Detection Results")

        if final_score >=70:
            st.error(f"Risk Score: {final_score}/100")
        elif final_score >=40:
            st.warning(f"Risk Score: {final_score}/100")
        else:
            st.success(f"Risk Score: {final_score}/100")

        st.write("### AI Analysis")
        st.write(ai_result)

        st.write("### Heuristic Indicators")
        for item in heuristic_indicators:
            st.write(f"- {item}")

        st.write("### URL Findings")
        for item in url_findings:
            st.write(f"- {item}")

        st.write("### Threat Intelligence")
        for item in threatintel:
            st.write(f"- {item}")

        report = generate_report(final_score,ai_result,heuristic_indicators,url_findings,threatintel)

        st.download_button(
            "Download Security Report",
            report,
            "threatlens_report.pdf",
            "application/pdf"
        )

        # Upgrade button
        st.link_button("Upgrade to Business Plan", "https://stripe.com")
