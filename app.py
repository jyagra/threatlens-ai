import streamlit as st
from openai import OpenAI
import os
from dotenv import load_dotenv
import re
import urllib.parse
import email
from email import policy
from email.parser import BytesParser
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
import requests

load_dotenv()

OPENAI_KEY = os.getenv("OPENAI_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

client = OpenAI(api_key=OPENAI_KEY)

st.set_page_config(page_title="ThreatLens AI", page_icon="🛡️")

st.title("🛡️ ThreatLens AI")
st.subheader("AI + Threat Intelligence Phishing Detection")

subject = st.text_input("Email Subject")
sender = st.text_input("Sender Email Address")
body = st.text_area("Email Body")

uploaded_email = st.file_uploader("Upload Email File (.eml)", type=["eml"])

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

    st.success("Email file loaded successfully")


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
# THREAT INTEL LOOKUP
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
# PDF REPORT
# -----------------------------
def generate_report(score, ai_text, heuristics, url_flags, threatintel):

    buffer = BytesIO()

    pdf = canvas.Canvas(buffer, pagesize=letter)

    pdf.drawString(50,750,"ThreatLens AI Security Report")

    pdf.drawString(50,730,f"Final Risk Score: {score}/100")

    y=700

    pdf.drawString(50,y,"AI Analysis")
    y-=20

    for line in ai_text.split("\n"):
        pdf.drawString(60,y,line)
        y-=15

    y-=10
    pdf.drawString(50,y,"Heuristic Indicators")
    y-=20

    for item in heuristics:
        pdf.drawString(60,y,f"- {item}")
        y-=15

    y-=10
    pdf.drawString(50,y,"URL Threat Indicators")
    y-=20

    for item in url_flags:
        pdf.drawString(60,y,f"- {item}")
        y-=15

    y-=10
    pdf.drawString(50,y,"Threat Intelligence Findings")
    y-=20

    for item in threatintel:
        pdf.drawString(60,y,f"- {item}")
        y-=15

    pdf.save()

    buffer.seek(0)

    return buffer


# -----------------------------
# MAIN ANALYSIS
# -----------------------------
if st.button("Analyze Email"):

    heuristic, heuristic_indicators = heuristic_score(subject,sender,body)

    urls, url_findings, ips = scan_urls(body)

    threatintel = []

    for ip in ips:

        result = check_ip_reputation(ip)

        if result:
            threatintel.append(result)

    prompt = f"""
You are a cybersecurity analyst.

Analyze this email for phishing risk.

Subject: {subject}
Sender: {sender}
Body: {body}

Return ONLY:

AI Risk Score: (0-100)
AI Risk Level: (Low, Medium, High)
Short Explanation
"""

    response = client.chat.completions.create(

        model="gpt-4o-mini",

        messages=[
            {"role":"system","content":"You are a cybersecurity analyst"},
            {"role":"user","content":prompt}
        ],

        temperature=0.3
    )

    ai_result = response.choices[0].message.content

    ai_score_match = re.search(r"\d+",ai_result)

    ai_score = int(ai_score_match.group()) if ai_score_match else 50

    final_score = int((ai_score + heuristic)/2)

    st.subheader("Detection Results")

    if final_score >=70:
        st.error(f"Final Risk Score: {final_score}/100")
    elif final_score >=40:
        st.warning(f"Final Risk Score: {final_score}/100")
    else:
        st.success(f"Final Risk Score: {final_score}/100")

    st.write("### AI Analysis")
    st.write(ai_result)

    st.write("### Heuristic Indicators")
    for item in heuristic_indicators:
        st.write(f"- {item}")

    st.write("### URL Threat Indicators")
    for item in url_findings:
        st.write(f"- {item}")

    st.write("### Threat Intelligence")
    for item in threatintel:
        st.write(f"- {item}")

    report = generate_report(final_score,ai_result,heuristic_indicators,url_findings,threatintel)

    st.download_button(
        "Download Security Report (PDF)",
        report,
        "threatlens_report.pdf",
        "application/pdf"
    )
