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
from reportlab.lib.utils import simpleSplit
from io import BytesIO
import requests

load_dotenv()

OPENAI_KEY = os.getenv("OPENAI_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

client = OpenAI(api_key=OPENAI_KEY)

st.set_page_config(page_title="ThreatLens AI by Joel Yagra", page_icon="🛡️")

st.title("🛡️ ThreatLens AI")
st.subheader("AI + Threat Intelligence Phishing Detection")

# -----------------------------
# SESSION STATE FOR FIELDS
# -----------------------------
if "subject" not in st.session_state:
    st.session_state["subject"] = ""
if "sender" not in st.session_state:
    st.session_state["sender"] = ""
if "body" not in st.session_state:
    st.session_state["body"] = ""

uploaded_email = st.file_uploader("Upload Email File (.eml)", type=["eml"])

# -----------------------------
# EMAIL FILE PARSING
# -----------------------------
if uploaded_email is not None:
    try:
        msg = BytesParser(policy=policy.default).parse(uploaded_email)

        st.session_state["subject"] = msg["subject"] or ""
        st.session_state["sender"] = msg["from"] or ""

        if msg.is_multipart():
            body_parts = []
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body_parts.append(part.get_content())
            st.session_state["body"] = "\n".join(body_parts)
        else:
            st.session_state["body"] = msg.get_content()

        st.success("✅ Email file loaded successfully")
    except Exception as e:
        st.error(f"Failed to parse email file: {e}")

subject = st.text_input("Email Subject", value=st.session_state["subject"])
sender = st.text_input("Sender Email Address", value=st.session_state["sender"])
body = st.text_area("Email Body", value=st.session_state["body"])


# -----------------------------
# URL SCANNER
# -----------------------------
def scan_urls(text):
    # Strip trailing punctuation from URLs
    urls = re.findall(r'(https?://[^\s<>"\']+?)([.,;:!?)\'\"]*(?:\s|$))', text)
    urls = [u[0] for u in urls]

    findings = []
    ips = []

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc

        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            findings.append(f"IP address link detected: {url}")
            ips.append(domain)

        suspicious_tlds = [".ru", ".tk", ".xyz", ".top", ".cn", ".pw", ".click"]
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                findings.append(f"Suspicious domain TLD detected: {domain}")

        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]
        for short in shorteners:
            if short in domain:
                findings.append(f"Shortened URL detected: {url}")

    return urls, findings, ips


# -----------------------------
# THREAT INTEL LOOKUP
# -----------------------------
def check_ip_reputation(ip):
    if not ABUSE_KEY:
        return f"⚠️ AbuseIPDB API key not set — skipping IP check for {ip}"

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSE_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            score = data["data"]["abuseConfidenceScore"]
            if score > 50:
                return f"⚠️ IP {ip} reported malicious (confidence score: {score}/100)"
            else:
                return f"✅ IP {ip} appears clean (confidence score: {score}/100)"
        else:
            return f"AbuseIPDB returned status {response.status_code} for IP {ip}"
    except requests.RequestException as e:
        return f"Failed to check IP {ip}: {e}"


# -----------------------------
# HEURISTIC DETECTION
# -----------------------------

# Common brand typosquatting patterns: (typo, legitimate)
TYPOSQUAT_PATTERNS = [
    (r"paypa[l1][^a-z]", "PayPal"),
    (r"arnazon|amaz0n|amazan", "Amazon"),
    (r"g00gle|g0ogle|googIe", "Google"),
    (r"micros0ft|microsofl|mlcrosoft", "Microsoft"),
    (r"app1e|appl3|appIe", "Apple"),
    (r"netfl1x|netf1ix", "Netflix"),
    (r"bankofamerlca|bankofamerica\.com\.\w+", "Bank of America"),
]

def heuristic_score(subject, sender, body):
    score = 0
    indicators = []

    subject = subject or ""
    sender = sender or ""
    body = body or ""

    text = (subject + " " + body).lower()
    sender_lower = sender.lower()

    # Urgent language
    urgent_words = [
        "urgent", "verify", "immediately", "suspended",
        "click now", "account locked", "confirm your", "unusual activity",
        "update your", "limited time", "act now"
    ]
    for word in urgent_words:
        if word in text:
            score += 15
            indicators.append(f"Urgent language detected: '{word}'")

    # Typosquatting check on sender
    for pattern, brand in TYPOSQUAT_PATTERNS:
        if re.search(pattern, sender_lower):
            score += 25
            indicators.append(f"Possible {brand} typosquat in sender address")

    # Mismatched sender domain (e.g., claims to be PayPal but domain isn't paypal.com)
    brand_domain_map = {
        "paypal": "paypal.com",
        "amazon": "amazon.com",
        "google": "google.com",
        "microsoft": "microsoft.com",
        "apple": "apple.com",
        "netflix": "netflix.com",
    }
    for brand, legit_domain in brand_domain_map.items():
        if brand in text and legit_domain not in sender_lower:
            score += 10
            indicators.append(f"Email mentions '{brand}' but sender is not from {legit_domain}")

    # Suspicious sender patterns
    if re.search(r"no.?reply.*@(?![\w-]+\.(com|org|net|gov|edu)$)", sender_lower):
        score += 10
        indicators.append("Suspicious no-reply sender domain")

    if re.search(r"@\d+\.\d+\.\d+\.\d+", sender_lower):
        score += 30
        indicators.append("Sender address uses raw IP instead of domain")

    return min(score, 100), indicators


# -----------------------------
# PDF REPORT (with text wrapping + page breaks)
# -----------------------------
def generate_report(score, ai_text, heuristics, url_flags, threatintel):
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    margin = 50
    y = height - 50

    def check_page(y, needed=20):
        if y < margin + needed:
            pdf.showPage()
            return height - 50
        return y

    def draw_heading(text, y):
        y = check_page(y, 30)
        pdf.setFont("Helvetica-Bold", 13)
        pdf.drawString(margin, y, text)
        pdf.setFont("Helvetica", 11)
        return y - 20

    def draw_wrapped(text, y, indent=60):
        lines = simpleSplit(text, "Helvetica", 11, width - indent - margin)
        for line in lines:
            y = check_page(y)
            pdf.drawString(indent, y, line)
            y -= 15
        return y

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(margin, y, "ThreatLens AI — Security Report")
    y -= 25

    pdf.setFont("Helvetica", 12)
    pdf.drawString(margin, y, f"Final Risk Score: {score}/100")
    y -= 30

    y = draw_heading("AI Analysis", y)
    for line in ai_text.split("\n"):
        if line.strip():
            y = draw_wrapped(line.strip(), y)
    y -= 10

    y = draw_heading("Heuristic Indicators", y)
    if heuristics:
        for item in heuristics:
            y = draw_wrapped(f"• {item}", y)
    else:
        y = draw_wrapped("No heuristic indicators found.", y)
    y -= 10

    y = draw_heading("URL Threat Indicators", y)
    if url_flags:
        for item in url_flags:
            y = draw_wrapped(f"• {item}", y)
    else:
        y = draw_wrapped("No URL threats detected.", y)
    y -= 10

    y = draw_heading("Threat Intelligence Findings", y)
    if threatintel:
        for item in threatintel:
            y = draw_wrapped(f"• {item}", y)
    else:
        y = draw_wrapped("No threat intelligence findings.", y)

    pdf.save()
    buffer.seek(0)
    return buffer


# -----------------------------
# MAIN ANALYSIS
# -----------------------------
if st.button("Analyze Email"):

    # Input validation
    if not subject.strip() and not sender.strip() and not body.strip():
        st.error("Please provide at least an email subject, sender, or body before analyzing.")
        st.stop()

    with st.spinner("Analyzing email..."):

        heuristic, heuristic_indicators = heuristic_score(subject, sender, body)

        urls, url_findings, ips = scan_urls(body)

        threatintel = []
        for ip in ips:
            result = check_ip_reputation(ip)
            if result:
                threatintel.append(result)

        prompt = f"""
You are a cybersecurity analyst specializing in phishing detection.

Analyze this email for phishing risk and return ONLY the following format with no extra text:

AI Risk Score: <number 0-100>
AI Risk Level: <Low | Medium | High>
Explanation: <2-4 sentences explaining the key risk factors>

Email to analyze:
Subject: {subject}
Sender: {sender}
Body: {body}
"""

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst specializing in phishing detection."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )

        ai_result = response.choices[0].message.content

        # More precise score extraction — looks for the score line specifically
        ai_score_match = re.search(r"AI Risk Score:\s*(\d+)", ai_result)
        ai_score = int(ai_score_match.group(1)) if ai_score_match else 50

        final_score = int((ai_score + heuristic) / 2)

    # -----------------------------
    # RESULTS DISPLAY
    # -----------------------------
    st.subheader("Detection Results")

    if final_score >= 70:
        st.error(f"🔴 Final Risk Score: {final_score}/100 — HIGH RISK")
    elif final_score >= 40:
        st.warning(f"🟡 Final Risk Score: {final_score}/100 — MEDIUM RISK")
    else:
        st.success(f"🟢 Final Risk Score: {final_score}/100 — LOW RISK")

    st.write("### AI Analysis")
    st.write(ai_result)

    st.write("### Heuristic Indicators")
    if heuristic_indicators:
        for item in heuristic_indicators:
            st.write(f"- {item}")
    else:
        st.write("No heuristic indicators found.")

    st.write("### URL Threat Indicators")
    if url_findings:
        for item in url_findings:
            st.write(f"- {item}")
    else:
        st.write("No URL threats detected.")

    st.write("### Threat Intelligence")
    if threatintel:
        for item in threatintel:
            st.write(f"- {item}")
    else:
        st.write("No threat intelligence findings.")

    report = generate_report(final_score, ai_result, heuristic_indicators, url_findings, threatintel)

    st.download_button(
        "📄 Download Security Report (PDF)",
        report,
        "threatlens_report.pdf",
        "application/pdf"
    )
st.markdown("---")
st.caption("ThreatLens AI © 2026 — Built by Joel Yagra | Cybersecurity Analyst")
