import streamlit as st
from openai import OpenAI
import os
from dotenv import load_dotenv
import re

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

st.set_page_config(page_title="ThreatLens AI", page_icon="🛡️")

st.title("🛡️ ThreatLens AI")
st.subheader("Hybrid AI + Heuristic Phishing Detection Engine")

subject = st.text_input("Email Subject")
sender = st.text_input("Sender Email Address")
body = st.text_area("Email Body")

def heuristic_score(subject, sender, body):
    score = 0
    indicators = []

    # Urgent language detection
    urgent_words = ["urgent", "immediately", "suspended", "verify", "24 hours"]
    for word in urgent_words:
        if word.lower() in (subject + body).lower():
            score += 15
            indicators.append(f"Urgent keyword detected: {word}")

    # Suspicious domain typo check
    if "paypa1" in sender.lower():
        score += 25
        indicators.append("Possible domain typo (paypa1 vs paypal)")

    # IP address link detection
    if re.search(r"http[s]?://\d+\.\d+\.\d+\.\d+", body):
        score += 20
        indicators.append("Link contains raw IP address")

    # Suspicious TLD
    suspicious_tlds = [".ru", ".tk", ".cn"]
    for tld in suspicious_tlds:
        if tld in body.lower():
            score += 15
            indicators.append(f"Suspicious TLD detected: {tld}")

    return min(score, 100), indicators

if st.button("Analyze Email"):

    heuristic, heuristic_indicators = heuristic_score(subject, sender, body)

    prompt = f"""
You are a cybersecurity analyst.

Analyze this email for phishing risk.

Subject: {subject}
Sender: {sender}
Body: {body}

Return ONLY:

AI Risk Score: (0-100)
AI Risk Level: (Low, Medium, High)
Short Explanation:
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a professional cybersecurity analyst."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.3
    )

    ai_result = response.choices[0].message.content

    # Extract AI numeric score
    ai_score_match = re.search(r"\d+", ai_result)
    ai_score = int(ai_score_match.group()) if ai_score_match else 50

    final_score = int((ai_score + heuristic) / 2)

    st.subheader("Detection Results")

    if final_score >= 70:
        st.error(f"Final Risk Score: {final_score}/100")
    elif final_score >= 40:
        st.warning(f"Final Risk Score: {final_score}/100")
    else:
        st.success(f"Final Risk Score: {final_score}/100")

    st.write("### AI Analysis")
    st.write(ai_result)

    st.write("### Heuristic Indicators")
    if heuristic_indicators:
        for item in heuristic_indicators:
            st.write(f"- {item}")
    else:
        st.write("No heuristic flags triggered.")
