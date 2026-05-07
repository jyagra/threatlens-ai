import smtplib
import csv
import time
from email.mime.text import MIMEText

# =========================
# CONFIG
# =========================
import os

EMAIL = os.getenv("EMAIL")
PASSWORD = os.getenv("EMAIL_PASSWORD")

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# =========================
# EMAIL FUNCTION
# =========================
def send_email(recipient, business_name):
    subject = "Quick question about your email security"

    body = f"""
Hi {business_name},

I was looking into businesses like yours and noticed something:

Many small teams are getting targeted with phishing emails that look completely legitimate (invoices, client messages, etc.).

I built a simple tool (ThreatLens AI) that analyzes suspicious emails and flags risks before anyone clicks.

I can run a quick check for you and send a short security report — free.

Would you like me to run one for your business?

– Joel
ThreatLens AI
https://threatlens-ai-pyjx.onrender.com
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL
    msg["To"] = recipient

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL, PASSWORD)

        server.sendmail(EMAIL, recipient, msg.as_string())
        server.quit()

        print(f"✅ Email sent to: {recipient}")

    except Exception as e:
        print(f"❌ Failed to send to {recipient}: {e}")


# =========================
# READ CSV + SEND EMAILS
# =========================
def run_outreach():
    with open("leads.csv", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            recipient = row["email"]
            business_name = row.get("business", "there")

            print(f"\n📤 Sending to: {recipient}")
            send_email(recipient, business_name)

            # Delay to avoid Gmail blocking
            time.sleep(10)


# =========================
# RUN
# =========================
if __name__ == "__main__":
    run_outreach()
