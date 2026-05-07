import os
import csv
import time
import re
import smtplib
from datetime import datetime
from email.mime.text import MIMEText

# =========================
# CONFIG
# =========================
EMAIL = "joel.threatlens@gmail.com"
PASSWORD = "rnut katl gpxg zxsa"  # 🔁 replace with Gmail App Password

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

CONTACTED_FILE = "contacted.csv"
LOG_FILE = "outreach_log.txt"

DRY_RUN = False  # 🔁 change to False when ready to send

# =========================
# EMAIL VALIDATION
# =========================
def is_valid_email(email):
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None

# =========================
# CHECK DUPLICATES
# =========================
def already_contacted(email):
    if not os.path.exists(CONTACTED_FILE):
        return False

    with open(CONTACTED_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if email in line:
                return True
    return False

# =========================
# SAVE CONTACTED
# =========================
def mark_contacted(email, company, industry):
    with open(CONTACTED_FILE, "a", encoding="utf-8") as f:
        f.write(f"{email},{company},{industry},{datetime.now()}\n")

# =========================
# LOG SYSTEM
# =========================
def log_event(message):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now()}] {message}\n")

# =========================
# GENERATE EMAIL CONTENT
# =========================
def generate_email(company, industry):
    subject = "Quick question about your email security"

    body = f"""
Hi {company} team,

I was looking into businesses in the {industry} space and noticed something:

Many small teams are getting targeted with phishing emails that look completely legitimate (invoices, client messages, etc.).

I built a simple tool (ThreatLens AI) that analyzes suspicious emails and flags risks before anyone clicks.

I can run a quick check for you and send a short security report — free.

Would you like me to run one for your business?

– Joel  
ThreatLens AI  
https://threatlens-ai-pyjx.onrender.com
"""
    return {"subject": subject, "body": body}

# =========================
# SEND EMAIL
# =========================
def send_email(recipient, subject, body):
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL
        msg["To"] = recipient

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL, PASSWORD)

        server.sendmail(EMAIL, recipient, msg.as_string())
        server.quit()

        return True

    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

# =========================
# MAIN PROGRAM
# =========================
if __name__ == "__main__":

    csv_file = "leads.csv"

    if not os.path.exists(csv_file):
        print(f"[!] {csv_file} not found.")
        exit()

    leads = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            leads.append(row)

    print(f"\n[+] Loaded {len(leads)} leads")
    print("=" * 60)

    total_sent = 0
    total_skipped = 0

    for lead in leads:
        email = lead.get("email", "").strip()
        company = lead.get("company", "Business").strip()
        industry = lead.get("industry", "general").strip()

        print(f"\n→ {company} ({email})")

        # Validate email
        if not is_valid_email(email):
            print("   ❌ Invalid email")
            log_event(f"INVALID: {email}")
            total_skipped += 1
            continue

        # Check duplicate
        if already_contacted(email):
            print("   ⏭ Already contacted")
            total_skipped += 1
            continue

        # Generate email
        print("   ✍️ Generating...")
        content = generate_email(company, industry)

        print(f"   Subject: {content['subject']}")

        # Send or dry run
        if not DRY_RUN:
            success = send_email(email, content["subject"], content["body"])

            if success:
                print("   ✅ Sent")
                mark_contacted(email, company, industry)
                log_event(f"SENT: {email}")
                total_sent += 1
            else:
                print("   ❌ Failed")
                log_event(f"FAILED: {email}")
        else:
            print("   🧪 Dry run (not sent)")
            mark_contacted(email, company, industry)
            total_sent += 1

        time.sleep(6)

    print("\n" + "=" * 60)
    print(f"Sent: {total_sent}")
    print(f"Skipped: {total_skipped}")
    print("=" * 60)
