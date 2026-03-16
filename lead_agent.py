"""
ThreatLens AI — Lead Generation & Email Agent (DuckDuckGo version)
"""

import os
import re
import json
import time
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bs4 import BeautifulSoup
from openai import OpenAI
from dotenv import load_dotenv
from datetime import datetime
from urllib.parse import unquote

load_dotenv()

GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")

client = OpenAI(api_key=OPENAI_KEY)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
}

LOG_FILE = "leads_log.json"

def load_log():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    return {}

def save_log(log):
    with open(LOG_FILE, "w") as f:
        json.dump(log, f, indent=2)

def already_contacted(email):
    return email in load_log()

def mark_contacted(email, company, industry):
    log = load_log()
    log[email] = {"company": company, "industry": industry, "contacted_at": datetime.now().isoformat()}
    save_log(log)

def duckduckgo_search(query, num_results=10):
    search_url = "https://html.duckduckgo.com/html/"
    params = {"q": query, "kl": "us-en"}
    try:
        response = requests.post(search_url, data=params, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        urls = []
        skip_domains = ["duckduckgo.com","youtube.com","facebook.com","twitter.com",
                        "linkedin.com","yelp.com","wikipedia.org","bbb.org","google.com",
                        "instagram.com","tiktok.com"]

        for a in soup.select("a.result__url"):
            href = a.get("href","")
            if href and href.startswith("http"):
                if not any(s in href for s in skip_domains):
                    urls.append(href)

        if not urls:
            for a in soup.select("a.result__a"):
                href = a.get("href","")
                if "uddg=" in href:
                    match = re.search(r"uddg=([^&]+)", href)
                    if match:
                        url = unquote(match.group(1))
                        if not any(s in url for s in skip_domains):
                            urls.append(url)

        result = list(dict.fromkeys(urls))[:num_results]
        print(f"    DuckDuckGo returned {len(result)} results")
        return result
    except Exception as e:
        print(f"  [!] Search failed: {e}")
        return []

def extract_contact_info(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=8)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.find("title")
        company_name = title.get_text().split("|")[0].split("-")[0].strip() if title else url
        email = None
        for a in soup.find_all("a", href=True):
            if a["href"].startswith("mailto:"):
                email = a["href"].replace("mailto:","").split("?")[0].strip()
                break
        if not email:
            page_text = soup.get_text()
            emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", page_text)
            filtered = [e for e in emails if not any(s in e.lower() for s in
                        ["example","test","noreply","no-reply","sentry","wix","squarespace"])]
            email = filtered[0] if filtered else None
        if not email:
            try:
                r2 = requests.get(url.rstrip("/")+"/contact", headers=HEADERS, timeout=6)
                soup2 = BeautifulSoup(r2.text, "html.parser")
                for a in soup2.find_all("a", href=True):
                    if a["href"].startswith("mailto:"):
                        email = a["href"].replace("mailto:","").split("?")[0].strip()
                        break
                if not email:
                    emails2 = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", soup2.get_text())
                    filtered2 = [e for e in emails2 if not any(s in e.lower() for s in ["example","test","noreply","wix"])]
                    email = filtered2[0] if filtered2 else None
            except:
                pass
        if not email:
            return None
        return {"company": company_name, "email": email, "url": url}
    except Exception as e:
        print(f"  [!] Could not scrape {url}: {e}")
        return None

def generate_email(company, industry, url):
    prompt = f"""Write a cold email for ThreatLens AI — a phishing detection tool for small businesses.

Target:
- Company: {company}
- Industry: {industry}
- Website: {url}

Rules:
- Max 120 words
- Friendly, not salesy
- Mention their industry's specific risk
- CTA: visit https://threatlens.ai for a free scan
- Sign off as "The ThreatLens Team"
- Last line must be: "To unsubscribe reply with STOP"

Return ONLY this JSON:
{{"subject": "...", "body": "..."}}"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7
    )
    raw = re.sub(r"```json|```", "", response.choices[0].message.content).strip()
    return json.loads(raw)

def send_email(to_email, subject, body):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = GMAIL_ADDRESS
        msg["To"] = to_email
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_ADDRESS, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"  [!] Send failed: {e}")
        return False

def run_agent(industries=None, leads_per_industry=5, location="United States", dry_run=True):
    if industries is None:
        industries = ["law firm", "accounting firm", "small business"]

    print(f"\n{'='*55}")
    print(f"  ThreatLens Lead Agent — {'DRY RUN' if dry_run else 'LIVE'}")
    print(f"{'='*55}\n")

    total_sent = 0
    total_skipped = 0

    for industry in industries:
        print(f"\n[+] Searching for: {industry} in {location}")
        urls = duckduckgo_search(f"{industry} {location} contact email site:.com", leads_per_industry * 2)
        if not urls:
            print(f"    Trying broader search...")
            urls = duckduckgo_search(f"{industry} {location}", leads_per_industry * 2)

        leads_found = 0
        for url in urls:
            if leads_found >= leads_per_industry:
                break
            print(f"\n  -> Checking: {url}")
            info = extract_contact_info(url)
            if not info:
                print(f"     No email found, skipping")
                continue
            email = info["email"]
            company = info["company"]
            if already_contacted(email):
                print(f"     Already contacted {email}, skipping")
                total_skipped += 1
                continue
            print(f"     Company: {company}")
            print(f"     Email:   {email}")
            print(f"     Generating email...")
            try:
                content = generate_email(company, industry, url)
            except Exception as e:
                print(f"     [!] GPT failed: {e}")
                continue
            print(f"     Subject: {content['subject']}")
            if dry_run:
                print(f"\n     --- PREVIEW ---")
                print(f"     To: {email}\n     Subject: {content['subject']}\n     Body:\n{content['body']}")
                print(f"     --- END ---\n")
                mark_contacted(email, company, industry)
                leads_found += 1
                total_sent += 1
            else:
                if send_email(email, content["subject"], content["body"]):
                    print(f"     Sent!")
                    mark_contacted(email, company, industry)
                    leads_found += 1
                    total_sent += 1
            time.sleep(3)
        print(f"\n  [{industry}] Done — {leads_found} leads contacted")

    print(f"\n{'='*55}")
    print(f"  Total sent:    {total_sent}")
    print(f"  Total skipped: {total_skipped}")
    print(f"{'='*55}\n")

if __name__ == "__main__":
    run_agent(
        industries=["law firm", "accounting firm", "small business"],
        leads_per_industry=5,
        location="United States",
        dry_run=True
    )
