import requests
import re
import pandas as pd
from bs4 import BeautifulSoup

emails_found = []

with open("business_list.csv") as f:
    next(f)

    for line in f:
        parts = line.strip().split(",")

        if len(parts) < 2:
            continue

        business = parts[0]
        website = parts[1]

        print("Scanning:", website)

        try:
            r = requests.get(website, timeout=8)

            matches = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", r.text)

            for email in matches:
                if "@" in email and "." in email:
                    emails_found.append({
                        "email": email,
                        "business": business
                    })
                    print("Found email:", email)
                    break

        except:
            print("Could not scan site")

df = pd.DataFrame(emails_found)

df.to_csv("leads.csv", index=False)

print("Saved emails to leads.csv")
