import requests
import pandas as pd

API_KEY = "YOUR_GOOGLE_PLACES_API_KEY"

search_queries = [
    "dentist Hartford Connecticut",
    "law firm Hartford Connecticut",
    "accounting firm Hartford Connecticut",
    "real estate agency Hartford Connecticut",
    "construction company Hartford Connecticut"
]

results = []

for query in search_queries:

    url = f"https://maps.googleapis.com/maps/api/place/textsearch/json?query={query}&key={API_KEY}"

    r = requests.get(url)
    data = r.json()

    for place in data.get("results", []):
        name = place.get("name")
        address = place.get("formatted_address")

        results.append({
            "business": name,
            "address": address
        })

df = pd.DataFrame(results)

df.to_csv("business_list.csv", index=False)

print("Businesses saved to business_list.csv")
