import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

# Load dataset
data = pd.read_csv("phishing_dataset.csv")

# Remove rows with missing values
data = data.dropna()

# Features and labels
X = data["text"]
y = data["label"]

# Convert text to vectors
vectorizer = TfidfVectorizer(stop_words="english")

X_vec = vectorizer.fit_transform(X)

# Train classifier
model = LogisticRegression(solver="liblinear")

model.fit(X_vec, y)

# Save model
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("✅ Model trained successfully")
