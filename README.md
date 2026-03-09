# ThreatLens AI
## Live Demo

ThreatLens AI is deployed and publicly accessible:

https://your-render-url.onrender.com

ThreatLens AI is a hybrid phishing detection engine that combines heuristic analysis with AI-powered threat assessment to detect potential phishing emails.

## Features

- AI-powered phishing analysis using OpenAI
- Heuristic rule-based detection engine
- Suspicious domain detection
- Urgent language detection
- Risk scoring system (0–100)
- Streamlit web interface

## Tech Stack

Python  
Streamlit  
OpenAI API  
Regex-based heuristic detection  

## How It Works

ThreatLens AI analyzes suspicious emails using two methods:

1. **Heuristic Analysis**
   - Detects urgent language
   - Identifies suspicious domains
   - Flags malicious links

2. **AI Analysis**
   - Uses a language model to evaluate phishing indicators
   - Generates threat explanations

The system combines both results to produce a final phishing risk score.

## Run Locally

Clone the repository:
git clone https://github.com/jyagra/threatlens-ai.git

cd threatlens-ai


Install dependencies:


pip install -r requirements.txt


Run the app:


streamlit run app.py


## Author

Joel Yagra  
Cybersecurity | AI Security | Cloud Security
