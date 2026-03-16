import smtplib
from email.mime.text import MIMEText

EMAIL = "joel.threatlens@gmail.com"
PASSWORD = "rnut katl gpxg zxsa"

recipient = "test@example.com"

msg = MIMEText("Hello,\n\nI'm offering a free phishing security check for small businesses.\n\nJoel\nThreatLens AI")
msg["Subject"] = "Free Cybersecurity Check"
msg["From"] = EMAIL
msg["To"] = recipient

server = smtplib.SMTP("smtp.gmail.com", 587)
server.starttls()
server.login(EMAIL, PASSWORD)
server.sendmail(EMAIL, recipient, msg.as_string())
server.quit()

print("Email sent successfully")
