# utils.py
import json
import os
import uuid
from datetime import datetime
import smtplib
from email.message import EmailMessage

BLACKLIST_FILE = "blacklist.json"
UNBLOCK_REQUESTS_FILE = "unblock_requests.json"
AUTHORIZED_IPS_FILE = "authorized_ips.json"

# Log failed login attempts
def log_failed_attempt(ip, username, password_attempt, reason):
    with open("log.txt", "a") as log:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"[{now}] IP: {ip} | User: {username} | Password: {password_attempt} | Reason: {reason}\n")

# Load blacklist from file
def load_blacklist():
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "w") as f:
            json.dump({"ips": []}, f)
    with open(BLACKLIST_FILE) as f:
        return json.load(f)["ips"]

# Save blacklist to file
def save_blacklist(ips):
    with open(BLACKLIST_FILE, "w") as f:
        json.dump({"ips": ips}, f, indent=2)

# Load authorized IPs per user
def load_authorized_ips():
    if not os.path.exists(AUTHORIZED_IPS_FILE):
        return {}
    with open(AUTHORIZED_IPS_FILE) as f:
        return json.load(f)

# Save authorized IPs per user
def save_authorized_ips(data):
    with open(AUTHORIZED_IPS_FILE, "w") as f:
        json.dump(data, f, indent=2)

# Send real email to alert about IP being blocked
SENDER_EMAIL = "bgusec5@gmail.com"  # Replace with your Gmail
APP_PASSWORD = "ixux zemm zwia qxbl"     # Replace with your App Password

def send_alert_email(recipient_email, ip):
    token = generate_unblock_token(ip, recipient_email)
    unblock_link = f"http://localhost:8000/unblock?token={token}"

    msg = EmailMessage()
    msg["Subject"] = "Alert: Suspicious Login Attempt Detected"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient_email
    msg.set_content(f"""Hello,

We detected multiple failed login attempts to your account.
As a result, the IP address {ip} has been temporarily blocked.

If this was you and you'd like to unblock your IP, please click the link below:
{unblock_link}

Thank you,
Security System
""")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SENDER_EMAIL, APP_PASSWORD)
            smtp.send_message(msg)
            print(f"[EMAIL] Real alert email sent to {recipient_email}")
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send email: {e}")

# Send email to approve or reject unknown IP access
def send_ip_verification_email(recipient_email, ip, username):
    token = str(uuid.uuid4())
    approve_link = f"http://localhost:8000/approve_ip?token={token}&username={username}&ip={ip}"
    reject_link = f"http://localhost:8000/reject_ip?token={token}&username={username}&ip={ip}"

    msg = EmailMessage()
    msg["Subject"] = "New IP Access Detected"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient_email
    msg.set_content(f"""Hello,

A login attempt to your account was made from an unknown IP address: {ip}.

If this was you, please approve the IP:
{approve_link}

If this was NOT you, click below to block the IP and secure your account:
{reject_link}

⚠️ Your account may have been compromised.
We recommend that you immediately change your password.

Security Tips:
- Use strong, unique passwords (e.g., 12+ characters, mix of letters/numbers/symbols)
- Do not reuse passwords across services
- Avoid clicking on suspicious links
- Consider using a password manager

Stay safe,
Security System
""")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SENDER_EMAIL, APP_PASSWORD)
            smtp.send_message(msg)
            print(f"[EMAIL] IP verification email sent to {recipient_email}")
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send IP verification email: {e}")

# Generate token to unblock IPs
def generate_unblock_token(ip, email):
    token = str(uuid.uuid4())
    request = {
        "ip": ip,
        "email": email,
        "token": token
    }

    if not os.path.exists(UNBLOCK_REQUESTS_FILE):
        with open(UNBLOCK_REQUESTS_FILE, "w") as f:
            json.dump({"requests": []}, f, indent=2)

    with open(UNBLOCK_REQUESTS_FILE, "r") as f:
        data = json.load(f)

    data["requests"].append(request)

    with open(UNBLOCK_REQUESTS_FILE, "w") as f:
        json.dump(data, f, indent=2)

    return token

# Levenshtein distance
def levenshtein_distance(a, b):
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost
            )

    return dp[m][n]

# Similarity score
def password_similarity(input_pwd, reference_pwd):
    distance = levenshtein_distance(input_pwd, reference_pwd)
    max_len = max(len(input_pwd), len(reference_pwd))
    if max_len == 0:
        return 1.0
    return 1 - (distance / max_len)