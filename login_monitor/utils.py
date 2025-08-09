# utils.py
import json
import os
import uuid
from datetime import datetime
import smtplib, ssl
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

# Save authorized IPs per user
def save_authorized_ips(data):
    with open(AUTHORIZED_IPS_FILE, "w") as f:
        json.dump(data, f, indent=2)

# Send real email to alert about IP being blocked
SENDER_EMAIL = "bgusec5@gmail.com"  # Replace with your Gmail
APP_PASSWORD = "vxfeqesvwnfbbsic"     # Replace with your App Password

def send_alert_email(recipient_email, ip, username):
    token = generate_unblock_token(ip, recipient_email)
    unblock_link = f"http://localhost:8000/unblock?token={token}"

    msg = EmailMessage()
    msg["Subject"] = "Alert: Suspicious Login Attempt Detected"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient_email
    text_body = build_security_alert_text(username, ip, unblock_link)
    msg.set_content(text_body)

    # HTML formatted
    html_body = build_security_alert_html(username, ip, unblock_link)
    msg.add_alternative(html_body, subtype="html")

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SENDER_EMAIL, APP_PASSWORD)
            smtp.send_message(msg)
            print(f"[EMAIL] Real alert email sent to {recipient_email}")
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send email: {e}")
def build_security_alert_text(username: str, ip: str, unblock_link: str) -> str:
    return f"""Security Alert

Hi {username},

We detected multiple failed login attempts that may indicate someone is trying to access your account.
IP address: {ip}

If these login attempts were made by you, you can review and request to unblock your IP here:
{unblock_link}

If you did NOT make these attempts, we strongly recommend changing your password immediately and following our security best practices:

1) Create a strong password (12+ characters, upper/lowercase letters, numbers, symbols).
2) Avoid reusing passwords across different sites.
3) Store passwords securely (use a reputable password manager).
4) Enable Two-Factor Authentication (2FA) wherever possible.
5) Monitor account activity for unusual sign-ins.
6) Be cautious with links and attachments from unknown sources.

Stay safe,
Your Security Team
"""

def build_security_alert_html(username: str, ip: str, unblock_link: str) -> str:
    return f"""
<html>
  <body style="font-family: Arial, sans-serif; line-height:1.55; color:#222;">
    <h2 style="margin-bottom:12px;">Security Alert – Unusual Login Attempts</h2>
    <p style="margin-bottom:12px;">
      We detected multiple failed login attempts that may indicate someone is trying to access your account.<br>
      <b>IP Address:</b> {ip}
    </p>

    <p style="margin-bottom:12px;">
      If these login attempts were made by you, please review and request to unblock your IP here:<br>
      <a href="{unblock_link}" 
         style="display:inline-block; margin-top:6px; padding:10px 14px; background:#0069d9; color:#fff; text-decoration:none; border-radius:6px;">
        Unblock My IP
      </a>
    </p>

    <p style="margin-bottom:16px;">
      If you did <b>NOT</b> make these attempts, we strongly recommend changing your password immediately and reviewing the following security tips:
    </p>

    <h3 style="margin:16px 0 8px;">How to Keep Your Account and Personal Information Secure</h3>
    <ul style="padding-left:20px; margin:8px 0 16px;">
      <li><b>Create a strong password:</b> Use at least 12 characters combining uppercase and lowercase letters, numbers, and symbols. Avoid simple words, personal dates, and easy sequences like <code>123456</code> or <code>qwerty</code>.</li>
      <li><b>Avoid password reuse:</b> Don’t use the same password across multiple services.</li>
      <li><b>Store passwords securely:</b> Use a reputable password manager (e.g., <i>Bitwarden</i>, <i>1Password</i>, <i>KeePass</i>) instead of unencrypted notes.</li>
      <li><b>Enable Two-Factor Authentication (2FA):</b> Activate it wherever possible—especially for email, banking, and social media accounts.</li>
      <li><b>Monitor account activity:</b> Regularly check login history for unknown locations or IP addresses.</li>
      <li><b>Be cautious with links and attachments:</b> Do not click suspicious links or download files from untrusted sources.</li>
    </ul>

    <p style="font-size:12px; color:#666;">
      This message was sent to help protect your account.
    </p>
  </body>
</html>
"""


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