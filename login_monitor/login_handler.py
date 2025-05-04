# login_handler.py
import socket
import json
import os
from datetime import datetime
from utils import (
    log_failed_attempt,
    send_alert_email,
    send_ip_verification_email,
    load_blacklist,
    save_blacklist,
    password_similarity,
    load_authorized_ips,
    save_authorized_ips
)

MAX_ATTEMPTS = 3
ATTEMPT_TRACK_FILE = "attempts.json"


def get_local_ip():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception:
        return "UNKNOWN"


def load_attempts():
    if not os.path.exists(ATTEMPT_TRACK_FILE):
        return {}
    with open(ATTEMPT_TRACK_FILE) as f:
        return json.load(f)


def save_attempts(attempts):
    with open(ATTEMPT_TRACK_FILE, "w") as f:
        json.dump(attempts, f, indent=2)


def login(users, username):
    ip = get_local_ip()
    if ip in load_blacklist():
        print("Your IP is currently blocked.")
        return False

    if username not in users:
        print("Username does not exist.")
        return False

    user_data = users[username]
    authorized_ips = load_authorized_ips()
    is_new_ip = username in authorized_ips and ip not in authorized_ips[username]

    attempts_data = load_attempts()
    user_attempts = attempts_data.get(ip, 0)

    while user_attempts < MAX_ATTEMPTS:
        password = input("Password: ")
        if password == user_data["current_password"]:
            print("Login successful!")

            # Reset attempt count
            if ip in attempts_data:
                del attempts_data[ip]
                save_attempts(attempts_data)

            # Handle new IP now (after successful login)
            if username in authorized_ips:
                if ip not in authorized_ips[username]:
                    print("New IP detected. Login not fully approved until confirmed.")
                    send_ip_verification_email(user_data["email"], ip, username)
                    return False
            else:
                authorized_ips[username] = [ip]
                save_authorized_ips(authorized_ips)

            return True
        else:
            # Similarity check
            pwd_candidates = [user_data["current_password"]] + user_data.get("old_passwords", [])
            similarities = [(p, password_similarity(password, p)) for p in pwd_candidates]
            most_similar_pwd, similarity = max(similarities, key=lambda x: x[1])

            risk_level = "likely attack" if similarity < 0.4 else ("suspicious" if similarity < 0.8 else "low risk")
            log_failed_attempt(ip, username, password, f"Incorrect password – max similarity: {similarity:.2f} with password: {most_similar_pwd} | Risk: {risk_level}")

            if similarity >= 0.8:
                print("Incorrect password. The password you entered is wrong but quite similar. Please try again.")
                continue

            user_attempts += 1
            attempts_data[ip] = user_attempts
            save_attempts(attempts_data)

            remaining = MAX_ATTEMPTS - user_attempts
            if remaining > 0:
                print(f"Incorrect password. Attempt {user_attempts}/{MAX_ATTEMPTS}. {remaining} tries left.")

    # Exceeded attempts: block IP and notify user
    blacklist = load_blacklist()
    if ip not in blacklist:
        blacklist.append(ip)
        save_blacklist(blacklist)
        send_alert_email(user_data["email"], ip)
    print("Too many failed attempts. Your IP has been blocked.")
    return False
