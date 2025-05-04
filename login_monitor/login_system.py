import json
import socket
from datetime import datetime
import os
import smtplib
from email.message import EmailMessage

DB_FILE = "users_db.json"
BLACKLIST_FILE = "blacklist.json"
MAX_ATTEMPTS = 3

# Load or initialize users database
def load_users():
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w") as f:
            json.dump({"users": {}}, f)
    with open(DB_FILE) as f:
        return json.load(f)["users"]

def save_users(users):
    with open(DB_FILE, "w") as f:
        json.dump({"users": users}, f, indent=2)

# Load or initialize blacklist
def load_blacklist():
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "w") as f:
            json.dump({"ips": []}, f)
    with open(BLACKLIST_FILE) as f:
        return json.load(f)["ips"]

def save_blacklist(ips):
    with open(BLACKLIST_FILE, "w") as f:
        json.dump({"ips": ips}, f, indent=2)

def get_local_ip():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception:
        return "UNKNOWN"

def log_failed_attempt(ip, username, password_attempt, reason):
    with open("log.txt", "a") as log:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"[{now}] IP: {ip} | User: {username} | Password: {password_attempt} | Reason: {reason}\n")

def send_alert_email(email, ip):
    # Dummy email sender function for simulation only
    print(f"[EMAIL] Alert sent to {email} about blocked IP {ip}.")
    # To implement real emails, configure SMTP here

def login(users, username):
    ip = get_local_ip()
    if ip in load_blacklist():
        print("Your IP is currently blocked.")
        return False

    if username not in users:
        print("Username does not exist.")
        return False

    user_data = users[username]
    attempts = 0

    while attempts < MAX_ATTEMPTS:
        password = input("Password: ")
        if password == user_data["current_password"]:
            print("Login successful!")
            return True
        else:
            attempts += 1
            log_failed_attempt(ip, username, password, "Incorrect password")
            remaining = MAX_ATTEMPTS - attempts
            if remaining > 0:
                print(f"Incorrect password. Attempt {attempts}/{MAX_ATTEMPTS}. {remaining} tries left.")

    # After 3 failed attempts
    blacklist = load_blacklist()
    if ip not in blacklist:
        blacklist.append(ip)
        save_blacklist(blacklist)
        send_alert_email(user_data["email"], ip)
    print("Too many failed attempts. Your IP has been blocked.")
    return False

def change_password(users, username):
    if not login(users, username):
        return
    new_pwd = input("Enter new password: ")
    old_pwd = users[username]["current_password"]
    users[username]["old_passwords"].insert(0, old_pwd)
    users[username]["old_passwords"] = users[username]["old_passwords"][:2]
    users[username]["current_password"] = new_pwd
    save_users(users)
    print("Password changed successfully.")

def register(users):
    print("\n--- User Registration ---")
    while True:
        username = input("Choose a username: ")
        if username in users:
            print("Username already exists. Try another one.")
        else:
            break
    password = input("Choose a password: ")
    email = input("Enter your email: ")
    users[username] = {
        "current_password": password,
        "old_passwords": [],
        "email": email
    }
    save_users(users)
    print("User registered successfully!")

if __name__ == "__main__":
    users = load_users()
    print("Welcome! Please choose an option:")
    print("1. Login")
    print("2. Register new user")
    choice = input("Enter 1 or 2: ")

    if choice == "1":
        username = input("Username: ")
        if login(users, username):
            change = input("Do you want to change your password? Type 'yes' to proceed: ")
            if change.lower() == "yes":
                change_password(users, username)

    elif choice == "2":
        register(users)
    else:
        print("Invalid choice.")
