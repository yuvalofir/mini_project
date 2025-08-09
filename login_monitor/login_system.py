import json
import socket
from datetime import datetime
import os
import smtplib
from email.message import EmailMessage
import sys
from login_handler import (
    login
)
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
        username = input("Choose a username (or type 'exit' to quit): ").strip()
        if username.lower() == "exit":
            print("Goodbye!")
            sys.exit()

        if username in users:
            print("Username already exists. Try another one.")
        else:
            break

    password = input("Choose a password (or type 'exit' to quit): ").strip()
    if password.lower() == "exit":
        print("Goodbye!")
        sys.exit()

    email = input("Enter your email (or type 'exit' to quit): ").strip()
    if email.lower() == "exit":
        print("Goodbye!")
        sys.exit()

    users[username] = {
        "current_password": password,
        "old_passwords": [],
        "email": email
    }
    save_users(users)
    print("User registered successfully!")

if __name__ == "__main__":
    while True:
        users = load_users()
        print("Welcome! Please choose an option:")
        print("1. Login")
        print("2. Register new user")
        print("Type 'exit' to quit the program.")
        choice = input("Enter 1 or 2: ").strip()

        if choice.lower() == "exit":
            print("Goodbye!")
            sys.exit()

        if choice == "1":
            username = input("Username: ").strip()
            if username.lower() == "exit":
                print("Goodbye!")
                sys.exit()

            if login(users, username):
                change = input("Do you want to change your password? Type 'yes' to proceed: ").strip()
                if change.lower() == "exit":
                    print("Goodbye!")
                    sys.exit()

                if change.lower() == "yes":
                    change_password(users, username)
            else:
                print("Login failed. Please try again.\n")
                continue  

        elif choice == "2":
            register(users)

        else:
            print("Invalid choice.")
