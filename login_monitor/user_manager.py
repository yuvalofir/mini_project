import json
import os

DB_FILE = "users_db.json"

def load_users():
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w") as f:
            json.dump({"users": {}}, f)
    with open(DB_FILE) as f:
        return json.load(f)["users"]

def save_users(users):
    with open(DB_FILE, "w") as f:
        json.dump({"users": users}, f, indent=2)

def register_user(users):
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

def change_password(users, username):
    from login_handler import login
    if not login(users, username):
        return
    new_pwd = input("Enter new password: ")
    old_pwd = users[username]["current_password"]
    users[username]["old_passwords"].insert(0, old_pwd)
    users[username]["old_passwords"] = users[username]["old_passwords"][:2]
    users[username]["current_password"] = new_pwd
    save_users(users)
    print("Password changed successfully.")