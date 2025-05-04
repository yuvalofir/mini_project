from user_manager import load_users, save_users, register_user, change_password
from login_handler import login

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
        register_user(users)
    else:
        print("Invalid choice.")
