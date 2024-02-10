# house keeping 
import dotenv
import bcrypt
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from dotenv import load_dotenv
from os import getenv
import pymongo

# Load environment variables
load_dotenv()

# User Registration
def register_user(db):
    username = input("Enter a new username: ")
    password = input("Enter a new password: ")

    # Check if the username already exists
    if db.Accounts.find_one({"username": username}):
        print("Username already exists. Please choose a different username.")
        return

    # Hash the password
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Store the new user
    db.Accounts.insert_one({"username": username, "password": hashed})
    print("User registered successfully.")

# User Login
def login_user(db):
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    # Find the user in the database
    user = db.Accounts.find_one({"username": username})

    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        print("Login successful.")
        return True
    else:
        print("Invalid username or password.")
        return False

#Quick Sort Algorithm to find passwords in db
def quick_sort(arr):
    if len(arr) <= 1:
        return arr
    pivot = arr[len(arr) // 2]['totalScore']
    left = [x for x in arr if x['totalScore'] < pivot]
    middle = [x for x in arr if x['totalScore'] == pivot]
    right = [x for x in arr if x['totalScore'] > pivot]
    return quick_sort(left) + middle + quick_sort(right)

# Main function
def main():
    # Connect to the database
    client = pymongo.MongoClient(getenv("MONGO_URL"))
    db = client["GateKeeper"]

    # Prompt the user to register or login
    while True:
        choice = input("Enter 1 to register, 2 to login: ")
        if choice == "1":
            register_user(db)
        elif choice == "2":
            if login_user(db):
                break
        else:
            print("Invalid choice. Please try again.")

    # Menu
    while True:
        print("1. Add a password")
        print("2. View passwords")
        print("3. Delete a password")
        print("4. View all passwords")
        print("5. Logout")
        choice = input("Enter your choice: ")

        if choice == "1":
            # Add a password
            name = input("Enter the name of the password: ")
            password = input("Enter the password: ")
            db.Passwords.insert_one({"name": name, "password": password})
            print("Password added successfully.")
        elif choice == "2":
            # View a password
            name = input("Enter the name of the password: ")
            password = db.Passwords.find_one({"name": name})
            if password:
                print(f"Password: {password['password']}")
            else:
                print("Password not found.")
        elif choice == "3":
            # Delete a password
            name = input("Enter the name of the password: ")
            db.Passwords.delete_one({"name": name})
            print("Password deleted successfully.")
        elif choice == "4":
            # View all passwords
            passwords = db.Passwords.find()
            for password in passwords:
                print(f"Name: {password['name']}, Password: {password['password']}")
        elif choice == "5":
            # Logout
            break
        else:
            print("Invalid choice. Please try again.")

    print("Logged out successfully.")