import dotenv
import bcrypt
import pymongo
import getpass
from cryptography.fernet import Fernet
from os import getenv
from prettytable import PrettyTable
from pyfiglet import Figlet
import time
import sys

# Load environment variables
dotenv.load_dotenv()

# Database connection
MONGO_URL = getenv("MONGO_URL")
ACCOUNTS_COLLECTION = getenv("ACCOUNTS_COLLECTION")
PASSWORDS_COLLECTION = getenv("PASSWORDS_COLLECTION")

client = pymongo.MongoClient(MONGO_URL)
db = client["GateKeeper"]
accounts_collection = db[ACCOUNTS_COLLECTION]
passwords_collection = db[PASSWORDS_COLLECTION]

def encrypt_password(password: str, key: bytes) -> str:
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

# Make er Perty
def animated_ascii_art(text, delay=0.06):
    f = Figlet(font='slant')
    result = f.renderText(text)
    for char in result:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)

def display_table(data, fields):
    table = PrettyTable()
    table.field_names = fields
    for row in data:
        table.add_row(row)
    print(table)


# User Registration
def register_user():
    username = input("Enter a new username: ")
    password = getpass.getpass("Enter a new password: ")

    # Check if the username already exists
    if accounts_collection.find_one({"username": username}):
        print("Username already exists. Please choose a different username.")
        return

    # Hash the password
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Store the new user
    accounts_collection.insert_one({"username": username, "password": hashed})
    print("User registered successfully.")

# User Login
def login_user():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")

    # Find the user in the database
    user = accounts_collection.find_one({"username": username})

    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        print("Login successful.")
        return True
    else:
        print("Invalid username or password.")
        return False

# Main function
def main():
    animated_ascii_art('GateKeeper')
    while True:
        choice = input("Enter 1 to register, 2 to login: ")
        if choice == "1":
            register_user()
        elif choice == "2":
            if login_user():
                break
        else:
            print("Invalid choice. Please try again.")

    # Menu for account management
    while True:
        print("1. Add an Account")
        print("2. View accounts")
        print("3. Delete an account")
        print("4. View all accounts")
        print("5. Logout")
        choice = input("Enter your choice: ")
        
        if choice == "1":
            # Add account
            name = input("Enter the name of the account: ")
            email = input("Enter the email of the account: ")
            password = input("Enter the password: ")
            # Generate a unique key for this account
            account_key = Fernet.generate_key()
            encrypted_password = encrypt_password(password, account_key)
            passwords_collection.insert_one({"name": name, "email": email, "password": encrypted_password, "key": account_key})
            print("Account added successfully.")
        elif choice == "2":
            # View account
            name = input("Enter the name of the account: ")
            account = passwords_collection.find_one({"name": name})
            if account:
                decrypted_password = decrypt_password(account['password'], account['key'])
                print(f"Email: {account['email']}, Password: {decrypted_password}")
            else:
                print("Account not found.")
        elif choice == "3":
            # Delete account
            name = input("Enter the name of the account: ")
            passwords_collection.delete_one({"name": name})
            print("Account deleted successfully!")
        elif choice == "4":
            # View all accounts
            accounts = passwords_collection.find()
            for account in accounts:
                decrypted_password = decrypt_password(account['password'], account['key'])
                print(f"Name: {account['name']}, Email: {account['email']}, Password: {decrypted_password}")
                display_table([account], ["Name", "Email", "Password"])
        elif choice == "5":
            # Logout
            break
        else:
            print("Invalid choice. Please try again.")

    print("Logged out successfully.")

if __name__ == "__main__":
    main()
