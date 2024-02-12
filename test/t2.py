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

# global variables
current_user_accounts_collection = None

#encrypt and decrypt passwords
def encrypt_password(password: str, key: bytes) -> str:
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

def show_connection():
    print("Connecting to the database", end="")
    for _ in range(5):  
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(0.6)  
    print("Connected to database successfully.")  

def ending_connection():
    print("Ending connection to the database", end="")
    for _ in range(5):  
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(0.6)  
    print("Ended connection to database successfully. Goodbye.")  

def print_ascii_frame():
    # print ascii art of "GateKeeper" in binary
    ascii_art = """
    your secrets are safe with
    ╔═════════════════════════════════════════════════════════╗
    ║011001001110010111010011001001001010110010011001001110000║
    ╚═════════════════════════════════════════════════════════╝
    """
    print(ascii_art)


def print_calling_card():
    turtle = (
        "|-------------------------|\n"
        "|                   __    |\n"
        "|        .,-;-;-,. /'_\   |\n"
        "|      _/_/_/_|_\_\) /    |\n"
        "|    '-<_><_><_><_>=/\    |\n"
        "|      `/_/====/_/-'\_\   |\n"
        "|       ""     ""    ""   | \n"
        "|github.com/drewjordan414 |\n"
        "|-------------------------|\n"

    )
    print(turtle)

def db_connection():
    # Database connection
    MONGO_URL = getenv("MONGO_URL")
    client = pymongo.MongoClient(MONGO_URL)
    db = client["GateKeeper"]

    ACCOUNTS_COLLECTION = getenv("ACCOUNTS_COLLECTION")
    PASSWORDS_COLLECTION = getenv("PASSWORDS_COLLECTION")
    accounts_collection = db[ACCOUNTS_COLLECTION]
    passwords_collection = db[PASSWORDS_COLLECTION]

    return db, accounts_collection, passwords_collection

def encrypt_password(password: str, key: bytes) -> str:
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

def display_table(data, fields):
    table = PrettyTable()
    table.field_names = fields
    for row in data:
        table.add_row(row)
    print(table)

# Additional functions for animated ASCII art, etc.

def register_user():
    db, _, _ = db_connection()  # We don't need accounts_collection or passwords_collection here
    user_accounts_collection = db["User_Accounts"]  # Assuming you have a User_Accounts collection

    username = input("Enter a new username: ")
    secret_key = getpass.getpass("Enter your secret key: ")
    password = getpass.getpass("Enter a new password: ")

    if user_accounts_collection.find_one({"username": username}):
        print("Username already exists. Please choose a different username.")
        return False

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_secret_key = bcrypt.hashpw(secret_key.encode('utf-8'), bcrypt.gensalt())

    user_accounts_collection.insert_one({"username": username, "password": hashed_password, "secret_key": hashed_secret_key})
    print("User registered successfully.")
    return True


def login_user():
    global current_user_accounts_collection
    
    db, user_accounts_collection, _ = db_connection()
    
    username = input("Enter your username: ")
    secret_key = getpass.getpass("Enter your secret key: ")
    password = getpass.getpass("Enter your password: ")

    user = user_accounts_collection.find_one({"username": username})
    if user:
        if bcrypt.checkpw(secret_key.encode('utf-8'), user["secret_key"]) and bcrypt.checkpw(password.encode('utf-8'), user["password"]):
            print("Login successful.")
            current_user_accounts_collection = db[f"{username}_accounts"]
            return True
        else:
            print("Invalid secret key or password.")
            return False
    else:
        print("User not found.")
        return False

def logout_user():
    global current_user_accounts_collection
    current_user_accounts_collection = None
    print("Logged out successfully.")

def add_account():
    if current_user_accounts_collection is None:
        print("You must be logged in to add an account.")
        return

    name = input("Enter the name of the account: ")
    email = input("Enter the email of the account: ")
    password = input("Enter the password: ")

    account_key = Fernet.generate_key()
    encrypted_password = encrypt_password(password, account_key)

    current_user_accounts_collection.insert_one({"name": name, "email": email, "password": encrypted_password, "key": account_key})
    print("Account added successfully.")

def view_accounts():
    if current_user_accounts_collection is None:
        print("You must be logged in to view accounts.")
        return

    accounts = current_user_accounts_collection.find()
    account_data = []
    for account in accounts:
        decrypted_password = decrypt_password(account['password'], account['key'])
        account_data.append([account['name'], account['email'], decrypted_password])

    if account_data:
        display_table(account_data, ["Name", "Email", "Password"])
    else:
        print("No accounts found.")

def delete_account():
    if current_user_accounts_collection is None:
        print("You must be logged in to delete an account.")
        return

    # Placeholder logic for deleting an account
    name = input("Enter the name of the account to delete: ")
    result = current_user_accounts_collection.delete_one({"name": name})

    if result.deleted_count > 0:
        print("Account deleted successfully.")
    else:
        print("No such account found.")

def view_all_accounts():
    if current_user_accounts_collection is None:
        print("You must be logged in to view all accounts.")
        return

    # Placeholder logic for viewing all accounts
    accounts = current_user_accounts_collection.find()
    account_data = []
    for account in accounts:
        decrypted_password = decrypt_password(account['password'], account['key'])
        account_data.append([account['name'], account['email'], decrypted_password])

    if account_data:
        display_table(account_data, ["Name", "Email", "Password"])
    else:
        print("No accounts found.")

# Main function
def main():
    show_connection()
    print_ascii_frame()
    print_calling_card()

    logged_in = False

    while True:
        if not logged_in:
            print("1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Enter your choice: ")

            if choice == "1":
                register_user()
            elif choice == "2":
                logged_in = login_user()
            elif choice == "3":
                break
            else:
                print("Invalid choice. Please try again.")
        else:
            while True:
                print("1. Add an Account")
                print("2. View Accounts")
                print("3. Delete an Account")
                print("4. View All Accounts")
                print("5. Logout")
                choice = input("Enter your choice: ")
                
                if choice == "1":
                    add_account()
                elif choice == "2":
                    view_accounts()
                elif choice == "3":
                    delete_account()  # Implement this function
                elif choice == "4":
                    view_all_accounts()  # Implement this function
                elif choice == "5":
                    logout_user()
                    logged_in = False
                    break
                else:
                    print("Invalid choice. Please try again.")

    print("Exited successfully.")

if __name__ == "__main__":
    main()
