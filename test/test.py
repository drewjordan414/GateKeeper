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
import time

# Load environment variables
dotenv.load_dotenv()

def db_connection():
    # Database connection
    MONGO_URL = getenv("MONGO_URL")
    ACCOUNTS_COLLECTION = getenv("ACCOUNTS_COLLECTION")
    PASSWORDS_COLLECTION = getenv("PASSWORDS_COLLECTION")

    client = pymongo.MongoClient(MONGO_URL)
    db = client["GateKeeper"]
    accounts_collection = db[ACCOUNTS_COLLECTION]
    passwords_collection = db[PASSWORDS_COLLECTION]

    return accounts_collection, passwords_collection

#show database connection
# def show_db_connection():
#     if db_connection() == True:
#         print("Database connected successfully")
#     else:
#         print("Database connection failed")


# # Database connection
# MONGO_URL = getenv("MONGO_URL")
# ACCOUNTS_COLLECTION = getenv("ACCOUNTS_COLLECTION")
# PASSWORDS_COLLECTION = getenv("PASSWORDS_COLLECTION")

# client = pymongo.MongoClient(MONGO_URL)
# db = client["GateKeeper"]
# accounts_collection = db[ACCOUNTS_COLLECTION]
# passwords_collection = db[PASSWORDS_COLLECTION]

def encrypt_password(password: str, key: bytes) -> str:
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

# Make er Perty
def animated_ascii_art(text, delay=0.006):
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

accounts_collection, passwords_collection = db_connection()

def show_connection():
    print("Connecting to the database", end="")
    for _ in range(5):  # You can adjust the number of dots here
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(0.6)  # Adjust this for timing between dots (total of 3 seconds delay)
    print("Connected to database successfully.")  # Move t

def print_ascii_frame():
    # print ascii art of "GateKeeper" in binary
    ascii_art = """
    your secrets are safe with
    ╔═════════════════════════════════════════════════════════╗
    ║011001001110010111010011001001001010110010011001001110000║
    ╚═════════════════════════════════════════════════════════╝
    """
    print(ascii_art)


# To use the function, just call it

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


# User Registration
def register_user():
    username = input("Enter a new username: ")
    password = getpass.getpass("Enter a new password: ")
    key = input("Enter your secret key: ")
    key_collection = accounts_collection.find_one({"key": key})
    if key_collection:
        print("Key is valid")
        return True
    else:
        print("Invalid key")
        return False
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
    show_connection()
    print_ascii_frame()
    print_calling_card()
    # choice = input("Press 2 to login: ")
    # if choice == "2":
    #     if login_user():
    #         print("Login successful.")
    # else:
    #     print("Invalid choice. Please try again.")
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
            name = input("Enter the name of the account: ").lower()  # Convert input to lowercase
            # Find account using a case-insensitive search
            account = passwords_collection.find_one({"name": {"$regex": f"^{name}$", "$options": "i"}})
            if account:
                decrypted_password = decrypt_password(account['password'], account['key'])
                # Displaying the result in a table
                account_data = [[account['name'], account['email'], decrypted_password]]
                display_table(account_data, ["Name", "Email", "Password"])
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
            account_data = []
            for account in accounts:
                decrypted_password = decrypt_password(account['password'], account['key'])
                account_data.append([account['name'], account['email'], decrypted_password])  # Add a list for each account
            display_table(account_data, ["Name", "Email", "Password"])

        elif choice == "5":
            # Logout
            break
        else:
            print("Invalid choice. Please try again.")

    print("Logged out successfully.")

if __name__ == "__main__":
    main()
