import dotenv
import bcrypt
import pymongo
from os import getenv

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

# User Registration
def register_user():
    username = input("Enter a new username: ")
    password = input("Enter a new password: ")

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
    password = input("Enter your password: ")

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
    # Prompt the user to register or login
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    deshashed = bcrypt.checkpw(password.encode('utf-8'), hashed)
    while True:
        choice = input("Enter 1 to register, 2 to login: ")
        if choice == "1":
            register_user()
        elif choice == "2":
            if login_user():
                break
        else:
            print("Invalid choice. Please try again.")

    # Menu
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
            passwords_collection.insert_one({"name": name, "email": email ,"password": hashed})
            print("Password added successfully.")
        elif choice == "2":
            # View account
            name = input("Enter the name of the account: ")
            password = passwords_collection.find_one({"name": name})
            if name:
                print(f"Email: {email['email']}, Password: {password['password']}")
            else:
                print("Account not found.")
        elif choice == "3":
            # Delete account
            name = input("Enter the name of the account: ")
            passwords_collection.delete_one({"name": name})
            print("Account deleted successfully!")
        elif choice == "4":
            # View all accounts
            passwords = passwords_collection.find()
            for password in passwords:
                print(f"Name: {password['name']}, Password: {password['password']}")
        elif choice == "5":
            # Logout
            break
        else:
            print("Invalid choice. Please try again.")

    print("Logged out successfully.")

if __name__ == "__main__":
    main()
