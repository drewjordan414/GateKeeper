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
            passwords_collection.insert_one({"name": name, "password": password})
            print("Password added successfully.")
        elif choice == "2":
            # View a password
            name = input("Enter the name of the password: ")
            password = passwords_collection.find_one({"name": name})
            if password:
                print(f"Password: {password['password']}")
            else:
                print("Password not found.")
        elif choice == "3":
            # Delete a password
            name = input("Enter the name of the password: ")
            passwords_collection.delete_one({"name": name})
            print("Password deleted successfully.")
        elif choice == "4":
            # View all passwords
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
