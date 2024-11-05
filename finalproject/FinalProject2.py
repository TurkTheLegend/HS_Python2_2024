import os
import json
import base64

import bcrypt
from cryptography.fernet import Fernet
import pandas as pd


class User:
    def __init__(self, username, master_password):
        self.username = username
        self.master_password = master_password
        self.apps = pd.DataFrame(columns=["title", "username", "encrypted_password", "salt"])

    def store_master_password(self):
        """Stores the master password securely."""
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(self.master_password.encode("utf-8"), salt)
        return hashed_password.decode("utf-8"), salt.decode("utf-8")

    def check_master_password(self, master_password):
        """Checks if the provided master password matches the stored one."""
        stored_master_password_hash, stored_salt = self.master_password
        return bcrypt.checkpw(
            master_password.encode("utf-8"),
            stored_master_password_hash.encode("utf-8"),
        )

    def store_app_password(self, title, username, password):
        """Encrypts and stores an app password using the master password."""
        salt = bcrypt.gensalt()
        key = bcrypt.kdf(
            password=self.master_password[0].encode("utf-8"),
            salt=salt,
            desired_key_bytes=32,
            rounds=100,
        )
        b64_key = base64.urlsafe_b64encode(key)
        f = Fernet(b64_key)
        encrypted_password = f.encrypt(password.encode("utf-8")).decode("utf-8")

        new_data = {
            "title": title,
            "username": username,
            "encrypted_password": encrypted_password,
            "salt": salt.decode("utf-8"),
        }

        self.apps = pd.concat([self.apps, pd.DataFrame([new_data])], ignore_index=True)

    def retrieve_app_password(self, title, username):
        """Retrieves and decrypts a stored app password."""
        entry = self.apps[
            (self.apps["title"] == title)
            & (self.apps["username"] == username)
        ]
        if not entry.empty:
            encrypted_app_password = entry["encrypted_password"].values[0]
            app_salt = entry["salt"].values[0]
            key = bcrypt.kdf(
                password=self.master_password[0].encode("utf-8"),
                salt=app_salt.encode("utf-8"),
                desired_key_bytes=32,
                rounds=100,
            )
            b64_key = base64.urlsafe_b64encode(key)
            f = Fernet(b64_key)
            decrypted_app_password = f.decrypt(
                encrypted_app_password.encode("utf-8")
            ).decode("utf-8")
            return decrypted_app_password
        else:
            return None

    def export_to_csv(self, filename="passwords.csv"):
        """
        Exports the user's app passwords to a CSV file in a format
        compatible with common password managers.
        """
        try:
            # Create a copy of the DataFrame to avoid modifying the original
            export_df = self.apps.copy()

            # Rename columns to match common password manager formats
            export_df = export_df.rename(columns={
                "title": "name",  # Rename "title" to "name"
            })

            # Decrypt the passwords
            export_df['password'] = export_df.apply(
                lambda row: self.retrieve_app_password(row['name'], row['username']), axis=1
            )

            # Add a URL column (we'll assume it's not stored currently)
            export_df['url'] = ''  # You can populate this if you have URL data

            # Add a notes column (optional)
            export_df['notes'] = ''

            # Reorder columns to match common formats
            export_df = export_df[['name', 'url', 'username', 'password', 'notes']]

            # Export the DataFrame to CSV (no need to drop columns here)
            export_df.to_csv(filename, index=False)
            print(f"Passwords exported to {filename} successfully!")

        except Exception as e:
            print(f"Error exporting to CSV: {e}")


class PasswordManager:
    def __init__(self):
        self.users = self.load_data()

    def load_data(self) -> dict:
        """Loads user data from a JSON file."""
        if not os.path.exists("data.json"):
            return {}
        with open("data.json", "r") as f:
            data = json.load(f)
            users = {}
            for username, user_data in data.items():
                master_password = (
                    user_data["master_password"][0],
                    user_data["master_password"][1],
                )
                user = User(username, master_password)
                user.apps = pd.DataFrame(user_data.get("apps", []))
                users[username] = user
            return users

    def save_data(self) -> None:
        """Saves user data to a JSON file."""
        data = {}
        for username, user in self.users.items():
            data[username] = {
                "master_password": user.master_password,
                "apps": user.apps.to_dict(orient="records"),
            }
        with open("data.json", "w") as f:
            json.dump(data, f, indent=4)

    def create_master_account(self, username, password):
        """Creates a new master account for a user."""
        if username in self.users:
            print("Username already exists.")
            return

        user = User(username, password)
        hashed_password, salt = user.store_master_password()
        user.master_password = (hashed_password, salt)
        self.users[username] = user
        self.save_data()
        print("Master password stored successfully!")

    def login_to_master_account(self, username, master_password):
        """Logs in a user to their master account."""
        user = self.users.get(username)
        if user and user.check_master_password(master_password):
            print("Login successful!")
            return user
        else:
            print("Incorrect master password or username not found.")
            return None

    def register_app_account(self, user, title, username, password):
        """Registers a new app account for a logged-in user."""
        user.store_app_password(title, username, password)
        self.save_data()
        print(f"Password for {username} on {title} stored successfully!")

    def retrieve_app_account_password(self, user, title, username):
        """Retrieves the password for an app account."""
        password = user.retrieve_app_password(title, username)
        if password:
            print(f"Password for {username} on {title}: {password}")
            return password
        else:
            print("Credentials not found.")
            return None

    def display_app_accounts(self, user):
        """Displays the list of applications and accounts using a DataFrame."""
        if not user.apps.empty:
            # Group by title and aggregate usernames
            app_df = user.apps.groupby('title')['username'].apply(list).reset_index(name='accounts')

            # Display the DataFrame
            print(app_df.to_markdown(index=False, numalign="left", stralign="left"))
        else:
            print("No stored passwords found.")



def main():
    """Main function to handle user interaction and password management."""
    password_manager = PasswordManager()

    while True:
        print("\nChoose an action:")
        print("1. Create Master Account")
        print("2. Login to Master Account")
        print("3. Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            username = input("Enter username for your master account: ").strip()
            while username == "":
                username = input("Enter username for your master account: ").strip()
            while True:
                password = input("Enter master password: ").strip()
                while password == "":
                    password = input("Enter master password: ").strip()
                confirm_password = input("Confirm master password: ")
                if password == confirm_password:
                    password_manager.create_master_account(username, password)
                    break
                else:
                    print("Passwords do not match. Please try again.")

        elif choice == "2":
            username = input("Enter username: ")
            master_password = input("Enter master password: ")
            user = password_manager.login_to_master_account(username, master_password)
            if user:
                while True:
                    print("\nChoose an action:")
                    print("1. Register new app account")
                    print("2. Retrieve app account password")
                    print("3. Display app accounts")
                    print("4. Export passwords to CSV")
                    print("5. Exit")
                    choice = input("Enter your choice: ")
                    if choice == "1":
                        title = input("Enter application name: ")
                        username = input("Enter account username: ").strip()
                        while username == "":
                            username = input("Enter account username: ").strip()
                        password = input("Enter password: ").strip()
                        while password == "":
                            password = input(("Enter password: ")).strip()
                        password_manager.register_app_account(
                            user, title, username, password
                        )
                    elif choice == "2":
                        if user.apps.empty:  # Use .empty to check if DataFrame is empty
                            print("No stored passwords found.")
                            continue

                        # Get unique app names from the DataFrame
                        titles = user.apps['title'].unique()
                        print("\nYour applications:")
                        for i, app in enumerate(titles):
                            print(f"{i + 1}. {app}")

                        try:
                            app_choice = int(input("Choose an application: ")) - 1
                            chosen_app = titles[app_choice]  # Select app name from the array

                            # Filter accounts for the chosen app
                            accounts_for_app = user.apps[user.apps['title'] == chosen_app]['username'].tolist()
                            print("\nYour accounts for this application:")
                            for i, account in enumerate(accounts_for_app):
                                print(f"{i + 1}. {account}")

                            account_choice = int(input("Choose an account: ")) - 1
                            chosen_account = accounts_for_app[account_choice]  # Select account from the filtered list

                            password_manager.retrieve_app_account_password(user, chosen_app, chosen_account)

                        except (ValueError, IndexError):
                            print("Invalid choice.")

                    elif choice == "3":
                        password_manager.display_app_accounts(user)
                    elif choice == "4":
                        filename = input("Enter the desired filename (e.g., passwords.csv): ")
                        user.export_to_csv(filename)
                    elif choice == "5":
                        break
                    else:
                        print("Invalid choice.")
            else:
                print("Incorrect master password or username not found.")

        elif choice == "3":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()