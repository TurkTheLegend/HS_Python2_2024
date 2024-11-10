import os
import json
import base64
import bcrypt
from cryptography.fernet import Fernet
import pandas as pd
from typing import Dict, Tuple, Union


class User:
    """Represents a user with a master password and app accounts."""

    def __init__(self, username: str, master_password: str) -> None:
        """
        Initializes a User object.

        Args:
            username: The user's username.
            master_password: The user's master password.
        """
        self.username = username
        self.master_password = master_password
        self.apps = pd.DataFrame(
            columns=["title", "username", "encrypted_password", "salt"]
        )

    def store_master_password(self) -> tuple[str, str]:
        """
        Stores the master password securely using bcrypt.

        Returns:
            A tuple containing the hashed master password and the salt.
        """
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(
            self.master_password.encode("utf-8"), salt
        )
        return hashed_password.decode("utf-8"), salt.decode("utf-8")

    def check_master_password(self, master_password: str) -> bool:
        """
        Checks if the provided master password matches the stored one.

        Args:
            master_password: The master password to check.

        Returns:
            True if the passwords match, False otherwise.
        """
        stored_master_password_hash, stored_salt = self.master_password
        return bcrypt.checkpw(
            master_password.encode("utf-8"),
            stored_master_password_hash.encode("utf-8"),
        )

    def store_app_password(
        self, title: str, username: str, password: str
    ) -> None:
        """
        Encrypts and stores an app password using the master password.

        Args:
            title: The title of the application.
            username: The username for the app account.
            password: The password for the app account.
        """
        salt = bcrypt.gensalt()
        key = bcrypt.kdf(
            password=self.master_password[0].encode("utf-8"),
            salt=salt,
            desired_key_bytes=32,
            rounds=100,
        )
        b64_key = base64.urlsafe_b64encode(key)
        f = Fernet(b64_key)
        encrypted_password = f.encrypt(password.encode("utf-8")).decode(
            "utf-8"
        )

        new_data = {
            "title": title,
            "username": username,
            "encrypted_password": encrypted_password,
            "salt": salt.decode("utf-8"),
        }

        self.apps = pd.concat(
            [self.apps, pd.DataFrame([new_data])], ignore_index=True
        )

    def retrieve_app_password(
        self, title: str, username: str
    ) -> Union[str, None]:
        """
        Retrieves and decrypts a stored app password.

        Args:
            title: The title of the application.
            username: The username for the app account.

        Returns:
            The decrypted password if found, None otherwise.
        """
        try:
            # Set 'title' and 'username' as index for faster lookup
            df_indexed = self.apps.set_index(["title", "username"])

            # Access the entry directly using the index
            encrypted_app_password = df_indexed.loc[
                (title, username), "encrypted_password"
            ]
            app_salt = df_indexed.loc[(title, username), "salt"]

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

        except KeyError:
            return None

    def export_to_csv(self, filename: str = "passwords.csv") -> None:
        """
        Exports the user's app passwords to a CSV file in a format
        compatible with common password managers.

        Args:
            filename: The name of the CSV file to export to.
        """
        try:
            # Create a copy of the DataFrame to avoid modifying the original
            export_df = self.apps.copy()

            # Rename columns to match common password manager formats
            export_df = export_df.rename(
                columns={
                    "title": "name",  # Rename "title" to "name"
                }
            )

            # Decrypt the passwords
            export_df["password"] = export_df.apply(
                lambda row: self.retrieve_app_password(
                    row["name"], row["username"]
                ),
                axis=1,
            )

            # Add a URL column
            export_df["url"] = ""

            # Add a notes column
            export_df["notes"] = ""

            # Reorder columns to match common formats
            export_df = export_df[
                ["name", "url", "username", "password", "notes"]
            ]

            # Export the DataFrame to CSV (no need to drop columns here)
            export_df.to_csv(filename, index=False)
            print(f"Passwords exported to {filename} successfully!")

        except Exception as e:
            print(f"Error exporting to CSV: {e}")


class PasswordManager:
    """Manages user accounts and their passwords."""

    def __init__(self) -> None:
        """Initializes a PasswordManager object."""
        self.users: Dict[str, User] = self.load_data()

    def load_data(self) -> Dict[str, User]:
        """
        Loads user data from a JSON file.

        Returns:
            A dictionary mapping usernames to User objects.
        """
        if not os.path.exists("data.json"):
            return {}
        try:
            with open("data.json", "r") as f:
                data = json.load(f)
                users: Dict[str, User] = {}
                for username, user_data in data.items():
                    master_password = (
                        user_data["master_password"][0],
                        user_data["master_password"][1],
                    )
                    user = User(username, master_password)  # type: ignore
                    user.apps = pd.DataFrame(user_data.get("apps", []))
                    users[username] = user
                return users
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading data: {e}")
            return {}

    def save_data(self) -> None:
        """Saves user data to a JSON file."""
        data: Dict[str, Dict[str, Union[Tuple[str, str], list]]] = {}
        for username, user in self.users.items():
            data[username] = {
                "master_password": user.master_password,
                "apps": user.apps.to_dict(orient="records"),
            }
        try:
            with open("data.json", "w") as f:
                json.dump(data, f, indent=4)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error saving data: {e}")

    def create_master_account(self, username: str, password: str) -> None:
        """
        Creates a new master account for a user.

        Args:
            username: The username for the master account.
            password: The master password.
        """
        if username in self.users:
            print("Username already exists.")
            return

        user = User(username, password)
        hashed_password, salt = user.store_master_password()
        user.master_password = (hashed_password, salt)
        self.users[username] = user
        self.save_data()
        print("Master password stored successfully!")

    def login_to_master_account(
        self, username: str, master_password: str
    ) -> Union[User, None]:
        """
        Logs in a user to their master account.

        Args:
            username: The username for the master account.
            master_password: The master password.

        Returns:
            The User object if login is successful, None otherwise.
        """
        user = self.users.get(username)
        if user and user.check_master_password(master_password):
            print("Login successful!")
            return user
        else:
            print("Incorrect master password or username not found.")
            return None

    def register_app_account(
        self, user: User, title: str, username: str, password: str
    ) -> None:
        """
        Registers a new app account for a logged-in user.

        Args:
            user: The User object.
            title: The title of the application.
            username: The username for the app account.
            password: The password for the app account.
        """
        user.store_app_password(title, username, password)
        self.save_data()
        print(f"Password for {username} on {title} stored successfully!")

    def retrieve_app_account_password(
        self, user: User, username: Union[str, None] = None
            , title: Union[str, None] = None
    ) -> Union[str, None]:
        """
        Retrieves the password for an app account.

        Args:
            user: The User object.
            username: The username for the app account.
            title: The title of the application.

        Returns:
            The decrypted password if found, None otherwise.
        """
        if title is None and username is None:
            if user.apps.empty:  # Use .empty to check if DataFrame is empty
                print("No stored passwords found.")
                return

            # Get unique app names from the DataFrame
            titles = user.apps["title"].unique()
            print("\nYour applications:")
            for i, app in enumerate(titles):
                print(f"{i + 1}. {app}")

            try:
                app_choice = int(input("Choose an application: ")) - 1
                title = titles[app_choice]  # Select app name from the array

                # Filter accounts for the chosen app
                accounts_for_app = user.apps[user.apps["title"] == title][
                    "username"
                ].tolist()
                print("\nYour accounts for this application:")
                for i, account in enumerate(accounts_for_app):
                    print(f"{i + 1}. {account}")

                account_choice = int(input("Choose an account: ")) - 1
                # Select account from the filtered list
                username = accounts_for_app[account_choice]

            except (ValueError, IndexError):
                print("Invalid choice.")
                return

        password = user.retrieve_app_password(title, username)  # type: ignore
        if password:
            print(f"Password for {username} on {title}: {password}")
            return password
        else:
            print("Credentials not found.")
            return

    def display_app_accounts(self, user: User) -> None:
        """
        Displays the list of applications and accounts using a DataFrame.

        Args:
            user: The User object.
        """
        if not user.apps.empty:
            # Group by title and aggregate usernames
            app_df = (
                user.apps.groupby("title")["username"]
                .apply(list)
                .reset_index(name="accounts")
            )

            # Display the DataFrame
            print(
                app_df.to_markdown(
                    index=False, numalign="left", stralign="left"
                )
            )
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
        match choice:
            case "1":
                username = input(
                    "Enter username for your master account: "
                ).strip()
                while username == "":
                    username = input(
                        "Enter username for your master account: "
                    ).strip()
                while True:
                    password = input("Enter master password: ").strip()
                    while password == "":
                        password = input("Enter master password: ").strip()
                    confirm_password = input("Confirm master password: ")
                    if password == confirm_password:
                        password_manager.create_master_account(
                            username, password
                        )
                        break
                    else:
                        print("Passwords do not match. Please try again.")

            case "2":
                username = input("Enter username: ")
                master_password = input("Enter master password: ")
                user = password_manager.login_to_master_account(
                    username, master_password
                )
                if user:
                    while True:
                        print("\nChoose an action:")
                        print("1. Register new app account")
                        print("2. Retrieve app account password")
                        print("3. Display app accounts")
                        print("4. Export passwords to CSV")
                        print("5. Exit")
                        choice = input("Enter your choice: ")
                        match choice:
                            case "1":
                                title = input("Enter application name: ")
                                username = (input("Enter account username: ")
                                            .strip())
                                while username == "":
                                    username = input(
                                        "Enter account username: "
                                    ).strip()
                                password = input(
                                    "Enter password: ").strip()
                                while password == "":
                                    password = input(
                                        "Enter password: ").strip()
                                password_manager.register_app_account(
                                    user, title, username, password
                                )
                            case "2":
                                (password_manager.
                                retrieve_app_account_password(
                                    user
                                ))  # Call without arguments
                            case "3":
                                password_manager.display_app_accounts(user)
                            case "4":
                                filename = input("Enter the desired filename" +
                                "(e.g., passwords.csv): "
                                )
                                user.export_to_csv(filename)
                            case "5":
                                break
                            case _:
                                print("Invalid choice.")

            case "3":
                break
            case _:
                print("Invalid choice.")

if __name__ == "__main__":
    main()