//News Headlines Console Screen with Login and API Integration
import csv
import hashlib
import re
import requests

login_attempts = 0
email_regex = r"^[\w\.-]+@[\w\.-]+\.\w{2,}$"

def is_valid_email(email):
    return bool(re.match(email_regex, email))

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def read_credentials():
    credentials = {}
    try:
        with open("12324729.csv", "r") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                email = row.get("email", "").strip()
                password = row.get("password", "").strip()
                security_question = row.get("security_question", "").strip()
                if email and password:
                    credentials[email] = {
                        "password": password,
                        "security_question": security_question,
                    }
    except FileNotFound:
        print("Credentials file not found. Please register a new user.")
    return credentials

def add_user(credentials):
    email = input("Enter your email: ")
    if is_valid_email(email):
        if email in credentials:
            print("Email already exists. Please try logging in or use a different email.")
            return
        password = input("Enter your password: ")
        security_question = input("Enter your security question: ")
        hashed_password = hash_password(password)
        credentials[email] = {
            "password": hashed_password,
            "security_question": security_question,
        }
        with open("12324729.csv", "a", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["email", "password", "security_question"])
            if csvfile.tell() == 0:
                writer.writeheader()
            writer.writerow({"email": email, "password": hashed_password, "security_question": security_question})
        print("User registered successfully!")
    else:
        print("Invalid email format. Please enter a valid email address (e.g., example@domain.com).")

def validate_login(email, password, credentials):
    if email in credentials:
        return credentials[email]["password"] == hash_password(password)
    else:
        return False

def forgot_password(credentials):
    email = input("Enter your registered email: ")
    if email in credentials:
        answer = input(credentials[email]["security_question"] + " (Y/N): ").upper()
        if answer == "Y":
            new_password = input("Enter your new password: ")
            if len(new_password) >= 8 and any(char in new_password for char in "!@#$%^&*"):
                credentials[email]["password"] = hash_password(new_password)
                with open("12324729.csv", "w", newline="") as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=["email", "password", "security_question"])
                    writer.writeheader()
                    writer.writerows(credentials.values())
                print("Password reset successful!")
            else:
                print("Password must be at least 8 characters and contain a special character!")
        else:
            print("Incorrect answer.")
    else:
        print("Email not found!")

def fetch_news(keyword, api_key="b0ad07f95af443978338f4924766941f"):
    url = f"https://newsapi.org/v2/top-headlines?q={keyword}&apiKey={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if data["status"] == "ok":
            articles = data["articles"][:5]  
            for article in articles:
                print(f"{article['title']} - {article['source']['name']}")
        else:
            print(f"Error: {data['message']}")
    else:
        print(f"API request failed with status code: {response.status_code}")

credentials = read_credentials()

while True:
    print("\nWelcome")
    choice = input("1. Login\n2. Register New User\n3. Forgot Password\n4. Exit\n: ")

    if choice == "1":
        if login_attempts < 5:
            email = input("Enter your email: ")
            if is_valid_email(email):
                password = input("Enter your password: ")
                if validate_login(email, password, credentials):
                    login_attempts = 0  
                    keyword = input("Enter a keyword or topic: ")
                    fetch_news(keyword)
                    break
                else:
                    login_attempts += 1
                    print("not a valid email address or password. Attempts remaining:", 5 - login_attempts)
            else:
                print("not a valid email address format. Please enter a valid email address (e.g., example@domain.com).")
        else:
            print("Too many login attempts. Please try again later!.")
            break

    elif choice == "2":
        add_user(credentials)

    elif choice == "3":
        forgot_password(credentials)

    elif choice == "4":
        print("Exit.")
        break

    else:
        print("Invalid choice.")
