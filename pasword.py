import hashlib
import requests
import certifi
import re

# Function to check if a password has been breached using Pwned Passwords API (HIBP API)
def check_password_breach(password):
    # Hash the password with SHA1
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]

    # Call the Pwned Passwords API
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    
    if response.status_code == 200:
        # Look through the response for the suffix of the hashed password
        hashes = response.text.splitlines()
        for h in hashes:
            h_suffix, count = h.split(':')
            if h_suffix == suffix:
                return int(count)
    return 0

# Function to check if an email has been breached using BreachDirectory API with requests
def check_email_breach_breachdirectory(email):
    print(f"\nChecking breaches for email: {email} using BreachDirectory API")
    
    url = "https://breachdirectory.p.rapidapi.com/"
    headers = {
        'x-rapidapi-key': "3b6cc6fd7fmshb5a0dd231cd4bf4p11fe98jsnfd001e2750a4",  # Replace with your actual RapidAPI key
        'x-rapidapi-host': "breachdirectory.p.rapidapi.com"
    }
    params = {"func": "auto", "term": email}
    
    # Use requests with certifi to handle SSL verification and auto-redirects
    response = requests.get(url, headers=headers, params=params, verify=certifi.where())
    
    if response.status_code == 200:
        data = response.json()
        if "breaches" in data:
            print(f"Warning! The email '{email}' has been found in breaches.")
            # Print details about where the email has been leaked
            for breach in data["breaches"]:
                print(f"- Breach Name: {breach['Name']}, Site: {breach['Domain']}")
        else:
            print(f"Good news! The email '{email}' has not been found in any known breaches.")
    else:
        print(f"Error fetching breach data for email: {response.status_code}, Message: {response.text}")

# Function to analyze both the password and the email
def analyze_password_and_email(password, email):
    print(f"Analyzing the security of your password and email...\n")

    # Check the password breach count
    breach_count = check_password_breach(password)
    if breach_count > 0:
        print(f"Warning! Your password has been found {breach_count} times in data breaches.")
    else:
        print("Good news! Your password has not been found in any known breaches.")

    # Check the email breach
    check_email_breach_breachdirectory(email)

# Function to validate if a password is strong
def is_strong_password(password):
    # Check the password strength
    if (len(password) < 8 or
        not re.search(r"[a-z]", password) or  # at least one lowercase letter
        not re.search(r"[A-Z]", password) or  # at least one uppercase letter
        not re.search(r"[0-9]", password) or  # at least one digit
        not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):  # at least one special character
        return False
    return True

# Strong password recommendations
def recommend_strong_password():
    print("To create a strong password, consider the following recommendations:")
    print("- At least 8 characters long.")
    print("- Include a mix of uppercase and lowercase letters.")
    print("- Include at least one number.")
    print("- Include at least one special character (e.g., @, #, $, %).")

if __name__ == "__main__":
    while True:
        user_password = input("Enter the password you want to check (or type 'exit' to quit): ")
        if user_password.lower() == 'exit':
            print("Exiting the program. Goodbye!")
            break

        # Check password strength
        if not is_strong_password(user_password):
            print("Your password is weak.")
            recommend_strong_password()

        user_email = input("Enter the email you want to check: ")
        analyze_password_and_email(user_password, user_email)
