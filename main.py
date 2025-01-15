import argparse
import bcrypt
import pyotp
from pymongo import MongoClient
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import getpass
import smtplib
from email.mime.text import MIMEText
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
from datetime import datetime

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["secure_db"]
users_collection = db["users"]
data_collection = db["data"]
audit_logs_collection = db["audit_logs"]  # Collection for audit logs

# Quantum-resistant key pair (in a real-world scenario, store this securely)
public_key, private_key = generate_keypair()

# Email configuration (replace with your SMTP server details)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"

# Helper functions
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password, hashed_password):
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode()  # Convert string to bytes
    return bcrypt.checkpw(password.encode(), hashed_password)

def generate_mfa_secret():
    return pyotp.random_base32()

def verify_mfa_code(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def encrypt_data(data):
    # Encrypt the data using Kyber for key encapsulation and AES for symmetric encryption
    ciphertext, shared_secret = encrypt(public_key)  # Kyber encapsulation
    cipher = AES.new(shared_secret[:32], AES.MODE_EAX)  # Use first 32 bytes of shared secret as AES key
    ciphertext_aes, tag = cipher.encrypt_and_digest(data.encode())
    return cipher.nonce + tag + ciphertext + ciphertext_aes

def decrypt_data(encrypted_data):
    # Decrypt the data using Kyber for key decapsulation and AES for symmetric decryption
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext_kyber = encrypted_data[32:32 + 768]  # Kyber ciphertext is 768 bytes
    ciphertext_aes = encrypted_data[32 + 768:]

    shared_secret = decrypt(ciphertext_kyber, private_key)  # Kyber decapsulation
    cipher = AES.new(shared_secret[:32], AES.MODE_EAX, nonce=nonce)  # Use first 32 bytes of shared secret as AES key
    return cipher.decrypt_and_verify(ciphertext_aes, tag).decode()

def send_email(to_email, subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())

def log_audit_event(username, action, status="success"):
    """Log an audit event to the database."""
    audit_logs_collection.insert_one({
        "timestamp": datetime.utcnow(),
        "username": username,
        "action": action,
        "status": status
    })

# CLI Commands
def login(username, password):
    user = users_collection.find_one({"username": username})
    if not user:
        print("User not found.")
        log_audit_event(username, "login", status="failed")
        return None

    if not verify_password(password, user["password_hash"]):
        print("Invalid password.")
        log_audit_event(username, "login", status="failed")
        return None

    # Generate and send MFA code
    totp = pyotp.TOTP(user["mfa_secret"])
    mfa_code = totp.now()
    send_email(user["email"], "Your MFA Code", f"Your MFA code is: {mfa_code}")
    print("MFA code sent to your email. Please check your inbox.")

    # Verify MFA code
    user_input = input("Enter MFA code: ")
    if not verify_mfa_code(user["mfa_secret"], user_input):
        print("Invalid MFA code.")
        log_audit_event(username, "login", status="failed")
        return None

    print("Login successful!")
    log_audit_event(username, "login")
    return user

def push_data(user, data, role):
    if user["role"] != role:
        print("Access denied. Your role does not allow pushing data for this role.")
        log_audit_event(user["username"], "push_data", status="failed")
        return

    encrypted_data = encrypt_data(data)
    data_collection.insert_one({
        "user_id": user["_id"],
        "encrypted_data": encrypted_data,
        "role": role
    })
    print("Data pushed successfully.")
    log_audit_event(user["username"], "push_data")

def fetch_data(user):
    data_entries = data_collection.find({"role": user["role"]})
    for entry in data_entries:
        decrypted_data = decrypt_data(entry["encrypted_data"])
        print(f"Data: {decrypted_data}")
    log_audit_event(user["username"], "fetch_data")

def add_user(admin, username, password, email, role):
    if admin["role"] != "admin":
        print("Only admins can add users.")
        log_audit_event(admin["username"], "add_user", status="failed")
        return

    if users_collection.find_one({"username": username}):
        print("User already exists.")
        log_audit_event(admin["username"], "add_user", status="failed")
        return

    # Hash the password before storing it
    password_hash = hash_password(password)
    mfa_secret = generate_mfa_secret()
    users_collection.insert_one({
        "username": username,
        "password_hash": password_hash,
        "email": email,
        "role": role,
        "mfa_secret": mfa_secret
    })
    print(f"User added successfully. MFA Secret: {mfa_secret}")
    log_audit_event(admin["username"], "add_user")

# Main CLI
def main():
    parser = argparse.ArgumentParser(description="Secure Database CLI Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Login command
    login_parser = subparsers.add_parser("login", help="Login to the system")
    login_parser.add_argument("username", help="Your username")
    login_parser.add_argument("password", help="Your password")

    # Push command
    push_parser = subparsers.add_parser("push", help="Push data to the database")
    push_parser.add_argument("data", help="Data to push")
    push_parser.add_argument("role", help="Role required to access this data")

    # Fetch command
    fetch_parser = subparsers.add_parser("fetch", help="Fetch data from the database")

    # Add-user command
    add_user_parser = subparsers.add_parser("add-user", help="Add a new user (admin only)")
    add_user_parser.add_argument("username", help="Username of the new user")
    add_user_parser.add_argument("password", help="Password of the new user")
    add_user_parser.add_argument("email", help="Email of the new user")
    add_user_parser.add_argument("role", help="Role of the new user")

    args = parser.parse_args()

    if args.command == "login":
        user = login(args.username, args.password)
        if user:
            print(f"Logged in as {user['username']} with role {user['role']}.")
    elif args.command == "push":
        user = login(getpass.getuser(), getpass.getpass("Password: "))
        if user:
            push_data(user, args.data, args.role)
    elif args.command == "fetch":
        user = login(getpass.getuser(), getpass.getpass("Password: "))
        if user:
            fetch_data(user)
    elif args.command == "add-user":
        admin = login(getpass.getuser(), getpass.getpass("Password: "))
        if admin:
            add_user(admin, args.username, args.password, args.email, args.role)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
