# Secure Database CLI Tool

A command-line interface (CLI) tool designed to manage a secure database with advanced security features such as quantum-resistant encryption, multi-factor authentication (MFA), role-based access control, and email notifications. This project leverages Kyber512 (post-quantum cryptography) for key encapsulation, ensuring future-proof security against quantum computing threats.

## Features
- **Quantum-Resistant Encryption**:
  Implements Kyber512 for key encapsulation to protect against quantum attacks.
  Combines Kyber-generated shared secrets with AES encryption for symmetric data security.
- **User Authentication**: Secure login with hashed passwords.
- **Multi-Factor Authentication (MFA)**: TOTP-based MFA for enhanced security.
- **Data Encryption**: AES encryption for sensitive data storage.
- **Role-Based Access Control**: Restrict data access based on user roles.
- **Email Notifications**: Send MFA codes via email.
- **Admin Controls**: Admins can add new users with specific roles.

## Technologies Used
- **Python Libraries**:
  - `argparse` - Command-line argument parsing.
  - `bcrypt` - Password hashing.
  - `pyotp` - MFA TOTP generation and verification.
  - `pymongo` - MongoDB integration.
  - `Crypto.Cipher` - AES encryption.
  - `smtplib` and `email.mime` - Email functionality.
- **Database**: MongoDB.

## Prerequisites

1. Install Python (>= 3.8).
2. Install MongoDB and ensure it is running.
3. Install the required Python libraries:
   ```bash
   pip install bcrypt pyotp pymongo pycryptodome

## Setup
1. Clone this repository:

       git clone https://github.com/<your-username>/<repository-name>.git
       cd <repository-name>
2. Configure the email settings in the script: Replace the placeholders in EMAIL_ADDRESS and EMAIL_PASSWORD with your email credentials:

       EMAIL_ADDRESS = "your-email@example.com"
       EMAIL_PASSWORD = "your-email-password"
3. Ensure MongoDB is running:

       sudo systemctl start mongod
4. Run the CLI tool:

        python main.py

## Usage

Commands
1. Login:

       python main.py login <username> <password>
2. Push Data:

       python main.py push <data> <role>
3. Fetch Data:

       python main.py fetch
4. Add User (Admin Only):

       python main.py add-user <username> <password> <email> <role>
## Security Notes
1. Encryption Key: The ENCRYPTION_KEY is generated within the script. In a production environment, securely store this key (e.g., in a secure environment variable or a secret management tool).
2. Email Credentials: Use a secure method to manage your email credentials (e.g., .env files or secret management tools).
3. Database Security: Ensure MongoDB is configured securely to prevent unauthorized access.

## Acknowledgments

Kyber512 Documentation

PyCryptodome Library

MongoDB Python Driver

pyotp Library

