# 🔐 Secure Database CLI Tool
A Quantum-Resistant, Zero Trust Architecture-Enabled Secure Data Management System



## 📌 Overview
Secure Database CLI Tool is a highly secure, role-based, and quantum-resistant command-line interface application designed to manage sensitive data in adherence with modern security standards. It integrates Zero Trust Architecture (ZTA) principles, Multi-Factor Authentication (MFA), audit logging, and quantum-safe encryption (Kyber512 + AES) to offer a future-ready, minimal-trust data handling platform.

## Features
**1. Zero Trust Architecture (ZTA):**

Role-Based Access Control (RBAC)

Multi-Factor Authentication via TOTP and secure email delivery

"Never Trust, Always Verify" principle enforced at every interaction

Logs all critical user actions and access attempts.

**2. Quantum-Resistant Encryption:**

Hybrid encryption using Kyber512 for public-key encapsulation

AES symmetric encryption for data payloads

Resists future quantum computing threats

**3. Role-Based Data Management:**

Role-specific push and fetch permissions

Supports granular control over data access

**4. Audit Logging:**

Every action (e.g., login, fetch, push, add-user) is logged

Supports monitoring and forensic tracing

**5. Secure Email Notifications:**

Sends MFA codes securely over encrypted SMTP

Configurable sender address and credentials

## Technologies Used
- **Python Libraries**:
  - `argparse` - Command-line argument parsing.
  - `bcrypt` - Password hashing.
  - `pyotp` - MFA TOTP generation and verification.
  - `pymongo` - MongoDB integration.
  - `Crypto.Cipher` - AES encryption.
  - `smtplib` and `email.mime` - Email functionality.
  - `pycrypto` - Kyber512.
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

## ZTA Principles in Action

Never Trust, Always Verify: Every user action is verified through MFA and role-based controls.

Minimize Attack Surface: Data access is restricted to the minimum necessary for each user role.

Audit and Monitor: Comprehensive logging ensures that every action is traceable.

## Security Highlights

Quantum-Resistant Encryption: Protects data against potential future quantum threats.

AES Encryption: Ensures fast and secure symmetric encryption for data.

MFA: Adds a critical layer of user authentication.

Audit Logs: Provides a transparent trail of all operations.

## License

MIT License © 2025 Likitha Yogesh
## Acknowledgments

Kyber512 Documentation

PyCryptodome Library

MongoDB Python Driver

pyotp Library

---
Enhance your data security with cutting-edge ZTA and quantum-resistant encryption. Let's build a safer digital future!
