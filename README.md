# Secure Database CLI Tool

This repository provides a secure, quantum-resistant, and Zero Trust Architecture (ZTA)-enabled database management CLI tool. It integrates advanced cryptographic techniques and ZTA principles to ensure robust protection of sensitive data.

## Features
**1. Zero Trust Architecture (ZTA):**

Implements strict role-based access control to ensure users only access data relevant to their role.

Multi-Factor Authentication (MFA) for enhanced user identity verification.

Comprehensive audit logging to track and monitor all actions within the system.

**2. Quantum-Resistant Encryption:**

Uses Kyber512, a quantum-resistant cryptographic algorithm, to secure data against future quantum computing threats.

Hybrid encryption model combining Kyber512 for key encapsulation and AES for symmetric encryption.

**3. Role-Based Data Management:**

Push and fetch data based on user roles, adhering to ZTA principles.

Granular data access policies for enhanced security.

**4. Audit Logging:**

Logs every critical event (e.g., login attempts, data access, user additions) to an audit trail.

Ensures transparency and accountability within the system.

**5. Secure Email Notifications:**

Sends MFA codes and other notifications via email, with encrypted communication over SMTP.

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
## Acknowledgments

Kyber512 Documentation

PyCryptodome Library

MongoDB Python Driver

pyotp Library

---
Enhance your data security with cutting-edge ZTA and quantum-resistant encryption. Let's build a safer digital future!
