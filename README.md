# System-Security-Management

# 🔐 Secure File Access System (SFAS)

A Python-based desktop application that demonstrates core principles of **System Security Management (SSM)**, including **authentication**, **access control**, **multi-factor authentication (MFA)**, **hybrid cryptography**, **VPN simulation**, and **firewall protection**.

---

## 📌 Features

- **User Registration & Login**
  - Role-based access (`admin` / `user`)
  - SHA-256 hashed password storage

- **Multi-Factor Authentication (MFA)**
  - OTP verification on login

- **Access Control**
  - Role-based restrictions for users

- **Hybrid Cryptography**
  - AES (symmetric) + RSA (asymmetric)
  - Data encryption + secure key transfer
  - IV (Initialization Vector) for AES encryption

- **VPN Simulation**
  - Toggleable status (CONNECTED / DISCONNECTED)

- **Firewall Simulation**
  - Whitelisted IP validation
  - Blocks unknown IPs

- **Real-Time Logging**
  - Tracks all actions in `security.log` with timestamp and severity

---

## 🖥️ GUI Overview

Built using **Tkinter** for a simple and intuitive interface:

- ✅ Register / Login
- 🔑 OTP input popup
- 🔐 Encrypt & Decrypt Messages
- 🛡️ Check Firewall
- 🌐 Toggle VPN

---

## 🔧 Technologies Used

- Python 3
- Tkinter (GUI)
- `cryptography` library (AES, RSA)
- `hashlib` (SHA-256 hashing)
- `logging` (Event logging)
- `socket` (IP simulation)

---




