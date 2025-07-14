import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext, ttk
import logging
import hashlib
import secrets
import mysql.connector
import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ------------------ Logging ------------------
logging.basicConfig(filename='security.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# ------------------ HIDS Simulation ------------------
hids_alerts = []
login_fail_count = {}

def log_hids_event(event):
    hids_alerts.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {event}")
    logging.warning(f"HIDS: {event}")

def monitor_file_integrity(filepath="security.log"):
    if not os.path.exists(filepath):
        return
    with open(filepath, "rb") as f:
        data = f.read()
        current_hash = hashlib.sha256(data).hexdigest()

    hash_file = filepath + ".hash"
    if os.path.exists(hash_file):
        with open(hash_file, "r") as hf:
            saved_hash = hf.read()
            if saved_hash != current_hash:
                log_hids_event(f"File integrity violation: {filepath} modified!")
    with open(hash_file, "w") as hf:
        hf.write(current_hash)

# ------------------ Database Setup ------------------
def setup_database():
    connection = None
    try:
        
        print("Attempting to connect to MySQL...")
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="1234"
        )
        
        if not connection.is_connected():
            print("Failed to connect to MySQL")
            return False
            
        print("Successfully connected to MySQL")
        cursor = connection.cursor()
        
        # Create database if it doesn't exist
        print("Creating database 'ssm' if it doesn't exist...")
        cursor.execute("CREATE DATABASE IF NOT EXISTS ssm")
        
        # Switch to the ssm database
        print("Switching to 'ssm' database...")
        cursor.execute("USE ssm")
        
        # Create users table if it doesn't exist
        print("Creating users table if it doesn't exist...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'user'
            )
        """)
        
        # Check if admin user exists
        print("Checking for admin user...")
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        if not cursor.fetchone():
            print("Creating test users...")
            # Insert test users for SQL injection demo
            cursor.execute("INSERT INTO users (username, password_hash, role) VALUES ('admin', 'admin123', 'admin')")
            cursor.execute("INSERT INTO users (username, password_hash, role) VALUES ('test', 'test123', 'user')")
            connection.commit()
            print("Test users created successfully")
        
        cursor.close()
        return True
    except mysql.connector.Error as err:
        print(f"Database setup error: {err}")
        logging.error(f"Database setup error: {err}")
        if err.errno == 1045:  # Access denied error
            print("Access denied. Please check your MySQL root password.")
        elif err.errno == 2003:  # Can't connect to server
            print("Cannot connect to MySQL server. Please check if MySQL is running.")
        return False
    finally:
        if connection and connection.is_connected():
            connection.close()
            print("Database connection closed.")

def connect_db():
    try:
        if not setup_database():
            print("Database setup failed")
            return None
            
        print("Connecting to ssm database...")
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="1234",
            database="ssm"
        )
        
        if not connection.is_connected():
            print("Failed to connect to ssm database")
            return None
            
        print("Successfully connected to ssm database")
        return connection
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        logging.error(f"Database connection error: {err}")
        if err.errno == 1045:  # Access denied error
            print("Access denied. Please check your MySQL root password.")
        elif err.errno == 2003:  # Can't connect to server
            print("Cannot connect to MySQL server. Please check if MySQL is running.")
        return None

def db_authenticate(username, password):
    conn = connect_db()
    if not conn:
        return False, None
        
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password_hash, role FROM users WHERE username=%s", (username,))
        result = cursor.fetchone()
        if result:
            stored_hash, role = result
            if hashlib.sha256(password.encode()).hexdigest() == stored_hash:
                return True, role
    except mysql.connector.Error as err:
        logging.error(f"Database authentication error: {err}")
    finally:
        conn.close()
    return False, None

# ------------------ VPN Simulation ------------------
vpn_connected = False
vpn_server = "Default VPN Server"

def toggle_vpn():
    global vpn_connected
    vpn_connected = not vpn_connected
    status = "connected" if vpn_connected else "disconnected"
    logging.info(f"VPN {status.upper()} to {vpn_server}")
    return status

def set_vpn_server(server):
    global vpn_server
    vpn_server = server
    logging.info(f"VPN server set to: {server}")

# ------------------ Firewall Simulation ------------------
allowed_ips = set()
allowed_ports = set()

def configure_firewall(ip=None, port=None, action="allow"):
    if ip:
        if action == "allow":
            allowed_ips.add(ip)
            logging.info(f"IP {ip} allowed")
        elif action == "block" and ip in allowed_ips:
            allowed_ips.remove(ip)
            logging.warning(f"IP {ip} blocked")
    if port:
        if action == "allow":
            allowed_ports.add(port)
            logging.info(f"Port {port} allowed")
        elif action == "block" and port in allowed_ports:
            allowed_ports.remove(port)
            logging.warning(f"Port {port} blocked")

def check_firewall(ip, port):
    if ip in allowed_ips and port in allowed_ports:
        logging.info(f"Access granted for IP {ip} on port {port}")
        return True
    else:
        logging.warning(f"Blocked: IP {ip} on port {port}")
        return False

# ------------------ Encryption ------------------
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def encrypt_message(message):
    key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(message.encode()) + encryptor.finalize()
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_data, encrypted_key, iv

def decrypt_message(encrypted_data, encrypted_key, iv):
    try:
        key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return b"[DECRYPTION ERROR]"

# ------------------ User Management ------------------
users = {}

def register_user(username, password, role="user"):
    if username in users:
        return False
    users[username] = {
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "role": role
    }
    logging.info(f"User registered: {username} ({role})")
    return True

def generate_otp():
    return str(secrets.randbelow(1000000)).zfill(6)

def authenticate(username, password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    user = users.get(username)
    if user and user['password'] == hashed:
        otp = generate_otp()
        logging.info(f"OTP generated for {username}: {otp}")
        # Print OTP to terminal instead of showing in GUI
        print(f"\n>>> OTP for {username} is: {otp} <<<\n")
        user_otp = simpledialog.askstring("OTP Required", "Enter OTP sent to your device:")
        return user_otp == otp, user['role']
    return False, None

# ------------------ Vulnerable SQL Injection Logic ------------------
vulnerable_users = [
    {"username": "admin", "password": "admin123"},
    {"username": "hacker", "password": "letmein"},
]

def sql_injection_login(username, password):
    for user in vulnerable_users:
        if user["username"] == username:
            if "'OR'" in password.upper() or "'1'='1" in password:
                logging.warning(f"SQL Injection successful for user: {username}")
                return True
            if user["password"] == password:
                return True
    return False

# ------------------ SQL Injection Demo Function ------------------
def demonstrate_sql_injection():
    conn = connect_db()
    if not conn:
        return "Database connection failed"
    
    cursor = conn.cursor()
    try:
        # Show normal query first
        normal_query = "SELECT * FROM users WHERE username = 'test' AND password_hash = 'wrongpass'"
        cursor.execute(normal_query)
        normal_result = cursor.fetchall()

        # Now show injection query
        injection_query = "SELECT * FROM users WHERE username = 'test' AND password_hash = '' OR '1'='1'"
        cursor.execute(injection_query)
        injection_result = cursor.fetchall()

        # Format results for display
        demonstration = (
            "SQL Injection Demonstration:\n\n"
            f"1. Normal Query:\n{normal_query}\n"
            f"Results: {len(normal_result)} rows returned\n\n"
            f"2. Injection Query:\n{injection_query}\n"
            f"Results: {len(injection_result)} rows returned\n"
            "\nThe injection query returns all users because '1'='1' is always true!"
        )
        logging.warning("SQL Injection demonstration performed")
        return demonstration

    except mysql.connector.Error as err:
        logging.error(f"SQL Injection demonstration error: {err}")
        return f"Error during demonstration: {err}"
    finally:
        cursor.close()
        conn.close()

def demonstrate_secure_vs_vulnerable_login(username, password, use_vulnerable_mode=True):
    """
    Demonstrates the difference between secure and vulnerable login methods.
    Returns a tuple of (success, message, query_used)
    """
    try:
        conn = connect_db()
        if not conn:
            return False, "Database connection failed", None
        
        cursor = conn.cursor()

        if use_vulnerable_mode:
            # VULNERABLE TO SQL INJECTION
            query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password}'"
            cursor.execute(query)
            query_used = query  # Save for demonstration
        else:
            # SECURE: Using parameterized queries
            query = "SELECT * FROM users WHERE username = %s AND password_hash = %s"
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            cursor.execute(query, (username, hashed_password))
            query_used = cursor.statement  # Get the actual executed query

        user = cursor.fetchone()
        if user:
            mode = "VULNERABLE" if use_vulnerable_mode else "SECURE"
            logging.info(f"Login successful using {mode} mode for user: {username}")
            return True, f"Login successful for {username}", query_used
        else:
            return False, "Invalid credentials", query_used

    except mysql.connector.Error as err:
        logging.error(f"Login error: {err}")
        return False, f"Database error: {err}", None
    finally:
        if 'conn' in locals() and conn.is_connected():
            conn.close()

# ------------------ GUI Application ------------------
class SecureAccessApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureAccessPro")

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        self.login_tab = tk.Frame(notebook)
        self.vpn_tab = tk.Frame(notebook)
        self.firewall_tab = tk.Frame(notebook)
        self.crypto_tab = tk.Frame(notebook)
        self.attack_tab = tk.Frame(notebook)
        self.hids_tab = tk.Frame(notebook)
        self.logs_tab = tk.Frame(notebook)

        notebook.add(self.login_tab, text="Login/Register")
        notebook.add(self.vpn_tab, text="VPN")
        notebook.add(self.firewall_tab, text="Firewall")
        notebook.add(self.crypto_tab, text="Crypto")
        notebook.add(self.attack_tab, text="Attacks")
        notebook.add(self.hids_tab, text="HIDS")
        notebook.add(self.logs_tab, text="Logs")

        self.role_label = None
        self.otp_entry = None

        self.build_login_tab()
        self.build_vpn_tab()
        self.build_firewall_tab()
        self.build_crypto_tab()
        self.build_attack_tab()
        self.build_hids_tab()
        self.build_logs_tab()

    def build_login_tab(self):
        tk.Label(self.login_tab, text="Username").pack()
        self.username_entry = tk.Entry(self.login_tab)
        self.username_entry.pack()

        tk.Label(self.login_tab, text="Password").pack()
        self.password_entry = tk.Entry(self.login_tab, show='*')
        self.password_entry.pack()

        tk.Label(self.login_tab, text="OTP (if required)").pack()
        self.otp_entry = tk.Entry(self.login_tab)
        self.otp_entry.pack()

        self.role_label = tk.Label(self.login_tab, text="Not logged in")
        self.role_label.pack(pady=10)

        tk.Button(self.login_tab, text="Register", command=self.register).pack(pady=5)
        tk.Button(self.login_tab, text="Secure Login", command=self.login).pack(pady=5)
        tk.Button(self.login_tab, text="SQL Injection Demo", command=self.show_sql_injection_demo).pack(pady=5)

    def build_vpn_tab(self):
        # VPN Controls Frame
        control_frame = tk.Frame(self.vpn_tab)
        control_frame.pack(pady=10)
        
        tk.Button(control_frame, text="Toggle VPN", command=self.vpn_toggle).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Set VPN Server", command=self.set_vpn_server).pack(side=tk.LEFT, padx=5)
        
        # VPN Status Display
        tk.Label(self.vpn_tab, text="VPN Status", font=('Arial', 12, 'bold')).pack(pady=5)
        self.vpn_status = scrolledtext.ScrolledText(self.vpn_tab, width=60, height=15)
        self.vpn_status.pack(pady=10)
        self.update_vpn_display()

    def update_vpn_display(self):
        if not hasattr(self, 'vpn_status'):
            return
            
        self.vpn_status.delete('1.0', tk.END)
        status_text = "VPN Configuration:\n"
        status_text += "=================\n\n"
        
        # Connection Status
        status_text += "Connection Status:\n"
        status_text += "----------------\n"
        status_text += f"✓ Status: {'CONNECTED' if vpn_connected else 'DISCONNECTED'}\n"
        status_text += f"✓ Current Server: {vpn_server}\n\n"
        
        # Add some simulated VPN details
        if vpn_connected:
            status_text += "Connection Details:\n"
            status_text += "-----------------\n"
            status_text += "✓ Protocol: UDP\n"
            status_text += "✓ Port: 1194\n"
            status_text += "✓ Encryption: AES-256-GCM\n"
            status_text += "✓ Data Sent: 0.0 MB\n"
            status_text += "✓ Data Received: 0.0 MB\n"
        
        self.vpn_status.insert(tk.END, status_text)
        self.vpn_status.see(tk.END)

    def vpn_toggle(self):
        status = toggle_vpn()
        messagebox.showinfo("VPN Status", f"VPN is now {status.upper()}")
        self.update_vpn_display()  # Update the display after toggling

    def set_vpn_server(self):
        server = simpledialog.askstring("VPN Server", "Enter VPN server address:")
        if server:
            set_vpn_server(server)
            messagebox.showinfo("VPN", f"Server set to: {server}")
            self.update_vpn_display()  # Update the display after changing server

    def build_firewall_tab(self):
        tk.Button(self.firewall_tab, text="Configure Firewall", command=self.configure_firewall_ui).pack(pady=10)
        tk.Button(self.firewall_tab, text="Test IP+Port", command=self.check_ip_port).pack(pady=10)
        
        # Add Firewall Status Display
        tk.Label(self.firewall_tab, text="Firewall Configuration", font=('Arial', 12, 'bold')).pack(pady=5)
        self.firewall_status = scrolledtext.ScrolledText(self.firewall_tab, width=60, height=15)
        self.firewall_status.pack(pady=10)
        self.update_firewall_display()

    def update_firewall_display(self):
        if not hasattr(self, 'firewall_status'):
            return
            
        self.firewall_status.delete('1.0', tk.END)
        status_text = "Current Firewall Configuration:\n\n"
        status_text += "Whitelisted (Allowed) IPs:\n"
        status_text += "------------------------\n"
        if allowed_ips:
            for ip in sorted(allowed_ips):
                status_text += f"✓ {ip}\n"
        else:
            status_text += "No IPs whitelisted\n"
            
        status_text += "\nAllowed Ports:\n"
        status_text += "-------------\n"
        if allowed_ports:
            for port in sorted(allowed_ports):
                status_text += f"✓ Port {port}\n"
        else:
            status_text += "No ports configured\n"
            
        self.firewall_status.insert(tk.END, status_text)
        self.firewall_status.see(tk.END)

    def configure_firewall_ui(self):
        ip = simpledialog.askstring("Firewall Config", "Enter IP to allow/block:")
        port = simpledialog.askinteger("Firewall Config", "Enter Port to allow/block:")
        action = simpledialog.askstring("Firewall Config", "Action (allow/block):", initialvalue="allow")
        if ip or port:
            configure_firewall(ip, port, action)
            messagebox.showinfo("Firewall", f"{action.capitalize()}ed IP {ip} and Port {port}")
            self.update_firewall_display()  # Update the display after configuration changes

    def build_crypto_tab(self):
        tk.Button(self.crypto_tab, text="Encrypt Message", command=self.encrypt_ui).pack(pady=10)
        tk.Button(self.crypto_tab, text="Cyber Insights", command=self.cyber_insights).pack(pady=10)

    def build_attack_tab(self):
        tk.Button(self.attack_tab, text="Simulate Brute Force", command=self.brute_force_attack).pack(pady=10)
        tk.Button(self.attack_tab, text="Simulate Port Scan", command=self.port_scan).pack(pady=10)
        tk.Button(self.attack_tab, text="Simulate Unauthorized VPN", command=self.unauthorized_vpn).pack(pady=10)
        tk.Button(self.attack_tab, text="Show SQL Injection Demo", command=self.show_sql_injection_demo).pack(pady=10)

    def build_hids_tab(self):
        tk.Button(self.hids_tab, text="Run HIDS Scan", command=self.run_hids_scan).pack(pady=10)
        self.hids_log_box = scrolledtext.ScrolledText(self.hids_tab, width=80, height=20)
        self.hids_log_box.pack()

    def build_logs_tab(self):
        log_area = scrolledtext.ScrolledText(self.logs_tab, width=80, height=20)
        log_area.pack()
        try:
            with open("security.log", "r") as log_file:
                log_area.insert(tk.END, log_file.read())
        except FileNotFoundError:
            log_area.insert(tk.END, "No logs found.")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        role = simpledialog.askstring("Role", "Enter role (admin/user):", initialvalue="user")
        if register_user(username, password, role):
            messagebox.showinfo("Registered", "User registered successfully!")
        else:
            messagebox.showwarning("Error", "Username already exists")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        otp = self.otp_entry.get() if self.otp_entry else ""
        
        # For SQL injection demo, try vulnerable login first
        success, role = vulnerable_sql_login(username, password, otp)
        
        if not success:
            # If vulnerable login fails, try regular authentication
            success, role = authenticate(username, password)
        
        if success:
            self.otp_entry.delete(0, tk.END)
            messagebox.showinfo("Success", f"Login successful as {role.upper()}")
            self.role_label.config(text=f"Logged in as: {role}")
            logging.info(f"{username} logged in as {role}")
            login_fail_count[username] = 0
        else:
            login_fail_count[username] = login_fail_count.get(username, 0) + 1
            if login_fail_count[username] >= 3:
                log_hids_event(f"Multiple failed login attempts for user: {username}")
            messagebox.showerror("Error", "Authentication failed")
            logging.warning(f"Failed login for {username}")

    def show_sql_injection_demo(self):
        result = demonstrate_sql_injection()
        messagebox.showinfo("SQL Injection Demonstration", result)

    def check_ip_port(self):
        ip = simpledialog.askstring("Firewall Test", "Enter IP to check:")
        port = simpledialog.askinteger("Firewall Test", "Enter Port to check:")
        if check_firewall(ip, port):
            messagebox.showinfo("Firewall", f"Access granted for {ip}:{port}")
        else:
            messagebox.showwarning("Firewall", f"Blocked {ip}:{port}")

    def encrypt_ui(self):
        msg = simpledialog.askstring("Encrypt", "Enter a message to encrypt")
        if msg:
            aes_key = secrets.token_bytes(32)
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(msg.encode()) + encryptor.finalize()

            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            result = (
                f"\nOriginal Message:\n{msg}\n"
                f"\nAES Key (hex):\n{aes_key.hex()}\n"
                f"\nIV (hex):\n{iv.hex()}\n"
                f"\nEncrypted Message (hex):\n{encrypted_data.hex()}\n"
                f"\nRSA-Encrypted AES Key (hex):\n{encrypted_key.hex()}\n"
            )

            decrypted = self.decrypt_message_verbose(encrypted_data, encrypted_key, iv, aes_key)
            result += f"\nFinal Decrypted Message:\n{decrypted.decode(errors='ignore')}"

            messagebox.showinfo("Hybrid Cryptography Result", result)

    def decrypt_message_verbose(self, encrypted_data, encrypted_key, iv, original_aes_key=None):
        try:
            decrypted_aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logging.info(f"Decrypted AES key matches original: {decrypted_aes_key == original_aes_key}")
            cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            return decrypted_data
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            return b"[DECRYPTION ERROR]"

    def cyber_insights(self):
        insights = (
            "\nCybersecurity Concepts Explained:\n"
            "- VPN: Creates an encrypted tunnel to protect your online activity.\n"
            "- Firewall: Filters traffic based on IPs and ports.\n"
            "- MFA: Requires multiple verification steps for secure login.\n"
            "- RBAC: Users are granted permissions based on roles.\n"
            "- Encryption: Protects data by converting it to unreadable form.\n"
        )
        messagebox.showinfo("Cyber Insights", insights)

    def brute_force_attack(self):
        target_user = "testuser"
        correct_password = "1234"
        users[target_user] = {"password": hashlib.sha256(correct_password.encode()).hexdigest(), "role": "user"}
        attempts = ["0000", "1111", "2222", "1234"]
        for pwd in attempts:
            hashed_attempt = hashlib.sha256(pwd.encode()).hexdigest()
            if users[target_user]["password"] == hashed_attempt:
                messagebox.showinfo("Brute-Force", f"Password cracked for {target_user}: {pwd}")
                logging.warning(f"Brute-force successful: {target_user} -> {pwd}")
                return
        messagebox.showinfo("Brute-Force", "Attack failed")

    def port_scan(self):
        open_ports = list(allowed_ports) if allowed_ports else [80, 443, 22]
        messagebox.showinfo("Port Scan", f"Discovered open ports: {open_ports}")
        logging.warning(f"Port scanning simulated: Open ports found -> {open_ports}")

    def unauthorized_vpn(self):
        global vpn_connected
        vpn_connected = True
        logging.warning("Unauthorized user connected to VPN (simulation)")
        messagebox.showinfo("VPN Breach", "Simulated unauthorized VPN access succeeded")

    def run_hids_scan(self):
        monitor_file_integrity()
        self.hids_log_box.delete("1.0", tk.END)
        if hids_alerts:
            self.hids_log_box.insert(tk.END, "\n".join(hids_alerts))
        else:
            self.hids_log_box.insert(tk.END, "✅ No suspicious activity detected.")

# ------------------ Vulnerable SQL Login ------------------
def vulnerable_sql_login(username, password, otp):
    # In-memory implementation for SQL injection demo
    try:
        # Simulate SQL query construction (vulnerable to injection)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password}'"
        print(f"[DEBUG] Attempting SQL injection with query: {query}")
        
        # Check for common SQL injection patterns
        if "' OR '1'='1" in query or "' OR 1=1" in query or "' OR '1'='1'--" in query or "' OR 1=1--" in query:
            print(f"[DEBUG] SQL Injection successful!")
            logging.warning(f"SQL Injection successful - User: {username}, Query: {query}")
            return True, "admin"  # Grant admin access on successful injection
            
        # For normal login, check against hardcoded users
        for test_user in [{"username": "admin", "password_hash": "admin123", "role": "admin"},
                         {"username": "test", "password_hash": "test123", "role": "user"}]:
            if test_user["username"] == username and test_user["password_hash"] == password:
                return True, test_user["role"]
                
        print("[DEBUG] SQL Injection failed - no results found")
        return False, None
        
    except Exception as err:
        print(f"[DEBUG] Error in vulnerable login: {err}")
        logging.error(f"Error in vulnerable login: {err}")
        return False, None

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureAccessApp(root)
    root.mainloop()
