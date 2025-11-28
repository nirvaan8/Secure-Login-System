"""
secure_login_gui.py
A secure login system with:
 - bcrypt password hashing
 - SQLite user store
 - Email OTP verification (SMTP configurable; falls back to console)
 - Password strength checking
 - Account lockout after 3 failed attempts (with cooldown)
 - Login session tokens with expiry (stored in DB)
 - Tkinter GUI for register/login/OTP

Usage:
    pip install bcrypt
    python secure_login_gui.py

NOTE: For sending real emails, fill SMTP_CONFIG below (host, port, email, password).
If you don't configure SMTP, OTP will be printed to console for testing.
"""

import bcrypt
import sqlite3
import secrets
import string
import smtplib
import json
import time
import datetime
from email.message import EmailMessage
import tkinter as tk
from tkinter import ttk, messagebox

# ---------- Configuration ----------
DB_FILE = "secure_users.db"
# Session token expiry (seconds)
SESSION_EXPIRY = 60 * 60  # 1 hour
# Account lockout settings
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION = 5 * 60  # 5 minutes

# SMTP config: fill in to enable real emails.
# Example:
# SMTP_CONFIG = {
#   "host": "smtp.gmail.com",
#   "port": 587,
#   "username": "youremail@gmail.com",
#   "password": "app-or-account-password",
#   "from_name": "SecureLoginDemo"
# }
SMTP_CONFIG = None  # set to dict to enable real email sending

# ------------------ DB Helpers ------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # users table: username unique, password_hash, email, verified (0/1), failed_attempts, lockout_until (timestamp or 0)
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        email TEXT NOT NULL,
        verified INTEGER DEFAULT 0,
        failed_attempts INTEGER DEFAULT 0,
        lockout_until INTEGER DEFAULT 0
    );
    ''')
    # otp table: username, otp, expiry timestamp
    c.execute('''
    CREATE TABLE IF NOT EXISTS otps (
        username TEXT,
        otp TEXT,
        expiry INTEGER,
        PRIMARY KEY (username)
    );
    ''')
    # sessions table: token, username, expiry
    c.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        username TEXT,
        expiry INTEGER
    );
    ''')
    conn.commit()
    conn.close()

# ------------------ Security Helpers ------------------
def hash_password(password: bytes) -> bytes:
    return bcrypt.hashpw(password, bcrypt.gensalt())

def check_password(password: bytes, hashed: bytes) -> bool:
    return bcrypt.checkpw(password, hashed)

def generate_otp(length=6):
    # numeric OTP
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def send_otp_via_email(to_email: str, otp: str):
    """
    Attempts to send OTP via SMTP if SMTP_CONFIG is set.
    Otherwise, fallback to printing OTP to console (for testing).
    """
    if SMTP_CONFIG:
        try:
            msg = EmailMessage()
            msg["Subject"] = "Your OTP Code"
            msg["From"] = f"{SMTP_CONFIG.get('from_name','SecureLogin')} <{SMTP_CONFIG['username']}>"
            msg["To"] = to_email
            msg.set_content(f"Your OTP code is: {otp}\nIt is valid for 5 minutes.")
            with smtplib.SMTP(SMTP_CONFIG["host"], SMTP_CONFIG["port"]) as smtp:
                smtp.starttls()
                smtp.login(SMTP_CONFIG["username"], SMTP_CONFIG["password"])
                smtp.send_message(msg)
            print(f"[INFO] OTP sent via email to {to_email}")
            return True
        except Exception as e:
            print(f"[WARN] Failed to send email: {e}. Falling back to console OTP.")
    # Fallback
    print(f"[FALLBACK] OTP for {to_email}: {otp}")
    return False

def save_otp(username, otp, ttl_seconds=300):
    expiry = int(time.time()) + ttl_seconds
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("REPLACE INTO otps (username, otp, expiry) VALUES (?, ?, ?);", (username, otp, expiry))
    conn.commit()
    conn.close()

def verify_otp(username, otp_candidate):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT otp, expiry FROM otps WHERE username = ?;", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False, "No OTP found. Request a new one."
    otp, expiry = row
    now = int(time.time())
    if now > expiry:
        return False, "OTP expired."
    if otp_candidate != otp:
        return False, "Incorrect OTP."
    # success -> delete otp record
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM otps WHERE username = ?;", (username,))
    conn.commit()
    conn.close()
    return True, "Verified"

def is_locked(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT lockout_until FROM users WHERE username = ?;", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False, 0
    lockout_until = row[0]
    now = int(time.time())
    if now < lockout_until:
        return True, lockout_until
    return False, 0

def record_failed_attempt(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT failed_attempts FROM users WHERE username = ?;", (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        return
    failed = row[0] + 1
    lockout_until = 0
    if failed >= MAX_FAILED_ATTEMPTS:
        lockout_until = int(time.time()) + LOCKOUT_DURATION
        failed = 0  # reset failed after lockout applied
    c.execute("UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE username = ?;", (failed, lockout_until, username))
    conn.commit()
    conn.close()

def reset_failed_attempts(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET failed_attempts = 0, lockout_until = 0 WHERE username = ?;", (username,))
    conn.commit()
    conn.close()

def create_session(username):
    token = secrets.token_urlsafe(32)
    expiry = int(time.time()) + SESSION_EXPIRY
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO sessions (token, username, expiry) VALUES (?, ?, ?);", (token, username, expiry))
    conn.commit()
    conn.close()
    return token, expiry

def validate_session(token):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username, expiry FROM sessions WHERE token = ?;", (token,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False, None
    username, expiry = row
    if int(time.time()) > expiry:
        # expired -> delete
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM sessions WHERE token = ?;", (token,))
        conn.commit()
        conn.close()
        return False, None
    return True, username

# ------------------ Password strength checker ------------------
COMMON_PASSWORDS = {
    "123456","password","12345678","qwerty","123456789","12345","1234","111111","1234567","dragon",
    "123123","baseball","abc123","football","monkey","letmein","shadow","master","666666","qwertyuiop"
}

def check_password_strength(pw: str):
    """
    Returns (is_strong: bool, messages: list[str])
    Rules:
        - Minimum 10 characters
        - Contains lower, upper, digit, special
        - Not in COMMON_PASSWORDS
    """
    msgs = []
    if len(pw) < 10:
        msgs.append("Password must be at least 10 characters.")
    if not any(c.islower() for c in pw):
        msgs.append("Include at least one lowercase letter.")
    if not any(c.isupper() for c in pw):
        msgs.append("Include at least one uppercase letter.")
    if not any(c.isdigit() for c in pw):
        msgs.append("Include at least one digit.")
    if not any(c in string.punctuation for c in pw):
        msgs.append("Include at least one special character (e.g. !@#$%).")
    if pw.lower() in COMMON_PASSWORDS:
        msgs.append("This password is too common; choose a less common password.")
    is_strong = len(msgs) == 0
    return is_strong, msgs

# ------------------ Core User Ops ------------------
def register_user(username: str, password_plain: str, email: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username = ?;", (username,))
    if c.fetchone():
        conn.close()
        return False, "Username already exists."
    # hash
    hashed = hash_password(password_plain.encode())
    c.execute("INSERT INTO users (username, password_hash, email, verified) VALUES (?, ?, ?, 0);",
              (username, hashed.decode(), email))
    conn.commit()
    conn.close()
    return True, "Registered. Please verify your email with the OTP sent."

def start_email_verification(username):
    # Lookup email
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT email FROM users WHERE username = ?;", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False, "User not found."
    email = row[0]
    otp = generate_otp(6)
    save_otp(username, otp, ttl_seconds=5*60)
    send_otp_via_email(email, otp)
    return True, f"OTP sent to {email} (or printed to console if SMTP not configured)."

def finalize_verification(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET verified = 1 WHERE username = ?;", (username,))
    conn.commit()
    conn.close()

def authenticate_user(username: str, password_plain: str):
    locked, lock_until = is_locked(username)
    if locked:
        until = datetime.datetime.utcfromtimestamp(lock_until).strftime("%Y-%m-%d %H:%M:%SZ")
        return False, f"Account locked until {until} UTC due to repeated failed attempts."

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password_hash, verified FROM users WHERE username = ?;", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False, "User not found."

    stored_hash, verified = row
    try:
        ok = check_password(password_plain.encode(), stored_hash.encode())
    except Exception:
        ok = False

    if not ok:
        record_failed_attempt(username)
        return False, "Incorrect password."

    if not verified:
        return False, "Email not verified. Please complete OTP verification."

    # success: reset failed attempts, create session
    reset_failed_attempts(username)
    token, expiry = create_session(username)
    return True, {"token": token, "expiry": expiry}

# ------------------ GUI ------------------
class SecureLoginApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Login System")
        self.geometry("520x420")
        self.resizable(False, False)
        self._create_widgets()
        self.current_user_for_verification = None
        self.current_session_token = None

    def _create_widgets(self):
        tabControl = ttk.Notebook(self)
        self.tab_register = ttk.Frame(tabControl)
        self.tab_login = ttk.Frame(tabControl)
        self.tab_dashboard = ttk.Frame(tabControl)
        tabControl.add(self.tab_register, text='Register')
        tabControl.add(self.tab_login, text='Login')
        tabControl.add(self.tab_dashboard, text='Dashboard')
        tabControl.pack(expand=1, fill="both")

        # Register tab
        self._build_register_tab(self.tab_register)
        # Login tab
        self._build_login_tab(self.tab_login)
        # Dashboard
        self._build_dashboard(self.tab_dashboard)

    def _build_register_tab(self, parent):
        frm = ttk.Frame(parent, padding=16)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Create account", font=("Segoe UI", 14)).grid(row=0, column=0, columnspan=2, pady=(0,10))

        ttk.Label(frm, text="Username:").grid(row=1, column=0, sticky="e")
        self.reg_username = ttk.Entry(frm, width=30)
        self.reg_username.grid(row=1, column=1)

        ttk.Label(frm, text="Email:").grid(row=2, column=0, sticky="e")
        self.reg_email = ttk.Entry(frm, width=30)
        self.reg_email.grid(row=2, column=1)

        ttk.Label(frm, text="Password:").grid(row=3, column=0, sticky="e")
        self.reg_password = ttk.Entry(frm, width=30, show="*")
        self.reg_password.grid(row=3, column=1)

        ttk.Label(frm, text="Confirm Password:").grid(row=4, column=0, sticky="e")
        self.reg_password_confirm = ttk.Entry(frm, width=30, show="*")
        self.reg_password_confirm.grid(row=4, column=1)

        self.reg_feedback = tk.Text(frm, height=6, width=50, state="disabled")
        self.reg_feedback.grid(row=6, column=0, columnspan=2, pady=8)

        btn_frame = ttk.Frame(frm)
        btn_frame.grid(row=7, column=0, columnspan=2)
        ttk.Button(btn_frame, text="Check Strength", command=self.check_strength_action).grid(column=0, row=0, padx=6)
        ttk.Button(btn_frame, text="Register", command=self.register_action).grid(column=1, row=0, padx=6)

    def _build_login_tab(self, parent):
        frm = ttk.Frame(parent, padding=16)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Login", font=("Segoe UI", 14)).grid(row=0, column=0, columnspan=2, pady=(0,10))

        ttk.Label(frm, text="Username:").grid(row=1, column=0, sticky="e")
        self.login_username = ttk.Entry(frm, width=30)
        self.login_username.grid(row=1, column=1)

        ttk.Label(frm, text="Password:").grid(row=2, column=0, sticky="e")
        self.login_password = ttk.Entry(frm, width=30, show="*")
        self.login_password.grid(row=2, column=1)

        ttk.Button(frm, text="Login", command=self.login_action).grid(row=3, column=0, columnspan=2, pady=8)

        ttk.Separator(frm, orient="horizontal").grid(row=4, column=0, columnspan=2, sticky="ew", pady=8)

        ttk.Label(frm, text="If you haven't verified email, enter your username and click 'Send OTP'").grid(row=5, column=0, columnspan=2)
        ttk.Button(frm, text="Send OTP", command=self.send_otp_action).grid(row=6, column=0, columnspan=2, pady=6)

    def _build_dashboard(self, parent):
        frm = ttk.Frame(parent, padding=16)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Dashboard (requires active session)", font=("Segoe UI", 14)).pack(pady=(0,10))
        self.session_info_lbl = ttk.Label(frm, text="No active session.")
        self.session_info_lbl.pack()
        ttk.Button(frm, text="Check Session", command=self.check_session_action).pack(pady=6)
        ttk.Button(frm, text="Logout", command=self.logout_action).pack(pady=6)

    # ---------------- actions ----------------
    def check_strength_action(self):
        pw = self.reg_password.get()
        ok, msgs = check_password_strength(pw)
        self.reg_feedback.config(state="normal")
        self.reg_feedback.delete("1.0", tk.END)
        if ok:
            self.reg_feedback.insert(tk.END, "Password strength: GOOD ✅\n")
        else:
            self.reg_feedback.insert(tk.END, "Password strength: Weak ❌\n")
            for m in msgs:
                self.reg_feedback.insert(tk.END, f"- {m}\n")
        self.reg_feedback.config(state="disabled")

    def register_action(self):
        username = self.reg_username.get().strip()
        email = self.reg_email.get().strip()
        pw = self.reg_password.get()
        pw2 = self.reg_password_confirm.get()
        if not username or not email or not pw:
            messagebox.showwarning("Missing data", "Please fill username, email, and password.")
            return
        if pw != pw2:
            messagebox.showwarning("Password mismatch", "Passwords do not match.")
            return
        ok, msgs = check_password_strength(pw)
        if not ok:
            messagebox.showwarning("Weak password", "Please choose a stronger password.\n" + "\n".join(msgs))
            return
        success, msg = register_user(username, pw, email)
        if not success:
            messagebox.showerror("Register failed", msg)
            return
        messagebox.showinfo("Registered", msg)
        # send OTP
        ok, msg2 = start_email_verification(username)
        if ok:
            self.current_user_for_verification = username
            self.prompt_for_otp(username)
        else:
            messagebox.showwarning("OTP issue", msg2)

    def prompt_for_otp(self, username):
        # Small popup to enter OTP
        popup = tk.Toplevel(self)
        popup.title("Enter OTP")
        popup.geometry("350x160")
        ttk.Label(popup, text=f"Enter OTP sent to the email for user: {username}").pack(pady=8)
        otp_entry = ttk.Entry(popup, width=30)
        otp_entry.pack(pady=6)
        def submit():
            otp_val = otp_entry.get().strip()
            ok, m = verify_otp(username, otp_val)
            if ok:
                finalize_verification(username)
                messagebox.showinfo("Verified", "Email verified successfully. You can now log in.")
                popup.destroy()
            else:
                messagebox.showerror("OTP failed", m)
        ttk.Button(popup, text="Verify", command=submit).pack(pady=6)
        ttk.Button(popup, text="Resend OTP", command=lambda: (start_email_verification(username), messagebox.showinfo("Resent", "OTP resent (or printed to console)."))).pack()

    def send_otp_action(self):
        username = self.login_username.get().strip()
        if not username:
            messagebox.showwarning("Missing", "Enter username to send OTP.")
            return
        ok, msg = start_email_verification(username)
        if ok:
            self.current_user_for_verification = username
            self.prompt_for_otp(username)
        else:
            messagebox.showerror("Error", msg)

    def login_action(self):
        username = self.login_username.get().strip()
        pw = self.login_password.get()
        if not username or not pw:
            messagebox.showwarning("Missing", "Provide username and password.")
            return
        ok, data_or_msg = authenticate_user(username, pw)
        if not ok:
            messagebox.showerror("Login failed", data_or_msg)
            return
        session_token = data_or_msg["token"]
        expiry = data_or_msg["expiry"]
        self.current_session_token = session_token
        until = datetime.datetime.utcfromtimestamp(expiry).strftime("%Y-%m-%d %H:%M:%SZ")
        messagebox.showinfo("Logged in", f"Login successful. Session expires at {until} UTC.")
        self.session_info_lbl.config(text=f"Active session for {username}\nExpires: {until} UTC\nToken: {session_token[:12]}...")

    def check_session_action(self):
        token = self.current_session_token
        if not token:
            messagebox.showinfo("No session", "No active session token stored in the app.")
            return
        valid, username = validate_session(token)
        if valid:
            messagebox.showinfo("Session valid", f"Session valid for user: {username}")
        else:
            messagebox.showwarning("Session expired", "Session invalid or expired.")
            self.current_session_token = None
            self.session_info_lbl.config(text="No active session.")

    def logout_action(self):
        if not self.current_session_token:
            messagebox.showinfo("Not logged in", "You are not currently logged in.")
            return
        # delete session from DB
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM sessions WHERE token = ?;", (self.current_session_token,))
        conn.commit()
        conn.close()
        self.current_session_token = None
        self.session_info_lbl.config(text="No active session.")
        messagebox.showinfo("Logged out", "Session ended.")

# ------------------ Run ------------------
def main():
    init_db()
    app = SecureLoginApp()
    app.mainloop()

if __name__ == "__main__":
    main()
