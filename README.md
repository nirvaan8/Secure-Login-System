🔐 Secure Login System (Python + Tkinter + SQLite)

A fully-featured secure authentication system built in Python, designed for learning and demonstrating real-world security concepts such as password hashing, OTP verification, session tokens, and login throttling.
Includes a clean Tkinter GUI for user registration, email verification, and login.

🌟 Features
✔ Password Security

Uses bcrypt for safe password hashing

Built-in password strength checker

Strong password rules:

Min 10 characters

Uppercase + lowercase

Digit

Special character

Not in common password list

✔ Email + OTP Verification

6-digit OTP sent via:

SMTP (Gmail, Outlook, custom server)

Console fallback for testing

OTP expires in 5 minutes

User marked as “verified” only after correct OTP

✔ Secure Login System

Account lockout after 3 wrong attempts

Lockout duration: 5 minutes

Reset after successful login

Clear and helpful login messages

✔ Session Tokens (Like Real Web Apps)

Cryptographically secure tokens

Stored in SQLite

Expire after 1 hour

Dashboard includes:

Session status

Token preview

Logout button

✔ GUI (Tkinter)

Register Tab

Login Tab

OTP popup

Dashboard Tab

Modern, user-friendly design using ttk

🗂 Tech Used
Component	Technology
Database	SQLite
Password Security	bcrypt
GUI	Tkinter
Email	smtplib / EmailMessage
Token Generation	Python secrets
OTP	Random numeric codes
