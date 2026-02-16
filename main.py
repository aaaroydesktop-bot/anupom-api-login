from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from jose import jwt
import hashlib
import os

app = FastAPI()

# CORS (Flutter connect এর জন্য)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- DATABASE ----------------
conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    email TEXT PRIMARY KEY,
    password TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS otp(
    email TEXT,
    code TEXT
)
""")
conn.commit()

# ---------------- CONFIG ----------------
SECRET_KEY = "ANUPOM_SECRET_KEY"
ALGORITHM = "HS256"

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

# ---------------- UTILS ----------------

def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str):
    return hashlib.sha256(password.encode()).hexdigest() == hashed

def create_token(email: str):
    payload = {
        "sub": email,
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def send_otp(email: str, code: str):
    try:
        msg = MIMEText(f"Your OTP Code is: {code}")
        msg["Subject"] = "Your Login OTP"
        msg["From"] = EMAIL_USER
        msg["To"] = email

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, email, msg.as_string())
        server.quit()

    except Exception as e:
        print("EMAIL ERROR:", e)

# ---------------- MODELS ----------------

class Register(BaseModel):
    email: EmailStr
    password: str

class Login(BaseModel):
    email: EmailStr
    password: str

class VerifyOTP(BaseModel):
    email: EmailStr
    otp: str

# ---------------- ROUTES ----------------

@app.get("/")
def home():
    return {"status": "API WORKING"}

# REGISTER
@app.post("/register")
def register(data: Register):

    cursor.execute("SELECT * FROM users WHERE email=?", (data.email,))
    if cursor.fetchone():
        raise HTTPException(400, "Email already registered")

    hashed = hash_password(data.password)

    cursor.execute(
        "INSERT INTO users(email,password) VALUES(?,?)",
        (data.email, hashed)
    )
    conn.commit()

    return {"message": "Registered Successfully"}

# LOGIN (OTP SEND)
@app.post("/login")
def login(data: Login):

    cursor.execute("SELECT password FROM users WHERE email=?", (data.email,))
    user = cursor.fetchone()

    if not user:
        raise HTTPException(400, "User not found")

    if not verify_password(data.password, user[0]):
        raise HTTPException(400, "Wrong password")

    code = str(random.randint(100000, 999999))

    cursor.execute("DELETE FROM otp WHERE email=?", (data.email,))
    cursor.execute("INSERT INTO otp(email,code) VALUES(?,?)", (data.email, code))
    conn.commit()

    send_otp(data.email, code)

    return {"message": "OTP sent"}

# VERIFY OTP
@app.post("/verify-otp")
def verify(data: VerifyOTP):

    cursor.execute("SELECT code FROM otp WHERE email=?", (data.email,))
    row = cursor.fetchone()

    if not row:
        raise HTTPException(400, "OTP expired")

    if row[0] != data.otp:
        raise HTTPException(400, "Invalid OTP")

    token = create_token(data.email)

    cursor.execute("DELETE FROM otp WHERE email=?", (data.email,))
    conn.commit()

    return {"access_token": token}
