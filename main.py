from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import hashlib
import random
import smtplib
import os
from email.mime.text import MIMEText

# ---------------- APP ----------------
app = FastAPI()

# -------- CORS (Flutter connect এর জন্য) --------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- ROOT ----------------
@app.get("/")
def root():
    return {"status": "API Running Successfully 🚀"}

# ---------------- DATABASE ----------------
DATABASE_URL = "sqlite:///./users.db"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    password = Column(String)

Base.metadata.create_all(bind=engine)

# ---------------- PASSWORD FIX (bcrypt crash solution) ----------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def safe_password(password: str) -> str:
    # SHA256 → then bcrypt (prevents 72 byte crash)
    return hashlib.sha256(password.encode()).hexdigest()

def hash_password(password: str):
    return pwd_context.hash(safe_password(password))

def verify_password(plain, hashed):
    return pwd_context.verify(safe_password(plain), hashed)

# ---------------- JWT ----------------
SECRET_KEY = "ANUPOM_SUPER_SECRET_2026"
ALGORITHM = "HS256"

def create_token(email: str):
    expire = datetime.utcnow() + timedelta(hours=24)
    payload = {"sub": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# ---------------- EMAIL CONFIG ----------------
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

otp_storage = {}

def send_otp(email, otp):
    try:
        msg = MIMEText(f"Your OTP Code is: {otp}")
        msg["Subject"] = "Login OTP Verification"
        msg["From"] = EMAIL_USER
        msg["To"] = email

        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, email, msg.as_string())
        server.quit()

        print("OTP SENT:", otp)

    except Exception as e:
        print("EMAIL ERROR:", e)
        raise HTTPException(status_code=500, detail="Email sending failed")

# ---------------- SCHEMAS ----------------
class RegisterSchema(BaseModel):
    email: EmailStr
    password: str

class LoginSchema(BaseModel):
    email: EmailStr
    password: str

class OTPSchema(BaseModel):
    email: EmailStr
    otp: str

# ---------------- DB Dependency ----------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------- REGISTER ----------------
@app.post("/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == data.email).first()
    if user:
        raise HTTPException(status_code=400, detail="Email already exists")

    new_user = User(
        email=data.email,
        password=hash_password(data.password)
    )

    db.add(new_user)
    db.commit()

    return {"message": "Registered successfully"}

# ---------------- LOGIN ----------------
@app.post("/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == data.email).first()

    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    otp = str(random.randint(100000, 999999))
    otp_storage[data.email] = otp

    send_otp(data.email, otp)

    return {"message": "OTP sent to email"}

# ---------------- VERIFY OTP ----------------
@app.post("/verify-otp")
def verify_otp(data: OTPSchema):

    stored = otp_storage.get(data.email)

    if not stored or stored != data.otp:
        raise HTTPException(status_code=401, detail="Wrong OTP")

    token = create_token(data.email)

    del otp_storage[data.email]

    return {
        "access_token": token,
        "token_type": "bearer"
    }
