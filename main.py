from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
import random, smtplib, os
from email.mime.text import MIMEText

# ---------------- APP ----------------
app = FastAPI()

# ---------------- DATABASE ----------------
DATABASE_URL = "sqlite:///./users.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ---------------- USER TABLE ----------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    password = Column(String)

Base.metadata.create_all(bind=engine)

# ---------------- PASSWORD HASH ----------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password[:72])

def verify_password(plain, hashed):
    return pwd_context.verify(plain[:72], hashed)

# ---------------- JWT ----------------
SECRET_KEY = "ANUPOM_SECRET_KEY_12345"
ALGORITHM = "HS256"

def create_token(email: str):
    expire = datetime.utcnow() + timedelta(hours=2)
    payload = {"sub": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except JWTError:
        return None

# ---------------- EMAIL OTP ----------------
EMAIL_USER = os.getenv("testanupom@gmail.com")
EMAIL_PASS = os.getenv("vraykifwaowxliir")

login_otp = {}
reset_otp = {}

def send_otp(email, otp):
    msg = MIMEText(f"Your OTP is: {otp}")
    msg["Subject"] = "Your Login OTP"
    msg["From"] = EMAIL_USER
    msg["To"] = email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, email, msg.as_string())

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

class ResetSchema(BaseModel):
    email: EmailStr
    new_password: str

# ---------------- DB DEP ----------------
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
        raise HTTPException(400, "Email already registered")

    new_user = User(
        email=data.email,
        password=hash_password(data.password)
    )
    db.add(new_user)
    db.commit()
    return {"message": "Registration successful"}

# ---------------- LOGIN ----------------
@app.post("/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(401, "Invalid credentials")

    otp = str(random.randint(100000, 999999))
    login_otp[data.email] = otp
    send_otp(data.email, otp)

    return {"message": "OTP sent to email"}

# ---------------- VERIFY OTP ----------------
@app.post("/verify-otp")
def verify(data: OTPSchema):
    stored = login_otp.get(data.email)
    if not stored or stored != data.otp:
        raise HTTPException(401, "Invalid OTP")

    token = create_token(data.email)
    del login_otp[data.email]

    return {"access_token": token}

# ---------------- FORGOT PASSWORD ----------------
@app.post("/forgot-password")
def forgot(data: LoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(404, "Email not found")

    otp = str(random.randint(100000, 999999))
    reset_otp[data.email] = otp
    send_otp(data.email, otp)

    return {"message": "Reset OTP sent"}

# ---------------- RESET PASSWORD ----------------
@app.post("/reset-password")
def reset(data: OTPSchema, db: Session = Depends(get_db)):
    stored = reset_otp.get(data.email)
    if not stored or stored != data.otp:
        raise HTTPException(401, "Invalid OTP")

    user = db.query(User).filter(User.email == data.email).first()
    user.password = hash_password("12345678")  # default temp
    db.commit()
    del reset_otp[data.email]

    return {"message": "Password reset successful. Default password: 12345678"}

# ---------------- GET USER ----------------
@app.get("/me")
def me(token: str):
    email = decode_token(token)
    if not email:
        raise HTTPException(401, "Invalid token")
    return {"email": email}
