from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import random, smtplib, os
from email.mime.text import MIMEText

# ================= APP =================
app = FastAPI(title="Anupom Auth API")

# ----------- CORS (Flutter এর জন্য জরুরি) -----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root route
@app.get("/")
def root():
    return {"status": "API Running 🚀"}

# ================= DATABASE =================
DATABASE_URL = "sqlite:///./users.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)

Base.metadata.create_all(bind=engine)

# ================= PASSWORD HASH (FIXED) =================
# bcrypt বাদ ❌ → pbkdf2 ব্যবহার ✔ (mobile safe)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password.strip())

def verify_password(plain, hashed):
    return pwd_context.verify(plain.strip(), hashed)

# ================= JWT =================
SECRET_KEY = "ANUPOM_SUPER_SECRET_KEY_2026"
ALGORITHM = "HS256"

def create_token(email: str):
    expire = datetime.utcnow() + timedelta(hours=12)
    payload = {"sub": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# ================= EMAIL CONFIG =================
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

# OTP memory
login_otp = {}

def send_otp(email, otp):
    try:
        msg = MIMEText(f"Your login OTP is: {otp}")
        msg["Subject"] = "Your Login OTP"
        msg["From"] = EMAIL_USER
        msg["To"] = email

        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, email, msg.as_string())
        server.quit()

        print("OTP SENT:", otp)

    except Exception as e:
        print("EMAIL ERROR:", e)
        raise HTTPException(500, "Email sending failed")

# ================= SCHEMAS =================
class RegisterSchema(BaseModel):
    email: EmailStr
    password: str

class LoginSchema(BaseModel):
    email: EmailStr
    password: str

class OTPSchema(BaseModel):
    email: EmailStr
    otp: str

# ================= DB DEP =================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ================= REGISTER =================
@app.post("/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):

    existing = db.query(User).filter(User.email == data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=data.email,
        password=hash_password(data.password)
    )
    db.add(user)
    db.commit()

    return {"message": "Account created successfully"}

# ================= LOGIN =================
@app.post("/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    otp = str(random.randint(100000, 999999))
    login_otp[data.email] = otp

    send_otp(data.email, otp)

    return {"message": "OTP sent to email"}

# ================= VERIFY OTP =================
@app.post("/verify-otp")
def verify_otp(data: OTPSchema):

    stored = login_otp.get(data.email)
    if not stored or stored != data.otp:
        raise HTTPException(status_code=401, detail="Wrong OTP")

    token = create_token(data.email)
    del login_otp[data.email]

    return {"access_token": token}
