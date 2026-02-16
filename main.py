from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
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

# -------- CORS (Flutter connect এর জন্য খুব জরুরি) --------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- ROOT FIX ----------------
@app.get("/")
def home():
    return {"status": "API Running Successfully 🚀"}

# ---------------- DATABASE ----------------
DATABASE_URL = "sqlite:///./users.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    password = Column(String)

Base.metadata.create_all(bind=engine)

# ---------------- PASSWORD ----------------
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

# ---------------- EMAIL (FIXED) ----------------
EMAIL_USER = os.getenv("testanupom@gmail.com")
EMAIL_PASS = os.getenv("vraykifwaowxliir")

login_otp = {}

def send_otp(email, otp):
    try:
        msg = MIMEText(f"Your Login OTP is: {otp}")
        msg["Subject"] = "Login OTP"
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

# ---------------- DB ----------------
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
        raise HTTPException(400, "Email already exists")

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
        raise HTTPException(401, "Invalid email or password")

    otp = str(random.randint(100000, 999999))
    login_otp[data.email] = otp

    send_otp(data.email, otp)

    return {"message": "OTP sent"}

# ---------------- VERIFY OTP ----------------
@app.post("/verify-otp")
def verify(data: OTPSchema):
    stored = login_otp.get(data.email)

    if not stored or stored != data.otp:
        raise HTTPException(401, "Wrong OTP")

    token = create_token(data.email)
    del login_otp[data.email]

    return {"access_token": token}
