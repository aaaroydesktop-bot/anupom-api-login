from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
import random

# ---------------- APP ----------------
app = FastAPI()

# -------- CORS (Flutter connect) --------
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
    return {"message": "Anupom Login API Running 🚀"}

# ---------------- DATABASE ----------------
DATABASE_URL = "sqlite:///./users.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ---------------- USER TABLE ----------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
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
    expire = datetime.utcnow() + timedelta(hours=12)
    payload = {"sub": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except JWTError:
        return None

# ---------------- OTP STORAGE ----------------
login_otp = {}

def send_otp(email, otp):
    # Email disabled (Render SMTP blocked)
    print("\n==============================")
    print("LOGIN OTP FOR:", email)
    print("OTP:", otp)
    print("==============================\n")

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

# ---------------- DB DEPENDENCY ----------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------- REGISTER ----------------
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

# ---------------- LOGIN ----------------
@app.post("/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == data.email).first()

    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    otp = str(random.randint(100000, 999999))
    login_otp[data.email] = otp

    send_otp(data.email, otp)

    return {"message": "OTP sent to server log"}

# ---------------- VERIFY OTP ----------------
@app.post("/verify-otp")
def verify(data: OTPSchema):

    stored = login_otp.get(data.email)

    if not stored:
        raise HTTPException(status_code=400, detail="OTP expired")

    if stored != data.otp:
        raise HTTPException(status_code=401, detail="Wrong OTP")

    token = create_token(data.email)
    del login_otp[data.email]

    return {"access_token": token}

# ---------------- GET USER ----------------
@app.get("/me")
def get_me(token: str):

    email = decode_token(token)

    if not email:
        raise HTTPException(status_code=401, detail="Invalid token")

    return {"email": email}
