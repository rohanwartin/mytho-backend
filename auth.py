from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status
import os
from dotenv import load_dotenv
import random, string
from email_utils import render_template, send_email_with_sendgrid

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRES_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> bool:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid Token Payload")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid Token")

def generate_otp(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))

def hash_otp(otp: str) -> str:
    return pwd_context.hash(otp)

def verify_hashed_tokens(plain_text, hashed_token) -> bool:
    return pwd_context.verify(plain_text, hashed_token)

def send_otp_to_email(email: str, otp: int) -> str:
    print(f"Sending {otp} to {email}")
    html = render_template(name="User", otp=otp)
    send_email_with_sendgrid(
        to_email=email,
        subject="Your OTP for Mytho World",
        html_content=html
    )
