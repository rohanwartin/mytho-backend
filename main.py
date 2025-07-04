from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List
from auth import create_access_token, verify_token, get_password_hash, verify_hashed_tokens, generate_otp, hash_otp, send_otp_to_email
from database import fake_users_db, otp_tokens
from models import UserModel, BotDetailModel, UserLoginModel, UserBase, VerifyOTPModel, ResetPasswordModel, ResetAuthPasswordModel, AccountAuthModel
from utils import get_access_token
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from db import SessionLocal
from db_models import User, PasswordResetToken

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()

def get_existing_user(user_email, db):
    return db.query(User).filter(User.email == user_email).first()

def get_latest_otp(existing_user_id, db):
    return (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.user_id == existing_user_id)
        .order_by(PasswordResetToken.created_at.desc())
        .first()
    )

def db_error(db, e):
    db.rollback()
    print(e)
    raise HTTPException(status_code=500, detail="Internal DB Error")

@app.post("/signup")
def signup(user: UserModel, db: Session = Depends(get_db)):
    existing_user = get_existing_user(user.email, db)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already exists")
    
    hashed_password = get_password_hash(user.password)
    new_user = User(
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password,
        is_active=True
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except Exception as e:
        db_error(db, e)        

    return get_access_token(data={"email": new_user.email, "full_name": new_user.full_name})

@app.post("/login")
def login(user: UserLoginModel, db: Session = Depends(get_db)):
    existing_user = get_existing_user(user.email, db)
    if not existing_user:
        raise HTTPException(status_code=400, detail="Invalid Credentials")
    
    if not verify_hashed_tokens(user.password, existing_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid Credentials")
    
    if existing_user.is_active:
        raise HTTPException(status_code=400, detail="User Already has a logged in session")
    
    existing_user.is_active = True

    try:
        db.commit()
        db.refresh(existing_user)
    except Exception as e:
        db_error(db, e)
    
    return get_access_token(data={"email": existing_user.email, "full_name": existing_user.full_name})

@app.post("/forgot-password")
def forgot_password(user: UserBase, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    existing_user = get_existing_user(user.email, db)
    if not existing_user:
        raise HTTPException(status_code=404, detail="Email Not Found")
    
    otp = generate_otp()
    otp_hash = hash_otp(otp)
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    new_otp_token = PasswordResetToken(
        user_id=existing_user.id,
        otp_hash=otp_hash,
        expires_at=expires_at,
        is_used=False,
        is_verified=False
    )

    try:
        db.add(new_otp_token)
        db.commit()
        db.refresh(new_otp_token)
    except Exception as e:
        db_error(db, e)

    background_tasks.add_task(send_otp_to_email, user.email, otp)
    return {"message": f"{otp} Sent to your {existing_user.email}"}

@app.post("/otp-verification")
def otp_verification(req: VerifyOTPModel, db: Session = Depends(get_db)):
    existing_user = get_existing_user(req.email, db)
    if not existing_user:
        raise HTTPException(status_code=400, detail="Email Does Not Exist")

    token = get_latest_otp(existing_user.id, db)

    if not token or token.is_used or token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or Expired OTP")
    
    if not verify_hashed_tokens(req.otp, token.otp_hash):
        raise HTTPException(status_code=400, detail="Incorrect OTP")

    token.is_verified = True

    try:
        db.commit()
        db.refresh(token)
    except Exception as e:
        db_error(db, e)

    return {"message": f"{req.otp} verified succesfully", "otp_token": token}

@app.post("/reset-password")
def reset_password(req: ResetPasswordModel, db: Session = Depends(get_db)):
    existing_user = get_existing_user(req.email, db)
    if not existing_user:
        raise HTTPException(status_code=400, detail="Email does not exist")

    token = get_latest_otp(existing_user.id, db)

    if not token or not token.is_verified or token.is_used:
        raise HTTPException(status_code=400, detail="OTP not verified or already used")
    
    existing_user.hashed_password = hash_otp(req.new_password)
    existing_user.is_active = False

    token.is_used = True
    token.is_verified = False # just resetting the flag

    try:
        db.commit()
        db.refresh(existing_user)
        db.refresh(token)
    except Exception as e:
        db_error(db, e)

    return f"{req.new_password} successfully set for {req.email}"

@app.patch("/reset-auth-password")
def reset_auth_password(req: ResetAuthPasswordModel, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    email = verify_token(token)
    existing_user = get_existing_user(email, db)
    if not existing_user:
        raise HTTPException(status_code=400, detail="Invalid Credentials")
    
    correct_old_password = verify_hashed_tokens(req.old_password, existing_user.hashed_password)
    if not correct_old_password:
        raise HTTPException(status_code=400, detail="Existing Password is Incorrect")
    
    new_hashed_password = get_password_hash(req.new_password)
    existing_user.hashed_password = new_hashed_password

    try:
        db.commit()
        db.refresh(existing_user)
    except Exception as e:
        db_error(db, e)

    return "Password Changed Successfully"

@app.patch("/account-auth")
def account_auth(req: AccountAuthModel, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    current_email = verify_token(token)
    existing_user = get_existing_user(current_email, db)

    if not existing_user:
        raise HTTPException(status_code=400, detail="Invalid Credentials")

    # rohan@wartinlabs.com cannot change into yash@wartinlabs.com, if yash is already a user    
    if req.email != current_email and get_existing_user(req.email, db):
        raise HTTPException(status_code=403, detail="Email Already in use")

    existing_user.email = req.email
    existing_user.full_name = req.full_name

    try:
        db.commit()
        db.refresh(existing_user)
    except Exception as e:
        db_error(db, e)

    return get_access_token(data={"email": existing_user.email, "full_name": existing_user.full_name})

@app.delete("/logout")
def logout(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    email = verify_token(token)
    existing_user = get_existing_user(email, db)

    if not existing_user:
        raise HTTPException(status_code=400, detail="Invalid Credentials")

    existing_user.is_active = False

    try:
        db.commit()
        db.refresh(existing_user)
    except Exception as e:
        db_error(db, e)

    return f"{email} logged out"


@app.get("/details")
def get_details(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    email = verify_token(token)
    existing_user = get_existing_user(email, db)
    if not existing_user:
        raise HTTPException(status_code=400, detail="Invalid Credentials")
    bots = [
        {
            "name": "Elon Musk",
            "description": "Grumpy Old Man",
            "version": "1.9"
        },
        {
            "name": "Steve Jobs",
            "description": "Grumpy Dead Man",
            "version": "6.9"
        }
    ]

    return {"bots": bots, "users": db.query(User).all(), "otp_tokens": db.query(PasswordResetToken).all()}