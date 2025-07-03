from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List
from auth import create_access_token, verify_token, get_password_hash, verify_hashed_tokens, generate_otp, hash_otp, send_otp_to_email
from database import fake_users_db, otp_tokens
from models import UserModel, BotDetailModel, UserLoginModel, UserBase, VerifyOTPModel, ResetPasswordModel, ResetAuthPasswordModel, AccountAuthModel
from utils import get_access_token
from datetime import datetime, timedelta

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/signup")
def signup(user: UserModel):
    if user.email in fake_users_db:
        raise HTTPException(status_code=400, detail="Email already exists")
    
    hashed_password = get_password_hash(user.password)
    fake_users_db[user.email] = {"email": user.email, "full_name": user.full_name, "hashed_password": hashed_password}
    return get_access_token(data={"email": user.email, "full_name": user.full_name})

@app.post("/login")
def login(user: UserLoginModel):
    if user.email not in fake_users_db:
        raise HTTPException(status_code=400, detail="Invalid Credentials")
    user_password_in_db = fake_users_db[user.email]["hashed_password"]
    if not verify_hashed_tokens(user.password, user_password_in_db):
        raise HTTPException(status_code=400, detail="Invalid Credentials")
    return get_access_token(data={"email": user.email, "full_name": fake_users_db[user.email]["full_name"]})

@app.post("/forgot-password")
def forgot_password(user: UserBase, background_tasks: BackgroundTasks):
    if user.email not in fake_users_db:
        raise HTTPException(status_code=404, detail="Email Not Found")
    
    otp = generate_otp()
    otp_hash = hash_otp(otp)
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    otp_tokens[user.email] = {
        "otp_hash": otp_hash,
        "expires_at": expires_at,
        "is_used": False,
        "is_verified": False
    }

    # background_tasks.add_task(send_otp_to_email, user.email, otp)
    return {"message": f"{otp} Sent to your {user.email}"}

@app.post("/otp-verification")
def otp_verification(req: VerifyOTPModel):
    token = otp_tokens.get(req.email)

    if not token or token["is_used"] or token["expires_at"] < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or Expired OTP")
    
    if not verify_hashed_tokens(req.otp, token["otp_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect OTP")

    token["is_verified"] = True

    return {"message": f"{req.otp} verified succesfully", "otp_token": token}

@app.post("/reset-password")
def reset_password(req: ResetPasswordModel):
    token = otp_tokens.get(req.email)

    if not token or not token["is_verified"] or token["is_used"]:
        raise HTTPException(status_code=400, detail="OTP not verified or already used")
    
    fake_users_db[req.email]["hashed_password"] = hash_otp(req.new_password)

    token["is_used"] = True
    token["is_verified"] = False # just resetting the flag

    return f"{req.new_password} successfully set for {req.email}"

@app.patch("/reset-auth-password")
def reset_auth_password(req: ResetAuthPasswordModel, token: str = Depends(oauth2_scheme)):
    email = verify_token(token)
    if email not in fake_users_db:
        raise HTTPException(status_code=400, detail="Invalid Credentials")
    existing_password = fake_users_db[email]["hashed_password"]
    correct_old_password = verify_hashed_tokens(req.old_password, existing_password)
    if not correct_old_password:
        raise HTTPException(status_code=400, detail="Existing Password is Incorrect")
    new_hashed_password = get_password_hash(req.new_password)
    fake_users_db[email]["hashed_password"] = new_hashed_password
    return {"fake_users_db": fake_users_db}

@app.patch("/account-auth")
def account_auth(req: AccountAuthModel, token: str = Depends(oauth2_scheme)):
    current_email = verify_token(token)

    if current_email not in fake_users_db:
        raise HTTPException(status_code=400, detail="Invalid Credentials")

    # rohan@wartinlabs.com cannot change into yash@wartinlabs.com, if yash is already a user    
    if req.email != current_email and req.email in fake_users_db:
        raise HTTPException(status_code=403, detail="Email Already in use")
    
    old_cred = {
        "email": fake_users_db[current_email]["email"],
        "full_name": fake_users_db[current_email]["full_name"]
    }

    new_user_data = {
        "email": req.email,
        "full_name": req.full_name,
        "hashed_password": fake_users_db[current_email]["hashed_password"]
    }
    
    del fake_users_db[current_email]
    fake_users_db[req.email] = new_user_data

    return {
        "old_credentials": old_cred,
        "new_credentials": {
            "email": fake_users_db[req.email]["email"],
            "full_name": fake_users_db[req.email]["full_name"]
        }
    }

@app.delete("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    email = verify_token(token)
    if email not in fake_users_db:
        raise HTTPException(status_code=400, detail="Invalid Credentials")
    del fake_users_db[email]
    return f"{email} deleted"


@app.get("/bot_details")
def get_bot_details(token: str = Depends(oauth2_scheme)):
    email = verify_token(token)
    if email not in fake_users_db:
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

    return {"bots": bots, "fake_users_db": fake_users_db}