from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List
from auth import create_access_token, verify_token, get_password_hash
from database import fake_users_db
from models import UserModel, BotDetailModel

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/signup")
def signup(user: UserModel):
    if user.email in fake_users_db:
        raise HTTPException(status_code=400, detail="Email already exists")
    
    hashed_password = get_password_hash(user.password)
    fake_users_db[user.email] = {"email": user.email, "full_name": user.full_name, "hashed_password": hashed_password}
    access_token = create_access_token(data={"email": user.email, "full_name": user.full_name})
    return {"access_token": access_token, "token_type": "bearer"}

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