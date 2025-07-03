from pydantic import BaseModel, EmailStr

class UserBase(BaseModel):
    email: str

class UserLoginModel(UserBase):
    password: str

class UserModel(UserLoginModel):
    full_name: str

class VerifyOTPModel(UserBase):
    otp: str

class ResetPasswordModel(UserBase):
    new_password: str

class ResetAuthPasswordModel(BaseModel):
    old_password: str
    new_password: str

class AccountAuthModel(UserBase):
    full_name: str

class BotDetailModel(BaseModel):
    name: str
    description: str
    version: str