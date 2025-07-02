from pydantic import BaseModel

class UserModel(BaseModel):
    email: str
    password: str

class BotDetailModel(BaseModel):
    name: str
    description: str
    version: str