from auth import create_access_token

def get_access_token(data: dict):
    access_token = create_access_token(data=data)
    return {"access_token": access_token, "token_type": "bearer"}