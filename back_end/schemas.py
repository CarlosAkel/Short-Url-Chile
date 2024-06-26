from typing import Union
from pydantic import BaseModel

class User(BaseModel):
    username: str
    email: str
    password: str
    
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Union[str, None] = None

class UserInDB(User):
    hashed_password: str

class Url(BaseModel):
    url: str
    short_url: str
    clicks: int

class GuestUrl(BaseModel):
    url: str
    short_url: str
    clicks: int
