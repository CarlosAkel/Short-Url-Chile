from fastapi import Depends, FastAPI, HTTPException, Request, Form, status, Security
import models
import os
import requests
from dotenv import load_dotenv
from database import engine, SessionLocal
from sqlalchemy.orm import Session
from flask_jwt_extended import (create_access_token,get_jwt_identity,jwt_required,JWTManager)
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, RedirectResponse
from typing import Annotated, Union
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from schemas import *
import random
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
load_dotenv()

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="some-random-string")
models.Base.metadata.create_all(bind=engine)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") # Auth With PasswordBearer
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

oauth = OAuth()
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    client_kwargs={
        'scope': 'email openid profile',
        'redirect_url': 'http://localhost:3000/google/auth'
    }
)


templates = Jinja2Templates(directory="templates")
    

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def generate_string(length):
    result = ''
    characters_length = len(characters)
    for i in range(length):
        result += characters[random.randint(0, characters_length - 1)]
    return result

def create_short_url():
    random_key = generate_string(5)
    new_url = f"{random_key}" 
    return new_url

def get_current_host(request: Request):
    return str(request.base_url)    

@app.post('/user')
async def create_user(request: Request, username: Annotated[str, Form()], email: Annotated[str, Form()],
                      password: Annotated[str, Form()], db: Session = Depends(get_db)):
    try:
        user = db.query(models.User).filter(models.User.email == email).first()
        user2 = db.query(models.User).filter(models.User.username == username).first()
        if not user and not user2:
            new_user = models.User(username=username, email=email, password=password)
            db.add(new_user)
            db.commit()
            db.refresh(new_user)
            return {"Response": {new_user.username}}
        return "User Already exist"
    except Exception as error:
        return f"Error: {error}"

@app.get('/users', response_model=dict)
async def get_users(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        users = db.query(models.User).all()
        serialized_users = [user.json() for user in users]
        return JSONResponse(content={"All_Users": serialized_users})
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Error: {error}")
    

@app.post('/login', response_model=dict)
async def login(request: Request, username: Annotated[str, Form()], email: Annotated[str, Form()], password: Annotated[str, Form()],
                 db: Session = Depends(get_db)):
    try:
        if (not username or not email) and not password :
            return JSONResponse(content= f"Missing username or password")

        user_email = db.query(models.User).filter(models.User.email == email).first()
        user = user_email
        user_username = db.query(models.User).filter(models.User.username == username).first()
        if not user_email:
            user = user_username
        
        if not user or not user.check_password(password):
            return JSONResponse(content= f"Invalid username or password {user}  {user.check_password(password)}")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
        )
        json_data = jsonable_encoder(Token(access_token=access_token, token_type="bearer"))
        return JSONResponse(content= json_data)
         
    except Exception as error:
        return JSONResponse(content= f"Login error: {error}")

@app.post('/url/guest')
async def create_url(request: Request, url: Annotated[str, Form()], db: Session = Depends(get_db)):
    short_url_key = create_short_url()
    db_url = models.GuestUrl(url=url,short_url= short_url_key)
    db.add(db_url)
    db.commit()
    db.refresh(db_url)
    json_data = jsonable_encoder({"short_url": f"{get_current_host(request)}{short_url_key}" })
    return JSONResponse(content= json_data)

@app.post('/url/user')
async def create_url_user(request: Request, url: Annotated[str, Form()],
                          current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    short_url_key = create_short_url()
    user = db.query(models.User).filter(models.User.username == current_user).first()
    db_url = models.Url(url=url,short_url= short_url_key ,user_id=user.id)
    db.add(db_url)
    db.commit()
    db.refresh(db_url)
    json_data = jsonable_encoder({"short_url": f"{get_current_host(request)}{short_url_key}" })
    return JSONResponse(content= json_data)

@app.get('/{id}')
async def create_url_user(id, db: Session = Depends(get_db)):
    guest_url = db.query(models.GuestUrl).filter(models.GuestUrl.short_url == id).first()
    if guest_url:
        return RedirectResponse(url=guest_url.url, status_code=302)
    else:
        user_url = db.query(models.Url).filter(models.Url.short_url == id).first()
        if user_url:
            return RedirectResponse(url=user_url.url, status_code=302)
        else:
            raise HTTPException(status_code=404, detail="URL not found")




@app.get("/google/login")
async def login(request: Request):
    url = request.url_for('auth')
    return await oauth.google.authorize_redirect(request, url)


@app.get('/google/auth')
async def auth(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as e:
        return templates.TemplateResponse(
            name='error.html',
            context={'request': request, 'error': e.error}
        )
    user = token.get('userinfo')
    if user:
        request.session['user'] = dict(user)
    json_data = jsonable_encoder({"Login": f"Login DATA WIII" })
    return JSONResponse(content= json_data)


@app.get('/google/logout')
def logout(request: Request):
    request.session.pop('user')
    request.session.clear()
    return RedirectResponse('/')



if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)
