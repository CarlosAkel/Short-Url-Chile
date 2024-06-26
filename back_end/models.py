from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from database import Base, engine
from werkzeug.security import generate_password_hash, check_password_hash
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password = Column(String(500), unique=False, nullable=False)

    # Define a one-to-many relationship with the Url model
    urls = relationship("Url", back_populates="user")
    
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def json(self):
        return {'username': self.username}
        

class Url(Base):
    __tablename__ = "urls"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True) 
    user_id = Column(Integer, ForeignKey("users.id"))
    short_url = Column(String, index=True)
    clicks = Column(Integer, index=True)


    user = relationship("User", back_populates="urls", uselist=False) 
    
    def __init__(self, url, user_id, short_url):
        self.url = url
        self.user_id = user_id
        self.short_url = short_url
        self.clicks = 0
    
    def json(self):
        return {'url': self.short_url}

class GuestUrl(Base):
    __tablename__ = "guest_urls"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    short_url = Column(String, index=True)
    clicks = Column(Integer, index=True)
    
    def __init__(self, url, short_url):
        self.url = url
        self.short_url = short_url
        self.clicks = 0


Base.metadata.create_all(bind=engine)