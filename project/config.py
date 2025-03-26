from datetime import timedelta
import os
from dotenv import load_dotenv



load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 50,         # Increase to 10 persistent connections
    'max_overflow': 100,      # Allow 20 more temporary connections
    'pool_timeout': 60,      # Wait 60 seconds before timeout
    'pool_pre_ping': True
    }
    AES_KEY = os.getenv("AES_SECRET_KEY")

    # ✅ JWT CONFIGURATION
    JWT_SECRET_KEY = "E3F2DCD19A45C9EE7243C1A6EA2C4"  # Change this in production!
    JWT_ACCESS_TOKEN_EXPIRES = False  # Access Token valid for 30 min
    JWT_TOKEN_LOCATION = ["headers"]  # Tokens should be in headers
    JWT_HEADER_NAME = "Authorization"
    JWT_HEADER_TYPE = "Bearer"
    
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = "harsh@nuviontech.com"
    MAIL_PASSWORD = "wwlspivichoaopkw"
    MAIL_DEFAULT_SENDER = "harsh@nuviontech.com"
    DRY_RUN = False

    # # ✅ Secure Cookie Storage for Refresh Tokens
    # JWT_COOKIE_SECURE = True  # Only send over HTTPS (Enable in Production)
    # JWT_COOKIE_HTTPONLY = True  # Prevent JavaScript access (Prevents XSS)
    # JWT_COOKIE_CSRF_PROTECT = True  # CSRF protection for cookies
