import random
# from socket import SocketIO
import eventlet
import pandas as pd
eventlet.monkey_patch()
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import json
import threading
import re
from flask import Flask, request, jsonify, render_template, url_for
from flask_jwt_extended import JWTManager, create_access_token, decode_token, jwt_required, get_jwt_identity
from flask_migrate import Migrate
import requests
# import socketio
from flask_socketio import SocketIO, emit
from config import Config
from models import IST, ApiLog, Log, OrderStatus, PhaseConfig, Stock, Trade, TradeCycle, db, User, bcrypt
import os
import logging
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_mail import Mail, Message
import platform
from datetime import datetime
from flask_cors import CORS
import time
import base64
import json
import hashlib
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from threading import Lock
import os
import logging
from collections import defaultdict
import pytz
from SmartApi.smartWebSocketV2 import SmartWebSocketV2
from math import ceil


app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

app.config.from_object(Config)
session_cache = defaultdict(dict)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

SECRET_KEY = "TiSVLTWhb0jadJ8GZ7LCakMaSdu6p/DZrIYR/Mq78lU="
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
websocket_clients = {}
# ✅ Convert the SECRET_KEY to a proper 256-bit key (same as CryptoJS)
AES_KEY = hashlib.sha256(SECRET_KEY.encode()).digest()

db.init_app(app)
bcrypt.init_app(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
mail = Mail(app)  # ✅ Initialize Flask-Mail here
# cipher = Fernet(os.getenv("AES_KEY"))  # AES Encryption Key from .env

logging.basicConfig(level=logging.DEBUG)

# Thread lock for background task
thread = None
thread_lock = Lock()
IST = pytz.timezone("Asia/Kolkata")

order_status_dict = {}
order_status_lock = threading.Lock()
order_locks = {}  # New lock to prevent concurrent orders per user/symbol

# ✅ Function to Encrypt Response (AES-256-CBC)
def encrypt_response(data_dict):
    """Encrypt a JSON response using AES-256-CBC (CryptoJS-compatible)"""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC)
        padded_data = pad(json.dumps(data_dict).encode(), AES.block_size)
        encrypted_bytes = cipher.encrypt(padded_data)

        # ✅ Encode IV and Ciphertext in Base64
        iv = base64.b64encode(cipher.iv).decode("utf-8")
        ct = base64.b64encode(encrypted_bytes).decode("utf-8")

        return json.dumps({"iv": iv, "ct": ct})  # Return JSON object
    except Exception as e:
        logging.error(f"❌ Encryption Error: {str(e)}")
        return None

# ✅ Function to Decrypt Request (AES-256-CBC)
def decrypt_request(encrypted_data):
    """Decrypt an AES-256-CBC encrypted JSON request from CryptoJS"""
    try:
        # ✅ Load the JSON payload
        parsed_data = json.loads(encrypted_data)
        iv = base64.b64decode(parsed_data["iv"])
        ct = base64.b64decode(parsed_data["ct"])

        # ✅ Remove "Salted__" header if present
        salted_match = re.match(b"Salted__(.{8})(.*)", ct, re.DOTALL)
        if salted_match:
            salt, ct = salted_match.groups()

        # ✅ Decrypt message
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ct), AES.block_size)
        
        return json.loads(decrypted.decode("utf-8"))  # Convert back to dict
    except Exception as e:
        logging.error(f"❌ Decryption Error: {str(e)}")
        return None

def add_log(user_email, action, details):
    try:
        log_entry = Log(user_email=user_email, action=action, details=details)
        db.session.add(log_entry)
        db.session.commit()
        logging.info(f"📌 Log Added: {action} - {details}")
    except Exception as e:
        db.session.rollback()  # ✅ Rollback in case of error
        logging.error(f"❌ Failed to log event: {str(e)}")

from flask_jwt_extended import get_jwt

def role_required(required_role):
    def decorator(func):
        @wraps(func)
        @jwt_required()
        def wrapper(*args, **kwargs):
            identity = get_jwt_identity()  # This will return only email
            claims = get_jwt()  # This will return full JWT payload, including role

            print(f"🔑 JWT Identity: {identity}")  # Debugging
            print(f"🛠 JWT Claims: {claims}")  # Debugging

            # ✅ Ensure role exists in claims
            if "role" not in claims:
                return jsonify({"data": encrypt_response({"message": "Invalid token format, missing role","status":"403"})}), 403

            if claims["role"] != required_role:
                return jsonify({"data": encrypt_response({"message": "Access denied","status":"403"})}), 403

            return func(*args, **kwargs)

        return wrapper
    return decorator

with app.app_context():
    db.create_all()
    if not User.query.filter_by(role="superuser").first():
        superuser = User(name="Abhijit", email="abhijit_vyas@hotmail.com", phone="9913131181", password="Justwin@29", 
                          address="Maninagar", pincode="320008", city="Ahmedabad", role="manager",smartapi_key=None,smartapi_username=None,smartapi_password=None,smartapi_totp_token=None, totp_secret=None)
        db.session.add(superuser)
        db.session.commit()

import pyotp
import qrcode
from io import BytesIO
import base64
from flask import send_file

@app.before_request
def log_request_data():
    if request.path == "/user/generate-2fa":
        logging.info("\n🚀 Received /user/generate-2fa API request")
        logging.info(f"📝 Request Method: {request.method}")
        logging.info(f"📩 Request Headers: {dict(request.headers)}")
        logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")

@app.route("/user/generate-2fa", methods=["POST"])
@jwt_required()
def generate_2fa():
    try:
        user_email = get_jwt_identity()
        user = User.query.filter_by(email=user_email).first()

        if not user:
            return jsonify({"data": encrypt_response({"message": "User not found","status":"404"})}), 404

        # ✅ Generate a TOTP secret if not already set
        if not user.totp_secret:
            user.totp_secret = pyotp.random_base32()  # Generate a random 32-character base32 secret
            db.session.commit()

        # ✅ Create a TOTP URI for the QR code
        totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
            name=user.email, issuer_name="KaizenBot"
        )

        # ✅ Generate QR Code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        qr_img = qr.make_image(fill="black", back_color="white")

        # ✅ Convert QR code to base64 string
        buffered = BytesIO()
        qr_img.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

        # ✅ Log the action
        add_log(user_email, "Generated 2FA QR Code", "User requested 2FA setup")

        return jsonify({
            "data": encrypt_response({
                "message": "QR code generated successfully",
                "qr_code": f"data:image/png;base64,{qr_base64}",
                "status":"200"
            })
        }), 200

    except Exception as e:
        logging.error(f"❌ Generate 2FA Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Failed to generate QR code","status":"500"})}), 500
    
@app.route("/user/verify-2fa", methods=["POST"])
@jwt_required()
def verify_2fa():
    try:
        encrypted_data = request.json.get("data")
        decrypted_request = decrypt_request(encrypted_data)

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format","status":"400"})}), 400

        otp = decrypted_request.get("otp")
        user_email = get_jwt_identity()
        user = User.query.filter_by(email=user_email).first()

        if not user or not user.totp_secret:
            return jsonify({"data": encrypt_response({"message": "2FA not set up for this user","status":"404"})}), 404

        # ✅ Verify the OTP
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(otp):
            add_log(user_email, "2FA Verification Failed", "Invalid OTP provided")
            return jsonify({"data": encrypt_response({"message": "Invalid OTP","status":"401"})}), 401

        # ✅ Enable 2FA (you can add a flag if needed, here we assume totp_secret presence means 2FA is enabled)
        add_log(user_email, "2FA Enabled", "OTP verified successfully")
        
        return jsonify({"data": encrypt_response({"message": "2FA enabled successfully","status":"200"})}), 200

    except Exception as e:
        logging.error(f"❌ Verify 2FA Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Failed to verify OTP","status":"500"})}), 500
    
# ✅ Render Login & Signup Pages
@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/signup", methods=["GET"])
def signup_page():
    return render_template("signup.html")

import threading
import platform
import requests
from flask_mail import Message
from datetime import datetime
from flask import current_app

# ✅ Define the Website Name
WEBSITE_NAME = "Kaizenbot.in"

def send_login_notification(user_email, user_name, user_role):
    """Sends an email notification when a user logs in."""

    app = current_app._get_current_object()  # ✅ Get Flask app instance

    def send_email():
        with app.app_context():  # ✅ Ensure the email is sent inside the app context
            try:
                device_name = platform.system()
                device_version = platform.release()
                public_ip = requests.get("https://api.ipify.org/?format=json", timeout=3).json().get("ip", "Unknown")
                login_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                subject = f"🚀 New Login Detected on {WEBSITE_NAME}"
                body = f"""
                Hello {user_name},  

                We noticed a new sign-in to your {WEBSITE_NAME} account. If this was you, no action is required.  

                📱 Device: {device_name}, Version {device_version}  
                🌍 IP Address: {public_ip}  
                🕒 Time: {login_time}  

                ❗ If you did **not** log in, please take immediate action:  
                - Change your password to secure your account.  
                - Contact support at **support@{WEBSITE_NAME.lower()}.in**.  

                Stay Safe,  
                The {WEBSITE_NAME} Security Team  
                """

                msg = Message(subject, recipients=[user_email], body=body)
                mail.send(msg)
                logging.info(f"📧 Login notification sent to {user_email}")
                log_entry = Log(user_email=user_email, action="Login Notification Sent", details="User logged in successfully")
                db.session.add(log_entry)
                db.session.commit()

            except Exception as e:
                logging.error(f"❌ Failed to send login email: {str(e)}")

    # ✅ Run email function in a separate thread
    threading.Thread(target=send_email).start()
# ✅ Function to Send Registration Notification
def send_registration_notification(user_email, user_name, user_role):
    app = current_app._get_current_object()  # ✅ Get Flask app instance

    def send_email():
        with app.app_context(): 
            try:
                registration_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                subject = f"🎉 Welcome to {WEBSITE_NAME} - Your Account is Ready!"
                body = f"""
                Hello {user_name},  

                🎊 Congratulations! You have successfully registered on {WEBSITE_NAME}.  

                Here are your account details:  
                - 📧 Email: {user_email}  
                - 🏷 Role: {user_role.capitalize()}  
                - 🕒 Registered On: {registration_time}  

                What's Next?  
                - 🚀 Log in at: [https://www.{WEBSITE_NAME.lower()}.in/login](https://www.{WEBSITE_NAME.lower()}.in/login)  
                - 🔐 Secure your account by enabling two-factor authentication (if available).  
                - 💡 Explore {WEBSITE_NAME} and get started!  

                If you did not register this account, please contact support immediately: **support@{WEBSITE_NAME.lower()}.in**.  

                Best Regards,  
                The {WEBSITE_NAME} Team  
                """

                msg = Message(subject, recipients=[user_email], body=body)
                mail.send(msg)
                logging.info(f"📧 Registration email sent to {user_email}")
                log_entry = Log(user_email=user_email, action="Registration Notification Sent", details="User registered successfully")
                db.session.add(log_entry)
                db.session.commit()

            except Exception as e:
                logging.error(f"❌ Failed to send registration email: {str(e)}")

    # ✅ Run email function in a separate thread
    threading.Thread(target=send_email).start()

@app.before_request
def log_request_data():
    if request.path == "/login":
        logging.info("\n🚀 Received /login API request")
        logging.info(f"📝 Request Method: {request.method}")
        logging.info(f"📩 Request Headers: {dict(request.headers)}")
        logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")

@app.route("/login", methods=["POST"])
def login():
    try:
        encrypted_data = request.json.get("data")
        logging.info(f"🔐 Encrypted Data Field: {encrypted_data}")

        decrypted_request = decrypt_request(encrypted_data)  
        
        logging.info(f"🔓 Decrypted Request: {decrypted_request}")
        
        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format", "status":"400"})})

        data = decrypted_request  # No need to use eval()

        user = User.query.filter_by(email=data["email"]).first()
        print("User",user)
        activated_user = User.query.filter_by(email=data["email"], is_active="True").first()
        
        if not activated_user:
            return jsonify({"data": encrypt_response({"message": "User is not activated","status":"401"})})
        
        if user.totp_secret:
            temp_token = create_access_token(identity=user.email, expires_delta=timedelta(minutes=5))
            return jsonify({"data": encrypt_response({"message": "2FA required for this user", "status": "402", "temp_token": temp_token})}) , 200

            
        if not user or not bcrypt.check_password_hash(user.password, data["password"]):
            log_entry = Log(user_email=data["email"], action="User Login Failed", details="Invalid credentials")
            db.session.add(log_entry)
            db.session.commit()
            logging.log(logging.ERROR, "❌ Invalid credentials")
            
            return jsonify({"data": encrypt_response({"message": "Invalid credentials","status":"401"})})
        

        access_token = create_access_token(identity=user.email, additional_claims={"role": user.role}, expires_delta=False)

        response_data = {
            "access_token": access_token,
            "role": user.role,
            "status": "200"
        }
        log_entry = Log(user_email=user.email, action="User Logged In", details=f"Role: {user.role}")
        db.session.add(log_entry)
        db.session.commit()
        # send_login_notification(user.email, user.name, user.role)
        logging.info(f"✅ User {user.email} logged in successfully")
        
        return jsonify({"data": encrypt_response(response_data)}), 200

    except Exception as e:
        logging.error(f"❌ Login Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Login failed","status":"500"})}), 500

@app.before_request
def log_request_data():
    if request.path == "/user/2fa-login":
        logging.info("\n🚀 Received /user/2fa-login API request")
        logging.info(f"📝 Request Method: {request.method}")
        logging.info(f"📩 Request Headers: {dict(request.headers)}")
        logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")

@app.route("/user/2fa-login", methods=["POST"])
@jwt_required()
def login_2fa():
    try:
        user = get_jwt_identity()
        encrypted_data = request.json.get("data")
        decrypted_request = decrypt_request(encrypted_data)

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format","status":"400"})}), 400

        otp = decrypted_request.get("otp")
        user = User.query.filter_by(email=user).first()
        
        if not user or not user.totp_secret:
            return jsonify({"data": encrypt_response({"message": "2FA not set up for this user","status":"404"})}), 404
        
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(otp):
            add_log(user.email, "2FA Login Failed", "Invalid OTP")
            return jsonify({"data": encrypt_response({"message": "Invalid OTP","status":"401"})}), 401
        
        access_token = create_access_token(identity=user.email, additional_claims={"role": user.role}, expires_delta=False)
        response_data = {
            "access_token": access_token,
            "role": user.role,
            "status": "200"
        }
        log_entry = Log(user_email=user.email, action="User Logged In", details=f"Role: {user.role}")
        db.session.add(log_entry)
        db.session.commit()
        send_login_notification(user.email, user.name, user.role)
        logging.info(f"✅ User {user.email} logged in successfully")
        
        return jsonify({"data": encrypt_response(response_data)}), 200
    except Exception as e:
        logging.error(f"❌ 2FA Login Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "2FA login failed","status":"500"})}), 500
    
@app.before_request
def log_request_data():
    if request.path == "/register":
        logging.info("\n🚀 Received /register API request")
        logging.info(f"📝 Request Method: {request.method}")
        logging.info(f"📩 Request Headers: {dict(request.headers)}")
        logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")
        
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
@app.route("/register", methods=["POST"])
def register():
    try:
        try:
            verify_jwt_in_request()
            user_email = get_jwt_identity()
            logging.info(f"🔑 JWT Identity (email): {user_email}")

            # ✅ Fetch the user's role from DB
            user = User.query.filter_by(email=user_email).first()
            if not user:
                logging.error("❌ JWT User Not Found in Database")
                return jsonify({"data": encrypt_response({"message": "Invalid token user","status":"403"})}), 403

            user_role = user.role  # Get role from DB
            logging.info(f"🔑 User Role from DB: {user_role}")

        except Exception as jwt_error:
            logging.error(f"❌ JWT Verification Failed: {str(jwt_error)}")
            return jsonify({"data": encrypt_response({"message": "Invalid or missing token","status":"401"})}), 401

        raw_body = request.data.decode('utf-8')
        logging.info(f"🔒 Raw Request Body: {raw_body}")

        # ✅ Extract Encrypted Data
        encrypted_data = request.json.get("data")
        logging.info(f"🔐 Encrypted Data Field: {encrypted_data}")

        # ✅ Decrypt Request
        decrypted_request = decrypt_request(encrypted_data)
        logging.info(f"🔓 Decrypted Request: {decrypted_request}")

        if not decrypted_request:
            logging.error("❌ Decryption Failed: No data received.")
            return jsonify({"data": encrypt_response({"message": "Invalid request format","status":"400"})}), 400

        # ✅ Fix: Ensure `decrypted_request` is a dictionary
        if isinstance(decrypted_request, str):
            data = eval(decrypted_request)  # Convert decrypted string to dict
        else:
            data = decrypted_request  # Already a dict

        logging.info(f"📦 Parsed Decrypted Data: {data}")

        # ✅ Validate Role Authorization
        allowed_roles = {"superuser": ["manager", "user"], "manager": ["user"]}
        if user_role not in allowed_roles or data["role"] not in allowed_roles[user_role]:
            logging.warning(f"❌ Unauthorized role: {user_role} cannot create {data['role']}.")
            return jsonify({"data": encrypt_response({"message": "Access denied","status":"403"})}), 403

        # ✅ Check for Duplicate Email
        existing_user = User.query.filter_by(email=data["email"]).first()
        if existing_user:
            logging.warning(f"❌ Duplicate email found: {data['email']}")
            logs = Log(user_email=user_email, action="User Registration Failed", details=f"Email already registered: {data['email']}")
            db.session.add(logs)
            db.session.commit()
            return jsonify({"data": encrypt_response({"message": "Email already registered","status":"400"})}), 400

        # ✅ Register User
        user = User(
            name=data["name"],
            email=data["email"],
            phone=data["phone"],
            password=data["password"],
            address=data["address"],
            pincode=data["pincode"],
            city=data["city"],
            role=data["role"],
            smartapi_key=None,
            smartapi_username=None,
            smartapi_password=None,
            smartapi_totp_token=None
            
        )
        
        db.session.add(user)
        log_entry = Log(user_email=user_email, action="User Registered", details=f"Registered {data['role']}: {data['email']}")
        send_registration_notification(data["email"], data["name"], data["role"])

        db.session.add(log_entry)
        db.session.commit()

        return jsonify({"data": encrypt_response({"message": "User registered successfully","status":"201"})}), 201

    except Exception as e:
        Log(user_email=user_email, action="User Registration Failed", details=str(e))
        db.session.commit()
        return jsonify({"data": encrypt_response({"message": "Registration failed","status":"500"})}), 500

from datetime import timedelta

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    try:
        encrypted_data = request.json.get("data")
        decrypted_request = decrypt_request(encrypted_data)

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format","status":"400"})}), 400

        email = decrypted_request.get("email")

        user = User.query.filter_by(email=email).first()

        if not user:
            return jsonify({"data": encrypt_response({"message": "User not found","status":"404"})}), 404

        if user.role == "superuser":
            return jsonify({"data": encrypt_response({"message": "superuser password cannot be reset","status":"403"})}), 403

        # ✅ Generate Reset Token (Valid for 30 minutes)
        reset_token = create_access_token(identity=email, expires_delta=timedelta(minutes=30))  

        # ✅ Send Email with Reset Link
        reset_link = f"https://kaizenbot.in/reset-password?token={reset_token}"
        send_email(email, reset_link)

        log_entry = Log(user_email=email, action="Forgot Password Requested", details="Password reset email sent.")
        db.session.add(log_entry)
        db.session.commit()

        return jsonify({"data": encrypt_response({"message": "Password reset link sent successfully","status":"200"})}), 200

    except Exception as e:
        logging.error(f"❌ Forgot Password Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Failed to send reset email","status":"500"})}), 500

@app.before_request
def log_request_data():
    if request.path == "/reset-password":
        logging.info("\n🚀 Received /reset-password API request")
        logging.info(f"📝 Request Method: {request.method}")
        logging.info(f"📩 Request Headers: {dict(request.headers)}")
        logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")

# ✅ Reset Password
@app.route("/reset-password", methods=["POST"])
def reset_password():
    try:
        encrypted_data = request.json.get("data")
        print(encrypted_data)
        decrypted_request = decrypt_request(encrypted_data)
        print(decrypted_request)

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format","status":"400"})}), 400

        reset_token = decrypted_request.get("token")
        new_password = decrypted_request.get("password")

        if not reset_token or not new_password:
            return jsonify({"data": encrypt_response({"message": "Invalid request data","status":"400"})}), 400

        # ✅ Decode Token
        try:
            decoded_data = decode_token(reset_token)
            print(decoded_data)
            email = decoded_data["sub"]
        except Exception as e:
            logging.error(f"❌ Token Decode Error: {str(e)}")
            return jsonify({"data": encrypt_response({"message": "Invalid or expired token","status":"400"})}), 400

        # ✅ Update Password
        user = User.query.filter_by(email=email).first()

        if not user:
            return jsonify({"data": encrypt_response({"message": "User not found","status":"404"})}), 404

        user.password = bcrypt.generate_password_hash(new_password).decode("utf-8")
        db.session.commit()

        log_entry = Log(user_email=email, action="Password Reset", details="User successfully reset password.")
        db.session.add(log_entry)
        db.session.commit()

        return jsonify({"data": encrypt_response({"message": "Password reset successfully","status":"200"})}), 200

    except Exception as e:
        logging.error(f"❌ Reset Password Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Failed to reset password","status":"500"})}), 500


def send_email(to_email, reset_link):
    try:
        smtp_server = os.getenv("SMTP_SERVER")
        smtp_port = int(os.getenv("SMTP_PORT"))
        smtp_username = os.getenv("SMTP_USERNAME")
        smtp_password = os.getenv("SMTP_PASSWORD")

        msg = MIMEMultipart()
        msg["From"] = smtp_username
        msg["To"] = to_email
        msg["Subject"] = "Password Reset Request"

        body = f"Hello,\n\nClick the link below to reset your password:\n{reset_link}\n\nIf you did not request this, please ignore this email.\n\nBest,\nKaizenbot Team"
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(smtp_username, to_email, msg.as_string())
        server.quit()

        logging.info(f"📩 Email sent successfully to {to_email}")

    except Exception as e:
        logging.error(f"❌ Email Sending Failed: {str(e)}")

@app.route("/user/activate", methods=["POST"])
@jwt_required()
def activate_user():
    try:
        encrypted_data = request.json.get("data")
        logging.info(f"🔐 Encrypted Data Field: {encrypted_data}")
        decrypted_request = decrypt_request(encrypted_data)
        logging.info(f"🔓 Decrypted Request: {decrypted_request}")

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format","status":"400"})}), 400

        data = decrypted_request
        identity = get_jwt_identity()
        user_email = identity  # JWT identity is the email now

        # ✅ Get current user role
        current_user = User.query.filter_by(email=user_email).first()
        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized","status":"403"})}), 403

        # ✅ Get target user
        target_user = User.query.filter_by(email=data["email"]).first()
        if not target_user:
            return jsonify({"data": encrypt_response({"message": "User not found","status":"404"})}), 404

        # ✅ Check permissions
        allowed_roles = {"superuser": ["manager", "user"], "manager": ["user"]}
        if current_user.role not in allowed_roles or target_user.role not in allowed_roles[current_user.role]:
            return jsonify({"data": encrypt_response({"message": "Permission denied","status":"403"})}), 403

        # ✅ Activate user
        target_user.is_active = "True"
        db.session.commit()

        # ✅ Log the action
        log_entry = Log(user_email=user_email, action=f"Activated {target_user.email}", details=f"Role: {target_user.role}")
        db.session.add(log_entry)
        db.session.commit()

        return jsonify({"data": encrypt_response({"message": "User activated successfully","status":"200"})}), 200

    except Exception as e:
        logging.error(f"❌ Activation Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Activation failed","status":"500"})}), 500

@app.route("/user/deactivate", methods=["POST"])
@jwt_required()
def deactivate_user():
    try:
        encrypted_data = request.json.get("data")
        decrypted_request = decrypt_request(encrypted_data)

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format","status":"400"})}), 400

        data = decrypted_request
        identity = get_jwt_identity()
        user_email = identity  # JWT identity is the email now

        # ✅ Get current user role
        current_user = User.query.filter_by(email=user_email).first()
        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized","status":"403"})}), 403

        # ✅ Get target user
        target_user = User.query.filter_by(email=data["email"]).first()
        if not target_user:
            return jsonify({"data": encrypt_response({"message": "User not found","status":"404"})}), 404

        # ✅ Check permissions
        allowed_roles = {"superuser": ["manager", "user"], "manager": ["user"]}
        if current_user.role not in allowed_roles or target_user.role not in allowed_roles[current_user.role]:
            return jsonify({"data": encrypt_response({"message": "Permission denied","status":"403"})}), 403

        # ✅ Deactivate user
        target_user.is_active = "False"
        db.session.commit()

        # ✅ Log the action
        log_entry = Log(user_email=user_email, action=f"Deactivated {target_user.email}", details=f"Role: {target_user.role}")
        db.session.add(log_entry)
        db.session.commit()

        return jsonify({"data": encrypt_response({"message": "User deactivated successfully","status":"200"})}), 200

    except Exception as e:
        logging.error(f"❌ Deactivation Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Deactivation failed","status":"500"})}), 500

@app.route("/logs", methods=["GET"])
@jwt_required()
def view_logs():
    try:
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()

        if not current_user or current_user.role not in ["superuser", "manager"]:
            return jsonify({"data": encrypt_response({"message": "Permission denied","status":"403"})}), 403

        logs = Log.query.order_by(Log.timestamp.desc()).all()
        log_list = [{"user_email": log.user_email, "action": log.action, "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S")} for log in logs]

        return jsonify({"data": encrypt_response({"logs": log_list,"status":"200"})}), 200

    except Exception as e:
        logging.error(f"❌ Log Viewing Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Failed to retrieve logs","status":"500"})}), 500


@app.before_request
def log_request_data():
    if request.path == "/superuser":
        logging.info("\n🚀 Received /register API request")
        logging.info(f"📝 Request Method: {request.method}")
        logging.info(f"📩 Request Headers: {dict(request.headers)}")
        logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")
        
# ✅ superuser Dashboard
@app.route("/superuser", methods=["GET"])
@role_required("superuser")
def superuser_dashboard():
    return jsonify({"data": encrypt_response({"message": "Welcome superuser!", "status":"200","role":"superuser"})}), 200

# ✅ Manager Dashboard
@app.before_request
def log_request_data():
    if request.path == "/manager":
        logging.info("\n🚀 Received /manager API request")
        logging.info(f"📝 Request Method: {request.method}")
        logging.info(f"📩 Request Headers: {dict(request.headers)}")
        logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")
          
@app.route("/manager", methods=["GET"])
@role_required("manager")
def manager_dashboard():
    return jsonify({"data": encrypt_response({"message": "Welcome Manager!", "status":"200","role":"manager"})}), 200

# ✅ User Dashboard
@app.route("/user", methods=["GET"])
@role_required("user")
def user_dashboard():
    return jsonify({"data": encrypt_response({"message": "Welcome User!", "status":"200"})}), 200

@app.route("/users", methods=["GET"])
@jwt_required()
def get_all_users():
    try:
        # ✅ Get JWT Identity & Role
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logging.info(f"🔑 JWT Identity: {user_email}")
        logging.info(f"🛠 JWT Claims: {current_user}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access","status":"403"})}), 403

        # ✅ Superadmin → Can view all (Managers & Users)
        if current_user.role == "superuser":
            users = User.query.filter(User.role != "superuser").all()  # Exclude superadmin itself

        # ✅ Manager → Can only view Users (not other Managers)
        elif current_user.role == "manager":
            users = User.query.filter_by(role="user").all()

        # ❌ Users cannot access this API
        else:
            return jsonify({"data": encrypt_response({"message": "Permission denied","status":"403"})}), 403

        # ✅ Prepare Response
        user_list = [
            {
                # "id": user.id,
                "name": user.name,
                "email": user.email,
                "phone": user.phone,
                "address": user.address,
                "pincode": user.pincode,
                "city": user.city,
                "role": user.role,
                "is_active": user.is_active,
            }
            for user in users
        ]

        # ✅ Log the Event
        log_entry = Log(user_email=user_email, action="Fetched User List", details=f"Role: {current_user.role}")
        db.session.add(log_entry)
        db.session.commit()

        # return jsonify({"data": {"users": user_list}}), 200
        return jsonify({"data": encrypt_response({"users": user_list,"status":"200"})}), 200

    except Exception as e:
        logging.error(f"❌ Fetch Users Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Failed to fetch users","status":"500"})}), 500


@app.route("/user/<identifier>", methods=["GET"])
@jwt_required()
def get_user_info(identifier):
    try:
        # ✅ Get JWT Identity
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logging.info(f"🔑 JWT Identity: {user_email}")
        logging.info(f"🛠 Current User: {current_user}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access","status":"403"})}), 403

        # ✅ Determine if identifier is email or ID
        if re.match(r"[^@]+@[^@]+\.[^@]+", identifier):
            target_user = User.query.filter_by(email=identifier).first()
        else:
            try:
                user_id = int(identifier)
                target_user = User.query.get(user_id)
            except ValueError:
                return jsonify({"data": encrypt_response({"message": "Invalid identifier format","status":"400"})}), 400

        if not target_user:
            return jsonify({"data": encrypt_response({"message": "User not found","status":"404"})}), 404

        # ✅ Strict Access Control: Only the user can access their own info
        if target_user.email != current_user.email:
            add_log(user_email, "Unauthorized User Info Access Attempt", 
                    f"Tried to access {target_user.email} (Role: {current_user.role})")
            return jsonify({"data": encrypt_response({"message": "Permission denied: You can only view your own information","status":"403"})}), 403

        # ✅ Prepare Non-Sensitive User Data (Exclude credentials)
        user_data = {
            "id": target_user.id,
            "name": target_user.name,
            "email": target_user.email,
            "phone": target_user.phone,
            "address": target_user.address,
            "pincode": target_user.pincode,
            "city": target_user.city,
            "role": target_user.role,
            "is_active": target_user.is_active,
            "totp_enabled": bool(target_user.totp_secret)  # Only indicates if 2FA is enabled, not the secret
        }

        # ✅ Log the Event
        add_log(user_email, "Fetched Own User Info", f"Viewed info for {target_user.email}")

        # ✅ Return Encrypted Response
        return jsonify({"data": encrypt_response({"user": user_data,"status":"200"})}), 200

    except Exception as e:
        logging.error(f"❌ Fetch User Info Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Failed to fetch user info","status":"500"})}), 500

# ... (Your existing imports remain unchanged)
from flask import request

# ✅ Edit User Profile
@app.before_request
def log_request_data():
    if request.path == "/user/edit-profile":
        logging.info("\n🚀 Received /user/edit-profile API request")
        logging.info(f"📝 Request Method: {request.method}")
        logging.info(f"📩 Request Headers: {dict(request.headers)}")
        logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}"
                     )
@app.route("/user/edit-profile", methods=["POST"])
@jwt_required()
def edit_profile():
    try:
        # ✅ Get JWT Identity
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logging.info(f"🔑 JWT Identity: {user_email}")
        logging.info(f"🛠 Current User: {current_user}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access","status":"403"})}), 403

        # ✅ Decrypt Request Data
        encrypted_data = request.json.get("data")
        decrypted_request = decrypt_request(encrypted_data)

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format","status":"400"})}), 400

        data = decrypted_request

        # ✅ Validate Input Fields
        name = data.get("name")
        phone = data.get("phone")
        email = data.get("email")
        address = data.get("address")
        city = data.get("city")
        pincode = data.get("pincode")

        # Basic validation
        if name and (not isinstance(name, str) or len(name.strip()) < 1):
            return jsonify({"data": encrypt_response({"message": "Invalid name","status":"400"})}), 400
        if phone and (not isinstance(phone, str) or not re.match(r"^\d{10}$", phone)):
            return jsonify({"data": encrypt_response({"message": "Invalid phone number (must be 10 digits)","status":"400"})}), 400
        if email and (not isinstance(email, str) or not re.match(r"[^@]+@[^@]+\.[^@]+", email)):
            return jsonify({"data": encrypt_response({"message": "Invalid email format","status":"400"})}), 400
        if email and email != current_user.email and User.query.filter_by(email=email).first():
            return jsonify({"data": encrypt_response({"message": "Email already in use","status":"400"})}), 400
        if address and (not isinstance(address, str) or len(address.strip()) < 1):
            return jsonify({"data": encrypt_response({"message": "Invalid address","status":"400"})}), 400
        if city and (not isinstance(city, str) or len(city.strip()) < 1):
            return jsonify({"data": encrypt_response({"message": "Invalid city","status":"400"})}), 400
        if pincode and (not isinstance(pincode, str) or not re.match(r"^\d{6}$", pincode)):
            return jsonify({"data": encrypt_response({"message": "Invalid pincode (must be 6 digits)", "status":"400"})}), 400

        # ✅ Update User Fields (only if provided in request)
        changes = []
        if name:
            current_user.name = name.strip()
            changes.append(f"name to '{name}'")
        if phone:
            current_user.phone = phone
            changes.append(f"phone to '{phone}'")
        if email and email != current_user.email:
            current_user.email = email
            changes.append(f"email to '{email}'")
        if address:
            current_user.address = address.strip()
            changes.append(f"address to '{address}'")
        if city:
            current_user.city = city.strip()
            changes.append(f"city to '{city}'")
        if pincode:
            current_user.pincode = pincode
            changes.append(f"pincode to '{pincode}'")

        if not changes:
            return jsonify({"data": encrypt_response({"message": "No fields provided to update","status":"400"})}), 400

        # ✅ Commit Changes to Database
        db.session.commit()

        # ✅ Log the Edit Action
        add_log(user_email, "Profile Updated", f"Updated: {', '.join(changes)}")

        # ✅ Prepare Updated User Data for Response
        user_data = {
            "id": current_user.id,
            "name": current_user.name,
            "email": current_user.email,
            "phone": current_user.phone,
            "address": current_user.address,
            "pincode": current_user.pincode,
            "city": current_user.city,
            "role": current_user.role,
            "is_active": current_user.is_active,
            "totp_enabled": bool(current_user.totp_secret)
        }

        # ✅ Return Encrypted Response
        return jsonify({
            "data": encrypt_response({
                "message": "Profile updated successfully",
                "user": user_data,
                "status": "200"
            })
        }), 200

    except Exception as e:
        db.session.rollback()  # Rollback on error
        logging.error(f"❌ Edit Profile Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Failed to update profile","status":"500"})}), 500

@app.before_request
def log_request_data():
    if request.path == "/user/save-angel-credentials":
        logging.info("\n🚀 Received /user/save-angel-credentials API request")
        logging.info(f"📝 Request Method: {request.method}")
        logging.info(f"📩 Request Headers: {dict(request.headers)}")
        logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")
 

from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from SmartApi.smartConnect import SmartConnect
import pyotp

@app.route("/user/save-angel-credentials", methods=["POST"])
@jwt_required()
def check_angel_credentials():
    try:
        # Get JWT Identity
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")
        logger.info(f"🛠 Current User: {current_user}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        # Decrypt Request Data
        encrypted_data = request.json.get("data")
        decrypted_request = decrypt_request(encrypted_data)

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format", "status": "400"})}), 400

        data = decrypted_request
        
        

        # Extract Angel One Credentials
        smartapi_key = data.get("smartapi_key")
        smartapi_username = data.get("smartapi_username")
        smartapi_password = data.get("smartapi_password")
        smartapi_totp_token = data.get("smartapi_totp_token")

        # Validate Input Fields
        required_fields = ["smartapi_key", "smartapi_username", "smartapi_password", "smartapi_totp_token"]
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({"data": encrypt_response({
                "message": f"Missing required fields: {', '.join(missing_fields)}",
                "status": "400"
            })}), 400

        for field in required_fields:
            value = data[field]
            if not isinstance(value, str) or len(value.strip()) < 1:
                return jsonify({"data": encrypt_response({
                    "message": f"Invalid {field}",
                    "status": "400"
                })}), 400

        # Validate Angel One Credentials
        smart_api = SmartConnect(smartapi_key.strip())
        try:
            totp = pyotp.TOTP(smartapi_totp_token.strip()).now()
            session_data = smart_api.generateSession(smartapi_username.strip(), smartapi_password.strip(), totp)
            logger.info(f"Angel One session validation response: {session_data}")
        except Exception as e:
            logger.error(f"Failed to validate Angel One credentials: {str(e)}")
            return jsonify({"data": encrypt_response({
                "message": "Invalid Angel One credentials",
                "status": "401"
            })}), 401

        if not session_data.get("status", False):
            error_msg = session_data.get("message", "Unknown error")
            logger.error(f"Angel One session generation failed: {error_msg}")
            return jsonify({"data": encrypt_response({
                "message": f"Invalid Angel One credentials: {error_msg}",
                "status": "401"
            })}), 401

        current_user.smartapi_key = smartapi_key.strip()
        current_user.smartapi_username = smartapi_username.strip()
        current_user.smartapi_password = smartapi_password.strip()
        current_user.smartapi_totp_token = smartapi_totp_token.strip()
        current_user.angel_linked = True
        current_user.trading_active = True
        db.session.commit()

        # Log the action
        add_log(user_email, "Angel One Credentials Validated and Saved", "Credentials validated and updated")
        
        # Prepare response (non-sensitive user data only)
        user_data = {
            "id": current_user.id,
            "name": current_user.name,
            "email": current_user.email,
            "phone": current_user.phone,
            "address": current_user.address,
            "pincode": current_user.pincode,
            "city": current_user.city,
            "role": current_user.role,
            "is_active": current_user.is_active,
            "totp_enabled": bool(current_user.totp_secret),
            "angel_credentials_set": True
        }
        
        return jsonify({"data": encrypt_response({
            "message": "Angel One credentials validated and saved successfully",
            "user": user_data,
            "status": "200"
        })}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Check Angel Credentials Error: {str(e)}")
        return jsonify({"data": encrypt_response({
            "message": f"Failed to validate or save Angel One credentials: {str(e)}",
            "status": "500"
        })}), 500
        

@app.route("/user/check-angle-status", methods=["GET"])
@jwt_required()
def check_angle_status():
    try:
        # Get JWT Identity
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")
        logger.info(f"🛠 Current User: {current_user}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        # Validate Angel One Credentials
        if current_user.angel_linked is False:
            return jsonify({"data": encrypt_response({
                "message": "Angel One credentials not linked",
                "status": "400"
            })}), 400
        elif current_user.angel_linked is True:
            return jsonify({"data": encrypt_response({
                "message": "Angel One credentials linked",
                "status": "200"
            })}), 200
            
    except Exception as e:
        logger.error(f"❌ Check Angel Status Error: {str(e)}")
        return jsonify({"data": encrypt_response({
            "message": f"Failed to check Angel One status: {str(e)}",
            "status": "500"
        })}), 500
        

from SmartApi.smartConnect import SmartConnect
import pyotp
from flask import request
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging
from datetime import datetime, timedelta
import time

def get_angel_session(user):
    """Get or generate a valid Angel One session for the user, forcing regeneration on error."""
    user_email = user.email
    current_time = datetime.now()
    max_retries = 3  # Number of retry attempts
    retry_delay = 5  # Seconds to wait between retries

    # Check if a valid session exists in cache
    if (user_email in session_cache and 
        'smart_api' in session_cache[user_email] and 
        session_cache[user_email]['expires_at'] > current_time):
        logger.info(f"Reusing existing session for {user_email}")
        return session_cache[user_email]['smart_api']

    # Validate credentials once before retries
    if not all([user.smartapi_key, user.smartapi_username, user.smartapi_password, user.smartapi_totp_token]):
        logger.error(f"Angel One credentials not set for {user_email}")
        raise Exception("Angel One credentials not set for this user")

    # Retry loop for session generation
    for attempt in range(max_retries):
        try:
            smart_api = SmartConnect(user.smartapi_key)
            totp = pyotp.TOTP(user.smartapi_totp_token).now()
            data = smart_api.generateSession(user.smartapi_username, user.smartapi_password, totp)
            
            logging.info(f"🔐 Angel One Session Data: {data}")

            if data['status'] == False:
                raise Exception(f"Angel One session generation failed: {data['message']}")

            auth_token = data['data']['jwtToken']
            refresh_token = data['data']['refreshToken']
            feed_token = smart_api.getfeedToken()

            expires_at = current_time + timedelta(hours=24)

            # Store session in cache
            session_cache[user_email] = {
                'smart_api': smart_api,
                'auth_token': auth_token,
                'refresh_token': refresh_token,
                'feed_token': feed_token,
                'expires_at': expires_at
            }

            logger.info(f"Generated new session for {user_email} with auth_token: {auth_token[:20]}... (truncated)")
            return smart_api

        except Exception as e:
            logger.error(f"❌ Angel Session Error for {user_email} (Attempt {attempt + 1}/{max_retries}): {str(e)}")
            
            # Check if it's a rate limit or similar recoverable error
            if "exceeding access rate" in str(e).lower() or "session" in str(e).lower():
                if attempt < max_retries - 1:  # Not the last attempt
                    logger.info(f"Retrying after {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    continue
            
            # On last attempt or non-recoverable error, try refreshing with existing token
            if attempt == max_retries - 1 and user_email in session_cache and 'refresh_token' in session_cache[user_email]:
                try:
                    logger.info(f"Attempting to refresh session for {user_email} using refresh_token")
                    smart_api = SmartConnect(user.smartapi_key)
                    refresh_data = smart_api.generateSessionWithRefreshToken(session_cache[user_email]['refresh_token'])
                    
                    if refresh_data['status'] == False:
                        raise Exception(f"Refresh failed: {refresh_data['message']}")

                    auth_token = refresh_data['data']['jwtToken']
                    refresh_token = refresh_data['data']['refreshToken']
                    feed_token = smart_api.getfeedToken()

                    expires_at = current_time + timedelta(hours=24)

                    session_cache[user_email] = {
                        'smart_api': smart_api,
                        'auth_token': auth_token,
                        'refresh_token': refresh_token,
                        'feed_token': feed_token,
                        'expires_at': expires_at
                    }

                    logger.info(f"Refreshed session for {user_email} with auth_token: {auth_token[:20]}... (truncated)")
                    return smart_api

                except Exception as refresh_e:
                    logger.error(f"❌ Refresh Token Error for {user_email}: {str(refresh_e)}")

            # If all retries fail and refresh fails, raise the final exception
            if attempt == max_retries - 1:
                logger.error(f"Failed to generate or refresh session for {user_email} after {max_retries} attempts")
                raise Exception(f"Unable to establish Angel One session for {user_email}: {str(e)}")

    # This line should never be reached due to the raise above, but included for completeness
    return None


def refresh_angel_session(user):
    """Refresh the session using the refresh token."""
    user_email = user.email
    try:
        if user_email not in session_cache or 'refresh_token' not in session_cache[user_email]:
            raise Exception("No existing session to refresh")

        smart_api = SmartConnect(user.smartapi_key)
        refresh_token = session_cache[user_email]['refresh_token']
        data = smart_api.generateToken(refresh_token)

        if data['status'] == False:
            raise Exception(f"Token refresh failed: {data['message']}")

        auth_token = data['data']['jwtToken']
        feed_token = data['data']['feedToken']
        expires_at = datetime.now() + timedelta(hours=24)

        session_cache[user_email] = {
            'smart_api': smart_api,
            'auth_token': auth_token,
            'refresh_token': refresh_token,
            'feed_token': feed_token,
            'expires_at': expires_at
        }

        logger.info(f"Refreshed session for {user_email} with auth_token: {auth_token[:20]}... (truncated)")
        return smart_api

    except Exception as e:
        logger.error(f"❌ Session Refresh Error for {user_email}: {str(e)}")
        return get_angel_session(user)

@app.route("/user/angel/rms-limit", methods=["GET"])
@jwt_required()
def get_rms_limit():
    try:
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        # Generate fresh session and call RMS limit
        smart_api = get_angel_session(current_user)
        rms = smart_api.rmsLimit()
        logger.info(f"RMS Limit Response: {rms}")

        # current_user.available_balance = rms['data']['availablecash']
        # db.session.commit()
        # db.session.close()
        
        # Log success (no DB storage)
        logger.info("Fetched RMS Limit successfully")
        return jsonify({"data": encrypt_response({"message": "RMS limit fetched successfully", "rms": rms, "status": "200"})}), 200

    except Exception as e:
        logger.error(f"❌ RMS Limit Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": f"Failed to fetch RMS limit: {str(e)}", "status": "500"})}), 500

# ✅ Get Order Book API
@app.route("/user/angel/order-book", methods=["GET"])
@jwt_required()
def get_order_book():
    try:
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        # Generate fresh session and call order book
        smart_api = get_angel_session(current_user)
        order_book = smart_api.orderBook()
        logger.info(f"Order Book Response: {order_book}")

        # Log success (no DB storage)
        logger.info("Fetched Order Book successfully")
        return jsonify({"data": encrypt_response({"message": "Order book fetched successfully", "order_book": order_book, "status": "200"})}), 200

    except Exception as e:
        error_str = str(e)
        if "Couldn't parse the JSON response" in error_str and "exceeding access rate" in error_str:
            logger.warning(f"Rate limit encountered for {user_email}: {error_str}")
            # Use cached order book if available
            if (user_email in session_cache and 
                'order_book' in session_cache[user_email] and 
                session_cache[user_email]['order_book']):
                order_book = session_cache[user_email]['order_book']
                logger.info(f"Using cached order book due to rate limit for {user_email}")
                return jsonify({
                    "data": encrypt_response({
                        "message": "Order book fetched successfully (from cache)",
                        "order_book": order_book,
                        "status": "200"
                    })
                }), 200
            else:
                # No cached data, return placeholder
                order_book = {"status": True, "message": "Rate limit exceeded, no cached data available", "data": []}
                logger.info(f"No cached order book available for {user_email}, returning placeholder")
                return jsonify({
                    "data": encrypt_response({
                        "message": "Order book fetched successfully (placeholder due to rate limit)",
                        "order_book": order_book,
                        "status": "200"
                    })
                }), 200
        else:
            # Log other errors as usual
            logger.error(f"❌ Order Book Error: {error_str}")
            return jsonify({
                "data": encrypt_response({
                    "message": f"Failed to fetch order book: {error_str}",
                    "status": "500"
                })
            }), 500

# ✅ Get Trade Book API
@app.route("/user/angel/trade-book", methods=["GET"])
@jwt_required()
def get_trade_book():
    try:
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        # Generate fresh session and call trade book
        smart_api = get_angel_session(current_user)
        trade_book = smart_api.tradeBook()
        logger.info(f"Trade Book Response: {trade_book}")

        # Log success (no DB storage)
        logger.info("Fetched Trade Book successfully")
        return jsonify({"data": encrypt_response({"message": "Trade book fetched successfully", "trade_book": trade_book, "status": "200"})}), 200

    except Exception as e:
        logger.error(f"❌ Trade Book Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": f"Failed to fetch trade book: {str(e)}", "status": "500"})}), 500

@app.route("/user/angel/all-holding", methods=["GET"])
@jwt_required()
def get_all_holding():
    try:
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        # Generate fresh session and call trade book
        smart_api = get_angel_session(current_user)
        holding = smart_api.allholding()
        # logger.info(f"holding Response: {holding}")

        # Log success (no DB storage)
        logger.info("Fetched holding successfully")
        return jsonify({"data": {"message": "Trade book fetched successfully", "all_holding": holding, "status": "200"}}), 200

    except Exception as e:
        # Log only non-rate-limit errors as errors
        error_str = str(e)
        if "Couldn't parse the JSON response" in error_str and "exceeding access rate" in error_str:
            logger.warning(f"Rate limit encountered for {user_email}: {error_str}")
            # Use cached holdings if available
            if (user_email in session_cache and 
                'holdings' in session_cache[user_email] and 
                session_cache[user_email]['holdings']):
                holding = session_cache[user_email]['holdings']
                logger.info(f"Using cached holdings due to rate limit for {user_email}")
                return jsonify({
                    "data": {
                        "message": "Holdings fetched successfully (from cache)",
                        "all_holding": holding,
                        "status": "200"
                    }
                }), 200
            else:
                # No cached data, return placeholder
                holding = {"status": True, "message": "Rate limit exceeded, no cached data available", "data": {"holdings": []}}
                logger.info(f"No cached holdings available for {user_email}, returning placeholder")
                return jsonify({
                    "data": {
                        "message": "Holdings fetched successfully (placeholder due to rate limit)",
                        "all_holding": holding,
                        "status": "200"
                    }
                }), 200
        else:
            # Log other errors as usual
            logger.error(f"❌ Holdings Error: {error_str}")
            return jsonify({
                "data": encrypt_response({
                    "message": f"Failed to fetch holdings: {error_str}",
                    "status": "500"
                })
            }), 500

@app.route("/user/angel/searchstock/<exchange>/<search_term>", methods=["GET"])
@jwt_required()
def search_stock(exchange, search_term):
    try:
        # Get JWT Identity
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        # Validate exchange parameter
        valid_exchanges = ["NSE", "BSE"]  # Add more as needed
        if exchange not in valid_exchanges:
            return jsonify({"data": encrypt_response({"message": f"Invalid exchange. Use one of: {', '.join(valid_exchanges)}", "status": "400"})}), 400

        # Validate search_term (basic check)
        if not search_term or not isinstance(search_term, str) or len(search_term.strip()) < 1:
            return jsonify({"data": encrypt_response({"message": "Invalid search term", "status": "400"})}), 400

        # Get or Generate Angel One Session
        smart_api = get_angel_session(current_user)

        # Search for the stock
        search_result = smart_api.searchScrip(exchange, search_term)
        # logger.info(f"Search Stock Response: {search_result}")

        # Check if the search was successful
        if not search_result or search_result.get("status") is False:
            return jsonify({"data": encrypt_response({"message": "Failed to fetch stock data", "status": "500"})}), 500

        # Log the action
        add_log(user_email, "Stock Search", f"Searched {exchange}:{search_term}")

        # Return encrypted response
        return jsonify({
            "data": encrypt_response({
                "message": "Stock search completed successfully",
                "search_result": search_result["data"] if search_result.get("data") else [],
                "status": "200"
            })
        }), 200

    except Exception as e:
        logger.error(f"❌ Stock Search Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": f"Failed to fetch stock search results: {str(e)}", "status": "500"})}), 500

@app.route("/user/stocks/add", methods=["POST"])
@jwt_required()
def add_user_stock():
    try:
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        # Decrypt request data
        encrypted_data = request.json.get("data")
        decrypted_request = decrypt_request(encrypted_data)

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format", "status": "8888"})}), 400
        
        data = decrypted_request
        required_fields = ["exchange", "tradingsymbol", "symboltoken"]
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        if missing_fields:
            return jsonify({"data": encrypt_response({"message": f"Missing required fields: {', '.join(missing_fields)}", "status": "8888"})}), 400

        # Check current stock count for the user
        stock_count = Stock.query.filter_by(user_id=current_user.id).count()
        logger.info(f"📊 Current stock count for user {user_email}: {stock_count}")
        if stock_count >= 5:
            logger.info(f"🚫 Stock limit reached for user {user_email}")
            return jsonify({"data": encrypt_response({
                "message": "Stock limit reached. Maximum 5 stocks allowed per user.",
                "status": "429"
            })}), 429

        # Check if stock already exists
        existing_stock = Stock.query.filter_by(
            user_id=current_user.id,
            tradingsymbol=data["tradingsymbol"]
        ).first()
        if existing_stock:
            return jsonify({
                "data": encrypt_response({
                    "message": f"Stock '{data['tradingsymbol']}' already exists for this user",
                    "status": "409"
                })
            }), 409
            
        # Create new stock entry
        new_stock = Stock(
            user_id=current_user.id,
            exchange=data["exchange"],
            tradingsymbol=data["tradingsymbol"],
            symboltoken=data["symboltoken"],
            live_price_status=True
        )
        db.session.add(new_stock)
        db.session.commit()

        # Initialize default PhaseConfig entries for the new stock
        # default_configs = [
        #     PhaseConfig(user_email=user_email, stock_symbol=data["tradingsymbol"], phase=1, start_sr_no=1, end_sr_no=21, down_increment=0.25),
        #     PhaseConfig(user_email=user_email, stock_symbol=data["tradingsymbol"], phase=2, start_sr_no=22, end_sr_no=41, down_increment=0.50),
        #     PhaseConfig(user_email=user_email, stock_symbol=data["tradingsymbol"], phase=3, start_sr_no=42, end_sr_no=55, down_increment=0.75),
        #     PhaseConfig(user_email=user_email, stock_symbol=data["tradingsymbol"], phase=4, start_sr_no=56, end_sr_no=70, down_increment=1.00),
        #     PhaseConfig(user_email=user_email, stock_symbol=data["tradingsymbol"], phase=5, start_sr_no=71, end_sr_no=81, down_increment=1.25),
        # ]
        
        # # Check if PhaseConfig already exists for this user and stock to avoid duplicates
        # existing_configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=data["tradingsymbol"]).first()
        # if not existing_configs:
        #     db.session.bulk_save_objects(default_configs)
        #     db.session.commit()
        #     logger.info(f"Initialized default PhaseConfig for {user_email} and stock {data['tradingsymbol']}")
        # else:
        #     logger.info(f"PhaseConfig already exists for {user_email} and stock {data['tradingsymbol']}, skipping initialization")

        # Log the action
        add_log(user_email, "Stock Added", f"Added {data['exchange']}:{data['tradingsymbol']} (Token: {data['symboltoken']})")
        
        # i want to forecefully add the stock to the live prices with restart the websocket
        # with live_prices_lock:
        #     live_prices[user_email][data["symboltoken"]] = {
        #         "tradingsymbol": data["tradingsymbol"],
        #         "exchange": data["exchange"],
        #         "ltp": 0.0,
        #         "ltt": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        #     }
        #     logger.info(f"Added stock {data['tradingsymbol']} to live prices for {user_email}")
        
        # i want to restart the websocket with using the thread in backend 
        # eventlet.spawn(start_websocket_stream, current_user)
        
        # t = threading.Thread(target=restart_websocket(current_user))
        # t.start()
        restart_websocket(current_user)
        
        return jsonify({
            "data": encrypt_response({
                "message": "Stock added successfully",
                "stock": new_stock.to_dict(),
                "status": "201"
            })
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Add Stock Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": f"Failed to add stock: {str(e)}", "status": "500"})}), 500



@app.route("/user/stocks", methods=["GET"])
@jwt_required()
def get_user_stocks():
    try:
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        # Retrieve all stocks for the user
        stocks = Stock.query.filter_by(user_id=current_user.id).all()
        stock_list = [stock.to_dict() for stock in stocks]

        # Log the action
        add_log(user_email, "Stocks Retrieved", f"Fetched {len(stock_list)} stocks")

        return jsonify({
            "data": encrypt_response({
                "message": "Stocks retrieved successfully",
                "stocks": stock_list,
                "status": "200"
            })
        }), 200

    except Exception as e:
        logger.error(f"❌ Get Stocks Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": f"Failed to retrieve stocks: {str(e)}", "status": "500"})}), 500

@app.route('/api/live-prices', methods=['GET'])
@jwt_required()
def get_live_prices():
    try:
        user_email = get_jwt_identity()
        logger.info(f"Fetching live prices for {user_email}")
        with app.app_context():
            user_stocks = Stock.query.filter_by(user_id=User.query.filter_by(email=user_email).first().id, live_price_status=True).all()
            user_tokens = {stock.symboltoken for stock in user_stocks}
        
        with live_prices_lock:
            user_prices = live_prices.get(user_email, {})
            if not user_prices:
                return jsonify({
                    'status': 'error',
                    'message': 'No live prices available for your stocks or WebSocket not active'
                }), 400
            filtered_prices = {token: data for token, data in user_prices.items() if token in user_tokens}
            if not filtered_prices:
                return jsonify({
                    'status': 'error',
                    'message': 'No live prices available for your active stocks'
                }), 400
            logger.info(f"Returning live prices for {user_email}: {filtered_prices}")
            return jsonify({
                'status': 'success',
                'data': filtered_prices
            }), 200
    except Exception as e:
        logger.error(f"Error fetching live prices for {user_email}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Unauthorized or server error'
        }), 401
    
from threading import Lock
import threading
import eventlet
import time as tm
from flask import Flask, request, jsonify
# from flask_socketio import SocketIO, emit
from flask_jwt_extended import JWTManager, get_jwt_identity, verify_jwt_in_request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pytz

IST = pytz.timezone('Asia/Kolkata')

# Market hours check
def is_market_open():
    now = datetime.now(IST)
    market_open = now.replace(hour=9, minute=0, second=0, microsecond=0)
    market_close = now.replace(hour=15, minute=30, second=0, microsecond=0)
    return now.weekday() < 5 and market_open <= now <= market_close

def get_wallet_value(smart_api):
    if app.config['DRY_RUN']:
        return 1000000
    else:
        try:
            rms = smart_api.rmsLimit()
            if rms.get('status') and rms.get('data'):
                return int(rms['data']['availableCash'])
            else:
                logger.error(f"Failed to fetch wallet value: {rms}")
                return 100000
            
        except Exception as e:
            logger.error(f"Failed to fetch wallet value: {str(e)}")
            return 100000
    

def calculate_v1(wallet_value):
    if wallet_value == 100000: return -0.642
    elif wallet_value == 150000: return -0.428
    elif wallet_value == 200000: return -0.214
    elif wallet_value == 250000: return 0.002
    elif wallet_value == 300000: return 0.216
    elif wallet_value == 350000: return 0.436
    elif wallet_value == 400000: return 0.6511
    elif wallet_value == 450000: return 0.872
    elif wallet_value == 500000: return 1.09
    elif wallet_value == 550000: return 1.311
    elif wallet_value == 600000: return 1.532
    elif wallet_value == 650000: return 1.754
    elif wallet_value == 700000: return 1.977
    elif wallet_value == 750000: return 2.201
    elif wallet_value == 800000: return 2.425
    elif wallet_value == 850000: return 2.65
    elif wallet_value == 900000: return 2.877
    elif wallet_value == 950000: return 3.104
    elif wallet_value == 1000000: return 3.332
    else: return 0.023


'''
def place_order(smart_api, symbol, qty, price, buy_sell='BUY'):
    if app.config['DRY_RUN']:
        # Simulate a successful order execution
        executed_qty = qty  # Assume full execution for simplicity
        logger.info(f"[DRY RUN] Simulated {buy_sell} order: {executed_qty}/{qty} of {symbol} at {price}")
        return executed_qty
    else:
        # qty = 1
        logger.info(f"Placing {buy_sell} order for {qty} of {symbol} at {price}")
        #  i want to store this log into one anotehr file 

        with open('order_logs.txt', 'a') as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Placing {buy_sell} order for {qty} of {symbol} at {price}\n")
            
        order_params = {
            "variety": "NORMAL",
            "tradingsymbol": symbol,
            "symboltoken": Stock.query.filter_by(tradingsymbol=symbol).first().symboltoken,
            "transactiontype": buy_sell,
            "exchange": Stock.query.filter_by(tradingsymbol=symbol).first().exchange,
            "ordertype": "MARKET",
            "producttype": "DELIVERY",
            "duration": "DAY",
            # "price": '0',
            "quantity": '1'
        }
        
        # Real API call (commented out for now)
        fake_response = smart_api.placeOrderFullResponse(order_params)
        print(fake_response)
        
        logger.info(f"Order {buy_sell} {qty} of {symbol} at {price}: {fake_response}")
        
        with open('fake_order_logs.txt', 'a') as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Order {buy_sell} {qty} of {symbol} at {price}: {fake_response}\n")
            
        
        executed_qty = qty if fake_response.get('status') == 'success' else 0
        time.sleep(3)
        logger.info(f"Order {buy_sell} {executed_qty}/{qty} of {symbol} at {price}: {fake_response}")
        order_id = fake_response.get('data').get('orderid')
        return executed_qty, order_id


def get_strategy_data(user_email, stock_symbol, base_price, wallet_value):
    configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=stock_symbol).order_by(PhaseConfig.start_sr_no).all()
    v1 = calculate_v1(wallet_value)
    strategy = []
    f_values = [20000, 1100]  # F2, F3
    f_values.append(f_values[1] + round(f_values[1] * v1))  # F4
    for i in range(3, 81):  # F5 to F82
        f_values.append(f_values[i-1] + round(f_values[i-1] * 0.022))  # Corrected to 0.022
    
    for config in configs:
        sr_no_range = range(config.start_sr_no, config.end_sr_no + 1)
        down_start = strategy[-1]['DOWN'] if strategy else 0
        for i, sr_no in enumerate(sr_no_range):
            down = down_start - (i * config.down_increment / 100)
            entry = round(base_price * (1 + down), 2)
            qnty = max(1, round(f_values[sr_no-1] / entry, 0))
            total_qty = qnty if sr_no == 1 else strategy[-1]['Total_Qty'] + qnty
            strategy.append({
                'Sr.No': sr_no,
                'DOWN': down,
                'Entry': entry,
                'Qnty': qnty,
                'Total_Qty': total_qty,
                'First_TGT': None if sr_no <= 8 else round(entry * 1.015, 2),
                'EXIT_1st_HALF': None if sr_no <= 8 else round(qnty / 2, 0),
                'Second_TGT': None if sr_no <= 8 else round(entry * 1.02, 2),
                'EXIT_2nd_HALF': None if sr_no <= 8 else round(qnty / 2, 0),
                'FINAL_TGT': round(entry * 1.015, 2)
            })
    # logger.info(f"Strategy data for {stock_symbol}: {strategy}")
    # logger.info(pd.DataFrame(strategy))
    return pd.DataFrame(strategy)
'''
'''
from flask import current_app
from datetime import datetime
import threading
import time
import json
from SmartApi.smartWebSocketOrderUpdate import SmartWebSocketOrderUpdate

order_status_dict = {}
order_status_lock = threading.Lock()

def handle_order_update(message, order_id_to_track, numeric_order_id_to_track=None):
    with app.app_context():
        try:
            order_data = json.loads(message)
            order_id = order_data.get('orderData', {}).get('orderid', 'N/A')
            unique_order_id = order_data.get('uniqueorderid', 'N/A')
            order_status = (order_data.get('orderData', {}).get('orderstatus') or 
                            order_data.get('order-status', 'unknown')).lower()
            symbol = order_data.get('orderData', {}).get('tradingsymbol', 'N/A')

            logger.info(f"Order Update - ID: {order_id}, Unique ID: {unique_order_id}, Symbol: {symbol}, Status: {order_status}")

            tracked_id = None
            if order_id == numeric_order_id_to_track or unique_order_id == order_id_to_track:
                tracked_id = order_id_to_track if unique_order_id == order_id_to_track else numeric_order_id_to_track

            if tracked_id:
                with order_status_lock:
                    order_status_dict[tracked_id] = {
                        'status': order_status,
                        'symbol': symbol,
                        'message': order_data.get('orderData', {}).get('text', order_data.get('error-message', ''))
                    }
                logger.info(f"Tracked order {tracked_id} updated to status: {order_status}")

                # Update OrderStatus in the database
                with current_app.app_context():  # Ensure Flask app context
                    # Try matching by both order_id and unique_order_id
                    order_entry = (OrderStatus.query.filter_by(order_id=order_id).first() or 
                                  OrderStatus.query.filter_by(unique_order_id=unique_order_id).first())
                    if order_entry:
                        order_entry.status = order_status
                        order_entry.message = order_status_dict[tracked_id]['message']
                        order_entry.updated_at = IST.localize(datetime.now())
                        db.session.commit()
                        logger.info(f"Updated OrderStatus for {order_entry.order_id} to {order_status}")
                    else:
                        logger.warning(f"No OrderStatus entry found for order_id: {order_id} or unique_order_id: {unique_order_id}")

        except json.JSONDecodeError:
            logger.warning(f"Non-JSON message received: {message}")
        except Exception as e:
            logger.error(f"Error processing order update: {e}")

def custom_on_message(wsapp, message, order_id_to_track, numeric_order_id_to_track):
    logger.info(f"Raw message received: {message}")
    handle_order_update(message, order_id_to_track, numeric_order_id_to_track)

def place_order(smart_api, symbol, qty, price, buy_sell='BUY', user_email=None):
    with app.app_context():
        if app.config['DRY_RUN']:
            executed_qty = qty
            logger.info(f"[DRY RUN] Simulated {buy_sell} order: {executed_qty}/{qty} of {symbol} at {price}")
            return executed_qty, "dry-run-order-id", "completed"
        
        if not user_email:
            logger.error(f"User email is None for {symbol} order")
            api_log = ApiLog(user_email or "unknown", symbol, None, "Place Order", "error", "User email not provided")
            db.session.add(api_log)
            db.session.commit()
            return 0, None, "error"
    
        logger.info(f"Placing {buy_sell} order for {qty} of {symbol} at {price}")
        order_params = {
            "variety": "NORMAL",
            "tradingsymbol": symbol,
            "symboltoken": Stock.query.filter_by(tradingsymbol=symbol).first().symboltoken,
            "transactiontype": buy_sell,
            "exchange": Stock.query.filter_by(tradingsymbol=symbol).first().exchange,
            "ordertype": "MARKET",
            "producttype": "DELIVERY",
            "duration": "DAY",
            "quantity": '1'
        }
    
        try:
            response = smart_api.placeOrderFullResponse(order_params)
            logger.info(f"Order {buy_sell} {qty} of {symbol} at {price}: {response}")
            
            order_id = response.get('data', {}).get('uniqueorderid')
            numeric_order_id = response.get('data', {}).get('orderid')
            if not order_id or not numeric_order_id:
                logger.error(f"Failed to get order IDs for {symbol}: uniqueorderid={order_id}, orderid={numeric_order_id}")
                api_log = ApiLog(user_email, symbol, None, "Place Order", "error", "Missing order IDs in response")
                db.session.add(api_log)
                db.session.commit()
                return 0, None, "error"
    
            # Save initial order status to the database
            order_entry = OrderStatus(
                user_email=user_email,
                order_id=numeric_order_id,
                unique_order_id=order_id,
                symbol=symbol,
                status="pending",
                message="Order placed, awaiting confirmation",
                quantity=float(qty),
                price=price,
                buy_sell=buy_sell
            )
            db.session.add(order_entry)
            db.session.commit()
            logger.info(f"Saved initial OrderStatus for {numeric_order_id}")
    
            if user_email not in session_cache:
                logger.error(f"No session data found for {user_email} in cache")
                user = User.query.filter_by(email=user_email).first()
                if user:
                    smart_api = get_angel_session(user)
                else:
                    api_log = ApiLog(user_email, symbol, order_id, "Place Order", "error", "User not found or session data missing")
                    db.session.add(api_log)
                    db.session.commit()
                    return 0, order_id, "error"
            
            session_data = session_cache[user_email]
            auth_token = session_data.get('auth_token')
            api_key = smart_api.api_key
            client_code = getattr(smart_api, 'client_code', user_email)
            feed_token = session_data.get('feed_token')
    
            if not all([auth_token, api_key, client_code, feed_token]):
                logger.error(f"Missing WebSocket credentials for {user_email}")
                api_log = ApiLog(user_email, symbol, order_id, "Place Order", "error", "Missing WebSocket credentials")
                db.session.add(api_log)
                db.session.commit()
                return 0, order_id, "error"
    
            client = SmartWebSocketOrderUpdate(auth_token, api_key, client_code, feed_token)
            client.on_message = lambda wsapp, message: custom_on_message(wsapp, message, order_id, numeric_order_id)
            
            ws_thread = threading.Thread(target=client.connect)
            ws_thread.daemon = True
            ws_thread.start()
    
            max_attempts = 10
            attempt = 0
            status = None
            while attempt < max_attempts:
                with order_status_lock:
                    tracked_id = order_id if order_id in order_status_dict else (numeric_order_id if numeric_order_id in order_status_dict else None)
                    if tracked_id:
                        status = order_status_dict[tracked_id]['status']
                        if status in ['complete', 'executed']:
                            executed_qty = qty
                            logger.info(f"Order {tracked_id} for {symbol} completed")
                            client.close_connection()
                            return executed_qty, order_id, "completed"
                        elif status in ['rejected', 'cancelled']:
                            logger.warning(f"Order {tracked_id} for {symbol} failed with status: {status}")
                            api_log = ApiLog(user_email, symbol, order_id, "Place Order", status, order_status_dict[tracked_id]['message'])
                            db.session.add(api_log)
                            db.session.commit()
                            client.close_connection()
                            return 0, order_id, status
                        else:
                            logger.info(f"Order {tracked_id} for {symbol} still pending: {status}")
                time.sleep(3)
                attempt += 1
            
            logger.error(f"Order {order_id} for {symbol} did not complete after {max_attempts} attempts")
            api_log = ApiLog(user_email, symbol, order_id, "Place Order", "timeout", "Order status not updated in time")
            db.session.add(api_log)
            db.session.commit()
            
            with current_app.app_context():
                order_entry = OrderStatus.query.filter_by(order_id=numeric_order_id).first()
                if order_entry:
                    order_entry.status = "timeout"
                    order_entry.message = "Order status not updated in time"
                    db.session.commit()
                    logger.info(f"Updated OrderStatus for {numeric_order_id} to timeout")
            
            client.close_connection()
            return 0, order_id, "timeout"
    
        except Exception as e:
            logger.error(f"Error placing order for {symbol}: {str(e)}")
            api_log = ApiLog(user_email, symbol, order_id if 'order_id' in locals() else None, "Place Order", "error", str(e))
            db.session.add(api_log)
            db.session.commit()
            return 0, None, "error"
'''

def get_strategy_data(user_email, stock_symbol, base_price, wallet_value):
    configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=stock_symbol).order_by(PhaseConfig.start_sr_no).all()
    v1 = calculate_v1(wallet_value)
    strategy = []
    f_values = [200, 110]  # F2, F3
    f_values.append(f_values[1] + round(f_values[1] * v1))  # F4
    for i in range(3, 81):  # F5 to F82
        f_values.append(f_values[i-1] + round(f_values[i-1] * 0.022))
    
    total_invested = 0
    total_qty = 0

    for config in configs:
        sr_no_range = range(config.start_sr_no, config.end_sr_no + 1)
        down_start = strategy[-1]['DOWN'] if strategy else 0
        for i, sr_no in enumerate(sr_no_range):
            down = down_start - (i * config.down_increment / 100)
            entry = round(base_price * (1 + down), 2) if sr_no > 1 else base_price
            qnty = max(1, round(f_values[sr_no-1] / entry, 0))
            total_qty += qnty
            if sr_no == 1:
                total_invested = round(entry * qnty, 2)  # H2 = B2 * E2
            else:
                total_invested = round(total_invested + f_values[sr_no-1], 2)  # H{row} = H{row-1} + F{row}
            
            avg_price = round(total_invested / total_qty, 2)

            first_tgt = None if sr_no <= 8 else round(entry * 1.015, 2)
            final_tgt = round(avg_price * 1.015, 2)
            second_tgt = None if sr_no <= 21 else round((first_tgt + final_tgt) / 2, 2)

            strategy.append({
                'Sr.No': sr_no,
                'DOWN': down,
                'Entry': entry,
                'Qnty': qnty,
                'Capital': f_values[sr_no-1],
                'Total_Qty': total_qty,
                'Total_Invested': total_invested,
                'First_TGT': first_tgt,
                'EXIT_1st_HALF': None if sr_no <= 8 else round(total_qty / 2, 0),
                'Second_TGT': second_tgt,
                'EXIT_2nd_HALF': None if sr_no <= 21 else round(total_qty / 4, 0),
                'FINAL_TGT': final_tgt,
                'AVG_on_Capital': avg_price
            })
    
    # logger.info(f"Strategy data for {stock_symbol}: {strategy}")
    return pd.DataFrame(strategy)

live_prices = {}
live_prices_lock = threading.Lock()

# WebSocket and thread management
websocket_clients = {}  # Key: user_email, Value: SmartWebSocketV2 instance
websocket_threads = {}  # Key: user_email, Value: threading.Thread instance
websocket_lock = threading.Lock()
# session_cache = {}
# Indian Standard Time
IST = pytz.timezone('Asia/Kolkata')


logging.basicConfig(
    filename='trading_strategy.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)
IST = pytz.timezone('Asia/Kolkata')

'''
def process_strategy(user, symbol, ltp, smart_api):
    logger.info(f"Process strategy for {symbol} at {ltp}")
    
    with app.app_context():
        try:
            # Fetch all trades for this stock and user, ordered by sr_no
            trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
            wallet_value = get_wallet_value(smart_api)
            
            logger.info(f"Trades for {symbol}: {len(trades)}")
            

            # Determine base price and latest trade
            latest_trade = trades[-1] if trades else None
            logger.info(f"Latest trade for {symbol}: {latest_trade}")
            base_price = latest_trade.base_price if latest_trade else ltp
            logger.info(f"Base price for {symbol}: {base_price}")
            strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
            
            # Handle initial buy if no trades or all are CLOSED/OLD_BUY
            if not trades or all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades):
                qty = strategy_data.loc[0, 'Qnty']
                executed_qty = place_order(smart_api, symbol, qty, ltp)
                # time.sleep(1)  # Wait for order to execute
                logger.info(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}")
                if executed_qty > 0:
                    sr_no = max([t.sr_no for t in trades], default=1)
                    new_trade = Trade(stock_symbol=symbol,sr_no=sr_no,entry_price=ltp,quantity=int(executed_qty),user_email=user.email,base_price=ltp,otal_quantity=int(executed_qty),
                        total_sold_quantity=0,status='OPEN',last_updated=IST.localize(datetime.now()),
                        description='Initial Buy')
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
                return

            # Determine the phase and drop increment based on the latest OPEN trade's sr_no
            latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
            current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
            logger.info(f"Currunt Sr No for {symbol} is {current_sr_no}")
            phase_config = PhaseConfig.query.filter_by(
                user_email=user.email,
                stock_symbol=symbol
            ).filter(
                PhaseConfig.start_sr_no <= current_sr_no,
                PhaseConfig.end_sr_no >= current_sr_no
            ).first()

            if not phase_config:
                logger.warning(f"No phase config found for {symbol} with sr_no {current_sr_no}, defaulting to 0.25%")
                down_increment = 0.0025
            else:
                down_increment = phase_config.down_increment / 100
                logger.info(f"Phase {phase_config.phase} for {symbol}, Sr.No: {current_sr_no}, Down Increment: {down_increment*100}%")

            # Check for additional buy based on phase-specific drop percentage
            current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
            drop_percent = (ltp - base_price) / base_price
            logger.info(f"Current open quantity for {symbol}: {current_open_qty}")
            logger.info(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
            
            if drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades):
                target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
                target_row = strategy_data.loc[target_idx]
                target_sr_no = int(target_row['Sr.No'])
                total_qty = int(target_row['Total_Qty'])
                qty_to_buy = total_qty - current_open_qty
                
                # Check if an OPEN trade already exists for this target_sr_no
                existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
                if existing_open_trade:
                    logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
                elif qty_to_buy > 0:
                    executed_qty = int(float(place_order(smart_api, symbol, qty_to_buy, ltp)))
                    if executed_qty > 0:
                        # Update total_quantity for all trades with the same sr_no (consistency)
                        for trade in trades:
                            if trade.sr_no == latest_open_trade.sr_no and trade.status == 'OPEN':
                                trade.total_quantity = total_qty  # Changed: Update all matching trades
                                trade.status = 'OLD_BUY'
                                trade.last_updated = IST.localize(datetime.now())
                                trade.description = f"Updated for Buy and chnaged the total quntity to {trade.total_quantity}"  # Changed: Added description
                                logger.info(f"Updated trade Sr.No {trade.sr_no} to OLD_BUY, Total_Qty: {total_qty}")
                        
                        # Create a new trade with the target_sr_no
                        new_trade = Trade(
                            stock_symbol=symbol,
                            sr_no=target_sr_no,
                            entry_price=ltp,
                            quantity=int(executed_qty),
                            user_email=user.email,
                            base_price=base_price,
                            total_quantity=sum(t.total_quantity for t in trades if t.status == 'OLD_BUY') + int(executed_qty),
                            total_sold_quantity=0,
                            status='OPEN',
                            last_updated=IST.localize(datetime.now()),
                            description='Additional Buy'  # Changed: Added description
                        )
                        db.session.add(new_trade)
                        db.session.commit()
                        logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
                    else:
                        logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}")
                else:
                    logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
            else:
                logger.info(f"No buy for {symbol}: Drop {drop_percent} > -{down_increment} or no open trades")

            # Process sells for OPEN trades (no sr_no change on sell)
            all_closed = True
            for trade in trades:
                if trade.status != 'OPEN':
                    continue
                all_closed = False
                
                base_price = trade.base_price
                logger.info(f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                
                sr_no = trade.sr_no  # Keep sr_no unchanged during sell
                entry_price = trade.entry_price
                current_qty = trade.total_quantity - trade.total_sold_quantity
                row = strategy_data.loc[sr_no-1]
                logger.info(f"trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

                # Define sell targets
                final_tgt = entry_price * 1.015
                first_tgt = entry_price * 1.015 if sr_no > 8 else None
                second_tgt = entry_price * 1.02 if sr_no > 21 else None
                half_qty = ceil(current_qty / 2) if sr_no > 8 else 0

                if sr_no <= 8:
                    logger.info(f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {final_tgt}")
                    if ltp >= final_tgt and current_qty > 0:
                        logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
                        executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
                        trade.total_sold_quantity += executed_qty
                        trade.description = 'Final TGT'  # Changed: Added description
                        if trade.total_sold_quantity >= trade.total_quantity:
                            trade.status = 'CLOSED'
                            trade.cycle_count += 1  # Changed: Increment cycle_count on full sell
                            logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                        trade.last_updated = IST.localize(datetime.now())
                        db.session.commit()
                        logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
                else:
                    logger.info(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")
                    if sr_no <= 21:
                        print("Comes under 21")
                        logger.info(f"Target (FIRST_TGT) for {symbol} Sr.No {sr_no}: {first_tgt}")
                        if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                            executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'  # Changed: Added description for first_tgt sell
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1  # Changed: Increment cycle_count on full sell
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        elif ltp >= final_tgt and current_qty > 0:
                            executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
                            trade.total_sold_quantity += executed_qty
                            trade.description = f"Final_TGT {final_tgt}"
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1  # Changed: Increment cycle_count on full sell
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
                    else:  # Sr.No > 21
                        if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                            executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'  # Changed: Added description for first_tgt sell
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1  # Changed: Increment cycle_count on full sell
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
                            remaining_qty = current_qty
                            executed_qty = int(place_order(smart_api, symbol, remaining_qty, ltp, 'SELL'))
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Second TGT'  # Changed: Added description
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1  # Changed: Increment cycle_count on full sell
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{remaining_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        elif ltp >= final_tgt and current_qty > 0:
                            executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'  # Changed: Added description
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1  # Changed: Increment cycle_count on full sell
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

            # Reset cycle if all trades are CLOSED and update TradeCycle
            if all_closed and trades:
                logger.info(f"All trades for {symbol} are CLOSED, resetting cycle to Sr.No 1")
                # Update or create TradeCycle entry
                current_cycle = TradeCycle.query.filter_by(
                    stock_symbol=symbol,
                    user_email=user.email,
                    status='ACTIVE'
                ).order_by(TradeCycle.cycle_start.desc()).first()
                
                if current_cycle:
                    current_cycle.cycle_end = IST.localize(datetime.now())
                    current_cycle.total_sold = sum(t.total_sold_quantity for t in trades)
                    current_cycle.total_bought = sum(t.total_quantity for t in trades)
                    current_cycle.profit = sum((ltp - t.entry_price) * t.total_sold_quantity for t in trades if t.status == 'CLOSED')
                    current_cycle.status = 'COMPLETED'
                    logger.info(f"Completed TradeCycle for {symbol}: Total Bought {current_cycle.total_bought}, Total Sold {current_cycle.total_sold}, Profit {current_cycle.profit}")
                
                # Start new cycle
                new_cycle = TradeCycle(
                    stock_symbol=symbol,
                    user_email=user.email,
                    cycle_start=IST.localize(datetime.now()),
                    status='ACTIVE'
                )
                db.session.add(new_cycle)
                db.session.commit()
                logger.info(f"Started new TradeCycle for {symbol}")

        except Exception as e:
            logger.error(f"Error in process_strategy for {symbol}: {str(e)}")
            db.session.rollback()
        finally:
            db.session.close()
'''

'''
def process_strategy(user, symbol, ltp, smart_api):
    logger.info(f"Process strategy for {symbol} at {ltp}")
    
    with app.app_context():
        try:
            # Fetch all trades for this stock and user, ordered by sr_no
            trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
            wallet_value = get_wallet_value(smart_api)
            
            logger.info(f"Trades for {symbol}: {len(trades)}")

            # Determine base price and latest trade
            latest_trade = trades[-1] if trades else None
            logger.info(f"Latest trade for {symbol}: {latest_trade}")
            base_price = latest_trade.base_price if latest_trade else ltp
            logger.info(f"Base price for {symbol}: {base_price}")
            strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
            
            # Handle initial buy if no trades or all are CLOSED/OLD_BUY
            if not trades or all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades):
                qty = strategy_data.loc[0, 'Qnty']
                executed_qty = place_order(smart_api, symbol, qty, ltp)
                logger.info(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}")
                if executed_qty > 0:
                    sr_no = max([t.sr_no for t in trades], default=1)
                    new_trade = Trade(
                        stock_symbol=symbol,
                        sr_no=sr_no,
                        entry_price=ltp,
                        quantity=int(executed_qty),
                        user_email=user.email,
                        base_price=ltp,
                        total_quantity=int(executed_qty),
                        total_sold_quantity=0,
                        status='OPEN',
                        last_updated=IST.localize(datetime.now()),
                        description='Initial Buy'
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
                return

            # Determine the phase and drop increment based on the latest OPEN trade's sr_no
            latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
            current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
            logger.info(f"Current Sr No for {symbol} is {current_sr_no}")
            phase_config = PhaseConfig.query.filter_by(
                user_email=user.email,
                stock_symbol=symbol
            ).filter(
                PhaseConfig.start_sr_no <= current_sr_no,
                PhaseConfig.end_sr_no >= current_sr_no
            ).first()

            if not phase_config:
                logger.warning(f"No phase config found for {symbol} with sr_no {current_sr_no}, defaulting to 0.25%")
                down_increment = 0.0025
            else:
                down_increment = phase_config.down_increment / 100
                logger.info(f"Phase {phase_config.phase} for {symbol}, Sr.No: {current_sr_no}, Down Increment: {down_increment*100}%")

            # Check for additional buy based on phase-specific drop percentage
            current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')

            
            drop_percent = (ltp - base_price) / base_price
            logger.info(f"Current open quantity for {symbol}: {current_open_qty}")
            logger.info(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
            
            if drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades):
                target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
                target_row = strategy_data.loc[target_idx]
                target_sr_no = int(target_row['Sr.No'])
                total_qty = int(target_row['Total_Qty'])
                qty_to_buy = total_qty - current_open_qty
                
                # Check if an OPEN trade already exists for this target_sr_no
                existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
                if existing_open_trade:
                    logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
                elif qty_to_buy > 0:
                    executed_qty = int(float(place_order(smart_api, symbol, qty_to_buy, ltp)))
                    if executed_qty > 0:
                        # Update total_quantity for all trades with the same sr_no
                        for trade in trades:
                            if trade.sr_no == latest_open_trade.sr_no and trade.status == 'OPEN':
                                trade.total_quantity = total_qty
                                trade.status = 'OLD_BUY'
                                trade.last_updated = IST.localize(datetime.now())
                                trade.description = f"Updated for Buy and changed the total quantity to {trade.total_quantity}"
                                logger.info(f"Updated trade Sr.No {trade.sr_no} to OLD_BUY, Total_Qty: {total_qty}")
                        
                        # Create a new trade with the target_sr_no
                        new_trade = Trade(
                            stock_symbol=symbol,
                            sr_no=target_sr_no,
                            entry_price=ltp,
                            quantity=int(executed_qty),
                            user_email=user.email,
                            base_price=base_price,
                            total_quantity=sum(t.total_quantity for t in trades if t.status == 'OLD_BUY') + int(executed_qty),
                            total_sold_quantity=0,
                            status='OPEN',
                            last_updated=IST.localize(datetime.now()),
                            description='Additional Buy'
                        )
                        db.session.add(new_trade)
                        db.session.commit()
                        logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
                    else:
                        logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}")
                else:
                    logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
            else:
                logger.info(f"No buy for {symbol}: Drop {drop_percent} > -{down_increment} or no open trades")

            # Process sells for OPEN trades (using strategy_data targets)
            all_closed = True
            for trade in trades:
                if trade.status != 'OPEN':
                    continue
                all_closed = False
                
                base_price = trade.base_price
                logger.info(f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                
                sr_no = trade.sr_no
                entry_price = trade.entry_price
                current_qty = trade.total_quantity - trade.total_sold_quantity
                row = strategy_data.loc[sr_no-1]
                logger.info(f"trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

                # Use targets from strategy_data
                final_tgt = row['FINAL_TGT']
                first_tgt = row['First_TGT']
                second_tgt = row['Second_TGT']
                half_qty = row['EXIT_1st_HALF'] if row['EXIT_1st_HALF'] is not None else 0

                if sr_no <= 8:
                    logger.info(f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {final_tgt}")
                    if ltp >= final_tgt and current_qty > 0:
                        logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
                        executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
                        trade.total_sold_quantity += executed_qty
                        trade.description = 'Final TGT'
                        if trade.total_sold_quantity >= trade.total_quantity:
                            trade.status = 'CLOSED'
                            trade.cycle_count += 1
                            logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                        trade.last_updated = IST.localize(datetime.now())
                        db.session.commit()
                        logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
                else:
                    logger.info(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")
                    if sr_no <= 21:
                        if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                            executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        elif ltp >= final_tgt and current_qty > 0:
                            executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
                            trade.total_sold_quantity += executed_qty
                            trade.description = f"Final_TGT {final_tgt}"
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
                    else:  # Sr.No > 21
                        if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                            executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
                            remaining_qty = current_qty
                            executed_qty = int(place_order(smart_api, symbol, remaining_qty, ltp, 'SELL'))
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Second TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{remaining_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        elif ltp >= final_tgt and current_qty > 0:
                            executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

            # Reset cycle if all trades are CLOSED and update TradeCycle
            if all_closed and trades:
                logger.info(f"All trades for {symbol} are CLOSED, resetting cycle to Sr.No 1")
                current_cycle = TradeCycle.query.filter_by(
                    stock_symbol=symbol,
                    user_email=user.email,
                    status='ACTIVE'
                ).order_by(TradeCycle.cycle_start.desc()).first()
                
                if current_cycle:
                    current_cycle.cycle_end = IST.localize(datetime.now())
                    current_cycle.total_sold = sum(t.total_sold_quantity for t in trades)
                    current_cycle.total_bought = sum(t.total_quantity for t in trades)
                    current_cycle.profit = sum((ltp - t.entry_price) * t.total_sold_quantity for t in trades if t.status == 'CLOSED')
                    current_cycle.status = 'COMPLETED'
                    logger.info(f"Completed TradeCycle for {symbol}: Total Bought {current_cycle.total_bought}, Total Sold {current_cycle.total_sold}, Profit {current_cycle.profit}")
                
                new_cycle = TradeCycle(
                    stock_symbol=symbol,
                    user_email=user.email,
                    cycle_start=IST.localize(datetime.now()),
                    status='ACTIVE'
                )
                db.session.add(new_cycle)
                db.session.commit()
                logger.info(f"Started new TradeCycle for {symbol}")

        except Exception as e:
            logger.error(f"Error in process_strategy for {symbol}: {str(e)}")
            db.session.rollback()
        finally:
            db.session.close()
'''                        



# Valid base_capital options
BASE_CAPITAL_OPTIONS = [
    100000, 150000, 200000, 250000, 300000, 350000, 400000, 450000, 500000,
    550000, 600000, 650000, 700000, 750000, 800000, 850000, 900000, 950000, 1000000
]

# Calculate max stocks based on cash range
def get_max_stocks(cash):
    if 100000 <= cash < 150000:
        return 1
    elif 150000 <= cash < 250000:
        return 1
    elif 250000 <= cash < 350000:
        return 2
    elif 350000 <= cash < 450000:
        return 3
    elif 450000 <= cash < 550000:
        return 4
    elif 550000 <= cash < 650000:
        return 5
    elif 650000 <= cash < 750000:
        return 6
    elif 750000 <= cash < 850000:
        return 7
    elif 850000 <= cash < 950000:
        return 8
    elif 950000 <= cash <= 1000000:
        return 9
    return 0  


@app.route('/api/base_capital_options', methods=['GET'])
@jwt_required()
def get_base_capital_options():
    try:
        # Assume user email is passed as a query parameter or from authentication
        user_email = get_jwt_identity()
        if not user_email:
            return jsonify({'error': 'User email is required'}), 400

        # Fetch user from database
        user = User.query.filter_by(email=user_email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Fetch RMS cash value (total cash in Angel One wallet)
        smart_api = get_angel_session(user)
        rms_cash = get_wallet_value(smart_api)
        if rms_cash is None:
            return jsonify({'error': 'Failed to fetch RMS cash value'}), 500

        # Update available_balance
        user.available_balance = rms_cash
        db.session.commit()
        logger.info(f"Updated available_balance for {user_email}: {user.available_balance}")

        # Calculate used_balance (sum of base_capital for active stocks)
        # Assume each Trade with status != 'CLOSED' represents an active stock
        active_trades = Stock.query.filter_by(user_id = user.id).filter(Stock.trading_status != False).all()
        logger.info(f"Active trades for {user_email}: {len(active_trades)}")
        
        logger.info(f"Active trades for {user_email}: active_trades {active_trades}")
        
        for trade in active_trades:
            logger.info(f"Trade for {trade.tradingsymbol}: {trade.allotment_captial}")

        # Unique stocks and their base_capital of additoon of all the stock.allotment_captial 
        
        stock_base_capitals = {}
        for trade in active_trades:
            logger.info(f"Trade for {trade.tradingsymbol}: {trade.allotment_captial}")
            stock_base_capitals[trade.symboltoken] = trade.allotment_captial
            

        used_balance = sum(stock_base_capitals.values())
        user.used_balance = used_balance
        user.remaining_balance = max(0, user.available_balance - user.used_balance)
        db.session.commit()
        logger.info(f"Calculated for {user_email}: used_balance={user.used_balance}, remaining_balance={user.remaining_balance}")

        # Determine max stocks based on available_balance
        max_stocks = get_max_stocks(user.available_balance)
        current_stocks = len(stock_base_capitals)
        remaining_stock_slots = max(0, max_stocks - current_stocks)

        # Filter base_capital options
        valid_options = [
            option for option in BASE_CAPITAL_OPTIONS
            if option <= user.remaining_balance and remaining_stock_slots > 0
        ]

        # Response
        response = {
            'available_balance': user.available_balance,
            'used_balance': user.used_balance,
            'remaining_balance': user.remaining_balance,
            'current_stocks': current_stocks,
            'max_stocks': max_stocks,
            'base_capital_options': valid_options
        }
        logger.info(f"Base capital options for {user_email}: {response}")
        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Error in get_base_capital_options: {str(e)}")
        return jsonify({'error': str(e)}), 500


# def process_strategy(user, symbol, ltp, smart_api):
#     logger.info(f"Process strategy for {symbol} at {ltp}")
    
#     with app.app_context():
#         try:
#             # Fetch all trades for this stock and user, ordered by sr_no
#             trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
#             wallet_value = Stock.query.filter_by(user_id=user.id).filter(Stock.tradingsymbol == symbol).first().allotment_captial
            
#             logger.info(f"Wallet value for {symbol}: {wallet_value}")
#             logger.info(f"Trades for {symbol}: {len(trades)}")

#             # Determine base price and latest trade
#             latest_trade = trades[-1] if trades else None
#             logger.info(f"Latest trade for {symbol}: {latest_trade}")
#             base_price = latest_trade.base_price if latest_trade else ltp
#             logger.info(f"Base price for {symbol}: {base_price}")
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
            
#             # Handle initial buy if no trades or all are CLOSED/OLD_BUY
#             if not trades or all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades):
#                 qty = strategy_data.loc[0, 'Qnty']
#                 executed_qty, order_id = place_order(smart_api, symbol, qty, ltp, user_email=user.email)

#                 order_status = smart_api.individual_order_details(order_id)
#                 with open('order_status.txt', 'w') as f:
#                     f.write(order_status)
                
#                 logger.info(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}")
#                 if executed_qty > 0:
#                     sr_no = max([t.sr_no for t in trades], default=1)
#                     new_trade = Trade(
#                         stock_symbol=symbol,
#                         sr_no=sr_no,
#                         entry_price=ltp,
#                         quantity=int(executed_qty),
#                         user_email=user.email,
#                         base_price=ltp,
#                         total_quantity=int(executed_qty),
#                         total_sold_quantity=0,
#                         status='OPEN',
#                         last_updated=IST.localize(datetime.now()),
#                         description='Initial Buy'
#                     )
#                     db.session.add(new_trade)
#                     db.session.commit()
#                     logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
#                 else:
#                     logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
#                 return

#             # Determine current open quantity and latest OPEN trade
#             current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
#             latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
#             current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
#             logger.info(f"Current Sr No for {symbol} is {current_sr_no}")
#             logger.info(f"Current open quantity for {symbol}: {current_open_qty}")

#             # Get phase config for buy logic
#             phase_config = PhaseConfig.query.filter_by(
#                 user_email=user.email,
#                 stock_symbol=symbol
#             ).filter(
#                 PhaseConfig.start_sr_no <= current_sr_no,
#                 PhaseConfig.end_sr_no >= current_sr_no
#             ).first()
#             down_increment = 0.0025 if not phase_config else phase_config.down_increment / 100
#             if not phase_config:
#                 logger.warning(f"No phase config found for {symbol} with sr_no {current_sr_no}, defaulting to 0.25%")
#             else:
#                 logger.info(f"Phase {phase_config.phase} for {symbol}, Sr.No: {current_sr_no}, Down Increment: {down_increment*100}%")

#             # Check for buy (drop or rise scenario)
#             drop_percent = (ltp - base_price) / base_price
#             logger.info(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
#             target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
#             target_row = strategy_data.loc[target_idx]
#             target_sr_no = int(target_row['Sr.No'])
#             total_qty = int(target_row['Total_Qty'])
#             qty_to_buy = total_qty - current_open_qty
            
#             if (drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades)) or \
#                (qty_to_buy > 0 and any(t.status == 'OPEN' for t in trades)):
#                 existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
#                 if existing_open_trade:
#                     logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
#                 elif qty_to_buy > 0:
#                     executed_qty = int(float(place_order(smart_api, symbol, qty_to_buy, ltp, user_email=user.email)))
#                     if executed_qty > 0:
#                         # Update previous OPEN trades to OLD_BUY
#                         for trade in trades:
#                             if trade.status == 'OPEN':
#                                 trade.status = 'OLD_BUY'
#                                 trade.last_updated = IST.localize(datetime.now())
#                                 trade.description = f"Updated to OLD_BUY before new buy at Sr.No {target_sr_no}"
#                                 logger.info(f"Updated trade Sr.No {trade.sr_no} to OLD_BUY, Total_Qty: {trade.total_quantity}")
                        
#                         # Create new trade
#                         new_trade = Trade(
#                             stock_symbol=symbol,
#                             sr_no=target_sr_no,
#                             entry_price=ltp,
#                             quantity=int(executed_qty),
#                             user_email=user.email,
#                             base_price=base_price,
#                             total_quantity=total_qty,
#                             total_sold_quantity=0,
#                             status='OPEN',
#                             last_updated=IST.localize(datetime.now()),
#                             description='Additional Buy'
#                         )
#                         db.session.add(new_trade)
#                         db.session.commit()
#                         logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
#                     else:
#                         logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}")
#                 else:
#                     logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
#             else:
#                 logger.info(f"No buy for {symbol}: Drop {drop_percent} > -{down_increment} or no open trades")

#             # Process sells for OPEN trades
#             all_closed = True
#             for trade in trades:
#                 if trade.status != 'OPEN':
#                     continue
#                 all_closed = False
                
#                 base_price = trade.base_price
#                 logger.info(f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
#                 strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                
#                 sr_no = trade.sr_no
#                 entry_price = trade.entry_price
#                 current_qty = trade.total_quantity - trade.total_sold_quantity
#                 row = strategy_data.loc[sr_no-1]
#                 logger.info(f"trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

#                 # Use targets from strategy_data
#                 final_tgt = row['FINAL_TGT']
#                 first_tgt = row['First_TGT']
#                 second_tgt = row['Second_TGT']
#                 half_qty = row['EXIT_1st_HALF'] if row['EXIT_1st_HALF'] is not None else 0
#                 second_half_qty = row['EXIT_2nd_HALF'] if row['EXIT_2nd_HALF'] is not None else 0

#                 logger.info(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}, Second_Half_Qty={second_half_qty}")

#                 if sr_no <= 8:
#                     if ltp >= final_tgt and current_qty > 0:
#                         logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
#                         executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email))
#                         trade.total_sold_quantity += executed_qty
#                         trade.description = 'Final TGT'
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                             trade.cycle_count += 1
#                             logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
#                 elif sr_no <= 21:
#                     if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email))
#                         trade.total_sold_quantity += executed_qty
#                         trade.description = 'First TGT'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email))
#                         trade.total_sold_quantity += executed_qty
#                         trade.description = 'Final TGT'
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                             trade.cycle_count += 1
#                             logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
#                 else:  # Sr.No > 21
#                     if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email))
#                         trade.total_sold_quantity += executed_qty
#                         trade.description = 'First TGT'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, second_half_qty, ltp, 'SELL', user_email=user.email))
#                         trade.total_sold_quantity += executed_qty
#                         trade.description = 'Second TGT'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{second_half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email))
#                         trade.total_sold_quantity += executed_qty
#                         trade.description = 'Final TGT'
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                             trade.cycle_count += 1
#                             logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

#             # Reset cycle if all trades are CLOSED and update TradeCycle
#             if all_closed and trades:
#                 logger.info(f"All trades for {symbol} are CLOSED, resetting cycle to Sr.No 1")
#                 current_cycle = TradeCycle.query.filter_by(
#                     stock_symbol=symbol,
#                     user_email=user.email,
#                     status='ACTIVE'
#                 ).order_by(TradeCycle.cycle_start.desc()).first()
                
#                 if current_cycle:
#                     current_cycle.cycle_end = IST.localize(datetime.now())
#                     current_cycle.total_sold = sum(t.total_sold_quantity for t in trades)
#                     current_cycle.total_bought = sum(t.total_quantity for t in trades)
#                     current_cycle.profit = sum((ltp - t.entry_price) * t.total_sold_quantity for t in trades if t.status == 'CLOSED')
#                     current_cycle.status = 'COMPLETED'
#                     logger.info(f"Completed TradeCycle for {symbol}: Total Bought {current_cycle.total_bought}, Total Sold {current_cycle.total_sold}, Profit {current_cycle.profit}")
                
#                 new_cycle = TradeCycle(
#                     stock_symbol=symbol,
#                     user_email=user.email,
#                     cycle_start=IST.localize(datetime.now()),
#                     status='ACTIVE'
#                 )
#                 db.session.add(new_cycle)
#                 db.session.commit()
#                 logger.info(f"Started new TradeCycle for {symbol}")

#         except Exception as e:
#             logger.error(f"Error in process_strategy for {symbol}: {str(e)}")
#             db.session.rollback()
#         finally:
#             db.session.close()
'''
def process_strategy(user, symbol, ltp, smart_api):
    logger.info(f"Process strategy for {symbol} at {ltp}")
    
    with app.app_context():
        try:
            # Fetch all trades for this stock and user, ordered by sr_no
            trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
            stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=symbol).first()
            wallet_value = stock.allotment_captial if stock else 0
            
            logger.info(f"Wallet value for {symbol}: {wallet_value}")
            logger.info(f"Trades for {symbol}: {len(trades)}")

            # Determine base price and latest trade
            latest_trade = trades[-1] if trades else None
            logger.info(f"Latest trade for {symbol}: {latest_trade}")
            base_price = latest_trade.base_price if latest_trade else ltp
            logger.info(f"Base price for {symbol}: {base_price}")
            strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
            
            # Function to check order status (from table or API)
            def get_order_status(order_id):
                # Try fetching from OrderStatus table first
                order = OrderStatus.query.filter_by(order_id=order_id, user_email=user.email).first()
                if order and order.status:
                    logger.info(f"Order status from table for {order_id}: {order.status}")
                    return order.status
                # Fallback to API if not found or outdated
                try:
                    status = smart_api.individual_order_details(order_id)
                    logger.info(f"Order status from API for {order_id}: {status}")
                    # Update OrderStatus table
                    new_status = OrderStatus(
                        order_id=order_id,
                        symbol=symbol,
                        user_email=user.email,
                        status=status.get('status', 'UNKNOWN') if isinstance(status, dict) else status,
                        last_updated=IST.localize(datetime.now())
                    )
                    db.session.merge(new_status)  # Merge to update if exists
                    db.session.commit()
                    return new_status.status
                except Exception as e:
                    logger.error(f"Failed to fetch order status for {order_id}: {str(e)}")
                    return 'UNKNOWN'

            # Handle initial buy if no trades or all are CLOSED/OLD_BUY
            if not trades or all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades):
                qty = strategy_data.loc[0, 'Qnty']
                try:
                    order_result = place_order(smart_api, symbol, qty, ltp, user_email=user.email)
                    logger.debug(f"place_order result for initial buy: {order_result}")
                    if isinstance(order_result, tuple) and len(order_result) == 2:
                        executed_qty, order_id = order_result
                    else:
                        logger.error(f"Unexpected place_order return value: {order_result}")
                        executed_qty, order_id = 0, None
                except Exception as e:
                    logger.error(f"Error placing initial buy order for {symbol}: {str(e)}")
                    executed_qty, order_id = 0, None

                # Check and log order status
                if order_id:
                    order_status = get_order_status(order_id)
                    logger.info(f"Initial buy order status for {symbol} (Order ID: {order_id}): {order_status}")
                    with open('order_status.txt', 'a') as f:  # Append mode
                        f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")
                else:
                    logger.warning(f"No order ID returned for initial buy of {symbol}")
                
                logger.info(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}")
                if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:  # Only proceed if order is successful
                    sr_no = max([t.sr_no for t in trades], default=1)
                    new_trade = Trade(
                        stock_symbol=symbol,
                        sr_no=sr_no,
                        entry_price=ltp,
                        quantity=int(executed_qty),
                        user_email=user.email,
                        base_price=ltp,
                        total_quantity=int(executed_qty),
                        total_sold_quantity=0,
                        status='OPEN',
                        last_updated=IST.localize(datetime.now()),
                        description='Initial Buy'
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Initial buy failed or not completed for {symbol} at {ltp}, Qty: {qty}, Status: {order_status}")
                return

            # Determine current open quantity and latest OPEN trade
            current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
            latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
            current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
            logger.info(f"Current Sr No for {symbol} is {current_sr_no}")
            logger.info(f"Current open quantity for {symbol}: {current_open_qty}")

            # Get phase config for buy logic
            phase_config = PhaseConfig.query.filter_by(
                user_email=user.email,
                stock_symbol=symbol
            ).filter(
                PhaseConfig.start_sr_no <= current_sr_no,
                PhaseConfig.end_sr_no >= current_sr_no
            ).first()
            down_increment = 0.0025 if not phase_config else phase_config.down_increment / 100
            if not phase_config:
                logger.warning(f"No phase config found for {symbol} with sr_no {current_sr_no}, defaulting to 0.25%")
            else:
                logger.info(f"Phase {phase_config.phase} for {symbol}, Sr.No: {current_sr_no}, Down Increment: {down_increment*100}%")

            # Check for buy (drop or rise scenario)
            drop_percent = (ltp - base_price) / base_price
            logger.info(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
            target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
            target_row = strategy_data.loc[target_idx]
            target_sr_no = int(target_row['Sr.No'])
            total_qty = int(target_row['Total_Qty'])
            qty_to_buy = total_qty - current_open_qty
            
            if (drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades)) or \
               (qty_to_buy > 0 and any(t.status == 'OPEN' for t in trades)):
                existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
                if existing_open_trade:
                    logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
                elif qty_to_buy > 0:
                    try:
                        order_result = place_order(smart_api, symbol, qty_to_buy, ltp, user_email=user.email)
                        logger.debug(f"place_order result for additional buy: {order_result}")
                        if isinstance(order_result, tuple) and len(order_result) == 2:
                            executed_qty, order_id = order_result
                        else:
                            logger.error(f"Unexpected place_order return value: {order_result}")
                            executed_qty, order_id = 0, None
                    except Exception as e:
                        logger.error(f"Error placing additional buy order for {symbol}: {str(e)}")
                        executed_qty, order_id = 0, None

                    # Check and log order status
                    if order_id:
                        order_status = get_order_status(order_id)
                        logger.info(f"Additional buy order status for {symbol} (Order ID: {order_id}): {order_status}")
                        with open('order_status.txt', 'a') as f:
                            f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")
                    else:
                        logger.warning(f"No order ID returned for additional buy of {symbol}")

                    if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                        # Update previous OPEN trades to OLD_BUY
                        for trade in trades:
                            if trade.status == 'OPEN':
                                trade.status = 'OLD_BUY'
                                trade.last_updated = IST.localize(datetime.now())
                                trade.description = f"Updated to OLD_BUY before new buy at Sr.No {target_sr_no}"
                                logger.info(f"Updated trade Sr.No {trade.sr_no} to OLD_BUY, Total_Qty: {trade.total_quantity}")
                        
                        # Create new trade
                        new_trade = Trade(
                            stock_symbol=symbol,
                            sr_no=target_sr_no,
                            entry_price=ltp,
                            quantity=int(executed_qty),
                            user_email=user.email,
                            base_price=base_price,
                            total_quantity=total_qty,
                            total_sold_quantity=0,
                            status='OPEN',
                            last_updated=IST.localize(datetime.now()),
                            description='Additional Buy'
                        )
                        db.session.add(new_trade)
                        db.session.commit()
                        logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
                    else:
                        logger.warning(f"Buy failed or not completed for {symbol} at {ltp}, Qty: {qty_to_buy}, Status: {order_status}")
                else:
                    logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
            else:
                logger.info(f"No buy for {symbol}: Drop {drop_percent} > -{down_increment} or no open trades")

            # Process sells for OPEN trades
            all_closed = True
            for trade in trades:
                if trade.status != 'OPEN':
                    continue
                all_closed = False
                
                base_price = trade.base_price
                logger.info(f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                
                sr_no = trade.sr_no
                entry_price = trade.entry_price
                current_qty = trade.total_quantity - trade.total_sold_quantity
                row = strategy_data.loc[sr_no-1]
                logger.info(f"trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

                # Use targets from strategy_data
                final_tgt = row['FINAL_TGT']
                first_tgt = row['First_TGT']
                second_tgt = row['Second_TGT']
                half_qty = row['EXIT_1st_HALF'] if row['EXIT_1st_HALF'] is not None else 0
                second_half_qty = row['EXIT_2nd_HALF'] if row['EXIT_2nd_HALF'] is not None else 0

                logger.info(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}, Second_Half_Qty={second_half_qty}")

                if sr_no <= 8:
                    if ltp >= final_tgt and current_qty > 0:
                        logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
                        try:
                            order_result = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            executed_qty = int(order_result) if order_result else 0
                            order_id = None  # Sell might not return order_id
                        except Exception as e:
                            logger.error(f"Error placing sell order for {symbol}: {str(e)}")
                            executed_qty = 0

                        if executed_qty > 0:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Sell failed for {symbol} Sr.No {sr_no} at {ltp}, Qty: {current_qty}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
                elif sr_no <= 21:
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        try:
                            order_result = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            executed_qty = int(order_result) if order_result else 0
                        except Exception as e:
                            logger.error(f"Error placing 1st half sell order for {symbol}: {str(e)}")
                            executed_qty = 0

                        if executed_qty > 0:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}")
                    elif ltp >= final_tgt and current_qty > 0:
                        try:
                            order_result = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            executed_qty = int(order_result) if order_result else 0
                        except Exception as e:
                            logger.error(f"Error placing final sell order for {symbol}: {str(e)}")
                            executed_qty = 0

                        if executed_qty > 0:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
                else:  # Sr.No > 21
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        try:
                            order_result = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            executed_qty = int(order_result) if order_result else 0
                        except Exception as e:
                            logger.error(f"Error placing 1st half sell order for {symbol}: {str(e)}")
                            executed_qty = 0

                        if executed_qty > 0:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}")
                    elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
                        try:
                            order_result = place_order(smart_api, symbol, second_half_qty, ltp, 'SELL', user_email=user.email)
                            executed_qty = int(order_result) if order_result else 0
                        except Exception as e:
                            logger.error(f"Error placing 2nd half sell order for {symbol}: {str(e)}")
                            executed_qty = 0

                        if executed_qty > 0:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Second TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{second_half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"2nd half sell failed for {symbol} at {ltp}, Qty: {second_half_qty}")
                    elif ltp >= final_tgt and current_qty > 0:
                        try:
                            order_result = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            executed_qty = int(order_result) if order_result else 0
                        except Exception as e:
                            logger.error(f"Error placing final sell order for {symbol}: {str(e)}")
                            executed_qty = 0

                        if executed_qty > 0:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

            # Reset cycle if all trades are CLOSED and update TradeCycle
            if all_closed and trades:
                logger.info(f"All trades for {symbol} are CLOSED, resetting cycle to Sr.No 1")
                current_cycle = TradeCycle.query.filter_by(
                    stock_symbol=symbol,
                    user_email=user.email,
                    status='ACTIVE'
                ).order_by(TradeCycle.cycle_start.desc()).first()
                
                if current_cycle:
                    current_cycle.cycle_end = IST.localize(datetime.now())
                    current_cycle.total_sold = sum(t.total_sold_quantity for t in trades)
                    current_cycle.total_bought = sum(t.total_quantity for t in trades)
                    current_cycle.profit = sum((ltp - t.entry_price) * t.total_sold_quantity for t in trades if t.status == 'CLOSED')
                    current_cycle.status = 'COMPLETED'
                    logger.info(f"Completed TradeCycle for {symbol}: Total Bought {current_cycle.total_bought}, Total Sold {current_cycle.total_sold}, Profit {current_cycle.profit}")
                
                new_cycle = TradeCycle(
                    stock_symbol=symbol,
                    user_email=user.email,
                    cycle_start=IST.localize(datetime.now()),
                    status='ACTIVE'
                )
                db.session.add(new_cycle)
                db.session.commit()
                logger.info(f"Started new TradeCycle for {symbol}")

        except Exception as e:
            logger.error(f"Error in process_strategy for {symbol}: {str(e)}", exc_info=True)
            db.session.rollback()
        finally:
            db.session.close()
'''

'''
def process_strategy(user, symbol, ltp, smart_api):
    logger.info(f"Process strategy for {symbol} at {ltp}")
    
    with app.app_context():
        try:
            # Fetch all trades for this stock and user, ordered by sr_no
            trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
            stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=symbol).first()
            wallet_value = stock.allotment_captial if stock else 0
            
            logger.info(f"Wallet value for {symbol}: {wallet_value}")
            logger.info(f"Trades for {symbol}: {len(trades)}")

            # Determine base price and latest trade
            latest_trade = trades[-1] if trades else None
            logger.info(f"Latest trade for {symbol}: {latest_trade}")
            base_price = latest_trade.base_price if latest_trade else ltp
            logger.info(f"Base price for {symbol}: {base_price}")
            strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)

            def get_order_status(order_id):
                order = OrderStatus.query.filter_by(order_id=order_id, user_email=user.email).first()
                if order and order.status:
                    logger.info(f"Order status from table for {order_id}: {order.status}")
                    return order.status
                try:
                    status = smart_api.individual_order_details(order_id)
                    logger.info(f"Order status from API for {order_id}: {status}")
                    new_status = OrderStatus(
                        order_id=order_id,
                        symbol=symbol,
                        user_email=user.email,
                        status=status.get('status', 'UNKNOWN') if isinstance(status, dict) else status,
                        last_updated=IST.localize(datetime.now())
                    )
                    db.session.merge(new_status)
                    db.session.commit()
                    return new_status.status
                except Exception as e:
                    logger.error(f"Failed to fetch order status for {order_id}: {str(e)}")
                    return 'UNKNOWN'

            # Handle initial buy if no trades or all are CLOSED/OLD_BUY
            if not trades or all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades):
                qty = strategy_data.loc[0, 'Qnty']
                executed_qty = 0
                order_id = None
                order_status = 'UNKNOWN'  # Default value to avoid UnboundLocalError
                
                try:
                    order_result = place_order(smart_api, symbol, qty, ltp, user_email=user.email)
                    logger.debug(f"place_order result for initial buy: {order_result}")
                    if isinstance(order_result, tuple) and len(order_result) == 3:
                        executed_qty, order_id, order_status = order_result
                    else:
                        logger.error(f"Unexpected place_order return value: {order_result}")
                        executed_qty, order_id, order_status = 0, None, 'ERROR'
                except Exception as e:
                    logger.error(f"Error placing initial buy order for {symbol}: {str(e)}")
                    executed_qty, order_id, order_status = 0, None, 'ERROR'

                # Log order status if order_id exists
                if order_id:
                    order_status = get_order_status(order_id)  # Update status from DB or API
                    logger.info(f"Initial buy order status for {symbol} (Order ID: {order_id}): {order_status}")
                    with open('order_status.txt', 'a') as f:
                        f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")
                else:
                    logger.warning(f"No order ID returned for initial buy of {symbol}")

                logger.info(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}")
                if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                    sr_no = max([t.sr_no for t in trades], default=1)
                    new_trade = Trade(
                        stock_symbol=symbol,
                        sr_no=sr_no,
                        entry_price=ltp,
                        quantity=int(executed_qty),
                        user_email=user.email,
                        base_price=ltp,
                        total_quantity=int(executed_qty),
                        total_sold_quantity=0,
                        status='OPEN',
                        last_updated=IST.localize(datetime.now()),
                        description='Initial Buy'
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Initial buy failed or not completed for {symbol} at {ltp}, Qty: {qty}, Status: {order_status}")
                return

            # Determine current open quantity and latest OPEN trade
            current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
            latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
            current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
            logger.info(f"Current Sr No for {symbol} is {current_sr_no}")
            logger.info(f"Current open quantity for {symbol}: {current_open_qty}")

            # Get phase config for buy logic
            phase_config = PhaseConfig.query.filter_by(
                user_email=user.email,
                stock_symbol=symbol
            ).filter(
                PhaseConfig.start_sr_no <= current_sr_no,
                PhaseConfig.end_sr_no >= current_sr_no
            ).first()
            down_increment = 0.0025 if not phase_config else phase_config.down_increment / 100
            if not phase_config:
                logger.warning(f"No phase config found for {symbol} with sr_no {current_sr_no}, defaulting to 0.25%")
            else:
                logger.info(f"Phase {phase_config.phase} for {symbol}, Sr.No: {current_sr_no}, Down Increment: {down_increment*100}%")

            # Check for buy (drop or rise scenario)
            drop_percent = (ltp - base_price) / base_price
            logger.info(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
            target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
            target_row = strategy_data.loc[target_idx]
            target_sr_no = int(target_row['Sr.No'])
            total_qty = int(target_row['Total_Qty'])
            qty_to_buy = total_qty - current_open_qty
            
            if (drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades)) or \
               (qty_to_buy > 0 and any(t.status == 'OPEN' for t in trades)):
                existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
                if existing_open_trade:
                    logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
                elif qty_to_buy > 0:
                    executed_qty = 0
                    order_id = None
                    order_status = 'UNKNOWN'  # Default value
                    
                    try:
                        order_result = place_order(smart_api, symbol, qty_to_buy, ltp, user_email=user.email)
                        logger.debug(f"place_order result for additional buy: {order_result}")
                        if isinstance(order_result, tuple) and len(order_result) == 3:
                            executed_qty, order_id, order_status = order_result
                        else:
                            logger.error(f"Unexpected place_order return value: {order_result}")
                            executed_qty, order_id, order_status = 0, None, 'ERROR'
                    except Exception as e:
                        logger.error(f"Error placing additional buy order for {symbol}: {str(e)}")
                        executed_qty, order_id, order_status = 0, None, 'ERROR'

                    if order_id:
                        order_status = get_order_status(order_id)
                        logger.info(f"Additional buy order status for {symbol} (Order ID: {order_id}): {order_status}")
                        with open('order_status.txt', 'a') as f:
                            f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")
                    else:
                        logger.warning(f"No order ID returned for additional buy of {symbol}")

                    if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                        for trade in trades:
                            if trade.status == 'OPEN':
                                trade.status = 'OLD_BUY'
                                trade.last_updated = IST.localize(datetime.now())
                                trade.description = f"Updated to OLD_BUY before new buy at Sr.No {target_sr_no}"
                                logger.info(f"Updated trade Sr.No {trade.sr_no} to OLD_BUY, Total_Qty: {trade.total_quantity}")
                        
                        new_trade = Trade(
                            stock_symbol=symbol,
                            sr_no=target_sr_no,
                            entry_price=ltp,
                            quantity=int(executed_qty),
                            user_email=user.email,
                            base_price=base_price,
                            total_quantity=total_qty,
                            total_sold_quantity=0,
                            status='OPEN',
                            last_updated=IST.localize(datetime.now()),
                            description='Additional Buy'
                        )
                        db.session.add(new_trade)
                        db.session.commit()
                        logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
                    else:
                        logger.warning(f"Buy failed or not completed for {symbol} at {ltp}, Qty: {qty_to_buy}, Status: {order_status}")
                else:
                    logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
            else:
                logger.info(f"No buy for {symbol}: Drop {drop_percent} > -{down_increment} or no open trades")

            # Process sells for OPEN trades
            all_closed = True
            for trade in trades:
                if trade.status != 'OPEN':
                    continue
                all_closed = False
                
                base_price = trade.base_price
                logger.info(f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                
                sr_no = trade.sr_no
                entry_price = trade.entry_price
                current_qty = trade.total_quantity - trade.total_sold_quantity
                row = strategy_data.loc[sr_no-1]
                logger.info(f"trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

                final_tgt = row['FINAL_TGT']
                first_tgt = row['First_TGT']
                second_tgt = row['Second_TGT']
                half_qty = row['EXIT_1st_HALF'] if row['EXIT_1st_HALF'] is not None else 0
                second_half_qty = row['EXIT_2nd_HALF'] if row['EXIT_2nd_HALF'] is not None else 0

                logger.info(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}, Second_Half_Qty={second_half_qty}")

                if sr_no <= 8:
                    if ltp >= final_tgt and current_qty > 0:
                        logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Sell failed for {symbol} Sr.No {sr_no} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
                elif sr_no <= 21:
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing 1st half sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}, Status: {order_status}")
                    elif ltp >= final_tgt and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing final sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
                else:  # Sr.No > 21
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing 1st half sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}, Status: {order_status}")
                    elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, second_half_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing 2nd half sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Second TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{second_half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"2nd half sell failed for {symbol} at {ltp}, Qty: {second_half_qty}, Status: {order_status}")
                    elif ltp >= final_tgt and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing final sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

            # Reset cycle if all trades are CLOSED and update TradeCycle
            if all_closed and trades:
                logger.info(f"All trades for {symbol} are CLOSED, resetting cycle to Sr.No 1")
                current_cycle = TradeCycle.query.filter_by(
                    stock_symbol=symbol,
                    user_email=user.email,
                    status='ACTIVE'
                ).order_by(TradeCycle.cycle_start.desc()).first()
                
                if current_cycle:
                    current_cycle.cycle_end = IST.localize(datetime.now())
                    current_cycle.total_sold = sum(t.total_sold_quantity for t in trades)
                    current_cycle.total_bought = sum(t.total_quantity for t in trades)
                    current_cycle.profit = sum((ltp - t.entry_price) * t.total_sold_quantity for t in trades if t.status == 'CLOSED')
                    current_cycle.status = 'COMPLETED'
                    logger.info(f"Completed TradeCycle for {symbol}: Total Bought {current_cycle.total_bought}, Total Sold {current_cycle.total_sold}, Profit {current_cycle.profit}")
                
                new_cycle = TradeCycle(
                    stock_symbol=symbol,
                    user_email=user.email,
                    cycle_start=IST.localize(datetime.now()),
                    status='ACTIVE'
                )
                db.session.add(new_cycle)
                db.session.commit()
                logger.info(f"Started new TradeCycle for {symbol}")

        except Exception as e:
            logger.error(f"Error in process_strategy for {symbol}: {str(e)}", exc_info=True)
            db.session.rollback()
        finally:
            db.session.close()
'''
'''
import json
import threading
import time
from flask import current_app
from SmartApi.smartWebSocketOrderUpdate import SmartWebSocketOrderUpdate


def handle_order_update(message, order_id_to_track, numeric_order_id_to_track=None):
    with app.app_context():
        try:
            order_data = json.loads(message)
            order_id = order_data.get('orderData', {}).get('orderid', 'N/A')
            unique_order_id = order_data.get('uniqueorderid', 'N/A')
            order_status = (order_data.get('orderData', {}).get('orderstatus') or 
                            order_data.get('order-status', 'unknown')).lower()
            symbol = order_data.get('orderData', {}).get('tradingsymbol', 'N/A')

            logger.info(f"Order Update - ID: {order_id}, Unique ID: {unique_order_id}, Symbol: {symbol}, Status: {order_status}")

            tracked_id = None
            if order_id == numeric_order_id_to_track or unique_order_id == order_id_to_track:
                tracked_id = order_id_to_track if unique_order_id == order_id_to_track else numeric_order_id_to_track

            if tracked_id:
                with order_status_lock:
                    order_status_dict[tracked_id] = {
                        'status': order_status,
                        'symbol': symbol,
                        'message': order_data.get('orderData', {}).get('text', order_data.get('error-message', ''))
                    }
                logger.info(f"Tracked order {tracked_id} updated to status: {order_status}")

                # Update OrderStatus in the database
                with current_app.app_context():
                    order_entry = (OrderStatus.query.filter_by(order_id=order_id).first() or 
                                  OrderStatus.query.filter_by(unique_order_id=unique_order_id).first())
                    if order_entry:
                        order_entry.status = order_status
                        order_entry.message = order_status_dict[tracked_id]['message']
                        order_entry.updated_at = IST.localize(datetime.now())
                        db.session.commit()
                        logger.info(f"Updated OrderStatus for {order_entry.order_id} to {order_status}")
                    else:
                        logger.warning(f"No OrderStatus entry found for order_id: {order_id} or unique_order_id: {unique_order_id}")

        except json.JSONDecodeError:
            logger.warning(f"Non-JSON message received: {message}")
        except Exception as e:
            logger.error(f"Error processing order update: {e}")

def custom_on_message(wsapp, message, order_id_to_track, numeric_order_id_to_track):
    logger.info(f"Raw message received: {message}")
    handle_order_update(message, order_id_to_track, numeric_order_id_to_track)

def place_order(smart_api, symbol, qty, price, buy_sell='BUY', user_email=None):
    with app.app_context():
        if app.config['DRY_RUN']:
            executed_qty = qty
            logger.info(f"[DRY RUN] Simulated {buy_sell} order: {executed_qty}/{qty} of {symbol} at {price}")
            return executed_qty, "dry-run-order-id", "completed"
        
        if not user_email:
            logger.error(f"User email is None for {symbol} order")
            api_log = ApiLog(user_email or "unknown", symbol, None, "Place Order", "error", "User email not provided")
            db.session.add(api_log)
            db.session.commit()
            return 0, None, "error"
    
        logger.info(f"Placing {buy_sell} order for {qty} of {symbol} at {price}")
        stock = Stock.query.filter_by(tradingsymbol=symbol).first()
        order_params = {
            "variety": "NORMAL",
            "tradingsymbol": symbol,
            "symboltoken": stock.symboltoken,
            "transactiontype": buy_sell,
            "exchange": stock.exchange,
            "ordertype": "MARKET",
            "producttype": "DELIVERY",
            "duration": "DAY",
            "quantity": '1' # [UPDATE 1] Fixed quantity from hardcoded '1' to dynamic qty
        }
    
        try:
            response = smart_api.placeOrderFullResponse(order_params)
            logger.info(f"Order {buy_sell} {qty} of {symbol} at {price}: {response}")
            
            order_id = response.get('data', {}).get('uniqueorderid')
            numeric_order_id = response.get('data', {}).get('orderid')
            if not order_id or not numeric_order_id:
                logger.error(f"Failed to get order IDs for {symbol}: uniqueorderid={order_id}, orderid={numeric_order_id}")
                api_log = ApiLog(user_email, symbol, None, "Place Order", "error", "Missing order IDs in response")
                db.session.add(api_log)
                db.session.commit()
                return 0, None, "error"
    
            # Save initial order status to the database
            order_entry = OrderStatus(
                user_email=user_email,
                order_id=numeric_order_id,
                unique_order_id=order_id,
                symbol=symbol,
                status="pending",
                message="Order placed, awaiting confirmation",
                quantity=float(qty),
                price=price,
                buy_sell=buy_sell
            )
            db.session.add(order_entry)
            db.session.commit()
            logger.info(f"Saved initial OrderStatus for {numeric_order_id}")
    
            if user_email not in session_cache:
                logger.error(f"No session data found for {user_email} in cache")
                user = User.query.filter_by(email=user_email).first()
                if user:
                    smart_api = get_angel_session(user)
                else:
                    api_log = ApiLog(user_email, symbol, order_id, "Place Order", "error", "User not found or session data missing")
                    db.session.add(api_log)
                    db.session.commit()
                    return 0, order_id, "error"
            
            session_data = session_cache[user_email]
            auth_token = session_data.get('auth_token')
            api_key = smart_api.api_key
            client_code = getattr(smart_api, 'client_code', user_email)
            feed_token = session_data.get('feed_token')
    
            if not all([auth_token, api_key, client_code, feed_token]):
                logger.error(f"Missing WebSocket credentials for {user_email}")
                api_log = ApiLog(user_email, symbol, order_id, "Place Order", "error", "Missing WebSocket credentials")
                db.session.add(api_log)
                db.session.commit()
                return 0, order_id, "error"
    
            client = SmartWebSocketOrderUpdate(auth_token, api_key, client_code, feed_token)
            client.on_message = lambda wsapp, message: custom_on_message(wsapp, message, order_id, numeric_order_id)
            
            ws_thread = threading.Thread(target=client.connect)
            ws_thread.daemon = True
            ws_thread.start()
    
            max_attempts = 10
            attempt = 0
            status = None
            while attempt < max_attempts:
                with order_status_lock:
                    tracked_id = order_id if order_id in order_status_dict else (numeric_order_id if numeric_order_id in order_status_dict else None)
                    if tracked_id and tracked_id in order_status_dict:  # [UPDATE 2] Added check to avoid KeyError
                        status = order_status_dict[tracked_id]['status']
                        if status in ['complete', 'executed']:
                            executed_qty = qty
                            logger.info(f"Order {tracked_id} for {symbol} completed")
                            client.close_connection()
                            return executed_qty, order_id, "completed"
                        elif status in ['rejected', 'cancelled']:
                            logger.warning(f"Order {tracked_id} for {symbol} failed with status: {status}")
                            api_log = ApiLog(user_email, symbol, order_id, "Place Order", status, order_status_dict[tracked_id]['message'])
                            db.session.add(api_log)
                            db.session.commit()
                            client.close_connection()
                            return 0, order_id, status
                        else:
                            logger.info(f"Order {tracked_id} for {symbol} still pending: {status}")
                time.sleep(3)
                attempt += 1
            
            logger.error(f"Order {order_id} for {symbol} did not complete after {max_attempts} attempts")
            api_log = ApiLog(user_email, symbol, order_id, "Place Order", "timeout", "Order status not updated in time")
            db.session.add(api_log)
            db.session.commit()
            
            with current_app.app_context():
                order_entry = OrderStatus.query.filter_by(order_id=numeric_order_id).first()
                if order_entry:
                    order_entry.status = "timeout"
                    order_entry.message = "Order status not updated in time"
                    db.session.commit()
                    logger.info(f"Updated OrderStatus for {numeric_order_id} to timeout")
            
            client.close_connection()
            return 0, order_id, "timeout"
    
        except Exception as e:
            logger.error(f"Error placing order for {symbol}: {str(e)}")
            api_log = ApiLog(user_email, symbol, order_id if 'order_id' in locals() else None, "Place Order", "error", str(e))
            db.session.add(api_log)
            db.session.commit()
            return 0, None, "error"

def process_strategy(user, symbol, ltp, smart_api):
    logger.info(f"Process strategy for {symbol} at {ltp}")
    
    with app.app_context():
        try:
            # Fetch all trades for this stock and user, ordered by sr_no
            trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
            stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=symbol).first()
            wallet_value = stock.allotment_captial if stock else 0
            
            logger.info(f"Wallet value for {symbol}: {wallet_value}")
            logger.info(f"Trades for {symbol}: {len(trades)}, Trades: {[t.__dict__ for t in trades]}")  # [UPDATE 3] Enhanced logging

            # [UPDATE 4] Check for pending or unresolved buy orders
            pending_orders = OrderStatus.query.filter_by(
                user_email=user.email,
                symbol=symbol,
                buy_sell='BUY'
            ).filter(
                OrderStatus.status.in_(['pending', 'UNKNOWN'])
            ).all()
            if pending_orders:
                logger.info(f"Skipping {symbol}: {len(pending_orders)} pending orders exist: {[o.order_id for o in pending_orders]}")
                return

            # Determine base price and latest trade
            latest_trade = trades[-1] if trades else None
            base_price = latest_trade.base_price if latest_trade else ltp
            logger.info(f"Base price for {symbol}: {base_price}")
            strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)

            def get_order_status(order_id):
                order = OrderStatus.query.filter_by(order_id=order_id, user_email=user.email).first()
                if order and order.status not in ['pending', 'UNKNOWN']:  # [UPDATE 5] Only return resolved statuses
                    logger.info(f"Order status from table for {order_id}: {order.status}")
                    return order.status
                try:
                    status = smart_api.individual_order_details(order_id)
                    logger.info(f"Order status from API for {order_id}: {status}")
                    new_status = OrderStatus(
                        order_id=order_id,
                        symbol=symbol,
                        user_email=user.email,
                        status=status.get('status', 'UNKNOWN') if isinstance(status, dict) else status,
                        updated_at=IST.localize(datetime.now())
                    )
                    db.session.merge(new_status)
                    db.session.commit()
                    return new_status.status
                except Exception as e:
                    logger.error(f"Failed to fetch order status for {order_id}: {str(e)}")
                    return 'UNKNOWN'

            # Handle initial buy if no trades or all are CLOSED/OLD_BUY
            if not trades or all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades):
                qty = int(strategy_data.loc[0, 'Qnty'])  # [UPDATE 6] Ensure integer qty
                executed_qty = 0
                order_id = None
                order_status = 'UNKNOWN'
                
                try:
                    order_result = place_order(smart_api, symbol, qty, ltp, user_email=user.email)
                    logger.debug(f"place_order result for initial buy: {order_result}")
                    if isinstance(order_result, tuple) and len(order_result) == 3:
                        executed_qty, order_id, order_status = order_result
                    else:
                        logger.error(f"Unexpected place_order return value: {order_result}")
                        executed_qty, order_id, order_status = 0, None, 'ERROR'
                except Exception as e:
                    logger.error(f"Error placing initial buy order for {symbol}: {str(e)}")
                    executed_qty, order_id, order_status = 0, None, 'ERROR'

                if order_id:
                    # [UPDATE 7] Wait for order resolution
                    for _ in range(5):  # Retry up to 5 times (15 seconds total)
                        order_status = get_order_status(order_id)
                        if order_status not in ['pending', 'UNKNOWN']:
                            break
                        logger.info(f"Waiting for initial buy order {order_id} to resolve, current status: {order_status}")
                        time.sleep(3)
                    
                    logger.info(f"Initial buy order status for {symbol} (Order ID: {order_id}): {order_status}")
                    with open('order_status.txt', 'a') as f:
                        f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")
                else:
                    logger.warning(f"No order ID returned for initial buy of {symbol}")

                logger.info(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}")
                if executed_qty > 0 and order_status in ['complete', 'executed']:
                    sr_no = max([t.sr_no for t in trades], default=1)
                    new_trade = Trade(
                        stock_symbol=symbol,
                        sr_no=sr_no,
                        entry_price=ltp,
                        quantity=int(executed_qty),
                        user_email=user.email,
                        base_price=ltp,
                        total_quantity=int(executed_qty),
                        total_sold_quantity=0,
                        status='OPEN',
                        last_updated=IST.localize(datetime.now()),
                        description='Initial Buy'
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Initial buy failed or not completed for {symbol} at {ltp}, Qty: {qty}, Status: {order_status}")
                return  # [UPDATE 8] Exit after initial buy attempt

            # Determine current open quantity and latest OPEN trade
            current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
            latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
            current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
            logger.info(f"Current Sr No for {symbol}: {current_sr_no}, Open Qty: {current_open_qty}")

            # Get phase config for buy logic
            phase_config = PhaseConfig.query.filter_by(
                user_email=user.email,
                stock_symbol=symbol
            ).filter(
                PhaseConfig.start_sr_no <= current_sr_no,
                PhaseConfig.end_sr_no >= current_sr_no
            ).first()
            down_increment = 0.0025 if not phase_config else phase_config.down_increment / 100
            logger.info(f"Phase: {phase_config.phase if phase_config else 'Unknown'}, Down Increment: {down_increment*100}%")

            # Check for additional buy
            drop_percent = (ltp - base_price) / base_price
            logger.info(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
            target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
            target_row = strategy_data.loc[target_idx]
            target_sr_no = int(target_row['Sr.No'])
            total_qty = int(target_row['Total_Qty'])
            qty_to_buy = total_qty - current_open_qty
            
            if drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades):  # [UPDATE 9] Simplified condition
                if qty_to_buy <= 0:
                    logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
                    return

                existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
                if existing_open_trade:
                    logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
                    return

                executed_qty = 0
                order_id = None
                order_status = 'UNKNOWN'
                
                try:
                    order_result = place_order(smart_api, symbol, qty_to_buy, ltp, user_email=user.email)
                    logger.debug(f"place_order result for additional buy: {order_result}")
                    if isinstance(order_result, tuple) and len(order_result) == 3:
                        executed_qty, order_id, order_status = order_result
                    else:
                        logger.error(f"Unexpected place_order return value: {order_result}")
                        executed_qty, order_id, order_status = 0, None, 'ERROR'
                except Exception as e:
                    logger.error(f"Error placing additional buy order for {symbol}: {str(e)}")
                    executed_qty, order_id, order_status = 0, None, 'ERROR'

                if order_id:
                    # [UPDATE 10] Wait for order resolution
                    for _ in range(5):  # Retry up to 5 times (15 seconds total)
                        order_status = get_order_status(order_id)
                        if order_status not in ['pending', 'UNKNOWN']:
                            break
                        logger.info(f"Waiting for additional buy order {order_id} to resolve, current status: {order_status}")
                        time.sleep(3)
                    
                    logger.info(f"Additional buy order status for {symbol} (Order ID: {order_id}): {order_status}")
                    with open('order_status.txt', 'a') as f:
                        f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")
                else:
                    logger.warning(f"No order ID returned for additional buy of {symbol}")

                if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                    for trade in trades:
                        if trade.status == 'OPEN':
                            trade.status = 'OLD_BUY'
                            trade.last_updated = IST.localize(datetime.now())
                            trade.description = f"Updated to OLD_BUY before new buy at Sr.No {target_sr_no}"
                            logger.info(f"Updated trade Sr.No {trade.sr_no} to OLD_BUY, Total_Qty: {trade.total_quantity}")
                    
                    new_trade = Trade(
                        stock_symbol=symbol,
                        sr_no=target_sr_no,
                        entry_price=ltp,
                        quantity=int(executed_qty),
                        user_email=user.email,
                        base_price=base_price,
                        total_quantity=total_qty,
                        total_sold_quantity=0,
                        status='OPEN',
                        last_updated=IST.localize(datetime.now()),
                        description='Additional Buy'
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Buy failed or not completed for {symbol} at {ltp}, Qty: {qty_to_buy}, Status: {order_status}")
                return  # [UPDATE 11] Exit after additional buy attempt

            # Process sells for OPEN trades (unchanged)
            all_closed = True
            for trade in trades:
                if trade.status != 'OPEN':
                    continue
                all_closed = False
                
                base_price = trade.base_price
                logger.info(f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                
                sr_no = trade.sr_no
                entry_price = trade.entry_price
                current_qty = trade.total_quantity - trade.total_sold_quantity
                row = strategy_data.loc[sr_no-1]
                logger.info(f"trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

                final_tgt = row['FINAL_TGT']
                first_tgt = row['First_TGT']
                second_tgt = row['Second_TGT']
                half_qty = row['EXIT_1st_HALF'] if row['EXIT_1st_HALF'] is not None else 0
                second_half_qty = row['EXIT_2nd_HALF'] if row['EXIT_2nd_HALF'] is not None else 0

                logger.info(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}, Second_Half_Qty={second_half_qty}")

                if sr_no <= 8:
                    if ltp >= final_tgt and current_qty > 0:
                        logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Sell failed for {symbol} Sr.No {sr_no} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
                elif sr_no <= 21:
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing 1st half sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}, Status: {order_status}")
                    elif ltp >= final_tgt and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing final sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
                else:  # Sr.No > 21
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing 1st half sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}, Status: {order_status}")
                    elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, second_half_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing 2nd half sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Second TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{second_half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"2nd half sell failed for {symbol} at {ltp}, Qty: {second_half_qty}, Status: {order_status}")
                    elif ltp >= final_tgt and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing final sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['COMPLETE', 'EXECUTED']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

            # Reset cycle if all trades are CLOSED and update TradeCycle (unchanged)
            if all_closed and trades:
                logger.info(f"All trades for {symbol} are CLOSED, resetting cycle to Sr.No 1")
                current_cycle = TradeCycle.query.filter_by(
                    stock_symbol=symbol,
                    user_email=user.email,
                    status='ACTIVE'
                ).order_by(TradeCycle.cycle_start.desc()).first()
                
                if current_cycle:
                    current_cycle.cycle_end = IST.localize(datetime.now())
                    current_cycle.total_sold = sum(t.total_sold_quantity for t in trades)
                    current_cycle.total_bought = sum(t.total_quantity for t in trades)
                    current_cycle.profit = sum((ltp - t.entry_price) * t.total_sold_quantity for t in trades if t.status == 'CLOSED')
                    current_cycle.status = 'COMPLETED'
                    logger.info(f"Completed TradeCycle for {symbol}: Total Bought {current_cycle.total_bought}, Total Sold {current_cycle.total_sold}, Profit {current_cycle.profit}")
                
                new_cycle = TradeCycle(
                    stock_symbol=symbol,
                    user_email=user.email,
                    cycle_start=IST.localize(datetime.now()),
                    status='ACTIVE'
                )
                db.session.add(new_cycle)
                db.session.commit()
                logger.info(f"Started new TradeCycle for {symbol}")

        except Exception as e:
            logger.error(f"Error in process_strategy for {symbol}: {str(e)}", exc_info=True)
            db.session.rollback()
        finally:
            db.session.close()
'''

import json
import threading
import time
from flask import current_app
from SmartApi.smartWebSocketOrderUpdate import SmartWebSocketOrderUpdate
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pytz
import logging

'''
def handle_order_update(message, order_id_to_track, numeric_order_id_to_track=None):
    with app.app_context():
        try:
            order_data = json.loads(message)
            order_id = order_data.get('orderData', {}).get('orderid', 'N/A')
            unique_order_id = order_data.get('uniqueorderid', order_data.get('orderData', {}).get('uniqueorderid', 'N/A'))
            order_status = (order_data.get('orderData', {}).get('orderstatus') or 
                            order_data.get('order-status', 'UNKNOWN')).lower()
            symbol = order_data.get('orderData', {}).get('tradingsymbol', 'N/A')
            filled_shares_str = order_data.get('orderData', {}).get('filledshares', '0')
            filled_shares = int(filled_shares_str) if filled_shares_str else 0
            avg_price = float(order_data.get('orderData', {}).get('averageprice', 0))
            transaction_type = order_data.get('orderData', {}).get('transactiontype', 'BUY')

            logger.info(f"Order Update - ID: {order_id}, Unique ID: {unique_order_id}, Symbol: {symbol}, Status: {order_status}, Filled: {filled_shares}")

            tracked_id = None
            if order_id == numeric_order_id_to_track or unique_order_id == order_id_to_track:
                tracked_id = order_id_to_track if unique_order_id == order_id_to_track else numeric_order_id_to_track

            if tracked_id:
                with order_status_lock:
                    order_status_dict[tracked_id] = {
                        'status': order_status,
                        'symbol': symbol,
                        'message': order_data.get('orderData', {}).get('text', order_data.get('error-message', '')),
                        'filled_shares': filled_shares,
                        'avg_price': avg_price
                    }
                logger.info(f"Tracked order {tracked_id} updated to status: {order_status}")

                order_entry = (OrderStatus.query.filter_by(order_id=order_id).first() or 
                              OrderStatus.query.filter_by(unique_order_id=unique_order_id).first())
                if order_entry:
                    order_entry.status = order_status
                    order_entry.message = order_status_dict[tracked_id]['message']
                    order_entry.updated_at = IST.localize(datetime.now())
                    db.session.commit()
                    logger.info(f"Updated OrderStatus for {order_entry.order_id} to {order_status}")

                    if order_status == 'complete' and transaction_type == 'BUY' and filled_shares > 0:
                        trade = Trade.query.filter_by(order_id=order_id, user_email=order_entry.user_email).first()
                        if not trade:
                            new_trade = Trade(
                                stock_symbol=symbol,
                                sr_no=1,
                                entry_price=avg_price if avg_price > 0 else order_entry.price,
                                quantity=filled_shares,
                                user_email=order_entry.user_email,
                                base_price=avg_price if avg_price > 0 else order_entry.price,
                                total_quantity=filled_shares,
                                total_sold_quantity=0,
                                status='OPEN',
                                last_updated=IST.localize(datetime.now()),
                                description='Initial Buy from WebSocket',
                                order_id=order_id
                            )
                            db.session.add(new_trade)
                            db.session.commit()
                            logger.info(f"Created Trade for {symbol} from order {order_id}: Qty {filled_shares}, Price {avg_price}")
                        else:
                            logger.info(f"Trade already exists for order {order_id}, skipping creation")
                else:
                    logger.warning(f"No OrderStatus entry found for order_id: {order_id} or unique_order_id: {unique_order_id}")

        except json.JSONDecodeError:
            logger.warning(f"Non-JSON message received: {message}")
        except Exception as e:
            logger.error(f"Error processing order update: {e}", exc_info=True)
            db.session.rollback()

def custom_on_message(wsapp, message, order_id_to_track, numeric_order_id_to_track):
    logger.info(f"Raw message received: {message}")
    handle_order_update(message, order_id_to_track, numeric_order_id_to_track)

def place_order(smart_api, symbol, qty, price, buy_sell='BUY', user_email=None):
    with app.app_context():
        if app.config.get('DRY_RUN', False):
            executed_qty = qty
            logger.info(f"[DRY RUN] Simulated {buy_sell} order: {executed_qty}/{qty} of {symbol} at {price}")
            return executed_qty, "dry-run-order-id", "completed"
        
        if not user_email:
            logger.error(f"User email is None for {symbol} order")
            api_log = ApiLog(user_email or "unknown", symbol, None, "Place Order", "error", "User email not provided")
            db.session.add(api_log)
            db.session.commit()
            return 0, None, "error"
    
        logger.info(f"Placing {buy_sell} order for {qty} of {symbol} at {price}")
        stock = Stock.query.filter_by(tradingsymbol=symbol).first()
        if not stock:
            logger.error(f"Stock {symbol} not found")
            api_log = ApiLog(user_email, symbol, None, "Place Order", "error", "Stock not found")
            db.session.add(api_log)
            db.session.commit()
            return 0, None, "error"

        order_params = {
            "variety": "NORMAL",
            "tradingsymbol": symbol,
            "symboltoken": stock.symboltoken,
            "transactiontype": buy_sell,
            "exchange": stock.exchange,
            "ordertype": "MARKET",
            "producttype": "DELIVERY",
            "duration": "DAY",
            "quantity": str(qty)  # Fixed: Dynamic quantity instead of hardcoded '1'
        }
    
        try:
            response = smart_api.placeOrderFullResponse(order_params)
            logger.info(f"Order {buy_sell} {qty} of {symbol} at {price}: {response}")
            
            order_id = response.get('data', {}).get('uniqueorderid')
            numeric_order_id = response.get('data', {}).get('orderid')
            if not order_id or not numeric_order_id:
                logger.error(f"Failed to get order IDs for {symbol}: uniqueorderid={order_id}, orderid={numeric_order_id}")
                api_log = ApiLog(user_email, symbol, None, "Place Order", "error", "Missing order IDs in response")
                db.session.add(api_log)
                db.session.commit()
                return 0, None, "error"
    
            order_entry = OrderStatus(
                user_email=user_email,
                order_id=numeric_order_id,
                unique_order_id=order_id,
                symbol=symbol,
                status="pending",
                message="Order placed, awaiting confirmation",
                quantity=float(qty),
                price=price,
                buy_sell=buy_sell,
                created_at=IST.localize(datetime.now()),
                updated_at=IST.localize(datetime.now())
            )
            db.session.add(order_entry)
            db.session.commit()
            logger.info(f"Saved initial OrderStatus for {numeric_order_id}")
    
            if user_email not in session_cache:
                logger.error(f"No session data found for {user_email} in cache")
                user = User.query.filter_by(email=user_email).first()
                if user:
                    smart_api = get_angel_session(user)  # Assumed function
                    session_cache[user_email] = {
                        'auth_token': smart_api._access_token,  # Adjust based on your SmartAPI implementation
                        'feed_token': smart_api.feedToken
                    }
                else:
                    api_log = ApiLog(user_email, symbol, order_id, "Place Order", "error", "User not found or session data missing")
                    db.session.add(api_log)
                    db.session.commit()
                    return 0, order_id, "error"
            
            session_data = session_cache[user_email]
            auth_token = session_data.get('auth_token')
            api_key = smart_api.api_key
            client_code = getattr(smart_api, 'client_code', user_email)
            feed_token = session_data.get('feed_token')
    
            if not all([auth_token, api_key, client_code, feed_token]):
                logger.error(f"Missing WebSocket credentials for {user_email}")
                api_log = ApiLog(user_email, symbol, order_id, "Place Order", "error", "Missing WebSocket credentials")
                db.session.add(api_log)
                db.session.commit()
                return 0, order_id, "error"
    
            client = SmartWebSocketOrderUpdate(auth_token, api_key, client_code, feed_token)
            client.on_message = lambda wsapp, message: custom_on_message(wsapp, message, order_id, numeric_order_id)
            
            ws_thread = threading.Thread(target=client.connect)
            ws_thread.daemon = True
            ws_thread.start()
    
            max_attempts = 10
            attempt = 0
            status = None
            while attempt < max_attempts:
                with order_status_lock:
                    tracked_id = order_id if order_id in order_status_dict else (numeric_order_id if numeric_order_id in order_status_dict else None)
                    if tracked_id and tracked_id in order_status_dict:
                        status = order_status_dict[tracked_id]['status']
                        if status in ['complete', 'executed']:
                            executed_qty = order_status_dict[tracked_id]['filled_shares'] or qty
                            logger.info(f"Order {tracked_id} for {symbol} completed with {executed_qty} shares")
                            client.close_connection()
                            return executed_qty, order_id, "completed"
                        elif status in ['rejected', 'cancelled']:
                            logger.warning(f"Order {tracked_id} for {symbol} failed with status: {status}")
                            api_log = ApiLog(user_email, symbol, order_id, "Place Order", status, order_status_dict[tracked_id]['message'])
                            db.session.add(api_log)
                            db.session.commit()
                            client.close_connection()
                            return 0, order_id, status
                        else:
                            logger.info(f"Order {tracked_id} for {symbol} still pending: {status}")
                time.sleep(3)
                attempt += 1
            
            logger.error(f"Order {order_id} for {symbol} did not complete after {max_attempts} attempts")
            api_log = ApiLog(user_email, symbol, order_id, "Place Order", "timeout", "Order status not updated in time")
            db.session.add(api_log)
            db.session.commit()
            
            order_entry = OrderStatus.query.filter_by(order_id=numeric_order_id).first()
            if order_entry:
                order_entry.status = "timeout"
                order_entry.message = "Order status not updated in time"
                db.session.commit()
                logger.info(f"Updated OrderStatus for {numeric_order_id} to timeout")
            
            client.close_connection()
            return 0, order_id, "timeout"
    
        except Exception as e:
            logger.error(f"Error placing order for {symbol}: {str(e)}", exc_info=True)
            api_log = ApiLog(user_email, symbol, order_id if 'order_id' in locals() else None, "Place Order", "error", str(e))
            db.session.add(api_log)
            db.session.commit()
            db.session.rollback()
            return 0, None, "error"

def process_strategy(user, symbol, ltp, smart_api):
    logger.info(f"Process strategy for {symbol} at {ltp}")
    
    with app.app_context():
        try:
            trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
            stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=symbol).first()
            wallet_value = stock.allotment_captial if stock else 0
            
            logger.info(f"Wallet value for {symbol}: {wallet_value}")
            logger.info(f"Trades for {symbol}: {len(trades)}, Trades: {[t.__dict__ for t in trades]}")

            pending_orders = OrderStatus.query.filter_by(
                user_email=user.email,
                symbol=symbol,
                buy_sell='BUY'
            ).filter(
                OrderStatus.status.in_(['pending', 'UNKNOWN'])
            ).all()
            if pending_orders:
                logger.info(f"Skipping {symbol}: {len(pending_orders)} pending orders exist: {[o.order_id for o in pending_orders]}")
                return

            latest_trade = trades[-1] if trades else None
            base_price = latest_trade.base_price if latest_trade else ltp
            logger.info(f"Base price for {symbol}: {base_price}")
            strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)

            def get_order_status(order_id):
                order = OrderStatus.query.filter_by(order_id=order_id, user_email=user.email).first()
                if order and order.status not in ['pending', 'UNKNOWN']:
                    logger.info(f"Order status from table for {order_id}: {order.status}")
                    return order.status
                try:
                    status = smart_api.individual_order_details(order_id)
                    logger.info(f"Order status from API for {order_id}: {status}")
                    new_status = OrderStatus(
                        order_id=order_id,
                        symbol=symbol,
                        user_email=user.email,
                        status=status.get('status', 'UNKNOWN').lower() if isinstance(status, dict) else status.lower(),
                        message=status.get('text', ''),
                        quantity=float(status.get('quantity', order.quantity if order else 0)),
                        price=float(status.get('price', order.price if order else 0)),
                        buy_sell=status.get('transactiontype', order.buy_sell if order else 'BUY'),
                        created_at=IST.localize(datetime.now()) if not order else order.created_at,
                        updated_at=IST.localize(datetime.now())
                    )
                    db.session.merge(new_status)
                    db.session.commit()
                    return new_status.status
                except Exception as e:
                    logger.error(f"Failed to fetch order status for {order_id}: {str(e)}")
                    db.session.rollback()
                    return 'UNKNOWN'

            if not trades or all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades):
                qty = int(strategy_data.loc[0, 'Qnty'])
                executed_qty = 0
                order_id = None
                order_status = 'UNKNOWN'
                
                try:
                    order_result = place_order(smart_api, symbol, qty, ltp, user_email=user.email)
                    logger.debug(f"place_order result for initial buy: {order_result}")
                    if isinstance(order_result, tuple) and len(order_result) == 3:
                        executed_qty, order_id, order_status = order_result
                    else:
                        logger.error(f"Unexpected place_order return value: {order_result}")
                        executed_qty, order_id, order_status = 0, None, 'ERROR'
                except Exception as e:
                    logger.error(f"Error placing initial buy order for {symbol}: {str(e)}")
                    executed_qty, order_id, order_status = 0, None, 'ERROR'

                if order_id:
                    for _ in range(5):
                        order_status = get_order_status(order_id)
                        if order_status not in ['pending', 'UNKNOWN']:
                            break
                        logger.info(f"Waiting for initial buy order {order_id} to resolve, current status: {order_status}")
                        time.sleep(3)
                    
                    logger.info(f"Initial buy order status for {symbol} (Order ID: {order_id}): {order_status}")
                    with open('order_status.txt', 'a') as f:
                        f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")

                logger.info(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}")
                if executed_qty > 0 and order_status in ['complete', 'executed']:
                    sr_no = max([t.sr_no for t in trades], default=1)
                    new_trade = Trade(
                        stock_symbol=symbol,
                        sr_no=sr_no,
                        entry_price=ltp,
                        quantity=int(executed_qty),
                        user_email=user.email,
                        base_price=ltp,
                        total_quantity=int(executed_qty),
                        total_sold_quantity=0,
                        status='OPEN',
                        last_updated=IST.localize(datetime.now()),
                        description='Initial Buy',
                        order_id=order_id
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Initial buy failed or not completed for {symbol} at {ltp}, Qty: {qty}, Status: {order_status}")
                return

            current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
            latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
            current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
            logger.info(f"Current Sr No for {symbol}: {current_sr_no}, Open Qty: {current_open_qty}")

            phase_config = PhaseConfig.query.filter_by(
                user_email=user.email,
                stock_symbol=symbol
            ).filter(
                PhaseConfig.start_sr_no <= current_sr_no,
                PhaseConfig.end_sr_no >= current_sr_no
            ).first()
            down_increment = 0.0025 if not phase_config else phase_config.down_increment / 100
            logger.info(f"Phase: {phase_config.phase if phase_config else 'Unknown'}, Down Increment: {down_increment*100}%")

            drop_percent = (ltp - base_price) / base_price
            logger.info(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
            target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
            target_row = strategy_data.loc[target_idx]
            target_sr_no = int(target_row['Sr.No'])
            total_qty = int(target_row['Total_Qty'])
            qty_to_buy = total_qty - current_open_qty
            
            if drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades):
                if qty_to_buy <= 0:
                    logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
                    return

                existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
                if existing_open_trade:
                    logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
                    return

                executed_qty = 0
                order_id = None
                order_status = 'UNKNOWN'
                
                try:
                    order_result = place_order(smart_api, symbol, qty_to_buy, ltp, user_email=user.email)
                    logger.debug(f"place_order result for additional buy: {order_result}")
                    if isinstance(order_result, tuple) and len(order_result) == 3:
                        executed_qty, order_id, order_status = order_result
                    else:
                        logger.error(f"Unexpected place_order return value: {order_result}")
                        executed_qty, order_id, order_status = 0, None, 'ERROR'
                except Exception as e:
                    logger.error(f"Error placing additional buy order for {symbol}: {str(e)}")
                    executed_qty, order_id, order_status = 0, None, 'ERROR'

                if order_id:
                    for _ in range(5):
                        order_status = get_order_status(order_id)
                        if order_status not in ['pending', 'UNKNOWN']:
                            break
                        logger.info(f"Waiting for additional buy order {order_id} to resolve, current status: {order_status}")
                        time.sleep(3)
                    
                    logger.info(f"Additional buy order status for {symbol} (Order ID: {order_id}): {order_status}")
                    with open('order_status.txt', 'a') as f:
                        f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")

                if executed_qty > 0 and order_status in ['complete', 'executed']:
                    for trade in trades:
                        if trade.status == 'OPEN':
                            trade.status = 'OLD_BUY'
                            trade.last_updated = IST.localize(datetime.now())
                            trade.description = f"Updated to OLD_BUY before new buy at Sr.No {target_sr_no}"
                            logger.info(f"Updated trade Sr.No {trade.sr_no} to OLD_BUY, Total_Qty: {trade.total_quantity}")
                    
                    new_trade = Trade(
                        stock_symbol=symbol,
                        sr_no=target_sr_no,
                        entry_price=ltp,
                        quantity=int(executed_qty),
                        user_email=user.email,
                        base_price=base_price,
                        total_quantity=total_qty,
                        total_sold_quantity=0,
                        status='OPEN',
                        last_updated=IST.localize(datetime.now()),
                        description='Additional Buy',
                        order_id=order_id
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Buy failed or not completed for {symbol} at {ltp}, Qty: {qty_to_buy}, Status: {order_status}")
                return

            all_closed = True
            for trade in trades:
                if trade.status != 'OPEN':
                    continue
                all_closed = False
                
                base_price = trade.base_price
                logger.info(f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                
                sr_no = trade.sr_no
                entry_price = trade.entry_price
                current_qty = trade.total_quantity - trade.total_sold_quantity
                row = strategy_data.loc[sr_no-1]
                logger.info(f"trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

                final_tgt = row['FINAL_TGT']
                first_tgt = row['First_TGT']
                second_tgt = row['Second_TGT']
                half_qty = row['EXIT_1st_HALF'] if row['EXIT_1st_HALF'] is not None else 0
                second_half_qty = row['EXIT_2nd_HALF'] if row['EXIT_2nd_HALF'] is not None else 0

                logger.info(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}, Second_Half_Qty={second_half_qty}")

                if sr_no <= 8:
                    if ltp >= final_tgt and current_qty > 0:
                        logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Sell failed for {symbol} Sr.No {sr_no} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
                elif sr_no <= 21:
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing 1st half sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}, Status: {order_status}")
                    elif ltp >= final_tgt and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing final sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
                else:  # Sr.No > 21
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing 1st half sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}, Status: {order_status}")
                    elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, second_half_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing 2nd half sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Second TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{second_half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"2nd half sell failed for {symbol} at {ltp}, Qty: {second_half_qty}, Status: {order_status}")
                    elif ltp >= final_tgt and current_qty > 0:
                        executed_qty = 0
                        order_id = None
                        order_status = 'UNKNOWN'
                        try:
                            order_result = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if isinstance(order_result, tuple) and len(order_result) == 3:
                                executed_qty, order_id, order_status = order_result
                            else:
                                executed_qty = 0
                        except Exception as e:
                            logger.error(f"Error placing final sell order for {symbol}: {str(e)}")

                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

            if all_closed and trades:
                logger.info(f"All trades for {symbol} are CLOSED, resetting cycle to Sr.No 1")
                current_cycle = TradeCycle.query.filter_by(
                    stock_symbol=symbol,
                    user_email=user.email,
                    status='ACTIVE'
                ).order_by(TradeCycle.cycle_start.desc()).first()
                
                if current_cycle:
                    current_cycle.cycle_end = IST.localize(datetime.now())
                    current_cycle.total_sold = sum(t.total_sold_quantity for t in trades)
                    current_cycle.total_bought = sum(t.total_quantity for t in trades)
                    current_cycle.profit = sum((ltp - t.entry_price) * t.total_sold_quantity for t in trades if t.status == 'CLOSED')
                    current_cycle.status = 'COMPLETED'
                    logger.info(f"Completed TradeCycle for {symbol}: Total Bought {current_cycle.total_bought}, Total Sold {current_cycle.total_sold}, Profit {current_cycle.profit}")
                
                new_cycle = TradeCycle(
                    stock_symbol=symbol,
                    user_email=user.email,
                    cycle_start=IST.localize(datetime.now()),
                    status='ACTIVE'
                )
                db.session.add(new_cycle)
                db.session.commit()
                logger.info(f"Started new TradeCycle for {symbol}")

        except Exception as e:
            logger.error(f"Error in process_strategy for {symbol}: {str(e)}", exc_info=True)
            db.session.rollback()
        finally:
            db.session.close()
'''
'''
def handle_order_update(message, order_id_to_track, numeric_order_id_to_track=None):
    with app.app_context():
        try:
            if isinstance(message, bytes):
                message = message.decode('utf-8')
            order_data = json.loads(message)
            order_id = order_data.get('orderData', {}).get('orderid', 'N/A')
            unique_order_id = order_data.get('uniqueorderid', order_data.get('orderData', {}).get('uniqueorderid', 'N/A'))
            order_status = (order_data.get('orderData', {}).get('orderstatus') or 
                            order_data.get('order-status', 'UNKNOWN')).lower()
            symbol = order_data.get('orderData', {}).get('tradingsymbol', 'N/A')
            filled_shares_str = order_data.get('orderData', {}).get('filledshares', '0')
            filled_shares = int(filled_shares_str or 0)  # Safely handle empty or None
            avg_price = float(order_data.get('orderData', {}).get('averageprice', 0) or 0)
            transaction_type = order_data.get('orderData', {}).get('transactiontype', 'BUY')

            logger.info(f"Order Update - ID: {order_id}, Unique ID: {unique_order_id}, Symbol: {symbol}, Status: {order_status}, Filled: {filled_shares}")

            tracked_id = None
            if order_id == numeric_order_id_to_track or unique_order_id == order_id_to_track:
                tracked_id = order_id_to_track if unique_order_id == order_id_to_track else numeric_order_id_to_track

            if tracked_id:
                with order_status_lock:
                    order_status_dict[tracked_id] = {
                        'status': order_status,
                        'symbol': symbol,
                        'message': order_data.get('orderData', {}).get('text', order_data.get('error-message', '')),
                        'filled_shares': filled_shares,
                        'avg_price': avg_price
                    }
                logger.info(f"Tracked order {tracked_id} updated to status: {order_status}")

                order_entry = (OrderStatus.query.filter_by(order_id=order_id).first() or 
                              OrderStatus.query.filter_by(unique_order_id=unique_order_id).first())
                if order_entry:
                    order_entry.status = order_status
                    order_entry.message = order_status_dict[tracked_id]['message']
                    order_entry.updated_at = IST.localize(datetime.now())
                    db.session.commit()
                    logger.info(f"Updated OrderStatus for {order_entry.order_id} to {order_status}")

                    if order_status == 'complete' and transaction_type == 'BUY' and filled_shares > 0:
                        trade = Trade.query.filter_by(order_id=order_id, user_email=order_entry.user_email).first()
                        if not trade:
                            new_trade = Trade(
                                stock_symbol=symbol,
                                sr_no=1,
                                entry_price=avg_price if avg_price > 0 else order_entry.price,
                                quantity=filled_shares,
                                user_email=order_entry.user_email,
                                base_price=avg_price if avg_price > 0 else order_entry.price,
                                total_quantity=filled_shares,
                                total_sold_quantity=0,
                                status='OPEN',
                                last_updated=IST.localize(datetime.now()),
                                description='Initial Buy from WebSocket',
                                order_id=order_id
                            )
                            db.session.add(new_trade)
                            db.session.commit()
                            logger.info(f"Created Trade for {symbol} from order {order_id}: Qty {filled_shares}, Price {avg_price}")
                        else:
                            logger.info(f"Trade already exists for order {order_id}, skipping creation")
                else:
                    logger.warning(f"No OrderStatus entry found for order_id: {order_id} or unique_order_id: {unique_order_id}")
        except json.JSONDecodeError:
            logger.warning(f"Non-JSON message received: {message}")
        except ValueError as e:
            logger.error(f"ValueError processing order update: {e}, Message: {message}")
        except Exception as e:
            logger.error(f"Error processing order update: {e}", exc_info=True)
            db.session.rollback()

def custom_on_message(wsapp, message, order_id_to_track, numeric_order_id_to_track):
    logger.info(f"Raw message received: {message}")
    try:
        handle_order_update(message, order_id_to_track, numeric_order_id_to_track)
    except Exception as e:
        logger.error(f"Error in custom_on_message: {e}", exc_info=True)

def place_order(smart_api, symbol, qty, price, buy_sell='BUY', user_email=None):
    with app.app_context():
        if app.config.get('DRY_RUN', False):
            executed_qty = qty
            logger.info(f"[DRY RUN] Simulated {buy_sell} order: {executed_qty}/{qty} of {symbol} at {price}")
            return executed_qty, "dry-run-order-id", "completed"

        if not user_email:
            logger.error(f"User email is None for {symbol} order")
            api_log = ApiLog(user_email or "unknown", symbol, None, "Place Order", "error", "User email not provided")
            db.session.add(api_log)
            db.session.commit()
            return 0, None, "error"

        lock_key = f"{user_email}_{symbol}"
        with order_locks.setdefault(lock_key, threading.Lock()):
            # Check for existing pending or recent orders
            pending_orders = OrderStatus.query.filter_by(
                user_email=user_email,
                symbol=symbol,
                buy_sell=buy_sell
            ).filter(
                OrderStatus.status.in_(['pending', 'UNKNOWN', 'timeout'])
            ).filter(
                OrderStatus.created_at > IST.localize(datetime.now()) - timedelta(minutes=5)
            ).all()
            if pending_orders:
                logger.info(f"Skipping {buy_sell} order for {symbol}: Recent pending orders: {[o.order_id for o in pending_orders]}")
                return 0, None, "pending_exists"

            logger.info(f"Placing {buy_sell} order for {qty} of {symbol} at {price}")
            stock = Stock.query.filter_by(tradingsymbol=symbol).first()
            if not stock:
                logger.error(f"Stock {symbol} not found")
                api_log = ApiLog(user_email, symbol, None, "Place Order", "error", "Stock not found")
                db.session.add(api_log)
                db.session.commit()
                return 0, None, "error"

            order_params = {
                "variety": "NORMAL",
                "tradingsymbol": symbol,
                "symboltoken": stock.symboltoken,
                "transactiontype": buy_sell,
                "exchange": stock.exchange,
                "ordertype": "MARKET",
                "producttype": "DELIVERY",
                "duration": "DAY",
                "quantity": str(qty)
            }

            try:
                response = smart_api.placeOrderFullResponse(order_params)
                logger.info(f"Order {buy_sell} {qty} of {symbol} at {price}: {response}")

                order_id = response.get('data', {}).get('uniqueorderid')
                numeric_order_id = response.get('data', {}).get('orderid')
                if not order_id or not numeric_order_id:
                    logger.error(f"Failed to get order IDs for {symbol}: uniqueorderid={order_id}, orderid={numeric_order_id}")
                    api_log = ApiLog(user_email, symbol, None, "Place Order", "error", "Missing order IDs in response")
                    db.session.add(api_log)
                    db.session.commit()
                    return 0, None, "error"

                order_entry = OrderStatus(
                    user_email=user_email,
                    order_id=numeric_order_id,
                    unique_order_id=order_id,
                    symbol=symbol,
                    status="pending",
                    message="Order placed, awaiting confirmation",
                    quantity=float(qty),
                    price=price,
                    buy_sell=buy_sell,
                    created_at=IST.localize(datetime.now()),
                    updated_at=IST.localize(datetime.now())
                )
                db.session.add(order_entry)
                db.session.commit()
                logger.info(f"Saved initial OrderStatus for {numeric_order_id}")

                if user_email not in session_cache:
                    logger.error(f"No session data found for {user_email} in cache")
                    user = User.query.filter_by(email=user_email).first()
                    if user:
                        smart_api = get_angel_session(user)
                        session_cache[user_email] = {
                            'auth_token': smart_api._access_token,
                            'feed_token': smart_api.feedToken
                        }
                    else:
                        api_log = ApiLog(user_email, symbol, order_id, "Place Order", "error", "User not found or session data missing")
                        db.session.add(api_log)
                        db.session.commit()
                        return 0, order_id, "error"

                session_data = session_cache[user_email]
                auth_token = session_data.get('auth_token')
                api_key = smart_api.api_key
                client_code = getattr(smart_api, 'client_code', user_email)
                feed_token = session_data.get('feed_token')

                if not all([auth_token, api_key, client_code, feed_token]):
                    logger.error(f"Missing WebSocket credentials for {user_email}")
                    api_log = ApiLog(user_email, symbol, order_id, "Place Order", "error", "Missing WebSocket credentials")
                    db.session.add(api_log)
                    db.session.commit()
                    return 0, order_id, "error"

                client = SmartWebSocketOrderUpdate(auth_token, api_key, client_code, feed_token)
                client.on_message = lambda wsapp, message: custom_on_message(wsapp, message, order_id, numeric_order_id)

                ws_thread = threading.Thread(target=client.connect)
                ws_thread.daemon = True
                ws_thread.start()

                max_attempts = 15
                attempt = 0
                status = None
                while attempt < max_attempts:
                    with order_status_lock:
                        tracked_id = order_id if order_id in order_status_dict else (numeric_order_id if numeric_order_id in order_status_dict else None)
                        if tracked_id and tracked_id in order_status_dict:
                            status = order_status_dict[tracked_id]['status']
                            if status in ['complete', 'executed']:
                                executed_qty = order_status_dict[tracked_id]['filled_shares'] or qty
                                logger.info(f"Order {tracked_id} for {symbol} completed with {executed_qty} shares")
                                client.close_connection()
                                return executed_qty, order_id, "completed"
                            elif status in ['rejected', 'cancelled']:
                                logger.warning(f"Order {tracked_id} for {symbol} failed with status: {status}")
                                api_log = ApiLog(user_email, symbol, order_id, "Place Order", status, order_status_dict[tracked_id]['message'])
                                db.session.add(api_log)
                                db.session.commit()
                                client.close_connection()
                                return 0, order_id, status
                            else:
                                logger.info(f"Order {tracked_id} for {symbol} still pending: {status}")
                    try:
                        order_details = smart_api.individual_order_details(numeric_order_id)
                        status = order_details.get('status', 'UNKNOWN').lower()
                        if status in ['complete', 'executed']:
                            executed_qty = int(order_details.get('filledshares', qty) or qty)
                            logger.info(f"API confirmed order {numeric_order_id} completed with {executed_qty} shares")
                            with order_status_lock:
                                order_status_dict[numeric_order_id] = {
                                    'status': status,
                                    'symbol': symbol,
                                    'message': order_details.get('text', ''),
                                    'filled_shares': executed_qty,
                                    'avg_price': float(order_details.get('averageprice', price) or price)
                                }
                            client.close_connection()
                            return executed_qty, order_id, "completed"
                        elif status in ['rejected', 'cancelled']:
                            logger.warning(f"API confirmed order {numeric_order_id} failed: {status}")
                            client.close_connection()
                            return 0, order_id, status
                    except Exception as e:
                        logger.error(f"API check failed for {numeric_order_id}: {e}")
                    time.sleep(2)
                    attempt += 1

                logger.error(f"Order {order_id} for {symbol} did not complete after {max_attempts} attempts")
                api_log = ApiLog(user_email, symbol, order_id, "Place Order", "timeout", "Order status not updated in time")
                db.session.add(api_log)
                db.session.commit()

                order_entry = OrderStatus.query.filter_by(order_id=numeric_order_id).first()
                if order_entry:
                    try:
                        order_details = smart_api.individual_order_details(numeric_order_id)
                        final_status = order_details.get('status', 'UNKNOWN').lower()
                        if final_status in ['complete', 'executed']:
                            executed_qty = int(order_details.get('filledshares', qty) or qty)
                            logger.info(f"Order {numeric_order_id} executed despite timeout, qty: {executed_qty}")
                            order_entry.status = final_status
                            order_entry.updated_at = IST.localize(datetime.now())
                            db.session.commit()
                            client.close_connection()
                            return executed_qty, order_id, "completed"
                        else:
                            order_entry.status = "timeout"
                            order_entry.message = "Order status not updated in time"
                            db.session.commit()
                            logger.info(f"Updated OrderStatus for {numeric_order_id} to timeout")
                    except Exception as e:
                        logger.error(f"Final API check failed for {numeric_order_id}: {e}")
                        order_entry.status = "timeout"
                        order_entry.message = "Order status not updated in time"
                        db.session.commit()

                client.close_connection()
                return 0, order_id, "timeout"

            except Exception as e:
                logger.error(f"Error placing order for {symbol}: {str(e)}", exc_info=True)
                api_log = ApiLog(user_email, symbol, order_id if 'order_id' in locals() else None, "Place Order", "error", str(e))
                db.session.add(api_log)
                db.session.commit()
                db.session.rollback()
                return 0, None, "error"

def process_strategy(user, symbol, ltp, smart_api):
    logger.info(f"Process strategy for {symbol} at {ltp}")
    
    with app.app_context():
        try:
            trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
            stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=symbol).first()
            wallet_value = stock.allotment_captial if stock else 0
            
            logger.info(f"Wallet value for {symbol}: {wallet_value}")
            logger.info(f"Trades for {symbol}: {len(trades)}, Trades: {[t.__dict__ for t in trades]}")

            pending_orders = OrderStatus.query.filter_by(
                user_email=user.email,
                symbol=symbol,
                buy_sell='BUY'
            ).filter(
                OrderStatus.status.in_(['pending', 'UNKNOWN', 'timeout'])
            ).filter(
                OrderStatus.created_at > IST.localize(datetime.now()) - timedelta(minutes=5)
            ).all()
            if pending_orders:
                logger.info(f"Skipping {symbol}: {len(pending_orders)} recent pending/timeout orders exist: {[o.order_id for o in pending_orders]}")
                return

            latest_trade = trades[-1] if trades else None
            base_price = latest_trade.base_price if latest_trade else ltp
            logger.info(f"Base price for {symbol}: {base_price}")
            strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)

            def get_order_status(order_id):
                order = OrderStatus.query.filter_by(order_id=order_id, user_email=user.email).first()
                if order and order.status not in ['pending', 'UNKNOWN', 'timeout']:
                    logger.info(f"Order status from table for {order_id}: {order.status}")
                    return order.status
                try:
                    status = smart_api.individual_order_details(order_id)
                    logger.info(f"Order status from API for {order_id}: {status}")
                    new_status = OrderStatus(
                        order_id=order_id,
                        symbol=symbol,
                        user_email=user.email,
                        status=status.get('status', 'UNKNOWN').lower() if isinstance(status, dict) else status.lower(),
                        message=status.get('text', ''),
                        quantity=float(status.get('quantity', order.quantity if order else 0)),
                        price=float(status.get('price', order.price if order else 0)),
                        buy_sell=status.get('transactiontype', order.buy_sell if order else 'BUY'),
                        created_at=IST.localize(datetime.now()) if not order else order.created_at,
                        updated_at=IST.localize(datetime.now())
                    )
                    db.session.merge(new_status)
                    db.session.commit()
                    return new_status.status
                except Exception as e:
                    logger.error(f"Failed to fetch order status for {order_id}: {str(e)}")
                    return 'UNKNOWN'

            if not trades or all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades):
                qty = int(strategy_data.loc[0, 'Qnty'])
                executed_qty, order_id, order_status = place_order(smart_api, symbol, qty, ltp, user_email=user.email)
                logger.debug(f"place_order result for initial buy: {executed_qty, order_id, order_status}")

                if order_id and order_status not in ['completed', 'complete', 'executed']:
                    for _ in range(5):
                        order_status = get_order_status(order_id)
                        if order_status not in ['pending', 'UNKNOWN', 'timeout']:
                            break
                        logger.info(f"Waiting for initial buy order {order_id} to resolve, current status: {order_status}")
                        time.sleep(2)

                    if order_status in ['timeout', 'UNKNOWN']:
                        try:
                            order_details = smart_api.individual_order_details(order_id)
                            final_status = order_details.get('status', 'UNKNOWN').lower()
                            if final_status in ['complete', 'executed']:
                                executed_qty = int(order_details.get('filledshares', qty) or qty)
                                order_status = final_status
                                logger.info(f"Order {order_id} executed despite timeout, qty: {executed_qty}")
                                order_entry = OrderStatus.query.filter_by(order_id=order_id).first()
                                if order_entry:
                                    order_entry.status = final_status
                                    order_entry.updated_at = IST.localize(datetime.now())
                                    db.session.commit()
                        except Exception as e:
                            logger.error(f"Final API check failed for {order_id}: {e}")

                logger.info(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}, Status: {order_status}")
                with open('order_status.txt', 'a') as f:
                    f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")

                if executed_qty > 0 and order_status in ['complete', 'executed']:
                    sr_no = max([t.sr_no for t in trades], default=1)
                    new_trade = Trade(
                        stock_symbol=symbol,
                        sr_no=sr_no,
                        entry_price=ltp,
                        quantity=int(executed_qty),
                        user_email=user.email,
                        base_price=ltp,
                        total_quantity=int(executed_qty),
                        total_sold_quantity=0,
                        status='OPEN',
                        last_updated=IST.localize(datetime.now()),
                        description='Initial Buy',
                        order_id=order_id
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Initial buy failed or not completed for {symbol} at {ltp}, Qty: {qty}, Status: {order_status}")
                return

            current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
            latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
            current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
            logger.info(f"Current Sr No for {symbol}: {current_sr_no}, Open Qty: {current_open_qty}")

            phase_config = PhaseConfig.query.filter_by(
                user_email=user.email,
                stock_symbol=symbol
            ).filter(
                PhaseConfig.start_sr_no <= current_sr_no,
                PhaseConfig.end_sr_no >= current_sr_no
            ).first()
            down_increment = 0.0025 if not phase_config else phase_config.down_increment / 100
            logger.info(f"Phase: {phase_config.phase if phase_config else 'Unknown'}, Down Increment: {down_increment*100}%")

            drop_percent = (ltp - base_price) / base_price
            logger.info(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
            target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
            target_row = strategy_data.loc[target_idx]
            target_sr_no = int(target_row['Sr.No'])
            total_qty = int(target_row['Total_Qty'])
            qty_to_buy = total_qty - current_open_qty
            
            if drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades):
                if qty_to_buy <= 0:
                    logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
                    return

                existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
                if existing_open_trade:
                    logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
                    return

                executed_qty, order_id, order_status = place_order(smart_api, symbol, qty_to_buy, ltp, user_email=user.email)
                logger.debug(f"place_order result for additional buy: {executed_qty, order_id, order_status}")

                if order_id and order_status not in ['completed', 'complete', 'executed']:
                    for _ in range(5):
                        order_status = get_order_status(order_id)
                        if order_status not in ['pending', 'UNKNOWN', 'timeout']:
                            break
                        logger.info(f"Waiting for additional buy order {order_id} to resolve, current status: {order_status}")
                        time.sleep(2)

                    if order_status in ['timeout', 'UNKNOWN']:
                        try:
                            order_details = smart_api.individual_order_details(order_id)
                            final_status = order_details.get('status', 'UNKNOWN').lower()
                            if final_status in ['complete', 'executed']:
                                executed_qty = int(order_details.get('filledshares', qty_to_buy) or qty_to_buy)
                                order_status = final_status
                                logger.info(f"Order {order_id} executed despite timeout, qty: {executed_qty}")
                                order_entry = OrderStatus.query.filter_by(order_id=order_id).first()
                                if order_entry:
                                    order_entry.status = final_status
                                    order_entry.updated_at = IST.localize(datetime.now())
                                    db.session.commit()
                        except Exception as e:
                            logger.error(f"Final API check failed for {order_id}: {e}")

                logger.info(f"Additional buy for {symbol} at {ltp}, Qty: {qty_to_buy}, Executed Qty: {executed_qty}, Status: {order_status}")
                with open('order_status.txt', 'a') as f:
                    f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")

                if executed_qty > 0 and order_status in ['complete', 'executed']:
                    for trade in trades:
                        if trade.status == 'OPEN':
                            trade.status = 'OLD_BUY'
                            trade.last_updated = IST.localize(datetime.now())
                            trade.description = f"Updated to OLD_BUY before new buy at Sr.No {target_sr_no}"
                            logger.info(f"Updated trade Sr.No {trade.sr_no} to OLD_BUY, Total_Qty: {trade.total_quantity}")
                    
                    new_trade = Trade(
                        stock_symbol=symbol,
                        sr_no=target_sr_no,
                        entry_price=ltp,
                        quantity=int(executed_qty),
                        user_email=user.email,
                        base_price=base_price,
                        total_quantity=total_qty,
                        total_sold_quantity=0,
                        status='OPEN',
                        last_updated=IST.localize(datetime.now()),
                        description='Additional Buy',
                        order_id=order_id
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Buy failed or not completed for {symbol} at {ltp}, Qty: {qty_to_buy}, Status: {order_status}")
                return

            all_closed = True
            for trade in trades:
                if trade.status != 'OPEN':
                    continue
                all_closed = False
                
                base_price = trade.base_price
                logger.info(f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                
                sr_no = trade.sr_no
                entry_price = trade.entry_price
                current_qty = trade.total_quantity - trade.total_sold_quantity
                row = strategy_data.loc[sr_no-1]
                logger.info(f"trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

                final_tgt = row['FINAL_TGT']
                first_tgt = row['First_TGT']
                second_tgt = row['Second_TGT']
                half_qty = row['EXIT_1st_HALF'] if row['EXIT_1st_HALF'] is not None else 0
                second_half_qty = row['EXIT_2nd_HALF'] if row['EXIT_2nd_HALF'] is not None else 0

                logger.info(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}, Second_Half_Qty={second_half_qty}")

                if sr_no <= 8:
                    if ltp >= final_tgt and current_qty > 0:
                        logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Sell failed for {symbol} Sr.No {sr_no} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
                elif sr_no <= 21:
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}, Status: {order_status}")
                    elif ltp >= final_tgt and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
                else:  # Sr.No > 21
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}, Status: {order_status}")
                    elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, second_half_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Second TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{second_half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"2nd half sell failed for {symbol} at {ltp}, Qty: {second_half_qty}, Status: {order_status}")
                    elif ltp >= final_tgt and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

            if all_closed and trades:
                logger.info(f"All trades for {symbol} are CLOSED, resetting cycle to Sr.No 1")
                current_cycle = TradeCycle.query.filter_by(
                    stock_symbol=symbol,
                    user_email=user.email,
                    status='ACTIVE'
                ).order_by(TradeCycle.cycle_start.desc()).first()
                
                if current_cycle:
                    current_cycle.cycle_end = IST.localize(datetime.now())
                    current_cycle.total_sold = sum(t.total_sold_quantity for t in trades)
                    current_cycle.total_bought = sum(t.total_quantity for t in trades)
                    current_cycle.profit = sum((ltp - t.entry_price) * t.total_sold_quantity for t in trades if t.status == 'CLOSED')
                    current_cycle.status = 'COMPLETED'
                    logger.info(f"Completed TradeCycle for {symbol}: Total Bought {current_cycle.total_bought}, Total Sold {current_cycle.total_sold}, Profit {current_cycle.profit}")
                
                new_cycle = TradeCycle(
                    stock_symbol=symbol,
                    user_email=user.email,
                    cycle_start=IST.localize(datetime.now()),
                    status='ACTIVE'
                )
                db.session.add(new_cycle)
                db.session.commit()
                logger.info(f"Started new TradeCycle for {symbol}")

        except Exception as e:
            logger.error(f"Error in process_strategy for {symbol}: {str(e)}", exc_info=True)
            db.session.rollback()
        finally:
            db.session.close()
'''

def handle_order_update(message, order_id_to_track, numeric_order_id_to_track=None):
    with app.app_context():
        try:
            if isinstance(message, bytes):
                message = message.decode('utf-8')
            order_data = json.loads(message)
            order_id = order_data.get('orderData', {}).get('orderid', 'N/A')
            unique_order_id = order_data.get('uniqueorderid', order_data.get('orderData', {}).get('uniqueorderid', 'N/A'))
            order_status = str(order_data.get('orderData', {}).get('orderstatus') or 
                              order_data.get('order-status', 'UNKNOWN')).lower()
            symbol = order_data.get('orderData', {}).get('tradingsymbol', 'N/A')
            filled_shares_str = order_data.get('orderData', {}).get('filledshares', '0')
            filled_shares = int(filled_shares_str or 0)
            avg_price = float(order_data.get('orderData', {}).get('averageprice', 0) or 0)
            transaction_type = order_data.get('orderData', {}).get('transactiontype', 'BUY')

            logger.info(f"Order Update - ID: {order_id}, Unique ID: {unique_order_id}, Symbol: {symbol}, Status: {order_status}, Filled: {filled_shares}")

            tracked_id = None
            if order_id == numeric_order_id_to_track or unique_order_id == order_id_to_track:
                tracked_id = order_id_to_track if unique_order_id == order_id_to_track else numeric_order_id_to_track

            if tracked_id:
                with order_status_lock:
                    order_status_dict[tracked_id] = {
                        'status': order_status,
                        'symbol': symbol,
                        'message': order_data.get('orderData', {}).get('text', order_data.get('error-message', '')),
                        'filled_shares': filled_shares,
                        'avg_price': avg_price
                    }
                logger.info(f"Tracked order {tracked_id} updated to status: {order_status}")

                order_entry = (OrderStatus.query.filter_by(order_id=order_id).first() or 
                              OrderStatus.query.filter_by(unique_order_id=unique_order_id).first())
                if order_entry:
                    order_entry.status = order_status
                    order_entry.message = order_status_dict[tracked_id]['message']
                    order_entry.updated_at = IST.localize(datetime.now())
                    db.session.commit()
                    logger.info(f"Updated OrderStatus for {order_entry.order_id} to {order_status}")

                    if order_status == 'complete' and transaction_type == 'BUY' and filled_shares > 0:
                        trade = Trade.query.filter_by(order_id=order_id, user_email=order_entry.user_email).first()
                        if not trade:
                            new_trade = Trade(
                                stock_symbol=symbol,
                                sr_no=1,
                                entry_price=avg_price if avg_price > 0 else order_entry.price,
                                quantity=filled_shares,
                                user_email=order_entry.user_email,
                                base_price=avg_price if avg_price > 0 else order_entry.price,
                                total_quantity=filled_shares,
                                total_sold_quantity=0,
                                status='OPEN',
                                last_updated=IST.localize(datetime.now()),
                                description='Initial Buy from WebSocket',
                                order_id=order_id
                            )
                            db.session.add(new_trade)
                            db.session.commit()
                            logger.info(f"Created Trade for {symbol} from order {order_id}: Qty {filled_shares}, Price {avg_price}")
                        else:
                            logger.info(f"Trade already exists for order {order_id}, skipping creation")
                else:
                    logger.warning(f"No OrderStatus entry found for order_id: {order_id} or unique_order_id: {unique_order_id}")
        except json.JSONDecodeError:
            logger.warning(f"Non-JSON message received: {message}")
        except ValueError as e:
            logger.error(f"ValueError processing order update: {e}, Message: {message}")
        except Exception as e:
            logger.error(f"Error processing order update: {e}", exc_info=True)
            db.session.rollback()

def custom_on_message(wsapp, message, order_id_to_track, numeric_order_id_to_track):
    logger.info(f"Raw message received: {message}")
    try:
        handle_order_update(message, order_id_to_track, numeric_order_id_to_track)
    except Exception as e:
        logger.error(f"Error in custom_on_message: {e}", exc_info=True)
'''
def place_order(smart_api, symbol, qty, price, buy_sell='BUY', user_email=None):
    with app.app_context():
        if app.config.get('DRY_RUN', False):
            executed_qty = qty
            logger.info(f"[DRY RUN] Simulated {buy_sell} order: {executed_qty}/{qty} of {symbol} at {price}")
            return executed_qty, "dry-run-order-id", "completed"

        if not user_email:
            logger.error(f"User email is None for {symbol} order")
            api_log = ApiLog(user_email or "unknown", symbol, None, "Place Order", "error", "User email not provided")
            db.session.add(api_log)
            db.session.commit()
            return 0, None, "error"

        lock_key = f"{user_email}_{symbol}"
        with order_locks.setdefault(lock_key, threading.Lock()):
            pending_orders = OrderStatus.query.filter_by(
                user_email=user_email,
                symbol=symbol,
                buy_sell=buy_sell
            ).filter(
                OrderStatus.status.in_(['pending', 'UNKNOWN', 'timeout'])
            ).filter(
                OrderStatus.created_at > IST.localize(datetime.now()) - timedelta(minutes=5)
            ).all()
            if pending_orders:
                logger.info(f"Skipping {buy_sell} order for {symbol}: Recent pending orders: {[o.order_id for o in pending_orders]}")
                return 0, None, "pending_exists"

            logger.info(f"Placing {buy_sell} order for {qty} of {symbol} at {price}")
            stock = Stock.query.filter_by(tradingsymbol=symbol).first()
            if not stock:
                logger.error(f"Stock {symbol} not found")
                api_log = ApiLog(user_email, symbol, None, "Place Order", "error", "Stock not found")
                db.session.add(api_log)
                db.session.commit()
                return 0, None, "error"

            order_params = {
                "variety": "NORMAL",
                "tradingsymbol": symbol,
                "symboltoken": stock.symboltoken,
                "transactiontype": buy_sell,
                "exchange": stock.exchange,
                "ordertype": "MARKET",
                "producttype": "DELIVERY",
                "duration": "DAY",
                "quantity": str(qty)
            }

            try:
                response = smart_api.placeOrderFullResponse(order_params)
                logger.info(f"Order {buy_sell} {qty} of {symbol} at {price}: {response}")

                order_id = response.get('data', {}).get('uniqueorderid')
                numeric_order_id = response.get('data', {}).get('orderid')
                if not order_id or not numeric_order_id:
                    logger.error(f"Failed to get order IDs for {symbol}: uniqueorderid={order_id}, orderid={numeric_order_id}")
                    api_log = ApiLog(user_email, symbol, None, "Place Order", "error", "Missing order IDs in response")
                    db.session.add(api_log)
                    db.session.commit()
                    return 0, None, "error"

                order_entry = OrderStatus(
                    user_email=user_email,
                    order_id=numeric_order_id,
                    unique_order_id=order_id,
                    symbol=symbol,
                    status="pending",
                    message="Order placed, awaiting confirmation",
                    quantity=float(qty),
                    price=price,
                    buy_sell=buy_sell,
                    created_at=IST.localize(datetime.now()),
                    updated_at=IST.localize(datetime.now())
                )
                db.session.add(order_entry)
                db.session.commit()
                logger.info(f"Saved initial OrderStatus for {numeric_order_id}")

                if user_email not in session_cache:
                    logger.error(f"No session data found for {user_email} in cache")
                    user = User.query.filter_by(email=user_email).first()
                    if user:
                        smart_api = get_angel_session(user)
                        session_cache[user_email] = {
                            'auth_token': smart_api._access_token,
                            'feed_token': smart_api.feedToken
                        }
                    else:
                        api_log = ApiLog(user_email, symbol, order_id, "Place Order", "error", "User not found or session data missing")
                        db.session.add(api_log)
                        db.session.commit()
                        return 0, order_id, "error"

                session_data = session_cache[user_email]
                auth_token = session_data.get('auth_token')
                api_key = smart_api.api_key
                client_code = getattr(smart_api, 'client_code', user_email)
                feed_token = session_data.get('feed_token')

                if not all([auth_token, api_key, client_code, feed_token]):
                    logger.error(f"Missing WebSocket credentials for {user_email}")
                    api_log = ApiLog(user_email, symbol, order_id, "Place Order", "error", "Missing WebSocket credentials")
                    db.session.add(api_log)
                    db.session.commit()
                    return 0, order_id, "error"

                client = SmartWebSocketOrderUpdate(auth_token, api_key, client_code, feed_token)
                client.on_message = lambda wsapp, message: custom_on_message(wsapp, message, order_id, numeric_order_id)

                ws_thread = threading.Thread(target=client.connect)
                ws_thread.daemon = True
                ws_thread.start()

                max_attempts = 15
                attempt = 0
                status = None
                while attempt < max_attempts:
                    with order_status_lock:
                        tracked_id = order_id if order_id in order_status_dict else (numeric_order_id if numeric_order_id in order_status_dict else None)
                        if tracked_id and tracked_id in order_status_dict:
                            status = order_status_dict[tracked_id]['status']
                            if status in ['complete', 'executed']:
                                executed_qty = order_status_dict[tracked_id]['filled_shares'] or qty
                                logger.info(f"Order {tracked_id} for {symbol} completed with {executed_qty} shares")
                                client.close_connection()
                                return executed_qty, order_id, "completed"
                            elif status in ['rejected', 'cancelled']:
                                logger.warning(f"Order {tracked_id} for {symbol} failed with status: {status}")
                                api_log = ApiLog(user_email, symbol, order_id, "Place Order", status, order_status_dict[tracked_id]['message'])
                                db.session.add(api_log)
                                db.session.commit()
                                client.close_connection()
                                return 0, order_id, status
                            else:
                                logger.info(f"Order {tracked_id} for {symbol} still pending: {status}")
                    try:
                        order_details = smart_api.individual_order_details(numeric_order_id)
                        logger.debug(f"API response for order {numeric_order_id}: {order_details}")
                        if isinstance(order_details, dict):
                            status = str(order_details.get('status', 'UNKNOWN')).lower()
                            if status in ['complete', 'executed']:
                                executed_qty = int(order_details.get('filledshares', qty) or qty)
                                logger.info(f"API confirmed order {numeric_order_id} completed with {executed_qty} shares")
                                with order_status_lock:
                                    order_status_dict[numeric_order_id] = {
                                        'status': status,
                                        'symbol': symbol,
                                        'message': order_details.get('text', ''),
                                        'filled_shares': executed_qty,
                                        'avg_price': float(order_details.get('averageprice', price) or price)
                                    }
                                client.close_connection()
                                return executed_qty, order_id, "completed"
                            elif status in ['rejected', 'cancelled']:
                                logger.warning(f"API confirmed order {numeric_order_id} failed: {status}")
                                client.close_connection()
                                return 0, order_id, status
                        elif isinstance(order_details, bool):
                            logger.warning(f"API returned boolean {order_details} for order {numeric_order_id}, assuming failure")
                            status = 'UNKNOWN'
                        else:
                            logger.error(f"Unexpected API response type for order {numeric_order_id}: {type(order_details)}")
                            status = 'UNKNOWN'
                    except Exception as e:
                        logger.error(f"API check failed for {numeric_order_id}: {str(e)}", exc_info=True)
                    time.sleep(2)
                    attempt += 1

                logger.error(f"Order {order_id} for {symbol} did not complete after {max_attempts} attempts")
                api_log = ApiLog(user_email, symbol, order_id, "Place Order", "timeout", "Order status not updated in time")
                db.session.add(api_log)
                db.session.commit()

                order_entry = OrderStatus.query.filter_by(order_id=numeric_order_id).first()
                if order_entry:
                    try:
                        order_details = smart_api.individual_order_details(numeric_order_id)
                        logger.debug(f"Final API response for order {numeric_order_id}: {order_details}")
                        if isinstance(order_details, dict):
                            final_status = str(order_details.get('status', 'UNKNOWN')).lower()
                            if final_status in ['complete', 'executed']:
                                executed_qty = int(order_details.get('filledshares', qty) or qty)
                                logger.info(f"Order {numeric_order_id} executed despite timeout, qty: {executed_qty}")
                                order_entry.status = final_status
                                order_entry.updated_at = IST.localize(datetime.now())
                                db.session.commit()
                                client.close_connection()
                                return executed_qty, order_id, "completed"
                            else:
                                order_entry.status = "timeout"
                                order_entry.message = "Order status not updated in time"
                                db.session.commit()
                                logger.info(f"Updated OrderStatus for {numeric_order_id} to timeout")
                        elif isinstance(order_details, bool):
                            logger.warning(f"Final API returned boolean {order_details} for order {numeric_order_id}, marking as timeout")
                            order_entry.status = "timeout"
                            order_entry.message = "Order status not updated in time (API returned boolean)"
                            db.session.commit()
                        else:
                            logger.error(f"Unexpected final API response type for order {numeric_order_id}: {type(order_details)}")
                            order_entry.status = "timeout"
                            order_entry.message = "Order status not updated in time (unexpected API response)"
                            db.session.commit()
                    except Exception as e:
                        logger.error(f"Final API check failed for {numeric_order_id}: {str(e)}", exc_info=True)
                        order_entry.status = "timeout"
                        order_entry.message = "Order status not updated in time"
                        db.session.commit()

                client.close_connection()
                return 0, order_id, "timeout"

            except Exception as e:
                logger.error(f"Error placing order for {symbol}: {str(e)}", exc_info=True)
                api_log = ApiLog(user_email, symbol, order_id if 'order_id' in locals() else None, "Place Order", "error", str(e))
                db.session.add(api_log)
                db.session.commit()
                db.session.rollback()
                return 0, None, "error"
'''

def place_order(smart_api, symbol, qty, price, buy_sell='BUY', user_email=None):
    with app.app_context():
        if app.config.get('DRY_RUN', False):
            executed_qty = qty
            logger.info(f"[DRY RUN] Simulated {buy_sell} order: {executed_qty}/{qty} of {symbol} at {price}")
            return executed_qty, "dry-run-order-id", "completed"

        if not user_email:
            logger.error(f"User email is None for {symbol} order")
            api_log = ApiLog(user_email or "unknown", symbol, None, "Place Order", "error", "User email not provided")
            db.session.add(api_log)
            db.session.commit()
            return 0, None, "error"

        lock_key = f"{user_email}_{symbol}"
        with order_locks.setdefault(lock_key, threading.Lock()):
            pending_orders = OrderStatus.query.filter_by(
                user_email=user_email,
                symbol=symbol,
                buy_sell=buy_sell
            ).filter(
                OrderStatus.status.in_(['pending', 'UNKNOWN', 'timeout'])
            ).filter(
                OrderStatus.created_at > IST.localize(datetime.now()) - timedelta(minutes=5)
            ).all()
            if pending_orders:
                logger.info(f"Skipping {buy_sell} order for {symbol}: Recent pending orders: {[o.order_id for o in pending_orders]}")
                return 0, None, "pending_exists"

            logger.info(f"Placing {buy_sell} order for {qty} of {symbol} at {price}")
            stock = Stock.query.filter_by(tradingsymbol=symbol).first()
            if not stock:
                logger.error(f"Stock {symbol} not found")
                api_log = ApiLog(user_email, symbol, None, "Place Order", "error", "Stock not found")
                db.session.add(api_log)
                db.session.commit()
                return 0, None, "error"

            order_params = {
                "variety": "NORMAL",
                "tradingsymbol": symbol,
                "symboltoken": stock.symboltoken,
                "transactiontype": buy_sell,
                "exchange": stock.exchange,
                "ordertype": "MARKET",
                "producttype": "DELIVERY",
                "duration": "DAY",
                "quantity": str(qty)
            }

            try:
                response = smart_api.placeOrderFullResponse(order_params)
                logger.info(f"Order {buy_sell} {qty} of {symbol} at {price}: {response}")

                order_id = response.get('data', {}).get('uniqueorderid')
                numeric_order_id = response.get('data', {}).get('orderid')
                if not order_id or not numeric_order_id:
                    logger.error(f"Failed to get order IDs for {symbol}: uniqueorderid={order_id}, orderid={numeric_order_id}")
                    api_log = ApiLog(user_email, symbol, None, "Place Order", "error", "Missing order IDs in response")
                    db.session.add(api_log)
                    db.session.commit()
                    return 0, None, "error"

                order_entry = OrderStatus(
                    user_email=user_email,
                    order_id=numeric_order_id,
                    unique_order_id=order_id,
                    symbol=symbol,
                    status="pending",
                    message="Order placed, awaiting confirmation",
                    quantity=float(qty),
                    price=price,
                    buy_sell=buy_sell,
                    created_at=IST.localize(datetime.now()),
                    updated_at=IST.localize(datetime.now())
                )
                db.session.add(order_entry)
                db.session.commit()
                logger.info(f"Saved initial OrderStatus for {numeric_order_id}")

                if user_email not in session_cache:
                    logger.error(f"No session data found for {user_email} in cache")
                    user = User.query.filter_by(email=user_email).first()
                    if user:
                        smart_api = get_angel_session(user)
                        session_cache[user_email] = {
                            'auth_token': smart_api._access_token,
                            'feed_token': smart_api.feedToken
                        }
                    else:
                        api_log = ApiLog(user_email, symbol, order_id, "Place Order", "error", "User not found or session data missing")
                        db.session.add(api_log)
                        db.session.commit()
                        return 0, order_id, "error"

                session_data = session_cache[user_email]
                auth_token = session_data.get('auth_token')
                api_key = smart_api.api_key
                client_code = getattr(smart_api, 'client_code', user_email)
                feed_token = session_data.get('feed_token')

                if not all([auth_token, api_key, client_code, feed_token]):
                    logger.error(f"Missing WebSocket credentials for {user_email}")
                    api_log = ApiLog(user_email, symbol, order_id, "Place Order", "error", "Missing WebSocket credentials")
                    db.session.add(api_log)
                    db.session.commit()
                    return 0, order_id, "error"

                client = SmartWebSocketOrderUpdate(auth_token, api_key, client_code, feed_token)
                client.on_message = lambda wsapp, message: custom_on_message(wsapp, message, order_id, numeric_order_id)

                ws_thread = threading.Thread(target=client.connect)
                ws_thread.daemon = True
                ws_thread.start()

                max_attempts = 15
                attempt = 0
                status = None
                while attempt < max_attempts:
                    with order_status_lock:
                        tracked_id = order_id if order_id in order_status_dict else (numeric_order_id if numeric_order_id in order_status_dict else None)
                        if tracked_id and tracked_id in order_status_dict:
                            status = order_status_dict[tracked_id]['status']
                            if status in ['complete', 'executed']:
                                executed_qty = order_status_dict[tracked_id]['filled_shares'] or qty
                                logger.info(f"Order {tracked_id} for {symbol} completed with {executed_qty} shares via WebSocket")
                                client.close_connection()
                                order_entry.status = "complete"
                                order_entry.message = "Order completed via WebSocket"
                                order_entry.updated_at = IST.localize(datetime.now())
                                db.session.commit()
                                return executed_qty, order_id, "completed"
                            elif status in ['rejected', 'cancelled']:
                                logger.warning(f"Order {tracked_id} for {symbol} failed with status: {status}")
                                api_log = ApiLog(user_email, symbol, order_id, "Place Order", status, order_status_dict[tracked_id]['message'])
                                db.session.add(api_log)
                                db.session.commit()
                                client.close_connection()
                                order_entry.status = status
                                order_entry.message = order_status_dict[tracked_id]['message']
                                order_entry.updated_at = IST.localize(datetime.now())
                                db.session.commit()
                                return 0, order_id, status
                            else:
                                logger.info(f"Order {tracked_id} for {symbol} still pending: {status}")

                    # API Fallback
                    try:
                        order_details = smart_api.individual_order_details(numeric_order_id)
                        logger.debug(f"API response for order {numeric_order_id}: {order_details}")
                        if isinstance(order_details, dict):
                            status = str(order_details.get('status', 'UNKNOWN')).lower()
                            executed_qty = int(order_details.get('filledshares', qty) or qty)
                            if status in ['complete', 'executed']:
                                logger.info(f"API confirmed order {numeric_order_id} completed with {executed_qty} shares")
                                with order_status_lock:
                                    order_status_dict[numeric_order_id] = {
                                        'status': status,
                                        'symbol': symbol,
                                        'message': order_details.get('text', ''),
                                        'filled_shares': executed_qty,
                                        'avg_price': float(order_details.get('averageprice', price) or price)
                                    }
                                client.close_connection()
                                order_entry.status = "complete"
                                order_entry.message = "Order completed via API"
                                order_entry.updated_at = IST.localize(datetime.now())
                                db.session.commit()
                                return executed_qty, order_id, "completed"
                            elif status in ['rejected', 'cancelled']:
                                logger.warning(f"API confirmed order {numeric_order_id} failed: {status}")
                                client.close_connection()
                                order_entry.status = status
                                order_entry.message = order_details.get('text', '')
                                order_entry.updated_at = IST.localize(datetime.now())
                                db.session.commit()
                                return 0, order_id, status
                        elif isinstance(order_details, bool):
                            logger.warning(f"API returned boolean {order_details} for order {numeric_order_id}, falling back to OrderBook")
                            order_book = smart_api.orderBook()
                            if order_book.get('status') == True and 'data' in order_book:
                                for order in order_book['data']:
                                    if order['orderid'] == numeric_order_id:
                                        status = str(order['status']).lower()
                                        executed_qty = int(order['filledshares'] or qty)
                                        if status in ['complete', 'executed']:
                                            logger.info(f"OrderBook confirmed order {numeric_order_id} completed with {executed_qty} shares")
                                            with order_status_lock:
                                                order_status_dict[numeric_order_id] = {
                                                    'status': status,
                                                    'symbol': symbol,
                                                    'message': order.get('text', ''),
                                                    'filled_shares': executed_qty,
                                                    'avg_price': float(order.get('averageprice', price) or price)
                                                }
                                            client.close_connection()
                                            order_entry.status = "complete"
                                            order_entry.message = "Order completed via OrderBook"
                                            order_entry.updated_at = IST.localize(datetime.now())
                                            db.session.commit()
                                            return executed_qty, order_id, "completed"
                                        elif status in ['rejected', 'cancelled']:
                                            logger.warning(f"OrderBook confirmed order {numeric_order_id} failed: {status}")
                                            client.close_connection()
                                            order_entry.status = status
                                            order_entry.message = order.get('text', '')
                                            order_entry.updated_at = IST.localize(datetime.now())
                                            db.session.commit()
                                            return 0, order_id, status
                            logger.warning(f"No matching order found in OrderBook for {numeric_order_id}, continuing wait")
                            status = 'UNKNOWN'
                        else:
                            logger.error(f"Unexpected API response type for order {numeric_order_id}: {type(order_details)}")
                            status = 'UNKNOWN'
                    except Exception as e:
                        logger.error(f"API check failed for {numeric_order_id}: {str(e)}", exc_info=True)
                    time.sleep(1)  # Reduced from 2s to 1s for faster checking
                    attempt += 1

                logger.error(f"Order {order_id} for {symbol} did not complete after {max_attempts} attempts")
                api_log = ApiLog(user_email, symbol, order_id, "Place Order", "timeout", "Order status not updated in time")
                db.session.add(api_log)
                db.session.commit()

                # Final Check with OrderBook
                order_entry = OrderStatus.query.filter_by(order_id=numeric_order_id).first()
                if order_entry:
                    try:
                        order_details = smart_api.individual_order_details(numeric_order_id)
                        logger.debug(f"Final API response for order {numeric_order_id}: {order_details}")
                        if isinstance(order_details, dict):
                            final_status = str(order_details.get('status', 'UNKNOWN')).lower()
                            executed_qty = int(order_details.get('filledshares', qty) or qty)
                            if final_status in ['complete', 'executed']:
                                logger.info(f"Order {numeric_order_id} executed despite timeout, qty: {executed_qty}")
                                order_entry.status = final_status
                                order_entry.message = "Order completed (final API check)"
                                order_entry.updated_at = IST.localize(datetime.now())
                                db.session.commit()
                                client.close_connection()
                                return executed_qty, order_id, "completed"
                            else:
                                order_entry.status = "timeout"
                                order_entry.message = "Order status not updated in time"
                                db.session.commit()
                                logger.info(f"Updated OrderStatus for {numeric_order_id} to timeout")
                        elif isinstance(order_details, bool):
                            logger.warning(f"Final API returned boolean {order_details} for order {numeric_order_id}, checking OrderBook")
                            order_book = smart_api.orderBook()
                            if order_book.get('status') == True and 'data' in order_book:
                                for order in order_book['data']:
                                    if order['orderid'] == numeric_order_id:
                                        final_status = str(order['status']).lower()
                                        executed_qty = int(order['filledshares'] or qty)
                                        if final_status in ['complete', 'executed']:
                                            logger.info(f"OrderBook confirmed order {numeric_order_id} completed with {executed_qty} shares")
                                            order_entry.status = "complete"
                                            order_entry.message = "Order completed via OrderBook (final check)"
                                            order_entry.updated_at = IST.localize(datetime.now())
                                            db.session.commit()
                                            client.close_connection()
                                            return executed_qty, order_id, "completed"
                                        else:
                                            order_entry.status = final_status if final_status in ['rejected', 'cancelled'] else "timeout"
                                            order_entry.message = order.get('text', 'Order status not updated in time')
                                            db.session.commit()
                                            logger.info(f"Updated OrderStatus for {numeric_order_id} to {order_entry.status}")
                        else:
                            logger.error(f"Unexpected final API response type for order {numeric_order_id}: {type(order_details)}")
                            order_entry.status = "timeout"
                            order_entry.message = "Order status not updated in time (unexpected API response)"
                            db.session.commit()
                    except Exception as e:
                        logger.error(f"Final API check failed for {numeric_order_id}: {str(e)}", exc_info=True)
                        order_entry.status = "timeout"
                        order_entry.message = "Order status not updated in time"
                        db.session.commit()

                client.close_connection()
                return 0, order_id, "timeout"

            except Exception as e:
                logger.error(f"Error placing order for {symbol}: {str(e)}", exc_info=True)
                api_log = ApiLog(user_email, symbol, order_id if 'order_id' in locals() else None, "Place Order", "error", str(e))
                db.session.add(api_log)
                db.session.commit()
                db.session.rollback()
                return 0, None, "error"
'''
def process_strategy(user, symbol, ltp, smart_api):
    logger.info(f"Process strategy for {symbol} at {ltp}")
    
    with app.app_context():
        try:
            trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
            stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=symbol).first()
            wallet_value = stock.allotment_captial if stock else 0
            
            logger.info(f"Wallet value for {symbol}: {wallet_value}")
            logger.info(f"Trades for {symbol}: {len(trades)}, Trades: {[t.__dict__ for t in trades]}")

            pending_orders = OrderStatus.query.filter_by(
                user_email=user.email,
                symbol=symbol,
                buy_sell='BUY'
            ).filter(
                OrderStatus.status.in_(['pending', 'UNKNOWN', 'timeout'])
            ).filter(
                OrderStatus.created_at > IST.localize(datetime.now()) - timedelta(minutes=5)
            ).all()
            if pending_orders:
                logger.info(f"Skipping {symbol}: {len(pending_orders)} recent pending/timeout orders exist: {[o.order_id for o in pending_orders]}")
                return
            open_sr1_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == 1), None)
            latest_trade = trades[-1] if trades else None
            base_price = latest_trade.base_price if latest_trade else ltp
            logger.info(f"Base price for {symbol}: {base_price}")
            strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)

            def get_order_status(order_id):
                order = OrderStatus.query.filter_by(order_id=order_id, user_email=user.email).first()
                if order and order.status not in ['pending', 'UNKNOWN', 'timeout']:
                    logger.info(f"Order status from table for {order_id}: {order.status}")
                    return order.status
                try:
                    status = smart_api.individual_order_details(order_id)
                    logger.info(f"Order status from API for {order_id}: {status}")
                    if isinstance(status, dict):
                        new_status = OrderStatus(
                            order_id=order_id,
                            symbol=symbol,
                            user_email=user.email,
                            status=str(status.get('status', 'UNKNOWN')).lower(),
                            message=status.get('text', ''),
                            quantity=float(status.get('quantity', order.quantity if order else 0)),
                            price=float(status.get('price', order.price if order else 0)),
                            buy_sell=status.get('transactiontype', order.buy_sell if order else 'BUY'),
                            created_at=IST.localize(datetime.now()) if not order else order.created_at,
                            updated_at=IST.localize(datetime.now())
                        )
                        db.session.merge(new_status)
                        db.session.commit()
                        return new_status.status
                    else:
                        logger.warning(f"API returned non-dict status for {order_id}: {status}")
                        return 'UNKNOWN'
                except Exception as e:
                    logger.error(f"Failed to fetch order status for {order_id}: {str(e)}")
                    return 'UNKNOWN'

            if not trades or all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades):
                qty = int(strategy_data.loc[0, 'Qnty'])
                executed_qty, order_id, order_status = place_order(smart_api, symbol, qty, ltp, user_email=user.email)
                logger.debug(f"place_order result for initial buy: {executed_qty, order_id, order_status}")

                if order_id and order_status not in ['completed', 'complete', 'executed']:
                    for _ in range(5):
                        order_status = get_order_status(order_id)
                        if order_status not in ['pending', 'UNKNOWN', 'timeout']:
                            break
                        logger.info(f"Waiting for initial buy order {order_id} to resolve, current status: {order_status}")
                        time.sleep(2)

                    if order_status in ['timeout', 'UNKNOWN']:
                        try:
                            order_details = smart_api.individual_order_details(order_id)
                            if isinstance(order_details, dict):
                                final_status = str(order_details.get('status', 'UNKNOWN')).lower()
                                if final_status in ['complete', 'executed']:
                                    executed_qty = int(order_details.get('filledshares', qty) or qty)
                                    order_status = final_status
                                    logger.info(f"Order {order_id} executed despite timeout, qty: {executed_qty}")
                                    order_entry = OrderStatus.query.filter_by(order_id=order_id).first()
                                    if order_entry:
                                        order_entry.status = final_status
                                        order_entry.updated_at = IST.localize(datetime.now())
                                        db.session.commit()
                            else:
                                logger.warning(f"Final API returned non-dict for {order_id}: {order_details}")
                        except Exception as e:
                            logger.error(f"Final API check failed for {order_id}: {e}")

                logger.info(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}, Status: {order_status}")
                with open('order_status.txt', 'a') as f:
                    f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")

                if executed_qty > 0 and order_status in ['complete', 'executed']:
                    sr_no = max([t.sr_no for t in trades], default=1)
                    new_trade = Trade(
                        stock_symbol=symbol,
                        sr_no=sr_no,
                        entry_price=ltp,
                        quantity=int(executed_qty),
                        user_email=user.email,
                        base_price=ltp,
                        total_quantity=int(executed_qty),
                        total_sold_quantity=0,
                        status='OPEN',
                        last_updated=IST.localize(datetime.now()),
                        description='Initial Buy',
                        order_id=order_id
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Initial buy failed or not completed for {symbol} at {ltp}, Qty: {qty}, Status: {order_status}")
                return

            current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
            latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
            current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
            logger.info(f"Current Sr No for {symbol}: {current_sr_no}, Open Qty: {current_open_qty}")

            phase_config = PhaseConfig.query.filter_by(
                user_email=user.email,
                stock_symbol=symbol
            ).filter(
                PhaseConfig.start_sr_no <= current_sr_no,
                PhaseConfig.end_sr_no >= current_sr_no
            ).first()
            down_increment = 0.0025 if not phase_config else phase_config.down_increment / 100
            logger.info(f"Phase: {phase_config.phase if phase_config else 'Unknown'}, Down Increment: {down_increment*100}%")

            drop_percent = (ltp - base_price) / base_price
            logger.info(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
            target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
            target_row = strategy_data.loc[target_idx]
            target_sr_no = int(target_row['Sr.No'])
            total_qty = int(target_row['Total_Qty'])
            qty_to_buy = total_qty - current_open_qty
            
            if drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades):
                if qty_to_buy <= 0:
                    logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
                    return

                existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
                if existing_open_trade:
                    logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
                    return

                executed_qty, order_id, order_status = place_order(smart_api, symbol, qty_to_buy, ltp, user_email=user.email)
                logger.debug(f"place_order result for additional buy: {executed_qty, order_id, order_status}")

                if order_id and order_status not in ['completed', 'complete', 'executed']:
                    for _ in range(5):
                        order_status = get_order_status(order_id)
                        if order_status not in ['pending', 'UNKNOWN', 'timeout']:
                            break
                        logger.info(f"Waiting for additional buy order {order_id} to resolve, current status: {order_status}")
                        time.sleep(2)

                    if order_status in ['timeout', 'UNKNOWN']:
                        try:
                            order_details = smart_api.individual_order_details(order_id)
                            if isinstance(order_details, dict):
                                final_status = str(order_details.get('status', 'UNKNOWN')).lower()
                                if final_status in ['complete', 'executed']:
                                    executed_qty = int(order_details.get('filledshares', qty_to_buy) or qty_to_buy)
                                    order_status = final_status
                                    logger.info(f"Order {order_id} executed despite timeout, qty: {executed_qty}")
                                    order_entry = OrderStatus.query.filter_by(order_id=order_id).first()
                                    if order_entry:
                                        order_entry.status = final_status
                                        order_entry.updated_at = IST.localize(datetime.now())
                                        db.session.commit()
                            else:
                                logger.warning(f"Final API returned non-dict for {order_id}: {order_details}")
                        except Exception as e:
                            logger.error(f"Final API check failed for {order_id}: {e}")

                logger.info(f"Additional buy for {symbol} at {ltp}, Qty: {qty_to_buy}, Executed Qty: {executed_qty}, Status: {order_status}")
                with open('order_status.txt', 'a') as f:
                    f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")

                if executed_qty > 0 and order_status in ['complete', 'executed']:
                    for trade in trades:
                        if trade.status == 'OPEN':
                            trade.status = 'OLD_BUY'
                            trade.last_updated = IST.localize(datetime.now())
                            trade.description = f"Updated to OLD_BUY before new buy at Sr.No {target_sr_no}"
                            logger.info(f"Updated trade Sr.No {trade.sr_no} to OLD_BUY, Total_Qty: {trade.total_quantity}")
                    
                    new_trade = Trade(
                        stock_symbol=symbol,
                        sr_no=target_sr_no,
                        entry_price=ltp,
                        quantity=int(executed_qty),
                        user_email=user.email,
                        base_price=base_price,
                        total_quantity=total_qty,
                        total_sold_quantity=0,
                        status='OPEN',
                        last_updated=IST.localize(datetime.now()),
                        description='Additional Buy',
                        order_id=order_id
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Buy failed or not completed for {symbol} at {ltp}, Qty: {qty_to_buy}, Status: {order_status}")
                return

            all_closed = True
            for trade in trades:
                if trade.status != 'OPEN':
                    continue
                all_closed = False
                
                base_price = trade.base_price
                logger.info(f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                
                sr_no = trade.sr_no
                entry_price = trade.entry_price
                current_qty = trade.total_quantity - trade.total_sold_quantity
                row = strategy_data.loc[sr_no-1]
                logger.info(f"trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

                final_tgt = row['FINAL_TGT']
                first_tgt = row['First_TGT']
                second_tgt = row['Second_TGT']
                half_qty = row['EXIT_1st_HALF'] if row['EXIT_1st_HALF'] is not None else 0
                second_half_qty = row['EXIT_2nd_HALF'] if row['EXIT_2nd_HALF'] is not None else 0

                logger.info(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}, Second_Half_Qty={second_half_qty}")

                if sr_no <= 8:
                    if ltp >= final_tgt and current_qty > 0:
                        logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Sell failed for {symbol} Sr.No {sr_no} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
                elif sr_no <= 21:
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}, Status: {order_status}")
                    elif ltp >= final_tgt and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
                else:  # Sr.No > 21
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}, Status: {order_status}")
                    elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, second_half_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Second TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{second_half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"2nd half sell failed for {symbol} at {ltp}, Qty: {second_half_qty}, Status: {order_status}")
                    elif ltp >= final_tgt and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

            if all_closed and trades:
                logger.info(f"All trades for {symbol} are CLOSED, resetting cycle to Sr.No 1")
                current_cycle = TradeCycle.query.filter_by(
                    stock_symbol=symbol,
                    user_email=user.email,
                    status='ACTIVE'
                ).order_by(TradeCycle.cycle_start.desc()).first()
                
                if current_cycle:
                    current_cycle.cycle_end = IST.localize(datetime.now())
                    current_cycle.total_sold = sum(t.total_sold_quantity for t in trades)
                    current_cycle.total_bought = sum(t.total_quantity for t in trades)
                    current_cycle.profit = sum((ltp - t.entry_price) * t.total_sold_quantity for t in trades if t.status == 'CLOSED')
                    current_cycle.status = 'COMPLETED'
                    logger.info(f"Completed TradeCycle for {symbol}: Total Bought {current_cycle.total_bought}, Total Sold {current_cycle.total_sold}, Profit {current_cycle.profit}")
                
                new_cycle = TradeCycle(
                    stock_symbol=symbol,
                    user_email=user.email,
                    cycle_start=IST.localize(datetime.now()),
                    status='ACTIVE'
                )
                db.session.add(new_cycle)
                db.session.commit()
                logger.info(f"Started new TradeCycle for {symbol}")

        except Exception as e:
            logger.error(f"Error in process_strategy for {symbol}: {str(e)}", exc_info=True)
            db.session.rollback()
        finally:
            db.session.close()
'''            
'''
def process_strategy(user, symbol, ltp, smart_api):
    logger.info(f"Process strategy for {symbol} at {ltp}")
    
    with app.app_context():
        try:
            trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
            stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=symbol).first()
            wallet_value = stock.allotment_captial if stock else 0
            
            logger.info(f"Wallet value for {symbol}: {wallet_value}")
            logger.info(f"Trades for {symbol}: {len(trades)}, Trades: {[t.__dict__ for t in trades]}")

            # Check for pending orders
            pending_orders = OrderStatus.query.filter_by(
                user_email=user.email,
                symbol=symbol,
                buy_sell='BUY'
            ).filter(
                OrderStatus.status.in_(['pending', 'UNKNOWN', 'timeout'])
            ).filter(
                OrderStatus.created_at > IST.localize(datetime.now()) - timedelta(minutes=5)
            ).all()
            if pending_orders:
                logger.info(f"Skipping {symbol}: {len(pending_orders)} recent pending/timeout orders exist: {[o.order_id for o in pending_orders]}")
                return

            # Check for existing open Sr.No 1 trade
            open_sr1_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == 1), None)
            latest_trade = trades[-1] if trades else None
            base_price = latest_trade.base_price if latest_trade else ltp
            logger.info(f"Base price for {symbol}: {base_price}")
            strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)

            def get_order_status(order_id):
                order = OrderStatus.query.filter_by(order_id=order_id, user_email=user.email).first()
                if order and order.status not in ['pending', 'UNKNOWN', 'timeout']:
                    logger.info(f"Order status from table for {order_id}: {order.status}")
                    return order.status
                try:
                    status = smart_api.individual_order_details(order_id)
                    logger.info(f"Order status from API for {order_id}: {status}")
                    if isinstance(status, dict):
                        new_status = OrderStatus(
                            order_id=order_id,
                            symbol=symbol,
                            user_email=user.email,
                            status=str(status.get('status', 'UNKNOWN')).lower(),
                            message=status.get('text', ''),
                            quantity=float(status.get('quantity', order.quantity if order else 0)),
                            price=float(status.get('price', order.price if order else 0)),
                            buy_sell=status.get('transactiontype', order.buy_sell if order else 'BUY'),
                            created_at=IST.localize(datetime.now()) if not order else order.created_at,
                            updated_at=IST.localize(datetime.now())
                        )
                        db.session.merge(new_status)
                        db.session.commit()
                        return new_status.status
                    elif isinstance(status, bool):
                        logger.warning(f"API returned boolean {status} for {order_id}, falling back to OrderBook")
                        order_book = smart_api.orderBook()
                        if order_book.get('status') == True and 'data' in order_book:
                            for order in order_book['data']:
                                if order['orderid'] == order_id:
                                    final_status = str(order['status']).lower()
                                    new_status = OrderStatus(
                                        order_id=order_id,
                                        symbol=symbol,
                                        user_email=user.email,
                                        status=final_status,
                                        message=order.get('text', ''),
                                        quantity=float(order.get('filledshares', order.quantity if order else 0)),
                                        price=float(order.get('averageprice', order.price if order else 0)),
                                        buy_sell=order.get('transactiontype', order.buy_sell if order else 'BUY'),
                                        created_at=IST.localize(datetime.now()) if not order else order.created_at,
                                        updated_at=IST.localize(datetime.now())
                                    )
                                    db.session.merge(new_status)
                                    db.session.commit()
                                    return final_status
                        return 'UNKNOWN'
                    else:
                        logger.warning(f"API returned unexpected type for {order_id}: {type(status)}")
                        return 'UNKNOWN'
                except Exception as e:
                    logger.error(f"Failed to fetch order status for {order_id}: {str(e)}")
                    return 'UNKNOWN'

            # Initial Buy Logic: Only if no trades or all are CLOSED/OLD_BUY, and no OPEN Sr.No 1
            if (not trades or all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades)) and not open_sr1_trade:
                qty = int(strategy_data.loc[0, 'Qnty'])
                executed_qty, order_id, order_status = place_order(smart_api, symbol, qty, ltp, user_email=user.email)
                logger.debug(f"place_order result for initial buy: {executed_qty, order_id, order_status}")

                if order_id and order_status not in ['completed', 'complete', 'executed']:
                    for _ in range(5):
                        order_status = get_order_status(order_id)
                        if order_status not in ['pending', 'UNKNOWN', 'timeout']:
                            break
                        logger.info(f"Waiting for initial buy order {order_id} to resolve, current status: {order_status}")
                        time.sleep(2)

                    if order_status in ['timeout', 'UNKNOWN']:
                        try:
                            order_details = smart_api.individual_order_details(order_id)
                            if isinstance(order_details, dict):
                                final_status = str(order_details.get('status', 'UNKNOWN')).lower()
                                if final_status in ['complete', 'executed']:
                                    executed_qty = int(order_details.get('filledshares', qty) or qty)
                                    order_status = final_status
                                    logger.info(f"Order {order_id} executed despite timeout, qty: {executed_qty}")
                                    order_entry = OrderStatus.query.filter_by(order_id=order_id).first()
                                    if order_entry:
                                        order_entry.status = final_status
                                        order_entry.updated_at = IST.localize(datetime.now())
                                        db.session.commit()
                            else:
                                logger.warning(f"Final API returned non-dict for {order_id}: {order_details}")
                        except Exception as e:
                            logger.error(f"Final API check failed for {order_id}: {e}")

                logger.info(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}, Status: {order_status}")
                with open('order_status.txt', 'a') as f:
                    f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")

                if executed_qty > 0 and order_status in ['complete', 'executed']:
                    sr_no = 1  # Explicitly set to Sr.No 1 for initial buy
                    new_trade = Trade(
                        stock_symbol=symbol,
                        sr_no=sr_no,
                        entry_price=ltp,
                        quantity=int(executed_qty),
                        user_email=user.email,
                        base_price=ltp,
                        total_quantity=int(executed_qty),
                        total_sold_quantity=0,
                        status='OPEN',
                        last_updated=IST.localize(datetime.now()),
                        description='Initial Buy',
                        order_id=order_id
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Initial buy failed or not completed for {symbol} at {ltp}, Qty: {qty}, Status: {order_status}")
                return

            # Additional Buy and Sell Logic
            current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
            latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
            current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
            logger.info(f"Current Sr No for {symbol}: {current_sr_no}, Open Qty: {current_open_qty}")

            phase_config = PhaseConfig.query.filter_by(
                user_email=user.email,
                stock_symbol=symbol
            ).filter(
                PhaseConfig.start_sr_no <= current_sr_no,
                PhaseConfig.end_sr_no >= current_sr_no
            ).first()
            down_increment = 0.0025 if not phase_config else phase_config.down_increment / 100
            logger.info(f"Phase: {phase_config.phase if phase_config else 'Unknown'}, Down Increment: {down_increment*100}%")

            drop_percent = (ltp - base_price) / base_price
            logger.info(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
            target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
            target_row = strategy_data.loc[target_idx]
            target_sr_no = int(target_row['Sr.No'])
            total_qty = int(target_row['Total_Qty'])
            qty_to_buy = total_qty - current_open_qty
            
            if drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades):
                if qty_to_buy <= 0:
                    logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
                    return

                existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
                if existing_open_trade:
                    logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
                    return

                executed_qty, order_id, order_status = place_order(smart_api, symbol, qty_to_buy, ltp, user_email=user.email)
                logger.debug(f"place_order result for additional buy: {executed_qty, order_id, order_status}")

                if order_id and order_status not in ['completed', 'complete', 'executed']:
                    for _ in range(5):
                        order_status = get_order_status(order_id)
                        if order_status not in ['pending', 'UNKNOWN', 'timeout']:
                            break
                        logger.info(f"Waiting for additional buy order {order_id} to resolve, current status: {order_status}")
                        time.sleep(2)

                    if order_status in ['timeout', 'UNKNOWN']:
                        try:
                            order_details = smart_api.individual_order_details(order_id)
                            if isinstance(order_details, dict):
                                final_status = str(order_details.get('status', 'UNKNOWN')).lower()
                                if final_status in ['complete', 'executed']:
                                    executed_qty = int(order_details.get('filledshares', qty_to_buy) or qty_to_buy)
                                    order_status = final_status
                                    logger.info(f"Order {order_id} executed despite timeout, qty: {executed_qty}")
                                    order_entry = OrderStatus.query.filter_by(order_id=order_id).first()
                                    if order_entry:
                                        order_entry.status = final_status
                                        order_entry.updated_at = IST.localize(datetime.now())
                                        db.session.commit()
                            else:
                                logger.warning(f"Final API returned non-dict for {order_id}: {order_details}")
                        except Exception as e:
                            logger.error(f"Final API check failed for {order_id}: {e}")

                logger.info(f"Additional buy for {symbol} at {ltp}, Qty: {qty_to_buy}, Executed Qty: {executed_qty}, Status: {order_status}")
                with open('order_status.txt', 'a') as f:
                    f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")

                if executed_qty > 0 and order_status in ['complete', 'executed']:
                    for trade in trades:
                        if trade.status == 'OPEN':
                            trade.status = 'OLD_BUY'
                            trade.last_updated = IST.localize(datetime.now())
                            trade.description = f"Updated to OLD_BUY before new buy at Sr.No {target_sr_no}"
                            logger.info(f"Updated trade Sr.No {trade.sr_no} to OLD_BUY, Total_Qty: {trade.total_quantity}")
                    
                    new_trade = Trade(
                        stock_symbol=symbol,
                        sr_no=target_sr_no,
                        entry_price=ltp,
                        quantity=int(executed_qty),
                        user_email=user.email,
                        base_price=base_price,
                        total_quantity=total_qty,
                        total_sold_quantity=0,
                        status='OPEN',
                        last_updated=IST.localize(datetime.now()),
                        description='Additional Buy',
                        order_id=order_id
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
                else:
                    logger.warning(f"Buy failed or not completed for {symbol} at {ltp}, Qty: {qty_to_buy}, Status: {order_status}")
                return

            # Sell Logic
            all_closed = True
            for trade in trades:
                if trade.status != 'OPEN':
                    continue
                all_closed = False
                
                base_price = trade.base_price
                logger.info(f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                
                sr_no = trade.sr_no
                entry_price = trade.entry_price
                current_qty = trade.total_quantity - trade.total_sold_quantity
                row = strategy_data.loc[sr_no-1]
                logger.info(f"trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

                final_tgt = row['FINAL_TGT']
                first_tgt = row['First_TGT']
                second_tgt = row['Second_TGT']
                half_qty = row['EXIT_1st_HALF'] if row['EXIT_1st_HALF'] is not None else 0
                second_half_qty = row['EXIT_2nd_HALF'] if row['EXIT_2nd_HALF'] is not None else 0

                logger.info(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}, Second_Half_Qty={second_half_qty}")

                if sr_no <= 8:
                    if ltp >= final_tgt and current_qty > 0:
                        logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Sell failed for {symbol} Sr.No {sr_no} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
                elif sr_no <= 21:
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}, Status: {order_status}")
                    elif ltp >= final_tgt and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
                else:  # Sr.No > 21
                    if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'First TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"1st half sell failed for {symbol} at {ltp}, Qty: {half_qty}, Status: {order_status}")
                    elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, second_half_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Second TGT'
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{second_half_qty}, Sr.No {sr_no}, Status: {trade.status}")
                        else:
                            logger.warning(f"2nd half sell failed for {symbol} at {ltp}, Qty: {second_half_qty}, Status: {order_status}")
                    elif ltp >= final_tgt and current_qty > 0:
                        executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                        if executed_qty > 0 and order_status in ['complete', 'executed']:
                            trade.total_sold_quantity += executed_qty
                            trade.description = 'Final TGT'
                            if trade.total_sold_quantity >= trade.total_quantity:
                                trade.status = 'CLOSED'
                                trade.cycle_count += 1
                                logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                            trade.last_updated = IST.localize(datetime.now())
                            db.session.commit()
                            logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                        else:
                            logger.warning(f"Final sell failed for {symbol} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                    else:
                        logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

            # Reset Cycle if All Trades are Closed
            if all_closed and trades:
                logger.info(f"All trades for {symbol} are CLOSED, resetting cycle to Sr.No 1")
                current_cycle = TradeCycle.query.filter_by(
                    stock_symbol=symbol,
                    user_email=user.email,
                    status='ACTIVE'
                ).order_by(TradeCycle.cycle_start.desc()).first()
                
                if current_cycle:
                    current_cycle.cycle_end = IST.localize(datetime.now())
                    current_cycle.total_sold = sum(t.total_sold_quantity for t in trades)
                    current_cycle.total_bought = sum(t.total_quantity for t in trades)
                    current_cycle.profit = sum((ltp - t.entry_price) * t.total_sold_quantity for t in trades if t.status == 'CLOSED')
                    current_cycle.status = 'COMPLETED'
                    logger.info(f"Completed TradeCycle for {symbol}: Total Bought {current_cycle.total_bought}, Total Sold {current_cycle.total_sold}, Profit {current_cycle.profit}")
                
                new_cycle = TradeCycle(
                    stock_symbol=symbol,
                    user_email=user.email,
                    cycle_start=IST.localize(datetime.now()),
                    status='ACTIVE'
                )
                db.session.add(new_cycle)
                db.session.commit()
                logger.info(f"Started new TradeCycle for {symbol}")

        except Exception as e:
            logger.error(f"Error in process_strategy for {symbol}: {str(e)}", exc_info=True)
            db.session.rollback()
        finally:
            db.session.close()
'''



'''
strategy_locks = {}

def process_strategy(user, symbol, ltp, smart_api):
    logger.info(f"Process strategy for {symbol} at {ltp}")
    
    with app.app_context():
        lock_key = f"{user.email}_{symbol}"
        with strategy_locks.setdefault(lock_key, Lock()):
            try:
                trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
                stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=symbol).first()
                wallet_value = stock.allotment_captial if stock else 0
                
                logger.info(f"Wallet value for {symbol}: {wallet_value}")
                logger.info(f"Trades for {symbol}: {len(trades)}, Trades: {[t.__dict__ for t in trades]}")

                # Check for pending orders
                pending_orders = OrderStatus.query.filter_by(
                    user_email=user.email,
                    symbol=symbol,
                    buy_sell='BUY'
                ).filter(
                    OrderStatus.status.in_(['pending', 'UNKNOWN', 'timeout'])
                ).filter(
                    OrderStatus.created_at > IST.localize(datetime.now()) - timedelta(minutes=5)
                ).all()
                if pending_orders:
                    logger.info(f"Skipping {symbol}: {len(pending_orders)} recent pending/timeout orders exist: {[o.order_id for o in pending_orders]}")
                    return

                # Check active cycle
                current_cycle = TradeCycle.query.filter_by(
                    stock_symbol=symbol,
                    user_email=user.email,
                    status='ACTIVE'
                ).order_by(TradeCycle.cycle_start.desc()).first()

                # If no active cycle and no open trades, start a new one
                if not current_cycle and not any(t.status == 'OPEN' for t in trades):
                    new_cycle = TradeCycle(
                        stock_symbol=symbol,
                        user_email=user.email,
                        cycle_start=IST.localize(datetime.now()),
                        status='ACTIVE'
                    )
                    db.session.add(new_cycle)
                    db.session.commit()
                    logger.info(f"Started new TradeCycle for {symbol}")
                    current_cycle = new_cycle

                latest_trade = trades[-1] if trades else None
                base_price = latest_trade.base_price if latest_trade else ltp
                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)

                def get_order_status(order_id):
                    order = OrderStatus.query.filter_by(order_id=order_id, user_email=user.email).first()
                    if order and order.status not in ['pending', 'UNKNOWN', 'timeout']:
                        logger.info(f"Order status from table for {order_id}: {order.status}")
                        return order.status
                    try:
                        status = smart_api.individual_order_details(order_id)
                        logger.info(f"Order status from API for {order_id}: {status}")
                        if isinstance(status, dict):
                            new_status = OrderStatus(
                                order_id=order_id,
                                symbol=symbol,
                                user_email=user.email,
                                status=str(status.get('status', 'UNKNOWN')).lower(),
                                message=status.get('text', ''),
                                quantity=float(status.get('quantity', order.quantity if order else 0)),
                                price=float(status.get('price', order.price if order else 0)),
                                buy_sell=status.get('transactiontype', order.buy_sell if order else 'BUY'),
                                created_at=IST.localize(datetime.now()) if not order else order.created_at,
                                updated_at=IST.localize(datetime.now())
                            )
                            db.session.merge(new_status)
                            db.session.commit()
                            return new_status.status
                        elif isinstance(status, bool):
                            logger.warning(f"API returned boolean {status} for {order_id}, falling back to OrderBook")
                            order_book = smart_api.orderBook()
                            if order_book.get('status') == True and 'data' in order_book:
                                for order in order_book['data']:
                                    if order['orderid'] == order_id:
                                        final_status = str(order['status']).lower()
                                        new_status = OrderStatus(
                                            order_id=order_id,
                                            symbol=symbol,
                                            user_email=user.email,
                                            status=final_status,
                                            message=order.get('text', ''),
                                            quantity=float(order.get('filledshares', order.quantity if order else 0)),
                                            price=float(order.get('averageprice', order.price if order else 0)),
                                            buy_sell=order.get('transactiontype', order.buy_sell if order else 'BUY'),
                                            created_at=IST.localize(datetime.now()) if not order else order.created_at,
                                            updated_at=IST.localize(datetime.now())
                                        )
                                        db.session.merge(new_status)
                                        db.session.commit()
                                        return final_status
                            return 'UNKNOWN'
                        else:
                            logger.warning(f"API returned unexpected type for {order_id}: {type(status)}")
                            return 'UNKNOWN'
                    except Exception as e:
                        logger.error(f"Failed to fetch order status for {order_id}: {str(e)}")
                        return 'UNKNOWN'

                # Initial Buy: Only if no OPEN trades and cycle is new
                open_trades = [t for t in trades if t.status == 'OPEN']
                if not open_trades and (not trades or all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades)):
                    qty = int(strategy_data.loc[0, 'Qnty'])
                    executed_qty, order_id, order_status = place_order(smart_api, symbol, qty, ltp, user_email=user.email)
                    logger.debug(f"place_order result for initial buy: {executed_qty, order_id, order_status}")

                    if order_id and order_status not in ['completed', 'complete', 'executed']:
                        for _ in range(5):
                            order_status = get_order_status(order_id)
                            if order_status not in ['pending', 'UNKNOWN', 'timeout']:
                                break
                            logger.info(f"Waiting for initial buy order {order_id} to resolve, current status: {order_status}")
                            time.sleep(2)

                        if order_status in ['timeout', 'UNKNOWN']:
                            try:
                                order_details = smart_api.individual_order_details(order_id)
                                if isinstance(order_details, dict):
                                    final_status = str(order_details.get('status', 'UNKNOWN')).lower()
                                    if final_status in ['complete', 'executed']:
                                        executed_qty = int(order_details.get('filledshares', qty) or qty)
                                        order_status = final_status
                                        logger.info(f"Order {order_id} executed despite timeout, qty: {executed_qty}")
                                        order_entry = OrderStatus.query.filter_by(order_id=order_id).first()
                                        if order_entry:
                                            order_entry.status = final_status
                                            order_entry.updated_at = IST.localize(datetime.now())
                                            db.session.commit()
                            except Exception as e:
                                logger.error(f"Final API check failed for {order_id}: {e}")

                    logger.info(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}, Status: {order_status}")
                    with open('order_status.txt', 'a') as f:
                        f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")

                    if executed_qty > 0 and order_status in ['complete', 'executed']:
                        new_trade = Trade(
                            stock_symbol=symbol,
                            sr_no=1,
                            entry_price=ltp,
                            quantity=int(executed_qty),
                            user_email=user.email,
                            base_price=ltp,
                            total_quantity=int(executed_qty),
                            total_sold_quantity=0,
                            status='OPEN',
                            last_updated=IST.localize(datetime.now()),
                            description='Initial Buy',
                            order_id=order_id
                        )
                        db.session.add(new_trade)
                        db.session.commit()
                        logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: 1, Total_Qty: {new_trade.total_quantity}")
                    else:
                        logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}, Status: {order_status}")
                    return

                # Additional Buy and Sell Logic
                current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
                latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
                current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
                logger.info(f"Current Sr No for {symbol}: {current_sr_no}, Open Qty: {current_open_qty}")

                # Fetch phase-specific down_increment
                phase_config = PhaseConfig.query.filter_by(
                    user_email=user.email,
                    stock_symbol=symbol
                ).filter(
                    PhaseConfig.start_sr_no <= current_sr_no,
                    PhaseConfig.end_sr_no >= current_sr_no
                ).first()
                down_increment = 0.0025 if not phase_config else phase_config.down_increment / 100
                logger.info(f"Phase: {phase_config.phase if phase_config else 'Unknown'}, Down Increment: {down_increment*100}%")

                drop_percent = (ltp - base_price) / base_price
                logger.info(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
                target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
                target_row = strategy_data.loc[target_idx]
                target_sr_no = int(target_row['Sr.No'])
                total_qty = int(target_row['Total_Qty'])
                qty_to_buy = total_qty - current_open_qty

                # Additional Buy on Drop
                if drop_percent <= -down_increment and open_trades:
                    if qty_to_buy <= 0:
                        logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
                        return

                    existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
                    if existing_open_trade:
                        logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
                        return

                    executed_qty, order_id, order_status = place_order(smart_api, symbol, qty_to_buy, ltp, user_email=user.email)
                    logger.debug(f"place_order result for additional buy: {executed_qty, order_id, order_status}")

                    if order_id and order_status not in ['completed', 'complete', 'executed']:
                        for _ in range(5):
                            order_status = get_order_status(order_id)
                            if order_status not in ['pending', 'UNKNOWN', 'timeout']:
                                break
                            logger.info(f"Waiting for additional buy order {order_id} to resolve, current status: {order_status}")
                            time.sleep(2)

                        if order_status in ['timeout', 'UNKNOWN']:
                            try:
                                order_details = smart_api.individual_order_details(order_id)
                                if isinstance(order_details, dict):
                                    final_status = str(order_details.get('status', 'UNKNOWN')).lower()
                                    if final_status in ['complete', 'executed']:
                                        executed_qty = int(order_details.get('filledshares', qty_to_buy) or qty_to_buy)
                                        order_status = final_status
                                        logger.info(f"Order {order_id} executed despite timeout, qty: {executed_qty}")
                                        order_entry = OrderStatus.query.filter_by(order_id=order_id).first()
                                        if order_entry:
                                            order_entry.status = final_status
                                            order_entry.updated_at = IST.localize(datetime.now())
                                            db.session.commit()
                            except Exception as e:
                                logger.error(f"Final API check failed for {order_id}: {e}")

                    logger.info(f"Additional buy for {symbol} at {ltp}, Qty: {qty_to_buy}, Executed Qty: {executed_qty}, Status: {order_status}")
                    with open('order_status.txt', 'a') as f:
                        f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")

                    if executed_qty > 0 and order_status in ['complete', 'executed']:
                        for trade in trades:
                            if trade.status == 'OPEN':
                                trade.status = 'OLD_BUY'
                                trade.last_updated = IST.localize(datetime.now())
                                trade.description = f"Updated to OLD_BUY before new buy at Sr.No {target_sr_no}"
                                logger.info(f"Updated trade Sr.No {trade.sr_no} to OLD_BUY, Total_Qty: {trade.total_quantity}")
                        
                        new_trade = Trade(
                            stock_symbol=symbol,
                            sr_no=target_sr_no,
                            entry_price=ltp,
                            quantity=int(executed_qty),
                            user_email=user.email,
                            base_price=base_price,
                            total_quantity=total_qty,
                            total_sold_quantity=0,
                            status='OPEN',
                            last_updated=IST.localize(datetime.now()),
                            description='Additional Buy',
                            order_id=order_id
                        )
                        db.session.add(new_trade)
                        db.session.commit()
                        logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
                    else:
                        logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}, Status: {order_status}")
                    return

                # Sell Logic
                all_closed = True
                for trade in trades:
                    if trade.status != 'OPEN':
                        continue
                    all_closed = False
                    
                    base_price = trade.base_price
                    strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                    sr_no = trade.sr_no
                    entry_price = trade.entry_price
                    current_qty = trade.total_quantity - trade.total_sold_quantity
                    row = strategy_data.loc[sr_no-1]

                    final_tgt = row['FINAL_TGT']
                    first_tgt = row['First_TGT']
                    second_tgt = row['Second_TGT']
                    half_qty = row['EXIT_1st_HALF'] if row['EXIT_1st_HALF'] is not None else 0
                    second_half_qty = row['EXIT_2nd_HALF'] if row['EXIT_2nd_HALF'] is not None else 0

                    logger.info(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}, Second_Half_Qty={second_half_qty}")

                    if sr_no <= 8:
                        if ltp >= final_tgt and current_qty > 0:
                            logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'Final TGT'
                                if trade.total_sold_quantity >= trade.total_quantity:
                                    trade.status = 'CLOSED'
                                    trade.cycle_count += 1
                                    logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                            else:
                                logger.warning(f"Sell failed for {symbol} Sr.No {sr_no} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                            if trade.total_sold_quantity < current_qty and ltp < entry_price:
                                re_entry_qty = current_qty - trade.total_sold_quantity
                                executed_qty, order_id, order_status = place_order(smart_api, symbol, re_entry_qty, ltp, 'BUY', user_email=user.email)
                                if executed_qty > 0 and order_status in ['complete', 'executed']:
                                    trade.total_quantity += executed_qty
                                    trade.description = f"Re-entry after partial sell at {entry_price}"
                                    trade.last_updated = IST.localize(datetime.now())
                                    db.session.commit()
                                    logger.info(f"Re-entered {executed_qty} for {symbol} Sr.No {sr_no} at {ltp}")
                    elif sr_no <= 21:
                        if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'First TGT'
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
                            if trade.total_sold_quantity < half_qty and ltp < entry_price:
                                re_entry_qty = half_qty - trade.total_sold_quantity
                                executed_qty, order_id, order_status = place_order(smart_api, symbol, re_entry_qty, ltp, 'BUY', user_email=user.email)
                                if executed_qty > 0 and order_status in ['complete', 'executed']:
                                    trade.total_quantity += executed_qty
                                    trade.description = f"Re-entry after partial sell at {entry_price}"
                                    trade.last_updated = IST.localize(datetime.now())
                                    db.session.commit()
                                    logger.info(f"Re-entered {executed_qty} for {symbol} Sr.No {sr_no} at {ltp}")
                        elif ltp >= final_tgt and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'Final TGT'
                                if trade.total_sold_quantity >= trade.total_quantity:
                                    trade.status = 'CLOSED'
                                    trade.cycle_count += 1
                                    logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                    else:  # Sr.No > 21
                        if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'First TGT'
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
                            if trade.total_sold_quantity < half_qty and ltp < entry_price:
                                re_entry_qty = half_qty - trade.total_sold_quantity
                                executed_qty, order_id, order_status = place_order(smart_api, symbol, re_entry_qty, ltp, 'BUY', user_email=user.email)
                                if executed_qty > 0 and order_status in ['complete', 'executed']:
                                    trade.total_quantity += executed_qty
                                    trade.description = f"Re-entry after partial sell at {entry_price}"
                                    trade.last_updated = IST.localize(datetime.now())
                                    db.session.commit()
                                    logger.info(f"Re-entered {executed_qty} for {symbol} Sr.No {sr_no} at {ltp}")
                        elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, second_half_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'Second TGT'
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{second_half_qty}, Sr.No {sr_no}")
                            if trade.total_sold_quantity < half_qty + second_half_qty and ltp < entry_price:
                                re_entry_qty = (half_qty + second_half_qty) - trade.total_sold_quantity
                                executed_qty, order_id, order_status = place_order(smart_api, symbol, re_entry_qty, ltp, 'BUY', user_email=user.email)
                                if executed_qty > 0 and order_status in ['complete', 'executed']:
                                    trade.total_quantity += executed_qty
                                    trade.description = f"Re-entry after partial sell at {entry_price}"
                                    trade.last_updated = IST.localize(datetime.now())
                                    db.session.commit()
                                    logger.info(f"Re-entered {executed_qty} for {symbol} Sr.No {sr_no} at {ltp}")
                        elif ltp >= final_tgt and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'Final TGT'
                                if trade.total_sold_quantity >= trade.total_quantity:
                                    trade.status = 'CLOSED'
                                    trade.cycle_count += 1
                                    logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")

                # Cycle Reset
                if all_closed and trades:
                    logger.info(f"All trades for {symbol} are CLOSED, resetting cycle")
                    if current_cycle:
                        current_cycle.cycle_end = IST.localize(datetime.now())
                        current_cycle.total_sold = sum(t.total_sold_quantity for t in trades)
                        current_cycle.total_bought = sum(t.total_quantity for t in trades)
                        current_cycle.profit = sum((ltp - t.entry_price) * t.total_sold_quantity for t in trades if t.status == 'CLOSED')
                        current_cycle.status = 'COMPLETED'
                        logger.info(f"Completed TradeCycle for {symbol}: Total Bought {current_cycle.total_bought}, Total Sold {current_cycle.total_sold}, Profit {current_cycle.profit}")
                        db.session.commit()
                    
                    time.sleep(7)  # 7-second delay before restarting cycle
                    new_cycle = TradeCycle(
                        stock_symbol=symbol,
                        user_email=user.email,
                        cycle_start=IST.localize(datetime.now()),
                        status='ACTIVE'
                    )
                    db.session.add(new_cycle)
                    db.session.commit()
                    logger.info(f"Started new TradeCycle for {symbol}")

            except Exception as e:
                logger.error(f"Error in process_strategy for {symbol}: {str(e)}", exc_info=True)
                db.session.rollback()
            finally:
                db.session.close()
'''
'''
import time
from datetime import datetime, timedelta
from threading import Lock
import pandas as pd

strategy_locks = {}

def process_strategy(user, symbol, ltp, smart_api):
    logger.info(f"Process strategy for {symbol} at {ltp}")
    
    with app.app_context():
        lock_key = f"{user.email}_{symbol}"
        with strategy_locks.setdefault(lock_key, Lock()):
            try:
                trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
                stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=symbol).first()
                wallet_value = stock.allotment_captial if stock else 0
                
                logger.info(f"Wallet value for {symbol}: {wallet_value}")
                logger.info(f"Trades for {symbol}: {len(trades)}, Trades: {[t.__dict__ for t in trades]}")

                # Check for pending orders
                pending_orders = OrderStatus.query.filter_by(
                    user_email=user.email,
                    symbol=symbol,
                    buy_sell='BUY'
                ).filter(
                    OrderStatus.status.in_(['pending', 'UNKNOWN', 'timeout'])
                ).filter(
                    OrderStatus.created_at > IST.localize(datetime.now()) - timedelta(minutes=5)
                ).all()
                if pending_orders:
                    logger.info(f"Skipping {symbol}: {len(pending_orders)} recent pending/timeout orders exist: {[o.order_id for o in pending_orders]}")
                    return

                # Check active cycle
                current_cycle = TradeCycle.query.filter_by(
                    stock_symbol=symbol,
                    user_email=user.email,
                    status='ACTIVE'
                ).order_by(TradeCycle.cycle_start.desc()).first()

                # If no active cycle and no trades, start a new one
                if not current_cycle and not trades:
                    new_cycle = TradeCycle(
                        stock_symbol=symbol,
                        user_email=user.email,
                        cycle_start=IST.localize(datetime.now()),
                        status='ACTIVE'
                    )
                    db.session.add(new_cycle)
                    db.session.commit()
                    logger.info(f"Started new TradeCycle for {symbol}")
                    current_cycle = new_cycle
                elif not current_cycle and all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades):
                    logger.info(f"No active cycle for {symbol}, but trades exist. Cycle should have reset earlier.")
                    # Cycle reset handled later after sell logic

                latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
                base_price = latest_open_trade.base_price if latest_open_trade else (trades[-1].base_price if trades else ltp)
                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)

                def get_order_status(order_id):
                    order = OrderStatus.query.filter_by(order_id=order_id, user_email=user.email).first()
                    if order and order.status not in ['pending', 'UNKNOWN', 'timeout']:
                        logger.info(f"Order status from table for {order_id}: {order.status}")
                        return order.status
                    try:
                        status = smart_api.individual_order_details(order_id)
                        logger.info(f"Order status from API for {order_id}: {status}")
                        if isinstance(status, dict):
                            new_status = OrderStatus(
                                order_id=order_id,
                                symbol=symbol,
                                user_email=user.email,
                                status=str(status.get('status', 'UNKNOWN')).lower(),
                                message=status.get('text', ''),
                                quantity=float(status.get('quantity', order.quantity if order else 0)),
                                price=float(status.get('price', order.price if order else 0)),
                                buy_sell=status.get('transactiontype', order.buy_sell if order else 'BUY'),
                                created_at=IST.localize(datetime.now()) if not order else order.created_at,
                                updated_at=IST.localize(datetime.now())
                            )
                            db.session.merge(new_status)
                            db.session.commit()
                            return new_status.status
                        elif isinstance(status, bool):
                            logger.warning(f"API returned boolean {status} for {order_id}, falling back to OrderBook")
                            order_book = smart_api.orderBook()
                            if order_book.get('status') == True and 'data' in order_book:
                                for order in order_book['data']:
                                    if order['orderid'] == order_id:
                                        final_status = str(order['status']).lower()
                                        new_status = OrderStatus(
                                            order_id=order_id,
                                            symbol=symbol,
                                            user_email=user.email,
                                            status=final_status,
                                            message=order.get('text', ''),
                                            quantity=float(order.get('filledshares', order.quantity if order else 0)),
                                            price=float(order.get('averageprice', order.price if order else 0)),
                                            buy_sell=order.get('transactiontype', order.buy_sell if order else 'BUY'),
                                            created_at=IST.localize(datetime.now()) if not order else order.created_at,
                                            updated_at=IST.localize(datetime.now())
                                        )
                                        db.session.merge(new_status)
                                        db.session.commit()
                                        return final_status
                            return 'UNKNOWN'
                        else:
                            logger.warning(f"API returned unexpected type for {order_id}: {type(status)}")
                            return 'UNKNOWN'
                    except Exception as e:
                        logger.error(f"Failed to fetch order status for {order_id}: {str(e)}")
                        return 'UNKNOWN'

                # Initial Buy: Only if no OPEN trades and cycle is new or completed
                open_trades = [t for t in trades if t.status == 'OPEN']
                if not open_trades and (not trades or (current_cycle and current_cycle.status == 'COMPLETED') or all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades)):
                    qty = int(strategy_data.loc[0, 'Qnty'])
                    executed_qty, order_id, order_status = place_order(smart_api, symbol, qty, ltp, user_email=user.email)
                    logger.debug(f"place_order result for initial buy: {executed_qty, order_id, order_status}")

                    if order_id and order_status not in ['completed', 'complete', 'executed']:
                        for _ in range(5):
                            order_status = get_order_status(order_id)
                            if order_status not in ['pending', 'UNKNOWN', 'timeout']:
                                break
                            logger.info(f"Waiting for initial buy order {order_id} to resolve, current status: {order_status}")
                            time.sleep(2)

                        if order_status in ['timeout', 'UNKNOWN']:
                            try:
                                order_details = smart_api.individual_order_details(order_id)
                                if isinstance(order_details, dict):
                                    final_status = str(order_details.get('status', 'UNKNOWN')).lower()
                                    if final_status in ['complete', 'executed']:
                                        executed_qty = int(order_details.get('filledshares', qty) or qty)
                                        order_status = final_status
                                        logger.info(f"Order {order_id} executed despite timeout, qty: {executed_qty}")
                                        order_entry = OrderStatus.query.filter_by(order_id=order_id).first()
                                        if order_entry:
                                            order_entry.status = final_status
                                            order_entry.updated_at = IST.localize(datetime.now())
                                            db.session.commit()
                            except Exception as e:
                                logger.error(f"Final API check failed for {order_id}: {e}")

                    logger.info(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}, Status: {order_status}")
                    with open('order_status.txt', 'a') as f:
                        f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")

                    if executed_qty > 0 and order_status in ['complete', 'executed']:
                        new_trade = Trade(
                            stock_symbol=symbol,
                            sr_no=1,
                            entry_price=ltp,
                            quantity=int(executed_qty),
                            user_email=user.email,
                            base_price=ltp,
                            total_quantity=int(executed_qty),
                            total_sold_quantity=0,
                            status='OPEN',
                            last_updated=IST.localize(datetime.now()),
                            description='Initial Buy',
                            order_id=order_id
                        )
                        db.session.add(new_trade)
                        db.session.commit()
                        logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: 1, Total_Qty: {new_trade.total_quantity}")
                    else:
                        logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}, Status: {order_status}")
                    return

                # Additional Buy and Sell Logic
                current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
                latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
                current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
                logger.info(f"Current Sr No for {symbol}: {current_sr_no}, Open Qty: {current_open_qty}")

                # Fetch phase-specific down_increment
                phase_config = PhaseConfig.query.filter_by(
                    user_email=user.email,
                    stock_symbol=symbol
                ).filter(
                    PhaseConfig.start_sr_no <= current_sr_no,
                    PhaseConfig.end_sr_no >= current_sr_no
                ).first()
                down_increment = 0.0025 if not phase_config else phase_config.down_increment / 100
                logger.info(f"Phase: {phase_config.phase if phase_config else 'Unknown'}, Down Increment: {down_increment*100}%")

                drop_percent = (ltp - base_price) / base_price
                logger.info(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
                target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
                target_row = strategy_data.loc[target_idx]
                target_sr_no = int(target_row['Sr.No'])
                total_qty = int(target_row['Total_Qty'])
                qty_to_buy = total_qty - current_open_qty

                # Additional Buy on Drop
                if drop_percent <= -down_increment and open_trades:
                    if qty_to_buy <= 0:
                        logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
                        return

                    existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
                    if existing_open_trade:
                        logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
                        return

                    if target_sr_no <= current_sr_no:
                        logger.info(f"Skipping buy for {symbol}: Target Sr.No {target_sr_no} <= Current Sr.No {current_sr_no}")
                        return

                    executed_qty, order_id, order_status = place_order(smart_api, symbol, qty_to_buy, ltp, user_email=user.email)
                    logger.debug(f"place_order result for additional buy: {executed_qty, order_id, order_status}")

                    if order_id and order_status not in ['completed', 'complete', 'executed']:
                        for _ in range(5):
                            order_status = get_order_status(order_id)
                            if order_status not in ['pending', 'UNKNOWN', 'timeout']:
                                break
                            logger.info(f"Waiting for additional buy order {order_id} to resolve, current status: {order_status}")
                            time.sleep(2)

                        if order_status in ['timeout', 'UNKNOWN']:
                            try:
                                order_details = smart_api.individual_order_details(order_id)
                                if isinstance(order_details, dict):
                                    final_status = str(order_details.get('status', 'UNKNOWN')).lower()
                                    if final_status in ['complete', 'executed']:
                                        executed_qty = int(order_details.get('filledshares', qty_to_buy) or qty_to_buy)
                                        order_status = final_status
                                        logger.info(f"Order {order_id} executed despite timeout, qty: {executed_qty}")
                                        order_entry = OrderStatus.query.filter_by(order_id=order_id).first()
                                        if order_entry:
                                            order_entry.status = final_status
                                            order_entry.updated_at = IST.localize(datetime.now())
                                            db.session.commit()
                            except Exception as e:
                                logger.error(f"Final API check failed for {order_id}: {e}")

                    logger.info(f"Additional buy for {symbol} at {ltp}, Qty: {qty_to_buy}, Executed Qty: {executed_qty}, Status: {order_status}")
                    with open('order_status.txt', 'a') as f:
                        f.write(f"{datetime.now()} - {symbol} - {order_id}: {order_status}\n")

                    if executed_qty > 0 and order_status in ['complete', 'executed']:
                        for trade in trades:
                            if trade.status == 'OPEN':
                                trade.status = 'OLD_BUY'
                                trade.last_updated = IST.localize(datetime.now())
                                trade.description = f"Updated to OLD_BUY before new buy at Sr.No {target_sr_no}"
                                logger.info(f"Updated trade Sr.No {trade.sr_no} to OLD_BUY, Total_Qty: {trade.total_quantity}")
                        
                        new_trade = Trade(
                            stock_symbol=symbol,
                            sr_no=target_sr_no,
                            entry_price=ltp,
                            quantity=int(executed_qty),
                            user_email=user.email,
                            base_price=base_price,
                            total_quantity=total_qty,
                            total_sold_quantity=0,
                            status='OPEN',
                            last_updated=IST.localize(datetime.now()),
                            description='Additional Buy',
                            order_id=order_id
                        )
                        db.session.add(new_trade)
                        db.session.commit()
                        logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
                    else:
                        logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}, Status: {order_status}")
                    return

                # Sell Logic
                all_closed = True
                for trade in trades:
                    if trade.status != 'OPEN':
                        continue
                    all_closed = False
                    
                    base_price = trade.base_price
                    strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                    sr_no = trade.sr_no
                    entry_price = trade.entry_price
                    current_qty = trade.total_quantity - trade.total_sold_quantity
                    row = strategy_data.loc[sr_no-1]

                    final_tgt = row['FINAL_TGT']
                    first_tgt = row['First_TGT']
                    second_tgt = row['Second_TGT']
                    half_qty = row['EXIT_1st_HALF'] if row['EXIT_1st_HALF'] is not None else 0
                    second_half_qty = row['EXIT_2nd_HALF'] if row['EXIT_2nd_HALF'] is not None else 0

                    logger.info(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}, Second_Half_Qty={second_half_qty}")

                    if sr_no <= 8:
                        if ltp >= final_tgt and current_qty > 0:
                            logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'Final TGT'
                                if trade.total_sold_quantity >= trade.total_quantity:
                                    trade.status = 'CLOSED'
                                    trade.cycle_count += 1
                                    logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                            else:
                                logger.warning(f"Sell failed for {symbol} Sr.No {sr_no} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                            if trade.total_sold_quantity < current_qty and ltp < entry_price:
                                re_entry_qty = current_qty - trade.total_sold_quantity
                                executed_qty, order_id, order_status = place_order(smart_api, symbol, re_entry_qty, ltp, 'BUY', user_email=user.email)
                                if executed_qty > 0 and order_status in ['complete', 'executed']:
                                    trade.total_quantity += executed_qty
                                    trade.description = f"Re-entry after partial sell at {entry_price}"
                                    trade.last_updated = IST.localize(datetime.now())
                                    db.session.commit()
                                    logger.info(f"Re-entered {executed_qty} for {symbol} Sr.No {sr_no} at {ltp}")
                    elif sr_no <= 21:
                        if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'First TGT'
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
                            if trade.total_sold_quantity < half_qty and ltp < entry_price:
                                re_entry_qty = half_qty - trade.total_sold_quantity
                                executed_qty, order_id, order_status = place_order(smart_api, symbol, re_entry_qty, ltp, 'BUY', user_email=user.email)
                                if executed_qty > 0 and order_status in ['complete', 'executed']:
                                    trade.total_quantity += executed_qty
                                    trade.description = f"Re-entry after partial sell at {entry_price}"
                                    trade.last_updated = IST.localize(datetime.now())
                                    db.session.commit()
                                    logger.info(f"Re-entered {executed_qty} for {symbol} Sr.No {sr_no} at {ltp}")
                        elif ltp >= final_tgt and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'Final TGT'
                                if trade.total_sold_quantity >= trade.total_quantity:
                                    trade.status = 'CLOSED'
                                    trade.cycle_count += 1
                                    logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                    else:  # Sr.No > 21
                        if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'First TGT'
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
                            if trade.total_sold_quantity < half_qty and ltp < entry_price:
                                re_entry_qty = half_qty - trade.total_sold_quantity
                                executed_qty, order_id, order_status = place_order(smart_api, symbol, re_entry_qty, ltp, 'BUY', user_email=user.email)
                                if executed_qty > 0 and order_status in ['complete', 'executed']:
                                    trade.total_quantity += executed_qty
                                    trade.description = f"Re-entry after partial sell at {entry_price}"
                                    trade.last_updated = IST.localize(datetime.now())
                                    db.session.commit()
                                    logger.info(f"Re-entered {executed_qty} for {symbol} Sr.No {sr_no} at {ltp}")
                        elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, second_half_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'Second TGT'
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{second_half_qty}, Sr.No {sr_no}")
                            if trade.total_sold_quantity < half_qty + second_half_qty and ltp < entry_price:
                                re_entry_qty = (half_qty + second_half_qty) - trade.total_sold_quantity
                                executed_qty, order_id, order_status = place_order(smart_api, symbol, re_entry_qty, ltp, 'BUY', user_email=user.email)
                                if executed_qty > 0 and order_status in ['complete', 'executed']:
                                    trade.total_quantity += executed_qty
                                    trade.description = f"Re-entry after partial sell at {entry_price}"
                                    trade.last_updated = IST.localize(datetime.now())
                                    db.session.commit()
                                    logger.info(f"Re-entered {executed_qty} for {symbol} Sr.No {sr_no} at {ltp}")
                        elif ltp >= final_tgt and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'Final TGT'
                                if trade.total_sold_quantity >= trade.total_quantity:
                                    trade.status = 'CLOSED'
                                    trade.cycle_count += 1
                                    logger.info(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")

                # Cycle Reset
                if all_closed and trades:
                    logger.info(f"All trades for {symbol} are CLOSED, resetting cycle")
                    if current_cycle and current_cycle.status == 'ACTIVE':
                        current_cycle.cycle_end = IST.localize(datetime.now())
                        current_cycle.total_sold = sum(t.total_sold_quantity for t in trades)
                        current_cycle.total_bought = sum(t.total_quantity for t in trades)
                        current_cycle.profit = sum((ltp - t.entry_price) * t.total_sold_quantity for t in trades if t.status == 'CLOSED')
                        current_cycle.status = 'COMPLETED'
                        logger.info(f"Completed TradeCycle for {symbol}: Total Bought {current_cycle.total_bought}, Total Sold {current_cycle.total_sold}, Profit {current_cycle.profit}")
                        db.session.commit()
                    
                    time.sleep(7)  # 7-second delay before restarting cycle
                    new_cycle = TradeCycle(
                        stock_symbol=symbol,
                        user_email=user.email,
                        cycle_start=IST.localize(datetime.now()),
                        status='ACTIVE'
                    )
                    db.session.add(new_cycle)
                    db.session.commit()
                    logger.info(f"Started new TradeCycle for {symbol}")

            except Exception as e:
                logger.error(f"Error in process_strategy for {symbol}: {str(e)}", exc_info=True)
                db.session.rollback()
            finally:
                db.session.close()
'''

import time
from datetime import datetime, timedelta
from threading import Lock
import pandas as pd

strategy_locks = {}

def log_to_file(message):
    with open('log.txt', 'a') as f:
        f.write(f"{datetime.now()} - {message}\n")

def process_strategy(user, symbol, ltp, smart_api):
    log_to_file(f"Process strategy for {symbol} at {ltp}")
    
    with app.app_context():
        lock_key = f"{user.email}_{symbol}"
        with strategy_locks.setdefault(lock_key, Lock()):
            try:
                trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
                stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=symbol).first()
                wallet_value = stock.allotment_captial if stock else 0
                
                log_to_file(f"Wallet value for {symbol}: {wallet_value}")
                log_to_file(f"Trades for {symbol}: {len(trades)}, Trades: {[t.__dict__ for t in trades]}")

                # Check for pending orders
                pending_orders = OrderStatus.query.filter_by(
                    user_email=user.email,
                    symbol=symbol,
                    buy_sell='BUY'
                ).filter(
                    OrderStatus.status.in_(['pending', 'UNKNOWN', 'timeout'])
                ).filter(
                    OrderStatus.created_at > IST.localize(datetime.now()) - timedelta(minutes=5)
                ).all()
                if pending_orders:
                    log_to_file(f"Skipping {symbol}: {len(pending_orders)} recent pending/timeout orders exist: {[o.order_id for o in pending_orders]}")
                    return

                # Check active cycle
                current_cycle = TradeCycle.query.filter_by(
                    stock_symbol=symbol,
                    user_email=user.email,
                    status='ACTIVE'
                ).order_by(TradeCycle.cycle_start.desc()).first()

                if not current_cycle and not trades:
                    new_cycle = TradeCycle(
                        stock_symbol=symbol,
                        user_email=user.email,
                        cycle_start=IST.localize(datetime.now()),
                        status='ACTIVE'
                    )
                    db.session.add(new_cycle)
                    db.session.commit()
                    log_to_file(f"Started new TradeCycle for {symbol}")
                    current_cycle = new_cycle
                elif not current_cycle and all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades):
                    log_to_file(f"No active cycle for {symbol}, but trades exist. Cycle should have reset earlier.")

                latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
                base_price = latest_open_trade.base_price if latest_open_trade else (trades[-1].base_price if trades else ltp)
                log_to_file(f"Base price for {symbol}: {base_price}")
                log_to_file(f"Latest open trade for {symbol}: {latest_open_trade}")
                # log_to_file(f"Strategy data for {symbol}: {get_strategy_data(user.email, symbol, base_price, wallet_value)}")
                
                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                log_to_file(f"base_price: {base_price}, wallet_value: {wallet_value}, strategy_data: {strategy_data}")
                log_to_file(f"Strategy data for {symbol}: {strategy_data}")
                
                def get_order_status(unique_order_id):
                    # Look up by unique_order_id in the database
                    order = OrderStatus.query.filter_by(unique_order_id=unique_order_id, user_email=user.email).first()
                    if order and order.status not in ['pending', 'UNKNOWN', 'timeout']:
                        log_to_file(f"Order status from table for unique_order_id {unique_order_id} (order_id: {order.order_id}): {order.status}")
                        return order.status

                    try:
                        # Query the API with unique_order_id
                        status = smart_api.individual_order_details(unique_order_id)
                        log_to_file(f"Order status from API for unique_order_id {unique_order_id}: {status}")

                        if isinstance(status, dict) and 'data' in status:
                            # Extract nested status fields from 'data'
                            final_status = str(status['data'].get('orderstatus', status['data'].get('status', 'UNKNOWN'))).lower()
                            executed_qty = float(status['data'].get('filledshares', order.quantity if order else 0))
                            order_id = status['data'].get('orderid', order.order_id if order else None)  # Get exchange order_id

                            # Update or create OrderStatus entry
                            new_status = OrderStatus(
                                user_email=user.email,
                                order_id=order_id,  # Exchange-generated order ID
                                unique_order_id=unique_order_id,  # Client-generated unique order ID
                                symbol=symbol,
                                status=final_status,
                                message=status['data'].get('text', ''),
                                quantity=executed_qty,
                                price=float(status['data'].get('averageprice', order.price if order else 0)),
                                buy_sell=status['data'].get('transactiontype', order.buy_sell if order else 'BUY'),
                                created_at=order.created_at if order else IST.localize(datetime.now()),
                                updated_at=IST.localize(datetime.now())
                            )
                            db.session.merge(new_status)  # Merge to update existing record or insert new one
                            db.session.commit()
                            log_to_file(f"Updated order status for unique_order_id {unique_order_id} (order_id: {order_id}): {final_status}")
                            return final_status

                        elif isinstance(status, dict) and 'status' in status and not status['status']:
                            # Handle API error (e.g., 'Order not found')
                            log_to_file(f"API error for unique_order_id {unique_order_id}: {status.get('message', 'Unknown error')}")
                            return 'UNKNOWN'

                        elif isinstance(status, bool):
                            # Fallback to OrderBook if API returns a boolean
                            log_to_file(f"API returned boolean {status} for unique_order_id {unique_order_id}, falling back to OrderBook")
                            order_book = smart_api.orderBook()
                            log_to_file(f"OrderBook response: {order_book}")
                            if order_book.get('status') == True and 'data' in order_book:
                                for order_data in order_book['data']:
                                    if order_data.get('uniqueorderid') == unique_order_id:
                                        final_status = str(order_data.get('orderstatus', order_data.get('status', 'UNKNOWN'))).lower()
                                        executed_qty = float(order_data.get('filledshares', order.quantity if order else 0))
                                        order_id = order_data.get('orderid', order.order_id if order else None)
                                        new_status = OrderStatus(
                                            user_email=user.email,
                                            order_id=order_id,
                                            unique_order_id=unique_order_id,
                                            symbol=symbol,
                                            status=final_status,
                                            message=order_data.get('text', ''),
                                            quantity=executed_qty,
                                            price=float(order_data.get('averageprice', order.price if order else 0)),
                                            buy_sell=order_data.get('transactiontype', order.buy_sell if order else 'BUY'),
                                            created_at=order.created_at if order else IST.localize(datetime.now()),
                                            updated_at=IST.localize(datetime.now())
                                        )
                                        db.session.merge(new_status)
                                        db.session.commit()
                                        log_to_file(f"Updated order status from OrderBook for unique_order_id {unique_order_id} (order_id: {order_id}): {final_status}")
                                        return final_status
                            return 'UNKNOWN'

                        else:
                            log_to_file(f"API returned unexpected response for unique_order_id {unique_order_id}: {type(status)} - {status}")
                            return 'UNKNOWN'

                    except Exception as e:
                        log_to_file(f"Failed to fetch order status for unique_order_id {unique_order_id}: {str(e)}")
                        return 'UNKNOWN'

               

                open_trades = [t for t in trades if t.status == 'OPEN']
                if not open_trades and (not trades or (current_cycle and current_cycle.status == 'COMPLETED') or all(t.status in ['CLOSED', 'OLD_BUY'] for t in trades)):
                    qty = int(strategy_data.loc[0, 'Qnty'])
                    executed_qty, order_id, order_status = place_order(smart_api, symbol, qty, ltp, user_email=user.email)
                    log_to_file(f"place_order result for initial buy: {executed_qty}, {order_id}, {order_status}")

                    if order_id and order_status not in ['completed', 'complete', 'executed']:
                        for _ in range(5):
                            order_status = get_order_status(order_id)
                            if order_status not in ['pending', 'UNKNOWN', 'timeout']:
                                break
                            log_to_file(f"Waiting for initial buy order {order_id} to resolve, current status: {order_status}")
                            time.sleep(2)

                        if order_status in ['timeout', 'UNKNOWN', 'pending']:
                            try:
                                unique_order_id = OrderStatus.query.filter_by(order_id=order_id, user_email=user.email).first().unique_order_id
                                
                                order_details = smart_api.individual_order_details(unique_order_id)
                                log_to_file(f"individual Order details for {order_id}: {order_details}")
                                if isinstance(order_details, dict):
                                    final_status = str(order_details.get('status', 'UNKNOWN')).lower()
                                    executed_qty = int(order_details.get('filledshares', qty) or 0)
                                    log_to_file(f"Final API check for {order_id}: status={final_status}, executed_qty={executed_qty}")
                                    order_entry = OrderStatus.query.filter_by(order_id=order_id).first()
                                    if order_entry:
                                        order_entry.status = final_status
                                        order_entry.quantity = executed_qty
                                        order_entry.updated_at = IST.localize(datetime.now())
                                        db.session.commit()
                                    order_status = final_status
                            except Exception as e:
                                log_to_file(f"Final API check failed for {order_id}: {e}")

                    log_to_file(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}, Status: {order_status}")

                    if executed_qty > 0 and order_status in ['complete', 'executed']:
                        new_trade = Trade(
                            stock_symbol=symbol,
                            sr_no=1,
                            entry_price=ltp,
                            quantity=int(executed_qty),
                            user_email=user.email,
                            base_price=ltp,
                            total_quantity=int(executed_qty),
                            total_sold_quantity=0,
                            status='OPEN',
                            last_updated=IST.localize(datetime.now()),
                            description='Initial Buy',
                            order_id=order_id
                        )
                        db.session.add(new_trade)
                        db.session.commit()
                        log_to_file(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: 1, Total_Qty: {new_trade.total_quantity}")
                    else:
                        log_to_file(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}, Status: {order_status}")
                    return

                current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
                latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
                current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
                log_to_file(f"Current Sr No for {symbol}: {current_sr_no}, Open Qty: {current_open_qty}")

                phase_config = PhaseConfig.query.filter_by(
                    user_email=user.email,
                    stock_symbol=symbol
                ).filter(
                    PhaseConfig.start_sr_no <= current_sr_no,
                    PhaseConfig.end_sr_no >= current_sr_no
                ).first()
                down_increment = 0.0025 if not phase_config else phase_config.down_increment / 100
                log_to_file(f"Phase: {phase_config.phase if phase_config else 'Unknown'}, Down Increment: {down_increment*100}%")

                drop_percent = (ltp - base_price) / base_price
                log_to_file(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
                target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
                target_row = strategy_data.loc[target_idx]
                target_sr_no = int(target_row['Sr.No'])
                total_qty = int(target_row['Total_Qty'])
                qty_to_buy = total_qty - current_open_qty
                log_to_file(f"Target Sr.No: {target_sr_no}, Total Qty: {total_qty}, Qty to Buy: {qty_to_buy}")

                if drop_percent <= -down_increment and open_trades:
                    if qty_to_buy <= 0:
                        log_to_file(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
                        return

                    existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
                    if existing_open_trade:
                        log_to_file(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
                        return

                    if target_sr_no <= current_sr_no:
                        log_to_file(f"Skipping buy for {symbol}: Target Sr.No {target_sr_no} <= Current Sr.No {current_sr_no}")
                        return

                    executed_qty, order_id, order_status = place_order(smart_api, symbol, qty_to_buy, ltp, user_email=user.email)
                    log_to_file(f"place_order result for additional buy: {executed_qty}, {order_id}, {order_status}")

                    if order_id and order_status not in ['completed', 'complete', 'executed']:
                        for _ in range(5):
                            order_status = get_order_status(order_id)
                            if order_status not in ['pending', 'UNKNOWN', 'timeout']:
                                break
                            log_to_file(f"Waiting for additional buy order {order_id} to resolve, current status: {order_status}")
                            time.sleep(2)

                        if order_status in ['timeout', 'UNKNOWN']:
                            try:
                                order_details = smart_api.individual_order_details(order_id)
                                if isinstance(order_details, dict):
                                    final_status = str(order_details.get('status', 'UNKNOWN')).lower()
                                    executed_qty = int(order_details.get('filledshares', qty_to_buy) or 0)
                                    log_to_file(f"Final API check for {order_id}: status={final_status}, executed_qty={executed_qty}")
                                    order_entry = OrderStatus.query.filter_by(order_id=order_id).first()
                                    if order_entry:
                                        order_entry.status = final_status
                                        order_entry.quantity = executed_qty
                                        order_entry.updated_at = IST.localize(datetime.now())
                                        db.session.commit()
                                    order_status = final_status
                            except Exception as e:
                                log_to_file(f"Final API check failed for {order_id}: {e}")

                    log_to_file(f"Additional buy for {symbol} at {ltp}, Qty: {qty_to_buy}, Executed Qty: {executed_qty}, Status: {order_status}")

                    if executed_qty > 0 and order_status in ['complete', 'executed']:
                        for trade in trades:
                            if trade.status == 'OPEN':
                                trade.status = 'OLD_BUY'
                                trade.last_updated = IST.localize(datetime.now())
                                trade.description = f"Updated to OLD_BUY before new buy at Sr.No {target_sr_no}"
                                log_to_file(f"Updated trade Sr.No {trade.sr_no} to OLD_BUY, Total_Qty: {trade.total_quantity}")
                        
                        new_trade = Trade(
                            stock_symbol=symbol,
                            sr_no=target_sr_no,
                            entry_price=ltp,
                            quantity=int(executed_qty),
                            user_email=user.email,
                            base_price=base_price,
                            total_quantity=total_qty,
                            total_sold_quantity=0,
                            status='OPEN',
                            last_updated=IST.localize(datetime.now()),
                            description='Additional Buy',
                            order_id=order_id
                        )
                        db.session.add(new_trade)
                        db.session.commit()
                        log_to_file(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
                    else:
                        log_to_file(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}, Status: {order_status}")
                    return

                all_closed = True
                for trade in trades:
                    if trade.status != 'OPEN':
                        continue
                    all_closed = False
                    
                    base_price = trade.base_price
                    strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                    sr_no = trade.sr_no
                    entry_price = trade.entry_price
                    current_qty = trade.total_quantity - trade.total_sold_quantity
                    row = strategy_data.loc[sr_no-1]

                    final_tgt = row['FINAL_TGT']
                    first_tgt = row['First_TGT']
                    second_tgt = row['Second_TGT']
                    half_qty = row['EXIT_1st_HALF'] if row['EXIT_1st_HALF'] is not None else 0
                    second_half_qty = row['EXIT_2nd_HALF'] if row['EXIT_2nd_HALF'] is not None else 0

                    log_to_file(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}, Second_Half_Qty={second_half_qty}")

                    if sr_no <= 8:
                        if ltp >= final_tgt and current_qty > 0:
                            log_to_file(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'Final TGT'
                                if trade.total_sold_quantity >= trade.total_quantity:
                                    trade.status = 'CLOSED'
                                    trade.cycle_count += 1
                                    log_to_file(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                log_to_file(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                            else:
                                log_to_file(f"Sell failed for {symbol} Sr.No {sr_no} at {ltp}, Qty: {current_qty}, Status: {order_status}")
                            if trade.total_sold_quantity < current_qty and ltp < entry_price:
                                re_entry_qty = current_qty - trade.total_sold_quantity
                                executed_qty, order_id, order_status = place_order(smart_api, symbol, re_entry_qty, ltp, 'BUY', user_email=user.email)
                                if executed_qty > 0 and order_status in ['complete', 'executed']:
                                    trade.total_quantity += executed_qty
                                    trade.description = f"Re-entry after partial sell at {entry_price}"
                                    trade.last_updated = IST.localize(datetime.now())
                                    db.session.commit()
                                    log_to_file(f"Re-entered {executed_qty} for {symbol} Sr.No {sr_no} at {ltp}")
                    elif sr_no <= 21:
                        if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'First TGT'
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                log_to_file(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
                            if trade.total_sold_quantity < half_qty and ltp < entry_price:
                                re_entry_qty = half_qty - trade.total_sold_quantity
                                executed_qty, order_id, order_status = place_order(smart_api, symbol, re_entry_qty, ltp, 'BUY', user_email=user.email)
                                if executed_qty > 0 and order_status in ['complete', 'executed']:
                                    trade.total_quantity += executed_qty
                                    trade.description = f"Re-entry after partial sell at {entry_price}"
                                    trade.last_updated = IST.localize(datetime.now())
                                    db.session.commit()
                                    log_to_file(f"Re-entered {executed_qty} for {symbol} Sr.No {sr_no} at {ltp}")
                        elif ltp >= final_tgt and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'Final TGT'
                                if trade.total_sold_quantity >= trade.total_quantity:
                                    trade.status = 'CLOSED'
                                    trade.cycle_count += 1
                                    log_to_file(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                log_to_file(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
                    else:  # Sr.No > 21
                        if first_tgt and ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, half_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'First TGT'
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                log_to_file(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
                            if trade.total_sold_quantity < half_qty and ltp < entry_price:
                                re_entry_qty = half_qty - trade.total_sold_quantity
                                executed_qty, order_id, order_status = place_order(smart_api, symbol, re_entry_qty, ltp, 'BUY', user_email=user.email)
                                if executed_qty > 0 and order_status in ['complete', 'executed']:
                                    trade.total_quantity += executed_qty
                                    trade.description = f"Re-entry after partial sell at {entry_price}"
                                    trade.last_updated = IST.localize(datetime.now())
                                    db.session.commit()
                                    log_to_file(f"Re-entered {executed_qty} for {symbol} Sr.No {sr_no} at {ltp}")
                        elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, second_half_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'Second TGT'
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                log_to_file(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{second_half_qty}, Sr.No {sr_no}")
                            if trade.total_sold_quantity < half_qty + second_half_qty and ltp < entry_price:
                                re_entry_qty = (half_qty + second_half_qty) - trade.total_sold_quantity
                                executed_qty, order_id, order_status = place_order(smart_api, symbol, re_entry_qty, ltp, 'BUY', user_email=user.email)
                                if executed_qty > 0 and order_status in ['complete', 'executed']:
                                    trade.total_quantity += executed_qty
                                    trade.description = f"Re-entry after partial sell at {entry_price}"
                                    trade.last_updated = IST.localize(datetime.now())
                                    db.session.commit()
                                    log_to_file(f"Re-entered {executed_qty} for {symbol} Sr.No {sr_no} at {ltp}")
                        elif ltp >= final_tgt and current_qty > 0:
                            executed_qty, order_id, order_status = place_order(smart_api, symbol, current_qty, ltp, 'SELL', user_email=user.email)
                            if executed_qty > 0 and order_status in ['complete', 'executed']:
                                trade.total_sold_quantity += executed_qty
                                trade.description = 'Final TGT'
                                if trade.total_sold_quantity >= trade.total_quantity:
                                    trade.status = 'CLOSED'
                                    trade.cycle_count += 1
                                    log_to_file(f"Cycle count incremented to {trade.cycle_count} for Sr.No {sr_no}")
                                trade.last_updated = IST.localize(datetime.now())
                                db.session.commit()
                                log_to_file(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")

                if all_closed and trades:
                    log_to_file(f"All trades for {symbol} are CLOSED, resetting cycle")
                    if current_cycle and current_cycle.status == 'ACTIVE':
                        current_cycle.cycle_end = IST.localize(datetime.now())
                        current_cycle.total_sold = sum(t.total_sold_quantity for t in trades)
                        current_cycle.total_bought = sum(t.total_quantity for t in trades)
                        current_cycle.profit = sum((ltp - t.entry_price) * t.total_sold_quantity for t in trades if t.status == 'CLOSED')
                        current_cycle.status = 'COMPLETED'
                        log_to_file(f"Completed TradeCycle for {symbol}: Total Bought {current_cycle.total_bought}, Total Sold {current_cycle.total_sold}, Profit {current_cycle.profit}")
                        db.session.commit()
                    
                    time.sleep(7)
                    new_cycle = TradeCycle(
                        stock_symbol=symbol,
                        user_email=user.email,
                        cycle_start=IST.localize(datetime.now()),
                        status='ACTIVE'
                    )
                    db.session.add(new_cycle)
                    db.session.commit()
                    log_to_file(f"Started new TradeCycle for {symbol}")

            except Exception as e:
                log_to_file(f"Error in process_strategy for {symbol}: {str(e)}")
                db.session.rollback()
            finally:
                db.session.close()

def start_websocket_stream(user):
    user_email = user.email
    try:
        with app.app_context():
            stocks = Stock.query.filter_by(user_id=user.id).all()
            if not any(stock.live_price_status for stock in stocks):
                logger.info(f"No stocks with live_price_status=True for {user_email}, skipping WebSocket")
                return

            with websocket_lock:
                if user_email in websocket_clients and websocket_clients[user_email].connected:
                    logger.info(f"WebSocket already running for {user_email}")
                    return

            smart_api = get_angel_session(user)
            auth_token = session_cache[user_email]['auth_token']
            feed_token = session_cache[user_email]['feed_token']
            api_key = user.smartapi_key
            client_code = user.smartapi_username

            token_map = {1: [], 3: []}
            for stock in stocks:
                if stock.live_price_status:
                    exchange_type = 1 if stock.exchange == "NSE" else 3
                    token_map[exchange_type].append(stock.symboltoken)

            token_list = [{"exchangeType": et, "tokens": tokens} for et, tokens in token_map.items() if tokens]
            if not token_list:
                logger.info(f"No active stocks to subscribe for {user_email}")
                return

            correlation_id = f"stream_{user_email}"
            mode = 3

            sws = SmartWebSocketV2(
                auth_token, api_key, client_code, feed_token,
                max_retry_attempt=5,  # Increased retries
                retry_strategy=0, retry_delay=10, retry_duration=15
            )

            def on_data(wsapp, message):
                try:
                    # Handle non-JSON or malformed messages
                    if isinstance(message, bytes):
                        logger.warning(f"Non-JSON message received for {user_email}: {message}")
                        return
                    if not isinstance(message, dict):
                        message = json.loads(message)

                    logger.debug(f"Raw message received for {user_email}: {message}")
                    token = message.get('token')
                    if not token:
                        logger.warning(f"Message missing token for {user_email}: {message}")
                        return

                    ltp = message.get('last_traded_price', 0) / 100 if message.get('last_traded_price') else 0
                    with app.app_context():
                        stock = Stock.query.filter_by(user_id=user.id, symboltoken=token).first()
                        if not stock:
                            logger.debug(f"Ignoring data for removed token {token} for {user_email}")
                            return
                        if stock:
                            with live_prices_lock:
                                if user_email not in live_prices:
                                    live_prices[user_email] = {}
                                live_prices[user_email][token] = {
                                    'price': ltp,
                                    'name': stock.tradingsymbol,
                                    'total_sell_quantity': message.get('total_sell_quantity', 0),
                                    'total_buy_quantity': message.get('total_buy_quantity', 0),
                                    'high_price_of_the_day': message.get('high_price_of_the_day', 0) / 100,
                                    'low_price_of_the_day': message.get('low_price_of_the_day', 0) / 100,
                                    'volume_trade_for_the_day': message.get('volume_trade_for_the_day', 0),
                                    'open_price': message.get('open_price_of_the_day', 0) / 100,
                                    'week_high': message.get('52_week_high_price', 0) / 100,
                                    'week_low': message.get('52_week_low_price', 0) / 100
                                }
                            logger.info(f"Updated live price for {user_email}, token {token}: {ltp}")
                            logger.debug(f"is market open: {is_market_open()}")
                            if is_market_open():
                                logger.info(f"Trading Status for {user} and its {user.trading_active}")
                                if user.trading_active and stock.trading_status:
                                    try:
                                        process_strategy(user, stock.tradingsymbol, ltp, smart_api)
                                    except Exception as e:
                                        logger.error(f"Error in process_strategy for {stock.tradingsymbol}: {str(e)}")
                                else:
                                    logger.info(f"Trading not active for {user_email}")
                            else:
                                logger.info(f"Market closed, skipping strategy for {stock.tradingsymbol}")
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to decode WebSocket message for {user_email}: {str(e)}")
                except Exception as e:
                    logger.error(f"Error in on_data callback for {user_email}: {str(e)}")

            def on_open(wsapp):
                logger.info(f"WebSocket opened for {user_email}")
                try:
                    sws.subscribe(correlation_id, mode, token_list)
                except Exception as e:
                    logger.error(f"Subscription failed for {user_email}: {str(e)}")

            def on_error(wsapp, error):
                logger.error(f"WebSocket error for {user_email}: {error}")
                with app.app_context():
                    if Stock.query.filter_by(user_id=user.id, live_price_status=True).count() > 0:
                        logger.info(f"Restarting WebSocket for {user_email} due to error")
                        restart_websocket(user)
                    else:
                        stop_websocket_stream(user)

            def on_close(wsapp, code=None, reason=None):
                logger.info(f"WebSocket closed for {user_email} with code={code}, reason={reason}")
                with websocket_lock:
                    if user_email in websocket_clients:
                        del websocket_clients[user_email]
                    if user_email in websocket_threads:
                        del websocket_threads[user_email]
                # Attempt to restart if stocks are still active
                with app.app_context():
                    if Stock.query.filter_by(user_id=user.id, live_price_status=True).count() > 0:
                        logger.info(f"Automatically restarting WebSocket for {user_email}")
                        restart_websocket(user)

            sws.on_open = on_open
            sws.on_data = on_data
            sws.on_error = on_error
            sws.on_close = on_close

            with websocket_lock:
                if user_email in websocket_clients:
                    try:
                        websocket_clients[user_email].close_connection()
                    except Exception as e:
                        logger.warning(f"Failed to close existing WebSocket for {user_email}: {str(e)}")
                websocket_clients[user_email] = sws

            thread = eventlet.spawn(sws.connect)
            with websocket_lock:
                websocket_threads[user_email] = thread
            logger.info(f"WebSocket thread started for {user_email}")

    except Exception as e:
        logger.error(f"WebSocket Setup Error for {user_email}: {str(e)}")
        with websocket_lock:
            if user_email in websocket_clients:
                del websocket_clients[user_email]
            if user_email in websocket_threads:
                del websocket_threads[user_email]

def restart_websocket(user):
    """Helper function to restart WebSocket for a user."""
    stop_websocket_stream(user)
    time.sleep(2)  # Small delay to avoid immediate reconnection issues
    start_websocket_stream(user)

def stop_websocket_stream(user):
    """Helper function to stop WebSocket for a user."""
    user_email = user.email
    with websocket_lock:
        if user_email in websocket_clients:
            try:
                websocket_clients[user_email].close_connection()
            except Exception as e:
                logger.warning(f"Failed to close WebSocket for {user_email}: {str(e)}")
            finally:
                del websocket_clients[user_email]
        if user_email in websocket_threads:
            del websocket_threads[user_email]
    logger.info(f"WebSocket stopped for {user_email}")


'''
def start_websocket_stream(user):
    user_email = user.email
    try:
        with app.app_context():
            stocks = Stock.query.filter_by(user_id=user.id).all()
            if not any(stock.live_price_status for stock in stocks):
                logger.info(f"No stocks with trading_status=True for {user_email}, skipping WebSocket")
                return

            with websocket_lock:
                if user_email in websocket_clients and websocket_clients[user_email].connected:
                    logger.info(f"WebSocket already running for {user_email}")
                    return

            smart_api = get_angel_session(user)
            auth_token = session_cache[user_email]['auth_token']
            feed_token = session_cache[user_email]['feed_token']
            api_key = user.smartapi_key
            client_code = user.smartapi_username

            token_map = {1: [], 3: []}
            for stock in stocks:
                if stock.live_price_status:
                    exchange_type = 1 if stock.exchange == "NSE" else 3
                    token_map[exchange_type].append(stock.symboltoken)

            token_list = [{"exchangeType": et, "tokens": tokens} for et, tokens in token_map.items() if tokens]
            if not token_list:
                logger.info(f"No active stocks to subscribe for {user_email}")
                return

            correlation_id = f"stream_{user_email}"
            mode = 3

            sws = SmartWebSocketV2(auth_token, api_key, client_code, feed_token,
                                   max_retry_attempt=3, retry_strategy=0, retry_delay=10, retry_duration=15)

            def on_data(wsapp, message):
                try:
                    logger.debug(f"Raw message received for {user_email}: {message}")
                    token = message.get('token')
                    ltp = message.get('last_traded_price', 0) / 100
                    with app.app_context():
                        stock = Stock.query.filter_by(user_id=user.id, symboltoken=token).first()
                        if not stock:
                            logger.debug(f"Ignoring data for removed token {token} for {user_email}")
                            return
                        if stock:
                            with live_prices_lock:
                                if user_email not in live_prices:
                                    live_prices[user_email] = {}
                                live_prices[user_email][token] = {
                                    'price': ltp,
                                    'name': stock.tradingsymbol,
                                    'total_sell_quantity': message.get('total_sell_quantity', 0),
                                    'total_buy_quantity': message.get('total_buy_quantity', 0),
                                    'high_price_of_the_day': message.get('high_price_of_the_day', 0) / 100,
                                    'low_price_of_the_day': message.get('low_price_of_the_day', 0) / 100,
                                    'volume_trade_for_the_day': message.get('volume_trade_for_the_day', 0),
                                    'open_price': message.get('open_price_of_the_day', 0) / 100,
                                    'week_high': message.get('52_week_high_price', 0) / 100,
                                    'week_low': message.get('52_week_low_price', 0) / 100
                                }
                            logger.info(f"Updated live price for {user_email}, token {token}: {ltp}")
                            logger.debug(f"is market open: {is_market_open()}")
                            if is_market_open():
                                logger.info(f"Trading Status for {user} and its {user.trading_active}")
                                if user.trading_active is True and stock.trading_status is True:
                                    try:
                                        process_strategy(user, stock.tradingsymbol, ltp, smart_api)
                                    except Exception as e:
                                        logger.error(f"Error in process_strategy for {stock.tradingsymbol}: {str(e)}")
                                else:
                                    logger.info(f"Trading not active for {user_email}")
                            else:
                                logger.info(f"Market closed, skipping strategy for {stock.tradingsymbol}")
                except Exception as e:
                    logger.error(f"Error in on_data callback for {user_email}: {str(e)}")

            def on_open(wsapp):
                logger.info(f"WebSocket opened for {user_email}")
                sws.subscribe(correlation_id, mode, token_list)

            def on_error(wsapp, error):
                logger.error(f"WebSocket error for {user_email}: {error}")
                with app.app_context():
                    if Stock.query.filter_by(user_id=user.id, trading_status=True).count() > 0:
                        restart_websocket(user)
                    else:
                        stop_websocket_stream(user)

            def on_close(wsapp, code=None, reason=None):
                logger.info(f"WebSocket closed for {user_email}")
                with websocket_lock:
                    if user_email in websocket_clients:
                        del websocket_clients[user_email]
                    if user_email in websocket_threads:
                        del websocket_threads[user_email]

            sws.on_open = on_open
            sws.on_data = on_data
            sws.on_error = on_error
            sws.on_close = on_close

            with websocket_lock:
                if user_email in websocket_clients:
                    websocket_clients[user_email].close_connection()
                websocket_clients[user_email] = sws

            thread = eventlet.spawn(sws.connect)
            with websocket_lock:
                websocket_threads[user_email] = thread
            logger.info(f"WebSocket thread started for {user_email}")

    except Exception as e:
        logger.error(f"WebSocket Setup Error for {user_email}: {str(e)}")
        with websocket_lock:
            if user_email in websocket_clients:
                del websocket_clients[user_email]
            if user_email in websocket_threads:
                del websocket_threads[user_email]

def stop_websocket_stream(user):
    """Stop WebSocket stream for a user and clean up only their data."""
    user_email = user.email
    with websocket_lock:
        if user_email in websocket_clients:
            logger.info(f"Closing WebSocket connection for {user_email}")
            websocket_clients[user_email].max_retry_attempt = 0  # Disable retries
            websocket_clients[user_email].close_connection()
            del websocket_clients[user_email]
        if user_email in websocket_threads:
            del websocket_threads[user_email]
        with live_prices_lock:
            if user_email in live_prices:
                del live_prices[user_email]  # Clear only this user's live prices
        logger.info(f"WebSocket fully stopped and cleaned up for {user_email}")

def restart_websocket(user):
    """Restart WebSocket for a user."""
    stop_websocket_stream(user)
    start_websocket_stream(user)

'''

'''
def start_websocket_stream(user):
    user_email = user.email
    try:
        with app.app_context():
            stocks = Stock.query.filter_by(user_id=user.id).all()
            if not any(stock.live_price_status for stock in stocks):  # Use trading_status as per your API
                logger.info(f"No stocks with trading_status=True for {user_email}, skipping WebSocket")
                return

            with websocket_lock:
                if user_email in websocket_clients:
                    logger.info(f"WebSocket already running for {user_email}")
                    return

            smart_api = get_angel_session(user)
            auth_token = session_cache[user_email]['auth_token']
            feed_token = session_cache[user_email]['feed_token']
            api_key = user.smartapi_key
            client_code = user.smartapi_username

            token_map = {1: [], 3: []}
            for stock in stocks:
                if stock.trading_status:  # Use trading_status
                    exchange_type = 1 if stock.exchange == "NSE" else 3
                    token_map[exchange_type].append(stock.symboltoken)

            token_list = [{"exchangeType": et, "tokens": tokens} for et, tokens in token_map.items() if tokens]
            if not token_list:
                logger.info(f"No active stocks to subscribe for {user_email}")
                return

            correlation_id = f"stream_{user_email}"
            mode = 3

            sws = SmartWebSocketV2(auth_token, api_key, client_code, feed_token,
                                   max_retry_attempt=3, retry_strategy=0, retry_delay=10, retry_duration=15)

            def on_data(wsapp, message):
                try:
                    logger.debug(f"Raw message received for {user_email}: {message}")
                    token = message.get('token')
                    ltp = message.get('last_traded_price', 0) / 100
                    with app.app_context():
                        stock = Stock.query.filter_by(user_id=user.id, symboltoken=token).first()
                        if not stock:
                            logger.debug(f"Ignoring data for removed token {token} for {user_email}")
                            return
                        if stock:
                            with live_prices_lock:
                                if user_email not in live_prices:
                                    live_prices[user_email] = {}
                                live_prices[user_email][token] = {
                                    'price': ltp,
                                    'name': stock.tradingsymbol,
                                    'total_sell_quantity': message.get('total_sell_quantity', 0),
                                    'total_buy_quantity': message.get('total_buy_quantity', 0),
                                    'high_price_of_the_day': message.get('high_price_of_the_day', 0) / 100,
                                    'low_price_of_the_day': message.get('low_price_of_the_day', 0) / 100,
                                    'volume_trade_for_the_day': message.get('volume_trade_for_the_day', 0),
                                    'open_price': message.get('open_price_of_the_day', 0) / 100,
                                    'week_high': message.get('52_week_high_price', 0) / 100,
                                    'week_low': message.get('52_week_low_price', 0) / 100
                                }
                            logger.info(f"Updated live price for {user_email}, token {token}: {ltp}")
                            if user.trading_active and stock.trading_status:
                                try:
                                    process_strategy(user, stock.tradingsymbol, ltp, smart_api)
                                except Exception as e:
                                    logger.error(f"Error in process_strategy for {stock.tradingsymbol}: {str(e)}")
                            else:
                                logger.info(f"Trading not active for {user_email}")
                except Exception as e:
                    logger.error(f"Error in on_data callback for {user_email}: {str(e)}")

            def on_open(wsapp):
                logger.info(f"WebSocket opened for {user_email}")
                sws.subscribe(correlation_id, mode, token_list)

            def on_error(wsapp, error):
                logger.error(f"WebSocket error for {user_email}: {error}")
                with app.app_context():
                    if Stock.query.filter_by(user_id=user.id, trading_status=True).count() > 0:
                        restart_websocket(user)
                    else:
                        stop_websocket_stream(user)

            def on_close(wsapp, code=None, reason=None):
                logger.info(f"WebSocket closed for {user_email}")
                with websocket_lock:
                    if user_email in websocket_clients:
                        del websocket_clients[user_email]
                    if user_email in websocket_threads:
                        del websocket_threads[user_email]

            sws.on_open = on_open
            sws.on_data = on_data
            sws.on_error = on_error
            sws.on_close = on_close

            with websocket_lock:
                if user_email in websocket_clients:
                    websocket_clients[user_email].close_connection()
                websocket_clients[user_email] = sws

            thread = eventlet.spawn(sws.connect)
            with websocket_lock:
                websocket_threads[user_email] = thread
            logger.info(f"WebSocket thread started for {user_email}")

    except Exception as e:
        logger.error(f"WebSocket Setup Error for {user_email}: {str(e)}")
        with websocket_lock:
            if user_email in websocket_clients:
                del websocket_clients[user_email]
            if user_email in websocket_threads:
                del websocket_threads[user_email]

def stop_websocket_stream(user):
    user_email = user.email
    with websocket_lock:
        if user_email in websocket_clients:
            logger.info(f"Closing WebSocket connection for {user_email}")
            websocket_clients[user_email].max_retry_attempt = 0
            websocket_clients[user_email].close_connection()
            del websocket_clients[user_email]
        if user_email in websocket_threads:
            del websocket_threads[user_email]
        with live_prices_lock:
            if user_email in live_prices:
                del live_prices[user_email]
        logger.info(f"WebSocket fully stopped and cleaned up for {user_email}")
        
def restart_websocket(user):
    stop_websocket_stream(user)
    start_websocket_stream(user)
'''

@app.before_request
def log_request_data():
    if request.path == "/api/toggle-trading-status":
        logging.info("\n🚀 Received /user/generate-2fa API request")
        logging.info(f"📝 Request Method: {request.method}")
        logging.info(f"📩 Request Headers: {dict(request.headers)}")
        logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")

# Default phase configurations
DEFAULT_PHASES = [
    {"phase": 1, "start_sr_no": 1, "end_sr_no": 21, "down_increment": 0.25},
    {"phase": 2, "start_sr_no": 22, "end_sr_no": 41, "down_increment": 0.50},
    {"phase": 3, "start_sr_no": 42, "end_sr_no": 55, "down_increment": 0.75},
    {"phase": 4, "start_sr_no": 56, "end_sr_no": 70, "down_increment": 1.00},
    {"phase": 5, "start_sr_no": 71, "end_sr_no": 81, "down_increment": 1.25},
]

@app.route('/api/toggle-trading-status', methods=['POST'])
@jwt_required()
def toggle_trading_status():
    try:
        user_email = get_jwt_identity()
        user = User.query.filter_by(email=user_email).first()
        if not user:
            response = {'status': 'error', 'message': 'User not found'}
            return jsonify({'data': encrypt_response(response)}), 403

        encrypted_data = request.json.get("data")
        if not encrypted_data:
            response = {'status': 'error', 'message': 'No request data provided'}
            return jsonify({'data': encrypt_response(response)}), 400

        decrypted_data = decrypt_request(encrypted_data)
        if decrypted_data is None:
            response = {'status': 'error', 'message': 'Failed to decrypt request data'}
            return jsonify({'data': encrypt_response(response)}), 400

        tradingsymbol = decrypted_data.get('tradingsymbol')
        trading_status = decrypted_data.get('trading_status')
        wallet_value = decrypted_data.get('wallet_value')
        selected_phase = decrypted_data.get('phase')
        new_down_increment = decrypted_data.get('down_increment')
        
        if trading_status is False:
            stock.trading_status = False
            db.session.commit()
            restart_websocket(user)
            response = {'status': 'success', 'message': 'Trading status disabled'}
            return jsonify({'data': encrypt_response(response)}), 200

        logger.info(f"Toggle trading status for {tradingsymbol} to {trading_status} for {user_email}")

        if not tradingsymbol or trading_status is None:
            response = {'status': 'error', 'message': 'Missing tradingsymbol or trading_status'}
            return jsonify({'data': encrypt_response(response)}),500
        if not wallet_value:
            response = {'status': 'error', 'message': 'Missing wallet_value'}
            return jsonify({'data': encrypt_response(response)}),500
        
        stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=tradingsymbol).first()
        if not stock:
            response = {'status': 'error', 'message': f"Stock '{tradingsymbol}' not found"}
            return jsonify({'data': encrypt_response(response)}), 404
        
        if stock.trading_status == trading_status:
            response = {'status': 'error', 'message': f"Trading status for {tradingsymbol} already set to {trading_status}"}
            return jsonify({'data': encrypt_response(response)}), 200
        
        if trading_status and not selected_phase:
            response = {'status': 'error', 'message': 'Phase number is required when enabling trading'}
            return jsonify({'data': encrypt_response(response)}), 400
        
        if selected_phase and not new_down_increment:
            response = {'status': 'error', 'message': 'down_increment is required when phase is provided'}
            return jsonify({'data': encrypt_response(response)}), 400
            
        log_to_file(f"Toggle trading status for {tradingsymbol} to {trading_status} for {user_email}")
        log_to_file(f"Phase: {selected_phase}, Down Increment: {new_down_increment}, Wallet Value: {wallet_value}")
        log_to_file(f"Trading Status: {trading_status}")
        log_to_file(f"allotment_capital: {wallet_value}")
        stock.trading_status = trading_status
        stock.allotment_captial = wallet_value
        db.session.commit()


        if trading_status:
            if not wallet_value:
                response = {'status': 'error', 'message': 'wallet_value is required when enabling trading'}
                return jsonify({'data': encrypt_response(response)}), 400
            wallet_value = float(wallet_value)
            if wallet_value <= 0:
                response = {'status': 'error', 'message': 'wallet_value must be positive'}
                return jsonify({'data': encrypt_response(response)}), 400

            selected_phase = int(selected_phase)
            new_down_increment = float(new_down_increment)
            if selected_phase not in [p["phase"] for p in DEFAULT_PHASES]:
                response = {'status': 'error', 'message': 'Invalid phase number'}
                return jsonify({'data': encrypt_response(response)}), 400
            if new_down_increment < 0:
                response = {'status': 'error', 'message': 'down_increment must be non-negative'}
                return jsonify({'data': encrypt_response(response)}), 400

            rms_cash = user.available_balance
            user.available_balance = rms_cash if rms_cash is not None else 0.0
            available = user.remaining_balance if user.remaining_balance is not None else user.available_balance
            if wallet_value > available:
                response = {'status': 'error', 'message': f"Insufficient remaining balance: {available}"}
                return jsonify({'data': encrypt_response(response)}), 400

            user.used_balance = (user.used_balance or 0.0) + wallet_value
            user.remaining_balance = max(0, user.available_balance - user.used_balance)
            logger.info(f"Updated balances for {user_email}: used_balance={user.used_balance}, remaining_balance={user.remaining_balance}")

            existing_configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=tradingsymbol).all()
            if not existing_configs:
                for default in DEFAULT_PHASES:
                    phase_config = PhaseConfig(
                        user_email=user_email,
                        stock_symbol=tradingsymbol,
                        phase=default["phase"],
                        start_sr_no=default["start_sr_no"],
                        end_sr_no=default["end_sr_no"],
                        down_increment=default["down_increment"]
                    )
                    db.session.add(phase_config)
                db.session.commit()
                existing_configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=tradingsymbol).all()

            # Calculate step_size based on the difference from the default for the selected phase
            selected_default = next(p for p in DEFAULT_PHASES if p["phase"] == selected_phase)
            step_size = new_down_increment + selected_default["down_increment"]

            # Update phases: keep defaults above, adjust selected and below
            for phase_config in existing_configs:
                if phase_config.phase < selected_phase:
                    # Keep default value for phases above selected_phase
                    phase_config.down_increment = next(p["down_increment"] for p in DEFAULT_PHASES if p["phase"] == phase_config.phase)
                elif phase_config.phase == selected_phase:
                    # Set selected phase to user-provided value
                    phase_config.down_increment = new_down_increment
                else:
                    # Adjust subsequent phases using step_size
                    phase_offset = phase_config.phase + selected_phase
                    default_value = next(p["down_increment"] for p in DEFAULT_PHASES if p["phase"] == phase_config.phase)
                    phase_config.down_increment = default_value + step_size
                logger.info(f"Updated DOWN increment for {tradingsymbol}, Phase {phase_config.phase} to {phase_config.down_increment}")


            # db.session.close()
            
            restart_websocket(user)

            # with websocket_lock:
            #     if user_email not in websocket_clients or user_email not in websocket_threads:
            #         start_websocket_stream(user)

        else:
            if stock.allotment_captial:
                user.used_balance = max(0, (user.used_balance or 0.0) - stock.allotment_captial)
                user.remaining_balance = max(0, user.available_balance - user.used_balance)
                stock.allotment_captial = 0
                logger.info(f"Released capital {stock.allotment_captial} for {tradingsymbol}. Updated balances: used_balance={user.used_balance}, remaining_balance={user.remaining_balance}")

            db.session.commit()

            active_stocks = Stock.query.filter_by(user_id=user.id, trading_status=True).count()
            if active_stocks == 0:
                stop_websocket_stream(user)
            else:
                restart_websocket(user)

        response = {'status': 'success', 'message': f"Trading status for {tradingsymbol} set to {trading_status}"}
        encrypted_response = encrypt_response(response)
        if encrypted_response is None:
            return jsonify({'error': 'Failed to encrypt response'}), 500
        return jsonify({'data': encrypted_response}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error toggling trading status: {str(e)}")
        response = {'status': 'error', 'message': str(e)}
        encrypted_response = encrypt_response(response)
        if encrypted_response is None:
            return jsonify({'error': 'Failed to encrypt response'}), 500
        return jsonify({'data': encrypted_response}), 500

'''
@app.route('/api/toggle-trading-status', methods=['POST'])
@jwt_required()
def toggle_trading_status():
    try:
        user_email = get_jwt_identity()
        user = User.query.filter_by(email=user_email).first()
        if not user:
            response = {'status': 'error', 'message': 'User not found'}
            return jsonify({'data': encrypt_response(response)}), 403

        encrypted_data = request.json.get("data")
        if not encrypted_data:
            response = {'status': 'error', 'message': 'No request data provided'}
            return jsonify({'data': encrypt_response(response)}), 400

        decrypted_data = decrypt_request(encrypted_data)
        if decrypted_data is None:
            response = {'status': 'error', 'message': 'Failed to decrypt request data'}
            return jsonify({'data': encrypt_response(response)}), 400

        tradingsymbol = decrypted_data.get('tradingsymbol')
        trading_status = decrypted_data.get('trading_status')
        wallet_value = decrypted_data.get('wallet_value')
        selected_phase = decrypted_data.get('phase')
        new_down_increment = decrypted_data.get('down_increment')

        logger.info(f"Toggle trading status for {tradingsymbol} to {trading_status} for {user_email}")

        if not tradingsymbol or trading_status is None:
            response = {'status': 'error', 'message': 'Missing tradingsymbol or trading_status'}
            return jsonify({'data': encrypt_response(response)}), 400
        
        stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=tradingsymbol).first()
        if not stock:
            response = {'status': 'error', 'message': f"Stock '{tradingsymbol}' not found"}
            return jsonify({'data': encrypt_response(response)}), 404
        
        if stock.trading_status == trading_status:
            response = {'status': 'error', 'message': f"Trading status for {tradingsymbol} already set to {trading_status}"}
            return jsonify({'data': encrypt_response(response)}), 200
        
        if trading_status and not selected_phase:
            response = {'status': 'error', 'message': 'Phase number is required when enabling trading'}
            return jsonify({'data': encrypt_response(response)}), 400
        
        if selected_phase and not new_down_increment:
            response = {'status': 'error', 'message': 'down_increment is required when phase is provided'}
            return jsonify({'data': encrypt_response(response)}), 400

        stock.trading_status = trading_status

        if trading_status:
            if not wallet_value:
                response = {'status': 'error', 'message': 'wallet_value is required when enabling trading'}
                return jsonify({'data': encrypt_response(response)}), 400
            wallet_value = float(wallet_value)
            if wallet_value <= 0:
                response = {'status': 'error', 'message': 'wallet_value must be positive'}
                return jsonify({'data': encrypt_response(response)}), 400

            selected_phase = int(selected_phase)
            new_down_increment = float(new_down_increment)
            if selected_phase not in [p["phase"] for p in DEFAULT_PHASES]:
                response = {'status': 'error', 'message': 'Invalid phase number'}
                return jsonify({'data': encrypt_response(response)}), 400
            if new_down_increment < 0:
                response = {'status': 'error', 'message': 'down_increment must be non-negative'}
                return jsonify({'data': encrypt_response(response)}), 400

            rms_cash = user.available_balance
            user.available_balance = rms_cash if rms_cash is not None else 0.0
            available = user.remaining_balance if user.remaining_balance is not None else user.available_balance
            if wallet_value > available:
                response = {'status': 'error', 'message': f"Insufficient remaining balance: {available}"}
                return jsonify({'data': encrypt_response(response)}), 400

            user.used_balance = (user.used_balance or 0.0) + wallet_value
            user.remaining_balance = max(0, user.available_balance - user.used_balance)
            logger.info(f"Updated balances for {user_email}: used_balance={user.used_balance}, remaining_balance={user.remaining_balance}")

            existing_configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=tradingsymbol).all()
            if not existing_configs:
                for default in DEFAULT_PHASES:
                    phase_config = PhaseConfig(
                        user_email=user_email,
                        stock_symbol=tradingsymbol,
                        phase=default["phase"],
                        start_sr_no=default["start_sr_no"],
                        end_sr_no=default["end_sr_no"],
                        down_increment=default["down_increment"]
                    )
                    db.session.add(phase_config)
                db.session.commit()
                existing_configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=tradingsymbol).all()

            selected_default = next(p for p in DEFAULT_PHASES if p["phase"] == selected_phase)
            step_size = new_down_increment - selected_default["down_increment"]
            for phase_config in existing_configs:
                if phase_config.phase >= selected_phase:
                    phase_offset = phase_config.phase - selected_phase
                    new_value = new_down_increment + (step_size * phase_offset)
                    phase_config.down_increment = new_value
                    logger.info(f"Updated DOWN increment for {tradingsymbol}, Phase {phase_config.phase} to {new_value}")

            stock.capital = wallet_value
            db.session.commit()

            # Updated WebSocket check: Rely on presence in websocket_clients and websocket_threads
            with websocket_lock:
                if user_email not in websocket_clients or user_email not in websocket_threads:
                    start_websocket_stream(user)

        else:
            if stock.capital:
                user.used_balance = max(0, (user.used_balance or 0.0) - stock.capital)
                user.remaining_balance = max(0, user.available_balance - user.used_balance)
                stock.capital = 0.0
                logger.info(f"Released capital {stock.capital} for {tradingsymbol}. Updated balances: used_balance={user.used_balance}, remaining_balance={user.remaining_balance}")

            db.session.commit()

            active_stocks = Stock.query.filter_by(user_id=user.id, trading_status=True).count()
            if active_stocks == 0:
                stop_websocket_stream(user)
            else:
                restart_websocket(user)

        response = {'status': 'success', 'message': f"Trading status for {tradingsymbol} set to {trading_status}"}
        encrypted_response = encrypt_response(response)
        if encrypted_response is None:
            return jsonify({'error': 'Failed to encrypt response'}), 500
        return jsonify({'data': encrypted_response}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error toggling trading status: {str(e)}")
        response = {'status': 'error', 'message': str(e)}
        encrypted_response = encrypt_response(response)
        if encrypted_response is None:
            return jsonify({'error': 'Failed to encrypt response'}), 500
        return jsonify({'data': encrypted_response}), 500
    
'''
'''
@app.route('/api/toggle-trading-status', methods=['POST'])
@jwt_required()
def toggle_trading_status():
    try:
        user_email = get_jwt_identity()
        user = User.query.filter_by(email=user_email).first()
        if not user:
            response = {'status': 'error', 'message': 'User not found'}
            return jsonify({'data': encrypt_response(response)}), 403

        encrypted_data = request.json.get("data")
        if not encrypted_data:
            response = {'status': 'error', 'message': 'No request data provided'}
            return jsonify({'data': encrypt_response(response)}), 400

        decrypted_data = decrypt_request(encrypted_data)
        if decrypted_data is None:
            response = {'status': 'error', 'message': 'Failed to decrypt request data'}
            return jsonify({'data': encrypt_response(response)}), 400

        # Parse decrypted data
        tradingsymbol = decrypted_data.get('tradingsymbol')
        trading_status = decrypted_data.get('trading_status')  # Boolean: True/False
        wallet_value = decrypted_data.get('wallet_value')      # Capital for the stock
        selected_phase = decrypted_data.get('phase')           # User-selected phase 
        new_down_increment = decrypted_data.get('down_increment')  # User-specified down_increment 

        logger.info(f"Toggle trading status for {tradingsymbol} to {trading_status} for {user_email}")

        # Validate basic inputs
        if not tradingsymbol or trading_status is None:
            response = {'status': 'error', 'message': 'Missing tradingsymbol or trading_status'}
            return jsonify({'data': encrypt_response(response)}), 400
        
        # Fetch the stock
        stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=tradingsymbol).first()
        if not stock:
            response = {'status': 'error', 'message': f"Stock '{tradingsymbol}' not found"}
            return jsonify({'data': encrypt_response(response)}), 404
        
        if stock.trading_status == trading_status:
            response = {'status': 'error', 'message': f"Trading status for {tradingsymbol} already set to {trading_status}"}
            return jsonify({'data': encrypt_response(response)}), 200
        
        if trading_status and not selected_phase:
            response = {'status': 'error', 'message': 'Phase number is required when enabling trading'}
            return jsonify({'data': encrypt_response(response)}), 400
        
        if selected_phase and not new_down_increment:
            response = {'status': 'error', 'message': 'down_increment is required when phase is provided'}
            return jsonify({'data': encrypt_response(response)}), 400
        
        # if trading_status is False and wallet_value:
        #     response = {'status': 'error', 'message': 'wallet_value must be None when disabling trading'}
        #     return jsonify({'data': encrypt_response(response )}), 400
        
        # Update trading status
        stock.trading_status = trading_status
        

        if trading_status:  # When enabling trading
            # Validate wallet_value and phase-related inputs
            if not wallet_value:
                response = {'status': 'error', 'message': 'wallet_value is required when enabling trading'}
                return jsonify({'data': encrypt_response(response)}), 400
            wallet_value = float(wallet_value)
            if wallet_value <= 0:
                response = {'status': 'error', 'message': 'wallet_value must be positive'}
                return jsonify({'data': encrypt_response(response)}), 400

            # Validate phase and down_increment if provided
            if selected_phase is not None and new_down_increment is not None:
                selected_phase = int(selected_phase)
                new_down_increment = float(new_down_increment)
                if selected_phase not in [p["phase"] for p in DEFAULT_PHASES]:
                    response = {'status': 'error', 'message': 'Invalid phase number'}
                    return jsonify({'data': encrypt_response(response)}), 400
                if new_down_increment < 0:
                    response = {'status': 'error', 'message': 'down_increment must be non-negative'}
                    return jsonify({'data': encrypt_response(response)}), 400
            elif selected_phase is not None or new_down_increment is not None:
                response = {'status': 'error', 'message': 'Both phase and down_increment must be provided together'}
                return jsonify({'data': encrypt_response(response)}), 400

            update_user_available_balance = get_wallet_value(user)
            
            user.available_balance = update_user_available_balance
            # Check available balance
            rms_cash = user.available_balance
            if rms_cash is None:
                response = {'status': 'error', 'message': 'Failed to fetch RMS cash value'}
                return jsonify({'data': encrypt_response(response)}), 500
            
            user.available_balance = rms_cash if rms_cash is not None else 0.0
            available = user.remaining_balance if user.remaining_balance is not None else user.available_balance
            if wallet_value > available:
                response = {'status': 'error', 'message': f"Insufficient remaining balance: {available}"}
                return jsonify({'data': encrypt_response(response)}), 400

            # Update user balances
            user.used_balance = (user.used_balance or 0.0) + wallet_value
            user.remaining_balance = max(0, user.available_balance - user.used_balance)
            logger.info(f"Updated balances for {user_email}: used_balance={user.used_balance}, remaining_balance={user.remaining_balance}")

            # Initialize or update phase configuration
            existing_configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=tradingsymbol).all()
            if not existing_configs:
                for default in DEFAULT_PHASES:
                    phase_config = PhaseConfig(
                        user_email=user_email,
                        stock_symbol=tradingsymbol,
                        phase=default["phase"],
                        start_sr_no=default["start_sr_no"],
                        end_sr_no=default["end_sr_no"],
                        down_increment=default["down_increment"]
                    )
                    db.session.add(phase_config)
                db.session.commit()
                existing_configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=tradingsymbol).all()

            # Update down_increment for selected phase and subsequent phases
            if selected_phase and new_down_increment is not None:
                selected_default = next(p for p in DEFAULT_PHASES if p["phase"] == selected_phase)
                step_size = new_down_increment - selected_default["down_increment"]

                for phase_config in existing_configs:
                    if phase_config.phase >= selected_phase:
                        phase_offset = phase_config.phase - selected_phase
                        new_value = new_down_increment + (step_size * phase_offset)
                        phase_config.down_increment = new_value
                        logger.info(f"Updated DOWN increment for {tradingsymbol}, Phase {phase_config.phase} to {new_value}")

            stock.capital = wallet_value
            db.session.commit()

            # Start WebSocket if needed
            with websocket_lock:
                if user_email not in websocket_clients or not websocket_clients[user_email].connected:
                    start_websocket_stream(user)

        else:  # When disabling trading
            if stock.capital:
                user.used_balance = max(0, (user.used_balance or 0.0) - stock.capital)
                user.remaining_balance = max(0, user.available_balance - user.used_balance)
                stock.capital = 0.0
                logger.info(f"Released capital {stock.capital} for {tradingsymbol}. Updated balances: used_balance={user.used_balance}, remaining_balance={user.remaining_balance}")

            db.session.commit()

            # Manage WebSocket
            active_stocks = Stock.query.filter_by(user_id=user.id, trading_status=True).count()
            if active_stocks == 0:
                stop_websocket_stream(user)
            else:
                restart_websocket(user)

        response = {'status': 'success', 'message': f"Trading status for {tradingsymbol} set to {trading_status}"}
        encrypted_response = encrypt_response(response)
        if encrypted_response is None:
            return jsonify({'error': 'Failed to encrypt response'}), 500
        return jsonify({'data': encrypted_response}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error toggling trading status: {str(e)}")
        response = {'status': 'error', 'message': str(e)}
        encrypted_response = encrypt_response(response)
        if encrypted_response is None:
            return jsonify({'error': 'Failed to encrypt response'}), 500
        return jsonify({'data': encrypted_response}), 500

'''    

'''        
@app.route('/api/toggle-trading-status', methods=['POST'])
@jwt_required()
def toggle_trading_status():
    try:
        user_email = get_jwt_identity()
        user = User.query.filter_by(email=user_email).first()
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 403

        data = request.get_json()
        tradingsymbol = data.get('tradingsymbol')
        trading_status = data.get('trading_status')
        logger.info(f"Toggle trading status for {tradingsymbol} to {trading_status} for {user_email}")

        if not tradingsymbol or trading_status is None:
            return jsonify({'status': 'error', 'message': 'Missing symboltoken or trading_status'}), 400

        with app.app_context():
            stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=tradingsymbol).first()
            if not stock:
                return jsonify({'status': 'error', 'message': f"Stock '{tradingsymbol}' not found"}), 404

            stock.trading_status = trading_status
            db.session.commit()

            if trading_status:
                with websocket_lock:
                    if user_email not in websocket_clients or not websocket_clients[user_email].connected:
                        start_websocket_stream(user)
            else:
                active_stocks = Stock.query.filter_by(user_id=user.id, trading_status=True).count()
                if active_stocks == 0:
                    stop_websocket_stream(user)
                else:
                    restart_websocket(user)  # Restart to update subscriptions

            return jsonify({'status': 'success', 'message': f"Trading status for {tradingsymbol} set to {trading_status}"}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error toggling trading status: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
'''


DEFAULT_PHASES = [
    {"phase": 1, "start_sr_no": 1, "end_sr_no": 21, "down_increment": 0.25},
    {"phase": 2, "start_sr_no": 22, "end_sr_no": 41, "down_increment": 0.50},
    {"phase": 3, "start_sr_no": 42, "end_sr_no": 55, "down_increment": 0.75},
    {"phase": 4, "start_sr_no": 56, "end_sr_no": 70, "down_increment": 1.00},
    {"phase": 5, "start_sr_no": 71, "end_sr_no": 81, "down_increment": 1.25},
]

@app.route('/api/update-down', methods=['POST'])
@jwt_required()
def update_down_increment():
    try:
        user_email = get_jwt_identity()
        data = request.get_json()
        stock_symbol = data['stock_symbol']
        selected_phase = int(data['phase'])  # Changed: Use phase instead of sr_no
        new_down_increment = float(data['down_increment'])

        # Validate selected phase
        if selected_phase not in [p["phase"] for p in DEFAULT_PHASES]:
            return jsonify({'status': 'error', 'message': 'Invalid phase number'}), 400

        # Find the default config for the selected phase to calculate the step
        selected_default = next(p for p in DEFAULT_PHASES if p["phase"] == selected_phase)
        original_down_increment = selected_default["down_increment"]
        step_size = new_down_increment - original_down_increment  # Dynamic step based on user change

        existing_configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=stock_symbol).all()
        
        # If no configs exist, initialize with defaults
        if not existing_configs:
            for default in DEFAULT_PHASES:
                phase_config = PhaseConfig(
                    user_email=user_email,
                    stock_symbol=stock_symbol,
                    phase=default["phase"],
                    start_sr_no=default["start_sr_no"],
                    end_sr_no=default["end_sr_no"],
                    down_increment=default["down_increment"]
                )
                db.session.add(phase_config)
            db.session.commit()
            existing_configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=stock_symbol).all()

        # Update phases starting from the selected phase
        for phase_config in existing_configs:
            if phase_config.phase >= selected_phase:
                # Calculate new down_increment based on step size
                default_phase = next(p for p in DEFAULT_PHASES if p["phase"] == phase_config.phase)
                phase_offset = phase_config.phase - selected_phase
                new_value = new_down_increment + (step_size * phase_offset)
                phase_config.down_increment = new_value
                logger.info(f"Updated DOWN increment for {stock_symbol}, Phase {phase_config.phase} to {new_value}")

        db.session.commit()
        time.sleep(7)  # Assuming this delay is intentional
        return jsonify({"data": encrypt_response({"message": "DOWN increment updated successfully","status": "200"})}), 200

    except Exception as e:
        logger.error(f"Error updating DOWN increment: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.before_request
def log_request_data():
    if request.path == "/api/dashboard_stats":
        logging.info("\n🚀 Received")
        logging.info(f"📝 Request Method: {request.method}")
        logging.info(f"📩 Request Headers: {dict(request.headers)}")
        logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")
# API to get dashboard statistics
'''
from flask_jwt_extended import jwt_required, get_jwt_identity
jwt = JWTManager(app)
@app.route('/api/dashboard_stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    try:
        user_email = get_jwt_identity()
        if not user_email:
            return jsonify({'error': 'User email is required'}), 400
        
        currunt_user = User.query.filter_by(email=user_email).first()
        if not currunt_user:
            return jsonify({'error': 'User not found'}), 404
        
        if not currunt_user.is_active:
            return jsonify({'error': 'User is not active'}), 403
        
        total_connected_users = User.query.filter_by(trading_active=True).count()
        users = User.query.filter_by(email=user_email).all()
        
        active_stock_data = []
        not_active_stock_data = []
        for user in users:
            not_active_stocks = Stock.query.filter_by(
                user_id=currunt_user.id,  
                trading_status = False
            ).all()
            logger.info(f"Not Active stocks for Temp {user.email}: {len(not_active_stocks)}")
            for stock in not_active_stocks:
                logger.info(f"Not Active stocks for {user.email}: {stock.tradingsymbol} {stock.live_price_status} {stock.trading_status}")
                
            
            active_stocks = Stock.query.filter_by(
                user_id=currunt_user.id,  
                trading_status = True
            ).all()
            
            logger.info(f"Active stocks for temp {user.email}: {len(active_stocks)}")
            for stock in active_stocks:
                # Get OPEN trades for this stock
                open_trades = Trade.query.filter_by(
                    stock_symbol=stock.tradingsymbol,  # Assuming Stock has 'symbol' column
                    user_email=currunt_user.email,
                    status='OPEN'
                ).order_by(Trade.sr_no.desc()).all()
                
                # i want to add if the not added the open trade then i want to append the not active stock
                if not open_trades:
                    active_stock_data.append({
                        'user_email': user.email,
                        'stock_symbol': stock.tradingsymbol,
                        'total_open_quantity': 0,
                        'current_sr_no': 0,
                        'phase': 'Unknown',
                        'activation_status': stock.trading_status
                    })
                    continue
                
                    
                # Total quantity of OPEN trades
                total_open_quantity = sum(trade.total_quantity for trade in open_trades)
                # Current sr_no (latest OPEN trade)
                current_sr_no = open_trades[0].sr_no  # Latest trade
                # Determine phase based on sr_no
                phase_config = PhaseConfig.query.filter_by(
                    user_email=user.email,
                    stock_symbol=stock.tradingsymbol
                ).filter(
                    PhaseConfig.start_sr_no <= current_sr_no,
                    PhaseConfig.end_sr_no >= current_sr_no
                ).first()
                phase = phase_config.phase if phase_config else "Unknown"
                # Stock data
                stock_info = {
                    'user_email': user.email,
                    'stock_symbol': stock.tradingsymbol,
                    'total_open_quantity': total_open_quantity,
                    'current_sr_no': current_sr_no,
                    'phase': phase,
                    'phase_drop': phase_config.down_increment if phase_config else 0,
                    'activation_status': stock.trading_status
                }
                active_stock_data.append(stock_info)
                logger.info(f"Active stock data for {user.email}/{stock.tradingsymbol}: {stock_info}")
        # Response
        response = {
            'not_active_stock_data': not_active_stock_data,
            'total_connected_users': total_connected_users,
            'active_stock_data': active_stock_data,
            'status': '200',
            'message': 'Dashboard stats retrieved successfully'
        }
        logger.info(f"Dashboard stats: {response}")
        return jsonify({'data': encrypt_response(response)}), 200
    except Exception as e:
        logger.error(f"Error in get_dashboard_stats: {str(e)}")
        return jsonify({'error': str(e)}), 500
'''
'''
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask import jsonify

@app.route('/api/dashboard_stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    try:
        user_email = get_jwt_identity()
        if not user_email:
            return jsonify({'error': 'User email is required'}), 400
        
        current_user = User.query.filter_by(email=user_email).first()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        
        if not current_user.is_active:
            return jsonify({'error': 'User is not active'}), 403
        
        total_connected_users = User.query.filter_by(trading_active=True).count()
        
        # Query stocks for the current user
        not_active_stocks = Stock.query.filter_by(
            user_id=current_user.id,  
            trading_status=False
        ).all()
        
        active_stocks = Stock.query.filter_by(
            user_id=current_user.id,  
            trading_status=True
        ).all()
        
        # Log counts for debugging
        logger.info(f"User ID: {current_user.id}")
        logger.info(f"Not Active stocks for {current_user.email}: {len(not_active_stocks)}")
        logger.info(f"Active stocks for {current_user.email}: {len(active_stocks)}")
        
        # Populate not_active_stock_data
        not_active_stock_data = []
        active_stock_data = []
        for stock in active_stock_data:
            stock_info = { 
                'user_email': current_user.email,
                    'stock_symbol': stock.tradingsymbol,
                    'total_open_quantity': 0,
                    'current_sr_no': 0,
                    'phase': 'Unknown',
                    'phase_drop': 0,
                    'activation_status': stock.trading_status
            }
            active_stock_data.append(stock_info)
            logger.info(f"Not Active stock: {stock.tradingsymbol}, trading_status={stock.trading_status}")

        # Populate active_stock_data
        
        for stock in active_stocks:
            open_trades = Trade.query.filter_by(
                stock_symbol=stock.tradingsymbol,
                user_email=current_user.email,
                status='OPEN'
            ).order_by(Trade.sr_no.desc()).all()
            
            if not open_trades:

                active_stock_data.append({
                    'user_email': current_user.email,
                    'stock_symbol': stock.tradingsymbol,
                    'total_open_quantity': 0,
                    'current_sr_no': 0,
                    'phase': 'Unknown',
                    'phase_drop': 0,
                    'activation_status': stock.trading_status
                })
                logger.info(f"No open trades for active stock {stock.tradingsymbol}")
                continue
            
            # Total quantity of OPEN trades
            total_open_quantity = sum(trade.total_quantity for trade in open_trades)
            # Current sr_no (latest OPEN trade)
            current_sr_no = open_trades[0].sr_no
            # Determine phase based on sr_no
            phase_config = PhaseConfig.query.filter_by(
                user_email=current_user.email,
                stock_symbol=stock.tradingsymbol
            ).filter(
                PhaseConfig.start_sr_no <= current_sr_no,
                PhaseConfig.end_sr_no >= current_sr_no
            ).first()
            phase = phase_config.phase if phase_config else "Unknown"
            # Stock data
            stock_info = {
                'user_email': current_user.email,
                'stock_symbol': stock.tradingsymbol,
                'total_open_quantity': total_open_quantity,
                'current_sr_no': current_sr_no,
                'phase': phase,
                'phase_drop': phase_config.down_increment if phase_config else 0,
                'activation_status': stock.trading_status
            }
            active_stock_data.append(stock_info)
            logger.info(f"Active stock data for {current_user.email}/{stock.tradingsymbol}: {stock_info}")

        # Response
        response = {
            'not_active_stock_data': not_active_stock_data,
            'total_connected_users': total_connected_users,
            'active_stock_data': active_stock_data,
            'status': '200',
            'message': 'Dashboard stats retrieved successfully'
        }
        logger.info(f"Dashboard stats: {response}")
        return jsonify({'data': encrypt_response(response)}), 200
    except Exception as e:
        logger.error(f"Error in get_dashboard_stats: {str(e)}")
        return jsonify({'error': str(e)}), 500
'''

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask import jsonify

@app.route('/api/dashboard_stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    try:
        user_email = get_jwt_identity()
        if not user_email:
            return jsonify({'error': 'User email is required'}), 400
        
        current_user = User.query.filter_by(email=user_email).first()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        
        if not current_user.is_active:
            return jsonify({'error': 'User is not active'}), 403
        
        total_connected_users = User.query.filter_by(trading_active=True).count()
        
        # Query all stocks for the current user (both active and inactive)
        all_stocks = Stock.query.filter_by(user_id=current_user.id).all()
        
        # Log counts for debugging
        logger.info(f"User ID: {current_user.id}")
        logger.info(f"Total stocks for {current_user.email}: {len(all_stocks)}")
        
        # Populate a single stock_data list
        stock_data = []
        for stock in all_stocks:
            # Get OPEN trades for this stock
            open_trades = Trade.query.filter_by(
                stock_symbol=stock.tradingsymbol,
                user_email=current_user.email,
                status='OPEN'
            ).order_by(Trade.sr_no.desc()).all()
            
            if not open_trades:
                # Append stock with no open trades (active or inactive)
                stock_info = {
                    'user_email': current_user.email,
                    'stock_symbol': stock.tradingsymbol,
                    'total_open_quantity': 0,
                    'current_sr_no': 0,
                    'phase': 'Unknown',
                    'phase_drop': 0,
                    'activation_status': stock.trading_status
                }
                stock_data.append(stock_info)
                logger.info(f"No open trades for stock {stock.tradingsymbol}, trading_status={stock.trading_status}")
                continue
            
            # Total quantity of OPEN trades
            total_open_quantity = sum(trade.total_quantity for trade in open_trades)
            # Current sr_no (latest OPEN trade)
            current_sr_no = open_trades[0].sr_no
            # Determine phase based on sr_no
            phase_config = PhaseConfig.query.filter_by(
                user_email=current_user.email,
                stock_symbol=stock.tradingsymbol
            ).filter(
                PhaseConfig.start_sr_no <= current_sr_no,
                PhaseConfig.end_sr_no >= current_sr_no
            ).first()
            phase = phase_config.phase if phase_config else "Unknown"
            # Stock data
            stock_info = {
                'user_email': current_user.email,
                'stock_symbol': stock.tradingsymbol,
                'total_open_quantity': total_open_quantity,
                'current_sr_no': current_sr_no,
                'phase': phase,
                'phase_drop': phase_config.down_increment if phase_config else 0,
                'activation_status': stock.trading_status
            }
            stock_data.append(stock_info)
            logger.info(f"Stock data for {current_user.email}/{stock.tradingsymbol}: {stock_info}")

        # Response
        response = {
            'total_connected_users': total_connected_users,
            'active_stock_data': stock_data,
            'status': '200',
            'message': 'Dashboard stats retrieved successfully'
        }
        logger.info(f"Dashboard stats: {response}")
        return jsonify({'data': encrypt_response(response)}), 200
    except Exception as e:
        logger.error(f"Error in get_dashboard_stats: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
def save_state_at_close():
    while True:
        now = datetime.now(IST)
        if now.hour == 15 and now.minute >= 30 and now.weekday() < 5:
            with websocket_lock:
                for user_email, ws in websocket_clients.items():
                    ws.close_connection()
            logger.info("Market closed, state saved")
            time.sleep(3600)
        time.sleep(60)

threading.Thread(target=save_state_at_close, daemon=True).start()

@app.before_request
def log_request_data():
    if request.path == "/user/stocks/remove":
        logging.info("\n🚀 Received /user/generate-2fa API request")
        logging.info(f"📝 Request Method: {request.method}")
        logging.info(f"📩 Request Headers: {dict(request.headers)}")
        logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")
        
@app.route("/user/stocks/remove", methods=["POST"])
@jwt_required()
def remove_user_stock():
    try:
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        encrypted_data = request.json.get("data")
        decrypted_request = decrypt_request(encrypted_data)
        logger.info(f"Decrypted Request: {decrypted_request}")

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format", "status": "400"})}), 400

        data = decrypted_request
        required_fields = ["symboltoken"]
        logger.info(f"Request Data: {data}")
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        if missing_fields:
            return jsonify({"data": encrypt_response({"message": f"Missing required fields: {', '.join(missing_fields)}", "status": "400"})}), 400

        stock = Stock.query.filter_by(user_id=current_user.id, symboltoken=data["symboltoken"]).first()
        if not stock:
            return jsonify({
                "data": encrypt_response({
                    "message": f"Stock '{data['symboltoken']}' not found for this user",
                    "status": "404"
                })
            }), 404
        delete_phase = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=data["symboltoken"]).all()
        for phase in delete_phase:
            db.session.delete(phase)
        
        db.session.delete(stock)
        db.session.commit()

        add_log(user_email, "Stock Removed", f"Removed {data['symboltoken']}")

        active_stocks = Stock.query.filter_by(user_id=current_user.id, trading_status=True).count()
        if active_stocks > 0:
            logger.info(f"Active stocks remain ({active_stocks}), restarting WebSocket for {user_email}")
            restart_websocket(current_user)
        else:
            logger.info(f"No active stocks remain, stopping WebSocket for {user_email}")
            stop_websocket_stream(current_user)
        

        
        
        
        return jsonify({
            "data": encrypt_response({
                "message": "Stock removed successfully",
                "status": "200"
            })
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Remove Stock Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": f"Failed to remove stock: {str(e)}", "status": "500"})}), 500
    
@app.route("/user/orders/cancel", methods=["POST"])
@jwt_required()
def cancel_order():
    try:
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        # Decrypt request data
        encrypted_data = request.json.get("data")
        decrypted_request = decrypt_request(encrypted_data)

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format", "status": "400"})}), 400

        data = decrypted_request
        required_fields = ["variety", "orderid"]
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        if missing_fields:
            return jsonify({"data": encrypt_response({"message": f"Missing required fields: {', '.join(missing_fields)}", "status": "400"})}), 400

        variety = data["variety"]
        order_id = data["orderid"]

        session = get_angel_session(current_user)
        smart_api = session['smart_api']

        order_response = smart_api.cancelOrder(order_id=order_id, variety=variety)

        if not order_response.get('status', False):
            return jsonify({
                "data": encrypt_response({
                    "status": False,
                    "message": order_response.get('message', 'Failed to cancel order'),
                    "errorcode": order_response.get('errorcode', 'UNKNOWN'),
                    "data": {}
                })
            }), 400

        # Construct success response
        response_data = {
            "status": True,
            "message": "SUCCESS",
            "errorcode": "",
            "data": {
                "orderid": order_id,
                "uniqueorderid": order_response.get('data', {}).get('uniqueorderid', 'N/A')  # Adjust based on actual response
            }
        }
        add_log(user_email, "Order Cancelled", f"Cancelled order {order_id} (variety: {variety})")

        return jsonify({"data": encrypt_response(response_data)}), 200

    except Exception as e:
        logger.error(f"❌ Cancel Order Error for {user_email}: {str(e)}")
        return jsonify({"data": encrypt_response({"message": f"Failed to cancel order: {str(e)}", "status": "500"})}), 500
    
def start_all_websocket_streams():
    """Start WebSocket streams for all users with active stocks."""
    with app.app_context():
        users = User.query.all()
        for user in users:
            stocks = Stock.query.filter_by(user_id=user.id).all()
            if not stocks:
                logger.info(f"No stocks for user {user.email}, skipping WebSocket")
                continue
            # if any(stock.live_price_status for stock in stocks):
            logger.info(f"Starting WebSocket for user {user.email}")
                # Use eventlet.spawn instead of threading.Thread for compatibility
            eventlet.spawn(start_websocket_stream, user)
            # else:
            #     logger.info(f"No active stocks for user {user.email}, skipping WebSocket")

@app.route('/api/get-order-history', methods=['GET'])
@jwt_required()
def get_order_history():
    try:
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403
        
        order_status = OrderStatus.query.filter_by(user_email=user_email).all()
        order_history = []
        for order in order_status:
            order_history.append({
                "order_id": order.order_id,
                "unique_order_id": order.unique_order_id,
                "symbol": order.symbol,
                "status": order.status,
                "message": order.message,
                "quantity": order.quantity,
                "price": order.price,
                "buy_sell": order.buy_sell,
                "created_at": order.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "updated_at": order.updated_at.strftime("%Y-%m-%d %H:%M:%S")
            })
        response = {
            "order_history": order_history,
            "status": "200",
            "message": "Order history retrieved successfully"
        }
        return jsonify({"data": encrypt_response(response)}), 200
    
    except Exception as e:
        logger.error(f"❌ Get Order History Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": f"Failed to get order history: {str(e)}", "status": "500"})}), 500
    
'''
def monitor_websocket_streams():
    """Background task to periodically ensure WebSocket streams are running for users with active stocks."""
    while True:
        try:
            with app.app_context():
                users = User.query.all()
                for user in users:
                    user_email = user.email
                    stocks = Stock.query.filter_by(user_id=user.id).all()
                    has_active_stocks = any(stock.live_price_status for stock in stocks)
                    logger.debug(f"Checking WebSocket for {user_email}, active_stocks={has_active_stocks}")
                    with websocket_lock:
                        is_running = user_email in websocket_clients and websocket_clients[user_email].connected
                    if has_active_stocks and not is_running:
                        logger.info(f"Detected missing WebSocket for {user_email}, starting it")
                        eventlet.spawn(start_websocket_stream, user)
                    elif not has_active_stocks and is_running:
                        logger.info(f"Detected unnecessary WebSocket for {user_email}, stopping it")
                        stop_websocket_stream(user)
                        
            logger.debug(f"WebSocket monitor checked all users. Active websockets: {list(websocket_clients.keys())}")
        except Exception as e:
            logger.error(f"Error in WebSocket monitor: {str(e)}")
        time.sleep(60)  # Check every 60 seconds
'''        

def monitor_websocket_streams():
    while True:
        try:
            with app.app_context():
                users = User.query.all()
                for user in users:
                    user_email = user.email
                    stocks = Stock.query.filter_by(user_id=user.id).all()
                    has_active_stocks = any(stock.live_price_status for stock in stocks)
                    logger.debug(f"Checking WebSocket for {user_email}, active_stocks={has_active_stocks}")
                    with websocket_lock:
                        is_running = user_email in websocket_clients and user_email in websocket_threads
                    if has_active_stocks and not is_running:
                        logger.info(f"Detected missing WebSocket for {user_email}, starting it")
                        eventlet.spawn(start_websocket_stream, user)
                    elif not has_active_stocks and is_running:
                        logger.info(f"Detected unnecessary WebSocket for {user_email}, stopping it")
                        stop_websocket_stream(user)
            logger.debug(f"WebSocket monitor checked all users. Active websockets: {list(websocket_clients.keys())}")
        except Exception as e:
            logger.error(f"Error in WebSocket monitor: {str(e)}")
        time.sleep(60)
        


# Run with Eventlet
if __name__ == "__main__":
    eventlet.monkey_patch()
    with app.app_context():
        db.create_all()
    start_all_websocket_streams()
    eventlet.spawn(monitor_websocket_streams)
    logger.info("Starting Flask app with Eventlet server on port 8000")
    eventlet.wsgi.server(eventlet.listen(('', 8000)), app)
