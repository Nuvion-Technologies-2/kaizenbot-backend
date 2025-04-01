import random
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

AES_KEY = hashlib.sha256(SECRET_KEY.encode()).digest()

db.init_app(app)
bcrypt.init_app(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
mail = Mail(app)  


logging.basicConfig(level=logging.DEBUG)

thread = None
thread_lock = Lock()
IST = pytz.timezone("Asia/Kolkata")

order_status_dict = {}
order_status_lock = threading.Lock()
order_locks = {}  

DEFAULT_PHASES = [
    {"phase": 1, "start_sr_no": 1, "end_sr_no": 21, "down_increment": 0.25},
    {"phase": 2, "start_sr_no": 22, "end_sr_no": 41, "down_increment": 0.50},
    {"phase": 3, "start_sr_no": 42, "end_sr_no": 55, "down_increment": 0.75},
    {"phase": 4, "start_sr_no": 56, "end_sr_no": 70, "down_increment": 1.00},
    {"phase": 5, "start_sr_no": 71, "end_sr_no": 81, "down_increment": 1.25},
]

def encrypt_response(data_dict):
    """Encrypt a JSON response using AES-256-CBC (CryptoJS-compatible)"""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC)
        padded_data = pad(json.dumps(data_dict).encode(), AES.block_size)
        encrypted_bytes = cipher.encrypt(padded_data)

        
        iv = base64.b64encode(cipher.iv).decode("utf-8")
        ct = base64.b64encode(encrypted_bytes).decode("utf-8")

        return json.dumps({"iv": iv, "ct": ct})  
    except Exception as e:
        logging.error(f"❌ Encryption Error: {str(e)}")
        return None


def decrypt_request(encrypted_data):
    """Decrypt an AES-256-CBC encrypted JSON request from CryptoJS"""
    try:
        
        parsed_data = json.loads(encrypted_data)
        iv = base64.b64decode(parsed_data["iv"])
        ct = base64.b64decode(parsed_data["ct"])

        
        salted_match = re.match(b"Salted__(.{8})(.*)", ct, re.DOTALL)
        if salted_match:
            salt, ct = salted_match.groups()

        
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ct), AES.block_size)
        
        return json.loads(decrypted.decode("utf-8"))  
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
        db.session.rollback()  
        logging.error(f"❌ Failed to log event: {str(e)}")

from flask_jwt_extended import get_jwt

def role_required(required_role):
    def decorator(func):
        @wraps(func)
        @jwt_required()
        def wrapper(*args, **kwargs):
            identity = get_jwt_identity()  
            claims = get_jwt()  

            print(f"🔑 JWT Identity: {identity}")  
            print(f"🛠 JWT Claims: {claims}")  

            
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

        
        if not user.totp_secret:
            user.totp_secret = pyotp.random_base32()  
            db.session.commit()

        
        totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
            name=user.email, issuer_name="KaizenBot"
        )

        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        qr_img = qr.make_image(fill="black", back_color="white")

        
        buffered = BytesIO()
        qr_img.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

        
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

        
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(otp):
            add_log(user_email, "2FA Verification Failed", "Invalid OTP provided")
            return jsonify({"data": encrypt_response({"message": "Invalid OTP","status":"401"})}), 401

        
        add_log(user_email, "2FA Enabled", "OTP verified successfully")
        
        return jsonify({"data": encrypt_response({"message": "2FA enabled successfully","status":"200"})}), 200

    except Exception as e:
        logging.error(f"❌ Verify 2FA Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Failed to verify OTP","status":"500"})}), 500
    

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


WEBSITE_NAME = "Kaizenbot.in"

def send_login_notification(user_email, user_name, user_role):
    """Sends an email notification when a user logs in."""

    app = current_app._get_current_object()  

    def send_email():
        with app.app_context():  
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
                - Contact support at **support@{WEBSITE_NAME.lower()}**.  

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

    
    threading.Thread(target=send_email).start()

def send_registration_notification(user_email, user_name, user_role):
    app = current_app._get_current_object()  

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

        data = decrypted_request  

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

            
            user = User.query.filter_by(email=user_email).first()
            if not user:
                logging.error("❌ JWT User Not Found in Database")
                return jsonify({"data": encrypt_response({"message": "Invalid token user","status":"403"})}), 403

            user_role = user.role  
            logging.info(f"🔑 User Role from DB: {user_role}")

        except Exception as jwt_error:
            logging.error(f"❌ JWT Verification Failed: {str(jwt_error)}")
            return jsonify({"data": encrypt_response({"message": "Invalid or missing token","status":"401"})}), 401

        raw_body = request.data.decode('utf-8')
        logging.info(f"🔒 Raw Request Body: {raw_body}")

        
        encrypted_data = request.json.get("data")
        logging.info(f"🔐 Encrypted Data Field: {encrypted_data}")

        
        decrypted_request = decrypt_request(encrypted_data)
        logging.info(f"🔓 Decrypted Request: {decrypted_request}")

        if not decrypted_request:
            logging.error("❌ Decryption Failed: No data received.")
            return jsonify({"data": encrypt_response({"message": "Invalid request format","status":"400"})}), 400

        
        if isinstance(decrypted_request, str):
            data = eval(decrypted_request)  
        else:
            data = decrypted_request  

        logging.info(f"📦 Parsed Decrypted Data: {data}")

        
        allowed_roles = {"superuser": ["manager", "user"], "manager": ["user"]}
        if user_role not in allowed_roles or data["role"] not in allowed_roles[user_role]:
            logging.warning(f"❌ Unauthorized role: {user_role} cannot create {data['role']}.")
            return jsonify({"data": encrypt_response({"message": "Access denied","status":"403"})}), 403

        
        existing_user = User.query.filter_by(email=data["email"]).first()
        if existing_user:
            logging.warning(f"❌ Duplicate email found: {data['email']}")
            logs = Log(user_email=user_email, action="User Registration Failed", details=f"Email already registered: {data['email']}")
            db.session.add(logs)
            db.session.commit()
            return jsonify({"data": encrypt_response({"message": "Email already registered","status":"400"})}), 400

        
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

        
        reset_token = create_access_token(identity=email, expires_delta=timedelta(minutes=30))  

        
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

        
        try:
            decoded_data = decode_token(reset_token)
            print(decoded_data)
            email = decoded_data["sub"]
        except Exception as e:
            logging.error(f"❌ Token Decode Error: {str(e)}")
            return jsonify({"data": encrypt_response({"message": "Invalid or expired token","status":"400"})}), 400

        
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
        user_email = identity  

        
        current_user = User.query.filter_by(email=user_email).first()
        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized","status":"403"})}), 403

        
        target_user = User.query.filter_by(email=data["email"]).first()
        if not target_user:
            return jsonify({"data": encrypt_response({"message": "User not found","status":"404"})}), 404

        
        allowed_roles = {"superuser": ["manager", "user"], "manager": ["user"]}
        if current_user.role not in allowed_roles or target_user.role not in allowed_roles[current_user.role]:
            return jsonify({"data": encrypt_response({"message": "Permission denied","status":"403"})}), 403

        
        target_user.is_active = "True"
        db.session.commit()

        
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
        user_email = identity  

        
        current_user = User.query.filter_by(email=user_email).first()
        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized","status":"403"})}), 403

        
        target_user = User.query.filter_by(email=data["email"]).first()
        if not target_user:
            return jsonify({"data": encrypt_response({"message": "User not found","status":"404"})}), 404

        
        allowed_roles = {"superuser": ["manager", "user"], "manager": ["user"]}
        if current_user.role not in allowed_roles or target_user.role not in allowed_roles[current_user.role]:
            return jsonify({"data": encrypt_response({"message": "Permission denied","status":"403"})}), 403

        
        target_user.is_active = "False"
        db.session.commit()

        
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
        

@app.route("/superuser", methods=["GET"])
@role_required("superuser")
def superuser_dashboard():
    return jsonify({"data": encrypt_response({"message": "Welcome superuser!", "status":"200","role":"superuser"})}), 200


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


@app.route("/user", methods=["GET"])
@role_required("user")
def user_dashboard():
    return jsonify({"data": encrypt_response({"message": "Welcome User!", "status":"200"})}), 200

@app.route("/users", methods=["GET"])
@jwt_required()
def get_all_users():
    try:
        
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logging.info(f"🔑 JWT Identity: {user_email}")
        logging.info(f"🛠 JWT Claims: {current_user}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access","status":"403"})}), 403

        
        if current_user.role == "superuser":
            users = User.query.filter(User.role != "superuser").all()  

        
        elif current_user.role == "manager":
            users = User.query.filter_by(role="user").all()

        
        else:
            return jsonify({"data": encrypt_response({"message": "Permission denied","status":"403"})}), 403

        
        user_list = [
            {
                
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

        
        log_entry = Log(user_email=user_email, action="Fetched User List", details=f"Role: {current_user.role}")
        db.session.add(log_entry)
        db.session.commit()

        
        return jsonify({"data": encrypt_response({"users": user_list,"status":"200"})}), 200

    except Exception as e:
        logging.error(f"❌ Fetch Users Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Failed to fetch users","status":"500"})}), 500


@app.route("/user/<identifier>", methods=["GET"])
@jwt_required()
def get_user_info(identifier):
    try:
        
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logging.info(f"🔑 JWT Identity: {user_email}")
        logging.info(f"🛠 Current User: {current_user}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access","status":"403"})}), 403

        
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

        
        if target_user.email != current_user.email:
            add_log(user_email, "Unauthorized User Info Access Attempt", 
                    f"Tried to access {target_user.email} (Role: {current_user.role})")
            return jsonify({"data": encrypt_response({"message": "Permission denied: You can only view your own information","status":"403"})}), 403

        
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
            "totp_enabled": bool(target_user.totp_secret)  
        }

        
        add_log(user_email, "Fetched Own User Info", f"Viewed info for {target_user.email}")

        
        return jsonify({"data": encrypt_response({"user": user_data,"status":"200"})}), 200

    except Exception as e:
        logging.error(f"❌ Fetch User Info Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": "Failed to fetch user info","status":"500"})}), 500


from flask import request


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
        
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logging.info(f"🔑 JWT Identity: {user_email}")
        logging.info(f"🛠 Current User: {current_user}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access","status":"403"})}), 403

        
        encrypted_data = request.json.get("data")
        decrypted_request = decrypt_request(encrypted_data)

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format","status":"400"})}), 400

        data = decrypted_request

        
        name = data.get("name")
        phone = data.get("phone")
        email = data.get("email")
        address = data.get("address")
        city = data.get("city")
        pincode = data.get("pincode")

        
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

        
        db.session.commit()

        
        add_log(user_email, "Profile Updated", f"Updated: {', '.join(changes)}")

        
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

        
        return jsonify({
            "data": encrypt_response({
                "message": "Profile updated successfully",
                "user": user_data,
                "status": "200"
            })
        }), 200

    except Exception as e:
        db.session.rollback()  
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
        
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")
        logger.info(f"🛠 Current User: {current_user}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        
        encrypted_data = request.json.get("data")
        decrypted_request = decrypt_request(encrypted_data)

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format", "status": "400"})}), 400

        data = decrypted_request
        
        

        
        smartapi_key = data.get("smartapi_key")
        smartapi_username = data.get("smartapi_username")
        smartapi_password = data.get("smartapi_password")
        smartapi_totp_token = data.get("smartapi_totp_token")

        
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

        
        add_log(user_email, "Angel One Credentials Validated and Saved", "Credentials validated and updated")
        
        
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
        
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")
        logger.info(f"🛠 Current User: {current_user}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        
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
    max_retries = 3  
    retry_delay = 5  

    
    if (user_email in session_cache and 
        'smart_api' in session_cache[user_email] and 
        session_cache[user_email]['expires_at'] > current_time):
        logger.info(f"Reusing existing session for {user_email}")
        return session_cache[user_email]['smart_api']

    
    if not all([user.smartapi_key, user.smartapi_username, user.smartapi_password, user.smartapi_totp_token]):
        logger.error(f"Angel One credentials not set for {user_email}")
        raise Exception("Angel One credentials not set for this user")

    
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
            
            
            if "exceeding access rate" in str(e).lower() or "session" in str(e).lower():
                if attempt < max_retries - 1:  
                    logger.info(f"Retrying after {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    continue
            
            
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

            
            if attempt == max_retries - 1:
                logger.error(f"Failed to generate or refresh session for {user_email} after {max_retries} attempts")
                raise Exception(f"Unable to establish Angel One session for {user_email}: {str(e)}")

    
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

        
        smart_api = get_angel_session(current_user)
        rms = smart_api.rmsLimit()
        logger.info(f"RMS Limit Response: {rms}")

        
        
        
        
        
        logger.info("Fetched RMS Limit successfully")
        return jsonify({"data": encrypt_response({"message": "RMS limit fetched successfully", "rms": rms, "status": "200"})}), 200

    except Exception as e:
        logger.error(f"❌ RMS Limit Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": f"Failed to fetch RMS limit: {str(e)}", "status": "500"})}), 500


@app.route("/user/angel/order-book", methods=["GET"])
@jwt_required()
def get_order_book():
    try:
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        
        smart_api = get_angel_session(current_user)
        order_book = smart_api.orderBook()
        logger.info(f"Order Book Response: {order_book}")

        
        logger.info("Fetched Order Book successfully")
        return jsonify({"data": encrypt_response({"message": "Order book fetched successfully", "order_book": order_book, "status": "200"})}), 200

    except Exception as e:
        error_str = str(e)
        if "Couldn't parse the JSON response" in error_str and "exceeding access rate" in error_str:
            logger.warning(f"Rate limit encountered for {user_email}: {error_str}")
            
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
            
            logger.error(f"❌ Order Book Error: {error_str}")
            return jsonify({
                "data": encrypt_response({
                    "message": f"Failed to fetch order book: {error_str}",
                    "status": "500"
                })
            }), 500


@app.route("/user/angel/trade-book", methods=["GET"])
@jwt_required()
def get_trade_book():
    try:
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        
        smart_api = get_angel_session(current_user)
        trade_book = smart_api.tradeBook()
        logger.info(f"Trade Book Response: {trade_book}")

        
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

        
        smart_api = get_angel_session(current_user)
        holding = smart_api.allholding()
        

        
        logger.info("Fetched holding successfully")
        return jsonify({"data": {"message": "Trade book fetched successfully", "all_holding": holding, "status": "200"}}), 200

    except Exception as e:
        
        error_str = str(e)
        if "Couldn't parse the JSON response" in error_str and "exceeding access rate" in error_str:
            logger.warning(f"Rate limit encountered for {user_email}: {error_str}")
            
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
        
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        
        valid_exchanges = ["NSE", "BSE"]  
        if exchange not in valid_exchanges:
            return jsonify({"data": encrypt_response({"message": f"Invalid exchange. Use one of: {', '.join(valid_exchanges)}", "status": "400"})}), 400

        
        if not search_term or not isinstance(search_term, str) or len(search_term.strip()) < 1:
            return jsonify({"data": encrypt_response({"message": "Invalid search term", "status": "400"})}), 400

        
        smart_api = get_angel_session(current_user)

        
        search_result = smart_api.searchScrip(exchange, search_term)
        

        
        if not search_result or search_result.get("status") is False:
            return jsonify({"data": encrypt_response({"message": "Failed to fetch stock data", "status": "500"})}), 500

        
        add_log(user_email, "Stock Search", f"Searched {exchange}:{search_term}")

        
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

        
        encrypted_data = request.json.get("data")
        decrypted_request = decrypt_request(encrypted_data)

        if not decrypted_request:
            return jsonify({"data": encrypt_response({"message": "Invalid request format", "status": "8888"})}), 400
        
        data = decrypted_request
        required_fields = ["exchange", "tradingsymbol", "symboltoken"]
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        if missing_fields:
            return jsonify({"data": encrypt_response({"message": f"Missing required fields: {', '.join(missing_fields)}", "status": "8888"})}), 400

        
        stock_count = Stock.query.filter_by(user_id=current_user.id).count()
        logger.info(f"📊 Current stock count for user {user_email}: {stock_count}")
        if stock_count >= 5:
            logger.info(f"🚫 Stock limit reached for user {user_email}")
            return jsonify({"data": encrypt_response({
                "message": "Stock limit reached. Maximum 5 stocks allowed per user.",
                "status": "429"
            })}), 429

        get_wallet_value(current_user.smartapi_key)
        
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
            
        
        new_stock = Stock(
            user_id=current_user.id,
            exchange=data["exchange"],
            tradingsymbol=data["tradingsymbol"],
            symboltoken=data["symboltoken"],
            live_price_status=True
        )
        db.session.add(new_stock)
        db.session.commit()

        add_log(user_email, "Stock Added", f"Added {data['exchange']}:{data['tradingsymbol']} (Token: {data['symboltoken']})")

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

        
        stocks = Stock.query.filter_by(user_id=current_user.id).all()
        stock_list = [stock.to_dict() for stock in stocks]

        
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

from flask_jwt_extended import JWTManager, get_jwt_identity, verify_jwt_in_request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pytz

IST = pytz.timezone('Asia/Kolkata')


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

def get_strategy_data(user_email, stock_symbol, base_price, wallet_value):
    configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=stock_symbol).order_by(PhaseConfig.start_sr_no).all()
    v1 = calculate_v1(wallet_value)
    strategy = []
    f_values = [200, 110]  
    f_values.append(f_values[1] + round(f_values[1] * v1))  
    for i in range(3, 81):  
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
                total_invested = round(entry * qnty, 2)  
            else:
                total_invested = round(total_invested + f_values[sr_no-1], 2)  
            
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
    
    
    return pd.DataFrame(strategy)

live_prices = {}
live_prices_lock = threading.Lock()


websocket_clients = {}  
websocket_threads = {}  
websocket_lock = threading.Lock()


logging.basicConfig(
    filename='trading_strategy.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

BASE_CAPITAL_OPTIONS = [
    100000, 150000, 200000, 250000, 300000, 350000, 400000, 450000, 500000,
    550000, 600000, 650000, 700000, 750000, 800000, 850000, 900000, 950000, 1000000
]


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
        
        user_email = get_jwt_identity()
        if not user_email:
            return jsonify({'error': 'User email is required'}), 400

        
        user = User.query.filter_by(email=user_email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        
        smart_api = get_angel_session(user)
        rms_cash = get_wallet_value(smart_api)
        if rms_cash is None:
            return jsonify({'error': 'Failed to fetch RMS cash value'}), 500

        
        user.available_balance = rms_cash
        db.session.commit()
        logger.info(f"Updated available_balance for {user_email}: {user.available_balance}")

        
        
        active_trades = Stock.query.filter_by(user_id = user.id).filter(Stock.trading_status != False).all()
        logger.info(f"Active trades for {user_email}: {len(active_trades)}")
        
        logger.info(f"Active trades for {user_email}: active_trades {active_trades}")
        
        for trade in active_trades:
            logger.info(f"Trade for {trade.tradingsymbol}: {trade.allotment_captial}")

        
        
        stock_base_capitals = {}
        for trade in active_trades:
            logger.info(f"Trade for {trade.tradingsymbol}: {trade.allotment_captial}")
            stock_base_capitals[trade.symboltoken] = trade.allotment_captial
            

        used_balance = sum(stock_base_capitals.values())
        user.used_balance = used_balance
        user.remaining_balance = max(0, user.available_balance - user.used_balance)
        db.session.commit()
        logger.info(f"Calculated for {user_email}: used_balance={user.used_balance}, remaining_balance={user.remaining_balance}")

        
        max_stocks = get_max_stocks(user.available_balance)
        current_stocks = len(stock_base_capitals)
        remaining_stock_slots = max(0, max_stocks - current_stocks)

        
        valid_options = [
            option for option in BASE_CAPITAL_OPTIONS
            if option <= user.remaining_balance and remaining_stock_slots > 0
        ]

        
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
def send_insufficient_funds_notification(user_email, user_name, symbol, order_id, quantity, price, message_text):
    """Sends an email notification when an order is rejected due to insufficient funds."""

    app = current_app._get_current_object()  # Get the Flask app context

    def send_email():
        with app.app_context():  
            try:
                rejection_time = IST.localize(datetime.now()).strftime("%Y-%m-%d %H:%M:%S")

                subject = f"⚠️ Order Rejected Due to Insufficient Funds on {WEBSITE_NAME}"
                body = f"""
                Hello {user_name},  

                Your recent order for {symbol} was rejected because your wallet balance is insufficient. Please add funds to continue trading.  

                📋 Order Details:  
                - Symbol: {symbol}  
                - Order ID: {order_id}  
                - Quantity: {quantity}  
                - Price: {price}  
                - Reason: {message_text}  
                - Time: {rejection_time}  

                💡 Action Required:  
                - Add funds to your wallet via the {WEBSITE_NAME} dashboard.  
                - Contact support at **support@{WEBSITE_NAME.lower()}.in** if you need assistance.  

                Happy Trading,  
                The {WEBSITE_NAME} Team  
                """

                msg = Message(subject, recipients=[user_email], body=body)
                mail.send(msg)
                logger.info(f"📧 Insufficient funds notification sent to {user_email} for order {order_id}")
                log_entry = Log(user_email=user_email, action="Insufficient Funds Notification Sent", details=f"Order {order_id} rejected due to insufficient funds")
                db.session.add(log_entry)
                db.session.commit()

            except Exception as e:
                logger.error(f"❌ Failed to send insufficient funds email: {str(e)}")

    threading.Thread(target=send_email).start()

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
            message_text = order_data.get('orderData', {}).get('text', order_data.get('error-message', ''))

            logger.info(f"Order Update - ID: {order_id}, Unique ID: {unique_order_id}, Symbol: {symbol}, Status: {order_status}, Filled: {filled_shares}")

            # Check for insufficient funds and send email notification
            if message_text.startswith("Your order has been rejected due to Insufficient Funds"):
                order_entry = (OrderStatus.query.filter_by(order_id=order_id).first() or 
                              OrderStatus.query.filter_by(unique_order_id=unique_order_id).first())
                if order_entry:
                    user = User.query.filter_by(email=order_entry.user_email).first()
                    if user:
                        send_insufficient_funds_notification(
                            user_email=user.email,
                            user_name=user.name if hasattr(user, 'name') else "User",  # Adjust based on your User model
                            symbol=symbol,
                            order_id=order_id,
                            quantity=order_entry.quantity,
                            price=order_entry.price,
                            message_text=message_text
                        )

            tracked_id = None
            if order_id == numeric_order_id_to_track or unique_order_id == order_id_to_track:
                tracked_id = order_id_to_track if unique_order_id == order_id_to_track else numeric_order_id_to_track

            if tracked_id:
                with order_status_lock:
                    order_status_dict[tracked_id] = {
                        'status': order_status,
                        'symbol': symbol,
                        'message': message_text,
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

                    try:
                        unique_order_id = OrderStatus.query.filter_by(order_id=numeric_order_id).first().unique_order_id
                        order_details = smart_api.individual_order_details(unique_order_id)
                        logger.debug(f"API response for order {unique_order_id}: {order_details}")
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
                    time.sleep(1)  
                    attempt += 1

                logger.error(f"Order {order_id} for {symbol} did not complete after {max_attempts} attempts")
                api_log = ApiLog(user_email, symbol, order_id, "Place Order", "timeout", "Order status not updated in time")
                db.session.add(api_log)
                db.session.commit()
                
                order_entry = OrderStatus.query.filter_by(order_id=numeric_order_id).first()
                if order_entry:
                    try:
                        # Forcefully check OrderBook first on timeout
                        order_book = smart_api.orderBook()
                        logger.debug(f"OrderBook response on timeout for order {numeric_order_id}: {order_book}")
                        order_found = False
                        if order_book.get('status') == True and 'data' in order_book:
                            for order in order_book['data']:
                                if order['orderid'] == numeric_order_id:
                                    final_status = str(order['status']).lower()
                                    executed_qty = int(order['filledshares'] or qty)
                                    if final_status in ['complete', 'executed']:
                                        logger.info(f"OrderBook confirmed order {numeric_order_id} completed with {executed_qty} shares on timeout")
                                        order_entry.status = "complete"
                                        order_entry.message = "Order completed via OrderBook (timeout check)"
                                        order_entry.updated_at = IST.localize(datetime.now())
                                        db.session.commit()
                                        client.close_connection()
                                        return executed_qty, order_id, "completed"
                                    elif final_status in ['rejected', 'cancelled']:
                                        logger.warning(f"OrderBook confirmed order {numeric_order_id} failed: {final_status} on timeout")
                                        order_entry.status = final_status
                                        order_entry.message = order.get('text', 'Order status resolved via OrderBook')
                                        order_entry.updated_at = IST.localize(datetime.now())
                                        db.session.commit()
                                        client.close_connection()
                                        return 0, order_id, final_status
                                    order_found = True
                                    break
                        
                        # If not found in OrderBook, fall back to individual_order_details
                        if not order_found:
                            order_details = smart_api.individual_order_details(order_id)  # Using unique_order_id
                            logger.debug(f"Final API response for order {order_id}: {order_details}")
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
                                    order_entry.status = final_status if final_status in ['rejected', 'cancelled'] else "timeout"
                                    order_entry.message = order_details.get('text', 'Order status not updated in time')
                                    order_entry.updated_at = IST.localize(datetime.now())
                                    db.session.commit()
                                    logger.info(f"Updated OrderStatus for {numeric_order_id} to {order_entry.status}")
                            elif isinstance(order_details, bool):
                                logger.warning(f"Final API returned boolean {order_details} for order {order_id}, marking as timeout")
                                order_entry.status = "timeout"
                                order_entry.message = "Order status not updated in time (API returned boolean)"
                                order_entry.updated_at = IST.localize(datetime.now())
                                db.session.commit()
                            else:
                                logger.error(f"Unexpected final API response type for order {order_id}: {type(order_details)}")
                                order_entry.status = "timeout"
                                order_entry.message = "Order status not updated in time (unexpected API response)"
                                order_entry.updated_at = IST.localize(datetime.now())
                                db.session.commit()
                    except Exception as e:
                        logger.error(f"Final check failed for {numeric_order_id}: {str(e)}", exc_info=True)
                        order_entry.status = "timeout"
                        order_entry.message = "Order status not updated in time"
                        order_entry.updated_at = IST.localize(datetime.now())
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
                
                
                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                log_to_file(f"base_price: {base_price}, wallet_value: {wallet_value}, strategy_data: {strategy_data}")
                log_to_file(f"Strategy data for {symbol}: {strategy_data}")
                
                def get_order_status(unique_order_id):
                    
                    order = OrderStatus.query.filter_by(unique_order_id=unique_order_id, user_email=user.email).first()
                    if order and order.status not in ['pending', 'UNKNOWN', 'timeout']:
                        log_to_file(f"Order status from table for unique_order_id {unique_order_id} (order_id: {order.order_id}): {order.status}")
                        return order.status

                    try:
                        
                        status = smart_api.individual_order_details(unique_order_id)
                        log_to_file(f"Order status from API for unique_order_id {unique_order_id}: {status}")

                        if isinstance(status, dict) and 'data' in status:
                            
                            final_status = str(status['data'].get('orderstatus', status['data'].get('status', 'UNKNOWN'))).lower()
                            executed_qty = float(status['data'].get('filledshares', order.quantity if order else 0))
                            order_id = status['data'].get('orderid', order.order_id if order else None)  

                            
                            new_status = OrderStatus(
                                user_email=user.email,
                                order_id=order_id,  
                                unique_order_id=unique_order_id,  
                                symbol=symbol,
                                status=final_status,
                                message=status['data'].get('text', ''),
                                quantity=executed_qty,
                                price=float(status['data'].get('averageprice', order.price if order else 0)),
                                buy_sell=status['data'].get('transactiontype', order.buy_sell if order else 'BUY'),
                                created_at=order.created_at if order else IST.localize(datetime.now()),
                                updated_at=IST.localize(datetime.now())
                            )
                            db.session.merge(new_status)  
                            db.session.commit()
                            log_to_file(f"Updated order status for unique_order_id {unique_order_id} (order_id: {order_id}): {final_status}")
                            return final_status

                        elif isinstance(status, dict) and 'status' in status and not status['status']:
                            
                            log_to_file(f"API error for unique_order_id {unique_order_id}: {status.get('message', 'Unknown error')}")
                            return 'UNKNOWN'

                        elif isinstance(status, bool):
                            
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
                    else:  
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
                max_retry_attempt=5,  
                retry_strategy=0, retry_delay=10, retry_duration=15
            )

            def on_data(wsapp, message):
                try:
                    
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
                            log_to_file(f"Live price update for {stock.tradingsymbol}: {ltp}")
                            logger.debug(f"is market open: {is_market_open()}")
                            if is_market_open():
                                logger.info(f"Trading Status for {user} and its {user.trading_active}")
                                if user.trading_active and stock.trading_status:
                                    try:
                                        process_strategy(user, stock.tradingsymbol, ltp, smart_api)
                                    except Exception as e:
                                        logger.error(f"Error in process_strategy for {stock.tradingsymbol}: {str(e)}")
                                        log_to_file(f"WebSocket data error for {user_email}: {str(e)}")
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
                        log_to_file(f"WebSocket setup error for {user_email}: {str(e)}")
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
    time.sleep(2)  
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

import time
from datetime import datetime, timedelta
from threading import Lock, Thread
import json
import threading
import eventlet
from flask import current_app
from flask_mail import Message

# Global locks and caches
strategy_locks = {}
order_locks = {}
websocket_lock = Lock()
order_status_lock = Lock()
live_prices_lock = Lock()
websocket_clients = {}
websocket_threads = {}
order_status_dict = {}
session_cache = {}
live_prices = {}
last_processed = {}  # For debouncing

def log_to_file(message):
    with open('log.txt', 'a') as f:
        f.write(f"{datetime.now()} - Thread {threading.current_thread().name} - {message}\n")

def send_insufficient_funds_notification(user_email, user_name, symbol, order_id, quantity, price, message_text):
    """Sends an email notification when an order is rejected due to insufficient funds."""
    app = current_app._get_current_object()  # Get the Flask app context

    def send_email():
        with app.app_context():  
            try:
                rejection_time = IST.localize(datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
                subject = f"⚠️ Order Rejected Due to Insufficient Funds on {WEBSITE_NAME}"
                body = f"""
                Hello {user_name},  

                Your recent order for {symbol} was rejected because your wallet balance is insufficient. Please add funds to continue trading.  

                📋 Order Details:  
                - Symbol: {symbol}  
                - Order ID: {order_id}  
                - Quantity: {quantity}  
                - Price: {price}  
                - Reason: {message_text}  
                - Time: {rejection_time}  

                💡 Action Required:  
                - Add funds to your wallet via the {WEBSITE_NAME} dashboard.  
                - Contact support at **support@{WEBSITE_NAME.lower()}.in** if you need assistance.  

                Happy Trading,  
                The {WEBSITE_NAME} Team  
                """
                msg = Message(subject, recipients=[user_email], body=body)
                mail.send(msg)
                logger.info(f"📧 Insufficient funds notification sent to {user_email} for order {order_id}")
                log_entry = Log(user_email=user_email, action="Insufficient Funds Notification Sent", details=f"Order {order_id} rejected due to insufficient funds")
                db.session.add(log_entry)
                db.session.commit()
            except Exception as e:
                logger.error(f"❌ Failed to send insufficient funds email: {str(e)}")

    Thread(target=send_email).start()

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
            message_text = order_data.get('orderData', {}).get('text', order_data.get('error-message', ''))

            logger.info(f"Order Update - ID: {order_id}, Unique ID: {unique_order_id}, Symbol: {symbol}, Status: {order_status}, Filled: {filled_shares}")

            # Check for insufficient funds and send email notification
            if message_text.startswith("Your order has been rejected due to Insufficient Funds"):
                order_entry = (OrderStatus.query.filter_by(order_id=order_id).first() or 
                              OrderStatus.query.filter_by(unique_order_id=unique_order_id).first())
                if order_entry:
                    user = User.query.filter_by(email=order_entry.user_email).first()
                    if user:
                        send_insufficient_funds_notification(
                            user_email=user.email,
                            user_name=user.name if hasattr(user, 'name') else "User",  # Adjust based on your User model
                            symbol=symbol,
                            order_id=order_id,
                            quantity=order_entry.quantity,
                            price=order_entry.price,
                            message_text=message_text
                        )

            tracked_id = None
            if order_id == numeric_order_id_to_track or unique_order_id == order_id_to_track:
                tracked_id = order_id_to_track if unique_order_id == order_id_to_track else numeric_order_id_to_track

            if tracked_id:
                with order_status_lock:
                    order_status_dict[tracked_id] = {
                        'status': order_status,
                        'symbol': symbol,
                        'message': message_text,
                        'filled_shares': filled_shares,
                        'avg_price': avg_price
                    }
                logger.info(f"Tracked order {tracked_id} updated to status: {order_status}")

                order_entry = (OrderStatus.query.filter_by(order_id=order_id).first() or 
                              OrderStatus.query.filter_by(unique_order_id=unique_order_id).first())
                if order_entry:
                    order_entry.status = order_status
                    order_entry.message = order_status_dict[tracked_id]['message']
                    if filled_shares > 0:
                        order_entry.quantity = filled_shares
                    if avg_price > 0:
                        order_entry.price = avg_price
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
        with order_locks.setdefault(lock_key, Lock()):
            # Check for recent or pending orders
            recent_orders = OrderStatus.query.filter_by(
                user_email=user_email,
                symbol=symbol,
                buy_sell=buy_sell
            ).filter(
                OrderStatus.created_at > IST.localize(datetime.now()) - timedelta(seconds=10)
            ).all()
            if recent_orders:
                logger.info(f"Skipping {buy_sell} order for {symbol}: Recent orders exist: {[o.order_id for o in recent_orders]}")
                return 0, None, "recent_order_exists"

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
                logger.info(f"Skipping {buy_sell} order for {symbol}: Pending orders: {[o.order_id for o in pending_orders]}")
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
                        smart_api = get_angel_session(user)  # Assume this function exists
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

                ws_thread = Thread(target=client.connect)
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

                    try:
                        unique_order_id = OrderStatus.query.filter_by(order_id=numeric_order_id).first().unique_order_id
                        order_details = smart_api.individual_order_details(unique_order_id)
                        logger.debug(f"API response for order {unique_order_id}: {order_details}")
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
                    time.sleep(1)
                    attempt += 1

                logger.error(f"Order {order_id} for {symbol} did not complete after {max_attempts} attempts")
                api_log = ApiLog(user_email, symbol, order_id, "Place Order", "timeout", "Order status not updated in time")
                db.session.add(api_log)
                db.session.commit()

                order_entry = OrderStatus.query.filter_by(order_id=numeric_order_id).first()
                if order_entry:
                    try:
                        # Forcefully check OrderBook first on timeout
                        order_book = smart_api.orderBook()
                        logger.debug(f"OrderBook response on timeout for order {numeric_order_id}: {order_book}")
                        order_found = False
                        if order_book.get('status') == True and 'data' in order_book:
                            for order in order_book['data']:
                                if order['orderid'] == numeric_order_id:
                                    final_status = str(order['status']).lower()
                                    executed_qty = int(order['filledshares'] or qty)
                                    if final_status in ['complete', 'executed']:
                                        logger.info(f"OrderBook confirmed order {numeric_order_id} completed with {executed_qty} shares on timeout")
                                        order_entry.status = "complete"
                                        order_entry.message = "Order completed via OrderBook (timeout check)"
                                        order_entry.updated_at = IST.localize(datetime.now())
                                        db.session.commit()
                                        client.close_connection()
                                        return executed_qty, order_id, "completed"
                                    elif final_status in ['rejected', 'cancelled']:
                                        logger.warning(f"OrderBook confirmed order {numeric_order_id} failed: {final_status} on timeout")
                                        order_entry.status = final_status
                                        order_entry.message = order.get('text', 'Order status resolved via OrderBook')
                                        order_entry.updated_at = IST.localize(datetime.now())
                                        db.session.commit()
                                        client.close_connection()
                                        return 0, order_id, final_status
                                    order_found = True
                                    break

                        # If not found in OrderBook, fall back to individual_order_details
                        if not order_found:
                            order_details = smart_api.individual_order_details(order_id)  # Using unique_order_id
                            logger.debug(f"Final API response for order {order_id}: {order_details}")
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
                                    order_entry.status = final_status if final_status in ['rejected', 'cancelled'] else "timeout"
                                    order_entry.message = order_details.get('text', 'Order status not updated in time')
                                    order_entry.updated_at = IST.localize(datetime.now())
                                    db.session.commit()
                                    logger.info(f"Updated OrderStatus for {numeric_order_id} to {order_entry.status}")
                            elif isinstance(order_details, bool):
                                logger.warning(f"Final API returned boolean {order_details} for order {order_id}, marking as timeout")
                                order_entry.status = "timeout"
                                order_entry.message = "Order status not updated in time (API returned boolean)"
                                order_entry.updated_at = IST.localize(datetime.now())
                                db.session.commit()
                            else:
                                logger.error(f"Unexpected final API response type for order {order_id}: {type(order_details)}")
                                order_entry.status = "timeout"
                                order_entry.message = "Order status not updated in time (unexpected API response)"
                                order_entry.updated_at = IST.localize(datetime.now())
                                db.session.commit()
                    except Exception as e:
                        logger.error(f"Final check failed for {numeric_order_id}: {str(e)}", exc_info=True)
                        order_entry.status = "timeout"
                        order_entry.message = "Order status not updated in time"
                        order_entry.updated_at = IST.localize(datetime.now())
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
    log_to_file(f"Process strategy for {symbol} at {ltp}")
    
    with app.app_context():
        lock_key = f"{user.email}_{symbol}"
        with strategy_locks.setdefault(lock_key, Lock()):
            try:
                trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
                stock = Stock.query.filter_by(user_id=user.id, tradingsymbol=symbol).first()
                if not stock or not stock.trading_status:
                    log_to_file(f"Trading not enabled for {symbol}")
                    return
                
                wallet_value = stock.allotment_captial if stock else 0
                log_to_file(f"Wallet value for {symbol}: {wallet_value}")
                log_to_file(f"Trades for {symbol}: {len(trades)}, Trades: {[t.__dict__ for t in trades]}")

                # Check for recent or pending orders
                recent_orders = OrderStatus.query.filter_by(
                    user_email=user.email,
                    symbol=symbol,
                    buy_sell='BUY'
                ).filter(
                    OrderStatus.created_at > IST.localize(datetime.now()) - timedelta(seconds=10)
                ).all()
                if recent_orders:
                    log_to_file(f"Skipping {symbol}: Recent orders exist: {[o.order_id for o in recent_orders]}")
                    return

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

                strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)  # Assume this function exists
                log_to_file(f"base_price: {base_price}, wallet_value: {wallet_value}, strategy_data: {strategy_data}")
                log_to_file(f"Strategy data for {symbol}: {strategy_data}")

                def get_order_status(unique_order_id):
                    order = OrderStatus.query.filter_by(unique_order_id=unique_order_id, user_email=user.email).first()
                    if order and order.status not in ['pending', 'UNKNOWN', 'timeout']:
                        log_to_file(f"Order status from table for unique_order_id {unique_order_id} (order_id: {order.order_id}): {order.status}")
                        return order.status

                    try:
                        status = smart_api.individual_order_details(unique_order_id)
                        log_to_file(f"Order status from API for unique_order_id {unique_order_id}: {status}")

                        if isinstance(status, dict) and 'data' in status:
                            final_status = str(status['data'].get('orderstatus', status['data'].get('status', 'UNKNOWN'))).lower()
                            executed_qty = float(status['data'].get('filledshares', order.quantity if order else 0))
                            order_id = status['data'].get('orderid', order.order_id if order else None)

                            new_status = OrderStatus(
                                user_email=user.email,
                                order_id=order_id,
                                unique_order_id=unique_order_id,
                                symbol=symbol,
                                status=final_status,
                                message=status['data'].get('text', ''),
                                quantity=executed_qty,
                                price=float(status['data'].get('averageprice', order.price if order else 0)),
                                buy_sell=status['data'].get('transactiontype', order.buy_sell if order else 'BUY'),
                                created_at=order.created_at if order else IST.localize(datetime.now()),
                                updated_at=IST.localize(datetime.now())
                            )
                            db.session.merge(new_status)
                            db.session.commit()
                            log_to_file(f"Updated order status for unique_order_id {unique_order_id} (order_id: {order_id}): {final_status}")
                            return final_status

                        elif isinstance(status, dict) and 'status' in status and not status['status']:
                            log_to_file(f"API error for unique_order_id {unique_order_id}: {status.get('message', 'Unknown error')}")
                            return 'UNKNOWN'

                        elif isinstance(status, bool):
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
                    else:
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

            smart_api = get_angel_session(user)  # Assume this function exists
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
                max_retry_attempt=5,
                retry_strategy=0, retry_delay=10, retry_duration=15
            )

            def on_data(wsapp, message):
                try:
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
                            lock_key = f"{user_email}_{stock.tradingsymbol}"
                            current_time = time.time()
                            if lock_key in last_processed and (current_time - last_processed[lock_key]) < 5:
                                logger.info(f"Debouncing {stock.tradingsymbol} for {user_email}")
                                return

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
                            log_to_file(f"Live price update for {stock.tradingsymbol}: {ltp}")
                            logger.debug(f"is market open: {is_market_open()}")  # Assume this function exists
                            if is_market_open():
                                logger.info(f"Trading Status for {user} and its {user.trading_active}")
                                if user.trading_active and stock.trading_status:
                                    try:
                                        process_strategy(user, stock.tradingsymbol, ltp, smart_api)
                                        last_processed[lock_key] = current_time
                                    except Exception as e:
                                        logger.error(f"Error in process_strategy for {stock.tradingsymbol}: {str(e)}")
                                        log_to_file(f"WebSocket data error for {user_email}: {str(e)}")
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
                        log_to_file(f"WebSocket setup error for {user_email}: {str(e)}")
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
    time.sleep(2)
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


@app.before_request
def log_request_data():
    if request.path == "/api/toggle-trading-status":
        logging.info("\n🚀 Received /user/generate-2fa API request")
        logging.info(f"📝 Request Method: {request.method}")
        logging.info(f"📩 Request Headers: {dict(request.headers)}")
        logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")


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

            
            selected_default = next(p for p in DEFAULT_PHASES if p["phase"] == selected_phase)
            step_size = new_down_increment + selected_default["down_increment"]

            
            for phase_config in existing_configs:
                if phase_config.phase < selected_phase:
                    
                    phase_config.down_increment = next(p["down_increment"] for p in DEFAULT_PHASES if p["phase"] == phase_config.phase)
                elif phase_config.phase == selected_phase:
                    
                    phase_config.down_increment = new_down_increment
                else:
                    
                    phase_offset = phase_config.phase + selected_phase
                    default_value = next(p["down_increment"] for p in DEFAULT_PHASES if p["phase"] == phase_config.phase)
                    phase_config.down_increment = default_value + step_size
                logger.info(f"Updated DOWN increment for {tradingsymbol}, Phase {phase_config.phase} to {phase_config.down_increment}")


            
            
            restart_websocket(user)

            
            
            

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


@app.route('/api/update-down', methods=['POST'])
@jwt_required()
def update_down_increment():
    try:
        user_email = get_jwt_identity()
        data = request.get_json()
        stock_symbol = data['stock_symbol']
        selected_phase = int(data['phase'])  
        new_down_increment = float(data['down_increment'])

        
        if selected_phase not in [p["phase"] for p in DEFAULT_PHASES]:
            return jsonify({'status': 'error', 'message': 'Invalid phase number'}), 400

        
        selected_default = next(p for p in DEFAULT_PHASES if p["phase"] == selected_phase)
        original_down_increment = selected_default["down_increment"]
        step_size = new_down_increment - original_down_increment  

        existing_configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=stock_symbol).all()
        
        
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

        
        for phase_config in existing_configs:
            if phase_config.phase >= selected_phase:
                
                default_phase = next(p for p in DEFAULT_PHASES if p["phase"] == phase_config.phase)
                phase_offset = phase_config.phase - selected_phase
                new_value = new_down_increment + (step_size * phase_offset)
                phase_config.down_increment = new_value
                logger.info(f"Updated DOWN increment for {stock_symbol}, Phase {phase_config.phase} to {new_value}")

        db.session.commit()
        time.sleep(7)  
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
        
        
        all_stocks = Stock.query.filter_by(user_id=current_user.id).all()
        
        
        logger.info(f"User ID: {current_user.id}")
        logger.info(f"Total stocks for {current_user.email}: {len(all_stocks)}")
        
        
        stock_data = []
        for stock in all_stocks:
            
            open_trades = Trade.query.filter_by(
                stock_symbol=stock.tradingsymbol,
                user_email=current_user.email,
                status='OPEN'
            ).order_by(Trade.sr_no.desc()).all()
            
            if not open_trades:
                
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
            
            
            total_open_quantity = sum(trade.total_quantity for trade in open_trades)
            
            current_sr_no = open_trades[0].sr_no
            
            phase_config = PhaseConfig.query.filter_by(
                user_email=current_user.email,
                stock_symbol=stock.tradingsymbol
            ).filter(
                PhaseConfig.start_sr_no <= current_sr_no,
                PhaseConfig.end_sr_no >= current_sr_no
            ).first()
            phase = phase_config.phase if phase_config else "Unknown"
            
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

        
        response_data = {
            "status": True,
            "message": "SUCCESS",
            "errorcode": "",
            "data": {
                "orderid": order_id,
                "uniqueorderid": order_response.get('data', {}).get('uniqueorderid', 'N/A')  
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
            
            logger.info(f"Starting WebSocket for user {user.email}")
                
            eventlet.spawn(start_websocket_stream, user)
            
            

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
        

if __name__ == "__main__":
    eventlet.monkey_patch()
    with app.app_context():
        db.create_all()
    start_all_websocket_streams()
    eventlet.spawn(monitor_websocket_streams)
    logger.info("Starting Flask app with Eventlet server on port 8000")
    eventlet.wsgi.server(eventlet.listen(('', 8000)), app)
