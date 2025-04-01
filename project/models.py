from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import os
import pytz

# Initialize Flask extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
cipher = Fernet(os.getenv("AES_SECRET_KEY"))

# Define IST timezone
IST = pytz.timezone("Asia/Kolkata")

# Helper function to get IST-localized current time
def now_ist():
    return IST.localize(datetime.now())

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)     
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    city = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # superadmin, manager, user
    is_active = db.Column(db.String(10), default="False")
    totp_secret = db.Column(db.String(32), nullable=True)
    sessions = db.relationship('AngelSession', backref='user', lazy=True)
    smartapi_key = db.Column(db.String(50), nullable=True)
    smartapi_username = db.Column(db.String(50), nullable=True)
    smartapi_password = db.Column(db.String(128), nullable=True)
    smartapi_totp_token = db.Column(db.String(50), nullable=True)
    trading_active = db.Column(db.Boolean, default=False, nullable=False, server_default='false')
    angel_linked = db.Column(db.Boolean, default=False, nullable=False)
    stocks = db.relationship('Stock', backref='user', lazy=True)
    
    # Cash tracking columns
    available_balance = db.Column(db.Float, default=0.0, nullable=False, server_default='0.0')
    remaining_balance = db.Column(db.Float, default=0.0, nullable=False, server_default='0.0')
    used_balance = db.Column(db.Float, default=0.0, nullable=False, server_default='0.0')

    def __init__(self, name, email, phone, password, address, pincode, city, role, smartapi_key=None, smartapi_username=None, smartapi_password=None, smartapi_totp_token=None, totp_secret=None):
        self.name = name
        self.email = email          
        self.phone = phone
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.address = address
        self.pincode = pincode
        self.city = city 
        self.role = role
        self.smartapi_key = smartapi_key
        self.smartapi_username = smartapi_username
        self.smartapi_password = smartapi_password
        self.smartapi_totp_token = smartapi_totp_token
        self.totp_secret = totp_secret

    def encrypt_data(self, data):
        return cipher.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data):
        return cipher.decrypt(encrypted_data.encode()).decode()

class AngelSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    auth_token = db.Column(db.String(3000), nullable=False)
    refresh_token = db.Column(db.String(3000), nullable=False)
    feed_token = db.Column(db.String(3000), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=now_ist)  # Use IST
    order_book = db.Column(db.JSON)
    holdings = db.Column(db.JSON)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "auth_token": self.auth_token,
            "refresh_token": self.refresh_token,
            "feed_token": self.feed_token,
            "expires_at": self.expires_at.isoformat(),
            "created_at": self.created_at.isoformat(),
            "order_book": self.order_book,
            "holdings": self.holdings
        }

class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exchange = db.Column(db.String(10), nullable=False)
    tradingsymbol = db.Column(db.String(50), nullable=False)
    symboltoken = db.Column(db.String(20), nullable=False)
    added_at = db.Column(db.DateTime, default=now_ist)  # Use IST
    trading_status = db.Column(db.Boolean, nullable=False, default=False)
    live_price_status = db.Column(db.Boolean, nullable=False, default=False)
    allotment_captial = db.Column(db.Integer, nullable=False, default=0)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'tradingsymbol', name='unique_user_stock'),
    )

    def __init__(self, user_id, exchange, tradingsymbol, symboltoken, live_price_status=False):
        self.user_id = user_id
        self.exchange = exchange
        self.tradingsymbol = tradingsymbol
        self.symboltoken = symboltoken  # Fixed typo: removed comma
        self.live_price_status = live_price_status

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "exchange": self.exchange,
            "tradingsymbol": self.tradingsymbol,
            "symboltoken": self.symboltoken,
            "added_at": self.added_at.strftime("%Y-%m-%d %H:%M:%S")
        }

class Trade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stock_symbol = db.Column(db.String(50), nullable=False)
    sr_no = db.Column(db.Integer, nullable=False)
    entry_price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='OPEN')
    user_email = db.Column(db.String(120), nullable=False)
    base_price = db.Column(db.Float, nullable=False)
    last_updated = db.Column(db.DateTime, default=now_ist)  # Use IST
    total_quantity = db.Column(db.Integer, default=0)
    total_sold_quantity = db.Column(db.Integer, default=0)
    cycle_count = db.Column(db.Integer, default=0)
    description = db.Column(db.String(100), default='')
    order_id = db.Column(db.String(50))

    def __repr__(self):
        return (f"<Trade(id={self.id}, stock_symbol={self.stock_symbol}, sr_no={self.sr_no}, "
                f"entry_price={self.entry_price}, quantity={self.quantity}, status={self.status}, "
                f"user_email={self.user_email}, order_id={self.order_id})>")

class TradeCycle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stock_symbol = db.Column(db.String(50), nullable=False)
    user_email = db.Column(db.String(120), nullable=False)
    cycle_start = db.Column(db.DateTime, nullable=False)
    cycle_end = db.Column(db.DateTime, nullable=True)
    total_bought = db.Column(db.Integer, default=0)
    total_sold = db.Column(db.Integer, default=0)
    profit = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default='ACTIVE')

    __table_args__ = (
        db.UniqueConstraint('stock_symbol', 'user_email', 'cycle_start', name='unique_cycle'),
    )

class PhaseConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    stock_symbol = db.Column(db.String(50), nullable=False)
    phase = db.Column(db.Integer, nullable=False)
    start_sr_no = db.Column(db.Integer, nullable=False)
    end_sr_no = db.Column(db.Integer, nullable=False)
    down_increment = db.Column(db.Float, nullable=False)
    __table_args__ = (db.UniqueConstraint('user_email', 'stock_symbol', 'phase', name='unique_phase_config'),)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=now_ist)  # Use IST
    details = db.Column(db.Text, nullable=True)

    def __init__(self, user_email, action, details):
        self.user_email = user_email
        self.action = action
        self.details = details

class ApiLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=True)
    symbol = db.Column(db.String(50), nullable=True)
    order_id = db.Column(db.String(50), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=now_ist)  # Use IST

    def __init__(self, user_email, symbol, order_id, action, status, message=None):
        self.user_email = user_email if user_email else "unknown"
        self.symbol = symbol
        self.order_id = order_id
        self.action = action
        self.status = status
        self.message = message
        
class OrderStatus(db.Model):
    __tablename__ = 'order_status'

    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    order_id = db.Column(db.String(50), nullable=False, unique=True)
    unique_order_id = db.Column(db.String(50), nullable=True, unique=True)
    symbol = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=True)
    quantity = db.Column(db.Float, nullable=False)
    price = db.Column(db.Float, nullable=False)
    buy_sell = db.Column(db.String(4), nullable=False)
    created_at = db.Column(db.DateTime, default=now_ist)
    updated_at = db.Column(db.DateTime, default=now_ist)

    def __repr__(self):
        return f"<OrderStatus {self.order_id} - {self.symbol} - {self.status}>"
'''
class OrderStatus(db.Model):
    __tablename__ = 'order_status'

    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    order_id = db.Column(db.String(50), nullable=False)
    unique_order_id = db.Column(db.String(50), nullable=True)
    symbol = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=True)
    quantity = db.Column(db.Float, nullable=False)
    price = db.Column(db.Float, nullable=False)
    buy_sell = db.Column(db.String(4), nullable=False)
    created_at = db.Column(db.DateTime, default=now_ist)  # Use IST
    updated_at = db.Column(db.DateTime, default=now_ist)  # Use IST

    def __repr__(self):
        return f"<OrderStatus {self.order_id} - {self.symbol} - {self.status}>"
'''
    
'''
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import os
import pytz

db = SQLAlchemy()
bcrypt = Bcrypt()
cipher = Fernet(os.getenv("AES_SECRET_KEY"))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)     
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    city = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # superadmin, manager, user
    is_active = db.Column(db.String(10), default="False")
    totp_secret = db.Column(db.String(32), nullable=True)
    sessions = db.relationship('AngelSession', backref='user', lazy=True)
    # angel_sessions = db.relationship('AngelSession', backref='user', lazy=True)
    
    smartapi_key = db.Column(db.String(50), nullable=True)
    smartapi_username = db.Column(db.String(50), nullable=True)
    smartapi_password = db.Column(db.String(128), nullable=True)
    smartapi_totp_token = db.Column(db.String(50), nullable=True)
    trading_active = db.Column(db.Boolean, default=False, nullable=False,server_default='false')  # New column
    angel_linked = db.Column(db.Boolean, default=False, nullable=False,)    # New column
    stocks = db.relationship('Stock', backref='user', lazy=True)
    
    # New columns for cash tracking
    available_balance = db.Column(db.Float, default=0.0, nullable=False, server_default='0.0')
    remaining_balance = db.Column(db.Float, default=0.0, nullable=False, server_default='0.0')
    used_balance = db.Column(db.Float, default=0.0, nullable=False, server_default='0.0')

    def __init__(self, name, email, phone, password, address, pincode, city, role, smartapi_key=None, smartapi_username=None, smartapi_password=None, smartapi_totp_token=None, totp_secret=None):
        self.name = name
        self.email = email          
        self.phone = phone
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.address = address
        self.pincode = pincode
        self.city = city 
        self.role = role
        self.smartapi_key = smartapi_key
        self.smartapi_username = smartapi_username
        self.smartapi_password = smartapi_password
        self.smartapi_totp_token = smartapi_totp_token
        self.totp_secret = totp_secret

    def encrypt_data(self, data):
        return cipher.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data):
        return cipher.decrypt(encrypted_data.encode()).decode()
    
class AngelSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    auth_token = db.Column(db.String(3000), nullable=False)
    refresh_token = db.Column(db.String(3000), nullable=False)
    feed_token = db.Column(db.String(3000), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(IST))
    order_book = db.Column(db.JSON)  # Cached order book data
    holdings = db.Column(db.JSON)    # Cached holdings data

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "auth_token": self.auth_token,
            "refresh_token": self.refresh_token,
            "feed_token": self.feed_token,
            "expires_at": self.expires_at.isoformat(),
            "created_at": self.created_at.isoformat(),
            "order_book": self.order_book,
            "holdings": self.holdings
        }

IST = pytz.timezone("Asia/Kolkata") 

class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key to User
    exchange = db.Column(db.String(10), nullable=False)  # e.g., "NSE", "BSE"
    tradingsymbol = db.Column(db.String(50), nullable=False)  # e.g., "IFCI", "SBIN-EQ"
    symboltoken = db.Column(db.String(20), nullable=False)  # e.g., "1512", "3045"
    added_at = db.Column(db.DateTime, default=lambda: datetime.now(IST))  # Timestamp in IST
    trading_status = db.Column(db.Boolean, nullable=False, default=False)
    live_price_status = db.Column(db.Boolean, nullable=False, default=False)
    allotment_captial = db.Column(db.Integer, nullable=False, default=0)

    # Unique constraint on user_id and tradingsymbol
    __table_args__ = (
        db.UniqueConstraint('user_id', 'tradingsymbol', name='unique_user_stock'),
    )

    def __init__(self, user_id, exchange, tradingsymbol, symboltoken, live_price_status=False):
        self.user_id = user_id
        self.exchange = exchange
        self.tradingsymbol = tradingsymbol
        self.symboltoken = symboltoken,
        self.live_price_status = live_price_status

    def to_dict(self):
        """Convert Stock object to a dictionary for easy JSON serialization."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "exchange": self.exchange,
            "tradingsymbol": self.tradingsymbol,
            "symboltoken": self.symboltoken,
            "added_at": self.added_at.strftime("%Y-%m-%d %H:%M:%S")
        }
        

class Trade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stock_symbol = db.Column(db.String(50), nullable=False)
    sr_no = db.Column(db.Integer, nullable=False)
    entry_price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='OPEN')  # OPEN, PARTIAL, CLOSED
    user_email = db.Column(db.String(120), nullable=False)
    base_price = db.Column(db.Float, nullable=False)  # Dynamic base price
    last_updated = db.Column(db.DateTime, default=IST.localize(datetime.now()))
    total_quantity = db.Column(db.Integer, default=0)
    total_sold_quantity = db.Column(db.Integer, default=0)
    cycle_count = db.Column(db.Integer, default=0)
    description = db.Column(db.String(100), default='')
    order_id = db.Column(db.String(50))  # New column to link to OrderStatus.order_id

    def __repr__(self):
        return (f"<Trade(id={self.id}, stock_symbol={self.stock_symbol}, sr_no={self.sr_no}, "
                f"entry_price={self.entry_price}, quantity={self.quantity}, status={self.status}, "
                f"user_email={self.user_email}, order_id={self.order_id})>")


class TradeCycle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stock_symbol = db.Column(db.String(50), nullable=False)
    user_email = db.Column(db.String(120), nullable=False)
    cycle_start = db.Column(db.DateTime, nullable=False)
    cycle_end = db.Column(db.DateTime, nullable=True)
    total_bought = db.Column(db.Integer, default=0)
    total_sold = db.Column(db.Integer, default=0)
    profit = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default='ACTIVE')  # ACTIVE, COMPLETED

    __table_args__ = (
        db.UniqueConstraint('stock_symbol', 'user_email', 'cycle_start', name='unique_cycle'),
    )

class PhaseConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    stock_symbol = db.Column(db.String(50), nullable=False)
    phase = db.Column(db.Integer, nullable=False)  # 1, 2, 3, 4, 5
    start_sr_no = db.Column(db.Integer, nullable=False)
    end_sr_no = db.Column(db.Integer, nullable=False)
    down_increment = db.Column(db.Float, nullable=False)  # e.g., 0.25, 0.50
    __table_args__ = (db.UniqueConstraint('user_email', 'stock_symbol', 'phase', name='unique_phase_config'),)
    
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(IST))  # ✅ Store in IST
    details = db.Column(db.Text, nullable=True)

    def __init__(self, user_email, action, details):
        self.user_email = user_email
        self.action = action
        self.details = details
        

class ApiLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=True)  # Changed to nullable=True
    symbol = db.Column(db.String(50), nullable=True)
    order_id = db.Column(db.String(50), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(IST))

    def __init__(self, user_email, symbol, order_id, action, status, message=None):
        self.user_email = user_email if user_email else "unknown"  # Fallback to "unknown" if None
        self.symbol = symbol
        self.order_id = order_id
        self.action = action
        self.status = status
        self.message = message



class OrderStatus(db.Model):
    __tablename__ = 'order_status'

    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)  # Links to the user
    order_id = db.Column(db.String(50), nullable=False)     # Numeric order ID (e.g., 250324000846003)
    unique_order_id = db.Column(db.String(50), nullable=True)  # Unique order ID (e.g., 616ed3ad-0cc7-4bdf-b8f2-003259abb469)
    symbol = db.Column(db.String(50), nullable=False)       # Trading symbol (e.g., YESBANK-EQ)
    status = db.Column(db.String(20), nullable=False)       # Status (e.g., rejected, completed)
    message = db.Column(db.Text, nullable=True)             # Detailed message (e.g., Insufficient Funds reason)
    quantity = db.Column(db.Float, nullable=False)          # Ordered quantity
    price = db.Column(db.Float, nullable=False)             # Price at order placement
    buy_sell = db.Column(db.String(4), nullable=False)      # BUY or SELL
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(IST))  # Timestamp of record creation
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(IST))  # Last update timestamp

    def __repr__(self):
        return f"<OrderStatus {self.order_id} - {self.symbol} - {self.status}>"

# class StrategyPhase(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
#     serial_no = db.Column(db.Integer, nullable=False)
#     entry_price = db.Column(db.Float, nullable=False)
#     drop_percentage = db.Column(db.Float, nullable=False)
#     quantity = db.Column(db.Integer, nullable=False)
#     first_target = db.Column(db.Float, nullable=True)
#     first_exit_qty = db.Column(db.Integer, nullable=True)
#     second_target = db.Column(db.Float, nullable=True)
#     second_exit_qty = db.Column(db.Integer, nullable=True)
#     final_target = db.Column(db.Float, nullable=False)
#     last_updated = db.Column(db.DateTime, default=lambda: datetime.now(IST))

#     def to_dict(self):
#         return {
#             "id": self.id,
#             "user_id": self.user_id,
#             "stock_id": self.stock_id,
#             "serial_no": self.serial_no,
#             "entry_price": self.entry_price,
#             "drop_percentage": self.drop_percentage,
#             "quantity": self.quantity,
#             "first_target": self.first_target,
#             "first_exit_qty": self.first_exit_qty,
#             "second_target": self.second_target,
#             "second_exit_qty": self.second_exit_qty,
#             "final_target": self.final_target,
#             "last_updated": self.last_updated.isoformat()
#         }

# class Position(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
#     phase_id = db.Column(db.Integer, db.ForeignKey('strategy_phase.id'), nullable=False)
#     quantity = db.Column(db.Integer, nullable=False)
#     entry_price = db.Column(db.Float, nullable=False)
#     created_at = db.Column(db.DateTime, default=lambda: datetime.now(IST))

# class Consent(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
#     action = db.Column(db.String(10), nullable=False)
#     quantity = db.Column(db.Integer, nullable=False)
#     price = db.Column(db.Float, nullable=False)
#     status = db.Column(db.String(20), default="pending")
#     created_at = db.Column(db.DateTime, default=lambda: datetime.now(IST))
#     responded_at = db.Column(db.DateTime)

# class Strategy(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     sr_no = db.Column(db.Integer, nullable=False, unique=True)
#     entry_price = db.Column(db.Float, nullable=False)
#     retracement_percent = db.Column(db.Float, nullable=False)
#     down_percent = db.Column(db.Float, nullable=False)
#     quantity = db.Column(db.Integer, nullable=False)
#     first_target = db.Column(db.Float, nullable=True)
#     first_exit_quantity = db.Column(db.Integer, nullable=True)
#     second_target = db.Column(db.Float, nullable=True)
#     second_exit_quantity = db.Column(db.Integer, nullable=True)
#     final_target = db.Column(db.Float, nullable=False)
#     final_target_percent = db.Column(db.Float, nullable=False)

#     def __init__(self, sr_no, entry_price, retracement_percent, down_percent, quantity, first_target=None, first_exit_quantity=None, second_target=None, second_exit_quantity=None, final_target=None, final_target_percent=None):
#         self.sr_no = sr_no
#         self.entry_price = entry_price
#         self.retracement_percent = retracement_percent
#         self.down_percent = down_percent
#         self.quantity = quantity
#         self.first_target = first_target
#         self.first_exit_quantity = first_exit_quantity
#         self.second_target = second_target
#         self.second_exit_quantity = second_exit_quantity
#         self.final_target = final_target
#         self.final_target_percent = final_target_percent

# class Position(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
#     current_sr_no = db.Column(db.Integer, nullable=False)
#     entry_price = db.Column(db.Float, nullable=False)
#     total_quantity = db.Column(db.Integer, nullable=False)
#     pending_quantity = db.Column(db.Integer, nullable=False, default=0)
#     last_updated = db.Column(db.DateTime, default=lambda: datetime.now(IST))

#     def __init__(self, user_id, stock_id, current_sr_no, entry_price, total_quantity, pending_quantity=0):
#         self.user_id = user_id
#         self.stock_id = stock_id
#         self.current_sr_no = current_sr_no
#         self.entry_price = entry_price
#         self.total_quantity = total_quantity
#         self.pending_quantity = pending_quantity

# class Order(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
#     order_type = db.Column(db.String(10), nullable=False)  # 'buy' or 'sell'
#     quantity = db.Column(db.Integer, nullable=False)
#     price = db.Column(db.Float, nullable=False)
#     status = db.Column(db.String(20), nullable=False, default='pending')  # 'pending', 'executed', 'partial'
#     timestamp = db.Column(db.DateTime, default=lambda: datetime.now(IST))

#     def __init__(self, user_id, stock_id, order_type, quantity, price):
#         self.user_id = user_id
#         self.stock_id = stock_id
#         self.order_type = order_type
#         self.quantity = quantity
#         self.price = price

'''