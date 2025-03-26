
from SmartApi.smartConnect import SmartConnect
import pyotp
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, decode_token
from flask_socketio import SocketIO, emit
import logging
from datetime import datetime, timedelta
from collections import defaultdict
import time
from SmartApi import smartExceptions as ex
import threading
import random


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory caches
session_cache = defaultdict(dict)
holdings_cache = defaultdict(dict)

def get_angel_session(user):
    """Get or generate a valid Angel One session for the user."""
    user_email = user.email
    current_time = datetime.now()

    if (user_email in session_cache and 
        'smart_api' in session_cache[user_email] and 
        session_cache[user_email]['expires_at'] > current_time):
        logger.info(f"Reusing existing session for {user_email}")
        return session_cache[user_email]['smart_api']

    try:
        if not all([user.smartapi_key, user.smartapi_username, user.smartapi_password, user.smartapi_totp_token]):
            raise Exception("Angel One credentials not set for this user")

        smart_api = SmartConnect(user.smartapi_key)
        totp = pyotp.TOTP(user.smartapi_totp_token).now()
        data = smart_api.generateSession(user.smartapi_username, user.smartapi_password, totp)

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
        logger.error(f"❌ Angel Session Error for {user_email}: {str(e)}")
        raise e

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

def get_holdings(user, retries=3, backoff=60):
    """Get or fetch holdings data with caching and rate limit retries."""
    user_email = user.email
    current_time = datetime.now()

    if (user_email in holdings_cache and 
        'data' in holdings_cache[user_email] and 
        holdings_cache[user_email]['expires_at'] > current_time):
        logger.info(f"Reusing cached holdings for {user_email}")
        return holdings_cache[user_email]['data']

    for attempt in range(retries):
        try:
            smart_api = get_angel_session(user)
            holding = smart_api.allholding()
            logger.info(f"Api allholding: {holding}")

            if holding['status'] and 'data' in holding and 'holdings' in holding['data']:
                expires_at = current_time + timedelta(minutes=5)
                holdings_cache[user_email] = {
                    'data': holding,
                    'expires_at': expires_at
                }
                return holding
            else:
                logger.warning(f"No valid holdings data for {user_email}")
                return {'status': False, 'message': 'No holdings data', 'data': {'holdings': [], 'today_profit_and_loss': 0}}

        except ex.DataException as e:
            if "exceeding access rate" in str(e):
                wait_time = backoff * (2 ** attempt)
                logger.warning(f"Rate limit hit for {user_email}, retrying in {wait_time}s (attempt {attempt + 1}/{retries})")
                time.sleep(wait_time)
            else:
                logger.error(f"❌ Holdings Fetch Error for {user_email}: {str(e)}")
                raise e
        except Exception as e:
            logger.error(f"❌ Unexpected Error for {user_email}: {str(e)}")
            raise e
    raise Exception("Max retries exceeded due to rate limiting")

def simulate_ltp_updates(user_email, holdings):
    """Simulate real-time LTP updates for holdings."""
    while True:
        try:
            logging.info(f"holdings simulate for {holdings}")
            updated_holdings = []
            today_pnl = 0
            for item in holdings:
                ltp_change = item['close'] * random.uniform(-0.05, 0.05)
                new_ltp = round(item['ltp'] + ltp_change, 2)
                today_pnl_per_stock = (new_ltp - item['close']) * item['quantity']
                updated_item = item.copy()
                updated_item['ltp'] = new_ltp
                updated_item['today_pnl'] = round(today_pnl_per_stock, 2)
                updated_holdings.append(updated_item)
                today_pnl += today_pnl_per_stock

            data = {
                'holdings': updated_holdings,
                'today_profit_and_loss': round(today_pnl, 2)
            }
            # socketio.emit('holdings_update', data, room=user_email)
            # logging.info(f"Simulated LTP Update for {user_email}: {data}")

            # logger.info(f"Emitted holdings update for {user_email}")
            time.sleep(3)  # Update every 5 seconds
        except Exception as e:
            logger.error(f"❌ Simulate LTP Error for {user_email}: {str(e)}")
            break

# WebSocket handlers
@socketio.on('connect')
def handle_connect(auth):
    """Handle WebSocket connection with JWT authentication."""
    try:
        if not auth or 'token' not in auth:
            raise Exception("Missing JWT token in auth")

        decoded_token = decode_token(auth['token'])
        user_email = decoded_token['sub']  # 'sub' contains the user identity (email)
        logger.info(f"WebSocket connected for {user_email}")
        emit('connection_response', {'message': f'Connected as {user_email}'}, room=user_email)
    except Exception as e:
        logger.error(f"❌ WebSocket Connect Error: {str(e)}")
        emit('error', {'message': f'Authentication failed: {str(e)}'})
        raise ConnectionRefusedError("Authentication failed")

@socketio.on('subscribe_holdings')
def handle_subscribe_holdings(auth):
    """Handle WebSocket subscription for holdings."""
    try:
        if not auth or 'token' not in auth:
            raise Exception("Missing JWT token in auth")

        decoded_token = decode_token(auth['token'])
        user_email = decoded_token['sub']
        current_user = User.query.filter_by(email=user_email).first()
        if not current_user:
            emit('error', {'message': 'Unauthorized access'}, room=user_email)
            return

        holding = get_holdings(current_user)
        if holding['status'] and 'data' in holding and 'holdings' in holding['data']:
            holdings = holding['data']['holdings']
            today_pnl = 0
            for item in holdings:
                today_pnl_per_stock = (item['ltp'] - item['close']) * item['quantity']
                item['today_pnl'] = round(today_pnl_per_stock, 2)
                today_pnl += today_pnl_per_stock
            holding['data']['today_profit_and_loss'] = round(today_pnl, 2)
            emit('holdings_update', holding['data'], room=user_email)
            logger.info(f"Initial Holdings Sent to {user_email}")

            threading.Thread(target=simulate_ltp_updates, args=(user_email, holdings), daemon=True).start()
        else:
            emit('holdings_update', {'holdings': [], 'today_profit_and_loss': 0}, room=user_email)
            logger.warning(f"No holdings data for {user_email}")

    except Exception as e:
        logger.error(f"❌ Subscribe Holdings Error for : {str(e)}")
        # emit('error', {'message': f"Failed to fetch holdings: {str(e)}"}, room=user_email)

# REST Endpoints (unchanged except for /user/angel/all-holding)
@app.before_request
def log_request_data():
    if request.path in ["/user/generate-angel-session", "/user/angel/rms-limit", "/user/angel/order-book", "/user/angel/trade-book", "/user/angel/all-holding"]:
        logger.info(f"\n🚀 Received {request.path} API request")
        logger.info(f"📝 Request Method: {request.method}")
        logger.info(f"📩 Request Headers: {dict(request.headers)}")
        logger.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")

@app.route("/user/generate-angel-session", methods=["POST"])
@jwt_required()
def generate_angel_session():
    try:
        user_email = get_jwt_identity()
        current_user = User.query.filter_by(email=user_email).first()
        logger.info(f"🔑 JWT Identity: {user_email}")

        if not current_user:
            return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

        smart_api = get_angel_session(current_user)
        response_data = {
            "message": "Angel One session generated or reused successfully",
            "status": "200"
        }
        logger.info(f"Session response: {response_data}")
        return jsonify({"data": encrypt_response(response_data)}), 200

    except Exception as e:
        logger.error(f"❌ Generate Angel Session Error: {str(e)}")
        return jsonify({"data": encrypt_response({"message": f"Failed to generate Angel One session: {str(e)}", "status": "500"})}), 500

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
        if "Invalid Token" in str(e):
            smart_api = refresh_angel_session(current_user)
            rms = smart_api.rmsLimit()
            logger.info(f"RMS Limit Response after refresh: {rms}")
            return jsonify({"data": encrypt_response({"message": "RMS limit fetched successfully", "rms": rms, "status": "200"})}), 200
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
        logger.error(f"❌ Order Book Error: {str(e)}")
        if "Invalid Token" in str(e):
            smart_api = refresh_angel_session(current_user)
            order_book = smart_api.orderBook()
            logger.info(f"Order Book Response after refresh: {order_book}")
            return jsonify({"data": encrypt_response({"message": "Order book fetched successfully", "order_book": order_book, "status": "200"})}), 200
        return jsonify({"data": encrypt_response({"message": f"Failed to fetch order book: {str(e)}", "status": "500"})}), 500

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
        if "Invalid Token" in str(e):
            smart_api = refresh_angel_session(current_user)
            trade_book = smart_api.tradeBook()
            logger.info(f"Trade Book Response after refresh: {trade_book}")
            return jsonify({"data": encrypt_response({"message": "Trade book fetched successfully", "trade_book": trade_book, "status": "200"})}), 200
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

        holding = get_holdings(current_user)
        logger.info(f"Holding Response: {holding}")

        if holding['status'] and 'data' in holding and 'holdings' in holding['data']:
            holdings = holding['data']['holdings']
            today_pnl = 0
            for item in holdings:
                today_pnl_per_stock = (item['ltp'] - item['close']) * item['quantity']
                item['today_pnl'] = round(today_pnl_per_stock, 2)
                today_pnl += today_pnl_per_stock

            holding['data']['today_profit_and_loss'] = round(today_pnl, 2)
            logger.info(f"Calculated Today's P&L: {holding['data']['today_profit_and_loss']}")
        else:
            logger.warning("No holdings data available to calculate today's P&L")
            holding['data']['today_profit_and_loss'] = 0

        logger.info("Fetched All Holdings successfully")
        return jsonify({"data": encrypt_response({
            "message": "All holdings fetched successfully",
            "all_holding": holding,
            "status": "200"
        })}), 200

    except Exception as e:
        logger.error(f"❌ All Holding Error: {str(e)}")
        if "Invalid Token" in str(e):
            smart_api = refresh_angel_session(current_user)
            holding = smart_api.allholding()
            logger.info(f"Holding Response after refresh: {holding}")
            if holding['status'] and 'data' in holding and 'holdings' in holding['data']:
                holdings = holding['data']['holdings']
                today_pnl = 0
                for item in holdings:
                    today_pnl_per_stock = (item['ltp'] - item['close']) * item['quantity']
                    item['today_pnl'] = round(today_pnl_per_stock, 2)
                    today_pnl += today_pnl_per_stock
                holding['data']['today_profit_and_loss'] = round(today_pnl, 2)
            else:
                holding['data']['today_profit_and_loss'] = 0
            return jsonify({"data": encrypt_response({
                "message": "All holdings fetched successfully",
                "all_holding": holding,
                "status": "200"
            })}), 200
        return jsonify({"data": encrypt_response({"message": f"Failed to fetch all holdings: {str(e)}", "status": "500"})}), 500
