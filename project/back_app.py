
# from SmartApi.smartConnect import SmartConnect
# import pyotp
# from flask import request
# from flask_jwt_extended import jwt_required, get_jwt_identity
# import logging

# # Configure logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# def get_angel_session(user):
#     """Generate a fresh Angel One session for the user using provided credentials."""
#     try:
#         if not all([user.smartapi_key, user.smartapi_username, user.smartapi_password, user.smartapi_totp_token]):
#             raise Exception("Angel One credentials not set for this user")

#         # Initialize SmartAPI and generate a fresh session
#         smart_api = SmartConnect(user.smartapi_key)
#         totp = pyotp.TOTP(user.smartapi_totp_token).now()
#         data = smart_api.generateSession(user.smartapi_username, user.smartapi_password, totp)

#         if data['status'] == False:
#             raise Exception(f"Angel One session generation failed: {data['message']}")

#         # Extract tokens (not stored, just logged for debugging)
#         auth_token = data['data']['jwtToken']
#         refresh_token = data['data']['refreshToken']
#         feed_token = smart_api.getfeedToken()

#         # Log session details for debugging
#         # logger.info(f"Generated session with auth_token: {auth_token[:20]}... (truncated)")
#         # logger.info(f"Session data: {data}")

#         return smart_api

#     except Exception as e:
#         logger.error(f"❌ Angel Session Error: {str(e)}")
#         raise e

# # Helper function to log requests (optional, kept for consistency)
# @app.before_request
# def log_request_data():
#     if request.path in ["/user/generate-angel-session", "/user/angel/rms-limit", "/user/angel/order-book", "/user/angel/trade-book"]:
#         logger.info(f"\n🚀 Received {request.path} API request")
#         logger.info(f"📝 Request Method: {request.method}")
#         logger.info(f"📩 Request Headers: {dict(request.headers)}")
#         logger.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")

# # ✅ Generate Angel One Session API
# @app.route("/user/generate-angel-session", methods=["POST"])
# @jwt_required()
# def generate_angel_session():
#     try:
#         user_email = get_jwt_identity()
#         current_user = User.query.filter_by(email=user_email).first()
#         logger.info(f"🔑 JWT Identity: {user_email}")

#         if not current_user:
#             return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

#         # Generate session
#         smart_api = get_angel_session(current_user)

#         # Prepare response (no session storage, just confirm success)
#         response_data = {
#             "message": "Angel One session generated successfully",
#             "status": "200"
#         }
#         logger.info(f"Session generated response: {response_data}")
#         return jsonify({"data": encrypt_response(response_data)}), 200

#     except Exception as e:
#         logger.error(f"❌ Generate Angel Session Error: {str(e)}")
#         return jsonify({"data": encrypt_response({"message": f"Failed to generate Angel One session: {str(e)}", "status": "500"})}), 500

# # ✅ Get RMS Limit API
# @app.route("/user/angel/rms-limit", methods=["GET"])
# @jwt_required()
# def get_rms_limit():
#     try:
#         user_email = get_jwt_identity()
#         current_user = User.query.filter_by(email=user_email).first()
#         logger.info(f"🔑 JWT Identity: {user_email}")

#         if not current_user:
#             return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

#         # Generate fresh session and call RMS limit
#         smart_api = get_angel_session(current_user)
#         rms = smart_api.rmsLimit()
#         logger.info(f"RMS Limit Response: {rms}")

#         return jsonify({"data": encrypt_response({"message": "RMS limit fetched successfully", "rms": rms, "status": "200"})}), 200

#     except Exception as e:
#         logger.error(f"❌ RMS Limit Error: {str(e)}")
#         return jsonify({"data": encrypt_response({"message": f"Failed to fetch RMS limit: {str(e)}", "status": "500"})}), 500

# # ✅ Get Order Book API
# @app.route("/user/angel/order-book", methods=["GET"])
# @jwt_required()
# def get_order_book():
#     try:
#         user_email = get_jwt_identity()
#         current_user = User.query.filter_by(email=user_email).first()
#         logger.info(f"🔑 JWT Identity: {user_email}")

#         if not current_user:
#             return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

#         # Generate fresh session and call order book
#         smart_api = get_angel_session(current_user)
#         order_book = smart_api.orderBook()
#         logger.info(f"Order Book Response: {order_book}")

#         # Log success (no DB storage)
#         logger.info("Fetched Order Book successfully")
#         return jsonify({"data": encrypt_response({"message": "Order book fetched successfully", "order_book": order_book, "status": "200"})}), 200

#     except Exception as e:
#         logger.error(f"❌ Order Book Error: {str(e)}")
#         return jsonify({"data": encrypt_response({"message": f"Failed to fetch order book: {str(e)}", "status": "500"})}), 500

# # ✅ Get Trade Book API
# @app.route("/user/angel/trade-book", methods=["GET"])
# @jwt_required()
# def get_trade_book():
#     try:
#         user_email = get_jwt_identity()
#         current_user = User.query.filter_by(email=user_email).first()
#         logger.info(f"🔑 JWT Identity: {user_email}")

#         if not current_user:
#             return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

#         # Generate fresh session and call trade book
#         smart_api = get_angel_session(current_user)
#         trade_book = smart_api.tradeBook()
#         logger.info(f"Trade Book Response: {trade_book}")
        
#         logger.info("Fetched Trade Book successfully")
#         return jsonify({"data": encrypt_response({"message": "Trade book fetched successfully", "trade_book": trade_book, "status": "200"})}), 200

#     except Exception as e:
#         logger.error(f"❌ Trade Book Error: {str(e)}")
#         return jsonify({"data": encrypt_response({"message": f"Failed to fetch trade book: {str(e)}", "status": "500"})}), 500

# @app.route("/user/angel/all-holding", methods=["GET"])
# @jwt_required()
# def get_all_holding():
#     try:
#         user_email = get_jwt_identity()
#         current_user = User.query.filter_by(email=user_email).first()
#         logger.info(f"🔑 JWT Identity: {user_email}")

#         if not current_user:
#             return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

#         # Generate fresh session and fetch all holdings
#         smart_api = get_angel_session(current_user)
#         holding = smart_api.allholding()
#         logger.info(f"Holding Response: {holding}")

#         # Calculate today's P&L
#         if holding['status'] and 'data' in holding and 'holdings' in holding['data']:
#             holdings = holding['data']['holdings']
#             today_pnl = 0
#             for item in holdings:
#                 # Today's P&L = (LTP - Close) * Quantity
#                 today_pnl_per_stock = (item['ltp'] - item['close']) * item['quantity']
#                 item['today_pnl'] = round(today_pnl_per_stock, 2)  # Add to each holding
#                 today_pnl += today_pnl_per_stock

#             # Add total today's P&L to response
#             holding['data']['today_profit_and_loss'] = round(today_pnl, 2)
#             logger.info(f"Calculated Today's P&L: {holding['data']['today_profit_and_loss']}")
#         else:
#             logger.warning("No holdings data available to calculate today's P&L")
#             holding['data']['today_profit_and_loss'] = 0

#         logger.info("Fetched All Holdings successfully")
#         logging.info(f"holding Response: {holding}")
#         return jsonify({"data": encrypt_response({
#             "message": "All holdings fetched successfully",
#             "all_holding": holding,
#             "status": "200"
#         })}), 200

#     except Exception as e:
#         logger.error(f"❌ All Holding Error: {str(e)}")
#         return jsonify({"data": encrypt_response({"message": f"Failed to fetch all holdings: {str(e)}", "status": "500"})}), 500

from SmartApi.smartConnect import SmartConnect
import pyotp
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging
from datetime import datetime, timedelta
from collections import defaultdict

# # Configure logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# # In-memory cache for session data per user
session_cache = defaultdict(dict)

# def get_angel_session(user):
#     """Get or generate a valid Angel One session for the user."""
#     user_email = user.email
#     current_time = datetime.now()

#     # Check if a valid session exists in cache
#     if (user_email in session_cache and 
#         'smart_api' in session_cache[user_email] and 
#         session_cache[user_email]['expires_at'] > current_time):
#         logger.info(f"Reusing existing session for {user_email}")
#         return session_cache[user_email]['smart_api']

#     # Generate a new session if none exists or it’s expired
#     try:
#         if not all([user.smartapi_key, user.smartapi_username, user.smartapi_password, user.smartapi_totp_token]):
#             raise Exception("Angel One credentials not set for this user")

#         smart_api = SmartConnect(user.smartapi_key)
#         totp = pyotp.TOTP(user.smartapi_totp_token).now()
#         data = smart_api.generateSession(user.smartapi_username, user.smartapi_password, totp)

#         if data['status'] == False:
#             raise Exception(f"Angel One session generation failed: {data['message']}")

#         auth_token = data['data']['jwtToken']
#         refresh_token = data['data']['refreshToken']
#         feed_token = smart_api.getfeedToken()

#         # Set expiration (assume 24 hours, adjust based on Angel One's token TTL)
#         expires_at = current_time + timedelta(hours=24)

#         # Store in cache
#         session_cache[user_email] = {
#             'smart_api': smart_api,
#             'auth_token': auth_token,
#             'refresh_token': refresh_token,
#             'feed_token': feed_token,
#             'expires_at': expires_at
#         }

#         logger.info(f"Generated new session for {user_email} with auth_token: {auth_token[:20]}... (truncated)")
#         return smart_api

#     except Exception as e:
#         logger.error(f"❌ Angel Session Error for {user_email}: {str(e)}")
#         raise e

# def refresh_angel_session(user):
#     """Refresh the session using the refresh token."""
#     user_email = user.email
#     try:
#         if user_email not in session_cache or 'refresh_token' not in session_cache[user_email]:
#             raise Exception("No existing session to refresh")

#         smart_api = SmartConnect(user.smartapi_key)
#         refresh_token = session_cache[user_email]['refresh_token']
#         data = smart_api.generateToken(refresh_token)

#         if data['status'] == False:
#             raise Exception(f"Token refresh failed: {data['message']}")

#         auth_token = data['data']['jwtToken']
#         feed_token = data['data']['feedToken']
#         expires_at = datetime.now() + timedelta(hours=24)

#         # Update cache with refreshed tokens
#         session_cache[user_email] = {
#             'smart_api': smart_api,
#             'auth_token': auth_token,
#             'refresh_token': refresh_token,  # Refresh token typically remains the same
#             'feed_token': feed_token,
#             'expires_at': expires_at
#         }

#         logger.info(f"Refreshed session for {user_email} with auth_token: {auth_token[:20]}... (truncated)")
#         return smart_api

#     except Exception as e:
#         logger.error(f"❌ Session Refresh Error for {user_email}: {str(e)}")
#         # Fallback to full session generation if refresh fails
#         return get_angel_session(user)

# # Helper function to log requests
# @app.before_request
# def log_request_data():
#     if request.path in ["/user/generate-angel-session", "/user/angel/rms-limit", "/user/angel/order-book", "/user/angel/trade-book", "/user/angel/all-holding"]:
#         logger.info(f"\n🚀 Received {request.path} API request")
#         logger.info(f"📝 Request Method: {request.method}")
#         logger.info(f"📩 Request Headers: {dict(request.headers)}")
#         logger.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")

# # ✅ Generate Angel One Session API
# @app.route("/user/generate-angel-session", methods=["POST"])
# @jwt_required()
# def generate_angel_session():
#     try:
#         user_email = get_jwt_identity()
#         current_user = User.query.filter_by(email=user_email).first()
#         logger.info(f"🔑 JWT Identity: {user_email}")

#         if not current_user:
#             return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

#         # Generate or reuse session
#         smart_api = get_angel_session(current_user)

#         response_data = {
#             "message": "Angel One session generated or reused successfully",
#             "status": "200"
#         }
#         logger.info(f"Session response: {response_data}")
#         return jsonify({"data": encrypt_response(response_data)}), 200

#     except Exception as e:
#         logger.error(f"❌ Generate Angel Session Error: {str(e)}")
#         return jsonify({"data": encrypt_response({"message": f"Failed to generate Angel One session: {str(e)}", "status": "500"})}), 500

# # ✅ Get RMS Limit API
# @app.route("/user/angel/rms-limit", methods=["GET"])
# @jwt_required()
# def get_rms_limit():
#     try:
#         user_email = get_jwt_identity()
#         current_user = User.query.filter_by(email=user_email).first()
#         logger.info(f"🔑 JWT Identity: {user_email}")

#         if not current_user:
#             return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

#         smart_api = get_angel_session(current_user)
#         rms = smart_api.rmsLimit()
#         logger.info(f"RMS Limit Response: {rms}")

#         logger.info("Fetched RMS Limit successfully")
#         return jsonify({"data": encrypt_response({"message": "RMS limit fetched successfully", "rms": rms, "status": "200"})}), 200

#     except Exception as e:
#         logger.error(f"❌ RMS Limit Error: {str(e)}")
#         if "Invalid Token" in str(e):
#             smart_api = refresh_angel_session(current_user)
#             rms = smart_api.rmsLimit()
#             logger.info(f"RMS Limit Response after refresh: {rms}")
#             return jsonify({"data": encrypt_response({"message": "RMS limit fetched successfully", "rms": rms, "status": "200"})}), 200
#         return jsonify({"data": encrypt_response({"message": f"Failed to fetch RMS limit: {str(e)}", "status": "500"})}), 500

# # ✅ Get Order Book API
# @app.route("/user/angel/order-book", methods=["GET"])
# @jwt_required()
# def get_order_book():
#     try:
#         user_email = get_jwt_identity()
#         current_user = User.query.filter_by(email=user_email).first()
#         logger.info(f"🔑 JWT Identity: {user_email}")

#         if not current_user:
#             return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

#         smart_api = get_angel_session(current_user)
#         order_book = smart_api.orderBook()
#         logger.info(f"Order Book Response: {order_book}")

#         logger.info("Fetched Order Book successfully")
#         return jsonify({"data": encrypt_response({"message": "Order book fetched successfully", "order_book": order_book, "status": "200"})}), 200

#     except Exception as e:
#         logger.error(f"❌ Order Book Error: {str(e)}")
#         if "Invalid Token" in str(e):
#             smart_api = refresh_angel_session(current_user)
#             order_book = smart_api.orderBook()
#             logger.info(f"Order Book Response after refresh: {order_book}")
#             return jsonify({"data": encrypt_response({"message": "Order book fetched successfully", "order_book": order_book, "status": "200"})}), 200
#         return jsonify({"data": encrypt_response({"message": f"Failed to fetch order book: {str(e)}", "status": "500"})}), 500

# # ✅ Get Trade Book API
# @app.route("/user/angel/trade-book", methods=["GET"])
# @jwt_required()
# def get_trade_book():
#     try:
#         user_email = get_jwt_identity()
#         current_user = User.query.filter_by(email=user_email).first()
#         logger.info(f"🔑 JWT Identity: {user_email}")

#         if not current_user:
#             return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

#         smart_api = get_angel_session(current_user)
#         trade_book = smart_api.tradeBook()
#         logger.info(f"Trade Book Response: {trade_book}")

#         logger.info("Fetched Trade Book successfully")
#         return jsonify({"data": encrypt_response({"message": "Trade book fetched successfully", "trade_book": trade_book, "status": "200"})}), 200

#     except Exception as e:
#         logger.error(f"❌ Trade Book Error: {str(e)}")
#         if "Invalid Token" in str(e):
#             smart_api = refresh_angel_session(current_user)
#             trade_book = smart_api.tradeBook()
#             logger.info(f"Trade Book Response after refresh: {trade_book}")
#             return jsonify({"data": encrypt_response({"message": "Trade book fetched successfully", "trade_book": trade_book, "status": "200"})}), 200
#         return jsonify({"data": encrypt_response({"message": f"Failed to fetch trade book: {str(e)}", "status": "500"})}), 500

# # ✅ Get All Holdings API
# @app.before_request
# def log_request_data():
#     if request.path == "/user/angel/all-holding":
#         logging.info("\n🚀 Received /user/angel/all-holding API request")
#         logging.info(f"📝 Request Method: {request.method}")
#         logging.info(f"📩 Request Headers: {dict(request.headers)}")
#         logging.info(f"🔒 Raw Request Body: {request.data.decode('utf-8')}")
# @app.route("/user/angel/all-holding", methods=["GET"])
# @jwt_required()
# def get_all_holding():
#     try:
#         user_email = get_jwt_identity()
#         current_user = User.query.filter_by(email=user_email).first()
#         logger.info(f"🔑 JWT Identity: {user_email}")

#         if not current_user:
#             return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

#         smart_api = get_angel_session(current_user)
#         holding = smart_api.allholding()
#         logger.info(f"Holding Response: {holding}")

#         if holding['status'] and 'data' in holding and 'holdings' in holding['data']:
#             holdings = holding['data']['holdings']
#             today_pnl = 0
#             for item in holdings:
#                 today_pnl_per_stock = (item['ltp'] - item['close']) * item['quantity']
#                 item['today_pnl'] = round(today_pnl_per_stock, 2)
#                 today_pnl += today_pnl_per_stock

#             holding['data']['today_profit_and_loss'] = round(today_pnl, 2)
#             logger.info(f"Calculated Today's P&L: {holding['data']['today_profit_and_loss']}")
#         else:
#             logger.warning("No holdings data available to calculate today's P&L")
#             holding['data']['today_profit_and_loss'] = 0

#         logger.info("Fetched All Holdings successfully")
#         return jsonify({"data": encrypt_response({
#             "message": "All holdings fetched successfully",
#             "all_holding": holding,
#             "status": "200"
#         })}), 200

#     except Exception as e:
#         logger.error(f"❌ All Holding Error: {str(e)}")
#         if "Invalid Token" in str(e):
#             smart_api = refresh_angel_session(current_user)
#             holding = smart_api.allholding()
#             logger.info(f"Holding Response after refresh: {holding}")
#             if holding['status'] and 'data' in holding and 'holdings' in holding['data']:
#                 holdings = holding['data']['holdings']
#                 today_pnl = 0
#                 for item in holdings:
#                     today_pnl_per_stock = (item['ltp'] - item['close']) * item['quantity']
#                     item['today_pnl'] = round(today_pnl_per_stock, 2)
#                     today_pnl += today_pnl_per_stock
#                 holding['data']['today_profit_and_loss'] = round(today_pnl, 2)
#             else:
#                 holding['data']['today_profit_and_loss'] = 0
#             return jsonify({"data": encrypt_response({
#                 "message": "All holdings fetched successfully",
#                 "all_holding": holding,
#                 "status": "200"
#             })}), 200
#         return jsonify({"data": encrypt_response({"message": f"Failed to fetch all holdings: {str(e)}", "status": "500"})}), 500

