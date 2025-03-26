
# from SmartApi.smartWebSocketV2 import SmartWebSocketV2
# from collections import defaultdict

# websocket_data = defaultdict(dict)

# def websocket_callback(message, user_email):
#     """Callback function to handle WebSocket messages."""
#     try:
#         if 'ltp' in message:
#             symbol_token = message['token']
#             ltp = float(message['ltp'])
#             websocket_data[user_email][symbol_token] = ltp
#             logger.info(f"WebSocket update for {user_email} - Token: {symbol_token}, LTP: {ltp}")
#     except Exception as e:
#         logger.error(f"❌ WebSocket Callback Error: {str(e)}")

# def start_websocket(user, auth_token, feed_token, symbol_tokens):
#     """Start WebSocket connection for a user."""
#     try:
#         # WebSocket configuration
#         correlation_id = f"{user.email}_holdings"
#         action = 1  # Subscribe
#         mode = 1    # LTP mode

#         # Subscription request
#         subscription_list = [{"exchangeType": 1, "tokens": symbol_tokens}]  # NSE exchange (adjust if needed)

#         # Initialize WebSocket
#         sws = SmartWebSocketV2(auth_token, user.smartapi_key, user.smartapi_username, feed_token)

#         # Start WebSocket in a separate thread
#         def on_open():
#             logger.info(f"WebSocket opened for {user.email}")
#             sws.subscribe(correlation_id, mode, subscription_list)

#         def on_data(ws, message):
#             websocket_callback(message, user.email)

#         def on_error(ws, error):
#             logger.error(f"WebSocket error for {user.email}: {error}")

#         def on_close(ws):
#             logger.info(f"WebSocket closed for {user.email}")

#         sws.on_open = on_open
#         sws.on_data = on_data
#         sws.on_error = on_error
#         sws.on_close = on_close

#         threading.Thread(target=sws.connect, daemon=True).start()
#         logger.info(f"Started WebSocket for {user.email} with tokens: {symbol_tokens}")

#     except Exception as e:
#         logger.error(f"❌ WebSocket Start Error: {str(e)}")

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
#         smart_api, auth_token, feed_token = get_angel_session(current_user)
#         holding = smart_api.allholding()
#         logger.info(f"Holding Response: {holding}")

#         # Calculate initial today's P&L and prepare WebSocket subscription
#         if holding['status'] and 'data' in holding and 'holdings' in holding['data']:
#             holdings = holding['data']['holdings']
#             today_pnl = 0
#             symbol_tokens = []

#             # Initialize WebSocket data with current LTP
#             for item in holdings:
#                 symbol_token = item['symboltoken']
#                 symbol_tokens.append(symbol_token)
#                 websocket_data[user_email][symbol_token] = item['ltp']  # Initial LTP
#                 today_pnl_per_stock = (item['ltp'] - item['close']) * item['quantity']
#                 item['today_pnl'] = round(today_pnl_per_stock, 2)
#                 today_pnl += today_pnl_per_stock

#             holding['data']['today_profit_and_loss'] = round(today_pnl, 2)
#             logger.info(f"Initial Today's P&L: {holding['data']['today_profit_and_loss']}")

#             # Start WebSocket for real-time updates
#             start_websocket(current_user, auth_token, feed_token, symbol_tokens)
#         else:
#             logger.warning("No holdings data available to calculate today's P&L")
#             holding['data']['today_profit_and_loss'] = 0

#         logger.info("Fetched All Holdings successfully")
#         return jsonify({"data": encrypt_response({
#             "message": "All holdings fetched successfully with WebSocket subscription",
#             "all_holding": holding,
#             "status": "200"
#         })}), 200

#     except Exception as e:
#         logger.error(f"❌ All Holding Error: {str(e)}")
#         return jsonify({"data": encrypt_response({"message": f"Failed to fetch all holdings: {str(e)}", "status": "500"})}), 500

# # ✅ Get Real-Time Today's P&L API
# @app.route("/user/angel/today-pnl", methods=["GET"])
# @jwt_required()
# def get_today_pnl():
#     try:
#         user_email = get_jwt_identity()
#         current_user = User.query.filter_by(email=user_email).first()
#         logger.info(f"🔑 JWT Identity: {user_email}")

#         if not current_user:
#             return jsonify({"data": encrypt_response({"message": "Unauthorized access", "status": "403"})}), 403

#         # Fetch initial holdings to get close prices and quantities
#         smart_api = get_angel_session(current_user)
#         holding = smart_api.allholding()

#         if holding['status'] and 'data' in holding and 'holdings' in holding['data']:
#             holdings = holding['data']['holdings']
#             today_pnl = 0

#             for item in holdings:
#                 symbol_token = item['symboltoken']
#                 ltp = websocket_data[user_email].get(symbol_token, item['ltp'])  # Use WebSocket LTP if available
#                 today_pnl_per_stock = (ltp - item['close']) * item['quantity']
#                 item['today_pnl'] = round(today_pnl_per_stock, 2)
#                 today_pnl += today_pnl_per_stock

#             response_data = {
#                 "message": "Today's P&L calculated successfully",
#                 "holdings": holdings,
#                 "today_profit_and_loss": round(today_pnl, 2),
#                 "status": "200"
#             }
#             logger.info(f"Real-Time Today's P&L: {today_pnl}")
#             return jsonify({"data": encrypt_response(response_data)}), 200
#         else:
#             logger.warning("No holdings data available for P&L calculation")
#             return jsonify({"data": encrypt_response({"message": "No holdings available", "today_profit_and_loss": 0, "status": "200"})}), 200

#     except Exception as e:
#         logger.error(f"❌ Today P&L Error: {str(e)}")
#         return jsonify({"data": encrypt_response({"message": f"Failed to calculate today's P&L: {str(e)}", "status": "500"})}), 500