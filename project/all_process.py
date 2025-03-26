        
# from threading import Lock
# import threading
# import eventlet
# from flask import Flask, request
# from flask_socketio import SocketIO, emit
# from flask_jwt_extended import JWTManager, get_jwt_identity, verify_jwt_in_request
#  # Replace with your actual utility imports
# import logging

# # Configure logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)


# socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')  # Explicitly set eventlet
# jwt = JWTManager(app)

# # # WebSocket lock and clients dictionary
# websocket_lock = Lock()
# websocket_clients = {}
# live_prices = {}
# session_cache = {}

# @socketio.on('stream_connect', namespace='/stream')
# def start_websocket_stream(user):
#     logger.info(f"Starting WebSocket stream for {user.email}")
#     user_email = user.email
#     try:
#         smart_api = get_angel_session(user)
#         auth_token = session_cache[user_email]['auth_token']
#         feed_token = session_cache[user_email]['feed_token']
#         api_key = user.smartapi_key
#         client_code = user.smartapi_username

#         with app.app_context():
#             stocks = Stock.query.filter_by(user_id=user.id).all()
#             logger.info(f"Stocks for {user_email}: {stocks}")
#             if not stocks:
#                 logger.info(f"No stocks found for {user_email}")
#                 emit('stock_stream', {'message': 'No stocks subscribed', 'data': []}, namespace='/stream', to=user_email)
#                 return

#         token_map = {}
#         for stock in stocks:
#             if stock.exchange == "NSE":
#                 exchange_type = 1
#             elif stock.exchange == "BSE":
#                 exchange_type = 3 
#             if exchange_type not in token_map:
#                 token_map[exchange_type] = []
#             token_map[exchange_type].append(stock.symboltoken)

#         token_list = [
#             {"exchangeType": exchange_type, "tokens": tokens}
#             for exchange_type, tokens in token_map.items()
#         ]

#         logger.info(f"Token list for {user_email}: {token_list}")

#         correlation_id = f"stream_{user_email}"
#         mode = 1

#         sws = SmartWebSocketV2(auth_token, api_key, client_code, feed_token, 
#                                max_retry_attempt=2, retry_strategy=0, retry_delay=10, retry_duration=30)

#         logger.info(f"WebSocket setup for {sws}")
#         def on_data(wsapp, message):
#             token = message.get('token')
#             last_traded_price = message.get('last_traded_price')
#             # Add stock name within app context
#             with app.app_context():
#                 stock = Stock.query.filter_by(symboltoken=token).first()
#                 if stock:
#                     message['name'] = stock.tradingsymbol
#                 else:
#                     message['name'] = 'Unknown'  # Fallback if no match
#             if token and last_traded_price is not None:
#                 live_prices[token] = {
#                     'price': last_traded_price / 100,  # Convert paisa to rupees
#                     'name': message['name']
#                 }
#             logger.info(f"Tick for {user_email}: {message}")
#             socketio.emit('stock_stream', {'message': 'New tick', 'data': message},
#                          namespace='/stream', to=user_email)

#         def on_open(wsapp):
#             logger.info(f"WebSocket opened for {user_email}")
#             sws.subscribe(correlation_id, mode, token_list)

#         def on_error(wsapp, error):
#             logger.error(f"WebSocket error for {user_email}: {error}")
#             socketio.emit('stock_stream', {'message': 'WebSocket error', 'error': str(error)}, 
#                          namespace='/stream', to=user_email)
#             with websocket_lock:
#                 if user_email in websocket_clients and websocket_clients[user_email] == wsapp:
#                     del websocket_clients[user_email]
#                     thread = threading.Thread(target=start_websocket_stream, args=(user,))
#                     thread.daemon = True
#                     thread.start()

#         def on_close(wsapp, code=None, reason=None):
#             logger.info(f"WebSocket closed for {user_email} with code: {code}, reason: {reason}")
#             socketio.emit('stock_stream', {'message': 'WebSocket closed'}, 
#                          namespace='/stream', to=user_email)
#             with websocket_lock:
#                 if user_email in websocket_clients and websocket_clients[user_email] == wsapp:
#                     del websocket_clients[user_email]

#         sws.on_open = on_open
#         sws.on_data = on_data
#         sws.on_error = on_error
#         sws.on_close = on_close

#         with websocket_lock:
#             if user_email in websocket_clients:
#                 websocket_clients[user_email].close_connection()
#             websocket_clients[user_email] = sws

#         sws.connect()

#     except Exception as e:
#         logger.error(f"❌ WebSocket Setup Error for {user_email}: {str(e)}")
#         socketio.emit('stock_stream', {'message': 'WebSocket setup failed', 'error': str(e)}, 
#                      namespace='/stream', to=user_email)

# @socketio.on('connect', namespace='/stream')
# def handle_connect(auth):
#     logger.info("WebSocket connected or not")
#     token = auth.get('token') if auth else None
#     if not token:
#         logger.error("No token provided in WebSocket connection")
#         emit('stock_stream', {'message': 'Unauthorized - No token provided', 'status': '401'})
#         return False

#     request.headers = {'Authorization': f'Bearer {token}'}
#     try:
#         verify_jwt_in_request()
#         user_email = get_jwt_identity()
#         current_user = User.query.filter_by(email=user_email).first()

#         if not current_user:
#             logger.error(f"Unauthorized WebSocket connection attempt: {user_email}")
#             emit('stock_stream', {'message': 'Unauthorized - User not found', 'status': '403'})
#             return False

#         logger.info(f"WebSocket connected for {user_email}")
#         emit('stock_stream', {'message': 'Connected to stock stream', 'status': '200'})

#         with websocket_lock:
#             logger.info(f"WebSocket clients: {websocket_clients}")
#             logger.info(f"Current user: {current_user}")
#             logger.info(f"User email: {user_email}")
#             if user_email not in websocket_clients or not hasattr(websocket_clients[user_email], 'connected') or not websocket_clients[user_email].connected:
#                 thread = threading.Thread(target=start_websocket_stream, args=(current_user,))
#                 thread.daemon = True
#                 thread.start()

#         return True

#     except Exception as e:
#         logger.error(f"JWT verification failed: {str(e)}")
#         emit('stock_stream', {'message': 'Unauthorized - Invalid token', 'status': '401'})
#         return False

# @socketio.on('disconnect', namespace='/stream')
# def handle_disconnect():
#     try:
#         verify_jwt_in_request()
#         user_email = get_jwt_identity()
#         with websocket_lock:
#             if user_email in websocket_clients:
#                 websocket_clients[user_email].close_connection()
#                 del websocket_clients[user_email]
#         logger.info(f"WebSocket disconnected for {user_email}")
#     except Exception as e:
#         logger.error(f"Disconnect error: {str(e)}")


# ------------------------------------------------------------------------------------


# websocket_lock = Lock()
# websocket_clients = {}
# live_prices = {}
# session_cache = {}

# # Strategy data (mimicking your Excel)
# import pandas as pd
# strategy_data = pd.DataFrame({
#     'Sr.No': list(range(1, 82)),
#     'DOWN': [0] + [-(i * 0.0025) for i in range(1, 21)] + 
#             [-0.055 - (i * 0.005) for i in range(0, 20)] + 
#             [-0.1575 - (i * 0.0075) for i in range(0, 14)] + 
#             [-0.265 - (i * 0.01) for i in range(0, 15)] + 
#             [-0.4175 - (i * 0.0125) for i in range(0, 11)],
#     'Qnty': [200, 11] + [round(11 + i * 0.25, 0) for i in range(79)]  # Simplified E column
# })
# strategy_data['Entry'] = strategy_data['DOWN'].apply(lambda x: round(100 * (1 + x), 2))
# strategy_data['First_TGT'] = [None]*8 + [round(e * 1.015, 2) for e in strategy_data['Entry'][8:]]
# strategy_data['EXIT_1st_HALF'] = [None]*8 + [round(q/2, 0) for q in strategy_data['Qnty'][8:]]
# strategy_data['Second_TGT'] = [None]*8 + [round(e * 1.02, 2) for e in strategy_data['Entry'][8:]]
# strategy_data['EXIT_2nd_HALF'] = [None]*8 + [round(q/2, 0) for q in strategy_data['Qnty'][8:]]
# strategy_data['FINAL_TGT'] = [round(e * 1.015, 2) for e in strategy_data['Entry']]

# with app.app_context():
#     db.create_all()

# def place_order(smart_api, symbol, qty, price, buy_sell='BUY'):
#     order_params = {
#         "variety": "NORMAL",
#         "tradingsymbol": symbol,
#         "symboltoken": Stock.query.filter_by(tradingsymbol=symbol).first().symboltoken,
#         "transactiontype": buy_sell,
#         "exchange": Stock.query.filter_by(tradingsymbol=symbol).first().exchange,
#         "ordertype": "MARKET",
#         "producttype": "DELIVERY",
#         "duration": "DAY",
#         "price": str(price),
#         "quantity": str(qty)
#     }
#     response = smart_api.placeOrder(order_params)
#     executed_qty = min(qty, int(response.get('data', {}).get('quantity', qty))) if response.get('status') else 0
#     logger.info(f"Order {buy_sell} {executed_qty}/{qty} of {symbol} at {price}: {response}")
#     return executed_qty

# def is_market_open():
#     now = datetime.now(IST)
#     market_open = now.replace(hour=9, minute=00, second=0, microsecond=0)
#     market_close = now.replace(hour=15, minute=30, second=0, microsecond=0)
#     return now.weekday() < 5 and market_open <= now <= market_close

# def process_strategy(user, symbol, ltp, smart_api):
#     if not is_market_open():
#         return

#     with app.app_context():
#         trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email, status='OPEN').order_by(Trade.sr_no).all()
#         if not trades and ltp <= 100:  # Initial entry
#             qty = strategy_data.loc[0, 'Qnty']
#             executed_qty = place_order(smart_api, symbol, qty, ltp)
#             if executed_qty > 0:
#                 trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=100, quantity=executed_qty, user_email=user.email)
#                 db.session.add(trade)
#                 db.session.commit()
#             return

#         base_price = 100  # Reference price
#         for trade in trades:
#             sr_no = trade.sr_no
#             entry_price = trade.entry_price
#             current_qty = trade.quantity - trade.sold_quantity
#             row = strategy_data.loc[sr_no-1]

#             # Buy logic
#             drop_percent = (ltp - base_price) / base_price
#             target_drop = row['DOWN']
#             if drop_percent <= target_drop and current_qty == 0 and sr_no < 81:
#                 qty = row['Qnty']
#                 executed_qty = place_order(smart_api, symbol, qty, ltp)
#                 if executed_qty > 0:
#                     trade.quantity = executed_qty
#                     trade.entry_price = entry_price 
#                     next_sr_no = min(sr_no + 1, 81)
#                     next_trade = Trade(stock_symbol=symbol, sr_no=next_sr_no, entry_price=entry_price, quantity=0, user_email=user.email)
#                     db.session.add(next_trade)
#                     db.session.commit()
#                     logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}")

#             # Profit booking
#             if sr_no <= 8:  # Phase 1
#                 target = row['FINAL_TGT']
#                 if ltp >= target and current_qty > 0:
#                     executed_qty = place_order(smart_api, symbol, current_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     if trade.sold_quantity == trade.quantity:
#                         trade.status = 'CLOSED'
#                         db.session.commit()
#                         tm.sleep(7)
#                         new_qty = row['Qnty']
#                         new_executed = place_order(smart_api, symbol, new_qty, ltp)
#                         if new_executed > 0:
#                             new_trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=100, quantity=new_executed, user_email=user.email)
#                             db.session.add(new_trade)
#                             db.session.commit()
#                             logger.info(f"Exit {symbol} at {ltp}, Restart at {ltp}, Qty: {new_executed}")
#                     else:
#                         trade.status = 'PARTIAL'
#                         db.session.commit()
#                         logger.info(f"Partial Exit {symbol} at {ltp}, Sold: {executed_qty}/{current_qty}")
#             else:  # Phase 2-6 (Sr.No 9-81)
#                 first_tgt = row['First_TGT']
#                 second_tgt = row['Second_TGT']
#                 final_tgt = row['FINAL_TGT']
#                 half_qty = row['EXIT_1st_HALF']

#                 if ltp >= first_tgt and trade.sold_quantity == 0 and current_qty > 0:
#                     executed_qty = place_order(smart_api, symbol, half_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     if trade.sold_quantity < half_qty:
#                         trade.status = 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}")

#                 elif ltp >= second_tgt and trade.sold_quantity == half_qty and current_qty > 0:
#                     executed_qty = place_order(smart_api, symbol, half_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     if trade.sold_quantity < trade.quantity:
#                         trade.status = 'PARTIAL'
#                     else:
#                         trade.status = 'CLOSED'
#                     db.session.commit()
#                     logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}")

#                 elif ltp >= final_tgt and current_qty > 0:
#                     executed_qty = place_order(smart_api, symbol, current_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     if trade.sold_quantity == trade.quantity:
#                         trade.status = 'CLOSED'
#                         db.session.commit()
#                         tm.sleep(7)
#                         new_qty = strategy_data.loc[0, 'Qnty']
#                         new_executed = place_order(smart_api, symbol, new_qty, ltp)
#                         if new_executed > 0:
#                             new_trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=100, quantity=new_executed, user_email=user.email)
#                             db.session.add(new_trade)
#                             db.session.commit()
#                             logger.info(f"Exit Final {symbol} at {ltp}, Restart at {ltp}, Qty: {new_executed}")
#                     else:
#                         trade.status = 'PARTIAL'
#                         db.session.commit()

#             # Re-entry for partial exits if price drops
#             if trade.status == 'PARTIAL' and ltp < entry_price:
#                 reentry_qty = trade.sold_quantity
#                 executed_qty = place_order(smart_api, symbol, reentry_qty, entry_price)
#                 if executed_qty > 0:
#                     trade.quantity += executed_qty
#                     trade.sold_quantity = 0
#                     trade.status = 'OPEN'
#                     db.session.commit()
#                     logger.info(f"Re-enter {symbol} at {entry_price}, Qty: {executed_qty}")
                    
# @socketio.on('stream_connect', namespace='/stream')
# def start_websocket_stream(user):
#     user_email = user.email
#     try:
#         smart_api = get_angel_session(user)
#         auth_token = session_cache[user_email]['auth_token']
#         feed_token = session_cache[user_email]['feed_token']
#         api_key = user.smartapi_key
#         client_code = user.smartapi_username

#         stocks = Stock.query.filter_by(user_id=user.id).all()
#         if not stocks:
#             emit('stock_stream', {'message': 'No stocks subscribed', 'data': []}, namespace='/stream', to=user_email)
#             return

#         token_map = {1: [], 3: []}
#         for stock in stocks:
#             if stock.exchange == "NSE":
#                 exchange_type = 1
#             elif stock.exchange == "BSE":
#                 exchange_type = 3
#             token_map[exchange_type].append(stock.symboltoken)

#         token_list = [{"exchangeType": et, "tokens": tokens} for et, tokens in token_map.items() if tokens]
#         correlation_id = f"stream_{user_email}"
#         mode = 1

#         sws = SmartWebSocketV2(auth_token, api_key, client_code, feed_token, 
#                                max_retry_attempt=2, retry_strategy=0, retry_delay=10, retry_duration=30)

#         def on_data(wsapp, message):
#             token = message.get('token')
#             ltp = message.get('last_traded_price', 0) / 100
#             with app.app_context():
#                 stock = Stock.query.filter_by(symboltoken=token).first()
#                 if stock:
#                     message['name'] = stock.tradingsymbol
#                     live_prices[token] = {'price': ltp, 'name': stock.tradingsymbol}
#                     process_strategy(user, stock.tradingsymbol, ltp, smart_api['smart_api'])
#                 socketio.emit('stock_stream', {'message': 'New tick', 'data': message}, 
#                              namespace='/stream', to=user_email)

#         def on_open(wsapp):
#             sws.subscribe(correlation_id, mode, token_list)

#         def on_error(wsapp, error):
#             with websocket_lock:
#                 if user_email in websocket_clients:
#                     del websocket_clients[user_email]
#                     thread = threading.Thread(target=start_websocket_stream, args=(user,))
#                     thread.daemon = True
#                     thread.start()

#         def on_close(wsapp, code=None, reason=None):
#             with websocket_lock:
#                 if user_email in websocket_clients:
#                     del websocket_clients[user_email]

#         sws.on_open = on_open
#         sws.on_data = on_data
#         sws.on_error = on_error
#         sws.on_close = on_close

#         with websocket_lock:
#             if user_email in websocket_clients:
#                 websocket_clients[user_email].close_connection()
#             websocket_clients[user_email] = sws

#         sws.connect()

#     except Exception as e:
#         logger.error(f"WebSocket Setup Error for {user_email}: {str(e)}")
#         socketio.emit('stock_stream', {'message': 'WebSocket setup failed', 'error': str(e)}, 
#                      namespace='/stream', to=user_email)

# @socketio.on('connect', namespace='/stream')
# def handle_connect(auth):
#     token = auth.get('token') if auth else None
#     if not token:
#         emit('stock_stream', {'message': 'Unauthorized - No token provided', 'status': '401'})
#         return False

#     request.headers = {'Authorization': f'Bearer {token}'}
#     try:
#         verify_jwt_in_request()
#         user_email = get_jwt_identity()
#         current_user = User.query.filter_by(email=user_email).first()

#         if not current_user:
#             emit('stock_stream', {'message': 'Unauthorized - User not found', 'status': '403'})
#             return False

#         emit('stock_stream', {'message': 'Connected to stock stream', 'status': '200'})
#         with websocket_lock:
#             if user_email not in websocket_clients or not hasattr(websocket_clients[user_email], 'connected') or not websocket_clients[user_email].connected:
#                 thread = threading.Thread(target=start_websocket_stream, args=(current_user,))
#                 thread.daemon = True
#                 thread.start()
#         return True

#     except Exception as e:
#         emit('stock_stream', {'message': 'Unauthorized - Invalid token', 'status': '401'})
#         return False

# @socketio.on('disconnect', namespace='/stream')
# def handle_disconnect():
#     try:
#         verify_jwt_in_request()
#         user_email = get_jwt_identity()
#         with websocket_lock:
#             if user_email in websocket_clients:
#                 websocket_clients[user_email].close_connection()
#                 del websocket_clients[user_email]
#     except Exception as e:
#         logger.error(f"Disconnect error: {str(e)}")

# @app.route('/api/live-prices', methods=['GET'])
# @jwt_required()
# def get_live_prices():
#     try:
#         user_email = get_jwt_identity()
#         return jsonify({'status': 'success', 'data': live_prices}), 200
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': 'Unauthorized or server error'}), 401
# def save_state_at_close():
#     while True:
#         now = datetime.now(IST)
#         if now.hour == 15 and now.minute >= 30 and now.weekday() < 5:
#             with websocket_lock:
#                 for user_email, ws in websocket_clients.items():
#                     ws.close_connection()
#             logger.info("Market closed, state saved in Trade table")
#             tm.sleep(3600)
#         tm.sleep(60)

# threading.Thread(target=save_state_at_close, daemon=True).start()

# WebSocket lock and data dictionaries
# websocket_lock = Lock()
# websocket_clients = {}
# live_prices = {}
# session_cache = {}
# # Indian Standard Time
# IST = pytz.timezone('Asia/Kolkata')

# Initialize DB
# with app.app_context():
#     db.create_all()
#     if not PhaseConfig.query.first():
#         default_configs = [
#             PhaseConfig(user_email='test@example.com', stock_symbol='RELIANCE', phase=1, start_sr_no=1, end_sr_no=21, down_increment=0.25),
#             PhaseConfig(user_email='test@example.com', stock_symbol='RELIANCE', phase=2, start_sr_no=22, end_sr_no=41, down_increment=0.50),
#             PhaseConfig(user_email='test@example.com', stock_symbol='RELIANCE', phase=3, start_sr_no=42, end_sr_no=55, down_increment=0.75),
#             PhaseConfig(user_email='test@example.com', stock_symbol='RELIANCE', phase=4, start_sr_no=56, end_sr_no=70, down_increment=1.00),
#             PhaseConfig(user_email='test@example.com', stock_symbol='RELIANCE', phase=5, start_sr_no=71, end_sr_no=81, down_increment=1.25),
#         ]
#         db.session.bulk_save_objects(default_configs)
#         db.session.commit()



# def process_strategy(user, symbol, ltp, smart_api):
#     logger.log(logging.INFO, f"Process strategy for {symbol} at {ltp}")
#     if not is_market_open():
#         return

#     with app.app_context():
#         trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email, status='OPEN').order_by(Trade.sr_no).all()
#         logger.log(logging.INFO, f"Trades for {symbol}: {trades}")
#         wallet_value = get_wallet_value(smart_api)
        
#         if trades:
#             base_price = trades[0].base_price
#             logger.log(logging.INFO, f"Base price for {symbol}: {base_price}")
#         else:
#             base_price = ltp
#             logger.log(logging.INFO, f"Base price for {symbol} set to LTP: {base_price}")
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
#             logger.log(logging.INFO, f"Strategy data for {symbol}: {strategy_data}")
#             qty = strategy_data.loc[0, 'Qnty']
#             logger.log(logging.INFO, f"Initial buy qty for {symbol}: {qty}")
#             executed_qty = place_order(smart_api, symbol, qty, ltp)
#             logger.log(logging.INFO, f"Initial buy executed qty for {symbol}: {executed_qty}")
#             if executed_qty > 0:
#                 trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=base_price, quantity=int(executed_qty), 
#                               user_email=user.email, base_price=base_price)
#                 db.session.add(trade)
#                 db.session.commit()
#                 logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}")
#             return

#         strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
        
#         for trade in trades:
#             sr_no = trade.sr_no
#             logger.log(logging.INFO, f"Trade Sr.No for {symbol}: {sr_no}")
#             entry_price = trade.entry_price
#             logger.log(logging.INFO, f"Trade entry price for {symbol}: {entry_price}")
#             current_qty = trade.quantity - trade.sold_quantity
#             logger.log(logging.INFO, f"Current quantity for {symbol}: {current_qty}")
#             row = strategy_data.loc[sr_no-1]
#             logger.log(logging.INFO, f"Strategy row for {symbol}: {row}")

#             drop_percent = (ltp - base_price) / base_price
#             logger.log(logging.INFO, f"Drop percent for {symbol}: {drop_percent}")
#             target_drop = row['DOWN']
#             logger.log(logging.INFO, f"Target drop for {symbol}: {target_drop}")
#             if drop_percent <= target_drop and current_qty == 0 and sr_no < 81:
#                 qty = row['Qnty']
#                 logger.log(logging.INFO, f"Buy qty for {symbol}: {qty}")
#                 executed_qty = place_order(smart_api, symbol, qty, ltp)
#                 logger.log(logging.INFO, f"Buy executed qty for {symbol}: {executed_qty}")
#                 if executed_qty > 0:
#                     trade.quantity = executed_qty
#                     trade.entry_price = entry_price
#                     next_sr_no = min(sr_no + 1, 81)
#                     next_trade = Trade(stock_symbol=symbol, sr_no=next_sr_no, entry_price=entry_price, 
#                                        quantity=0, user_email=user.email, base_price=base_price)
#                     db.session.add(next_trade)
#                     db.session.commit()
#                     logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}")

#             if sr_no <= 8:
#                 target = row['FINAL_TGT']
#                 if ltp >= target and current_qty > 0:
#                     executed_qty = place_order(smart_api, symbol, current_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     if trade.sold_quantity == trade.quantity:
#                         trade.status = 'CLOSED'
#                         db.session.commit()
#                         tm.sleep(7)
#                         new_qty = strategy_data.loc[0, 'Qnty']
#                         new_executed = place_order(smart_api, symbol, new_qty, ltp)
#                         if new_executed > 0:
#                             new_trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=base_price, 
#                                               quantity=new_executed, user_email=user.email, base_price=base_price)
#                             db.session.add(new_trade)
#                             db.session.commit()
#                             logger.info(f"Exit {symbol} at {ltp}, Restart at {ltp}, Qty: {new_executed}")
#                     else:
#                         trade.status = 'PARTIAL'
#                         db.session.commit()
#             else:
#                 first_tgt = row['First_TGT']
#                 second_tgt = row['Second_TGT']
#                 final_tgt = row['FINAL_TGT']
#                 half_qty = row['EXIT_1st_HALF']

#                 if ltp >= first_tgt and trade.sold_quantity == 0 and current_qty > 0:
#                     executed_qty = place_order(smart_api, symbol, half_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     if trade.sold_quantity < half_qty:
#                         trade.status = 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}")

#                 elif ltp >= second_tgt and trade.sold_quantity == half_qty and current_qty > 0:
#                     executed_qty = place_order(smart_api, symbol, half_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     if trade.sold_quantity < trade.quantity:
#                         trade.status = 'PARTIAL'
#                     else:
#                         trade.status = 'CLOSED'
#                     db.session.commit()
#                     logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}")

#                 elif ltp >= final_tgt and current_qty > 0:
#                     executed_qty = place_order(smart_api, symbol, current_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     if trade.sold_quantity == trade.quantity:
#                         trade.status = 'CLOSED'
#                         db.session.commit()
#                         tm.sleep(7)
#                         new_qty = strategy_data.loc[0, 'Qnty']
#                         new_executed = place_order(smart_api, symbol, new_qty, ltp)
#                         if new_executed > 0:
#                             new_trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=base_price, 
#                                               quantity=new_executed, user_email=user.email, base_price=base_price)
#                             db.session.add(new_trade)
#                             db.session.commit()
#                             logger.info(f"Exit Final {symbol} at {ltp}, Restart at {ltp}, Qty: {new_executed}")
#                     else:
#                         trade.status = 'PARTIAL'
#                         db.session.commit()

#             if trade.status == 'PARTIAL' and ltp < entry_price:
#                 reentry_qty = trade.sold_quantity
#                 executed_qty = place_order(smart_api, symbol, reentry_qty, entry_price)
#                 if executed_qty > 0:
#                     trade.quantity += executed_qty
#                     trade.sold_quantity = 0
#                     trade.status = 'OPEN'
#                     db.session.commit()
#                     logger.info(f"Re-enter {symbol} at {entry_price}, Qty: {executed_qty}")

# def process_strategy(user, symbol, ltp, smart_api):
#     logger.log(logging.INFO, f"Process strategy for {symbol} at {ltp}")
#     # if not is_market_open():
#     #     logger.info(f"Market closed, skipping strategy for {symbol}")
#     #     return

#     with app.app_context():
#         trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
#         logger.log(logging.INFO, f"Trades for {symbol}: {trades}")
#         wallet_value = get_wallet_value(smart_api)
#         logger.log(logging.INFO, f"Trade status {symbol}: {trades[0].status if trades else None}")
        
#         if not any(t.status == 'OPEN' for t in trades):
#             base_price = ltp
#             logger.log(logging.INFO, f"Base price for {symbol} set to LTP: {base_price}")
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
#             qty = strategy_data.loc[0, 'Qnty']
#             executed_qty = place_order(smart_api, symbol, qty, ltp)
#             if executed_qty > 0:
#                 trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=ltp, quantity=int(executed_qty), 
#                               user_email=user.email, base_price=base_price)
#                 db.session.add(trade)
#                 db.session.commit()
#                 logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}")
#             else:
#                 logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
#             return

#         base_price = trades[0].base_price
#         strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
        
#         # Handle sells
#         for trade in trades:
#             if trade.status not in ['OPEN', 'PARTIAL']:
#                 logger.info(f"Skipping trade for {symbol} Sr.No {trade.sr_no} - Status: {trade.status}")
#                 continue
#             sr_no = trade.sr_no
#             logger.log(logging.INFO, f"Trade Sr.No for {symbol}: {sr_no}")
#             entry_price = trade.entry_price
#             logger.log(logging.INFO, f"Trade entry price for {symbol}: {entry_price}")
#             current_qty = trade.quantity - trade.sold_quantity
#             logger.log(logging.INFO, f"Current quantity for {symbol}: {current_qty}")
#             row = strategy_data.loc[sr_no-1]
#             logger.log(logging.INFO, f"Strategy row for {symbol} Sr.No {sr_no}: {row}")

#             if sr_no <= 8:
#                 target = row['FINAL_TGT']
#                 logger.log(logging.INFO, f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {target}")
#                 if ltp >= target and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {target}")
#                     executed_qty = place_order(smart_api, symbol, current_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                     if trade.sold_quantity == trade.quantity:
#                         trade.status = 'CLOSED'
#                         db.session.commit()
#                         logger.info(f"Trade CLOSED for {symbol} Sr.No {sr_no}")
#                         tm.sleep(7)
#                         new_qty = strategy_data.loc[0, 'Qnty']
#                         new_executed = int(place_order(smart_api, symbol, new_qty, ltp))
#                         if new_executed > 0:
#                             new_trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=ltp, 
#                                               quantity=int(new_executed), user_email=user.email, base_price=base_price)
#                             db.session.add(new_trade)
#                             db.session.commit()
#                             logger.info(f"Restarted {symbol} at {ltp}, Qty: {new_executed}, Sr.No: 1")
#                         else:
#                             logger.warning(f"Restart failed for {symbol} at {ltp}, Qty: {new_qty}")
#                     else:
#                         trade.status = 'PARTIAL'
#                         db.session.commit()
#                         logger.info(f"Trade PARTIAL for {symbol} Sr.No {sr_no}, Sold: {trade.sold_quantity}/{trade.quantity}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {target} or Qty {current_qty} <= 0")
#             else:
#                 first_tgt = row['First_TGT']
#                 second_tgt = row['Second_TGT']
#                 final_tgt = row['FINAL_TGT']
#                 half_qty = row['EXIT_1st_HALF']
#                 logger.log(logging.INFO, f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")

#                 if ltp >= first_tgt and trade.sold_quantity == 0 and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= First_TGT {first_tgt}")
#                     executed_qty = place_order(smart_api, symbol, half_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     trade.status = 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
#                 elif ltp >= second_tgt and trade.sold_quantity == half_qty and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= Second_TGT {second_tgt}")
#                     executed_qty = place_order(smart_api, symbol, half_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     trade.status = 'CLOSED' if trade.sold_quantity == trade.quantity else 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                 elif ltp >= final_tgt and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
#                     executed_qty = place_order(smart_api, symbol, current_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                     if trade.sold_quantity == trade.quantity:
#                         trade.status = 'CLOSED'
#                         db.session.commit()
#                         logger.info(f"Trade CLOSED for {symbol} Sr.No {sr_no}")
#                         tm.sleep(7)
#                         new_qty = strategy_data.loc[0, 'Qnty']
#                         new_executed = place_order(smart_api, symbol, new_qty, ltp)
#                         if new_executed > 0:
#                             new_trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=ltp, 
#                                               quantity=int(new_executed), user_email=user.email, base_price=base_price)
#                             db.session.add(new_trade)
#                             db.session.commit()
#                             logger.info(f"Restarted {symbol} at {ltp}, Qty: {new_executed}, Sr.No: 1")
#                         else:
#                             logger.warning(f"Restart failed for {symbol} at {ltp}, Qty: {new_qty}")
#                     else:
#                         trade.status = 'PARTIAL'
#                         db.session.commit()
#                         logger.info(f"Trade PARTIAL for {symbol} Sr.No {sr_no}, Sold: {trade.sold_quantity}/{trade.quantity}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets (First: {first_tgt}, Second: {second_tgt}, Final: {final_tgt}) or conditions not met")

#             # Re-entry logic
#             if trade.status == 'PARTIAL' and ltp < entry_price:
#                 logger.info(f"Re-entry condition met for {symbol} Sr.No {sr_no}: LTP {ltp} < Entry {entry_price}")
#                 reentry_qty = trade.sold_quantity
#                 executed_qty = place_order(smart_api, symbol, reentry_qty, ltp)
#                 if executed_qty > 0:
#                     trade.quantity += executed_qty
#                     trade.sold_quantity = 0
#                     trade.status = 'OPEN'
#                     db.session.commit()
#                     logger.info(f"Re-enter {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}")
#                 else:
#                     logger.warning(f"Re-entry failed for {symbol} at {ltp}, Qty: {reentry_qty}")

#         # Handle buys based on drop percentage
#         current_open_qty = sum(t.quantity - t.sold_quantity for t in trades if t.status in ['OPEN', 'PARTIAL'])
#         drop_percent = (ltp - base_price) / base_price
#         logger.log(logging.INFO, f"Drop percent for {symbol}: {drop_percent}")

#         if drop_percent <= -0.0025:  # 0.25% drop or more
#             valid_drops = strategy_data[strategy_data['DOWN'] <= drop_percent]
#             if not valid_drops.empty:
#                 target_row = valid_drops.iloc[-1]
#                 target_sr_no = int(target_row['Sr.No'])
#                 logger.info(f"Buy condition met for {symbol}: Drop {drop_percent} <= {target_row['DOWN']}, Target Sr.No: {target_sr_no}")
#                 if not any(t.sr_no == target_sr_no and t.status in ['OPEN', 'PARTIAL'] for t in trades):
#                     total_qty = target_row['Total_Qty']
#                     qty_to_buy = total_qty - current_open_qty
#                     if qty_to_buy > 0:
#                         executed_qty = place_order(smart_api, symbol, int(qty_to_buy), ltp)
#                         if executed_qty > 0:
#                             trade = Trade(stock_symbol=symbol, sr_no=target_sr_no, entry_price=ltp, 
#                                           quantity=int(executed_qty), user_email=user.email, base_price=base_price)
#                             db.session.add(trade)
#                             db.session.commit()
#                             logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}")
#                         else:
#                             logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}, Sr.No: {target_sr_no}")
#                     else:
#                         logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
#                 else:
#                     logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Trade already exists")
#             else:
#                 logger.info(f"No valid drop rows for {symbol} at drop {drop_percent}")
#         else:
#             logger.info(f"No buy for {symbol}: Drop {drop_percent} > -0.0025")

# def process_strategy(user, symbol, ltp, smart_api):
#     logger.log(logging.INFO, f"Process strategy for {symbol} at {ltp}")
#     if not is_market_open():
#         logger.info(f"Market closed, skipping strategy for {symbol}")
#         return

#     with app.app_context():
#         trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.id).all()  # Order by ID for latest trade
#         logger.log(logging.INFO, f"Trades for {symbol}: {trades}")
#         wallet_value = get_wallet_value(smart_api)
#         logger.log(logging.INFO, f"Trade status {symbol}: {trades[0].status if trades else None}")
        
#         # If no open trades, start fresh with LTP as base_price
#         if not any(t.status == 'OPEN' for t in trades):
#             base_price = ltp
#             logger.log(logging.INFO, f"Base price for {symbol} set to LTP: {base_price}")
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
#             logger.log(logging.INFO, f"Strategy data for {symbol}: {strategy_data}")
#             qty = strategy_data.loc[0, 'Qnty']
#             executed_qty = place_order(smart_api, symbol, qty, ltp)
#             if executed_qty > 0:
#                 trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=ltp, quantity=int(executed_qty), 
#                               user_email=user.email, base_price=ltp)  # Set base_price to LTP for new trade
#                 db.session.add(trade)
#                 db.session.commit()
#                 logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}")
#             else:
#                 logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
#             return

#         # Use the last trade's entry_price as base_price for drop calculation
#         last_trade = trades[-1]  # Last trade by ID (most recent)
#         base_price = last_trade.entry_price
#         logger.log(logging.INFO, f"Base price updated to last trade entry for {symbol}: {base_price}")
#         strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)  # Update strategy with new base_price
#         logger.log(logging.INFO, f"Strategy data for {symbol}: {strategy_data}")
        
#         # Handle sells
#         for trade in trades:
#             if trade.status not in ['OPEN', 'PARTIAL']:
#                 logger.info(f"Skipping trade for {symbol} Sr.No {trade.sr_no} - Status: {trade.status}")
#                 continue
#             sr_no = trade.sr_no
#             entry_price = trade.entry_price
#             current_qty = int(trade.quantity - trade.sold_quantity)
#             row = strategy_data.loc[sr_no-1]
#             logger.log(logging.INFO, f"Trade Sr.No {sr_no}, Entry {entry_price}, Qty {current_qty}, Row: {row}")

#             if sr_no <= 8:
#                 target = row['FINAL_TGT']
#                 logger.log(logging.INFO, f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {target}")
#                 if ltp >= target and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {target}")
#                     executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                     trade.sold_quantity += executed_qty
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                     if trade.sold_quantity == trade.quantity:
#                         trade.status = 'CLOSED'
#                         db.session.commit()
#                         logger.info(f"Trade CLOSED for {symbol} Sr.No {sr_no}")
#                         tm.sleep(7)
#                         new_qty = strategy_data.loc[0, 'Qnty']
#                         new_executed = int(place_order(smart_api, symbol, new_qty, ltp))
#                         if new_executed > 0:
#                             new_trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=ltp, 
#                                               quantity=new_executed, user_email=user.email, base_price=ltp)  # Update base_price
#                             db.session.add(new_trade)
#                             db.session.commit()
#                             logger.info(f"Restarted {symbol} at {ltp}, Qty: {new_executed}, Sr.No: 1")
#                         else:
#                             logger.warning(f"Restart failed for {symbol} at {ltp}, Qty: {new_qty}")
#                     # else:
#                     #     trade.status = 'PARTIAL'
#                     #     db.session.commit()
#                     #     logger.info(f"Trade PARTIAL for {symbol} Sr.No {sr_no}, Sold: {trade.sold_quantity}/{trade.quantity}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {target} or Qty {current_qty} <= 0")
#             else:
#                 first_tgt = row['First_TGT']
#                 second_tgt = row['Second_TGT']
#                 final_tgt = row['FINAL_TGT']
#                 half_qty = row['EXIT_1st_HALF']
#                 logger.log(logging.INFO, f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")

#                 if ltp >= first_tgt and trade.sold_quantity == 0 and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= First_TGT {first_tgt}")
#                     executed_qty = place_order(smart_api, symbol, half_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     trade.status = 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
#                 elif ltp >= second_tgt and trade.sold_quantity == half_qty and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= Second_TGT {second_tgt}")
#                     executed_qty = place_order(smart_api, symbol, half_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     trade.status = 'CLOSED' if trade.sold_quantity == trade.quantity else 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                 elif ltp >= final_tgt and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
#                     executed_qty = place_order(smart_api, symbol, current_qty, ltp, 'SELL')
#                     trade.sold_quantity += executed_qty
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                     if trade.sold_quantity == trade.quantity:
#                         trade.status = 'CLOSED'
#                         db.session.commit()
#                         logger.info(f"Trade CLOSED for {symbol} Sr.No {sr_no}")
#                         tm.sleep(7)
#                         new_qty = strategy_data.loc[0, 'Qnty']
#                         new_executed = int(place_order(smart_api, symbol, new_qty, ltp))
#                         if new_executed > 0:
#                             new_trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=ltp, 
#                                               quantity=new_executed, user_email=user.email, base_price=ltp)
#                             db.session.add(new_trade)
#                             db.session.commit()
#                             logger.info(f"Restarted {symbol} at {ltp}, Qty: {new_executed}, Sr.No: 1")
#                         else:
#                             logger.warning(f"Restart failed for {symbol} at {ltp}, Qty: {new_qty}")
#                     else:
#                         trade.status = 'PARTIAL'
#                         db.session.commit()
#                         logger.info(f"Trade PARTIAL for {symbol} Sr.No {sr_no}, Sold: {trade.sold_quantity}/{trade.quantity}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets (First: {first_tgt}, Second: {second_tgt}, Final: {final_tgt}) or conditions not met")

#             # Re-entry logic
#             if trade.status == 'PARTIAL' and ltp < entry_price:
#                 logger.info(f"Re-entry condition met for {symbol} Sr.No {sr_no}: LTP {ltp} < Entry {entry_price}")
#                 reentry_qty = trade.sold_quantity
#                 executed_qty = place_order(smart_api, symbol, reentry_qty, ltp)
#                 if executed_qty > 0:
#                     trade.quantity += executed_qty
#                     trade.sold_quantity = 0
#                     trade.status = 'OPEN'
#                     db.session.commit()
#                     logger.info(f"Re-enter {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}")
#                 else:
#                     logger.warning(f"Re-entry failed for {symbol} at {ltp}, Qty: {reentry_qty}")

#         # Handle buys based on drop from last trade's entry price
#         last_trade = trades[-1]  # Re-fetch last trade for consistency
#         base_price = last_trade.entry_price  # Use last trade's entry as base_price
#         # current_open_qty = sum(t.quantity - t.sold_quantity for t in trades if t.status in ['OPEN', 'PARTIAL'])
#         current_open_qty = sum(t.quantity - t.sold_quantity for t in trades if t.status in ['OPEN'])
#         drop_percent = (ltp - base_price) / base_price
#         logger.log(logging.INFO, f"Drop percent for {symbol} from {base_price}: {drop_percent}")

#         if drop_percent <= -0.0025:  # 0.25% drop or more
#             valid_drops = strategy_data[strategy_data['DOWN'] <= drop_percent]
#             if not valid_drops.empty:
#                 target_row = valid_drops.iloc[-1]
#                 target_sr_no = int(target_row['Sr.No'])
#                 logger.info(f"Buy condition met for {symbol}: Drop {drop_percent} <= {target_row['DOWN']}, Target Sr.No: {target_sr_no}")
#                 if not any(t.sr_no == target_sr_no and t.status in ['OPEN', 'PARTIAL'] for t in trades):
#                     total_qty = target_row['Total_Qty']
#                     qty_to_buy = total_qty - current_open_qty
#                     if qty_to_buy > 0:
#                         executed_qty = place_order(smart_api, symbol, int(qty_to_buy), ltp)
#                         if executed_qty > 0:
#                             trade = Trade(stock_symbol=symbol, sr_no=target_sr_no, entry_price=ltp, 
#                                           quantity=int(executed_qty), user_email=user.email, base_price=ltp)  # Update base_price
#                             db.session.add(trade)
#                             db.session.commit()
#                             logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}")
#                         else:
#                             logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}, Sr.No: {target_sr_no}")
#                     else:
#                         logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
#                 else:
#                     logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Trade already exists")
#             else:
#                 logger.info(f"No valid drop rows for {symbol} at drop {drop_percent}")
#         else:
#             logger.info(f"No buy for {symbol}: Drop {drop_percent} > -0.0025")

# def process_strategy(user, symbol, ltp, smart_api):
#     logger.log(logging.INFO, f"Process strategy for {symbol} at {ltp}")
#     if not is_market_open():
#         logger.info(f"Market closed, skipping strategy for {symbol}")
#         return

#     with app.app_context():
#         trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.id).all()
#         logger.log(logging.INFO, f"Trades for {symbol}: {trades}")
#         wallet_value = get_wallet_value(smart_api)
#         logger.log(logging.INFO, f"Trade status {symbol}: {trades[0].status if trades else None}")
        
#         if not any(t.status == 'OPEN' for t in trades):
#             base_price = ltp
#             logger.log(logging.INFO, f"Base price for {symbol} set to LTP: {base_price}")
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
#             qty = strategy_data.loc[0, 'Qnty']
#             executed_qty = place_order(smart_api, symbol, qty, ltp)
#             if executed_qty > 0:
#                 trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=ltp, quantity=int(executed_qty), 
#                               user_email=user.email, base_price=ltp)
#                 db.session.add(trade)
#                 db.session.commit()
#                 logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}")
#             else:
#                 logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
#             return

#         last_trade = trades[-1]
#         base_price = last_trade.entry_price
#         logger.log(logging.INFO, f"Base price updated to last trade entry for {symbol}: {base_price}")
#         strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)

#         # Handle sells (unchanged from your final code)
#         for trade in trades:
#             if trade.status not in ['OPEN', 'PARTIAL']:
#                 logger.info(f"Skipping trade for {symbol} Sr.No {trade.sr_no} - Status: {trade.status}")
#                 continue
#             sr_no = trade.sr_no
#             entry_price = trade.entry_price
#             current_qty = int(trade.quantity - trade.sold_quantity)
#             row = strategy_data.loc[sr_no-1]
#             logger.log(logging.INFO, f"Trade Sr.No {sr_no}, Entry {entry_price}, Qty {current_qty}, Row: {row}")

#             if sr_no <= 8:
#                 target = row['FINAL_TGT']
#                 logger.log(logging.INFO, f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {target}")
#                 if ltp >= target and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {target}")
#                     executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                     trade.sold_quantity += executed_qty
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                     if trade.sold_quantity == trade.quantity:
#                         trade.status = 'CLOSED'
#                         db.session.commit()
#                         logger.info(f"Trade CLOSED for {symbol} Sr.No {sr_no}")
#                         tm.sleep(7)
#                         new_qty = strategy_data.loc[0, 'Qnty']
#                         new_executed = int(place_order(smart_api, symbol, new_qty, ltp))
#                         if new_executed > 0:
#                             new_trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=ltp, 
#                                               quantity=new_executed, user_email=user.email, base_price=ltp)
#                             db.session.add(new_trade)
#                             db.session.commit()
#                             logger.info(f"Restarted {symbol} at {ltp}, Qty: {new_executed}, Sr.No: 1")
#                         else:
#                             logger.warning(f"Restart failed for {symbol} at {ltp}, Qty: {new_qty}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {target} or Qty {current_qty} <= 0")
#             else:
#                 first_tgt = row['First_TGT']
#                 second_tgt = row['Second_TGT']
#                 final_tgt = row['FINAL_TGT']
#                 half_qty = row['EXIT_1st_HALF']
#                 logger.log(logging.INFO, f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")

#                 if ltp >= first_tgt and trade.sold_quantity == 0 and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= First_TGT {first_tgt}")
#                     executed_qty = int(float(place_order(smart_api, symbol, half_qty, ltp, 'SELL')))
#                     trade.sold_quantity += executed_qty
#                     trade.status = 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
#                 elif ltp >= second_tgt and trade.sold_quantity == half_qty and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= Second_TGT {second_tgt}")
#                     executed_qty = int(float(place_order(smart_api, symbol, half_qty, ltp, 'SELL')))
#                     trade.sold_quantity += executed_qty
#                     trade.status = 'CLOSED' if trade.sold_quantity == trade.quantity else 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                 elif ltp >= final_tgt and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
#                     executed_qty = int(float(place_order(smart_api, symbol, current_qty, ltp, 'SELL')))
#                     trade.sold_quantity += executed_qty
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                     if trade.sold_quantity == trade.quantity:
#                         trade.status = 'CLOSED'
#                         db.session.commit()
#                         logger.info(f"Trade CLOSED for {symbol} Sr.No {sr_no}")
#                         tm.sleep(7)
#                         new_qty = strategy_data.loc[0, 'Qnty']
#                         new_executed = int(place_order(smart_api, symbol, new_qty, ltp))
#                         if new_executed > 0:
#                             new_trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=ltp, 
#                                               quantity=new_executed, user_email=user.email, base_price=ltp)
#                             db.session.add(new_trade)
#                             db.session.commit()
#                             logger.info(f"Restarted {symbol} at {ltp}, Qty: {new_executed}, Sr.No: 1")
#                         else:
#                             logger.warning(f"Restart failed for {symbol} at {ltp}, Qty: {new_qty}")
#                     else:
#                         trade.status = 'PARTIAL'
#                         db.session.commit()
#                         logger.info(f"Trade PARTIAL for {symbol} Sr.No {sr_no}, Sold: {trade.sold_quantity}/{trade.quantity}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets (First: {first_tgt}, Second: {second_tgt}, Final: {final_tgt}) or Qty {current_qty} <= 0")

#             if trade.status == 'PARTIAL' and ltp < entry_price:
#                 logger.info(f"Re-entry condition met for {symbol} Sr.No {sr_no}: LTP {ltp} < Entry {entry_price}")
#                 reentry_qty = trade.sold_quantity
#                 executed_qty = int(float(place_order(smart_api, symbol, reentry_qty, ltp)))
#                 if executed_qty > 0:
#                     trade.quantity += executed_qty
#                     trade.sold_quantity = 0
#                     trade.status = 'OPEN'
#                     db.session.commit()
#                     logger.info(f"Re-enter {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}")
#                 else:
#                     logger.warning(f"Re-entry failed for {symbol} at {ltp}, Qty: {reentry_qty}")

#         # Handle buys with closest drop match
#         last_trade = trades[-1]
#         base_price = last_trade.entry_price
#         current_open_qty = sum(int(t.quantity - t.sold_quantity) for t in trades if t.status in ['OPEN', 'PARTIAL'])
#         drop_percent = (ltp - base_price) / base_price
#         logger.log(logging.INFO, f"Drop percent for {symbol} from {base_price}: {drop_percent}")
        
#         if drop_percent <= -0.0025:
#             valid_drops = strategy_data[strategy_data['DOWN'] <= drop_percent]
#             logger.log(logging.INFO, f"Valid drop rows for {symbol} at drop {drop_percent}: {valid_drops}")
#             if not valid_drops.empty:
#                 # Find the row where DOWN is closest to drop_percent but still <=
#                 target_row = valid_drops.iloc[(valid_drops['DOWN'] - drop_percent).abs().idxmin()]
#                 logger.log(logging.INFO, f"Closest drop row for {symbol} at drop {drop_percent}: {target_row}")
#                 target_sr_no = int(target_row['Sr.No'])
#                 logger.info(f"Buy condition met for {symbol}: Drop {drop_percent} closest to {target_row['DOWN']}, Target Sr.No: {target_sr_no}")
#                 if not any(t.sr_no == target_sr_no and t.status in ['OPEN'] for t in trades):
#                     total_qty = int(target_row['Total_Qty'])
#                     qty_to_buy = total_qty - current_open_qty
#                     if qty_to_buy > 0:
#                         executed_qty = int(float(place_order(smart_api, symbol, qty_to_buy, ltp)))
#                         if executed_qty > 0:
#                             trade = Trade(stock_symbol=symbol, sr_no=target_sr_no, entry_price=ltp, 
#                                           quantity=executed_qty, user_email=user.email, base_price=ltp)
#                             db.session.add(trade)
#                             db.session.commit()
#                             logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}")
#                         else:
#                             logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}, Sr.No: {target_sr_no}")
#                     else:
#                         logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
#                 else:
#                     logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Trade already exists")
#             else:
#                 logger.info(f"No valid drop rows for {symbol} at drop {drop_percent}")
#         else:
#             logger.info(f"No buy for {symbol}: Drop {drop_percent} > -0.0025")

# def process_strategy(user, symbol, ltp, smart_api):
#     logger.log(logging.INFO, f"Process strategy for {symbol} at {ltp}")
#     if not is_market_open():
#         logger.info(f"Market closed, skipping strategy for {symbol}")
#         return

#     with app.app_context():
#         trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.id).all()
#         logger.log(logging.INFO, f"Trades for {symbol}: {trades}")
#         wallet_value = get_wallet_value(smart_api)
#         logger.log(logging.INFO, f"Trade status {symbol}: {trades[0].status if trades else None}")
        
#         if not any(t.status == 'OPEN' for t in trades):
#             base_price = ltp
#             logger.log(logging.INFO, f"Base price for {symbol} set to LTP: {base_price}")
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
#             qty = strategy_data.loc[0, 'Qnty']
#             executed_qty = place_order(smart_api, symbol, qty, ltp)
#             if executed_qty > 0:
#                 trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=ltp, quantity=int(executed_qty), 
#                               user_email=user.email, base_price=ltp)
#                 db.session.add(trade)
#                 db.session.commit()
#                 logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}")
#             else:
#                 logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
#             return

#         last_trade = trades[-1]
#         base_price = last_trade.entry_price
#         logger.log(logging.INFO, f"Base price updated to last trade entry for {symbol}: {base_price}")
#         strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)

#         # Handle sells
#         for trade in trades:
#             if trade.status not in ['OPEN', 'PARTIAL']:
#                 logger.info(f"Skipping trade for {symbol} Sr.No {trade.sr_no} - Status: {trade.status}")
#                 continue
#             sr_no = trade.sr_no
#             entry_price = trade.entry_price
#             current_qty = int(trade.quantity - trade.sold_quantity)
#             row = strategy_data.loc[sr_no-1]
#             logger.log(logging.INFO, f"Trade Sr.No {sr_no}, Entry {entry_price}, Qty {current_qty}, Row: {row}")

#             # Use trade's entry_price for targets, not row's Entry
#             final_tgt = entry_price * 1.015
#             if sr_no > 8:
#                 first_tgt = entry_price * 1.015
#                 second_tgt = entry_price * 1.02
#                 half_qty = current_qty / 2  # Based on actual quantity
#             else:
#                 first_tgt = second_tgt = None
#                 half_qty = 0

#             if sr_no <= 8:
#                 logger.log(logging.INFO, f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {final_tgt}")
#                 if ltp >= final_tgt and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
#                     executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                     trade.sold_quantity += executed_qty
#                     if trade.sold_quantity == trade.quantity:
#                         trade.status = 'CLOSED'
#                     db.session.commit()
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt} or Qty {current_qty} <= 0")
#             else:
#                 logger.log(logging.INFO, f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")
#                 if ltp >= first_tgt and trade.sold_quantity == 0 and current_qty > 0:
#                     executed_qty = int(float(place_order(smart_api, symbol, half_qty, ltp, 'SELL')))
#                     trade.sold_quantity += executed_qty
#                     trade.status = 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
#                 elif ltp >= second_tgt and trade.sold_quantity == half_qty and current_qty > 0:
#                     executed_qty = int(float(place_order(smart_api, symbol, half_qty, ltp, 'SELL')))
#                     trade.sold_quantity += executed_qty
#                     trade.status = 'CLOSED' if trade.sold_quantity == trade.quantity else 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
#                 elif ltp >= final_tgt and current_qty > 0:
#                     executed_qty = int(float(place_order(smart_api, symbol, current_qty, ltp, 'SELL')))
#                     trade.sold_quantity += executed_qty
#                     trade.status = 'CLOSED' if trade.sold_quantity == trade.quantity else 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

#         # Handle buys
#         last_trade = trades[-1]
#         base_price = last_trade.entry_price
#         current_open_qty = sum(int(t.quantity - t.sold_quantity) for t in trades if t.status in ['OPEN', 'PARTIAL'])
#         drop_percent = (ltp - base_price) / base_price
#         logger.log(logging.INFO, f"Drop percent for {symbol} from {base_price}: {drop_percent}")
        
#         if drop_percent <= -0.0025:
#             valid_drops = strategy_data[strategy_data['DOWN'] <= drop_percent]
#             logger.log(logging.INFO, f"Valid drop rows for {symbol} at drop {drop_percent}: {valid_drops}")
#             if not valid_drops.empty:
#                 target_idx = (valid_drops['DOWN'] - drop_percent).abs().idxmin()
#                 target_row = strategy_data.loc[target_idx]
#                 target_sr_no = int(target_row['Sr.No'])
#                 logger.info(f"Buy condition met for {symbol}: Drop {drop_percent} closest to {target_row['DOWN']}, Target Sr.No: {target_sr_no}")
#                 if not any(t.sr_no == target_sr_no and t.status in ['OPEN', 'PARTIAL'] for t in trades):
#                     total_qty = int(target_row['Total_Qty'])
#                     qty_to_buy = total_qty - current_open_qty
#                     if qty_to_buy > 0:
#                         executed_qty = int(float(place_order(smart_api, symbol, qty_to_buy, ltp)))
#                         if executed_qty > 0:
#                             trade = Trade(stock_symbol=symbol, sr_no=target_sr_no, entry_price=ltp, 
#                                           quantity=executed_qty, user_email=user.email, base_price=base_price)  # Keep original base_price
#                             db.session.add(trade)
#                             db.session.commit()
#                             logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}")
#                         else:
#                             logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}")
#             else:
#                 logger.info(f"No valid drop rows for {symbol} at drop {drop_percent}")
#         else:
#             logger.info(f"No buy for {symbol}: Drop {drop_percent} > -0.0025")

# def process_strategy(user, symbol, ltp, smart_api):
#     logger.log(logging.INFO, f"Process strategy for {symbol} at {ltp}")
#     if not is_market_open():
#         logger.info(f"Market closed, skipping strategy for {symbol}")
#         return

#     with app.app_context():
#         trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.id).all()
#         logger.log(logging.INFO, f"Trades for {symbol}: {trades}")
#         wallet_value = get_wallet_value(smart_api)
#         logger.log(logging.INFO, f"Trade status {symbol}: {trades[0].status if trades else None}")
        
#         if not any(t.status == 'OPEN' for t in trades):
#             base_price = ltp
#             logger.log(logging.INFO, f"Base price for {symbol} set to LTP: {base_price}")
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
#             qty = strategy_data.loc[0, 'Qnty']
#             executed_qty = place_order(smart_api, symbol, qty, ltp)
#             if executed_qty > 0:
#                 trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=ltp, quantity=int(executed_qty), 
#                               user_email=user.email, base_price=ltp)
#                 db.session.add(trade)
#                 db.session.commit()
#                 logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}")
#             else:
#                 logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
#             return

#         last_trade = trades[-1]
#         base_price = last_trade.entry_price
#         logger.log(logging.INFO, f"Base price updated to last trade entry for {symbol}: {base_price}")
#         strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)

#         # Handle sells
#         for trade in trades:
#             if trade.status not in ['OPEN', 'PARTIAL']:
#                 logger.info(f"Skipping trade for {symbol} Sr.No {trade.sr_no} - Status: {trade.status}")
#                 continue
#             sr_no = trade.sr_no
#             entry_price = trade.entry_price
#             current_qty = int(trade.quantity - trade.sold_quantity)
#             row = strategy_data.loc[sr_no-1]
#             logger.log(logging.INFO, f"Trade Sr.No {sr_no}, Entry {entry_price}, Qty {current_qty}, Row: {row}")

#             # Targets based on trade's entry_price
#             final_tgt = entry_price * 1.015
#             first_tgt = entry_price * 1.015 if sr_no > 8 else None
#             second_tgt = entry_price * 1.02 if sr_no > 21 else None  # Second_TGT only after Sr.No 21
#             half_qty = current_qty / 2 if sr_no > 8 else 0

#             if sr_no <= 8:
#                 logger.log(logging.INFO, f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {final_tgt}")
#                 if ltp >= final_tgt and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
#                     executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                     trade.sold_quantity += executed_qty
#                     if trade.sold_quantity == trade.quantity:
#                         trade.status = 'CLOSED'
#                     db.session.commit()
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
#             else:
#                 logger.log(logging.INFO, f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")
#                 if ltp >= first_tgt and trade.sold_quantity == 0 and current_qty > 0:
#                     executed_qty = int(float(place_order(smart_api, symbol, half_qty, ltp, 'SELL')))
#                     trade.sold_quantity += executed_qty
#                     trade.status = 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
#                 elif second_tgt and ltp >= second_tgt and trade.sold_quantity == half_qty and current_qty > 0:
#                     executed_qty = int(float(place_order(smart_api, symbol, half_qty, ltp, 'SELL')))
#                     trade.sold_quantity += executed_qty
#                     trade.status = 'CLOSED' if trade.sold_quantity == trade.quantity else 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
#                 elif ltp >= final_tgt and current_qty > 0:
#                     executed_qty = int(float(place_order(smart_api, symbol, current_qty, ltp, 'SELL')))
#                     trade.sold_quantity += executed_qty
#                     trade.status = 'CLOSED' if trade.sold_quantity == trade.quantity else 'PARTIAL'
#                     db.session.commit()
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

#         # Handle buys
#         last_trade = trades[-1]
#         base_price = last_trade.entry_price
#         current_open_qty = sum(int(t.quantity - t.sold_quantity) for t in trades if t.status in ['OPEN', 'PARTIAL'])
#         drop_percent = (ltp - base_price) / base_price
#         logger.log(logging.INFO, f"Drop percent for {symbol} from {base_price}: {drop_percent}")
        
#         if drop_percent <= -0.0025:
#             # Find the nearest DOWN value, not just <= drop_percent
#             target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
#             target_row = strategy_data.loc[target_idx]
#             target_sr_no = int(target_row['Sr.No'])
#             logger.log(logging.INFO, f"Closest drop row for {symbol} at drop {drop_percent}: {target_row}")
#             logger.info(f"Buy condition met for {symbol}: Drop {drop_percent} closest to {target_row['DOWN']}, Target Sr.No: {target_sr_no}")
#             if not any(t.sr_no == target_sr_no and t.status in ['OPEN', 'PARTIAL'] for t in trades):
#                 total_qty = int(target_row['Total_Qty'])
#                 qty_to_buy = total_qty - current_open_qty
#                 if qty_to_buy > 0:
#                     executed_qty = int(float(place_order(smart_api, symbol, qty_to_buy, ltp)))
#                     if executed_qty > 0:
#                         trade = Trade(stock_symbol=symbol, sr_no=target_sr_no, entry_price=ltp, 
#                                       quantity=executed_qty, user_email=user.email, base_price=base_price)
#                         db.session.add(trade)
#                         db.session.commit()
#                         logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}")
#                     else:
#                         logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}")
#                 else:
#                     logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
#             else:
#                 logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Trade already exists")
#         else:
#             logger.info(f"No buy for {symbol}: Drop {drop_percent} > -0.0025")
    

# def process_strategy(user, symbol, ltp, smart_api):
#     logger.log(logging.INFO, f"Process strategy for {symbol} at {ltp}")
#     if not is_market_open():
#         logger.info(f"Market closed, skipping strategy for {symbol}")
#         return

#     with app.app_context():
#         trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.id).all()
#         logger.log(logging.INFO, f"Trades for {symbol}: {trades}")
#         wallet_value = get_wallet_value(smart_api)
#         logger.log(logging.INFO, f"Trade status {symbol}: {trades[0].status if trades else None}")
        
#         if not any(t.status == 'OPEN' for t in trades):
#             base_price = ltp
#             logger.log(logging.INFO, f"Base price for {symbol} set to LTP: {base_price}")
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
#             qty = strategy_data.loc[0, 'Qnty']
#             executed_qty = place_order(smart_api, symbol, qty, ltp)
#             if executed_qty > 0:
#                 trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=ltp, quantity=int(executed_qty), 
#                               user_email=user.email, base_price=ltp, total_quantity=int(executed_qty))  # Added total_quantity for initial trade - Line 29
#                 db.session.add(trade)
#                 db.session.commit()
#                 logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}")
#             else:
#                 logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
#             return

#         last_trade = trades[-1]
#         base_price = last_trade.entry_price
#         logger.log(logging.INFO, f"Base price updated to last trade entry for {symbol}: {base_price}")
#         strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)

#         # Combined sell logic for total_quantity
#         total_quantity = sum(int(t.quantity - t.sold_quantity) for t in trades if t.status in ['OPEN', 'PARTIAL'])
#         reference_price = last_trade.entry_price  # Using last trade's entry as reference
#         combined_first_tgt = reference_price * 1.015  # 1.5% target
#         combined_half_qty = total_quantity // 2
#         if ltp >= combined_first_tgt and total_quantity > 0:
#             logger.info(f"Combined First_TGT condition met for {symbol}: LTP {ltp} >= First_TGT {combined_first_tgt}")
#             sold_shares = 0
#             for trade in trades:
#                 if trade.status in ['OPEN', 'PARTIAL']:
#                     current_qty = trade.quantity - trade.sold_quantity
#                     if current_qty > 0:
#                         qty_to_sell = min(current_qty, combined_half_qty - sold_shares)
#                         if qty_to_sell > 0:
#                             executed_qty = int(float(place_order(smart_api, symbol, qty_to_sell, ltp, 'SELL')))
#                             trade.sold_quantity += executed_qty
#                             sold_shares += executed_qty
#                             trade.status = 'CLOSED' if trade.sold_quantity == trade.quantity else 'PARTIAL'
#                             trade.total_quantity = total_quantity - executed_qty  # Update total_quantity after sell
#                             logger.info(f"Sold {executed_qty}/{qty_to_sell} from Trade {trade.id} at {ltp}")
#                     if sold_shares >= combined_half_qty:
#                         break
#             db.session.commit()
#             logger.info(f"Half combined sell completed for {symbol}: Sold {sold_shares}/{combined_half_qty}")
#             # Update total_quantity for remaining trades
#             remaining_total = total_quantity - sold_shares
#             for trade in trades:
#                 if trade.status in ['OPEN', 'PARTIAL']:
#                     trade.total_quantity = remaining_total
#             db.session.commit()
#         # Added combined sell logic for half of total_quantity - Insert before Line 36

#         # Handle sells
#         for trade in trades:
#             if trade.status not in ['OPEN', 'PARTIAL']:
#                 logger.info(f"Skipping trade for {symbol} Sr.No {trade.sr_no} - Status: {trade.status}")
#                 continue
#             sr_no = trade.sr_no
#             entry_price = trade.entry_price
#             current_qty = int(trade.quantity - trade.sold_quantity)
#             row = strategy_data.loc[sr_no-1]
#             logger.log(logging.INFO, f"Trade Sr.No {sr_no}, Entry {entry_price}, Qty {current_qty}, Row: {row}")

#             # Targets based on trade's entry_price
#             final_tgt = entry_price * 1.015
#             first_tgt = entry_price * 1.015 if sr_no > 8 else None
#             second_tgt = entry_price * 1.02 if sr_no > 21 else None  # Second_TGT only after Sr.No 21
#             half_qty = current_qty / 2 if sr_no > 8 else 0

#             if sr_no <= 8:
#                 logger.log(logging.INFO, f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {final_tgt}")
#                 if ltp >= final_tgt and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
#                     executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                     trade.sold_quantity += executed_qty
#                     if trade.sold_quantity == trade.quantity:
#                         trade.status = 'CLOSED'
#                     db.session.commit()
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
#             else:
#                 logger.log(logging.INFO, f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")
#                 if sr_no <= 21:  # Added condition for Sr.No 9-21 - Line 15
#                     if ltp >= first_tgt and trade.sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(float(place_order(smart_api, symbol, half_qty, ltp, 'SELL')))
#                         trade.sold_quantity += executed_qty
#                         trade.status = 'PARTIAL'  # Fixed status from CLOSED to PARTIAL - Line 19
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(float(place_order(smart_api, symbol, current_qty, ltp, 'SELL')))
#                         trade.sold_quantity += executed_qty
#                         trade.status = 'CLOSED' if trade.sold_quantity == trade.quantity else 'PARTIAL'
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
#                 else:  # Sr.No > 21
#                     if ltp >= first_tgt and trade.sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(float(place_order(smart_api, symbol, half_qty, ltp, 'SELL')))
#                         trade.sold_quantity += executed_qty
#                         trade.status = 'PARTIAL'  # Fixed status from CLOSED to PARTIAL - Line 32
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
#                     elif second_tgt and ltp >= second_tgt and trade.sold_quantity == half_qty and current_qty > 0:
#                         executed_qty = int(float(place_order(smart_api, symbol, half_qty, ltp, 'SELL')))
#                         trade.sold_quantity += executed_qty
#                         trade.status = 'CLOSED' if trade.sold_quantity == trade.quantity else 'PARTIAL'
#                         db.session.commit()
#                         logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(float(place_order(smart_api, symbol, current_qty, ltp, 'SELL')))
#                         trade.sold_quantity += executed_qty
#                         trade.status = 'CLOSED' if trade.sold_quantity == trade.quantity else 'PARTIAL'
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

#         # Handle buys
#         last_trade = trades[-1]
#         base_price = last_trade.entry_price
#         current_open_qty = sum(int(t.quantity - t.sold_quantity) for t in trades if t.status in ['OPEN'])
#         total_quantity = current_open_qty  # Calculate and set total_quantity for all trades - Insert after Line 71
#         for trade in trades:
#             if trade.status in ['OPEN']:
#                 trade.total_quantity = total_quantity
#         db.session.commit()
#         drop_percent = (ltp - base_price) / base_price
#         logger.log(logging.INFO, f"Drop percent for {symbol} from {base_price}: {drop_percent}")
        
#         if drop_percent <= -0.0025:
#             # Find the nearest DOWN value, not just <= drop_percent
#             target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
#             target_row = strategy_data.loc[target_idx]
#             target_sr_no = int(target_row['Sr.No'])
#             logger.log(logging.INFO, f"Closest drop row for {symbol} at drop {drop_percent}: {target_row}")
#             logger.info(f"Buy condition met for {symbol}: Drop {drop_percent} closest to {target_row['DOWN']}, Target Sr.No: {target_sr_no}")
#             if not any(t.sr_no == target_sr_no and t.status in ['OPEN'] for t in trades):
#                 total_qty = int(target_row['Total_Qty'])
#                 qty_to_buy = total_qty - current_open_qty
#                 if qty_to_buy > 0:
#                     executed_qty = int(float(place_order(smart_api, symbol, qty_to_buy, ltp)))
#                     if executed_qty > 0:
#                         new_total_quantity = current_open_qty + executed_qty
#                         trade = Trade(stock_symbol=symbol, sr_no=target_sr_no, entry_price=ltp, 
#                                       quantity=executed_qty, user_email=user.email, base_price=base_price, 
#                                       total_quantity=int(new_total_quantity))  # Added total_quantity to new trade - Line 85 (part 1)
#                         db.session.add(trade)
#                         # Update total_quantity for existing trades
#                         for t in trades:
#                             if t.status in ['OPEN']:
#                                 t.total_quantity = new_total_quantity
#                         db.session.commit()  # Added total_quantity update for existing trades - Line 85 (part 2)
#                         logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}")
#                     else:
#                         logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}")
#                 else:
#                     logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
#             else:
#                 logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Trade already exists")
#         else:
#             logger.info(f"No buy for {symbol}: Drop {drop_percent} > -0.0025")
# def process_strategy(user, symbol, ltp, smart_api):
#     logger.log(logging.INFO, f"Process strategy for {symbol} at {ltp}")
#     # if not is_market_open():
#     #     logger.info(f"Market closed, skipping strategy for {symbol}")
#     #     return

#     with app.app_context():
#         # Fetch or create a single trade for this stock and user
#         trade = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).first()
#         logger.log(logging.INFO, f"Trade for {symbol}: {trade}")
#         wallet_value = get_wallet_value(smart_api)
#         logger.log(logging.INFO, f"Trade status {symbol}: {trade.status if trade else None}")

#         if not trade or trade.status == 'CLOSED':
#             base_price = ltp
#             logger.log(logging.INFO, f"Base price for {symbol} set to LTP: {base_price}")
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
#             qty = strategy_data.loc[0, 'Qnty']
#             executed_qty = place_order(smart_api, symbol, qty, ltp)
#             if executed_qty > 0:
#                 trade = Trade(
#                     stock_symbol=symbol,
#                     sr_no=1,
#                     entry_price=ltp,
#                     quantity=int(executed_qty),
#                     user_email=user.email,
#                     base_price=ltp,
#                     total_quantity=int(executed_qty),  # Added total_quantity for initial trade - Line 23
#                     total_sold_quantity=0  # Initialize total_sold_quantity - Line 24 (added)
#                 )
#                 db.session.add(trade)
#                 db.session.commit()
#                 logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Total_Qty: {trade.total_quantity}")
#             else:
#                 logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
#             return

#         # Use the existing trade
#         base_price = trade.base_price
#         logger.log(logging.INFO, f"Base price updated to trade base price for {symbol}: {base_price}")
#         strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)

#         # Combined sell logic for total_quantity
#         current_open_qty = trade.total_quantity - trade.total_sold_quantity
#         reference_price = trade.entry_price  # Using trade's entry price as reference
#         combined_first_tgt = reference_price * 1.015  # 1.5% target
#         combined_half_qty = current_open_qty // 2
        
#         if ltp >= combined_first_tgt and current_open_qty > 0:
#             logger.info(f"Combined First_TGT condition met for {symbol}: LTP {ltp} >= First_TGT {combined_first_tgt}")
#             executed_qty = int(float(place_order(smart_api, symbol, combined_half_qty, ltp, 'SELL')))
#             trade.total_sold_quantity += executed_qty
#             trade.status = 'PARTIAL' if trade.total_sold_quantity < trade.total_quantity else 'CLOSED'
#             trade.last_updated = IST.localize(datetime.now())
#             db.session.commit()
#             logger.info(f"Half combined sell completed for {symbol}: Sold {executed_qty}/{combined_half_qty}, Total_Sold: {trade.total_sold_quantity}")
#         # Updated combined sell logic with total_sold_quantity - Insert before Line 36

#         # Handle individual sells (simplified to update single trade)
#         if trade.status in ['OPEN']:
#             sr_no = trade.sr_no
#             entry_price = trade.entry_price
#             current_qty = trade.total_quantity - trade.total_sold_quantity
#             row = strategy_data.loc[sr_no-1]
#             logger.log(logging.INFO, f"Trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

#             final_tgt = entry_price * 1.015
#             first_tgt = entry_price * 1.015 if sr_no > 8 else None
#             second_tgt = entry_price * 1.02 if sr_no > 21 else None
#             half_qty = current_qty / 2 if sr_no > 8 else 0

#             if sr_no <= 8:
#                 logger.log(logging.INFO, f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {final_tgt}")
#                 if ltp >= final_tgt and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
#                     executed_qty = int(place_order(smart_api, symbol, trade.total_quantity , ltp, 'SELL'))
#                     trade.total_sold_quantity += executed_qty
#                     trade.status = 'CLOSED' if trade.total_sold_quantity == trade.total_quantity else 'PARTIAL'
#                     trade.last_updated = IST.localize(datetime.now())
#                     db.session.commit()
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
#             else:
#                 logger.log(logging.INFO, f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")
#                 if sr_no <= 21:
#                     if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(float(place_order(smart_api, symbol, half_qty, ltp, 'SELL')))
#                         trade.total_sold_quantity += executed_qty
#                         trade.status = 'PARTIAL'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(float(place_order(smart_api, symbol, current_qty, ltp, 'SELL')))
#                         trade.total_sold_quantity += executed_qty
#                         trade.status = 'CLOSED' if trade.total_sold_quantity == trade.total_quantity else 'PARTIAL'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
#                 else:  # Sr.No > 21
#                     if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(float(place_order(smart_api, symbol, half_qty, ltp, 'SELL')))
#                         trade.total_sold_quantity += executed_qty
#                         trade.status = 'PARTIAL'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
#                     elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
#                         executed_qty = int(float(place_order(smart_api, symbol, half_qty, ltp, 'SELL')))
#                         trade.total_sold_quantity += executed_qty
#                         trade.status = 'CLOSED' if trade.total_sold_quantity == trade.total_quantity else 'PARTIAL'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(float(place_order(smart_api, symbol, current_qty, ltp, 'SELL')))
#                         trade.total_sold_quantity += executed_qty
#                         trade.status = 'CLOSED' if trade.total_sold_quantity == trade.total_quantity else 'PARTIAL'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

#         # Handle buys
#         current_open_qty = trade.total_quantity - trade.total_sold_quantity
#         logger.log(logging.INFO, f"Current open quantity for {symbol}: {current_open_qty}")
#         logger.log(logging.INFO, f"LTP for {symbol}: {ltp}")
#         drop_percent = (ltp - base_price) / base_price

#         logger.log(logging.INFO, f"Drop percent for {symbol} from {base_price}: {drop_percent}")
        
#         if drop_percent <= -0.0025 and trade.status in ['OPEN']:
#             target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
#             target_row = strategy_data.loc[target_idx]
#             target_sr_no = int(target_row['Sr.No'])
#             logger.log(logging.INFO, f"Closest drop row for {symbol} at drop {drop_percent}: {target_row}")
#             logger.info(f"Buy condition met for {symbol}: Drop {drop_percent} closest to {target_row['DOWN']}, Target Sr.No: {target_sr_no}")
#             total_qty = int(target_row['Total_Qty'])
#             qty_to_buy = total_qty - current_open_qty
#             if qty_to_buy > 0:
#                 executed_qty = int(float(place_order(smart_api, symbol, qty_to_buy, ltp)))
#                 if executed_qty > 0:
#                     trade.total_quantity += executed_qty
#                     trade.sr_no = target_sr_no  # Update sr_no to latest buy level
#                     trade.entry_price = ((trade.entry_price * (trade.total_quantity - executed_qty)) + (ltp * executed_qty)) / trade.total_quantity  # Weighted average entry price
#                     trade.last_updated = IST.localize(datetime.now())
#                     db.session.commit()
#                     logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {trade.total_quantity}")
#                 else:
#                     logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}")
#             else:
#                 logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
#         else:
#             logger.info(f"No buy for {symbol}: Drop {drop_percent} > -0.0025 or trade closed")
 
# def process_strategy(user, symbol, ltp, smart_api):
#     logger.log(logging.INFO, f"Process strategy for {symbol} at {ltp}")
    
#     with app.app_context():
#         # Fetch all trades for this stock and user, ordered by sr_no
#         trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
#         wallet_value = get_wallet_value(smart_api)

#         # Check for new buy condition first
#         latest_trade = trades[-1] if trades else None
#         base_price = latest_trade.base_price if latest_trade else ltp
#         strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
        
#         # Handle buy logic
#         if not trades or all(t.status in ['CLOSED', 'BUY_NEW'] for t in trades):
#             qty = strategy_data.loc[0, 'Qnty']
#             executed_qty = place_order(smart_api, symbol, qty, ltp)
#             if executed_qty > 0:
#                 sr_no = max([t.sr_no for t in trades], default=0) + 1
#                 new_trade = Trade(
#                     stock_symbol=symbol,
#                     sr_no=sr_no,
#                     entry_price=ltp,
#                     quantity=int(executed_qty),
#                     user_email=user.email,
#                     base_price=ltp,
#                     total_quantity=int(executed_qty),
#                     total_sold_quantity=0,
#                     status='OPEN',
#                     last_updated=IST.localize(datetime.now())
#                 )
#                 db.session.add(new_trade)
#                 db.session.commit()
#                 logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
#             else:
#                 logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
#             return
        
#         # Check for additional buy based on drop percentage
#         current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
#         drop_percent = (ltp - base_price) / base_price
#         logger.log(logging.INFO, f"Current open quantity for {symbol}: {current_open_qty}")
#         logger.log(logging.INFO, f"Drop percent for {symbol} from {base_price}: {drop_percent}")
        
#         if drop_percent <= -0.0025 and any(t.status == 'OPEN' for t in trades):
#             target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
#             target_row = strategy_data.loc[target_idx]
#             target_sr_no = int(target_row['Sr.No'])
#             total_qty = int(target_row['Total_Qty'])
#             qty_to_buy = total_qty - current_open_qty
            
#             if qty_to_buy > 0:
#                 executed_qty = int(float(place_order(smart_api, symbol, qty_to_buy, ltp)))
#                 if executed_qty > 0:
#                     for trade in trades[::-1]:
#                         if trade.status == 'OPEN':
#                             trade.status = 'BUY_NEW'
#                             trade.last_updated = IST.localize(datetime.now())
#                             break
                    
#                     new_trade = Trade(
#                         stock_symbol=symbol,
#                         sr_no=target_sr_no,
#                         entry_price=ltp,
#                         quantity=int(executed_qty),
#                         user_email=user.email,
#                         base_price=base_price,
#                         total_quantity=int(executed_qty),
#                         total_sold_quantity=0,
#                         status='OPEN',
#                         last_updated=IST.localize(datetime.now())
#                     )
#                     db.session.add(new_trade)
#                     db.session.commit()
#                     logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
#                 else:
#                     logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}")
#             else:
#                 logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
#         else:
#             logger.info(f"No buy for {symbol}: Drop {drop_percent} > -0.0025 or no open trades")

#         # Process sells for OPEN trades
#         for trade in trades:
#             if trade.status != 'OPEN':
#                 continue
            
#             base_price = trade.base_price
#             logger.log(logging.INFO, f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
            
#             sr_no = trade.sr_no
#             entry_price = trade.entry_price
#             current_qty = trade.total_quantity - trade.total_sold_quantity
#             row = strategy_data.loc[sr_no-1]
#             logger.log(logging.INFO, f"Trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

#             # Define sell targets
#             final_tgt = entry_price * 1.015  # 1.5% target
#             first_tgt = entry_price * 1.015 if sr_no > 8 else None
#             second_tgt = entry_price * 1.02 if sr_no > 21 else None
            
#             # Adjust half_qty for odd numbers: sell larger portion first
#             half_qty = ceil(current_qty / 2) if sr_no > 8 else 0  # Round up for first sell

#             if sr_no <= 8:
#                 logger.log(logging.INFO, f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {final_tgt}")
#                 if ltp >= final_tgt and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
#                     executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                     trade.total_sold_quantity += executed_qty
#                     if trade.total_sold_quantity >= trade.total_quantity:
#                         trade.status = 'CLOSED'
#                     trade.last_updated = IST.localize(datetime.now())
#                     db.session.commit()
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
#             else:
#                 logger.log(logging.INFO, f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")
#                 if sr_no <= 21:
#                     if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
#                 else:  # Sr.No > 21
#                     if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
#                         remaining_qty = current_qty  # Sell remaining at higher price
#                         executed_qty = int(place_order(smart_api, symbol, remaining_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{remaining_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

# def process_strategy(user, symbol, ltp, smart_api):
#     logger.log(logging.INFO, f"Process strategy for {symbol} at {ltp}")
    
#     with app.app_context():
#         # Fetch all trades for this stock and user, ordered by sr_no
#         trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
#         wallet_value = get_wallet_value(smart_api)

#         # Determine base price and latest trade
#         latest_trade = trades[-1] if trades else None
#         base_price = latest_trade.base_price if latest_trade else ltp
#         strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
        
#         # Handle initial buy if no trades or all are CLOSED/BUY_NEW
#         if not trades or all(t.status in ['CLOSED', 'BUY_NEW'] for t in trades):
#             qty = strategy_data.loc[0, 'Qnty']
#             executed_qty = place_order(smart_api, symbol, qty, ltp)
#             if executed_qty > 0:
#                 sr_no = max([t.sr_no for t in trades], default=0) + 1
#                 new_trade = Trade(
#                     stock_symbol=symbol,
#                     sr_no=sr_no,
#                     entry_price=ltp,
#                     quantity=int(executed_qty),
#                     user_email=user.email,
#                     base_price=ltp,
#                     total_quantity=int(executed_qty),
#                     total_sold_quantity=0,
#                     status='OPEN',
#                     last_updated=IST.localize(datetime.now())
#                 )
#                 db.session.add(new_trade)
#                 db.session.commit()
#                 logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
#             else:
#                 logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
#             return

#         # Determine the phase and drop increment based on the latest OPEN trade's sr_no
#         latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
#         current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1  # Default to 1 if no OPEN trades
#         phase_config = PhaseConfig.query.filter_by(
#             user_email=user.email,
#             stock_symbol=symbol
#         ).filter(
#             PhaseConfig.start_sr_no <= current_sr_no,
#             PhaseConfig.end_sr_no >= current_sr_no
#         ).first()

#         if not phase_config:
#             logger.warning(f"No phase config found for {symbol} with sr_no {current_sr_no}, defaulting to 0.25%")
#             down_increment = 0.0025  # Default fallback
#         else:
#             down_increment = phase_config.down_increment / 100  # Convert percentage to decimal (e.g., 0.25 -> 0.0025)
#             logger.log(logging.INFO, f"Phase {phase_config.phase} for {symbol}, Sr.No {current_sr_no}, Down Increment: {down_increment*100}%")

#         # Check for additional buy based on phase-specific drop percentage
#         current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
#         drop_percent = (ltp - base_price) / base_price
#         logger.log(logging.INFO, f"Current open quantity for {symbol}: {current_open_qty}")
#         logger.log(logging.INFO, f"Drop percent for {symbol} from {base_price}: {drop_percent}")
        
#         if drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades):
#             target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
#             target_row = strategy_data.loc[target_idx]
#             target_sr_no = int(target_row['Sr.No'])
#             total_qty = int(target_row['Total_Qty'])
#             qty_to_buy = total_qty - current_open_qty
            
#             if qty_to_buy > 0:
#                 executed_qty = int(float(place_order(smart_api, symbol, qty_to_buy, ltp)))
#                 if executed_qty > 0:
#                     # Mark the latest OPEN trade as BUY_NEW
#                     if latest_open_trade:
#                         latest_open_trade.status = 'BUY_NEW'
#                         latest_open_trade.last_updated = IST.localize(datetime.now())
                    
#                     # Create a new trade
#                     new_trade = Trade(
#                         stock_symbol=symbol,
#                         sr_no=target_sr_no,
#                         entry_price=ltp,
#                         quantity=int(executed_qty),
#                         user_email=user.email,
#                         base_price=base_price,
#                         total_quantity=int(executed_qty),
#                         total_sold_quantity=0,
#                         status='OPEN',
#                         last_updated=IST.localize(datetime.now())
#                     )
#                     db.session.add(new_trade)
#                     db.session.commit()
#                     logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
#                 else:
#                     logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}")
#             else:
#                 logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
#         else:
#             logger.info(f"No buy for {symbol}: Drop {drop_percent} > -{down_increment} or no open trades")

#         # Process sells for OPEN trades
#         for trade in trades:
#             if trade.status != 'OPEN':
#                 continue
            
#             base_price = trade.base_price
#             logger.log(logging.INFO, f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
            
#             sr_no = trade.sr_no
#             entry_price = trade.entry_price
#             current_qty = trade.total_quantity - trade.total_sold_quantity
#             row = strategy_data.loc[sr_no-1]
#             logger.log(logging.INFO, f"Trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

#             # Define sell targets
#             final_tgt = entry_price * 1.015  # 1.5% target
#             first_tgt = entry_price * 1.015 if sr_no > 8 else None
#             second_tgt = entry_price * 1.02 if sr_no > 21 else None
#             half_qty = ceil(current_qty / 2) if sr_no > 8 else 0  # Round up for first sell

#             if sr_no <= 8:
#                 logger.log(logging.INFO, f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {final_tgt}")
#                 if ltp >= final_tgt and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
#                     executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                     trade.total_sold_quantity += executed_qty
#                     if trade.total_sold_quantity >= trade.total_quantity:
#                         trade.status = 'CLOSED'
#                     trade.last_updated = IST.localize(datetime.now())
#                     db.session.commit()
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
#             else:
#                 logger.log(logging.INFO, f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")
#                 if sr_no <= 21:
#                     if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
#                 else:  # Sr.No > 21
#                     if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
#                         remaining_qty = current_qty
#                         executed_qty = int(place_order(smart_api, symbol, remaining_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{remaining_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")                      
         
# def process_strategy(user, symbol, ltp, smart_api):
#     logger.log(logging.INFO, f"Process strategy for {symbol} at {ltp}")
    
#     with app.app_context():
#         # Fetch all trades for this stock and user, ordered by sr_no
#         trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
#         wallet_value = get_wallet_value(smart_api)

#         # Determine base price and latest trade
#         latest_trade = trades[-1] if trades else None
#         base_price = latest_trade.base_price if latest_trade else ltp
#         strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
        
#         # Handle initial buy if no trades or all are CLOSED/BUY_NEW
#         if not trades or all(t.status in ['CLOSED', 'BUY_NEW'] for t in trades):
#             qty = strategy_data.loc[0, 'Qnty']
#             executed_qty = place_order(smart_api, symbol, qty, ltp)
#             if executed_qty > 0:
#                 sr_no = max([t.sr_no for t in trades], default=0) + 1
#                 new_trade = Trade(
#                     stock_symbol=symbol,
#                     sr_no=sr_no,
#                     entry_price=ltp,
#                     quantity=int(executed_qty),
#                     user_email=user.email,
#                     base_price=ltp,
#                     total_quantity=int(executed_qty),
#                     total_sold_quantity=0,
#                     status='OPEN',
#                     last_updated=IST.localize(datetime.now())
#                 )
#                 db.session.add(new_trade)
#                 db.session.commit()
#                 logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
#             else:
#                 logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
#             return

#         # Determine the phase and drop increment based on the latest OPEN trade's sr_no
#         latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
#         current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
#         phase_config = PhaseConfig.query.filter_by(
#             user_email=user.email,
#             stock_symbol=symbol
#         ).filter(
#             PhaseConfig.start_sr_no <= current_sr_no,
#             PhaseConfig.end_sr_no >= current_sr_no
#         ).first()

#         if not phase_config:
#             logger.warning(f"No phase config found for {symbol} with sr_no {current_sr_no}, defaulting to 0.25%")
#             down_increment = 0.0025
#         else:
#             down_increment = phase_config.down_increment / 100
#             logger.log(logging.INFO, f"Phase {phase_config.phase} for {symbol}, Sr.No {current_sr_no}, Down Increment: {down_increment*100}%")

#         # Check for additional buy based on phase-specific drop percentage
#         current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
#         drop_percent = (ltp - base_price) / base_price
#         logger.log(logging.INFO, f"Current open quantity for {symbol}: {current_open_qty}")
#         logger.log(logging.INFO, f"Drop percent for {symbol} from {base_price}: {drop_percent}")
        
#         if drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades):
#             target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
#             target_row = strategy_data.loc[target_idx]
#             target_sr_no = int(target_row['Sr.No'])
#             total_qty = int(target_row['Total_Qty'])
#             qty_to_buy = total_qty - current_open_qty
            
#             if qty_to_buy > 0:
#                 executed_qty = int(float(place_order(smart_api, symbol, qty_to_buy, ltp)))
#                 if executed_qty > 0:
#                     # Update the latest OPEN trade's total_quantity and mark as BUY_NEW
#                     if latest_open_trade:
#                         latest_open_trade.total_quantity = total_qty  # Update to target total qty
#                         latest_open_trade.status = 'BUY_NEW'
#                         latest_open_trade.last_updated = IST.localize(datetime.now())
#                         logger.info(f"Updated previous trade Sr.No {latest_open_trade.sr_no} to BUY_NEW, Total_Qty: {total_qty}")
                    
#                     # Create a new trade with the executed quantity and latest price
#                     new_trade = Trade(
#                         stock_symbol=symbol,
#                         sr_no=target_sr_no,
#                         entry_price=ltp,  # Reflect latest trade price
#                         quantity=int(executed_qty),
#                         user_email=user.email,
#                         base_price=base_price,  # Retain original base price for drop calc
#                         total_quantity=int(executed_qty),  # Only the new qty
#                         total_sold_quantity=0,
#                         status='OPEN',
#                         last_updated=IST.localize(datetime.now())
#                     )
#                     db.session.add(new_trade)
#                     db.session.commit()
#                     logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
#                 else:
#                     logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}")
#             else:
#                 logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
#         else:
#             logger.info(f"No buy for {symbol}: Drop {drop_percent} > -{down_increment} or no open trades")

#         # Process sells for OPEN trades
#         for trade in trades:
#             if trade.status != 'OPEN':
#                 continue
            
#             base_price = trade.base_price
#             logger.log(logging.INFO, f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
            
#             sr_no = trade.sr_no
#             entry_price = trade.entry_price
#             current_qty = trade.total_quantity - trade.total_sold_quantity
#             row = strategy_data.loc[sr_no-1]
#             logger.log(logging.INFO, f"Trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

#             # Define sell targets
#             final_tgt = entry_price * 1.015
#             first_tgt = entry_price * 1.015 if sr_no > 8 else None
#             second_tgt = entry_price * 1.02 if sr_no > 21 else None
#             half_qty = ceil(current_qty / 2) if sr_no > 8 else 0

#             if sr_no <= 8:
#                 logger.log(logging.INFO, f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {final_tgt}")
#                 if ltp >= final_tgt and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
#                     executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                     trade.total_sold_quantity += executed_qty
#                     if trade.total_sold_quantity >= trade.total_quantity:
#                         trade.status = 'CLOSED'
#                     trade.last_updated = IST.localize(datetime.now())
#                     db.session.commit()
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
#             else:
#                 logger.log(logging.INFO, f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")
#                 if sr_no <= 21:
#                     if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
#                 else:  # Sr.No > 21
#                     if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
#                         remaining_qty = current_qty
#                         executed_qty = int(place_order(smart_api, symbol, remaining_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{remaining_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
         
# def process_strategy(user, symbol, ltp, smart_api):
#     logger.log(logging.INFO, f"Process strategy for {symbol} at {ltp}")
    
#     with app.app_context():
#         # Fetch all trades for this stock and user, ordered by sr_no
#         trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
#         wallet_value = get_wallet_value(smart_api)

#         # Determine base price and latest trade
#         latest_trade = trades[-1] if trades else None
#         base_price = latest_trade.base_price if latest_trade else ltp
#         strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
        
#         # Handle initial buy if no trades or all are CLOSED/BUY_NEW
#         if not trades or all(t.status in ['CLOSED', 'BUY_NEW'] for t in trades):
#             qty = strategy_data.loc[0, 'Qnty']
#             executed_qty = place_order(smart_api, symbol, qty, ltp)
#             if executed_qty > 0:
#                 sr_no = max([t.sr_no for t in trades], default=0) + 1
#                 new_trade = Trade(
#                     stock_symbol=symbol,
#                     sr_no=sr_no,
#                     entry_price=ltp,
#                     quantity=int(executed_qty),
#                     user_email=user.email,
#                     base_price=ltp,
#                     total_quantity=int(executed_qty),
#                     total_sold_quantity=0,
#                     status='OPEN',
#                     last_updated=IST.localize(datetime.now())
#                 )
#                 db.session.add(new_trade)
#                 db.session.commit()
#                 logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
#             else:
#                 logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
#             return

#         # Determine the phase and drop increment based on the latest OPEN trade's sr_no
#         latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
#         current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
#         phase_config = PhaseConfig.query.filter_by(
#             user_email=user.email,
#             stock_symbol=symbol
#         ).filter(
#             PhaseConfig.start_sr_no <= current_sr_no,
#             PhaseConfig.end_sr_no >= current_sr_no
#         ).first()

#         if not phase_config:
#             logger.warning(f"No phase config found for {symbol} with sr_no {current_sr_no}, defaulting to 0.25%")
#             down_increment = 0.0025
#         else:
#             down_increment = phase_config.down_increment / 100
#             logger.log(logging.INFO, f"Phase {phase_config.phase} for {symbol}, Sr.No {current_sr_no}, Down Increment: {down_increment*100}%")

#         # Check for additional buy based on phase-specific drop percentage
#         current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
#         drop_percent = (ltp - base_price) / base_price
#         logger.log(logging.INFO, f"Current open quantity for {symbol}: {current_open_qty}")
#         logger.log(logging.INFO, f"Drop percent for {symbol} from {base_price}: {drop_percent}")
        
#         if drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades):
#             target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
#             target_row = strategy_data.loc[target_idx]
#             target_sr_no = int(target_row['Sr.No'])
#             total_qty = int(target_row['Total_Qty'])
#             qty_to_buy = total_qty - current_open_qty
            
#             # Check if an OPEN trade already exists for this target_sr_no
#             existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
#             if existing_open_trade:
#                 logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
#             elif qty_to_buy > 0:
#                 executed_qty = int(float(place_order(smart_api, symbol, qty_to_buy, ltp)))
#                 if executed_qty > 0:
#                     # Update the latest OPEN trade's total_quantity and mark as BUY_NEW
#                     if latest_open_trade:
#                         latest_open_trade.total_quantity = total_qty  # Update to target total qty
#                         latest_open_trade.status = 'BUY_NEW'
#                         latest_open_trade.last_updated = IST.localize(datetime.now())
#                         logger.info(f"Updated previous trade Sr.No {latest_open_trade.sr_no} to BUY_NEW, Total_Qty: {total_qty}")
                    
#                     # Create a new trade with the executed quantity and latest price
#                     new_trade = Trade(
#                         stock_symbol=symbol,
#                         sr_no=target_sr_no,
#                         entry_price=ltp,
#                         quantity=int(executed_qty),
#                         user_email=user.email,
#                         base_price=base_price,
#                         total_quantity=int(executed_qty),
#                         total_sold_quantity=0,
#                         status='OPEN',
#                         last_updated=IST.localize(datetime.now())
#                     )
#                     db.session.add(new_trade)
#                     db.session.commit()
#                     logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {target_sr_no}, Total_Qty: {new_trade.total_quantity}")
#                 else:
#                     logger.warning(f"Buy failed for {symbol} at {ltp}, Qty: {qty_to_buy}")
#             else:
#                 logger.info(f"No buy for {symbol} Sr.No {target_sr_no}: Qty to buy {qty_to_buy} <= 0")
#         else:
#             logger.info(f"No buy for {symbol}: Drop {drop_percent} > -{down_increment} or no open trades")

#         # Process sells for OPEN trades
#         for trade in trades:
#             if trade.status != 'OPEN':
#                 continue
            
#             base_price = trade.base_price
#             logger.log(logging.INFO, f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
            
#             sr_no = trade.sr_no
#             entry_price = trade.entry_price
#             current_qty = trade.total_quantity - trade.total_sold_quantity
#             row = strategy_data.loc[sr_no-1]
#             logger.log(logging.INFO, f"Trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

#             # Define sell targets
#             final_tgt = entry_price * 1.015
#             first_tgt = entry_price * 1.015 if sr_no > 8 else None
#             second_tgt = entry_price * 1.02 if sr_no > 21 else None
#             half_qty = ceil(current_qty / 2) if sr_no > 8 else 0

#             if sr_no <= 8:
#                 logger.log(logging.INFO, f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {final_tgt}")
#                 if ltp >= final_tgt and current_qty > 0:
#                     logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
#                     executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                     trade.total_sold_quantity += executed_qty
#                     if trade.total_sold_quantity >= trade.total_quantity:
#                         trade.status = 'CLOSED'
#                     trade.last_updated = IST.localize(datetime.now())
#                     db.session.commit()
#                     logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                 else:
#                     logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
#             else:
#                 logger.log(logging.INFO, f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")
#                 if sr_no <= 21:
#                     if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
#                 else:  # Sr.No > 21
#                     if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
#                         remaining_qty = current_qty
#                         executed_qty = int(place_order(smart_api, symbol, remaining_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{remaining_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                     elif ltp >= final_tgt and current_qty > 0:
#                         executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")                       

# # Configure logging to a single file
# logging.basicConfig(
#     filename='trading_strategy.log',  # All logs go to this file
#     level=logging.INFO,               # Log INFO and above (INFO, WARNING, ERROR)
#     format='%(asctime)s - %(levelname)s - %(message)s',  # Timestamp, level, message
#     datefmt='%Y-%m-%d %H:%M:%S'       # Readable date format
# )

# logger = logging.getLogger(__name__)
# IST = pytz.timezone('Asia/Kolkata')

# def process_strategy(user, symbol, ltp, smart_api):
#     logger.info(f"Process strategy for {symbol} at {ltp}")
    
#     with app.app_context():
#         try:
#             # Fetch all trades for this stock and user, ordered by sr_no
#             trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email).order_by(Trade.sr_no).all()
#             wallet_value = get_wallet_value(smart_api)

#             # Determine base price and latest trade
#             latest_trade = trades[-1] if trades else None
#             base_price = latest_trade.base_price if latest_trade else ltp
#             strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
            
#             # Handle initial buy if no trades or all are CLOSED/BUY_NEW
#             if not trades or all(t.status in ['CLOSED', 'BUY_NEW'] for t in trades):
#                 qty = strategy_data.loc[0, 'Qnty']
#                 executed_qty = place_order(smart_api, symbol, qty, ltp)
#                 time.sleep(1)  # Wait for order to execute
#                 logger.info(f"Initial buy for {symbol} at {ltp}, Qty: {qty}, Executed Qty: {executed_qty}")
#                 if executed_qty > 0:
#                     sr_no = max([t.sr_no for t in trades], default=0)  # Increment sr_no for new buy
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
#                         last_updated=IST.localize(datetime.now())
#                     )
                    
#                     db.session.add(new_trade)
#                     db.session.commit()
#                     logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}, Total_Qty: {new_trade.total_quantity}")
#                 else:
#                     logger.warning(f"Initial buy failed for {symbol} at {ltp}, Qty: {qty}")
#                 return

#             # Determine the phase and drop increment based on the latest OPEN trade's sr_no
#             latest_open_trade = next((t for t in trades[::-1] if t.status == 'OPEN'), None)
#             current_sr_no = latest_open_trade.sr_no if latest_open_trade else 1
#             phase_config = PhaseConfig.query.filter_by(
#                 user_email=user.email,
#                 stock_symbol=symbol
#             ).filter(
#                 PhaseConfig.start_sr_no <= current_sr_no,
#                 PhaseConfig.end_sr_no >= current_sr_no
#             ).first()

#             if not phase_config:
#                 logger.warning(f"No phase config found for {symbol} with sr_no {current_sr_no}, defaulting to 0.25%")
#                 down_increment = 0.0025
#             else:
#                 down_increment = phase_config.down_increment / 100
#                 logger.info(f"Phase {phase_config.phase} for {symbol}, Sr.No: {current_sr_no}, Down Increment: {down_increment*100}%")

#             # Check for additional buy based on phase-specific drop percentage
#             current_open_qty = sum(t.total_quantity - t.total_sold_quantity for t in trades if t.status == 'OPEN')
#             drop_percent = (ltp - base_price) / base_price
#             logger.info(f"Current open quantity for {symbol}: {current_open_qty}")
#             logger.info(f"Drop percent for {symbol} from {base_price}: {drop_percent}")
            
#             if drop_percent <= -down_increment and any(t.status == 'OPEN' for t in trades):
#                 target_idx = (strategy_data['DOWN'] - drop_percent).abs().idxmin()
#                 target_row = strategy_data.loc[target_idx]
#                 target_sr_no = int(target_row['Sr.No'])
#                 total_qty = int(target_row['Total_Qty'])
#                 qty_to_buy = total_qty - current_open_qty
                
#                 # Check if an OPEN trade already exists for this target_sr_no
#                 existing_open_trade = next((t for t in trades if t.status == 'OPEN' and t.sr_no == target_sr_no), None)
#                 if existing_open_trade:
#                     logger.info(f"Skipping buy for {symbol}: OPEN trade already exists for Sr.No {target_sr_no}")
#                 elif qty_to_buy > 0:
#                     executed_qty = int(float(place_order(smart_api, symbol, qty_to_buy, ltp)))
#                     if executed_qty > 0:
#                         # Update the latest OPEN trade's total_quantity and mark as BUY_NEW
#                         if latest_open_trade:
#                             latest_open_trade.total_quantity = total_qty
#                             latest_open_trade.status = 'BUY_NEW'
#                             latest_open_trade.last_updated = IST.localize(datetime.now())
#                             logger.info(f"Updated previous trade Sr.No {latest_open_trade.sr_no} to BUY_NEW, Total_Qty: {total_qty}")
                        
#                         # Create a new trade with the target_sr_no (only on buy)
#                         new_trade = Trade(
#                             stock_symbol=symbol,
#                             sr_no=target_sr_no,  # Use target_sr_no for new buy
#                             entry_price=ltp,
#                             quantity=int(executed_qty),
#                             user_email=user.email,
#                             base_price=base_price,
#                             total_quantity=int(executed_qty),
#                             total_sold_quantity=0,
#                             status='OPEN',
#                             last_updated=IST.localize(datetime.now())
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

#             # Process sells for OPEN trades (no sr_no change on sell)
#             all_closed = True  # Track if all trades are closed for cycle reset
#             for trade in trades:
#                 if trade.status != 'OPEN':
#                     continue
#                 all_closed = False  # At least one trade is still OPEN
                
#                 base_price = trade.base_price
#                 logger.info(f"Processing trade for {symbol} Sr.No {trade.sr_no} with base price: {base_price}")
#                 strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
                
#                 sr_no = trade.sr_no  # Keep sr_no unchanged during sell
#                 entry_price = trade.entry_price
#                 current_qty = trade.total_quantity - trade.total_sold_quantity
#                 row = strategy_data.loc[sr_no-1]
#                 logger.info(f"Trade Sr.No {sr_no}, Entry {entry_price}, Current_Qty {current_qty}, Row: {row}")

#                 # Define sell targets
#                 final_tgt = entry_price * 1.015
#                 first_tgt = entry_price * 1.015 if sr_no > 8 else None
#                 second_tgt = entry_price * 1.02 if sr_no > 21 else None
#                 half_qty = ceil(current_qty / 2) if sr_no > 8 else 0

#                 if sr_no <= 8:
#                     logger.info(f"Target (FINAL_TGT) for {symbol} Sr.No {sr_no}: {final_tgt}")
#                     if ltp >= final_tgt and current_qty > 0:
#                         logger.info(f"Exit condition met for {symbol} Sr.No {sr_no}: LTP {ltp} >= FINAL_TGT {final_tgt}")
#                         executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                         trade.total_sold_quantity += executed_qty
#                         if trade.total_sold_quantity >= trade.total_quantity:
#                             trade.status = 'CLOSED'
#                         trade.last_updated = IST.localize(datetime.now())
#                         db.session.commit()
#                         logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                     else:
#                         logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < FINAL_TGT {final_tgt}")
#                 else:
#                     logger.info(f"Targets for {symbol} Sr.No {sr_no}: First_TGT={first_tgt}, Second_TGT={second_tgt}, FINAL_TGT={final_tgt}, Half_Qty={half_qty}")
#                     if sr_no <= 21:
#                         if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                             executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
#                             trade.total_sold_quantity += executed_qty
#                             if trade.total_sold_quantity >= trade.total_quantity:
#                                 trade.status = 'CLOSED'
#                             trade.last_updated = IST.localize(datetime.now())
#                             db.session.commit()
#                             logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                         elif ltp >= final_tgt and current_qty > 0:
#                             executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                             trade.total_sold_quantity += executed_qty
#                             if trade.total_sold_quantity >= trade.total_quantity:
#                                 trade.status = 'CLOSED'
#                             trade.last_updated = IST.localize(datetime.now())
#                             db.session.commit()
#                             logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                         else:
#                             logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")
#                     else:  # Sr.No > 21
#                         if ltp >= first_tgt and trade.total_sold_quantity == 0 and current_qty > 0:
#                             executed_qty = int(place_order(smart_api, symbol, half_qty, ltp, 'SELL'))
#                             trade.total_sold_quantity += executed_qty
#                             if trade.total_sold_quantity >= trade.total_quantity:
#                                 trade.status = 'CLOSED'
#                             trade.last_updated = IST.localize(datetime.now())
#                             db.session.commit()
#                             logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{half_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                         elif second_tgt and ltp >= second_tgt and trade.total_sold_quantity == half_qty and current_qty > 0:
#                             remaining_qty = current_qty
#                             executed_qty = int(place_order(smart_api, symbol, remaining_qty, ltp, 'SELL'))
#                             trade.total_sold_quantity += executed_qty
#                             if trade.total_sold_quantity >= trade.total_quantity:
#                                 trade.status = 'CLOSED'
#                             trade.last_updated = IST.localize(datetime.now())
#                             db.session.commit()
#                             logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{remaining_qty}, Sr.No {sr_no}, Status: {trade.status}")
#                         elif ltp >= final_tgt and current_qty > 0:
#                             executed_qty = int(place_order(smart_api, symbol, current_qty, ltp, 'SELL'))
#                             trade.total_sold_quantity += executed_qty
#                             if trade.total_sold_quantity >= trade.total_quantity:
#                                 trade.status = 'CLOSED'
#                             trade.last_updated = IST.localize(datetime.now())
#                             db.session.commit()
#                             logger.info(f"Sold {executed_qty}/{current_qty} for {symbol} Sr.No {sr_no} at {ltp}, Status: {trade.status}")
#                         else:
#                             logger.info(f"No exit for {symbol} Sr.No {sr_no}: LTP {ltp} < Targets")

#             # Reset cycle if all trades are CLOSED (full target achieved)
#             if all_closed and trades:
#                 logger.info(f"All trades for {symbol} are CLOSED, resetting cycle to Sr.No 1")
#                 # Next buy will start at sr_no=1 (handled by initial buy logic)

#         except Exception as e:
#             logger.error(f"Error in process_strategy for {symbol}: {str(e)}")
#             db.session.rollback()
#         finally:
#             db.session.close()                        



# Configure logging to a single file