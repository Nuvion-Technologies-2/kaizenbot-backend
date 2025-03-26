   
# @socketio.on('stream_connect', namespace='/stream')
# def start_websocket_stream(user):
#     user_email = user.email
#     try:
#         with app.app_context():  # Add context for initial setup
#             smart_api = get_angel_session(user)
#             auth_token = session_cache[user_email]['auth_token']
#             feed_token = session_cache[user_email]['feed_token']
#             api_key = user.smartapi_key
#             client_code = user.smartapi_username

#             stocks = Stock.query.filter_by(user_id=user.id).all()
#             if not stocks:
#                 emit('stock_stream', {'message': 'No stocks subscribed', 'data': []}, namespace='/stream', to=user_email)
#                 return

#             token_map = {1: [], 3: []}
#             for stock in stocks:
#                 exchange_type = 1 if stock.exchange == "NSE" else 3
#                 token_map[exchange_type].append(stock.symboltoken)

#             token_list = [{"exchangeType": et, "tokens": tokens} for et, tokens in token_map.items() if tokens]
#             correlation_id = f"stream_{user_email}"
#             mode = 3

#             sws = SmartWebSocketV2(auth_token, api_key, client_code, feed_token, 
#                                    max_retry_attempt=2, retry_strategy=0, retry_delay=10, retry_duration=30)


#             def on_data(wsapp, message):
#                 total_sell_quantity = message.get('total_sell_quantity')
#                 total_buy_quantity = message.get('total_buy_quantity')
#                 high_price_of_the_day = message.get('high_price_of_the_day', 0) / 100
#                 low_price_of_the_day = message.get('low_price_of_the_day',0) / 100
#                 volume_trade_for_the_day = message.get('volume_trade_for_the_day')
#                 open_price = message.get('open_price_of_the_day',0) / 100
#                 week_high = message.get('52_week_high_price',0) / 100
#                 week_low = message.get('52_week_low_price', 0) / 100
#                 token = message.get('token')
#                 ltp = message.get('last_traded_price', 0) / 100
#                 with app.app_context():
#                     stock = Stock.query.filter_by(symboltoken=token).first()
#                     if stock:
#                         message['name'] = stock.tradingsymbol
#                         message['total_sell_quantity'] = total_sell_quantity
#                         message['total_buy_quantity'] = total_buy_quantity
#                         message['high_price_of_the_day'] = high_price_of_the_day
#                         message['low_price_of_the_day'] = low_price_of_the_day
#                         message['volume_trade_for_the_day'] = volume_trade_for_the_day
#                         message['open_price'] = open_price
#                         message['week_high'] = week_high
#                         message['week_low'] = week_low
#                         live_prices[token] = {'price': ltp, 'name': stock.tradingsymbol, 'total_sell_quantity': total_sell_quantity, 'total_buy_quantity': total_buy_quantity, 'high_price_of_the_day': high_price_of_the_day, 'low_price_of_the_day': low_price_of_the_day, 'volume_trade_for_the_day': volume_trade_for_the_day, 'open_price': open_price, 'week_high': week_high, 'week_low': week_low}
#                         try:
#                             logger.debug(f"Processing strategy for {stock.tradingsymbol} with LTP={ltp}")
#                             process_strategy(user, stock.tradingsymbol, ltp, smart_api)
#                         except Exception as e:
#                             logger.error(f"Error in process_strategy for {stock.tradingsymbol}: {str(e)}")
#                             raise  # Re-raise to ensure WebSocket logs the full error
#                         socketio.emit('stock_stream', {'message': 'New tick', 'data': message}, 
#                                      namespace='/stream', to=user_email)
            
                        
#             def on_open(wsapp):
#                 sws.subscribe(correlation_id, mode, token_list)

#             def on_error(wsapp, error):
#                 with websocket_lock:
#                     if user_email in websocket_clients:
#                         del websocket_clients[user_email]
#                         thread = threading.Thread(target=start_websocket_stream, args=(user,))
#                         thread.daemon = True
#                         thread.start()

#             def on_close(wsapp, code=None, reason=None):
#                 with websocket_lock:
#                     if user_email in websocket_clients:
#                         del websocket_clients[user_email]

#             sws.on_open = on_open
#             sws.on_data = on_data
#             sws.on_error = on_error
#             sws.on_close = on_close

#             with websocket_lock:
#                 if user_email in websocket_clients:
#                     websocket_clients[user_email].close_connection()
#                 websocket_clients[user_email] = sws

#             sws.connect()

#     except Exception as e:
#         logger.error(f"WebSocket Setup Error for {user_email}: {str(e)}")
#         with app.app_context():  # Add context for emit in except block
#             socketio.emit('stock_stream', {'message': 'WebSocket setup failed', 'error': str(e)}, 
#                           namespace='/stream', to=user_email)

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
