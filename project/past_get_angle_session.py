# def get_angel_session(user):
#     """Get or generate a valid Angel One session for the user."""
#     user_email = user.email
#     current_time = datetime.now()

#     if (user_email in session_cache and 
#         'smart_api' in session_cache[user_email] and 
#         session_cache[user_email]['expires_at'] > current_time):
#         logger.info(f"Reusing existing session for {user_email}")
#         return session_cache[user_email]['smart_api']

#     try:
#         if not all([user.smartapi_key, user.smartapi_username, user.smartapi_password, user.smartapi_totp_token]):
#             raise Exception("Angel One credentials not set for this user")

#         smart_api = SmartConnect(user.smartapi_key)
#         totp = pyotp.TOTP(user.smartapi_totp_token).now()
#         data = smart_api.generateSession(user.smartapi_username, user.smartapi_password, totp)
        
#         logging.info(f"🔐 Angel One Session Data: {data}")

#         if data['status'] == False:
#             raise Exception(f"Angel One session generation failed: {data['message']}")

#         auth_token = data['data']['jwtToken']
#         refresh_token = data['data']['refreshToken']
#         feed_token = smart_api.getfeedToken()

#         expires_at = current_time + timedelta(hours=24)

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
