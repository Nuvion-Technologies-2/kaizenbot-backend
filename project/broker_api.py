from SmartApi.smartConnect import SmartConnect
import pyotp
from datetime import datetime, timedelta
from flask import current_app
import logging
from models import AngelSession, db
import json

logger = logging.getLogger(__name__)

class BrokerAPI:
    def __init__(self):
        self.smart_api = None
        self.session_cache = {}

    def get_session(self, user):
        user_email = user.email
        current_time = datetime.now()

        if (user_email in self.session_cache and 
            self.session_cache[user_email]['expires_at'] > current_time):
            logger.info(f"Reusing existing session for {user_email}")
            return self.session_cache[user_email]['smart_api']

        if not all([user.smartapi_key, user.smartapi_username, user.smartapi_password, user.smartapi_totp_token]):
            raise Exception("Angel One credentials not set for this user")

        self.smart_api = SmartConnect(user.smartapi_key)
        totp = pyotp.TOTP(user.smartapi_totp_token).now()
        data = self.smart_api.generateSession(user.smartapi_username, user.smartapi_password, totp)

        if data['status'] is False:
            raise Exception(f"Session generation failed: {data['message']}")

        auth_token = data['data']['jwtToken']
        refresh_token = data['data']['refreshToken']
        feed_token = self.smart_api.getfeedToken()

        expires_at = current_time + timedelta(hours=24)

        session = AngelSession(
            user_id=user.id,
            auth_token=auth_token,
            refresh_token=refresh_token,
            feed_token=feed_token,
            expires_at=expires_at
        )
        db.session.add(session)
        db.session.commit()

        self.session_cache[user_email] = {
            'smart_api': self.smart_api,
            'auth_token': auth_token,
            'refresh_token': refresh_token,
            'feed_token': feed_token,
            'expires_at': expires_at
        }
        return self.smart_api

    def refresh_session(self, user):
        user_email = user.email
        if user_email not in self.session_cache or 'refresh_token' not in self.session_cache[user_email]:
            return self.get_session(user)

        self.smart_api = SmartConnect(user.smartapi_key)
        refresh_token = self.session_cache[user_email]['refresh_token']
        data = self.smart_api.generateToken(refresh_token)

        if data['status'] is False:
            return self.get_session(user)

        auth_token = data['data']['jwtToken']
        feed_token = data['data']['feedToken']
        expires_at = datetime.now() + timedelta(hours=24)

        session = AngelSession.query.filter_by(user_id=user.id).first()
        session.auth_token = auth_token
        session.feed_token = feed_token
        session.expires_at = expires_at
        db.session.commit()

        self.session_cache[user_email] = {
            'smart_api': self.smart_api,
            'auth_token': auth_token,
            'refresh_token': refresh_token,
            'feed_token': feed_token,
            'expires_at': expires_at
        }
        return self.smart_api

    def start_websocket(self, user, stock_symbols, callback):
        smart_api = self.get_session(user)
        feed_token = self.session_cache[user.email]['feed_token']
        from SmartApi import SmartWebSocket
        ws = SmartWebSocket(feed_token, smart_api._host, user.smartapi_key)
        def on_message(ws, message):
            data = json.loads(message)
            callback(data)
        def on_open(ws):
            for symbol in stock_symbols:
                ws.subscribe(exchange=stock_symbols[symbol]['exchange'], token=stock_symbols[symbol]['symboltoken'])
        ws.on_message = on_message
        ws.on_open = on_open
        ws.connect()
        return ws

broker = BrokerAPI()