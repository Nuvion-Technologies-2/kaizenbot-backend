import json
import pandas as pd
from datetime import datetime, time
import pytz
from models import Strategy, Position, Order, db
import threading
import time as time_module
from flask import current_app
from models import User, Stock
from broker_api import broker
from project.app import add_log
IST = pytz.timezone("Asia/Kolkata")

class TradingStrategy:
    def __init__(self):
        self.is_trading_paused = False
        self.thread_lock = threading.Lock()
        self.strategies = {}
        self.load_strategy_from_excel()

    def load_strategy_from_excel(self):
        df = pd.read_excel('data/strategy.xlsx')
        for index, row in df.iterrows():
            strategy = Strategy(
                sr_no=int(row['Sr.No']),
                entry_price=float(row['Entry']),
                retracement_percent=float(row['Rtrcmnt Entry %']),
                down_percent=float(row['DOWN']),
                quantity=int(row['Qnty']),
                first_target=float(row['First_TGT 1.50%']) if pd.notna(row['First_TGT 1.50%']) else None,
                first_exit_quantity=int(row['EXIT_1st_HALF Quantity']) if pd.notna(row['EXIT_1st_HALF Quantity']) else None,
                second_target=float(row['Second_TGT']) if pd.notna(row['Second_TGT']) else None,
                second_exit_quantity=int(row['EXIT_2nd_HALF Quantity']) if pd.notna(row['EXIT_2nd_HALF Quantity']) else None,
                final_target=float(row['FINAL_TGT 1.50%']),
                final_target_percent=float(row['Final_TGT AWAY %'])
            )
            db.session.add(strategy)
        db.session.commit()
        self.strategies = {s.sr_no: s for s in Strategy.query.all()}

    def is_market_hours(self):
        now = datetime.now(IST).time()
        market_open = current_app.config['MARKET_OPEN_TIME']
        market_close = current_app.config['MARKET_CLOSE_TIME']
        return market_open <= now <= market_close

    def execute_trade(self, user_id, stock_id, cmp):
        if self.is_trading_paused or not self.is_market_hours():
            return

        position = Position.query.filter_by(user_id=user_id, stock_id=stock_id).first()
        if not position:
            position = Position(user_id=user_id, stock_id=stock_id, current_sr_no=1, entry_price=cmp, total_quantity=0)
            db.session.add(position)
            db.session.commit()

        strategy = self.strategies[position.current_sr_no]
        initial_price = position.entry_price if position.total_quantity > 0 else cmp

        # Buy Logic
        if (cmp <= initial_price * (1 + strategy.down_percent)):
            quantity = strategy.quantity
            order = Order(user_id=user_id, stock_id=stock_id, order_type='buy', quantity=quantity, price=cmp)
            db.session.add(order)
            smart_api = broker.get_session(User.query.get(user_id))
            smart_api.placeOrder(...)  # Implement with Smart API params
            position.total_quantity += quantity
            position.pending_quantity += quantity
            position.entry_price = cmp
            db.session.commit()
            self.log_trade(user_id, stock_id, 'buy', quantity, cmp)

        # Sell Logic (Targets)
        if position.total_quantity > 0:
            if strategy.first_target and cmp >= strategy.first_target and strategy.first_exit_quantity:
                qty_to_sell = min(strategy.first_exit_quantity, position.pending_quantity)
                if qty_to_sell > 0:
                    order = Order(user_id=user_id, stock_id=stock_id, order_type='sell', quantity=qty_to_sell, price=cmp)
                    db.session.add(order)
                    smart_api.placeOrder(...)  # Implement with Smart API params
                    position.pending_quantity -= qty_to_sell
                    self.log_trade(user_id, stock_id, 'sell', qty_to_sell, cmp)
            if strategy.second_target and cmp >= strategy.second_target and strategy.second_exit_quantity:
                qty_to_sell = min(strategy.second_exit_quantity, position.pending_quantity)
                if qty_to_sell > 0:
                    order = Order(user_id=user_id, stock_id=stock_id, order_type='sell', quantity=qty_to_sell, price=cmp)
                    db.session.add(order)
                    smart_api.placeOrder(...)  # Implement with Smart API params
                    position.pending_quantity -= qty_to_sell
                    self.log_trade(user_id, stock_id, 'sell', qty_to_sell, cmp)
            if cmp >= strategy.final_target and position.pending_quantity > 0:
                order = Order(user_id=user_id, stock_id=stock_id, order_type='sell', quantity=position.pending_quantity, price=cmp)
                db.session.add(order)
                smart_api.placeOrder(...)  # Implement with Smart API params
                position.pending_quantity = 0
                self.log_trade(user_id, stock_id, 'sell', position.pending_quantity, cmp)
                time_module.sleep(7)  # 7-second delay
                position.current_sr_no = 1
                position.total_quantity = 0
                position.entry_price = cmp
                db.session.commit()

    def log_trade(self, user_id, stock_id, order_type, quantity, price):
        user = User.query.get(user_id)
        stock = Stock.query.get(stock_id)
        add_log(user.email, f"{order_type.upper()} Order", f"Stock: {stock.tradingsymbol}, Qty: {quantity}, Price: {price}")

    def start_trading(self, user_id):
        user = User.query.get(user_id)
        if not user.trading_active:
            user.trading_active = True
            db.session.commit()
            stocks = Stock.query.filter_by(user_id=user_id).all()
            stock_symbols = {s.id: s.to_dict() for s in stocks}
            def price_callback(data):
                stock_id = int(data.get('token'))  # Adjust based on Smart API response
                cmp = float(data.get('last_price'))  # Adjust based on Smart API response
                self.execute_trade(user_id, stock_id, cmp)
            ws = broker.start_websocket(user, stock_symbols, price_callback)
            threading.Thread(target=self.run_trading_loop, args=(user_id, ws)).start()

    def stop_trading(self, user_id):
        user = User.query.get(user_id)
        if user.trading_active:
            user.trading_active = False
            db.session.commit()

    def run_trading_loop(self, user_id, ws):
        while True:
            if not self.is_market_hours() and User.query.get(user_id).trading_active:
                self.save_state(user_id)
                self.stop_trading(user_id)
            time_module.sleep(60)  # Check every minute

    def save_state(self, user_id):
        positions = Position.query.filter_by(user_id=user_id).all()
        state = {p.stock_id: {'current_sr_no': p.current_sr_no, 'entry_price': p.entry_price, 'total_quantity': p.total_quantity, 'pending_quantity': p.pending_quantity} for p in positions}
        with open('data/state.json', 'w') as f:
            json.dump(state, f)

    def load_state(self, user_id):
        try:
            with open('data/state.json', 'r') as f:
                state = json.load(f)
                for stock_id, data in state.items():
                    position = Position.query.filter_by(user_id=user_id, stock_id=stock_id).first()
                    if position:
                        position.current_sr_no = data['current_sr_no']
                        position.entry_price = data['entry_price']
                        position.total_quantity = data['total_quantity']
                        position.pending_quantity = data['pending_quantity']
                    else:
                        position = Position(user_id=user_id, stock_id=stock_id, **data)
                        db.session.add(position)
                db.session.commit()
        except FileNotFoundError:
            pass

strategy = TradingStrategy()