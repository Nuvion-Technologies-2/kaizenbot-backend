def calculate_v1(wallet_value):
    v1_map = {
        100000: -0.642, 150000: -0.428, 200000: -0.214, 250000: 0.002, 300000: 0.216,
        350000: 0.436, 400000: 0.6511, 450000: 0.872, 500000: 1.09, 550000: 1.311,
        600000: 1.532, 650000: 1.754, 700000: 1.977, 750000: 2.201, 800000: 2.425,
        850000: 2.65, 900000: 2.877, 950000: 3.104, 1000000: 3.332
    }
    return v1_map.get(wallet_value, 0.023)  # Default if not in map

def get_strategy_data(user_email, stock_symbol, base_price, wallet_value):
    configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=stock_symbol).order_by(PhaseConfig.start_sr_no).all()
    if not configs:  # Default config if none in DB
        configs = [
            PhaseConfig(user_email=user_email, stock_symbol=stock_symbol, start_sr_no=1, end_sr_no=21, down_increment=0.25),
            PhaseConfig(user_email=user_email, stock_symbol=stock_symbol, start_sr_no=22, end_sr_no=41, down_increment=0.50),
            PhaseConfig(user_email=user_email, stock_symbol=stock_symbol, start_sr_no=42, end_sr_no=55, down_increment=0.75),
            PhaseConfig(user_email=user_email, stock_symbol=stock_symbol, start_sr_no=56, end_sr_no=70, down_increment=1.00),
            PhaseConfig(user_email=user_email, stock_symbol=stock_symbol, start_sr_no=71, end_sr_no=81, down_increment=1.25)
        ]
    
    v1 = calculate_v1(wallet_value)
    strategy = []
    f_values = [20000, 1100]  # F2, F3
    f_values.append(f_values[1] + round(f_values[1] * v1))  # F4
    for i in range(3, 81):  # F5 to F82
        f_values.append(f_values[i-1] + round(f_values[i-1] * 0.022))
    
    for config in configs:
        sr_no_range = range(config.start_sr_no, config.end_sr_no + 1)
        down_start = strategy[-1]['DOWN'] if strategy else 0
        for i, sr_no in enumerate(sr_no_range):
            down = down_start - (i * config.down_increment / 100) if sr_no > 1 else 0
            entry = round(base_price * (1 + down), 2)
            qnty = max(1, round(f_values[sr_no-1] / entry, 0))
            strategy.append({
                'Sr.No': sr_no,
                'DOWN': down,
                'Entry': entry,
                'Qnty': qnty,
                'First_TGT': None if sr_no <= 8 else round(entry * 1.015, 2),
                'EXIT_1st_HALF': None if sr_no <= 8 else round(qnty / 2, 0),
                'Second_TGT': None if sr_no <= 8 else round(entry * 1.02, 2),
                'EXIT_2nd_HALF': None if sr_no <= 8 else round(qnty / 2, 0),
                'FINAL_TGT': round(entry * 1.015, 2)
            })
    return pd.DataFrame(strategy)

def place_order(smart_api, symbol, quantity, ltp, order_type='BUY'):
    params = {
        'variety': 'NORMAL',
        'tradingsymbol': symbol,
        'symboltoken': '2885',  # RELIANCE
        'transactiontype': order_type,
        'exchange': 'NSE',
        'ordertype': 'MARKET',
        'producttype': 'INTRADAY',
        'duration': 'DAY',
        'quantity': quantity,
        'price': ltp
    }
    return smart_api.placeOrder(params)

def process_strategy(user, symbol, ltp, smart_api):
    if not is_market_open():
        return

    with app.app_context():
        trades = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email, status='OPEN').order_by(Trade.sr_no).all()
        wallet_value = smart_api.getWalletValue()
        
        if not trades:
            base_price = ltp
            strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
            qty = strategy_data.loc[0, 'Qnty']
            executed_qty = place_order(smart_api, symbol, qty, ltp)
            trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=base_price, quantity=executed_qty, 
                          user_email=user.email, base_price=base_price)
            db.session.add(trade)
            db.session.commit()
            logger.info(f"Initial Buy {symbol} at {ltp}, Qty: {executed_qty}")
            return

        base_price = trades[0].base_price
        sr1_trade = Trade.query.filter_by(stock_symbol=symbol, user_email=user.email, sr_no=1, status='OPEN').first()
        reference_price = sr1_trade.entry_price if sr1_trade else base_price
        strategy_data = get_strategy_data(user.email, symbol, base_price, wallet_value)
        
        # Handle sells
        for trade in trades:
            sr_no = trade.sr_no
            entry_price = trade.entry_price
            current_qty = trade.quantity - trade.sold_quantity
            row = strategy_data.loc[sr_no-1]
            
            if sr_no <= 8:
                target = row['FINAL_TGT']
                if ltp >= target and current_qty > 0:
                    executed_qty = place_order(smart_api, symbol, current_qty, ltp, 'SELL')
                    trade.sold_quantity += executed_qty
                    if trade.sold_quantity == trade.quantity:
                        trade.status = 'CLOSED'
                        db.session.commit()
                        tm.sleep(7)
                        new_qty = max(1, round(20000 / ltp, 0))
                        new_executed = place_order(smart_api, symbol, new_qty, ltp)
                        new_trade = Trade(stock_symbol=symbol, sr_no=1, entry_price=ltp, quantity=new_executed, 
                                          user_email=user.email, base_price=base_price)
                        db.session.add(new_trade)
                        db.session.commit()
                        logger.info(f"Exit {symbol} at {ltp}, Restart at {ltp}, Qty: {new_executed}")
            else:
                first_tgt = row['First_TGT']
                second_tgt = row['Second_TGT']
                half_qty = row['EXIT_1st_HALF']
                if ltp >= first_tgt and current_qty > 0:
                    sell_qty = min(half_qty, current_qty)
                    executed_qty = place_order(smart_api, symbol, sell_qty, ltp, 'SELL')
                    trade.sold_quantity += executed_qty
                    trade.status = 'PARTIAL' if trade.sold_quantity < trade.quantity else 'CLOSED'
                    db.session.commit()
                    logger.info(f"Exit 1st Half {symbol} at {ltp}, Sold: {executed_qty}/{sell_qty}")
                elif ltp >= second_tgt and current_qty > 0:
                    sell_qty = current_qty
                    executed_qty = place_order(smart_api, symbol, sell_qty, ltp, 'SELL')
                    trade.sold_quantity += executed_qty
                    trade.status = 'CLOSED' if trade.sold_quantity == trade.quantity else 'PARTIAL'
                    db.session.commit()
                    logger.info(f"Exit 2nd Half {symbol} at {ltp}, Sold: {executed_qty}/{sell_qty}")
        
        # Handle buys
        drop_percent = (ltp - reference_price) / reference_price
        current_qty = sum(t.quantity - t.sold_quantity for t in trades)
        if drop_percent < 0:
            sr_no = strategy_data.index[strategy_data['DOWN'] >= drop_percent].min() + 1
            if sr_no and not any(t.sr_no == sr_no for t in trades):
                total_qty = strategy_data.loc[:sr_no-1, 'Qnty'].sum()
                qty_to_buy = total_qty - current_qty
                if qty_to_buy > 0:
                    executed_qty = place_order(smart_api, symbol, qty_to_buy, ltp)
                    trade = Trade(stock_symbol=symbol, sr_no=sr_no, entry_price=base_price, 
                                  quantity=executed_qty, user_email=user.email, base_price=base_price)
                    db.session.add(trade)
                    db.session.commit()
                    logger.info(f"Buy {symbol} at {ltp}, Qty: {executed_qty}, Sr.No: {sr_no}")
        
        # Re-entry for partial sells
        for trade in trades:
            if trade.status == 'PARTIAL' and ltp < trade.entry_price:
                reentry_qty = trade.quantity - trade.sold_quantity
                executed_qty = place_order(smart_api, symbol, reentry_qty, ltp)
                trade.quantity += executed_qty
                trade.sold_quantity = 0
                trade.status = 'OPEN'
                db.session.commit()
                logger.info(f"Re-enter {symbol} at {ltp}, Qty: {executed_qty}")