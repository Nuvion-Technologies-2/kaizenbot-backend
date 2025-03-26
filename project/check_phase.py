import pandas as pd
from project.models import PhaseConfig
from project.app import calculate_v1


def get_strategy_data(user_email, stock_symbol, base_price, wallet_value):
    configs = PhaseConfig.query.filter_by(user_email=user_email, stock_symbol=stock_symbol).order_by(PhaseConfig.start_sr_no).all()
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
            down = down_start - (i * config.down_increment / 100)
            entry = round(base_price * (1 + down), 2)
            qnty = max(1, round(f_values[sr_no-1] / entry, 0))
            total_qty = qnty if sr_no == 1 else strategy[-1]['Total_Qty'] + qnty
            strategy.append({
                'Sr.No': sr_no,
                'DOWN': down,
                'Entry': entry,
                'Qnty': qnty,
                'Total_Qty': total_qty,
                'First_TGT': None if sr_no <= 8 else round(entry * 1.015, 2),
                'EXIT_1st_HALF': None if sr_no <= 8 else round(qnty / 2, 0),
                'Second_TGT': None if sr_no <= 8 else round(entry * 1.02, 2),
                'EXIT_2nd_HALF': None if sr_no <= 8 else round(qnty / 2, 0),
                'FINAL_TGT': round(entry * 1.015, 2)
            })
    return pd.DataFrame(strategy)

# Simulate with base_price = 270.94, assuming one config
base_price = 270.94
wallet_value = 100000  # Placeholder
v1 = 0.1  # Placeholder for calculate_v1
f_values = [20000, 1100]
f_values.append(f_values[1] + round(f_values[1] * v1))
for i in range(3, 81):
    f_values.append(f_values[i-1] + round(f_values[i-1] * 0.022))

# Assuming PhaseConfig: start_sr_no=1, end_sr_no=81, down_increment=0.25
down_start = 0
strategy = []
for sr_no in range(1, 82):
    down = down_start - ((sr_no - 1) * 0.25 / 100)  # down_increment = 0.25%
    entry = round(base_price * (1 + down), 2)
    qnty = max(1, round(f_values[sr_no-1] / entry, 0))
    total_qty = qnty if sr_no == 1 else strategy[-1]['Total_Qty'] + qnty
    strategy.append({'Sr.No': sr_no, 'DOWN': down, 'Entry': entry, 'Qnty': qnty, 'Total_Qty': total_qty})

strategy_df = pd.DataFrame(strategy)
print(strategy_df.head(10))
print(strategy_df.tail(5))