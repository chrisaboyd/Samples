"""
Example strategies demonstrating different timeframe implementations.
These serve as templates for creating new strategies.
"""

from strategies.base_strategy import BaseStrategy
import pandas as pd
import numpy as np

class SwingTradingStrategy(BaseStrategy):
    """
    Example swing trading strategy operating on daily timeframe.
    Uses longer-term moving averages and weekly support/resistance levels.
    """
    
    def __init__(self, market_data):
        super().__init__(market_data)
        self.parameters.update({
            'timeframe': 'D',           # Daily timeframe
            'intraday': False,          # Not an intraday strategy
            
            # Strategy-specific parameters
            'ma_short': 20,             # 20-day moving average
            'ma_long': 50,              # 50-day moving average
            'rsi_period': 14,           # 14-day RSI
            'rsi_overbought': 70,
            'rsi_oversold': 30,
            'stop_loss_pct': 5.0,       # Wider stops for swing trading
            'take_profit_pct': 15.0,    # Larger profit targets
            'position_size_pct': 20.0   # Larger position sizes
        })

class DayTradingStrategy(BaseStrategy):
    """
    Example day trading strategy operating on 5-minute bars.
    Uses VWAP and intraday momentum.
    """
    
    def __init__(self, market_data):
        super().__init__(market_data)
        self.parameters.update({
            'timeframe': '5min',        # 5-minute bars
            'intraday': True,           # Intraday strategy
            'market_open_time': '09:30',
            'market_close_time': '16:00',
            
            # Strategy-specific parameters
            'vwap_dev_threshold': 1.5,  # VWAP deviation threshold
            'momentum_period': 12,      # 1-hour momentum (12 * 5min)
            'volume_ma_period': 20,     # Volume moving average
            'stop_loss_pct': 0.5,       # Tighter stops
            'take_profit_pct': 1.0,     # Smaller profit targets
            'max_hold_time': 120,       # Max 2 hours per trade
            'position_size_pct': 10.0   # Smaller position sizes
        })
        
    def is_valid_trading_time(self, timestamp):
        """
        Add day trading specific time restrictions.
        """
        if not super().is_valid_trading_time(timestamp):
            return False
            
        # Avoid first 15 minutes of trading
        market_open = pd.to_datetime(self.parameters['market_open_time']).time()
        morning_cutoff = (pd.to_datetime(self.parameters['market_open_time']) + 
                         pd.Timedelta(minutes=15)).time()
        
        # Avoid last 15 minutes of trading
        market_close = pd.to_datetime(self.parameters['market_close_time']).time()
        afternoon_cutoff = (pd.to_datetime(self.parameters['market_close_time']) - 
                          pd.Timedelta(minutes=15)).time()
        
        current_time = timestamp.time()
        if current_time < morning_cutoff or current_time > afternoon_cutoff:
            return False
            
        return True

class OpeningRangeBreakoutStrategy(BaseStrategy):
    """
    Example opening range breakout strategy operating on 1-minute bars.
    Trades breakouts of the first 15-minute range.
    """
    
    def __init__(self, market_data):
        super().__init__(market_data)
        self.parameters.update({
            'timeframe': '1min',        # 1-minute bars
            'intraday': True,
            'market_open_time': '09:30',
            'market_close_time': '16:00',
            
            # Strategy-specific parameters
            'range_minutes': 15,        # Opening range period
            'breakout_threshold': 0.1,  # 0.1% breakout threshold
            'stop_loss_pct': 0.3,       # Stop under/over the range
            'take_profit_pct': 0.9,     # 1:3 risk/reward
            'max_hold_time': 60,        # Exit within 1 hour
            'position_size_pct': 15.0,  # Medium position size
            'min_range_atr': 0.5        # Minimum range as % of ATR
        })
        
    def calculate_opening_range(self, price_data, timestamp):
        """
        Calculate opening range for the current day.
        """
        today = timestamp.date()
        market_open = pd.Timestamp.combine(today, 
            pd.to_datetime(self.parameters['market_open_time']).time())
        range_end = market_open + pd.Timedelta(minutes=self.parameters['range_minutes'])
        
        range_mask = (price_data.index >= market_open) & (price_data.index <= range_end)
        range_prices = price_data[range_mask]
        
        if len(range_prices) > 0:
            return {
                'high': range_prices.max(),
                'low': range_prices.min(),
                'mid': (range_prices.max() + range_prices.min()) / 2
            }
        return None

# Example usage in main.py:
"""
# For swing trading (daily timeframe):
strategy = SwingTradingStrategy(market_data)
backtester = Backtester(market_data, strategy, initial_capital=100000)
results = backtester.run('2023-01-01', '2024-01-01')

# For day trading (5-minute bars):
strategy = DayTradingStrategy(market_data)
backtester = Backtester(market_data, strategy, initial_capital=100000)
results = backtester.run('2024-04-01', '2024-04-12')

# For opening range breakout (1-minute bars):
strategy = OpeningRangeBreakoutStrategy(market_data)
backtester = Backtester(market_data, strategy, initial_capital=100000)
results = backtester.run('2024-04-01', '2024-04-12')
""" 