from datetime import datetime, time
import pandas as pd
import numpy as np
from strategies.base_strategy import LiveStrategy
from strategies.indicators import detect_trend
import os
import pickle

class Live5mSupertrendStrategy(LiveStrategy):
    '''
    - Uses last 30 days of daily data and detect_trend() for a moderate or strong trend
    - If trending, calculate previous daily high and low
    - Calculate the 5m opening range break high and low
    - If price breaks in direction of trend, check for a re-test of the opening range break
    - If price re-tests, generate a signal
    - Entry price is close of re-test signal
    - Stop loss is above/below the high or low of entry signal
    - Take profit previous day's high or low
    '''
    def __init__(self):
        super().__init__("5m_supertrend")
        self.parameters.update({
            'market_open_time': time(9, 30),
            'market_close_time': time(16, 0),
            'trend_threshold': 3,
            'opening_range_duration': 5,
            'tolerance': 0.002,  # 0.2% tolerance for retest
            'trend_direction': None,
            'orb_levels': {},  # Store ORB levels by ticker
            'daily_levels': {},  # Store previous day's high/low by ticker
            'breakout_levels': {},  # Store breakout levels by ticker
            'debug': True
        })
        # Load daily data
        self.daily_data = self._load_daily_data()

    def _load_daily_data(self) -> dict:
        """Load daily bars from saved file"""
        try:
            daily_bars_path = os.path.join('saved_data', 'daily_bars.pkl')
            if os.path.exists(daily_bars_path):
                with open(daily_bars_path, 'rb') as f:
                    return pickle.load(f)
            else:
                if self.parameters['debug']:
                    print("[DEBUG] No daily bars file found at", daily_bars_path)
                return {}
        except Exception as e:
            if self.parameters['debug']:
                print(f"[DEBUG] Error loading daily bars: {e}")
            return {}

    def detect_trend(self, ticker: str, data: pd.DataFrame) -> dict:
        '''
        Detect trend using daily data from the last 30 days
        Returns trend direction and strength
        '''
        # Get daily data from base class
        daily_df = self.get_daily_df(ticker)
        
        if daily_df.empty or len(daily_df) < 5:  # Need at least 5 days of data
            if self.parameters['debug']:
                print(f"[DEBUG] {ticker} - Insufficient daily data: {len(daily_df)} bars")
            return {'trend': None, 'strength': 0}

        # Use the trend detection from indicators.py
        trend_analysis = detect_trend(daily_df)
        
        # Store previous day's high and low for profit targets
        if len(daily_df) >= 2:
            prev_day = daily_df.iloc[-2]
            self.daily_levels[ticker] = {
                'high': prev_day['high'],
                'low': prev_day['low']
            }
            if self.parameters['debug']:
                print(f"[DEBUG] {ticker} - Previous day levels - High: {prev_day['high']:.2f}, Low: {prev_day['low']:.2f}")
        
        return {
            'trend': trend_analysis['trend_rating'],
            'strength': trend_analysis['overall_score']
        }

    def generate_signal(self, ticker: str, data: pd.DataFrame) -> dict:
        '''
        Generate a signal for the given ticker and current data
        '''
        now = datetime.now().time()
        open_time = self.parameters['market_open_time']
        orb_end_time = datetime.combine(datetime.today(), open_time) + \
                      pd.Timedelta(minutes=self.parameters['opening_range_duration'])
        orb_end_time = orb_end_time.time()
        
        # Initialize result
        result = {'signal': None}
        
        # Skip if outside market hours
        if now < open_time or now > self.parameters['market_close_time']:
            return result
            
        # Detect trend if not already set
        if ticker not in self.daily_levels:
            trend = self.detect_trend(ticker, data)
            if self.parameters['debug']:
                print(f"[DEBUG] {ticker} - Trend Analysis: {trend}")
            
            # Only trade if we have a strong enough trend
            if not trend['trend'] or abs(trend['strength']) < self.parameters['trend_threshold']:
                return result
                
            self.parameters['trend_direction'] = 1 if 'Uptrend' in trend['trend'] else -1
        
        # Calculate ORB levels during first 5 minutes
        if now <= orb_end_time:
            current_bars = data[data.index.time <= now]
            orb_high = current_bars['high'].max()
            orb_low = current_bars['low'].min()
            
            self.parameters['orb_levels'][ticker] = {
                'high': orb_high,
                'low': orb_low
            }
            
            if self.parameters['debug']:
                print(f"[DEBUG] {ticker} - Setting ORB levels - High: {orb_high:.2f}, Low: {orb_low:.2f}")
            return result
        
        # After ORB period, look for breakouts and retests
        if ticker not in self.parameters['orb_levels']:
            return result
            
        orb_high = self.parameters['orb_levels'][ticker]['high']
        orb_low = self.parameters['orb_levels'][ticker]['low']
        current_close = data['close'].iloc[-1]
        current_high = data['high'].iloc[-1]
        current_low = data['low'].iloc[-1]
        
        # Calculate retest zone with tolerance
        tolerance = self.parameters['tolerance'] * current_close
        
        if self.parameters['trend_direction'] == 1:  # Uptrend
            # Look for breakout above ORB high
            if ticker not in self.parameters['breakout_levels'] and current_close > orb_high:
                self.parameters['breakout_levels'][ticker] = orb_high
                if self.parameters['debug']:
                    print(f"[DEBUG] {ticker} - Bullish breakout detected at {current_close:.2f}")
                return result
                
            # Look for retest of breakout level
            if ticker in self.parameters['breakout_levels']:
                breakout_level = self.parameters['breakout_levels'][ticker]
                if abs(current_low - breakout_level) <= tolerance:
                    # Generate long signal
                    stop_loss = min(current_low, orb_low)
                    profit_target = self.daily_levels[ticker]['high']
                    
                    if self.parameters['debug']:
                        print(f"[DEBUG] {ticker} - Long signal generated:")
                        print(f"Entry: {current_close:.2f}")
                        print(f"Stop: {stop_loss:.2f}")
                        print(f"Target: {profit_target:.2f}")
                    
                    return {
                        'signal': 'buy',
                        'entry_price': current_close,
                        'stop_loss': stop_loss,
                        'profit_target': profit_target,
                        'orb_high': orb_high,
                        'orb_low': orb_low
                    }
                    
        elif self.parameters['trend_direction'] == -1:  # Downtrend
            # Look for breakout below ORB low
            if ticker not in self.parameters['breakout_levels'] and current_close < orb_low:
                self.parameters['breakout_levels'][ticker] = orb_low
                if self.parameters['debug']:
                    print(f"[DEBUG] {ticker} - Bearish breakout detected at {current_close:.2f}")
                return result
                
            # Look for retest of breakout level
            if ticker in self.parameters['breakout_levels']:
                breakout_level = self.parameters['breakout_levels'][ticker]
                if abs(current_high - breakout_level) <= tolerance:
                    # Generate short signal
                    stop_loss = max(current_high, orb_high)
                    profit_target = self.daily_levels[ticker]['low']
                    
                    if self.parameters['debug']:
                        print(f"[DEBUG] {ticker} - Short signal generated:")
                        print(f"Entry: {current_close:.2f}")
                        print(f"Stop: {stop_loss:.2f}")
                        print(f"Target: {profit_target:.2f}")
                    
                    return {
                        'signal': 'sell',
                        'entry_price': current_close,
                        'stop_loss': stop_loss,
                        'profit_target': profit_target,
                        'orb_high': orb_high,
                        'orb_low': orb_low
                    }
        
        return result
    
