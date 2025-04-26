from datetime import datetime, time
import pandas as pd
import numpy as np
from strategies.base_strategy import LiveStrategy

class BollingerBandReversal(LiveStrategy):
    """
    Bollinger Band Reversal Strategy
    
    - Uses daily timeframe for higher confidence pattern recognition
    - Identifies reversals when price touches Bollinger Bands with confirming indicators
    - Enters on 1m timeframe after a break and retest of the previous day's close
    - Uses RSI to confirm oversold/overbought conditions
    - Identifies candlestick patterns (hammer, shooting star, engulfing) on increased volume
    """
    def __init__(self):
        super().__init__("BB_Reversal")
        self.parameters.update({
            'market_open_time': time(9, 30),
            'market_close_time': time(16, 0),
            'bb_period': 20,             # Period for Bollinger Bands
            'bb_std_dev': 2,             # Standard deviations for Bollinger Bands
            'rsi_period': 14,            # RSI period
            'rsi_oversold': 30,          # RSI oversold threshold
            'rsi_overbought': 70,        # RSI overbought threshold
            'volume_increase_factor': 1.5,  # Required volume increase vs previous day
            'tolerance': 0.001,          # Price tolerance for entries
            'tp1_ratio': 0.5,            # Take Profit 1 at 50% to BB midline
            'tp2_ratio': 1.0,            # Take Profit 2 at opposite BB
        })
        # State variables
        self.daily_data = {}             # Daily candlestick data
        self.reversal_signals = {}       # Reversal signals from daily timeframe 
        self.breakout_flags = {}         # Flags for intraday breakout/retest
        self.last_check_day = {}         # Last day we checked for reversal pattern
    
    def calculate_bollinger_bands(self, prices, period=None, std_dev=None):
        """Calculate Bollinger Bands for a series of prices"""
        if period is None:
            period = self.parameters['bb_period']
        if std_dev is None:
            std_dev = self.parameters['bb_std_dev']
            
        # Calculate moving average
        ma = prices.rolling(window=period).mean()
        
        # Calculate standard deviation
        std = prices.rolling(window=period).std()
        
        # Calculate upper and lower bands
        upper_band = ma + (std * std_dev)
        lower_band = ma - (std * std_dev)
        
        return {
            'middle': ma,
            'upper': upper_band,
            'lower': lower_band
        }
    
    def is_hammer(self, row):
        """
        Detect hammer candlestick pattern
        - Small body
        - Long lower shadow (at least 2x body)
        - Little or no upper shadow
        """
        body_size = abs(row['close'] - row['open'])
        total_range = row['high'] - row['low']
        
        # Prevent division by zero
        if body_size == 0:
            return False
            
        # Determine shadows
        if row['close'] >= row['open']:  # Bullish candle
            upper_shadow = row['high'] - row['close']
            lower_shadow = row['open'] - row['low']
        else:  # Bearish candle
            upper_shadow = row['high'] - row['open']
            lower_shadow = row['close'] - row['low']
            
        # Check if it's a hammer
        # 1. Body is in the upper 1/3 of the range
        # 2. Lower shadow at least 2x the body
        # 3. Upper shadow is small (less than 10% of total range)
        body_position = (row['low'] + 2*total_range/3 <= min(row['open'], row['close']))
        long_lower_wick = (lower_shadow >= 2 * body_size)
        small_upper_wick = (upper_shadow <= 0.1 * total_range)
        
        return body_position and long_lower_wick and small_upper_wick
    
    def is_shooting_star(self, row):
        """
        Detect shooting star candlestick pattern
        - Small body
        - Long upper shadow (at least 2x body)
        - Little or no lower shadow
        """
        body_size = abs(row['close'] - row['open'])
        total_range = row['high'] - row['low']
        
        # Prevent division by zero
        if body_size == 0:
            return False
            
        # Determine shadows
        if row['close'] >= row['open']:  # Bullish candle
            upper_shadow = row['high'] - row['close']
            lower_shadow = row['open'] - row['low']
        else:  # Bearish candle
            upper_shadow = row['high'] - row['open']
            lower_shadow = row['close'] - row['low']
            
        # Check if it's a shooting star
        # 1. Body is in the lower 1/3 of the range
        # 2. Upper shadow at least 2x the body
        # 3. Lower shadow is small (less than 10% of total range)
        body_position = (row['low'] + total_range/3 >= max(row['open'], row['close']))
        long_upper_wick = (upper_shadow >= 2 * body_size)
        small_lower_wick = (lower_shadow <= 0.1 * total_range)
        
        return body_position and long_upper_wick and small_lower_wick
    
    def is_engulfing(self, current, previous):
        """
        Detect bullish or bearish engulfing pattern
        - Current candle's body completely engulfs previous candle's body
        - Current and previous candles have opposite colors
        
        Returns: 1 for bullish engulfing, -1 for bearish engulfing, 0 for no engulfing
        """
        # Check if current candle is bullish (close > open)
        current_bullish = current['close'] > current['open']
        previous_bullish = previous['close'] > previous['open']
        
        # Different colors requirement
        if current_bullish == previous_bullish:
            return 0
            
        # For bullish engulfing
        if current_bullish:
            # Current open lower than previous close
            # Current close higher than previous open
            if (current['open'] <= previous['close'] and 
                current['close'] >= previous['open']):
                return 1
                
        # For bearish engulfing
        else:
            # Current open higher than previous close
            # Current close lower than previous open
            if (current['open'] >= previous['close'] and 
                current['close'] <= previous['open']):
                return -1
                
        return 0
    
    def update_daily_bars(self, ticker, daily_data):
        """
        Update daily bar data and check for reversal patterns
        
        Args:
            ticker: Symbol
            daily_data: DataFrame of daily bars
        """
        # Store the daily data
        self.daily_data[ticker] = daily_data.copy()
        
        # Initialize ticker data structures if first time seeing ticker
        if ticker not in self.reversal_signals:
            self.reversal_signals[ticker] = {'long': False, 'short': False}
            self.breakout_flags[ticker] = {'long': False, 'short': False, 'long_taken': False, 'short_taken': False}
            self.last_check_day[ticker] = None
        
        # Get today's date
        today = datetime.now().date()
        
        # If we already checked for today, skip
        if self.last_check_day[ticker] == today:
            return
            
        # Calculate indicators on daily data
        if len(daily_data) < self.parameters['bb_period']:
            return  # Not enough data
            
        # Calculate Bollinger Bands
        df = daily_data.copy()
        bb = self.calculate_bollinger_bands(df['close'])
        df['bb_middle'] = bb['middle']
        df['bb_upper'] = bb['upper']
        df['bb_lower'] = bb['lower']
        
        # Calculate RSI
        df['rsi'] = self.calculate_rsi(df['close'], periods=self.parameters['rsi_period'])
        
        # Skip if we don't have enough data
        if df.shape[0] < 2:
            return
            
        # Get the last two days' data
        current_day = df.iloc[-1]
        previous_day = df.iloc[-2]
        
        # Check volume increase
        volume_increased = current_day['volume'] >= self.parameters['volume_increase_factor'] * previous_day['volume']
        
        # Check for bullish reversal (long setup)
        bullish_reversal = False
        if (current_day['low'] <= current_day['bb_lower'] and  # Price at/below lower band
            current_day['rsi'] <= self.parameters['rsi_oversold'] and  # RSI oversold
            volume_increased):  # Volume increased
            
            # Check candlestick patterns
            is_hammer = self.is_hammer(current_day)
            is_bullish_engulfing = self.is_engulfing(current_day, previous_day) == 1
            
            bullish_reversal = is_hammer or is_bullish_engulfing
            
            if bullish_reversal:
                # Store the signal details
                self.reversal_signals[ticker]['long'] = True
                self.reversal_signals[ticker]['long_price'] = current_day['close']
                self.reversal_signals[ticker]['long_stop'] = current_day['low']
                self.reversal_signals[ticker]['long_tp1'] = current_day['bb_middle']
                self.reversal_signals[ticker]['long_tp2'] = current_day['bb_upper']
                self.reversal_signals[ticker]['long_day_high'] = current_day['high']
                self.reversal_signals[ticker]['long_day_low'] = current_day['low']
                self.reversal_signals[ticker]['long_pattern'] = 'Hammer' if is_hammer else 'Bullish Engulfing'
                
                # For debugging
                if self.parameters.get('debug', False):
                    print(f"[DEBUG] {ticker} - Daily BULLISH Reversal Signal:")
                    print(f"  Date: {df.index[-1]}")
                    print(f"  Close: ${current_day['close']:.2f}")
                    print(f"  Lower BB: ${current_day['bb_lower']:.2f}")
                    print(f"  RSI: {current_day['rsi']:.1f}")
                    print(f"  Pattern: {self.reversal_signals[ticker]['long_pattern']}")
                    print(f"  Entry: ${self.reversal_signals[ticker]['long_price']:.2f}")
                    print(f"  Stop: ${self.reversal_signals[ticker]['long_stop']:.2f}")
                    print(f"  TP1: ${self.reversal_signals[ticker]['long_tp1']:.2f}")
                    print(f"  TP2: ${self.reversal_signals[ticker]['long_tp2']:.2f}")
        
        # Check for bearish reversal (short setup)
        bearish_reversal = False
        if (current_day['high'] >= current_day['bb_upper'] and  # Price at/above upper band
            current_day['rsi'] >= self.parameters['rsi_overbought'] and  # RSI overbought
            volume_increased):  # Volume increased
            
            # Check candlestick patterns
            is_shooting_star = self.is_shooting_star(current_day)
            is_bearish_engulfing = self.is_engulfing(current_day, previous_day) == -1
            
            bearish_reversal = is_shooting_star or is_bearish_engulfing
            
            if bearish_reversal:
                # Store the signal details
                self.reversal_signals[ticker]['short'] = True
                self.reversal_signals[ticker]['short_price'] = current_day['close']
                self.reversal_signals[ticker]['short_stop'] = current_day['high']
                self.reversal_signals[ticker]['short_tp1'] = current_day['bb_middle']
                self.reversal_signals[ticker]['short_tp2'] = current_day['bb_lower']
                self.reversal_signals[ticker]['short_day_high'] = current_day['high']
                self.reversal_signals[ticker]['short_day_low'] = current_day['low']
                self.reversal_signals[ticker]['short_pattern'] = 'Shooting Star' if is_shooting_star else 'Bearish Engulfing'
                
                # For debugging
                if self.parameters.get('debug', False):
                    print(f"[DEBUG] {ticker} - Daily BEARISH Reversal Signal:")
                    print(f"  Date: {df.index[-1]}")
                    print(f"  Close: ${current_day['close']:.2f}")
                    print(f"  Upper BB: ${current_day['bb_upper']:.2f}")
                    print(f"  RSI: {current_day['rsi']:.1f}")
                    print(f"  Pattern: {self.reversal_signals[ticker]['short_pattern']}")
                    print(f"  Entry: ${self.reversal_signals[ticker]['short_price']:.2f}")
                    print(f"  Stop: ${self.reversal_signals[ticker]['short_stop']:.2f}")
                    print(f"  TP1: ${self.reversal_signals[ticker]['short_tp1']:.2f}")
                    print(f"  TP2: ${self.reversal_signals[ticker]['short_tp2']:.2f}")
                    
        # Update the last check day
        self.last_check_day[ticker] = today
        
    def generate_signal(self, ticker: str, current_data: pd.DataFrame) -> dict:
        """
        Generate trading signals based on the 1-minute chart after daily reversal pattern
        
        Args:
            ticker: Symbol
            current_data: DataFrame of 1-minute bars
            
        Returns:
            dict: Signal details or {'signal': None}
        """
        # Initialize response with default signal None and basic indicators
        response = {'signal': None}
        
        # Add RSI and VWAP to response if we have enough data
        if len(current_data) >= self.parameters['rsi_period']:
            rsi_series = self.calculate_rsi(current_data['close'], periods=self.parameters['rsi_period'])
            response['rsi'] = rsi_series.iloc[-1]
            
            vwap_series = self.calculate_vwap(current_data)
            response['vwap'] = vwap_series.iloc[-1]
            
        # Skip if no daily reversal signal
        if ticker not in self.reversal_signals or not any(self.reversal_signals[ticker].values()):
            return response
            
        # Skip if we already took the trade
        flags = self.breakout_flags[ticker]
        if flags['long_taken'] and flags['short_taken']:
            return response
            
        # Get current bar
        if len(current_data) < 1:
            return response
            
        current_bar = current_data.iloc[-1]
        current_high = current_bar['high']
        current_low = current_bar['low']
        current_close = current_bar['close']
        
        # Check tolerance
        t = self.parameters['tolerance']
        
        # Check for long entry if we have a bullish reversal signal
        if (self.reversal_signals[ticker].get('long', False) and 
            not flags['long_taken']):
            
            signal_price = self.reversal_signals[ticker]['long_price']
            day_low = self.reversal_signals[ticker]['long_day_low']
            day_high = self.reversal_signals[ticker]['long_day_high']
            
            # First, detect a breakout above yesterday's close
            if not flags['long'] and current_high > signal_price:
                flags['long'] = True
                if self.parameters.get('debug', False):
                    print(f"[DEBUG] {ticker} - LONG breakout above ${signal_price:.2f}")
                    
            # Then, wait for a retest of the breakout level
            elif flags['long']:
                # Price is retesting the breakout level
                if signal_price * (1-t) <= current_low <= signal_price * (1+t):
                    # Generate long signal
                    stop_loss = day_low
                    
                    # Calculate take profit levels based on Bollinger Bands
                    entry_to_stop = current_close - stop_loss
                    profit_target1 = current_close + self.parameters['tp1_ratio'] * 2 * entry_to_stop
                    profit_target2 = current_close + self.parameters['tp2_ratio'] * 2 * entry_to_stop
                    
                    # Use the midline and upper band from daily signals if available
                    if 'long_tp1' in self.reversal_signals[ticker]:
                        profit_target1 = self.reversal_signals[ticker]['long_tp1']
                    if 'long_tp2' in self.reversal_signals[ticker]:
                        profit_target2 = self.reversal_signals[ticker]['long_tp2']
                    
                    # Mark the trade as taken
                    flags['long_taken'] = True
                    
                    pattern = self.reversal_signals[ticker].get('long_pattern', 'Unknown')
                    
                    # Create response
                    response = {
                        'signal': 'buy',
                        'entry_price': float(current_close),
                        'stop_loss': float(stop_loss),
                        'profit_target': float(profit_target1),  # Use TP1 as the primary target
                        'profit_target2': float(profit_target2), # Secondary target
                        'pattern': pattern,
                        'bb_lower': float(self.reversal_signals[ticker].get('bb_lower', 0)),
                        'bb_middle': float(self.reversal_signals[ticker].get('long_tp1', 0)),
                        'bb_upper': float(self.reversal_signals[ticker].get('long_tp2', 0)),
                        'reversal_price': float(signal_price),
                        'day_high': float(day_high),
                        'day_low': float(day_low),
                        'rsi': float(response.get('rsi', 0)) if 'rsi' in response else None,
                        'vwap': float(response.get('vwap', 0)) if 'vwap' in response else None
                    }
                    
                    # Debug
                    if self.parameters.get('debug', False):
                        print(f"[DEBUG] {ticker} - GENERATING LONG SIGNAL:")
                        print(f"  Pattern: {pattern}")
                        print(f"  Entry: ${current_close:.2f}")
                        print(f"  Stop: ${stop_loss:.2f}")
                        print(f"  TP1: ${profit_target1:.2f}")
                        print(f"  TP2: ${profit_target2:.2f}")
                    
                    return response
        
        # Check for short entry if we have a bearish reversal signal
        if (self.reversal_signals[ticker].get('short', False) and 
            not flags['short_taken']):
            
            signal_price = self.reversal_signals[ticker]['short_price']
            day_low = self.reversal_signals[ticker]['short_day_low']
            day_high = self.reversal_signals[ticker]['short_day_high']
            
            # First, detect a breakdown below yesterday's close
            if not flags['short'] and current_low < signal_price:
                flags['short'] = True
                if self.parameters.get('debug', False):
                    print(f"[DEBUG] {ticker} - SHORT breakdown below ${signal_price:.2f}")
                    
            # Then, wait for a retest of the breakdown level
            elif flags['short']:
                # Price is retesting the breakdown level
                if signal_price * (1-t) <= current_high <= signal_price * (1+t):
                    # Generate short signal
                    stop_loss = day_high
                    
                    # Calculate take profit levels based on Bollinger Bands
                    entry_to_stop = stop_loss - current_close
                    profit_target1 = current_close - self.parameters['tp1_ratio'] * 2 * entry_to_stop
                    profit_target2 = current_close - self.parameters['tp2_ratio'] * 2 * entry_to_stop
                    
                    # Use the midline and lower band from daily signals if available
                    if 'short_tp1' in self.reversal_signals[ticker]:
                        profit_target1 = self.reversal_signals[ticker]['short_tp1']
                    if 'short_tp2' in self.reversal_signals[ticker]:
                        profit_target2 = self.reversal_signals[ticker]['short_tp2']
                    
                    # Mark the trade as taken
                    flags['short_taken'] = True
                    
                    pattern = self.reversal_signals[ticker].get('short_pattern', 'Unknown')
                    
                    # Create response
                    response = {
                        'signal': 'sell',
                        'entry_price': float(current_close),
                        'stop_loss': float(stop_loss),
                        'profit_target': float(profit_target1),  # Use TP1 as the primary target
                        'profit_target2': float(profit_target2), # Secondary target
                        'pattern': pattern,
                        'bb_upper': float(self.reversal_signals[ticker].get('bb_upper', 0)),
                        'bb_middle': float(self.reversal_signals[ticker].get('short_tp1', 0)),
                        'bb_lower': float(self.reversal_signals[ticker].get('short_tp2', 0)),
                        'reversal_price': float(signal_price),
                        'day_high': float(day_high),
                        'day_low': float(day_low),
                        'rsi': float(response.get('rsi', 0)) if 'rsi' in response else None,
                        'vwap': float(response.get('vwap', 0)) if 'vwap' in response else None
                    }
                    
                    # Debug
                    if self.parameters.get('debug', False):
                        print(f"[DEBUG] {ticker} - GENERATING SHORT SIGNAL:")
                        print(f"  Pattern: {pattern}")
                        print(f"  Entry: ${current_close:.2f}")
                        print(f"  Stop: ${stop_loss:.2f}")
                        print(f"  TP1: ${profit_target1:.2f}")
                        print(f"  TP2: ${profit_target2:.2f}")
                    
                    return response
                    
        return response