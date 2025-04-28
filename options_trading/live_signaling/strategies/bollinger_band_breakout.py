from datetime import datetime, time
import pandas as pd
import numpy as np
from strategies.base_strategy import LiveStrategy

class BollingerBandBreakout(LiveStrategy):
    """
    Bollinger Band Breakout Strategy
    
    - Detects expanding Bollinger Bands (high volatility)
    - Identifies breakouts beyond the upper/lower bands
    - Confirms with RSI momentum (but not extreme values)
    - Requires MACD crossover for confirmation
    - Requires volume spike above 20-day average
    - Enters on 1m timeframe after a breakout and retest
    """
    def __init__(self):
        super().__init__("BB_Breakout")
        self.parameters.update({
            'market_open_time': time(9, 30),
            'market_close_time': time(16, 0),
            'bb_period': 20,             # Period for Bollinger Bands
            'bb_std_dev': 2,             # Standard deviations for Bollinger Bands
            'rsi_period': 14,            # RSI period
            'rsi_long_min': 50,          # RSI minimum for long entries
            'rsi_long_max': 70,          # RSI maximum for long entries
            'rsi_short_min': 30,         # RSI minimum for short entries  
            'rsi_short_max': 50,         # RSI maximum for short entries
            'macd_fast': 12,             # MACD fast EMA period
            'macd_slow': 26,             # MACD slow EMA period
            'macd_signal': 9,            # MACD signal line period
            'vol_ma_period': 20,         # Volume moving average period
            'vol_increase_factor': 1.2,  # Required volume above moving average
            'bb_expansion_factor': 1.1,  # Required BB width expansion (10%)
            'tolerance': 0.001,          # Price tolerance for entries
            'atr_period': 14,            # ATR calculation period
        })
        # State variables
        self.daily_data = {}             # Daily candlestick data
        self.breakout_signals = {}       # Breakout signals from daily timeframe 
        self.breakout_flags = {}         # Flags for intraday breakout/retest
        self.last_check_day = {}         # Last day we checked for breakout pattern
    
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
        
        # Calculate bandwidth (normalized)
        bandwidth = (upper_band - lower_band) / ma
        
        return {
            'middle': ma,
            'upper': upper_band,
            'lower': lower_band,
            'bandwidth': bandwidth
        }
    
    def calculate_macd(self, prices):
        """Calculate MACD for a series of prices"""
        fast = self.parameters['macd_fast']
        slow = self.parameters['macd_slow']
        signal_period = self.parameters['macd_signal']
        
        # Calculate EMAs
        ema_fast = prices.ewm(span=fast, adjust=False).mean()
        ema_slow = prices.ewm(span=slow, adjust=False).mean()
        
        # Calculate MACD line
        macd_line = ema_fast - ema_slow
        
        # Calculate signal line
        signal_line = macd_line.ewm(span=signal_period, adjust=False).mean()
        
        # Calculate histogram
        histogram = macd_line - signal_line
        
        return {
            'macd': macd_line,
            'signal': signal_line,
            'histogram': histogram
        }
        
    def calculate_atr(self, data, period=None):
        """Calculate Average True Range"""
        if period is None:
            period = self.parameters['atr_period']
            
        high = data['high']
        low = data['low']
        close = data['close'].shift(1)
        
        # Handle first row with no previous close
        close.iloc[0] = data['open'].iloc[0]
        
        # Calculate true range
        tr1 = high - low
        tr2 = abs(high - close)
        tr3 = abs(low - close)
        
        tr = pd.DataFrame({
            'tr1': tr1,
            'tr2': tr2,
            'tr3': tr3
        }).max(axis=1)
        
        # Calculate ATR
        atr = tr.rolling(window=period).mean()
        
        return atr
    
    def update_daily_bars(self, ticker, daily_data):
        """
        Update daily bar data and check for breakout patterns
        
        Args:
            ticker: Symbol
            daily_data: DataFrame of daily bars
        """
        # Store the daily data
        self.daily_data[ticker] = daily_data.copy()
        
        # Initialize ticker data structures if first time seeing ticker
        if ticker not in self.breakout_signals:
            self.breakout_signals[ticker] = {'long': False, 'short': False}
            self.breakout_flags[ticker] = {'long': False, 'short': False, 'long_taken': False, 'short_taken': False}
            self.last_check_day[ticker] = None
        
        # Get today's date
        today = datetime.now().date()
        
        # If we already checked for today, skip
        if self.last_check_day[ticker] == today:
            return
            
        # Calculate indicators on daily data
        if len(daily_data) < max(self.parameters['bb_period'], self.parameters['vol_ma_period']):
            return  # Not enough data
            
        # Calculate Bollinger Bands
        df = daily_data.copy()
        bb = self.calculate_bollinger_bands(df['close'])
        df['bb_middle'] = bb['middle']
        df['bb_upper'] = bb['upper']
        df['bb_lower'] = bb['lower']
        df['bb_bandwidth'] = bb['bandwidth']
        
        # Calculate RSI
        df['rsi'] = self.calculate_rsi(df['close'], periods=self.parameters['rsi_period'])
        
        # Calculate MACD
        macd = self.calculate_macd(df['close'])
        df['macd'] = macd['macd']
        df['macd_signal'] = macd['signal']
        df['macd_hist'] = macd['histogram']
        
        # Calculate volume moving average
        df['volume_ma'] = df['volume'].rolling(window=self.parameters['vol_ma_period']).mean()
        
        # Calculate ATR for take profit targets
        df['atr'] = self.calculate_atr(df)
        
        # Skip if we don't have enough data
        if df.shape[0] < 3:
            return
            
        # Get the current and previous day's data for analysis
        current_day = df.iloc[-1]
        prev_day = df.iloc[-2]
        
        # Check volume spike
        volume_spike = current_day['volume'] >= self.parameters['vol_increase_factor'] * current_day['volume_ma']
        
        # Check Bollinger Band expansion (increasing volatility)
        bb_expanding = current_day['bb_bandwidth'] >= self.parameters['bb_expansion_factor'] * prev_day['bb_bandwidth']
        
        # Check for bullish breakout (long setup)
        bullish_breakout = False
        if (current_day['close'] > current_day['bb_upper'] and  # Price closed above upper band
            self.parameters['rsi_long_min'] <= current_day['rsi'] <= self.parameters['rsi_long_max'] and  # RSI in target range
            current_day['macd_hist'] > 0 and  # MACD histogram positive
            prev_day['macd_hist'] < current_day['macd_hist'] and  # MACD histogram increasing
            volume_spike and  # Volume above average
            bb_expanding):  # Volatility expanding
            
            bullish_breakout = True
            
            # Store the signal details
            self.breakout_signals[ticker]['long'] = True
            self.breakout_signals[ticker]['long_price'] = current_day['close']
            self.breakout_signals[ticker]['long_stop'] = min(current_day['low'], prev_day['low'])
            self.breakout_signals[ticker]['long_atr'] = current_day['atr']
            self.breakout_signals[ticker]['long_bb_upper'] = current_day['bb_upper']
            
            # For debugging
            if self.parameters.get('debug', False):
                print(f"[DEBUG] {ticker} - Daily BULLISH Breakout Signal:")
                print(f"  Date: {df.index[-1]}")
                print(f"  Close: ${current_day['close']:.2f}")
                print(f"  Upper BB: ${current_day['bb_upper']:.2f}")
                print(f"  RSI: {current_day['rsi']:.1f}")
                print(f"  MACD Hist: {current_day['macd_hist']:.3f}")
                print(f"  Volume: {current_day['volume']} vs MA: {current_day['volume_ma']}")
                print(f"  Bandwidth: {current_day['bb_bandwidth']:.3f} vs Prev: {prev_day['bb_bandwidth']:.3f}")
                print(f"  Entry: ${self.breakout_signals[ticker]['long_price']:.2f}")
                print(f"  Stop: ${self.breakout_signals[ticker]['long_stop']:.2f}")
                print(f"  ATR: ${current_day['atr']:.2f}")
        
        # Check for bearish breakout (short setup)
        bearish_breakout = False
        if (current_day['close'] < current_day['bb_lower'] and  # Price closed below lower band
            self.parameters['rsi_short_min'] <= current_day['rsi'] <= self.parameters['rsi_short_max'] and  # RSI in target range
            current_day['macd_hist'] < 0 and  # MACD histogram negative
            prev_day['macd_hist'] > current_day['macd_hist'] and  # MACD histogram decreasing (more negative)
            volume_spike and  # Volume above average
            bb_expanding):  # Volatility expanding
            
            bearish_breakout = True
            
            # Store the signal details
            self.breakout_signals[ticker]['short'] = True
            self.breakout_signals[ticker]['short_price'] = current_day['close']
            self.breakout_signals[ticker]['short_stop'] = max(current_day['high'], prev_day['high'])
            self.breakout_signals[ticker]['short_atr'] = current_day['atr']
            self.breakout_signals[ticker]['short_bb_lower'] = current_day['bb_lower']
            
            # For debugging
            if self.parameters.get('debug', False):
                print(f"[DEBUG] {ticker} - Daily BEARISH Breakout Signal:")
                print(f"  Date: {df.index[-1]}")
                print(f"  Close: ${current_day['close']:.2f}")
                print(f"  Lower BB: ${current_day['bb_lower']:.2f}")
                print(f"  RSI: {current_day['rsi']:.1f}")
                print(f"  MACD Hist: {current_day['macd_hist']:.3f}")
                print(f"  Volume: {current_day['volume']} vs MA: {current_day['volume_ma']}")
                print(f"  Bandwidth: {current_day['bb_bandwidth']:.3f} vs Prev: {prev_day['bb_bandwidth']:.3f}")
                print(f"  Entry: ${self.breakout_signals[ticker]['short_price']:.2f}")
                print(f"  Stop: ${self.breakout_signals[ticker]['short_stop']:.2f}")
                print(f"  ATR: ${current_day['atr']:.2f}")
                    
        # Update the last check day
        self.last_check_day[ticker] = today
        
    def generate_signal(self, ticker: str, current_data: pd.DataFrame) -> dict:
        """
        Generate trading signals based on the 1-minute chart after daily breakout pattern
        
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
            
        # Skip if no daily breakout signal
        if ticker not in self.breakout_signals or not any(self.breakout_signals[ticker].values()):
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
        
        # Check for long entry if we have a bullish breakout signal
        if (self.breakout_signals[ticker].get('long', False) and 
            not flags['long_taken']):
            
            signal_price = self.breakout_signals[ticker]['long_price']
            stop_loss = self.breakout_signals[ticker]['long_stop']
            atr = self.breakout_signals[ticker]['long_atr']
            
            # First, detect a breakout above the signal price
            if not flags['long'] and current_high > signal_price:
                flags['long'] = True
                if self.parameters.get('debug', False):
                    print(f"[DEBUG] {ticker} - LONG breakout above ${signal_price:.2f}")
                    
            # Then, wait for a retest of the breakout level
            elif flags['long']:
                # Price is retesting the breakout level
                if signal_price * (1-t) <= current_low <= signal_price * (1+t):
                    # Generate long signal
                    # Calculate take profit levels based on ATR
                    profit_target1 = current_close + 1 * atr
                    profit_target2 = current_close + 2 * atr
                    
                    # Mark the trade as taken
                    flags['long_taken'] = True
                    
                    # Create response
                    response = {
                        'signal': 'buy',
                        'entry_price': float(current_close),
                        'stop_loss': float(stop_loss),
                        'profit_target': float(profit_target1),  # Use TP1 as the primary target
                        'profit_target2': float(profit_target2), # Secondary target
                        'atr': float(atr),
                        'bb_breakout': float(self.breakout_signals[ticker].get('long_bb_upper', 0)),
                        'breakout_price': float(signal_price),
                        'rsi': float(response.get('rsi', 0)) if 'rsi' in response else None,
                        'vwap': float(response.get('vwap', 0)) if 'vwap' in response else None
                    }
                    
                    # Debug
                    if self.parameters.get('debug', False):
                        print(f"[DEBUG] {ticker} - GENERATING LONG SIGNAL:")
                        print(f"  Entry: ${current_close:.2f}")
                        print(f"  Stop: ${stop_loss:.2f}")
                        print(f"  TP1 (1x ATR): ${profit_target1:.2f}")
                        print(f"  TP2 (2x ATR): ${profit_target2:.2f}")
                    
                    return response
        
        # Check for short entry if we have a bearish breakout signal
        if (self.breakout_signals[ticker].get('short', False) and 
            not flags['short_taken']):
            
            signal_price = self.breakout_signals[ticker]['short_price']
            stop_loss = self.breakout_signals[ticker]['short_stop']
            atr = self.breakout_signals[ticker]['short_atr']
            
            # First, detect a breakdown below the signal price
            if not flags['short'] and current_low < signal_price:
                flags['short'] = True
                if self.parameters.get('debug', False):
                    print(f"[DEBUG] {ticker} - SHORT breakdown below ${signal_price:.2f}")
                    
            # Then, wait for a retest of the breakdown level
            elif flags['short']:
                # Price is retesting the breakdown level
                if signal_price * (1-t) <= current_high <= signal_price * (1+t):
                    # Generate short signal
                    # Calculate take profit levels based on ATR
                    profit_target1 = current_close - 1 * atr
                    profit_target2 = current_close - 2 * atr
                    
                    # Mark the trade as taken
                    flags['short_taken'] = True
                    
                    # Create response
                    response = {
                        'signal': 'sell',
                        'entry_price': float(current_close),
                        'stop_loss': float(stop_loss),
                        'profit_target': float(profit_target1),  # Use TP1 as the primary target
                        'profit_target2': float(profit_target2), # Secondary target
                        'atr': float(atr),
                        'bb_breakout': float(self.breakout_signals[ticker].get('short_bb_lower', 0)),
                        'breakout_price': float(signal_price),
                        'rsi': float(response.get('rsi', 0)) if 'rsi' in response else None,
                        'vwap': float(response.get('vwap', 0)) if 'vwap' in response else None
                    }
                    
                    # Debug
                    if self.parameters.get('debug', False):
                        print(f"[DEBUG] {ticker} - GENERATING SHORT SIGNAL:")
                        print(f"  Entry: ${current_close:.2f}")
                        print(f"  Stop: ${stop_loss:.2f}")
                        print(f"  TP1 (1x ATR): ${profit_target1:.2f}")
                        print(f"  TP2 (2x ATR): ${profit_target2:.2f}")
                    
                    return response
                    
        return response