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
        self.reversal_signals = {}       # Reversal signals from daily timeframe 
        self.breakout_flags = {}         # Flags for intraday breakout/retest
        self.last_check_day = {}         # Last day we checked for reversal pattern

    def check_reversal_pattern(self, ticker: str) -> None:
        """
        Check for reversal patterns using daily data
        """
        # Get today's date
        today = datetime.now().date()
        
        # If we already checked for today, skip
        if ticker in self.last_check_day and self.last_check_day[ticker] == today:
            return
            
        # Get daily data from base class
        df = self.get_daily_df(ticker)
        
        if df.empty or len(df) < self.parameters['bb_period']:
            if self.parameters['debug']:
                print(f"[DEBUG] {self.name} - Insufficient daily data for {ticker}: {len(df)} bars")
            return
            
        # Initialize ticker data structures if first time seeing ticker
        if ticker not in self.reversal_signals:
            self.reversal_signals[ticker] = {'long': False, 'short': False}
            self.breakout_flags[ticker] = {'long': False, 'short': False, 'long_taken': False, 'short_taken': False}
            self.last_check_day[ticker] = None
            
        # Calculate indicators
        middle_band, upper_band, lower_band = self.calculate_bollinger_bands(
            df['close'],
            window=self.parameters['bb_period'],
            num_std=self.parameters['bb_std_dev']
        )
        df['bb_middle'] = middle_band
        df['bb_upper'] = upper_band
        df['bb_lower'] = lower_band
        
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
                if self.parameters['debug']:
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
                if self.parameters['debug']:
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
        
        # Check for reversal patterns using daily data
        self.check_reversal_pattern(ticker)
        
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
                if self.parameters['debug']:
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
                    if self.parameters['debug']:
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
                if self.parameters['debug']:
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
                    if self.parameters['debug']:
                        print(f"[DEBUG] {ticker} - GENERATING SHORT SIGNAL:")
                        print(f"  Pattern: {pattern}")
                        print(f"  Entry: ${current_close:.2f}")
                        print(f"  Stop: ${stop_loss:.2f}")
                        print(f"  TP1: ${profit_target1:.2f}")
                        print(f"  TP2: ${profit_target2:.2f}")
                    
                    return response
                    
        return response