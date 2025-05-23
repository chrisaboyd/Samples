from abc import ABC, abstractmethod
import pandas as pd
import numpy as np
from typing import Dict, Any

class LiveStrategy(ABC):
    def __init__(self, name: str):
        self.name = name
        self.parameters = {}
        self.data_buffer = {}  # Store data for each ticker
        
    @abstractmethod
    def generate_signal(self, ticker: str, current_data: pd.DataFrame) -> dict:
        """Generate trading signals from the current market data"""
        pass
    
    def update_data(self, ticker: str, bar_data: pd.DataFrame):
        """Update the strategy's data buffer with new bar data"""
        if ticker not in self.data_buffer:
            self.data_buffer[ticker] = bar_data
        else:
            self.data_buffer[ticker] = pd.concat([self.data_buffer[ticker], bar_data])
            # Keep only last 100 bars for memory efficiency
            self.data_buffer[ticker] = self.data_buffer[ticker].tail(100)
            
    def update_daily_bars(self, ticker: str, daily_bars: pd.DataFrame):
        """
        Update the strategy's data buffer with daily bar data
        
        This method processes daily bars and ensures they're properly formatted
        for use by the strategy. It's primarily used at startup to ensure
        we have historical context for generating signals.
        
        Args:
            ticker: Symbol being updated
            daily_bars: DataFrame with daily OHLCV data
        """
        if ticker not in self.data_buffer:
            # Initialize with daily data
            self.data_buffer[ticker] = daily_bars
        else:
            # Check if we have newer data than what's already loaded
            if len(self.data_buffer[ticker]) > 0 and len(daily_bars) > 0:
                # Get the most recent timestamp in our buffer
                last_timestamp = self.data_buffer[ticker].index[-1]
                
                # Filter daily bars to only include newer data
                new_bars = daily_bars[daily_bars.index > last_timestamp]
                
                if len(new_bars) > 0:
                    # Append the new data
                    self.data_buffer[ticker] = pd.concat([self.data_buffer[ticker], new_bars])
                    # Keep only last 100 bars for memory efficiency
                    self.data_buffer[ticker] = self.data_buffer[ticker].tail(100)
            else:
                # Just use the daily data if our buffer is empty
                self.data_buffer[ticker] = daily_bars
        
        # Ensure the index is properly sorted
        self.data_buffer[ticker] = self.data_buffer[ticker].sort_index()
            
    def calculate_rsi(self, data, periods=14, ema=True):
        """
        Calculate Relative Strength Index
        
        Args:
            data (pd.Series): Close price series
            periods (int): RSI periods (typically 14)
            ema (bool): Whether to use EMA (vs SMA)
            
        Returns:
            pd.Series: RSI values
        """
        # Calculate price changes
        delta = data.diff()
        
        # Split gains and losses
        gains = delta.copy()
        losses = delta.copy()
        gains[gains < 0] = 0
        losses[losses > 0] = 0
        losses = abs(losses)
        
        # First value is NaN
        gains.iloc[0] = 0
        losses.iloc[0] = 0
        
        # Calculate averages
        if ema:
            # Use EMA for smoother results
            avg_gain = gains.ewm(com=periods-1, min_periods=periods).mean()
            avg_loss = losses.ewm(com=periods-1, min_periods=periods).mean()
        else:
            # Use SMA for traditional RSI
            avg_gain = gains.rolling(window=periods, min_periods=periods).mean()
            avg_loss = losses.rolling(window=periods, min_periods=periods).mean()
        
        # Calculate RS and RSI
        rs = avg_gain / avg_loss
        rsi = 100 - (100 / (1 + rs))
        
        return rsi

    def calculate_vwap(self, data):
        """
        Calculate Volume Weighted Average Price
        
        Args:
            data (pd.DataFrame): DataFrame with high, low, close, and volume
            
        Returns:
            pd.Series: VWAP values
        """
        # Calculate typical price
        data['typical_price'] = (data['high'] + data['low'] + data['close']) / 3
        
        # Calculate price * volume
        data['pv'] = data['typical_price'] * data['volume']
        
        # Calculate cumulative values
        data['cumulative_pv'] = data['pv'].cumsum()
        data['cumulative_volume'] = data['volume'].cumsum()
        
        # Calculate VWAP
        data['vwap'] = data['cumulative_pv'] / data['cumulative_volume']
        
        return data['vwap']
        
    def calculate_bollinger_bands(self, data, window=20, num_std=2):
        """
        Calculate Bollinger Bands
        
        Args:
            data (pd.Series): Price series (typically close)
            window (int): The window for moving average
            num_std (float): Number of standard deviations for bands
            
        Returns:
            tuple: (middle_band, upper_band, lower_band)
        """
        # Calculate middle band (SMA)
        middle_band = data.rolling(window=window).mean()
        
        # Calculate standard deviation
        rolling_std = data.rolling(window=window).std()
        
        # Calculate upper and lower bands
        upper_band = middle_band + (rolling_std * num_std)
        lower_band = middle_band - (rolling_std * num_std)
        
        return middle_band, upper_band, lower_band
    
    def calculate_macd(self, data, fast_period=12, slow_period=26, signal_period=9):
        """
        Calculate Moving Average Convergence Divergence (MACD)
        
        Args:
            data (pd.Series): Price series (typically close)
            fast_period (int): Period for fast EMA
            slow_period (int): Period for slow EMA
            signal_period (int): Period for signal line
            
        Returns:
            tuple: (macd_line, signal_line, histogram)
        """
        # Calculate fast and slow EMAs
        ema_fast = data.ewm(span=fast_period, adjust=False).mean()
        ema_slow = data.ewm(span=slow_period, adjust=False).mean()
        
        # Calculate MACD line
        macd_line = ema_fast - ema_slow
        
        # Calculate signal line
        signal_line = macd_line.ewm(span=signal_period, adjust=False).mean()
        
        # Calculate histogram
        histogram = macd_line - signal_line
        
        return macd_line, signal_line, histogram
    
    def calculate_atr(self, data, window=14):
        """
        Calculate Average True Range (ATR)
        
        Args:
            data (pd.DataFrame): DataFrame with high, low, close columns
            window (int): Period for ATR calculation
            
        Returns:
            pd.Series: ATR values
        """
        df = data.copy()
        
        # Calculate True Range
        df['prev_close'] = df['close'].shift(1)
        df['high-low'] = df['high'] - df['low']
        df['high-prev_close'] = abs(df['high'] - df['prev_close'])
        df['low-prev_close'] = abs(df['low'] - df['prev_close'])
        
        df['tr'] = df[['high-low', 'high-prev_close', 'low-prev_close']].max(axis=1)
        
        # Calculate ATR
        atr = df['tr'].rolling(window=window).mean()
        
        return atr
    
    def calculate_obv(self, data):
        """
        Calculate On-Balance Volume (OBV)
        
        Args:
            data (pd.DataFrame): DataFrame with close and volume columns
            
        Returns:
            pd.Series: OBV values
        """
        df = data.copy()
        
        # Calculate price changes
        df['price_change'] = df['close'].diff()
        
        # Initialize OBV with first row volume
        df['obv'] = 0
        df.loc[0, 'obv'] = df.loc[0, 'volume']
        
        # Calculate OBV based on price change
        for i in range(1, len(df)):
            if df.loc[i, 'price_change'] > 0:
                df.loc[i, 'obv'] = df.loc[i-1, 'obv'] + df.loc[i, 'volume']
            elif df.loc[i, 'price_change'] < 0:
                df.loc[i, 'obv'] = df.loc[i-1, 'obv'] - df.loc[i, 'volume']
            else:
                df.loc[i, 'obv'] = df.loc[i-1, 'obv']
        
        return df['obv']
    
    def calculate_stochastic_oscillator(self, data, k_period=14, d_period=3):
        """
        Calculate Stochastic Oscillator
        
        Args:
            data (pd.DataFrame): DataFrame with high, low, close columns
            k_period (int): Period for %K line
            d_period (int): Period for %D line (signal)
            
        Returns:
            tuple: (%K, %D)
        """
        df = data.copy()
        
        # Calculate %K
        df['lowest_low'] = df['low'].rolling(window=k_period).min()
        df['highest_high'] = df['high'].rolling(window=k_period).max()
        df['%K'] = 100 * ((df['close'] - df['lowest_low']) / (df['highest_high'] - df['lowest_low']))
        
        # Calculate %D (signal line)
        df['%D'] = df['%K'].rolling(window=d_period).mean()
        
        return df['%K'], df['%D']

    def estimate_option_prices(self, option_data: Dict[str, Any], 
                              stop_loss_price: float, 
                              take_profit_price: float) -> Dict[str, Any]:
        """
        Estimate option prices at stop loss and take profit levels using Black-Scholes
        """
        try:
            if not option_data:
                return {}
            
            # Get current data
            current_price = option_data['underlying_price']
            option_price = option_data.get('mark', 1.0)
            strike = option_data['strike']
            option_type = option_data['option_type'].lower()
            days_to_expiry = option_data.get('days_to_expiry', 14)
            T = days_to_expiry / 365  # Time in years
            
            # If we have greeks from API, use them
            if 'greeks' in option_data and 'delta' in option_data['greeks']:
                # Use delta from API
                delta = option_data['greeks']['delta']
                if option_type == 'put':
                    delta = -delta  # Put delta is negative
                    
                # If we have implied volatility, use Black-Scholes
                if 'impliedVolatility' in option_data:
                    sigma = option_data['impliedVolatility']
                    r = 0.05  # Assume 5% risk-free rate (can be parameterized)
                    
                    # Use Black-Scholes to compute new prices
                    if option_type == 'call':
                        sl_price = self._bs_call(stop_loss_price, strike, T, r, sigma)
                        tp_price = self._bs_call(take_profit_price, strike, T, r, sigma)
                    else:
                        sl_price = self._bs_put(stop_loss_price, strike, T, r, sigma)
                        tp_price = self._bs_put(take_profit_price, strike, T, r, sigma)
                    
                    return {
                        'entry': option_price,
                        'stop_loss': max(0.01, sl_price),
                        'take_profit': max(0.01, tp_price),
                        'estimated_delta': delta
                    }
                
                # If no IV, use delta approximation
                if option_type == 'call':
                    sl_price_diff = stop_loss_price - current_price
                    tp_price_diff = take_profit_price - current_price
                else:
                    sl_price_diff = current_price - stop_loss_price
                    tp_price_diff = current_price - take_profit_price
                    
                sl_option_price = max(0.01, option_price + (sl_price_diff * delta))
                tp_option_price = max(0.01, option_price + (tp_price_diff * delta))
                
                return {
                    'entry': option_price,
                    'stop_loss': sl_option_price,
                    'take_profit': tp_option_price,
                    'estimated_delta': delta
                }
            
            # Otherwise, fall back to our original estimation approach
            # [existing code here]
        
        except Exception as e:
            logger.error(f"Error estimating option prices: {e}", exc_info=True)
            return {}
        
    def _bs_call(self, S, K, T, r, sigma, q=0):
        """Black-Scholes formula for call option price"""
        from scipy.stats import norm
        
        d1 = (np.log(S/K) + (r - q + sigma**2/2)*T) / (sigma*np.sqrt(T))
        d2 = d1 - sigma * np.sqrt(T)
        return S * np.exp(-q*T) * norm.cdf(d1) - K * np.exp(-r*T) * norm.cdf(d2)
    
    def _bs_put(self, S, K, T, r, sigma, q=0):
        """Black-Scholes formula for put option price"""
        from scipy.stats import norm
        
        d1 = (np.log(S/K) + (r - q + sigma**2/2)*T) / (sigma*np.sqrt(T))
        d2 = d1 - sigma * np.sqrt(T)
        return K * np.exp(-r*T) * norm.cdf(-d2) - S * np.exp(-q*T) * norm.cdf(-d1)
