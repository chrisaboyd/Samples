from abc import ABC, abstractmethod
import pandas as pd
import os
import pickle

class LiveStrategy(ABC):
    def __init__(self, name: str):
        self.name = name
        self.parameters = {
            'debug': True  # Enable debug logging by default
        }
        self.data_buffer = {}  # Store data for each ticker
        self.daily_data = self._load_daily_data()  # Load daily data on initialization
        
    def _load_daily_data(self) -> dict:
        """Load daily bars from saved file"""
        try:
            daily_bars_path = os.path.join('saved_data', 'daily_bars.pkl')
            if os.path.exists(daily_bars_path):
                with open(daily_bars_path, 'rb') as f:
                    data = pickle.load(f)
                if self.parameters.get('debug', True):
                    print(f"[DEBUG] {self.name} - Loaded daily data for {len(data)} symbols")
                return data
            else:
                if self.parameters.get('debug', True):
                    print(f"[DEBUG] {self.name} - No daily bars file found at {daily_bars_path}")
                return {}
        except Exception as e:
            if self.parameters.get('debug', True):
                print(f"[DEBUG] {self.name} - Error loading daily bars: {e}")
            return {}
            
    def get_daily_df(self, ticker: str) -> pd.DataFrame:
        """
        Convert daily data dictionary for a ticker into a DataFrame
        
        Args:
            ticker: The symbol to get data for
            
        Returns:
            DataFrame with OHLCV data or empty DataFrame if no data available
        """
        if not self.daily_data or ticker not in self.daily_data:
            if self.parameters.get('debug', True):
                print(f"[DEBUG] {self.name} - No daily data available for {ticker}")
            return pd.DataFrame()
            
        # Convert daily data dictionary to DataFrame
        ticker_data = self.daily_data[ticker]
        daily_df = pd.DataFrame({
            'open': pd.Series(ticker_data['open']),
            'high': pd.Series(ticker_data['high']),
            'low': pd.Series(ticker_data['low']),
            'close': pd.Series(ticker_data['close']),
            'volume': pd.Series(ticker_data['volume'])
        })
        
        # Sort by index (timestamp) to ensure correct order
        daily_df.sort_index(inplace=True)
        
        if self.parameters.get('debug', True):
            print(f"[DEBUG] {self.name} - Loaded {len(daily_df)} daily bars for {ticker}")
            
        return daily_df

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