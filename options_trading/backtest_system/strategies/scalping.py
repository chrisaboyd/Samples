import pandas as pd
import numpy as np
from strategies.base_strategy import BaseStrategy

class ScalpingStrategy(BaseStrategy):
    """
    Intraday scalping strategy implementation with added momentum confirmation via MACD.
    Uses volume spikes, price action, and MACD for quick profits with strict risk management.
    """
    
    def __init__(self, market_data):
        super().__init__(market_data)
        self.parameters.update({
            'timeframe': '1min',           # Use 1-minute data
            'intraday': True,              # This is an intraday strategy
            'market_open_time': '09:30',
            'market_close_time': '16:00',
            
            # Scalping-specific parameters – tuned for intraday signals
            'price_movement_threshold': 0.0005,  # 0.05% price movement (more sensitive)
            'volume_ma_period': 3,               # Very short moving average for volume
            'volume_threshold': 1.5,             # 50% above average volume
            'atr_period': 5,                     # Shorter ATR window for intraday volatility
            'atr_multiplier': 1.0,               # Use full ATR for stop loss calculations
            'min_profit_target': 0.001,          # 0.1% minimum profit target (can be refined)
            'max_hold_time': 3,                  # Maximum hold time in minutes
            'min_volume': 5000,                  # Lower volume threshold for signal validity
            'volatility_threshold': 0.002,       # ATR must be below 0.2% of price
            
            # MACD parameters for added momentum confirmation:
            'macd_fast': 5,
            'macd_slow': 13,
            'macd_signal': 5,
            
            # Time filters – can be adjusted based on further testing:
            'morning_wait_minutes': 5,           # Short wait after market open
            'avoid_lunch': False,                # Disabled for testing; enable later if needed
            'lunch_start': '12:00',
            'lunch_end': '13:00'
        })
    
    def calculate_indicators(self, price_data, volume_data):
        """
        Calculate technical indicators for the strategy.
        
        Args:
            price_data (pd.Series): Minute-by-minute price data.
            volume_data (pd.Series): Minute-by-minute volume data.
            
        Returns:
            pd.DataFrame: DataFrame with calculated indicators.
        """
        df = pd.DataFrame(index=price_data.index)
        df['price'] = price_data
        df['volume'] = volume_data
        
        # Calculate price change (percentage)
        df['price_change'] = df['price'].pct_change()
        
        # Volume indicators
        df['volume_ma'] = df['volume'].rolling(window=self.parameters['volume_ma_period']).mean()
        df['volume_ratio'] = df['volume'] / df['volume_ma']
        
        # ATR for volatility (using a simple high-low approach)
        high_low = df['price'].rolling(window=2).max() - df['price'].rolling(window=2).min()
        df['atr'] = high_low.rolling(window=self.parameters['atr_period']).mean()
        
        # MACD Calculation
        fast_span = self.parameters['macd_fast']
        slow_span = self.parameters['macd_slow']
        signal_span = self.parameters['macd_signal']
        
        df['ema_fast'] = df['price'].ewm(span=fast_span, adjust=False).mean()
        df['ema_slow'] = df['price'].ewm(span=slow_span, adjust=False).mean()
        df['macd'] = df['ema_fast'] - df['ema_slow']
        df['macd_signal'] = df['macd'].ewm(span=signal_span, adjust=False).mean()
        df['macd_hist'] = df['macd'] - df['macd_signal']
        
        return df
    
    def is_valid_trading_time(self, timestamp):
        """
        Check if the timestamp is within valid trading hours.
        
        Args:
            timestamp (pd.Timestamp): Time to check.
            
        Returns:
            bool: Whether the time is valid for trading.
        """
        if not isinstance(timestamp, pd.Timestamp):
            timestamp = pd.Timestamp(timestamp)
        current_time = timestamp.time()
        market_open = pd.to_datetime(self.parameters['market_open_time']).time()
        market_close = pd.to_datetime(self.parameters['market_close_time']).time()
        return market_open <= current_time <= market_close
    
    def validate_data_frequency(self, data):
        """
        Validate that the incoming data is 1-minute frequency.
        
        Args:
            data (pd.DataFrame/Series): Data to validate.
            
        Returns:
            bool: Whether the data frequency is correct.
        """
        if len(data) < 2:
            return True
        time_diff = pd.Series(data.index[1:]) - pd.Series(data.index[:-1])
        median_diff = time_diff.median()
        # Allow for minor variation (between 55 and 65 seconds)
        is_one_minute = pd.Timedelta(seconds=55) <= median_diff <= pd.Timedelta(seconds=65)
        if not is_one_minute:
            print(f"Warning: Data frequency appears to be {median_diff}, not 1-minute as required")
        return is_one_minute
    
    def generate_signals(self):
        """
        Generate buy/sell signals based on price action, volume, and MACD momentum.
        
        Returns:
            dict: Dictionary with tickers as keys and signal DataFrames as values.
        """
        tickers = self.market_data.get_tickers()
        self.signals = {}
        
        for ticker in tickers:
            price_data = self.market_data.get_price_data(ticker)
            volume_data = self.market_data.get_volume(ticker)
            
            if price_data.empty or volume_data.empty:
                continue
            
            # Validate that we're using 1-minute data.
            if not self.validate_data_frequency(price_data):
                print(f"Warning: {ticker} data may not be suitable for a scalping strategy")
            
            indicators = self.calculate_indicators(price_data, volume_data)
            
            # Initialize signal columns.
            indicators['buy_signal'] = 0
            indicators['sell_signal'] = 0
            
            for i in range(len(indicators)):
                timestamp = indicators.index[i]
                
                # Skip timestamps outside of valid trading hours.
                if not self.is_valid_trading_time(timestamp):
                    continue
                
                price_movement = abs(indicators['price_change'].iloc[i]) > self.parameters['price_movement_threshold']
                volume_spike = indicators['volume_ratio'].iloc[i] > self.parameters['volume_threshold']
                sufficient_volume = indicators['volume'].iloc[i] > self.parameters['min_volume']
                
                atr_value = indicators['atr'].iloc[i]
                price = indicators['price'].iloc[i]
                volatility_ok = (atr_value / price) < self.parameters['volatility_threshold']
                
                # MACD confirmation conditions:
                macd_confirmation_buy = indicators['macd'].iloc[i] > indicators['macd_signal'].iloc[i]
                macd_confirmation_sell = indicators['macd'].iloc[i] < indicators['macd_signal'].iloc[i]
                
                # Debug information (optional):
                if price_movement and volume_spike and sufficient_volume:
                    print(f"\nPotential signal at {timestamp}:")
                    print(f"  Price change: {indicators['price_change'].iloc[i]:.4f}")
                    print(f"  Volume ratio: {indicators['volume_ratio'].iloc[i]:.2f}")
                    print(f"  Volume: {indicators['volume'].iloc[i]:.0f}")
                    print(f"  ATR: {atr_value:.4f}")
                    print(f"  Price: {price:.2f}")
                    print(f"  MACD: {indicators['macd'].iloc[i]:.4f}, Signal: {indicators['macd_signal'].iloc[i]:.4f}")
                
                # Generate buy signal:
                if (price_movement and volume_spike and sufficient_volume and volatility_ok and 
                    indicators['price_change'].iloc[i] > 0 and macd_confirmation_buy):
                    indicators.iloc[i, indicators.columns.get_loc('buy_signal')] = 1
                    print(f"\nBUY SIGNAL GENERATED at {timestamp}:")
                    print(f"  Price change: {indicators['price_change'].iloc[i]:.4f}")
                    print(f"  Volume ratio: {indicators['volume_ratio'].iloc[i]:.2f}")
                    print(f"  Volume: {indicators['volume'].iloc[i]:.0f}")
                    print(f"  ATR: {atr_value:.4f}")
                    print(f"  Price: {price:.2f}")
                    print(f"  MACD: {indicators['macd'].iloc[i]:.4f}, Signal: {indicators['macd_signal'].iloc[i]:.4f}")
                
                # Generate sell signal:
                if (price_movement and volume_spike and sufficient_volume and volatility_ok and 
                    indicators['price_change'].iloc[i] < 0 and macd_confirmation_sell):
                    indicators.iloc[i, indicators.columns.get_loc('sell_signal')] = 1
                    print(f"\nSELL SIGNAL GENERATED at {timestamp}:")
                    print(f"  Price change: {indicators['price_change'].iloc[i]:.4f}")
                    print(f"  Volume ratio: {indicators['volume_ratio'].iloc[i]:.2f}")
                    print(f"  Volume: {indicators['volume'].iloc[i]:.0f}")
                    print(f"  ATR: {atr_value:.4f}")
                    print(f"  Price: {price:.2f}")
                    print(f"  MACD: {indicators['macd'].iloc[i]:.4f}, Signal: {indicators['macd_signal'].iloc[i]:.4f}")
            
            self.signals[ticker] = indicators
            print(f"\nSignal summary for {ticker}:")
            print(f"Total buy signals: {indicators['buy_signal'].sum()}")
            print(f"Total sell signals: {indicators['sell_signal'].sum()}")
            print(f"Average volume: {indicators['volume'].mean():.0f}")
            print(f"Number of volume spikes: {(indicators['volume_ratio'] > self.parameters['volume_threshold']).sum()}")
            print(f"Average ATR: {indicators['atr'].mean():.4f}")
        
        return self.signals
