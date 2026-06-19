import pandas as pd
import numpy as np
from strategies.base_strategy import BaseStrategy

class ScalpingStrategy(BaseStrategy):
    """
    Intraday scalping strategy implementation.
    Uses volume spikes and price action for quick profits with strict risk management.
    """
    
    def __init__(self, market_data):
        """
        Initialize with market data.
        
        Args:
            market_data (MarketData): Market data object
        """
        super().__init__(market_data)
        
        # Update base parameters for intraday trading
        self.parameters.update({
            'timeframe': '1min',  # Use 1-minute data
            'intraday': True,     # This is an intraday strategy
            'market_open_time': '09:30',
            'market_close_time': '16:00',
            
            # Scalping-specific parameters - adjusted for 1-minute data
            'price_movement_threshold': 0.0005,  # 0.05% price movement (more sensitive)
            'volume_ma_period': 3,              # Very short MA for recent volume
            'volume_threshold': 1.5,            # 50% above average volume
            'atr_period': 5,                    # Shorter ATR for intraday volatility
            'atr_multiplier': 1.0,             # Full ATR for stop loss
            'min_profit_target': 0.001,        # 0.1% minimum profit (reduced)
            'max_hold_time': 3,                # Maximum 3 minutes hold time
            'min_volume': 5000,                # Lower volume threshold
            
            # Time filters - can be adjusted based on testing
            'morning_wait_minutes': 5,         # Short wait after open
            'avoid_lunch': False,              # Disabled for testing
            'lunch_start': '12:00',
            'lunch_end': '13:00'
        })
    
    def calculate_indicators(self, price_data, volume_data):
        """
        Calculate technical indicators for the strategy.
        
        Args:
            price_data (pd.Series): Minute-by-minute price data
            volume_data (pd.Series): Minute-by-minute volume data
            
        Returns:
            pd.DataFrame: DataFrame with calculated indicators
        """
        df = pd.DataFrame(index=price_data.index)
        df['price'] = price_data
        df['volume'] = volume_data
        
        # Price movement
        df['price_change'] = df['price'].pct_change()
        
        # Volume indicators
        df['volume_ma'] = df['volume'].rolling(window=self.parameters['volume_ma_period']).mean()
        df['volume_ratio'] = df['volume'] / df['volume_ma']
        
        # ATR for volatility
        high_low = df['price'].rolling(window=2).max() - df['price'].rolling(window=2).min()
        df['atr'] = high_low.rolling(window=self.parameters['atr_period']).mean()
        
        return df
        
    def is_valid_trading_time(self, timestamp):
        """
        Check if the timestamp is within valid trading hours.
        More lenient version for testing purposes.
        
        Args:
            timestamp (pd.Timestamp): Time to check
            
        Returns:
            bool: Whether the time is valid for trading
        """
        if not isinstance(timestamp, pd.Timestamp):
            timestamp = pd.Timestamp(timestamp)
        
        # For testing: Only check if it's within market hours
        current_time = timestamp.time()
        market_open = pd.to_datetime(self.parameters['market_open_time']).time()
        market_close = pd.to_datetime(self.parameters['market_close_time']).time()
        
        return market_open <= current_time <= market_close

    def validate_data_frequency(self, data):
        """
        Validate that we're working with 1-minute data.
        
        Args:
            data (pd.DataFrame/Series): Data to validate
            
        Returns:
            bool: Whether the data frequency is correct
        """
        if len(data) < 2:
            return True
            
        # Check time difference between consecutive points
        time_diff = pd.Series(data.index[1:]) - pd.Series(data.index[:-1])
        median_diff = time_diff.median()
        
        # Allow some flexibility (between 55-65 seconds)
        is_one_minute = pd.Timedelta(seconds=55) <= median_diff <= pd.Timedelta(seconds=65)
        
        if not is_one_minute:
            print(f"Warning: Data frequency appears to be {median_diff}, not 1-minute as required")
            
        return is_one_minute

    def generate_signals(self):
        """
        Generate buy/sell signals based on price action and volume.
        
        Returns:
            dict: Dictionary with tickers as keys and signal DataFrames as values
        """
        tickers = self.market_data.get_tickers()
        self.signals = {}
        
        for ticker in tickers:
            price_data = self.market_data.get_price_data(ticker)
            volume_data = self.market_data.get_volume(ticker)
            
            if price_data.empty or volume_data.empty:
                continue
            
            # Validate data frequency
            if not self.validate_data_frequency(price_data):
                print(f"Warning: {ticker} data may not be suitable for scalping strategy")
                
            indicators = self.calculate_indicators(price_data, volume_data)
            
            # Initialize signal columns
            indicators['buy_signal'] = 0
            indicators['sell_signal'] = 0
            
            for i in range(len(indicators)):
                timestamp = indicators.index[i]
                
                # Skip if not valid trading time
                if not self.is_valid_trading_time(timestamp):
                    continue
                
                # Price movement condition
                price_movement = abs(indicators['price_change'].iloc[i]) > self.parameters['price_movement_threshold']
                
                # Volume condition
                volume_spike = indicators['volume_ratio'].iloc[i] > self.parameters['volume_threshold']
                sufficient_volume = indicators['volume'].iloc[i] > self.parameters['min_volume']
                
                # Volatility condition
                atr_value = indicators['atr'].iloc[i]
                price = indicators['price'].iloc[i]
                volatility_ok = atr_value / price < 0.002  # ATR less than 0.2% of price
                
                # Debug info for almost-triggered conditions
                if price_movement and volume_spike and sufficient_volume:
                    print(f"\nPotential signal at {timestamp}:")
                    print(f"  Price change: {indicators['price_change'].iloc[i]:.4f}")
                    print(f"  Volume ratio: {indicators['volume_ratio'].iloc[i]:.2f}")
                    print(f"  Volume: {indicators['volume'].iloc[i]:.0f}")
                    print(f"  ATR: {atr_value:.4f}")
                    print(f"  Price: {price:.2f}")
                
                # Generate buy signal
                if (price_movement and volume_spike and sufficient_volume and volatility_ok and 
                    indicators['price_change'].iloc[i] > 0):
                    indicators.iloc[i, indicators.columns.get_loc('buy_signal')] = 1
                    print(f"\nBUY SIGNAL GENERATED at {timestamp}:")
                    print(f"  Price change: {indicators['price_change'].iloc[i]:.4f}")
                    print(f"  Volume ratio: {indicators['volume_ratio'].iloc[i]:.2f}")
                    print(f"  Volume: {indicators['volume'].iloc[i]:.0f}")
                    print(f"  ATR: {atr_value:.4f}")
                    print(f"  Price: {price:.2f}")
                
                # Generate sell signal
                if (price_movement and volume_spike and sufficient_volume and volatility_ok and 
                    indicators['price_change'].iloc[i] < 0):
                    indicators.iloc[i, indicators.columns.get_loc('sell_signal')] = 1
                    print(f"\nSELL SIGNAL GENERATED at {timestamp}:")
                    print(f"  Price change: {indicators['price_change'].iloc[i]:.4f}")
                    print(f"  Volume ratio: {indicators['volume_ratio'].iloc[i]:.2f}")
                    print(f"  Volume: {indicators['volume'].iloc[i]:.0f}")
                    print(f"  ATR: {atr_value:.4f}")
                    print(f"  Price: {price:.2f}")
            
            self.signals[ticker] = indicators
            
            # Print debug info
            print(f"\nSignal summary for {ticker}:")
            print(f"Total buy signals: {indicators['buy_signal'].sum()}")
            print(f"Total sell signals: {indicators['sell_signal'].sum()}")
            print(f"Average volume: {indicators['volume'].mean():.0f}")
            print(f"Number of volume spikes: {(indicators['volume_ratio'] > self.parameters['volume_threshold']).sum()}")
            print(f"Average ATR: {indicators['atr'].mean():.4f}")
        
        return self.signals

