import pandas as pd
import numpy as np
from strategies.base_strategy import BaseStrategy

class ScalpingStrategy(BaseStrategy):
    """
    Simple scalping strategy implementation.
    Uses short-term price movements for quick profits.
    """
    
    def __init__(self, market_data):
        """
        Initialize with market data.
        
        Args:
            market_data (MarketData): Market data object
        """
        super().__init__(market_data)
        
        # Default parameters
        self.parameters = {
            'ema_short': 5,        # Short-term EMA period (reduced from 9)
            'ema_long': 15,        # Long-term EMA period (reduced from 21)
            'rsi_period': 14,      # RSI calculation period
            'rsi_overbought': 65,  # RSI overbought threshold (reduced from 70)
            'rsi_oversold': 35,    # RSI oversold threshold (increased from 30)
            'stop_loss_pct': 0.5,  # Stop loss percentage
            'take_profit_pct': 1.0 # Take profit percentage
        }
    
    def calculate_indicators(self, price_data):
        """
        Calculate technical indicators for the strategy.
        
        Args:
            price_data (pd.Series): Price data series
            
        Returns:
            pd.DataFrame: DataFrame with calculated indicators
        """
        df = pd.DataFrame(index=price_data.index)
        df['price'] = price_data
        
        # Calculate EMAs
        df['ema_short'] = price_data.ewm(span=self.parameters['ema_short'], adjust=False).mean()
        df['ema_long'] = price_data.ewm(span=self.parameters['ema_long'], adjust=False).mean()
        
        # Calculate RSI
        delta = price_data.diff()
        gain = (delta.where(delta > 0, 0)).fillna(0)
        loss = (-delta.where(delta < 0, 0)).fillna(0)
        
        avg_gain = gain.rolling(window=self.parameters['rsi_period']).mean()
        avg_loss = loss.rolling(window=self.parameters['rsi_period']).mean()
        
        rs = avg_gain / avg_loss
        df['rsi'] = 100 - (100 / (1 + rs))
        
        return df
        
    def generate_signals(self):
        """
        Generate buy/sell signals based on EMA crossover and RSI.
        
        Returns:
            dict: Dictionary with tickers as keys and signal DataFrames as values
        """
        tickers = self.market_data.get_tickers()
        self.signals = {}
        
        for ticker in tickers:
            price_data = self.market_data.get_price_data(ticker)
            indicators = self.calculate_indicators(price_data)
            
            # Initialize signal columns
            indicators['buy_signal'] = 0
            indicators['sell_signal'] = 0
            
            # EMA crossover (buy when short crosses above long)
            ema_cross_above = (indicators['ema_short'] > indicators['ema_long']) & \
                              (indicators['ema_short'].shift(1) <= indicators['ema_long'].shift(1))
            
            # EMA crossover (sell when short crosses below long)
            ema_cross_below = (indicators['ema_short'] < indicators['ema_long']) & \
                              (indicators['ema_short'].shift(1) >= indicators['ema_long'].shift(1))
            
            # RSI conditions
            rsi_oversold = indicators['rsi'] < self.parameters['rsi_oversold']
            rsi_overbought = indicators['rsi'] > self.parameters['rsi_overbought']
            
            # Print debugging information
            print(f"\nSignal conditions for {ticker}:")
            print(f"EMA cross above: {ema_cross_above.sum()} occurrences")
            print(f"EMA cross below: {ema_cross_below.sum()} occurrences")
            print(f"RSI oversold: {rsi_oversold.sum()} occurrences")
            print(f"RSI overbought: {rsi_overbought.sum()} occurrences")
            
            # Buy signal: EMA cross above OR RSI oversold (changed from AND to OR)
            buy_condition = ema_cross_above | rsi_oversold
            indicators.loc[buy_condition, 'buy_signal'] = 1
            
            # Sell signal: EMA cross below OR RSI overbought
            sell_condition = ema_cross_below | rsi_overbought
            indicators.loc[sell_condition, 'sell_signal'] = 1
            
            print(f"Total buy signals: {indicators['buy_signal'].sum()}")
            print(f"Total sell signals: {indicators['sell_signal'].sum()}")
            
            self.signals[ticker] = indicators
            
        return self.signals

