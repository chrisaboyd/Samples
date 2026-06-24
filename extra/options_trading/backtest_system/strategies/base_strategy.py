import pandas as pd
import numpy as np

class BaseStrategy:
    """
    Base class for all trading strategies.
    Defines the common interface and utility methods.
    """
    
    def __init__(self, market_data):
        """
        Initialize strategy with market data.
        
        Args:
            market_data (MarketData): Market data object
        """
        self.market_data = market_data
        self.signals = {}
        self.parameters = {
            'timeframe': 'D',  # Default to daily timeframe
            'intraday': False,  # Whether strategy requires intraday data
            'market_open_time': '09:30',  # Market open time
            'market_close_time': '16:00', # Market close time
        }
        
    def set_parameters(self, **kwargs):
        """
        Set strategy parameters.
        
        Args:
            **kwargs: Key-value pairs of parameters
                timeframe: str, data frequency ('1min', '5min', '15min', 'H', 'D', etc.)
                intraday: bool, whether strategy requires intraday data
                market_open_time: str, market open time (HH:MM)
                market_close_time: str, market close time (HH:MM)
        """
        self.parameters.update(kwargs)
        return self
        
    def generate_signals(self):
        """
        Generate trading signals based on the strategy.
        Should be implemented by subclasses.
        
        Returns:
            dict: Dictionary with tickers as keys and signal DataFrames as values
        """
        raise NotImplementedError("Subclasses must implement generate_signals()")
    
    def get_signals(self, ticker=None):
        """
        Get generated signals for a specific ticker.
        
        Args:
            ticker (str, optional): Ticker symbol. If None, returns all signals.
        
        Returns:
            pd.DataFrame or dict: Signals for specified ticker or all tickers
        """
        if not self.signals:
            self.generate_signals()
            
        if ticker is None:
            return self.signals
        elif ticker in self.signals:
            return self.signals[ticker]
        else:
            raise ValueError(f"No signals for ticker {ticker}")
            
    def plot_signals(self, ticker, ax=None):
        """
        Plot price data with buy/sell signals.
        
        Args:
            ticker (str): Ticker symbol
            ax (matplotlib.axes, optional): Axes to plot on
        """
        import matplotlib.pyplot as plt
        
        if ax is None:
            fig, ax = plt.subplots(figsize=(12, 6))
            
        signals = self.get_signals(ticker)
        price = self.market_data.get_price_data(ticker)
        
        # Plot price
        ax.plot(price.index, price, label=f"{ticker} Close Price", color='blue', alpha=0.6)
        
        # Plot buy signals
        if 'buy_signal' in signals.columns:
            buy_points = signals[signals['buy_signal'] > 0]
            ax.scatter(buy_points.index, price.loc[buy_points.index], 
                      color='green', marker='^', s=100, label='Buy Signal')
        
        # Plot sell signals
        if 'sell_signal' in signals.columns:
            sell_points = signals[signals['sell_signal'] > 0]
            ax.scatter(sell_points.index, price.loc[sell_points.index], 
                      color='red', marker='v', s=100, label='Sell Signal')
        
        ax.set_title(f"{ticker} Price with {self.__class__.__name__} Signals")
        ax.set_xlabel('Date')
        ax.set_ylabel('Price')
        ax.legend()
        ax.grid(True)
        
        return ax

    def is_valid_trading_time(self, timestamp):
        """
        Check if current time is valid for trading.
        
        Args:
            timestamp (pd.Timestamp): Current timestamp
            
        Returns:
            bool: Whether trading is allowed
        """
        # If not intraday, always return True
        if not self.parameters.get('intraday', False):
            return True
            
        current_time = timestamp.time()
        market_open = pd.to_datetime(self.parameters['market_open_time']).time()
        market_close = pd.to_datetime(self.parameters['market_close_time']).time()
        
        return market_open <= current_time <= market_close
    
    def get_timeframe(self):
        """
        Get strategy timeframe.
        
        Returns:
            str: Timeframe specification
        """
        return self.parameters.get('timeframe', 'D')
    
    def is_intraday(self):
        """
        Check if strategy is intraday.
        
        Returns:
            bool: Whether strategy operates on intraday data
        """
        return self.parameters.get('intraday', False)

