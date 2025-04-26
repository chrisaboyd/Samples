from strategies.base_strategy import BaseStrategy
import pandas as pd
import numpy as np

class SimpleStrategy(BaseStrategy):
    """
    A simple strategy for backtesting purposes.
    This strategy generates random buy and sell signals with configurable parameters.
    Useful for testing portfolio and position management features like stop loss and take profit.
    """
    
    def __init__(self, market_data):
        super().__init__(market_data)
        self.parameters.update({
            'timeframe': 'D',           # Daily timeframe
            'intraday': False,          # Not an intraday strategy
            
            # Strategy-specific parameters
            'buy_probability': 0.05,    # 5% chance of buy signal on any day
            'sell_probability': 0.10,   # 10% chance of sell signal on any day
            'stop_loss_pct': 2.0,       # 2% stop loss
            'take_profit_pct': 5.0,     # 5% take profit
            'position_size_pct': 10.0,  # 10% of equity per position
            'max_positions': 5,         # Maximum number of open positions
            'random_seed': 42           # For reproducibility
        })
        np.random.seed(self.parameters['random_seed'])
        
    def generate_signals(self):
        """
        Generate random buy and sell signals for all tickers in the market data.
        
        Returns:
            dict: Dictionary with tickers as keys and signal DataFrames as values
        """
        tickers = self.market_data.get_tickers()
        self.signals = {}
        
        for ticker in tickers:
            # Get price data
            price_data = self.market_data.get_price_data(ticker)
            
            # Initialize signals DataFrame
            signals = pd.DataFrame(index=price_data.index)
            signals['price'] = price_data
            signals['buy_signal'] = 0
            signals['sell_signal'] = 0
            signals['stop_loss'] = 0
            signals['take_profit'] = 0
            
            # Random buy signals
            random_buys = np.random.random(len(signals)) < self.parameters['buy_probability']
            signals.loc[random_buys, 'buy_signal'] = 1
            
            # Random sell signals
            random_sells = np.random.random(len(signals)) < self.parameters['sell_probability']
            signals.loc[random_sells, 'sell_signal'] = 1
            
            # Calculate stop loss and take profit levels for buys
            buy_indices = signals[signals['buy_signal'] == 1].index
            for buy_idx in buy_indices:
                buy_price = signals.loc[buy_idx, 'price']
                signals.loc[buy_idx, 'stop_loss'] = buy_price * (1 - self.parameters['stop_loss_pct'] / 100)
                signals.loc[buy_idx, 'take_profit'] = buy_price * (1 + self.parameters['take_profit_pct'] / 100)
            
            self.signals[ticker] = signals
            
        return self.signals
    
    def get_position_size(self, equity, ticker=None):
        """
        Calculate position size based on current equity.
        
        Args:
            equity (float): Current equity
            ticker (str, optional): Ticker symbol
            
        Returns:
            float: Position size as percentage of equity
        """
        return equity * (self.parameters['position_size_pct'] / 100)
    
    def get_stop_loss(self, ticker, entry_price, position_type='long'):
        """
        Calculate stop loss level for a position.
        
        Args:
            ticker (str): Ticker symbol
            entry_price (float): Entry price
            position_type (str): 'long' or 'short'
            
        Returns:
            float: Stop loss price level
        """
        if position_type == 'long':
            return entry_price * (1 - self.parameters['stop_loss_pct'] / 100)
        else:  # short position
            return entry_price * (1 + self.parameters['stop_loss_pct'] / 100)
    
    def get_take_profit(self, ticker, entry_price, position_type='long'):
        """
        Calculate take profit level for a position.
        
        Args:
            ticker (str): Ticker symbol
            entry_price (float): Entry price
            position_type (str): 'long' or 'short'
            
        Returns:
            float: Take profit price level
        """
        if position_type == 'long':
            return entry_price * (1 + self.parameters['take_profit_pct'] / 100)
        else:  # short position
            return entry_price * (1 - self.parameters['take_profit_pct'] / 100) 