import pandas as pd
import numpy as np
from backtester.portfolio import Portfolio

class Backtester:
    """
    Core backtesting engine that runs strategies and analyzes performance.
    """
    
    def __init__(self, market_data, strategy, initial_capital=100000.0, commission=0.001):
        """
        Initialize backtester with market data and strategy.
        
        Args:
            market_data (MarketData): Market data object
            strategy (BaseStrategy): Trading strategy
            initial_capital (float): Initial capital amount
            commission (float): Commission rate as decimal
        """
        self.market_data = market_data
        self.strategy = strategy
        self.initial_capital = initial_capital
        self.commission = commission
        
        self.portfolio = Portfolio(initial_capital, commission)
        self.results = None
    
    def run(self, start_date=None, end_date=None):
        """
        Run backtest between specified dates.
        
        Args:
            start_date (str, optional): Start date in 'YYYY-MM-DD' format
            end_date (str, optional): End date in 'YYYY-MM-DD' format
            
        Returns:
            dict: Backtest results
        """
        # Generate trading signals
        self.strategy.generate_signals()
        
        # Get tickers
        tickers = self.market_data.get_tickers()
        
        # Slice market data if dates are specified
        if start_date is not None or end_date is not None:
            market_data = self.market_data.slice_dates(start_date, end_date)
        else:
            market_data = self.market_data
        
        # Get consolidated dates across all tickers
        all_dates = set()
        for ticker in tickers:
            dates = market_data.get_price_data(ticker).index
            all_dates.update(dates)
        all_dates = sorted(all_dates)
        
        # Iterate through each date
        for date in all_dates:
            # Check if we need to close any positions based on stop loss/take profit
            self.portfolio.check_stop_loss_take_profit(date, market_data)
            
            # Process signals for each ticker
            for ticker in tickers:
                try:
                    # Get signals and price data
                    signals = self.strategy.get_signals(ticker)
                    price = market_data.get_price_data(ticker)
                    
                    if date not in signals.index or date not in price.index:
                        continue
                    
                    # Get current price and signals
                    current_price = price.loc[date]
                    if isinstance(current_price, pd.Series):
                        current_price = current_price.iloc[0]
                    current_price = float(current_price)
                    
                    current_signals = signals.loc[date]
                    
                    # Extract buy/sell signals as scalar values
                    buy_signal = current_signals.get('buy_signal', 0)
                    if isinstance(buy_signal, pd.Series):
                        buy_signal = buy_signal.iloc[0]
                    buy_signal = float(buy_signal)
                    
                    sell_signal = current_signals.get('sell_signal', 0)
                    if isinstance(sell_signal, pd.Series):
                        sell_signal = sell_signal.iloc[0]
                    sell_signal = float(sell_signal)
                    
                    # Process buy signal
                    if buy_signal > 0 and ticker not in self.portfolio.open_positions:
                        # Calculate position size (10% of portfolio)
                        position_size = self.portfolio.current_capital * 0.1
                        
                        # Calculate stop loss and take profit levels
                        stop_loss = current_price * (1 - self.strategy.parameters['stop_loss_pct'] / 100)
                        take_profit = current_price * (1 + self.strategy.parameters['take_profit_pct'] / 100)
                        
                        # Open long position
                        self.portfolio.buy(ticker, date, current_price, amount=position_size,
                                          stop_loss=stop_loss, take_profit=take_profit)
                    
                    # Process sell signal
                    if sell_signal > 0 and ticker in self.portfolio.open_positions:
                        position = self.portfolio.open_positions[ticker]
                        if position.direction == 1:  # Long position
                            self.portfolio.sell(ticker, date, current_price, reason='SIGNAL')
                    
                except Exception as e:
                    print(f"Error processing ticker {ticker} on {date}: {e}")
                    continue
            
            # Update equity curve
            self.portfolio.update_equity_curve(date, market_data)
        
        # Close any remaining positions at the end
        last_date = all_dates[-1] if all_dates else None
        for ticker in list(self.portfolio.open_positions.keys()):
            try:
                if ticker in self.portfolio.open_positions:
                    last_price = market_data.get_price_data(ticker).loc[last_date]
                    if isinstance(last_price, pd.Series):
                        last_price = last_price.iloc[0]
                    last_price = float(last_price)
                    
                    position = self.portfolio.open_positions[ticker]
                    
                    if position.direction == 1:  # Long position
                        self.portfolio.sell(ticker, last_date, last_price, reason='END_OF_BACKTEST')
                    else:  # Short position
                        self.portfolio.cover(ticker, last_date, last_price, reason='END_OF_BACKTEST')
            except Exception as e:
                print(f"Error closing position for {ticker} at end of backtest: {e}")
        
        # Calculate performance metrics
        self.calculate_performance()
        
        return self.results
    
    def calculate_performance(self):
        """
        Calculate performance metrics for the backtest.
        """
        # Get equity curve and trades summary
        equity = self.portfolio.get_equity_curve()
        trades = self.portfolio.get_trades_summary()
        
        # Convert trades history to DataFrame for analysis
        trades_history = pd.DataFrame(self.portfolio.trades_history)
        
        # Calculate basic metrics
        initial_capital = self.initial_capital
        final_capital = equity.iloc[-1] if not equity.empty else self.portfolio.current_capital
        
        total_return = (final_capital - initial_capital) / initial_capital * 100
        
        # Calculate daily returns
        daily_returns = equity.pct_change().dropna()
        
        # Calculate Sharpe ratio (assuming 0% risk-free rate)
        sharpe_ratio = np.sqrt(252) * daily_returns.mean() / daily_returns.std() if len(daily_returns) > 1 else 0
        
        # Calculate maximum drawdown
        cumulative_returns = (1 + daily_returns).cumprod()
        running_max = cumulative_returns.cummax()
        drawdown = (cumulative_returns / running_max - 1) * 100
        max_drawdown = drawdown.min() if not drawdown.empty else 0
        
        # Calculate trade statistics
        if not trades.empty:
            winning_trades = trades[trades['pnl'] > 0]
            losing_trades = trades[trades['pnl'] <= 0]
            
            num_trades = len(trades)
            num_winning = len(winning_trades)
            num_losing = len(losing_trades)
            
            win_rate = num_winning / num_trades * 100 if num_trades > 0 else 0
            
            avg_win = winning_trades['pnl'].mean() if not winning_trades.empty else 0
            avg_loss = losing_trades['pnl'].mean() if not losing_trades.empty else 0
            
            avg_win_loss_ratio = abs(avg_win / avg_loss) if avg_loss != 0 else float('inf')
            
            gross_profit = winning_trades['pnl'].sum() if not winning_trades.empty else 0
            gross_loss = losing_trades['pnl'].sum() if not losing_trades.empty else 0
            
            profit_factor = abs(gross_profit / gross_loss) if gross_loss != 0 else float('inf')
        else:
            num_trades = 0
            win_rate = 0
            avg_win_loss_ratio = 0
            profit_factor = 0
        
        # Store results
        self.results = {
            'initial_capital': initial_capital,
            'final_capital': final_capital,
            'total_return_pct': total_return,
            'sharpe_ratio': sharpe_ratio,
            'max_drawdown_pct': max_drawdown,
            'num_trades': num_trades,
            'win_rate_pct': win_rate,
            'avg_win_loss_ratio': avg_win_loss_ratio,
            'profit_factor': profit_factor,
            'equity_curve': equity,
            'trades': trades,
            'trades_history': trades_history,
            'daily_returns': daily_returns
        }


