import pandas as pd
import numpy as np
from backtester.portfolio import Portfolio
import time
from tqdm import tqdm

class Backtester:
    """
    Core backtesting engine that runs strategies and analyzes performance.
    """
    
    def __init__(self, market_data, strategy, initial_capital=100000.0, commission=0.001, start_date=None, end_date=None):
        """
        Initialize backtester with market data and strategy.
        
        Args:
            market_data (MarketData): Market data object
            strategy (BaseStrategy): Trading strategy
            initial_capital (float): Initial capital amount
            commission (float): Commission rate as decimal
            start_date (datetime, optional): Start date for backtesting
            end_date (datetime, optional): End date for backtesting
        """
        self.market_data = market_data
        self.strategy = strategy
        self.initial_capital = initial_capital
        self.commission = commission
        self.start_date = start_date
        self.end_date = end_date
        self.data = market_data.data
        
        self.portfolio = Portfolio(initial_capital, commission)
        self.results = None
    
    def run(self):
        """
        Run the backtest.
        """
        print(f"Starting backtest from {self.start_date} to {self.end_date}")
        
        # Initialize start time for performance tracking
        start_time = time.time()
        
        # Generate signals first
        print("Generating signals...")
        signals_dict = self.strategy.generate_signals()
        
        # Get all trading days in the date range
        all_dates = []
        for ticker, signal_df in signals_dict.items():
            all_dates.extend(signal_df.index.tolist())
        all_dates = sorted(list(set(all_dates)))
        print(f"Found {len(all_dates)} unique timestamps in signals")
        
        # Filter dates based on start_date and end_date if provided
        if self.start_date is not None:
            all_dates = [d for d in all_dates if d >= self.start_date]
        if self.end_date is not None:
            all_dates = [d for d in all_dates if d <= self.end_date]
        
        # Track signals and executions for performance analysis
        total_signals = 0
        executed_signals = 0
        skipped_signals = 0
        
        # Main backtest loop over all timestamps
        print(f"Processing {len(all_dates)} timestamps")
        for current_time in tqdm(all_dates, desc="Running backtest"):
            # Process signals for each ticker
            for ticker, signal_df in signals_dict.items():
                if current_time not in signal_df.index:
                    continue
                    
                # Get the signals for current timestamp
                current_signals = signal_df.loc[current_time]
                
                # Check if we have any buy or sell signals
                if current_signals['buy_signal'] > 0:
                    total_signals += 1
                    
                    # Get signal details
                    entry_price = current_signals['entry_price']
                    stop_loss = current_signals['stop_loss']
                    take_profit = current_signals['profit_target']
                    
                    # Risk calculation (optional)
                    risk_per_share = abs(entry_price - stop_loss)
                    risk_amount = self.portfolio.current_capital * 0.02  # Risk 2% of capital
                    
                    if risk_per_share > 0:
                        num_shares = 100
                        
                        # Set the position size
                        self.portfolio.current_position_size = num_shares
                        
                        # Execute the buy trade
                        position = self.portfolio.buy(ticker, current_time, entry_price, 
                                                   stop_loss=stop_loss, 
                                                   take_profit=take_profit)
                        if position:
                            executed_signals += 1
                            print(f"BUY {ticker} at {current_time}: {num_shares} shares at ${entry_price:.2f}")
                        else:
                            skipped_signals += 1
                            
                elif current_signals['sell_signal'] > 0:
                    total_signals += 1
                    
                    # Get signal details
                    entry_price = current_signals['entry_price']
                    stop_loss = current_signals['stop_loss']
                    take_profit = current_signals['profit_target']
                    
                    # Risk calculation (optional)
                    risk_per_share = abs(entry_price - stop_loss)
                    risk_amount = self.portfolio.current_capital * 0.02  # Risk 2% of capital
                    
                    if risk_per_share > 0:
                        num_shares = 100
                        
                        # Set the position size
                        self.portfolio.current_position_size = num_shares
                        
                        # Execute the sell trade
                        position = self.portfolio.sell(ticker, current_time, entry_price, 
                                                    stop_loss=stop_loss, 
                                                    take_profit=take_profit)
                        if position:
                            executed_signals += 1
                            print(f"SELL {ticker} at {current_time}: {num_shares} shares at ${entry_price:.2f}")
                        else:
                            skipped_signals += 1
            
            # Get market data for all tickers at this timestamp and update positions
            ticker_data = {}
            for ticker in signals_dict.keys():
                try:
                    # Get price data for this ticker at current timestamp
                    price_data = self.market_data.get_price_data(ticker)
                    if current_time in price_data.index:
                        ticker_data[ticker] = price_data.loc[current_time]
                except Exception as e:
                    print(f"Error getting data for {ticker} at {current_time}: {e}")
            
            # Update positions with latest data
            if ticker_data:
                # Convert ticker_data to format expected by update_positions
                market_frame = pd.DataFrame.from_dict(ticker_data, orient='index')
                market_frame['ticker'] = market_frame.index
                market_frame.reset_index(drop=True, inplace=True)
                
                self.portfolio.update_positions(current_time, market_frame)
        
        # Calculate and print performance metrics
        elapsed_time = time.time() - start_time
        print(f"Backtest completed in {elapsed_time:.2f} seconds")
        print(f"Total signals generated: {total_signals}")
        print(f"Executed signals: {executed_signals}")
        print(f"Skipped signals: {skipped_signals}")
        if total_signals > 0:
            print(f"Execution rate: {executed_signals/total_signals*100:.2f}%")
        
        # Print detailed trade summary
        self.portfolio.print_trade_summary()
        
        # Calculate performance metrics
        self.calculate_performance_metrics()
        
        return self.results
    
    def calculate_performance_metrics(self):
        """
        Calculate performance metrics for the backtest.
        """
        # Get equity curve and trades summary
        equity = self.portfolio.get_equity_curve()
        trades = self.portfolio.get_trades_summary()
        
        # Convert trades history to DataFrame for analysis
        trades_history = pd.DataFrame(self.portfolio.trades_history) if self.portfolio.trades_history else pd.DataFrame()
        
        # Calculate basic metrics
        initial_capital = self.initial_capital
        final_capital = equity.iloc[-1] if not equity.empty else self.portfolio.current_capital
        
        total_return = (final_capital - initial_capital) / initial_capital * 100
        
        # Calculate daily returns - ensure we're working with numeric values
        if not equity.empty:
            # Make sure we have a clean Series of numeric values
            equity_numeric = pd.to_numeric(equity, errors='coerce')
            daily_returns = equity_numeric.pct_change().dropna()
            
            # Calculate Sharpe ratio (assuming 0% risk-free rate)
            if len(daily_returns) > 1:
                # Ensure values are numeric before calculating statistics
                try:
                    mean_return = daily_returns.mean()
                    std_return = daily_returns.std()
                    if std_return > 0:
                        sharpe_ratio = np.sqrt(252) * mean_return / std_return
                    else:
                        sharpe_ratio = 0
                except Exception:
                    print("Warning: Could not calculate Sharpe ratio, setting to 0")
                    sharpe_ratio = 0
            else:
                sharpe_ratio = 0
            
            # Calculate maximum drawdown
            try:
                cumulative_returns = (1 + daily_returns).cumprod()
                running_max = cumulative_returns.cummax()
                drawdown = (cumulative_returns / running_max - 1) * 100
                max_drawdown = drawdown.min() if not drawdown.empty else 0
            except Exception:
                print("Warning: Could not calculate maximum drawdown, setting to 0")
                max_drawdown = 0
        else:
            daily_returns = pd.Series()
            sharpe_ratio = 0
            max_drawdown = 0
        
        # Calculate trade statistics using both trades and trades_history
        # trades contains closed position info, trades_history contains all trade actions
        # First check if we have any completed trades in closed_positions
        num_trades = len(self.portfolio.closed_positions)
        
        if num_trades > 0:
            # Calculate statistics based on closed positions
            winning_trades = [p for p in self.portfolio.closed_positions if p.pnl > 0]
            losing_trades = [p for p in self.portfolio.closed_positions if p.pnl <= 0]
            
            num_winning = len(winning_trades)
            num_losing = len(losing_trades)
            
            win_rate = (num_winning / num_trades * 100) if num_trades > 0 else 0
            
            avg_win = sum(p.pnl for p in winning_trades) / num_winning if num_winning > 0 else 0
            avg_loss = sum(p.pnl for p in losing_trades) / num_losing if num_losing > 0 else 0
            
            avg_win_loss_ratio = abs(avg_win / avg_loss) if avg_loss != 0 and not np.isnan(avg_loss) and avg_loss < 0 else float('inf')
            
            gross_profit = sum(p.pnl for p in winning_trades)
            gross_loss = sum(p.pnl for p in losing_trades)
            
            profit_factor = abs(gross_profit / gross_loss) if gross_loss != 0 and not np.isnan(gross_loss) and gross_loss < 0 else float('inf')
        
        # If we don't have closed_positions data, try using trades_history
        elif not trades_history.empty and 'pnl' in trades_history.columns:
            # Filter out non-exit actions
            exit_trades = trades_history[trades_history['action'].isin(['SELL', 'COVER'])]
            
            num_trades = len(exit_trades)
            
            winning_trades = exit_trades[exit_trades['pnl'] > 0]
            losing_trades = exit_trades[exit_trades['pnl'] <= 0]
            
            num_winning = len(winning_trades)
            num_losing = len(losing_trades)
            
            win_rate = (num_winning / num_trades * 100) if num_trades > 0 else 0
            
            avg_win = winning_trades['pnl'].mean() if not winning_trades.empty else 0
            avg_loss = losing_trades['pnl'].mean() if not losing_trades.empty else 0
            
            avg_win_loss_ratio = abs(avg_win / avg_loss) if avg_loss != 0 and not np.isnan(avg_loss) and avg_loss < 0 else float('inf')
            
            gross_profit = winning_trades['pnl'].sum() if not winning_trades.empty else 0
            gross_loss = losing_trades['pnl'].sum() if not losing_trades.empty else 0
            
            profit_factor = abs(gross_profit / gross_loss) if gross_loss != 0 and not np.isnan(gross_loss) and gross_loss < 0 else float('inf')
        else:
            # If no trade data is available
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

    def generate_signals(self):
        """
        This method should be implemented by strategy classes, not the backtester.
        """
        raise NotImplementedError("This method should be implemented by strategy classes.")
