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
    
    def run(self):
        print("\n=== Starting Backtest Execution ===")
        
        # Generate trading signals
        print("Generating signals...")
        self.strategy.generate_signals()
        
        # Get tickers and date range
        tickers = self.market_data.get_tickers()
        all_dates = self.market_data.get_price_data(tickers[0]).index
        print(f"Processing {len(all_dates)} timestamps from {all_dates[0]} to {all_dates[-1]}")
        
        # Debug ALL signals before processing
        for ticker in tickers:
            signals = self.strategy.get_signals(ticker)
            non_zero_signals = signals[(signals['buy_signal'] > 0) | (signals['sell_signal'] > 0)]
            print(f"\nAll generated signals for {ticker}:")
            print(f"Total signals found: {len(non_zero_signals)}")
            if len(non_zero_signals) > 0:
                print(non_zero_signals[['buy_signal', 'sell_signal', 'entry_price', 'stop_loss', 'profit_target']])
        
        # Initialize portfolio
        self.portfolio.current_capital = self.initial_capital
        print(f"\nStarting backtest with initial capital: ${self.initial_capital:,.2f}")
        
        # Iterate through each timestamp
        for current_time in all_dates:
            # Process new signals
            for ticker in tickers:
                try:
                    signals = self.strategy.get_signals(ticker)
                    
                    # Check if we have any signals at all
                    if signals is None:
                        print(f"Warning: No signals DataFrame found for {ticker}")
                        continue
                        
                    # Check if current_time exists in signals
                    if current_time not in signals.index:
                        continue
                    
                    current_signals = signals.loc[current_time]
                    
                    # Only debug non-zero signals
                    if current_signals.get('buy_signal', 0) > 0 or current_signals.get('sell_signal', 0) > 0:
                        print(f"\nFound active signal for {ticker} at {current_time}:")
                        print(f"Buy signal: {current_signals.get('buy_signal', 0)}")
                        print(f"Sell signal: {current_signals.get('sell_signal', 0)}")
                        print(f"Entry price: {current_signals.get('entry_price', 0)}")
                        print(f"Stop loss: {current_signals.get('stop_loss', 0)}")
                        print(f"Profit target: {current_signals.get('profit_target', 0)}")
                    
                    # Process buy signals
                    if current_signals.get('buy_signal', 0) > 0:
                        try:
                            entry_price = float(current_signals['entry_price'])
                            stop_loss = float(current_signals['stop_loss'])
                            risk_per_share = abs(entry_price - stop_loss)
                            risk_amount = self.portfolio.current_capital * 0.02
                            
                            print("\nCalculating position size:")
                            print(f"Entry price: ${entry_price:.2f}")
                            print(f"Stop loss: ${stop_loss:.2f}")
                            print(f"Risk per share: ${risk_per_share:.2f}")
                            print(f"Risk amount: ${risk_amount:.2f}")
                            
                            if risk_per_share > 0:
                                num_shares = int(risk_amount / risk_per_share)
                                if num_shares > 0:
                                    print(f"Opening long position: {num_shares} shares at ${entry_price:.2f}")
                                    self.portfolio.buy(ticker, current_time, entry_price, 
                                                    stop_loss=stop_loss, 
                                                    take_profit=float(current_signals['profit_target']))
                        except Exception as e:
                            print(f"Error processing buy signal: {str(e)}")
                            
                    # Process sell signals
                    elif current_signals.get('sell_signal', 0) > 0:
                        try:
                            entry_price = float(current_signals['entry_price'])
                            stop_loss = float(current_signals['stop_loss'])
                            risk_per_share = abs(entry_price - stop_loss)
                            risk_amount = self.portfolio.current_capital * 0.02
                            
                            if risk_per_share > 0:
                                num_shares = int(risk_amount / risk_per_share)
                                if num_shares > 0:
                                    print(f"Opening short position: {num_shares} shares at ${entry_price:.2f}")
                                    self.portfolio.sell(ticker, current_time, entry_price,
                                                    stop_loss=stop_loss,
                                                    take_profit=float(current_signals['profit_target']))
                        except Exception as e:
                            print(f"Error processing sell signal: {str(e)}")
                            
                except Exception as e:
                    print(f"Error processing {ticker}: {str(e)}")
            
            # Update equity curve with market_data
            try:
                self.portfolio.update_equity_curve(current_time, self.market_data)
            except Exception as e:
                print(f"Error updating equity curve: {str(e)}")

        print("\n=== Backtest Complete ===")
        print(f"Final capital: ${self.portfolio.current_capital:,.2f}")
        print(f"Total trades executed: {len(self.portfolio.trades_history)}")
        
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
            
            avg_win_loss_ratio = abs(avg_win / avg_loss) if avg_loss != 0 and not np.isnan(avg_loss) else float('inf')
            
            gross_profit = winning_trades['pnl'].sum() if not winning_trades.empty else 0
            gross_loss = losing_trades['pnl'].sum() if not losing_trades.empty else 0
            
            profit_factor = abs(gross_profit / gross_loss) if gross_loss != 0 and not np.isnan(gross_loss) else float('inf')
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

    def generate_signals(self):
        """
        This method should be implemented by strategy classes, not the backtester.
        """
        raise NotImplementedError("This method should be implemented by strategy classes.")
