import pandas as pd
import numpy as np
from backtester.portfolio import Portfolio

class Backtester:
    """
    Core backtesting engine that runs strategies and analyzes performance.
    """
    
    def __init__(self, strategy, market_data, initial_capital):
        """
        Initialize backtester with market data and strategy.
        
        Args:
            strategy (BaseStrategy): Trading strategy
            market_data (MarketData): Market data object
            initial_capital (float): Initial capital amount
        """
        self.strategy = strategy
        self.market_data = market_data
        self.initial_capital = initial_capital
        self.portfolio = Portfolio(initial_capital)
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
        
        for current_time in all_dates:
            # First, check for exits on open positions
            for ticker in list(self.portfolio.open_positions.keys()):
                try:
                    position = self.portfolio.open_positions[ticker]
                    current_price = self.market_data.get_price_data(ticker).loc[current_time].iloc[0]
                    
                    # Check stop loss
                    if position.direction == 1:  # Long position
                        if current_price <= position.stop_loss:
                            print(f"\nStop loss triggered for {ticker}")
                            print(f"Entry price: ${position.entry_price:.2f}")
                            print(f"Stop price: ${current_price:.2f}")
                            if self.portfolio.close_position(ticker, current_time, current_price, "Stop Loss"):
                                continue
                            
                        elif current_price >= position.take_profit:
                            print(f"\nTake profit triggered for {ticker}")
                            print(f"Entry price: ${position.entry_price:.2f}")
                            print(f"Exit price: ${current_price:.2f}")
                            if self.portfolio.close_position(ticker, current_time, current_price, "Take Profit"):
                                continue
                    
                    elif position.direction == -1:  # Short position
                        if current_price >= position.stop_loss:
                            print(f"\nStop loss triggered for {ticker}")
                            print(f"Entry price: ${position.entry_price:.2f}")
                            print(f"Stop price: ${current_price:.2f}")
                            self.portfolio.close_position(ticker, current_time, current_price, "Stop Loss")
                            continue
                            
                        if current_price <= position.take_profit:
                            print(f"\nTake profit triggered for {ticker}")
                            print(f"Entry price: ${position.entry_price:.2f}")
                            print(f"Exit price: ${current_price:.2f}")
                            self.portfolio.close_position(ticker, current_time, current_price, "Take Profit")
                            continue
                            
                except Exception as e:
                    print(f"Error checking position exits: {str(e)}")
            
            # Then process new signals (only if we don't have an open position)
            for ticker in tickers:
                if ticker in self.portfolio.open_positions:
                    continue  # Skip if we already have a position
                    
                try:
                    signals = self.strategy.get_signals(ticker)
                    if current_time not in signals.index:
                        continue
                        
                    current_signals = signals.loc[current_time]
                    
                    # Process buy signals
                    if current_signals.get('buy_signal', 0) > 0:
                        try:
                            entry_price = float(current_signals['entry_price'])
                            stop_loss = float(current_signals['stop_loss'])
                            take_profit = float(current_signals['profit_target'])
                            position_value = entry_price * 100
                            
                            print(f"\nProcessing buy signal for {ticker}:")
                            print(f"Entry price: ${entry_price:.2f}")
                            print(f"Stop loss: ${stop_loss:.2f}")
                            print(f"Take profit: ${take_profit:.2f}")
                            print(f"Position value: ${position_value:.2f}")
                            
                            if position_value <= self.portfolio.current_capital:
                                self.portfolio.current_position_size = 100
                                self.portfolio.buy(
                                    ticker, 
                                    current_time, 
                                    entry_price,
                                    stop_loss=stop_loss,
                                    take_profit=take_profit
                                )
                            else:
                                print(f"Warning: Not enough capital. Required: ${position_value:.2f}, Available: ${self.portfolio.current_capital:.2f}")
                                    
                        except Exception as e:
                            print(f"Error processing buy signal: {str(e)}")
                            
                    # Similar changes for sell signals...
                    
                except Exception as e:
                    print(f"Error processing signals: {str(e)}")
            
            # Update equity curve
            self.portfolio.update_equity_curve(current_time, self.market_data)

        # Close any remaining open positions at the end of the backtest
        for ticker, position in self.portfolio.open_positions.items():
            if position is not None:
                try:
                    # Get last price
                    last_price_data = self.market_data.get_price_at_time(ticker, all_dates[-1])
                    if last_price_data is not None and not last_price_data.empty:
                        ticker_col = last_price_data.columns[0]
                        last_price = last_price_data['close'].iloc[0] if 'close' in last_price_data.columns else last_price_data[ticker_col].iloc[0]
                        
                        print(f"\nClosing remaining {position.direction} position in {ticker} at end of backtest")
                        print(f"Entry price: ${position.entry_price:.2f}")
                        print(f"Exit price: ${last_price:.2f}")
                        
                        self.portfolio.close_position(
                            ticker,
                            all_dates[-1],
                            last_price,
                            'backtest_end'
                        )
                except Exception as e:
                    print(f"Error closing position for {ticker}: {str(e)}")

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
