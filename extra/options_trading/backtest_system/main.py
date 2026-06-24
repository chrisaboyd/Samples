# main.py
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import matplotlib.dates as mdates

# Import custom modules
from data.data_loader import DataLoader
from data.market_data import MarketData
from strategies.base_strategy import BaseStrategy
from strategies.scalping import ScalpingStrategy
from strategies.ORBStrategy import ORBStrategy
from backtester.backtester import Backtester
from analysis.performance import plot_performance, print_performance_summary
from analysis.visualization import plot_equity_curve, plot_drawdown, plot_trades

def run_backtest(tickers, 
                start_date, 
                end_date, 
                strategy_params=None, 
                initial_capital=100000.0, 
                commission=0.001):
    """
    Run a backtest with specified parameters.
    
    Args:
        tickers (list): List of ticker symbols
        start_date (str): Start date in 'YYYY-MM-DD' format
        end_date (str): End date in 'YYYY-MM-DD' format
        strategy_params (dict, optional): Strategy parameters
        initial_capital (float, optional): Initial capital amount
        commission (float, optional): Commission rate as decimal
        
    Returns:
        dict: Backtest results
        
    Raises:
        ValueError: If no data is found for any of the provided tickers
    """
    print(f"Running backtest for {tickers} from {start_date} to {end_date}")
    
    # 1. Load market data
    data_loader = DataLoader(data_source='yahoo')
    try:
        # Use 1-minute data for scalping strategy
        data_dict = data_loader.get_multi_ticker_data(tickers, start_date, end_date, interval='1m')
        if not data_dict:
            raise ValueError(f"No data found for any of the provided tickers: {tickers}")
        
        # Check which tickers have data
        available_tickers = list(data_dict.keys())
        if len(available_tickers) < len(tickers):
            missing_tickers = set(tickers) - set(available_tickers)
            print(f"Warning: No data found for tickers: {missing_tickers}")
            print(f"Proceeding with available tickers: {available_tickers}")
            tickers = available_tickers
            
        market_data = MarketData(data_dict)
    except Exception as e:
        raise ValueError(f"Error loading data for tickers {tickers}: {str(e)}")
    
    # 2. Initialize strategy
    strategy = ORBStrategy(market_data)
    
    # Apply custom strategy parameters if provided
    if strategy_params:
        strategy.set_parameters(**strategy_params)
    
    # 3. Create and run backtester
    backtester = Backtester(
        strategy=strategy,
        market_data=market_data,
        initial_capital=initial_capital
    )
    results = backtester.run()
    
    # 4. Return results
    return results, market_data, strategy, backtester

def analyze_results(results, market_data, strategy, tickers):
    """
    Analyze and visualize backtest results with proper timezone handling.
    
    Args:
        results (dict): Backtest results
        market_data (MarketData): Market data object
        strategy (BaseStrategy): Strategy used in backtest
        tickers (list): List of ticker symbols
    """
    # Helper function to convert timezone-aware datetimes to naive
    def strip_tz(dt_index):
        if hasattr(dt_index, 'tz') and dt_index.tz is not None:
            return dt_index.tz_localize(None)
        return dt_index
    
    # Convert timezone-aware DataFrames
    if 'trades' in results and not results['trades'].empty:
        results['trades'].index = strip_tz(results['trades'].index)
        
        # Convert datetime columns if they exist
        for col in ['entry_date', 'exit_date']:
            if col in results['trades'].columns and pd.api.types.is_datetime64_dtype(results['trades'][col]):
                # Approach for Series of datetimes
                try:
                    if hasattr(results['trades'][col].dt, 'tz') and results['trades'][col].dt.tz is not None:
                        results['trades'][col] = pd.DatetimeIndex(results['trades'][col]).tz_localize(None)
                except:
                    # Alternative approach if the above fails
                    results['trades'][col] = results['trades'][col].apply(
                        lambda x: x.replace(tzinfo=None) if hasattr(x, 'tzinfo') and x.tzinfo is not None else x
                    )
    
    # Convert series data
    if 'equity_curve' in results and isinstance(results['equity_curve'], pd.Series):
        results['equity_curve'].index = strip_tz(results['equity_curve'].index)
        
    if 'daily_returns' in results and isinstance(results['daily_returns'], pd.Series):
        results['daily_returns'].index = strip_tz(results['daily_returns'].index)
    
    # Print performance summary first
    print("\n===== PERFORMANCE SUMMARY =====")
    print(f"Initial Capital: ${results['initial_capital']:.2f}")
    print(f"Final Capital: ${results['final_capital']:.2f}")
    print(f"Total Return: {results['total_return_pct']:.2f}%")
    print(f"Sharpe Ratio: {results['sharpe_ratio']:.2f}")
    print(f"Max Drawdown: {results['max_drawdown_pct']:.2f}%")
    print(f"Number of Trades: {results['num_trades']}")
    print(f"Win Rate: {results['win_rate_pct']:.2f}%")
    print(f"Average Win/Loss Ratio: {results['avg_win_loss_ratio']:.2f}")
    print(f"Profit Factor: {results['profit_factor']:.2f}")
    
    # Display enhanced trade statistics before plots
    if 'trades' in results and not results['trades'].empty:
        trades_df = results['trades'].copy()
        
        # Calculate additional metrics
        trades_df['duration'] = trades_df['exit_date'] - trades_df['entry_date']
        trades_df['return_pct'] = (trades_df['pnl'] / (trades_df['entry_price'] * trades_df['quantity'])) * 100
        trades_df['capital_usage'] = trades_df['entry_price'] * trades_df['quantity']
        trades_df['return_on_capital'] = (trades_df['pnl'] / results['initial_capital']) * 100
        
        # Create cumulative metrics
        trades_df['cumulative_pnl'] = trades_df['pnl'].cumsum()
        trades_df['cumulative_return'] = (trades_df['cumulative_pnl'] / results['initial_capital']) * 100
        
        print("\n===== DETAILED TRADE LOG =====")
        print("\nTrade-by-Trade Analysis:")
        print("-" * 120)
        for idx, trade in trades_df.iterrows():
            print(f"Trade #{idx + 1}")
            print(f"Ticker: {tickers[0]}")
            print(f"Entry: {trade['entry_date'].strftime('%Y-%m-%d %H:%M')} at ${trade['entry_price']:.2f}")
            print(f"Exit: {trade['exit_date'].strftime('%Y-%m-%d %H:%M')} at ${trade['exit_price']:.2f}")
            print(f"Quantity: {trade['quantity']:.0f} shares")
            print(f"P&L: ${trade['pnl']:.2f} ({trade['return_pct']:.2f}% trade return)")
            print(f"Capital Used: ${trade['capital_usage']:.2f} ({trade['return_on_capital']:.2f}% return on capital)")
            print(f"Duration: {trade['duration']}")
            print(f"Cumulative P&L: ${trade['cumulative_pnl']:.2f} ({trade['cumulative_return']:.2f}% total return)")
            print("-" * 120)
        
        print("\nTrade Statistics Summary:")
        print("-" * 80)
        print(f"Average Trade Duration: {trades_df['duration'].mean()}")
        print(f"Average Trade Return: {trades_df['return_pct'].mean():.2f}%")
        print(f"Best Trade Return: {trades_df['return_pct'].max():.2f}%")
        print(f"Worst Trade Return: {trades_df['return_pct'].min():.2f}%")
        print(f"Average Capital Usage: ${trades_df['capital_usage'].mean():.2f}")
        print(f"Total P&L: ${trades_df['pnl'].sum():.2f}")
        print(f"Average P&L per Trade: ${trades_df['pnl'].mean():.2f}")
        print(f"Largest Winning Trade: ${trades_df['pnl'].max():.2f}")
        print(f"Largest Losing Trade: ${trades_df['pnl'].min():.2f}")
        print("-" * 80)
    
    # Create visualization plots with adjusted size and spacing
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))  # Changed from 3 to 2 subplots
    fig.patch.set_facecolor('white')
    
    # Plot equity curve
    equity_curve = results['equity_curve']
    if isinstance(equity_curve, pd.Series):
        dates = equity_curve.index  # Already converted to timezone-naive above
        values = equity_curve.values.astype(float)
        
        ax1.set_facecolor('white')
        ax1.plot(dates, values, label='Portfolio Value', color='blue', linewidth=1.5)
        ax1.set_title('Portfolio Equity Curve', fontsize=10, pad=5)
        ax1.set_ylabel('Portfolio Value ($)', fontsize=8)
        ax1.grid(True, alpha=0.3)
        ax1.tick_params(axis='both', labelsize=8)
        
        # Format x-axis
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
        ax1.xaxis.set_major_locator(mdates.AutoDateLocator(minticks=3, maxticks=7))
        
        # Format y-axis
        ax1.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'${x:,.0f}'))
        
        # Add initial capital line
        ax1.axhline(y=results['initial_capital'], color='gray', linestyle='--', alpha=0.5, 
                   label='Initial Capital')
        ax1.legend(loc='upper left', fontsize=8)
    
    # Plot drawdown
    daily_returns = results['daily_returns']
    if isinstance(daily_returns, pd.Series):
        dates = daily_returns.index  # Already converted to timezone-naive above
        values = daily_returns.values.astype(float)
        
        cumulative_returns = np.cumprod(1 + values)
        running_max = np.maximum.accumulate(cumulative_returns)
        drawdown = (cumulative_returns / running_max - 1) * 100
        
        ax2.set_facecolor('white')
        ax2.fill_between(dates, 0, drawdown, color='red', alpha=0.3, label='Drawdown')
        ax2.set_title('Portfolio Drawdown', fontsize=10, pad=5)
        ax2.set_ylabel('Drawdown (%)', fontsize=8)
        ax2.grid(True, alpha=0.3)
        ax2.tick_params(axis='both', labelsize=8)
        ax2.legend(fontsize=8, loc='lower left')
        
        # Format axes
        ax2.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
        ax2.xaxis.set_major_locator(mdates.AutoDateLocator(minticks=3, maxticks=7))
        ax2.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'{x:.1f}%'))
    
    # Adjust layout and show plot
    plt.tight_layout()
    plt.show()

def main(tickers=None):
    """
    Main function to run the backtesting system.
    
    Args:
        tickers (str or list, optional): Single ticker or list of tickers to backtest.
                                If None, uses default tickers.
    """
    if tickers is None:
        tickers = ['SPY']  # Default to SPY if no tickers provided
    
    if not isinstance(tickers, list):
        tickers = [tickers]  # Convert single ticker to list
    
    # Validate input
    if not tickers:
        raise ValueError("No tickers provided")
    
    # Define backtest parameters - use last 7 days for 1-minute data
    end_date = datetime.now().strftime('%Y-%m-%d')  # Today's date
    start_date = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')  # 7 days ago
    
    print(f"Backtesting period: {start_date} to {end_date}")
    print("Using 1-minute data for intraday scalping strategy")
    
    # Customize strategy parameters
    strategy_params = {
        'opening_range_duration': 15,      # First 15 minutes of trading
        'tolerance': 0.001,                # 0.1% tolerance for retest
        'stop_loss_lookback': 3,           # Look at last 3 candles for stop loss
        'profit_target_multiplier': 2.0,   # 1:2 risk/reward ratio
        'market_open_time': '09:30',
        'market_close_time': '16:00',
        'morning_wait_minutes': 0,         # Don't wait after open
        'avoid_lunch': False               # Trade through lunch hour
    }
    
    try:
        # Run backtest
        results, market_data, strategy, backtester = run_backtest(
            tickers=tickers,
            start_date=start_date,
            end_date=end_date,
            strategy_params=strategy_params,
            initial_capital=100000.0,
            commission=0.001
        )
        
        # Analyze results
        analyze_results(results, market_data, strategy, tickers)
        
    except ValueError as e:
        print(f"Error: {str(e)}")
        return None
    except Exception as e:
        print(f"Unexpected error occurred: {str(e)}")
        return None
    
    return results, market_data, strategy, backtester

if __name__ == "__main__":
    # Example usage:
    # To run with specific tickers:
    # results = main(['AAPL', 'GOOGL', 'MSFT'])
    # 
    # To run with a single ticker:
    # results = main('TSLA')
    #
    # To run with default ticker (SPY):
    # results = main()
    main()