# main.py
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

# Import custom modules
from data.data_loader import DataLoader
from data.market_data import MarketData
from strategies.scalping import ScalpingStrategy
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
    """
    print(f"Running backtest for {tickers} from {start_date} to {end_date}")
    
    # 1. Load market data
    data_loader = DataLoader(data_source='yahoo')
    data_dict = data_loader.get_multi_ticker_data(tickers, start_date, end_date)
    market_data = MarketData(data_dict)
    
    # 2. Initialize strategy
    strategy = ScalpingStrategy(market_data)
    
    # Apply custom strategy parameters if provided
    if strategy_params:
        strategy.set_parameters(**strategy_params)
    
    # 3. Create and run backtester
    backtester = Backtester(market_data, strategy, initial_capital, commission)
    results = backtester.run()
    
    # 4. Return results
    return results, market_data, strategy, backtester

def analyze_results(results, market_data, strategy, tickers):
    """
    Analyze and visualize backtest results.
    
    Args:
        results (dict): Backtest results
        market_data (MarketData): Market data object
        strategy (BaseStrategy): Strategy used in backtest
        tickers (list): List of ticker symbols
    """
    # Print performance summary
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
    
    # Create visualization plots
    fig, axes = plt.subplots(3, 1, figsize=(14, 18), gridspec_kw={'height_ratios': [2, 1, 1]})
    
    # Plot equity curve
    equity_curve = results['equity_curve']
    if isinstance(equity_curve, pd.Series):
        # Convert index to datetime if needed
        if isinstance(equity_curve.index, pd.DatetimeIndex):
            dates = equity_curve.index.to_pydatetime()
        else:
            dates = pd.to_datetime(equity_curve.index)
        
        # Ensure values are numeric
        values = equity_curve.values
        if isinstance(values, pd.Series):
            values = values.values
        values = values.astype(float)
        
        ax1 = axes[0]
        ax1.plot(dates, values, label='Portfolio Value', color='blue')
        ax1.set_title('Portfolio Equity Curve')
        ax1.set_ylabel('Portfolio Value ($)')
        ax1.grid(True)
        ax1.legend()
    
    # Plot drawdown
    daily_returns = results['daily_returns']
    if isinstance(daily_returns, pd.Series):
        # Convert index to datetime if needed
        if isinstance(daily_returns.index, pd.DatetimeIndex):
            dates = daily_returns.index.to_pydatetime()
        else:
            dates = pd.to_datetime(daily_returns.index)
        
        # Ensure values are numeric
        values = daily_returns.values
        if isinstance(values, pd.Series):
            values = values.values
        values = values.astype(float)
        
        cumulative_returns = (1 + values).cumprod()
        running_max = cumulative_returns.cummax()
        drawdown = (cumulative_returns / running_max - 1) * 100
        
        ax2 = axes[1]
        ax2.fill_between(dates, 0, drawdown, color='red', alpha=0.3)
        ax2.set_title('Portfolio Drawdown')
        ax2.set_ylabel('Drawdown (%)')
        ax2.grid(True)
    
    # Plot price with buy/sell signals for the first ticker
    ticker = tickers[0]
    price = market_data.get_price_data(ticker)
    if isinstance(price, pd.Series):
        # Convert index to datetime if needed
        if isinstance(price.index, pd.DatetimeIndex):
            dates = price.index.to_pydatetime()
        else:
            dates = pd.to_datetime(price.index)
        
        # Ensure values are numeric
        values = price.values
        if isinstance(values, pd.Series):
            values = values.values
        values = values.astype(float)
        
        signals = strategy.get_signals(ticker)
        if isinstance(signals, pd.DataFrame):
            # Convert index to datetime if needed
            if isinstance(signals.index, pd.DatetimeIndex):
                signal_dates = signals.index.to_pydatetime()
            else:
                signal_dates = pd.to_datetime(signals.index)
            
            ax3 = axes[2]
            ax3.plot(dates, values, label=f'{ticker} Price', color='blue', alpha=0.6)
            
            # Plot buy signals
            if 'buy_signal' in signals.columns:
                buy_mask = signals['buy_signal'] > 0
                if buy_mask.any():
                    buy_dates = signal_dates[buy_mask]
                    buy_prices = values[pd.Series(dates).isin(buy_dates)]
                    ax3.scatter(buy_dates, buy_prices, color='green', marker='^', s=100, label='Buy Signal')
            
            # Plot sell signals
            if 'sell_signal' in signals.columns:
                sell_mask = signals['sell_signal'] > 0
                if sell_mask.any():
                    sell_dates = signal_dates[sell_mask]
                    sell_prices = values[pd.Series(dates).isin(sell_dates)]
                    ax3.scatter(sell_dates, sell_prices, color='red', marker='v', s=100, label='Sell Signal')
            
            ax3.set_title(f'{ticker} Price with Signals')
            ax3.set_ylabel('Price ($)')
            ax3.grid(True)
            ax3.legend()
    
    plt.tight_layout()
    plt.show()
    
    # Display trade statistics
    if not results['trades'].empty:
        print("\n===== TRADE STATISTICS =====")
        print(results['trades'].describe())
    
def main():
    """
    Main function to run the backtesting system.
    """
    # Define backtest parameters
    tickers = ['SPY', 'QQQ', 'TSLA', 'PLTR']
    end_date = '2024-04-11'  # Today's date
    start_date = '2023-04-11'  # 1 year ago
    
    # Customize strategy parameters
    strategy_params = {
        'ema_short': 9,
        'ema_long': 21,
        'rsi_period': 14,
        'rsi_overbought': 70,
        'rsi_oversold': 30,
        'stop_loss_pct': 0.5,
        'take_profit_pct': 1.0
    }
    
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
    
    # Example of how to run a backtest on a single ticker
    print("\nRunning individual backtest for TSLA...")
    results_tsla, market_data_tsla, strategy_tsla, backtester_tsla = run_backtest(
        tickers=['TSLA'],
        start_date=start_date,
        end_date=end_date,
        strategy_params={
            'ema_short': 5,
            'ema_long': 15,
            'rsi_period': 7,
            'rsi_overbought': 75,
            'rsi_oversold': 25,
            'stop_loss_pct': 1.0,
            'take_profit_pct': 2.0
        }
    )
    
    # Analyze TSLA results
    analyze_results(results_tsla, market_data_tsla, strategy_tsla, ['TSLA'])

if __name__ == "__main__":
    main()