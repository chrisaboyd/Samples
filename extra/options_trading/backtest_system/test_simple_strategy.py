import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

# Import backtesting components
from data.market_data import MarketData
from strategies.simple_strategy import SimpleStrategy
from backtester.backtester import Backtester
from backtester.portfolio import Portfolio

def generate_test_data(tickers=['AAPL', 'MSFT', 'GOOGL'], days=60):
    """Generate synthetic test data for backtesting"""
    
    # Set random seed for reproducibility
    np.random.seed(42)
    
    # Create date range
    end_date = datetime.now().date()
    start_date = end_date - timedelta(days=days)
    date_range = pd.date_range(start=start_date, end=end_date, freq='D')
    
    # Dictionary to store data for each ticker
    data_dict = {}
    
    for ticker in tickers:
        # Generate random price with general upward trend and some volatility
        start_price = 100 + np.random.uniform(-20, 20)
        daily_returns = np.random.normal(0.0005, 0.015, size=len(date_range))
        
        # Ensure we don't have excessive downside
        daily_returns = np.clip(daily_returns, -0.05, 0.05)
        
        # Calculate price series
        prices = [start_price]
        for ret in daily_returns:
            next_price = prices[-1] * (1 + ret)
            prices.append(next_price)
        prices = prices[1:]  # Remove initial seed price
        
        # Create DataFrame for this ticker
        df = pd.DataFrame(index=date_range)
        df['Open'] = prices * (1 - np.random.uniform(0, 0.005, size=len(prices)))
        df['High'] = prices * (1 + np.random.uniform(0.001, 0.015, size=len(prices)))
        df['Low'] = prices * (1 - np.random.uniform(0.001, 0.015, size=len(prices)))
        df['Close'] = prices
        df['Volume'] = np.random.randint(100000, 10000000, size=len(prices))
        
        # Ensure High >= Open, Close, Low
        df['High'] = np.maximum(df['High'], df[['Open', 'Close']].max(axis=1))
        
        # Ensure Low <= Open, Close, High
        df['Low'] = np.minimum(df['Low'], df[['Open', 'Close']].min(axis=1))
        
        data_dict[ticker] = df
    
    return data_dict

def main():
    # Generate synthetic test data
    print("Generating test market data...")
    test_data = generate_test_data(tickers=['AAPL', 'AMZN', 'GOOGL', 'MSFT', 'TSLA'], days=120)
    
    # Create MarketData instance
    market_data = MarketData()
    for ticker, df in test_data.items():
        market_data.add_data(ticker, df)
    
    # Initialize strategy
    print("Initializing SimpleStrategy...")
    strategy = SimpleStrategy(market_data)
    
    # Configure strategy parameters
    strategy.set_parameters({
        'timeframe': 'D',
        'buy_probability': 0.03,       # 3% chance of buy signal
        'sell_probability': 0.05,      # 5% chance of sell signal
        'stop_loss_pct': 3.0,          # 3% stop loss
        'take_profit_pct': 8.0,        # 8% take profit
        'position_size_pct': 15.0,     # 15% of equity per position
        'max_positions': 3,            # Max 3 positions at a time
    })
    
    # Generate signals
    print("Generating signals...")
    signals = strategy.generate_signals()
    
    # Initialize portfolio with stop loss and take profit enabled
    initial_capital = 100000.0
    portfolio = Portfolio(initial_capital=initial_capital, use_fractional_shares=True)
    
    # Setting up the backtester
    print("Running backtest...")
    backtester = Backtester(market_data, strategy, portfolio)
    
    # Run the backtest
    results = backtester.run_backtest(
        enable_stop_loss=True,
        enable_take_profit=True,
        verbose=True
    )
    
    # Print performance metrics
    print("\nBacktest Results:")
    print(f"Initial Capital: ${initial_capital:,.2f}")
    print(f"Final Equity: ${results['final_equity']:,.2f}")
    print(f"Total Return: {(results['final_equity'] / initial_capital - 1) * 100:.2f}%")
    print(f"Total Trades: {results['total_trades']}")
    print(f"Win Rate: {results['win_rate']:.2f}%")
    print(f"Average Profit per Trade: ${results['avg_profit_per_trade']:,.2f}")
    
    # Plot equity curve
    plt.figure(figsize=(12, 6))
    plt.plot(results['equity_curve'])
    plt.title('Equity Curve')
    plt.xlabel('Date')
    plt.ylabel('Equity ($)')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('equity_curve.png')
    plt.show()

if __name__ == "__main__":
    main() 