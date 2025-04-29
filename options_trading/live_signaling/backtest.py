import pandas as pd
import os
from strategies.indicators import detect_trend
import glob
from datetime import datetime
import pytz
import numpy as np

def load_latest_market_data():
    """Load the most recent market data file from saved_data directory"""
    data_dir = "saved_data"
    files = glob.glob(os.path.join(data_dir, "market_data_*.pkl"))
    if not files:
        raise FileNotFoundError("No market data files found")
    
    # Get the most recent file
    latest_file = max(files)
    print(f"Loading data from {latest_file}")
    data = pd.read_pickle(latest_file)
    
    # Debug print
    print("\nData Structure:")
    if isinstance(data, dict):
        print("Data is a dictionary with strategies:", data.keys())
        # Show available symbols across all strategies
        all_symbols = set()
        for strategy in data:
            if isinstance(data[strategy], dict):
                all_symbols.update(data[strategy].keys())
        print(f"\nAvailable symbols across all strategies: {sorted(list(all_symbols))}")
        
        # Show sample of data structure
        first_strategy = next(iter(data))
        if isinstance(data[first_strategy], dict):
            first_symbol = next(iter(data[first_strategy]))
            print(f"\nSample data structure for {first_strategy} - {first_symbol}:")
            print(data[first_strategy][first_symbol])
    
    return data

def get_symbol_data(data, symbol):
    """
    Extract and combine data for a symbol across all strategies
    
    Args:
        data: Nested dictionary of market data
        symbol: Symbol to extract data for
        
    Returns:
        DataFrame with market data for the symbol
    """
    symbol_data = None
    
    for strategy in data:
        if isinstance(data[strategy], dict) and symbol in data[strategy]:
            strategy_data = data[strategy][symbol]
            
            # Convert dictionary of OHLCV dictionaries to DataFrame
            if isinstance(strategy_data, dict) and all(col in strategy_data for col in ['open', 'high', 'low', 'close', 'volume']):
                df = pd.DataFrame({
                    'open': strategy_data['open'],
                    'high': strategy_data['high'],
                    'low': strategy_data['low'],
                    'close': strategy_data['close'],
                    'volume': strategy_data['volume']
                })
                
                if symbol_data is None:
                    symbol_data = df
                else:
                    # Merge with existing data, keeping the latest values
                    symbol_data = pd.concat([symbol_data, df])
                    symbol_data = symbol_data[~symbol_data.index.duplicated(keep='last')]
                    symbol_data.sort_index(inplace=True)
    
    if symbol_data is not None:
        print(f"\nLoaded {len(symbol_data)} bars for {symbol}")
        print(f"Date range: {symbol_data.index[0]} to {symbol_data.index[-1]}")
        
    return symbol_data

def run_backtest(data, symbol, initial_capital=10000):
    """
    Run a simple backtest using the trend detection strategy
    
    Args:
        data: Nested dictionary of market data
        symbol: Stock symbol to backtest
        initial_capital: Starting capital
    """
    # Get symbol data across all strategies
    symbol_data = get_symbol_data(data, symbol)
    
    if symbol_data is None or symbol_data.empty:
        print(f"No data found for {symbol}")
        return pd.DataFrame(), initial_capital
    
    # Ensure we have the required columns
    required_columns = ['open', 'high', 'low', 'close', 'volume']
    if not all(col in symbol_data.columns for col in required_columns):
        print(f"Missing required columns. Available columns: {symbol_data.columns}")
        return pd.DataFrame(), initial_capital
    
    # Debug print
    print(f"\nBacktesting {symbol}")
    print(f"Data columns: {symbol_data.columns}")
    print(f"Data range: {symbol_data.index[0]} to {symbol_data.index[-1]}")
    print(f"Number of bars: {len(symbol_data)}")
    
    # Initialize tracking variables
    position = 0  # 0: no position, 1: long, -1: short
    capital = initial_capital
    trades = []
    entry_price = 0
    
    # Calculate total bars for progress tracking
    total_bars = len(symbol_data) - 1
    progress_interval = max(1, total_bars // 20)  # Show progress every 5%
    
    # Run through each bar
    for i in range(len(symbol_data) - 1):
        # Show progress
        if i % progress_interval == 0:
            progress = (i / total_bars) * 100
            print(f"\rProgress: {progress:.1f}%", end="")
            
        # Get the data up to current bar (make a copy to avoid warnings)
        current_data = symbol_data.iloc[:i+1].copy()
        if len(current_data) < 15:  # Need at least 15 bars for indicators
            continue
            
        # Get trend analysis
        trend = detect_trend(current_data)
        current_close = current_data['close'].iloc[-1]
        next_close = symbol_data['close'].iloc[i+1]  # For calculating returns
        
        # Trading logic
        if position == 0:  # No position
            if trend['trend_rating'] in ['Strong Uptrend', 'Moderate Uptrend']:
                position = 1
                entry_price = current_close
                trades.append({
                    'time': current_data.index[-1],
                    'action': 'BUY',
                    'price': current_close,
                    'trend_score': trend['overall_score']
                })
                print(f"\nBUY: {current_data.index[-1]} at ${current_close:.2f} (Score: {trend['overall_score']:.2f})")
                
        elif position == 1:  # Long position
            if trend['trend_rating'] in ['Strong Downtrend', 'Moderate Downtrend']:
                # Calculate return
                returns = (current_close - entry_price) / entry_price
                capital *= (1 + returns)
                
                position = 0
                trades.append({
                    'time': current_data.index[-1],
                    'action': 'SELL',
                    'price': current_close,
                    'trend_score': trend['overall_score'],
                    'returns': returns * 100
                })
                print(f"\nSELL: {current_data.index[-1]} at ${current_close:.2f} (Return: {returns*100:.2f}%)")
    
    print("\rProgress: 100%")  # Complete the progress bar
    
    # Close any open position at the end
    if position == 1:
        final_returns = (symbol_data['close'].iloc[-1] - entry_price) / entry_price
        capital *= (1 + final_returns)
        trades.append({
            'time': symbol_data.index[-1],
            'action': 'SELL',
            'price': symbol_data['close'].iloc[-1],
            'trend_score': trend['overall_score'],
            'returns': final_returns * 100
        })
    
    # Calculate performance metrics
    total_return = ((capital - initial_capital) / initial_capital) * 100
    trades_df = pd.DataFrame(trades)
    winning_trades = trades_df[trades_df['returns'] > 0] if 'returns' in trades_df else pd.DataFrame()
    
    print("\nBacktest Results:")
    print(f"Total Return: {total_return:.2f}%")
    print(f"Final Capital: ${capital:.2f}")
    print(f"Number of Trades: {len(trades)}")
    if not trades_df.empty and 'returns' in trades_df:
        print(f"Win Rate: {(len(winning_trades) / len(trades_df)) * 100:.2f}%")
        print(f"Average Return per Trade: {trades_df['returns'].mean():.2f}%")
        print(f"Max Drawdown: {trades_df['returns'].min():.2f}%")
        print(f"Best Trade: {trades_df['returns'].max():.2f}%")
    
    return trades_df, capital

if __name__ == "__main__":
    # Load the data
    market_data = load_latest_market_data()
    
    # Get unique symbols across all strategies
    symbols = set()
    for strategy in market_data:
        if isinstance(market_data[strategy], dict):
            symbols.update(market_data[strategy].keys())
    symbols = sorted(list(symbols))
    
    print(f"\nRunning backtest for symbols: {symbols}")
    
    # Run backtest for each symbol
    results = {}
    for symbol in symbols:
        trades, final_capital = run_backtest(market_data, symbol)
        if not trades.empty:  # Only store results if we got trades
            results[symbol] = {
                'trades': trades,
                'final_capital': final_capital
            }
    
    # You can save the results to a file if needed
    # pd.to_pickle(results, 'saved_data/backtest_results.pkl') 