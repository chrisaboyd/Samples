# analysis/performance.py
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

def calculate_drawdown(equity_curve):
    """
    Calculate drawdown series from equity curve.
    
    Args:
        equity_curve (pd.Series): Portfolio equity curve
        
    Returns:
        pd.Series: Drawdown percentage series
    """
    # Calculate drawdown
    running_max = equity_curve.cummax()
    drawdown = (equity_curve / running_max - 1) * 100
    return drawdown

def calculate_underwater_periods(drawdown, threshold=-5):
    """
    Calculate underwater periods (drawdowns exceeding threshold).
    
    Args:
        drawdown (pd.Series): Drawdown percentage series
        threshold (float): Drawdown threshold percentage (negative number)
        
    Returns:
        list: List of (start_date, end_date, max_drawdown) tuples
    """
    underwater = drawdown < threshold
    
    # Find start and end of underwater periods
    underwater_starts = underwater[underwater & ~underwater.shift(1).fillna(False)].index
    underwater_ends = underwater[underwater & ~underwater.shift(-1).fillna(False)].index
    
    if len(underwater_starts) == 0 or len(underwater_ends) == 0:
        return []
    
    # Ensure same number of starts and ends
    if len(underwater_starts) > len(underwater_ends):
        underwater_starts = underwater_starts[:len(underwater_ends)]
    elif len(underwater_ends) > len(underwater_starts):
        underwater_ends = underwater_ends[:len(underwater_starts)]
    
    # Calculate max drawdown for each period
    periods = []
    for start, end in zip(underwater_starts, underwater_ends):
        period_drawdown = drawdown.loc[start:end]
        max_dd = period_drawdown.min()
        periods.append((start, end, max_dd))
    
    return periods

def calculate_performance_metrics(equity_curve, trades=None):
    """
    Calculate comprehensive performance metrics.
    
    Args:
        equity_curve (pd.Series): Portfolio equity curve
        trades (pd.DataFrame, optional): Trades summary data
        
    Returns:
        dict: Performance metrics
    """
    metrics = {}
    
    # Basic return metrics
    initial_value = equity_curve.iloc[0]
    final_value = equity_curve.iloc[-1]
    
    metrics['total_return'] = (final_value - initial_value) / initial_value * 100
    
    # Calculate returns
    daily_returns = equity_curve.pct_change().dropna()
    
    # Risk metrics
    metrics['volatility'] = daily_returns.std() * np.sqrt(252)  # Annualized
    metrics['sharpe_ratio'] = (daily_returns.mean() / daily_returns.std()) * np.sqrt(252) if len(daily_returns) > 1 else 0
    
    # Drawdown analysis
    drawdown = calculate_drawdown(equity_curve)
    metrics['max_drawdown'] = drawdown.min()
    metrics['avg_drawdown'] = drawdown[drawdown < 0].mean() if len(drawdown[drawdown < 0]) > 0 else 0
    
    # Calculate Calmar ratio (return / max drawdown)
    metrics['calmar_ratio'] = abs(metrics['total_return'] / metrics['max_drawdown']) if metrics['max_drawdown'] != 0 else float('inf')
    
    # Trade metrics if available
    if trades is not None and len(trades) > 0:
        winning_trades = trades[trades['pnl'] > 0]
        losing_trades = trades[trades['pnl'] <= 0]
        
        metrics['num_trades'] = len(trades)
        metrics['win_rate'] = len(winning_trades) / len(trades) * 100 if len(trades) > 0 else 0
        
        metrics['avg_profit'] = winning_trades['pnl'].mean() if len(winning_trades) > 0 else 0
        metrics['avg_loss'] = losing_trades['pnl'].mean() if len(losing_trades) > 0 else 0
        
        metrics['profit_factor'] = (winning_trades['pnl'].sum() / abs(losing_trades['pnl'].sum())) if len(losing_trades) > 0 and losing_trades['pnl'].sum() != 0 else float('inf')
        
        metrics['avg_trade'] = trades['pnl'].mean()
        metrics['median_trade'] = trades['pnl'].median()
        
        # Calculate average holding period
        if 'entry_date' in trades.columns and 'exit_date' in trades.columns:
            try:
                holding_periods = (trades['exit_date'] - trades['entry_date']).dt.total_seconds() / 3600  # hours
                metrics['avg_holding_period_hours'] = holding_periods.mean()
            except:
                metrics['avg_holding_period_hours'] = None
    
    return metrics

def plot_performance(results, figsize=(12, 16)):
    """
    Create comprehensive performance visualization.
    
    Args:
        results (dict): Backtest results
        figsize (tuple): Figure size
        
    Returns:
        matplotlib.figure.Figure: The created figure
    """
    equity_curve = results['equity_curve']
    trades = results.get('trades', pd.DataFrame())
    
    fig, axes = plt.subplots(4, 1, figsize=figsize, gridspec_kw={'height_ratios': [2, 1, 1, 1]})
    
    # Plot equity curve
    ax1 = axes[0]
    ax1.plot(equity_curve.index, equity_curve, label='Portfolio Value', color='blue')
    ax1.set_title('Portfolio Equity Curve')
    ax1.set_ylabel('Value ($)')
    ax1.grid(True)
    
    # Add initial capital reference line
    ax1.axhline(y=results['initial_capital'], color='green', linestyle='--', alpha=0.7,
               label=f"Initial Capital (${results['initial_capital']:,.2f})")
    
    # Mark underwater periods
    drawdown = calculate_drawdown(equity_curve)
    underwater_periods = calculate_underwater_periods(drawdown, threshold=-10)
    
    for start, end, max_dd in underwater_periods:
        ax1.axvspan(start, end, color='red', alpha=0.2)
    
    ax1.legend()
    
    # Plot underwater chart
    ax2 = axes[1]
    ax2.fill_between(drawdown.index, 0, drawdown.values, color='red', alpha=0.5)
    ax2.set_title('Drawdown')
    ax2.set_ylabel('Drawdown (%)')
    ax2.grid(True)
    
    # Plot daily returns
    daily_returns = equity_curve.pct_change().dropna() * 100
    ax3 = axes[2]
    ax3.bar(daily_returns.index, daily_returns.values, color=['green' if x > 0 else 'red' for x in daily_returns])
    ax3.set_title('Daily Returns')
    ax3.set_ylabel('Return (%)')
    ax3.grid(True)
    
    # Plot trade PnL if available
    ax4 = axes[3]
    if not trades.empty and 'pnl' in trades.columns:
        trade_indices = range(len(trades))
        colors = ['green' if pnl > 0 else 'red' for pnl in trades['pnl']]
        ax4.bar(trade_indices, trades['pnl'], color=colors)
        ax4.set_title('Trade PnL')
        ax4.set_xlabel('Trade Number')
        ax4.set_ylabel('PnL ($)')
        ax4.grid(True)
    else:
        ax4.set_visible(False)
    
    plt.tight_layout()
    return fig

def print_performance_summary(results):
    """
    Print summary of backtest performance metrics.
    
    Args:
        results (dict): Backtest results
    """
    print("=" * 40)
    print("PERFORMANCE SUMMARY")
    print("=" * 40)
    
    # Portfolio metrics
    print(f"Initial Capital: ${results['initial_capital']:,.2f}")
    print(f"Final Capital: ${results['final_capital']:,.2f}")
    print(f"Total Return: {results['total_return_pct']:.2f}%")
    print(f"Sharpe Ratio: {results['sharpe_ratio']:.2f}")
    print(f"Maximum Drawdown: {results['max_drawdown_pct']:.2f}%")
    print("-" * 40)
    
    # Trade metrics
    print(f"Total Trades: {results['num_trades']}")
    print(f"Win Rate: {results['win_rate_pct']:.2f}%")
    print(f"Profit Factor: {results['profit_factor']:.2f}")
    print(f"Average Win/Loss Ratio: {results['avg_win_loss_ratio']:.2f}")
    print("=" * 40)


# analysis/visualization.py
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

def plot_equity_curve(equity_curve, initial_capital=None, ax=None):
    """
    Plot portfolio equity curve.
    
    Args:
        equity_curve (pd.Series): Portfolio equity curve
        initial_capital (float, optional): Initial capital for reference line
        ax (matplotlib.axes, optional): Existing axes to plot on
        
    Returns:
        matplotlib.axes: Axes with the plot
    """
    if ax is None:
        fig, ax = plt.subplots(figsize=(12, 6))
    
    ax.plot(equity_curve.index, equity_curve, label='Portfolio Value', color='blue')
    
    if initial_capital is not None:
        ax.axhline(y=initial_capital, color='green', linestyle='--', alpha=0.7,
                 label=f"Initial Capital (${initial_capital:,.2f})")
    
    ax.set_title('Portfolio Equity Curve')
    ax.set_xlabel('Date')
    ax.set_ylabel('Value ($)')
    ax.grid(True)
    ax.legend()
    
    return ax

def plot_drawdown(equity_curve, ax=None):
    """
    Plot portfolio drawdown chart.
    
    Args:
        equity_curve (pd.Series): Portfolio equity curve
        ax (matplotlib.axes, optional): Existing axes to plot on
        
    Returns:
        matplotlib.axes: Axes with the plot
    """
    if ax is None:
        fig, ax = plt.subplots(figsize=(12, 4))
    
    # Calculate drawdown
    running_max = equity_curve.cummax()
    drawdown = (equity_curve / running_max - 1) * 100
    
    ax.fill_between(drawdown.index, 0, drawdown.values, color='red', alpha=0.3)
    ax.set_title('Portfolio Drawdown')
    ax.set_xlabel('Date')
    ax.set_ylabel('Drawdown (%)')
    ax.grid(True)
    
    # Add horizontal lines at common drawdown levels
    ax.axhline(y=-5, color='orange', linestyle='--', alpha=0.5, label='-5%')
    ax.axhline(y=-10, color='red', linestyle='--', alpha=0.5, label='-10%')
    ax.axhline(y=-20, color='darkred', linestyle='--', alpha=0.5, label='-20%')
    ax.legend()
    
    return ax

def plot_trades(market_data, trades, ticker, ax=None):
    """
    Plot price chart with trade entry/exit points.
    
    Args:
        market_data (MarketData): Market data object
        trades (pd.DataFrame): Trades dataframe
        ticker (str): Ticker symbol
        ax (matplotlib.axes, optional): Existing axes to plot on
        
    Returns:
        matplotlib.axes: Axes with the plot
    """
    if ax is None:
        fig, ax = plt.subplots(figsize=(12, 6))
    
    # Get price data for ticker
    price_data = market_data.get_price_data(ticker)
    
    # Plot price
    ax.plot(price_data.index, price_data, label=f"{ticker} Price", color='blue', alpha=0.6)
    
    # Filter trades for this ticker
    if 'ticker' in trades.columns:
        ticker_trades = trades[trades['ticker'] == ticker]
    else:
        ticker_trades = trades  # Assume all trades are for this ticker
    
    # Plot entry points
    if 'entry_date' in ticker_trades.columns and 'entry_price' in ticker_trades.columns:
        entry_dates = ticker_trades['entry_date']
        entry_prices = ticker_trades['entry_price']
        
        ax.scatter(entry_dates, entry_prices, marker='^', color='green', s=100, label='Entry')
    
    # Plot exit points
    if 'exit_date' in ticker_trades.columns and 'exit_price' in ticker_trades.columns:
        exit_dates = ticker_trades['exit_date']
        exit_prices = ticker_trades['exit_price']
        
        # Color based on profit
        if 'pnl' in ticker_trades.columns:
            colors = ['green' if pnl > 0 else 'red' for pnl in ticker_trades['pnl']]
            ax.scatter(exit_dates, exit_prices, marker='v', color=colors, s=100, label='Exit')
        else:
            ax.scatter(exit_dates, exit_prices, marker='v', color='red', s=100, label='Exit')
    
    # Connect entry and exit points
    for i, trade in ticker_trades.iterrows():
        if 'entry_date' in trade and 'exit_date' in trade:
            ax.plot([trade['entry_date'], trade['exit_date']], 
                   [trade['entry_price'], trade['exit_price']], 
                   'k--', alpha=0.3)
    
    ax.set_title(f"{ticker} Price with Trades")
    ax.set_xlabel('Date')
    ax.set_ylabel('Price')
    ax.grid(True)
    ax.legend()
    
    return ax