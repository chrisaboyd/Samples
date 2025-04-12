import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.ticker import FuncFormatter

class PerformanceVisualizer:
    """
    Creates visualizations for trading strategy performance.
    """
    
    def __init__(self, backtest_results):
        """
        Initialize with backtest results.
        
        Args:
            backtest_results (dict): Results from Backtester
        """
        self.results = backtest_results
    
    def plot_equity_curve(self, benchmark=None, figsize=(12, 6)):
        """
        Plot equity curve with optional benchmark comparison.
        
        Args:
            benchmark (pd.Series, optional): Benchmark returns
            figsize (tuple): Figure size
        
        Returns:
            matplotlib.figure.Figure: Figure object
        """
        if 'equity_curve' not in self.results or self.results['equity_curve'].empty:
            fig, ax = plt.subplots(figsize=figsize)
            ax.text(0.5, 0.5, "No equity data available", ha='center', va='center')
            return fig
        
        equity = self.results['equity_curve']
        
        fig, ax = plt.subplots(figsize=figsize)
        
        # Plot equity curve
        ax.plot(equity.index, equity, label='Strategy', color='blue', linewidth=2)
        
        # Plot benchmark if provided
        if benchmark is not None:
            # Ensure benchmark is aligned with equity curve
            aligned_benchmark = benchmark.reindex(equity.index, method='ffill')
            # Scale benchmark to start at same initial capital
            scaled_benchmark = aligned_benchmark / aligned_benchmark.iloc[0] * equity.iloc[0]
            ax.plot(aligned_benchmark.index, scaled_benchmark, label='Benchmark', color='gray', linewidth=1, alpha=0.7)
        
        # Add initial capital reference line
        initial_capital = self.results['initial_capital']
        ax.axhline(initial_capital, color='green', linestyle='--', alpha=0.5, label='Initial Capital')
        
        # Format y-axis as currency
        def currency_formatter(x, pos):
            return f"${x:,.0f}"
        
        ax.yaxis.set_major_formatter(FuncFormatter(currency_formatter))
        
        # Format dates on x-axis
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
        ax.xaxis.set_major_locator(mdates.MonthLocator(interval=3))
        plt.xticks(rotation=45)
        
        # Add labels and legend
        ax.set_title('Equity Curve')
        ax.set_xlabel('Date')
        ax.set_ylabel('Portfolio Value')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        fig.tight_layout()
        return fig
    
    def plot_drawdowns(self, figsize=(12, 8)):
        """
        Plot drawdowns over time.
        
        Args:
            figsize (tuple): Figure size
        
        Returns:
            matplotlib.figure.Figure: Figure object
        """
        if 'daily_returns' not in self.results or self.results['daily_returns'].empty:
            fig, ax = plt.subplots(figsize=figsize)
            ax.text(0.5, 0.5, "No return data available", ha='center', va='center')
            return fig
        
        daily_returns = self.results['daily_returns']
        
        # Calculate cumulative returns and drawdowns
        cum_rets = (1 + daily_returns).cumprod()
        running_max = cum_rets.cummax()
        drawdown = (cum_rets / running_max - 1) * 100
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=figsize, gridspec_kw={'height_ratios': [3, 1]})
        
        # Plot equity curve in top panel
        equity = self.results['equity_curve']
        ax1.plot(equity.index, equity, label='Equity', color='blue', linewidth=2)
        
        # Format y-axis as currency
        def currency_formatter(x, pos):
            return f"${x:,.0f}"
        
        ax1.yaxis.set_major_formatter(FuncFormatter(currency_formatter))
        
        # Plot drawdowns in bottom panel
        ax2.fill_between(drawdown.index, drawdown, 0, color='red', alpha=0.3, label='Drawdown')
        
        # Highlight max drawdown
        max_dd = drawdown.min()
        max_dd_date = drawdown.idxmin()
        
        ax2.scatter(max_dd_date, max_dd, color='darkred', s=80, zorder=5)
        ax2.annotate(f"Max DD: {max_dd:.2f}%", 
                    xy=(max_dd_date, max_dd),
                    xytext=(max_dd_date, max_dd * 0.8),
                    arrowprops=dict(arrowstyle="->", color='black'),
                    ha='center')
        
        # Format dates on x-axis
        for ax in [ax1, ax2]:
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            ax.xaxis.set_major_locator(mdates.MonthLocator(interval=3))
            ax.grid(True, alpha=0.3)
        
        # Set labels
        ax1.set_title('Equity Curve and Drawdowns')
        ax1.set_ylabel('Portfolio Value')
        ax1.legend()
        
        ax2.set_xlabel('Date')
        ax2.set_ylabel('Drawdown (%)')
        
        # Set y-limits for drawdown plot
        ax2.set_ylim(min(max_dd * 1.5, -30), 5)  # Cap at -30% for readability
        
        plt.xticks(rotation=45)
        fig.tight_layout()
        return fig
    
    def plot_trade_analysis(self, figsize=(16, 12)):
        """
        Plot comprehensive trade analysis charts.
        
        Args:
            figsize (tuple): Figure size
        
        Returns:
            matplotlib.figure.Figure: Figure object
        """
        if 'trades' not in self.results or self.results['trades'].empty:
            fig, ax = plt.subplots(figsize=figsize)
            ax.text(0.5, 0.5, "No trade data available", ha='center', va='center')
            return fig
        
        trades = self.results['trades']
        
        fig, axes = plt.subplots(2, 2, figsize=figsize)
        
        # 1. PnL Distribution
        ax1 = axes[0, 0]
        ax1.hist(trades['pnl'], bins=20, color='blue', alpha=0.7)
        ax1.axvline(0, color='red', linestyle='--')
        ax1.set_title('P&L Distribution')
        ax1.set_xlabel('P&L ($)')
        ax1.set_ylabel('Frequency')
        
        # 2. Cumulative P&L
        ax2 = axes[0, 1]
        cum_pnl = trades['pnl'].cumsum()
        ax2.plot(range(len(cum_pnl)), cum_pnl, color='green')
        ax2.set_title('Cumulative P&L')
        ax2.set_xlabel('Trade #')
        ax2.set_ylabel('Cumulative P&L ($)')
        ax2.axhline(0, color='red', linestyle='--', alpha=0.5)
        
        # 3. Win/Loss by Hold Time (if data available)
        ax3 = axes[1, 0]
        if 'entry_date' in trades.columns and 'exit_date' in trades.columns:
            trades['holding_period'] = (trades['exit_date'] - trades['entry_date']).dt.total_seconds() / 86400  # days
            
            # Create scatter plot
            winning_trades = trades[trades['pnl'] > 0]
            losing_trades = trades[trades['pnl'] <= 0]
            
            if not winning_trades.empty:
                ax3.scatter(winning_trades['holding_period'], winning_trades['pnl'], 
                          color='green', alpha=0.6, label='Winners')
            
            if not losing_trades.empty:
                ax3.scatter(losing_trades['holding_period'], losing_trades['pnl'], 
                          color='red', alpha=0.6, label='Losers')
            
            ax3.set_title('P&L vs Holding Period')
            ax3.set_xlabel('Holding Period (days)')
            ax3.set_ylabel('P&L ($)')
            ax3.axhline(0, color='black', linestyle='-', alpha=0.3)
            ax3.legend()
        else:
            ax3.text(0.5, 0.5, "Holding period data not available", ha='center', va='center')
        
        # 4. Win Rate by Month (if data available)
        ax4 = axes[1, 1]
        if 'entry_date' in trades.columns:
            # Group by month and calculate win rate
            trades['year_month'] = trades['entry_date'].dt.to_period('M')
            
            monthly_stats = trades.groupby('year_month').apply(
                lambda x: pd.Series({
                    'win_rate': (x['pnl'] > 0).mean() * 100,
                    'count': len(x)
                })
            )
            
            # Bar chart with win rate
            months = [str(m) for m in monthly_stats.index]
            win_rates = monthly_stats['win_rate']
            trades_count = monthly_stats['count']
            
            bars = ax4.bar(months, win_rates, color='blue', alpha=0.7)
            
            # Add trade count labels on top of bars
            for i, (count, bar) in enumerate(zip(trades_count, bars)):
                height = bar.get_height()
                ax4.text(bar.get_x() + bar.get_width()/2., height + 2,
                       f'{count:.0f}', ha='center', va='bottom', rotation=0)
            
            ax4.set_title('Monthly Win Rate')
            ax4.set_xlabel('Month')
            ax4.set_ylabel('Win Rate (%)')
            ax4.set_ylim(0, 100)
            plt.setp(ax4.xaxis.get_majorticklabels(), rotation=45)
        else:
            ax4.text(0.5, 0.5, "Date data not available", ha='center', va='center')
        
        fig.tight_layout()
        return fig
    
    def plot_monthly_returns_heatmap(self, figsize=(12, 8)):
        """
        Plot heatmap of monthly returns.
        
        Args:
            figsize (tuple): Figure size
        
        Returns:
            matplotlib.figure.Figure: Figure object
        """
        if 'equity_curve' not in self.results or self.results['equity_curve'].empty:
            fig, ax = plt.subplots(figsize=figsize)
            ax.text(0.5, 0.5, "No equity data available", ha='center', va='center')
            return fig
        
        equity = self.results['equity_curve']
        
        # Resample to month-end and calculate returns
        monthly_returns = equity.resample('M').last().pct_change().dropna() * 100
        
        # Create DataFrame with year and month
        returns_df = pd.DataFrame({
            'year': monthly_returns.index.year,
            'month': monthly_returns.index.month,
            'return': monthly_returns.values
        })
        
        # Pivot to create year x month table
        pivot_table = returns_df.pivot(index='year', columns='month', values='return')
        
        # Replace month numbers with names
        month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
                      'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        pivot_table.columns = [month_names[i-1] for i in pivot_table.columns]
        
        fig, ax = plt.subplots(figsize=figsize)
        
        # Create heatmap
        cmap = plt.cm.RdYlGn  # Red for negative, green for positive
        im = ax.imshow(pivot_table, cmap=cmap, aspect='auto')
        
        # Add colorbar
        cbar = plt.colorbar(im, ax=ax)
        cbar.set_label('Return (%)')
        
        # Configure axes
        ax.set_title('Monthly Returns Heatmap (%)')
        ax.set_ylabel('Year')
        
        # Set x-axis ticks to month names
        ax.set_xticks(np.arange(len(month_names)))
        ax.set_xticklabels(month_names)
        
        # Set y-axis ticks to years
        ax.set_yticks(np.arange(len(pivot_table.index)))
        ax.set_yticklabels(pivot_table.index)
        
        # Add text annotations with return values
        for i in range(len(pivot_table.index)):
            for j in range(len(pivot_table.columns)):
                value = pivot_table.iloc[i, j]
                if not np.isnan(value):
                    text_color = 'white' if abs(value) > 8 else 'black'
                    ax.text(j, i, f'{value:.1f}%', ha='center', va='center', color=text_color)
        
        fig.tight_layout()
        return fig

def plot_equity_curve(results, benchmark=None, figsize=(12, 6)):
    """
    Plot equity curve with optional benchmark comparison.
    
    Args:
        results (dict): Backtest results
        benchmark (pd.Series, optional): Benchmark returns
        figsize (tuple): Figure size
    
    Returns:
        matplotlib.figure.Figure: Figure object
    """
    visualizer = PerformanceVisualizer(results)
    return visualizer.plot_equity_curve(benchmark, figsize)

def plot_drawdown(results, figsize=(12, 8)):
    """
    Plot drawdowns over time.
    
    Args:
        results (dict): Backtest results
        figsize (tuple): Figure size
    
    Returns:
        matplotlib.figure.Figure: Figure object
    """
    visualizer = PerformanceVisualizer(results)
    return visualizer.plot_drawdowns(figsize)

def plot_trades(results, figsize=(16, 12)):
    """
    Plot comprehensive trade analysis charts.
    
    Args:
        results (dict): Backtest results
        figsize (tuple): Figure size
    
    Returns:
        matplotlib.figure.Figure: Figure object
    """
    visualizer = PerformanceVisualizer(results)
    return visualizer.plot_trade_analysis(figsize)

