import pandas as pd
import numpy as np

class Position:
    """
    Represents a single trading position with entry/exit points and P&L tracking.
    """
    
    def __init__(self, ticker, entry_date, entry_price, position_size, direction, stop_loss=None, take_profit=None):
        """
        Initialize a new position.
        
        Args:
            ticker (str): Ticker symbol
            entry_date: Entry date/time
            entry_price (float): Entry price
            position_size (float): Number of shares/contracts
            direction (int): 1 for long, -1 for short
            stop_loss (float, optional): Stop loss price
            take_profit (float, optional): Take profit price
        """
        self.ticker = ticker
        self.entry_date = entry_date
        self.entry_price = entry_price
        self.position_size = position_size
        self.direction = direction  # 1 for long, -1 for short
        
        self.exit_date = None
        self.exit_price = None
        self.pnl = None
        self.status = 'OPEN'
        self.exit_reason = None
        
        self.stop_loss = stop_loss
        self.take_profit = take_profit
        
    def close_position(self, exit_date, exit_price, reason=None):
        """
        Close the position and calculate P&L.
        
        Args:
            exit_date: Exit date/time
            exit_price (float): Exit price
            reason (str, optional): Reason for closing
        
        Returns:
            float: Realized P&L
        """
        self.exit_date = exit_date
        self.exit_price = exit_price
        self.status = 'CLOSED'
        self.exit_reason = reason
        
        # Calculate P&L
        if self.direction == 1:  # Long position
            price_diff = (exit_price - self.entry_price)
        else:  # Short position
            price_diff = (self.entry_price - exit_price)
        
        self.pnl = price_diff * self.position_size
        
        return self.pnl
    
    def calculate_unrealized_pnl(self, current_price):
        """
        Calculate unrealized P&L at current market price.
        
        Args:
            current_price (float): Current market price
            
        Returns:
            float: Unrealized P&L
        """
        if self.status == 'CLOSED':
            return self.pnl
        
        price_diff = (current_price - self.entry_price)
        return price_diff * self.position_size
    
    def to_dict(self):
        """
        Convert position to dictionary for easy analysis.
        
        Returns:
            dict: Position details
        """
        return {
            'ticker': self.ticker,
            'entry_date': self.entry_date,
            'entry_price': self.entry_price,
            'position_size': self.position_size,
            'direction': 'LONG' if self.direction == 1 else 'SHORT',
            'exit_date': self.exit_date,
            'exit_price': self.exit_price,
            'pnl': self.pnl,
            'status': self.status,
            'exit_reason': self.exit_reason
        }


class Portfolio:
    """
    Manages a portfolio of positions, tracks performance and executes trades.
    """
    
    def __init__(self, initial_capital):
        """
        Initialize portfolio with starting capital.
        
        Args:
            initial_capital (float): Initial capital amount
        """
        self.initial_capital = initial_capital
        self.current_capital = initial_capital
        self.current_position_size = 0
        self.commission = 0.001
        
        self.positions = []
        self.closed_positions = []
        self.open_positions = {}  # ticker -> Position
        
        # Performance tracking
        self.equity_curve = pd.Series(initial_capital, index=[pd.Timestamp.now()])  # Initialize as Series
        self.trades_history = []
    
    def buy(self, ticker, timestamp, price, stop_loss=None, take_profit=None):
        """
        Execute a buy order
        """
        if self.current_capital <= 0:
            return
            
        # Calculate position value using the stored position size
        position_value = price * self.current_position_size
        
        # Check if we have enough capital
        if position_value > self.current_capital:
            print(f"Warning: Not enough capital for position. Required: ${position_value:.2f}, Available: ${self.current_capital:.2f}")
            return
            
        # Store the position
        self.open_positions[ticker] = Position(
            ticker=ticker,
            entry_date=timestamp,
            entry_price=price,
            position_size=self.current_position_size,  # Use the stored position size
            direction=1,
            stop_loss=stop_loss,
            take_profit=take_profit
        )
        
        # Update capital
        self.current_capital -= position_value
        print(f"Buy executed: {self.current_position_size} shares of {ticker} at ${price:.2f}")
        print(f"Position value: ${position_value:.2f}")
        print(f"Remaining capital: ${self.current_capital:.2f}")
        
    def sell(self, ticker, timestamp, price, stop_loss=None, take_profit=None):
        """
        Execute a sell order (short position)
        """
        if self.current_capital <= 0:
            return
            
        # Calculate position value
        position_value = price * self.current_position_size
        
        if position_value > self.current_capital:
            return
            
        self.open_positions[ticker] = Position(
            ticker=ticker,
            entry_date=timestamp,
            entry_price=price,
            position_size=self.current_position_size,
            direction=-1,
            stop_loss=stop_loss,
            take_profit=take_profit
        )
        
        # Update capital
        self.current_capital -= position_value
        print(f"Short executed: {self.current_position_size} shares of {ticker} at ${price:.2f}")
    
    def short(self, ticker, date, price, quantity=None, amount=None, stop_loss=None, take_profit=None):
        """
        Open a short position.
        
        Args:
            ticker (str): Ticker symbol
            date: Trade date/time
            price (float): Entry price
            quantity (float, optional): Number of shares to short
            amount (float, optional): USD amount to short (alternative to quantity)
            stop_loss (float, optional): Stop loss price
            take_profit (float, optional): Take profit price
            
        Returns:
            Position: The newly created position
        """
        # Calculate quantity if amount is specified
        if quantity is None and amount is not None:
            quantity = amount / price
            
        # Calculate commission
        value = price * quantity
        commission_cost = value * self.commission
        
        # Check for sufficient capital (assuming margin requirement)
        margin_requirement = value * 0.5  # 50% margin requirement
        total_required = margin_requirement + commission_cost
        
        if total_required > self.current_capital:
            # Adjust quantity to match available capital
            quantity = (self.current_capital / (price * 0.5)) / (1 + self.commission)
            value = price * quantity
            commission_cost = value * self.commission
            margin_requirement = value * 0.5
            
        # Create new position
        position = Position(ticker, date, price, quantity, direction=-1)
        
        # Store stop loss and take profit levels
        position.stop_loss = stop_loss
        position.take_profit = take_profit
        
        # Update capital (reserve margin)
        self.current_capital -= (margin_requirement + commission_cost)
        
        # Add to positions
        self.positions.append(position)
        self.open_positions[ticker] = position
        
        # Log trade
        trade_info = {
            'date': date,
            'ticker': ticker,
            'action': 'SHORT',
            'price': price,
            'quantity': quantity,
            'value': value,
            'commission': commission_cost,
            'margin': margin_requirement,
            'capital_after': self.current_capital
        }
        self.trades_history.append(trade_info)
        
        return position
    
    def cover(self, ticker, date, price, reason=None):
        """
        Close a short position.
        
        Args:
            ticker (str): Ticker symbol
            date: Trade date/time
            price (float): Exit price
            reason (str, optional): Reason for covering
            
        Returns:
            float: Realized P&L
        """
        if ticker not in self.open_positions:
            return 0.0
            
        position = self.open_positions[ticker]
        
        if position.direction != -1:
            return 0.0  # Not a short position
            
        # Calculate cost to cover and commission
        cost = price * position.position_size
        commission_cost = cost * self.commission
        
        # Close position and calculate P&L
        pnl = position.close_position(date, price, reason)
        
        # Update capital
        # Return margin + P&L - commission
        margin_returned = position.entry_price * position.position_size * 0.5  # 50% margin
        self.current_capital += margin_returned + pnl - commission_cost
        
        # Move to closed positions
        self.closed_positions.append(position)
        del self.open_positions[ticker]
        
        # Log trade
        trade_info = {
            'date': date,
            'ticker': ticker,
            'action': 'COVER',
            'price': price,
            'quantity': position.position_size,
            'cost': cost,
            'commission': commission_cost,
            'pnl': pnl,
            'capital_after': self.current_capital
        }
        self.trades_history.append(trade_info)
        
        return pnl
    
    def update_equity_curve(self, current_time, market_data):
        """
        Update the equity curve with current portfolio value
        """
        # Calculate total value of open positions
        positions_value = 0
        for ticker, position in self.open_positions.items():
            # Fix the float conversion
            current_price = market_data.get_price_data(ticker).loc[current_time].iloc[0]
            positions_value += current_price * position.position_size
        
        # Total portfolio value is cash plus positions
        total_value = self.current_capital + positions_value
        
        # Convert timezone-aware timestamp to UTC
        if hasattr(current_time, 'tz') and current_time.tz is not None:
            current_time = current_time.tz_convert('UTC')
        
        # Update the Series
        self.equity_curve[current_time] = total_value
    
    def check_stop_loss_take_profit(self, date, market_data):
        """
        Check if any open positions hit stop loss or take profit levels.
        
        Args:
            date: Current date/time
            market_data (MarketData): Market data object
        """
        # Make a copy since we'll be modifying the dictionary during iteration
        tickers = list(self.open_positions.keys())
        
        for ticker in tickers:
            if ticker not in self.open_positions:
                continue
                
            position = self.open_positions[ticker]
            
            try:
                # Get latest prices
                current_price = market_data.get_price_data(ticker).loc[date]
                
                # Check stop loss
                if position.stop_loss is not None:
                    if (position.direction == 1 and current_price <= position.stop_loss) or \
                       (position.direction == -1 and current_price >= position.stop_loss):
                        if position.direction == 1:
                            self.sell(ticker, date, current_price, reason='STOP_LOSS')
                        else:
                            self.cover(ticker, date, current_price, reason='STOP_LOSS')
                        continue
                
                # Check take profit
                if position.take_profit is not None:
                    if (position.direction == 1 and current_price >= position.take_profit) or \
                       (position.direction == -1 and current_price <= position.take_profit):
                        if position.direction == 1:
                            self.sell(ticker, date, current_price, reason='TAKE_PROFIT')
                        else:
                            self.cover(ticker, date, current_price, reason='TAKE_PROFIT')
            except (KeyError, ValueError):
                # If price data is not available for this date
                pass
    
    def get_trades_summary(self):
        """
        Get summary of all closed trades.
        
        Returns:
            pd.DataFrame: Summary of closed trades
        """
        if not self.closed_positions:
            return pd.DataFrame()
            
        trades_data = [pos.to_dict() for pos in self.closed_positions]
        return pd.DataFrame(trades_data)
    
    def get_equity_curve(self):
        """
        Get the equity curve.
        
        Returns:
            pd.Series: Equity curve
        """
        return self.equity_curve

    def close_position(self, ticker, exit_date, exit_price, reason=""):
        """
        Close an existing position
        """
        if ticker not in self.open_positions:
            print(f"Warning: No open position found for {ticker} to close")
            return False
            
        position = self.open_positions[ticker]
        position.exit_date = exit_date
        position.exit_price = exit_price
        position.exit_reason = reason
        
        # Calculate P&L
        if position.direction == 1:  # Long position
            position.pnl = (exit_price - position.entry_price) * position.position_size
        else:  # Short position
            position.pnl = (position.entry_price - exit_price) * position.position_size
            
        # Update capital
        self.current_capital += (exit_price * position.position_size)
        
        # Add to trade history
        self.trades_history.append({
            'ticker': position.ticker,
            'entry_date': position.entry_date,
            'entry_price': position.entry_price,
            'exit_date': position.exit_date,
            'exit_price': position.exit_price,
            'quantity': position.position_size,
            'direction': position.direction,
            'pnl': position.pnl,
            'exit_reason': position.exit_reason
        })
        
        # Remove from open positions
        del self.open_positions[ticker]
        print(f"Position closed: {ticker} at ${exit_price:.2f}, P&L: ${position.pnl:.2f}")
        return True

    def calculate_trade_stats(self):
        """Calculate trading statistics"""
        if not self.trades_history:
            return {
                'num_trades': 0,
                'win_rate_pct': 0,
                'avg_win_loss_ratio': 0,
                'profit_factor': 0
            }
            
        # Convert to DataFrame and filter out non-trade entries
        trades_df = pd.DataFrame(self.trades_history)
        
        # Debug print
        print("\nRaw Trade Data:")
        print(trades_df[['entry_price', 'exit_price', 'quantity', 'pnl']].head())
        
        # Filter for completed trades only (must have both entry and exit)
        valid_trades = trades_df.dropna(subset=['entry_price', 'exit_price', 'pnl'])
        
        if len(valid_trades) == 0:
            print("Warning: No valid completed trades found")
            return {
                'num_trades': 0,
                'win_rate_pct': 0,
                'avg_win_loss_ratio': 0,
                'profit_factor': 0
            }
        
        num_trades = len(valid_trades)
        winning_trades = valid_trades[valid_trades['pnl'] > 0]
        losing_trades = valid_trades[valid_trades['pnl'] < 0]
        break_even_trades = valid_trades[valid_trades['pnl'] == 0]
        
        num_winners = len(winning_trades)
        num_losers = len(losing_trades)
        
        # Debug print
        print(f"\nTrade Breakdown:")
        print(f"Total valid trades: {num_trades}")
        print(f"Winners: {num_winners}")
        print(f"Losers: {num_losers}")
        print(f"Break even: {len(break_even_trades)}")
        
        # Calculate win rate
        win_rate = (num_winners / num_trades * 100) if num_trades > 0 else 0
        
        # Calculate win/loss ratio and profit factor
        if num_winners > 0 and num_losers > 0:
            avg_win = winning_trades['pnl'].mean()
            avg_loss = abs(losing_trades['pnl'].mean())
            win_loss_ratio = avg_win / avg_loss if avg_loss != 0 else 0
            
            total_gains = winning_trades['pnl'].sum()
            total_losses = abs(losing_trades['pnl'].sum())
            profit_factor = total_gains / total_losses if total_losses != 0 else 0
            
            # Debug print
            print(f"\nProfitability Metrics:")
            print(f"Average winning trade: ${avg_win:.2f}")
            print(f"Average losing trade: ${avg_loss:.2f}")
            print(f"Total gains: ${total_gains:.2f}")
            print(f"Total losses: ${total_losses:.2f}")
        else:
            win_loss_ratio = 1 if num_winners > 0 else 0
            profit_factor = 1 if num_winners > 0 else 0
        
        stats = {
            'num_trades': num_trades,
            'win_rate_pct': win_rate,
            'avg_win_loss_ratio': win_loss_ratio,
            'profit_factor': profit_factor
        }
        
        # Debug print
        print("\nFinal Statistics:")
        for key, value in stats.items():
            print(f"{key}: {value}")
            
        return stats

    def get_results(self):
        """
        Get backtest results
        """
        # Convert equity curve index to UTC
        equity_curve = self.equity_curve.copy()
        if hasattr(equity_curve.index, 'tz') and equity_curve.index.tz is not None:
            equity_curve.index = equity_curve.index.tz_convert('UTC')
        
        # Calculate trade statistics first
        trade_stats = self.calculate_trade_stats()
        
        results = {
            'initial_capital': self.initial_capital,
            'final_capital': self.current_capital,
            'trades': pd.DataFrame(self.trades_history),
            'equity_curve': equity_curve,
            'total_return_pct': ((self.current_capital - self.initial_capital) / self.initial_capital) * 100,
            **trade_stats  # Include trade statistics
        }
        
        # Calculate daily returns if we have enough data
        if len(equity_curve) > 1:
            results['daily_returns'] = equity_curve.pct_change().fillna(0)
            results['sharpe_ratio'] = self.calculate_sharpe_ratio(results['daily_returns'])
            results['max_drawdown_pct'] = self.calculate_max_drawdown(equity_curve)
            
        return results

    def calculate_sharpe_ratio(self, returns, risk_free_rate=0.0):
        """Calculate the Sharpe ratio"""
        if len(returns) < 2:
            return 0
        excess_returns = returns - risk_free_rate
        return np.sqrt(252) * (excess_returns.mean() / excess_returns.std())

    def calculate_max_drawdown(self, equity_curve):
        """Calculate the maximum drawdown percentage"""
        rolling_max = equity_curve.expanding().max()
        drawdowns = (equity_curve - rolling_max) / rolling_max * 100
        return abs(drawdowns.min())