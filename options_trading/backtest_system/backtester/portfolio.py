import pandas as pd
import numpy as np

class Position:
    """
    Represents a single trading position with entry/exit points and P&L tracking.
    """
    
    def __init__(self, ticker, entry_date, entry_price, quantity, direction=1):
        """
        Initialize a new position.
        
        Args:
            ticker (str): Ticker symbol
            entry_date: Entry date/time
            entry_price (float): Entry price
            quantity (float): Number of shares/contracts
            direction (int): 1 for long, -1 for short
        """
        self.ticker = ticker
        self.entry_date = entry_date
        self.entry_price = entry_price
        self.quantity = quantity
        self.direction = direction  # 1 for long, -1 for short
        
        self.exit_date = None
        self.exit_price = None
        self.current_price = entry_price
        self.current_value = quantity * entry_price
        self.pnl = 0.0
        self.status = 'OPEN'
        self.exit_reason = None
        self.stop_loss = None
        self.take_profit = None
        
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
        self.current_price = exit_price
        self.status = 'CLOSED'
        self.exit_reason = reason
        
        # Calculate P&L
        price_diff = (exit_price - self.entry_price) * self.direction
        self.pnl = price_diff * self.quantity
        
        # Update current value
        if self.direction == 1:  # Long position
            self.current_value = self.quantity * exit_price
        else:  # Short position
            self.current_value = self.quantity * (2 * self.entry_price - exit_price)
        
        return self.pnl
        
    # Alias for backward compatibility
    close = close_position
    
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
        
        price_diff = (current_price - self.entry_price) * self.direction
        return price_diff * self.quantity
    
    def update_value(self, current_price):
        """
        Update position with current market price.
        
        Args:
            current_price (float): Current market price
        """
        self.current_price = current_price
        if self.direction == 1:  # Long position
            self.current_value = self.quantity * current_price
        else:  # Short position
            # For short positions, value increases when price decreases
            self.current_value = self.quantity * (2 * self.entry_price - current_price)
        
        self.pnl = self.calculate_unrealized_pnl(current_price)
    
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
            'quantity': self.quantity,
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
    
    def __init__(self, initial_capital=100000.0, commission_rate=0.0):
        """
        Initialize the portfolio with a given starting capital.
        
        Args:
            initial_capital (float): The initial capital to start with.
            commission_rate (float): The commission rate for trades (as a percentage).
        """
        self.initial_capital = initial_capital
        self.current_capital = initial_capital
        self.commission_rate = commission_rate
        self.open_positions = {}
        self.closed_positions = []
        self.trades_history = []
        self.equity_curve = {}
        self.cash_history = {}
        self.current_position_size = None  # Default position size (can be overridden)
        self.max_position_size = 0.05  # Max position size as percentage of capital
        self.max_capital_per_position = 0.2  # Max capital per position
        
        self.positions = []
        self.closed_positions = []
        self.open_positions = {}  # ticker -> Position
        
        # Performance tracking
        self.equity_curve = pd.Series(initial_capital)
        self.trades_history = []
    
    def buy(self, ticker, timestamp, price, stop_loss=None, take_profit=None):
        """
        Execute a buy order
        
        Args:
            ticker (str): Ticker symbol
            timestamp: Entry time/date
            price (float): Entry price
            stop_loss (float, optional): Stop loss price
            take_profit (float, optional): Take profit price
            
        Returns:
            Position: The newly created position
        """
        if self.current_capital <= 0:
            print(f"Warning: Insufficient capital (${self.current_capital:.2f}) to open position for {ticker}")
            return None
            
        # Check if we have a current position size set
        if self.current_position_size <= 0:
            print(f"Warning: Invalid position size ({self.current_position_size}) for {ticker}")
            return None
            
        # Calculate position value (price * num_shares)
        position_value = price * self.current_position_size
        
        # Include commission
        commission_cost = position_value * self.commission_rate
        total_cost = position_value + commission_cost
        
        # Check if we have enough capital and adjust position size if needed
        if total_cost > self.current_capital:
            original_size = self.current_position_size
            # Adjust position size based on available capital
            adjusted_size = int((self.current_capital / price) / (1 + self.commission_rate))
            self.current_position_size = max(0, adjusted_size)
            print(f"Warning: Reduced position size from {original_size} to {self.current_position_size} shares due to insufficient capital")
            
            # Recalculate position value with adjusted size
            position_value = price * self.current_position_size
            commission_cost = position_value * self.commission_rate
            total_cost = position_value + commission_cost
            
        if self.current_position_size <= 0:
            print(f"Warning: Position size became zero after adjustment for {ticker}")
            return None
            
        # Create position object
        position = Position(
            ticker=ticker,
            entry_date=timestamp,
            entry_price=price,
            quantity=self.current_position_size,
            direction=1  # 1 for long
        )
        
        # Store stop loss and take profit levels
        position.stop_loss = stop_loss
        position.take_profit = take_profit
        
        # Update capital
        self.current_capital -= total_cost
        
        # Add to positions
        self.positions.append(position)
        self.open_positions[ticker] = position
        
        # Log trade
        trade_info = {
            'date': timestamp,
            'ticker': ticker,
            'action': 'BUY',
            'direction': 'LONG',
            'price': price,
            'quantity': self.current_position_size,
            'value': position_value,
            'commission': commission_cost,
            'capital_after': self.current_capital
        }
        self.trades_history.append(trade_info)
        
        return position
        
    def sell(self, ticker, timestamp, price, stop_loss=None, take_profit=None):
        """
        Execute a sell order (short position)
        
        Args:
            ticker (str): Ticker symbol
            timestamp: Entry time/date
            price (float): Entry price
            stop_loss (float, optional): Stop loss price
            take_profit (float, optional): Take profit price
            
        Returns:
            Position: The newly created position
        """
        if self.current_capital <= 0:
            print(f"Warning: Insufficient capital (${self.current_capital:.2f}) to open short position for {ticker}")
            return None
            
        # Check if we have a current position size set
        if self.current_position_size <= 0:
            print(f"Warning: Invalid position size ({self.current_position_size}) for short position on {ticker}")
            return None
            
        # Calculate position value
        position_value = price * self.current_position_size
        
        # Include commission
        commission_cost = position_value * self.commission_rate
        total_cost = position_value + commission_cost
        
        # Check if we have enough capital and adjust position size if needed
        if total_cost > self.current_capital:
            original_size = self.current_position_size
            # Adjust position size based on available capital
            adjusted_size = int((self.current_capital / price) / (1 + self.commission_rate))
            self.current_position_size = max(0, adjusted_size)
            print(f"Warning: Reduced short position size from {original_size} to {self.current_position_size} shares due to insufficient capital")
            
            # Recalculate position value with adjusted size
            position_value = price * self.current_position_size
            commission_cost = position_value * self.commission_rate
            total_cost = position_value + commission_cost
            
        if self.current_position_size <= 0:
            print(f"Warning: Position size became zero after adjustment for short position on {ticker}")
            return None
            
        # Create position object
        position = Position(
            ticker=ticker,
            entry_date=timestamp,
            entry_price=price,
            quantity=self.current_position_size,
            direction=-1  # -1 for short
        )
        
        # Store stop loss and take profit levels
        position.stop_loss = stop_loss
        position.take_profit = take_profit
        
        # Update capital (reserve margin)
        self.current_capital -= total_cost
        
        # Add to positions
        self.positions.append(position)
        self.open_positions[ticker] = position
        
        # Log trade
        trade_info = {
            'date': timestamp,
            'ticker': ticker,
            'action': 'SHORT',
            'direction': 'SHORT',
            'price': price,
            'quantity': self.current_position_size,
            'value': position_value,
            'commission': commission_cost,
            'capital_after': self.current_capital
        }
        self.trades_history.append(trade_info)
        
        return position
    
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
        commission_cost = value * self.commission_rate
        
        # Check for sufficient capital (assuming margin requirement)
        margin_requirement = value * 0.5  # 50% margin requirement
        total_required = margin_requirement + commission_cost
        
        if total_required > self.current_capital:
            # Adjust quantity to match available capital
            quantity = (self.current_capital / (price * 0.5)) / (1 + self.commission_rate)
            value = price * quantity
            commission_cost = value * self.commission_rate
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
        cost = price * position.quantity
        commission_cost = cost * self.commission_rate
        
        # Close position and calculate P&L
        pnl = position.close_position(date, price, reason)
        
        # Update capital
        # Return margin + P&L - commission
        margin_returned = position.entry_price * position.quantity * 0.5  # 50% margin
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
            'quantity': position.quantity,
            'cost': cost,
            'commission': commission_cost,
            'pnl': pnl,
            'capital_after': self.current_capital
        }
        self.trades_history.append(trade_info)
        
        return pnl
    
    def update_equity_curve(self, date, market_data):
        """
        Update equity curve for the given date.
        
        Args:
            date (datetime): Current date
            market_data (MarketData): Market data object
        """
        # Calculate total value of open positions
        positions_value = 0.0
        
        if market_data is None:
            # If no market data provided, use current values from positions
            for ticker, position in self.open_positions.items():
                if hasattr(position, 'current_value'):
                    positions_value += position.current_value
        else:
            # Update with market data
            for ticker, position in self.open_positions.items():
                try:
                    # Get current price for the ticker
                    price_data = market_data.get_price_data(ticker)
                    
                    if date in price_data.index:
                        price = price_data.loc[date]
                        
                        # Handle different price data formats
                        if isinstance(price, pd.Series):
                            if 'Close' in price:
                                price = price['Close']
                            elif 'close' in price:
                                price = price['close']
                            else:
                                price = price.iloc[0]
                        elif isinstance(price, pd.DataFrame):
                            if 'Close' in price.columns:
                                price = price['Close'].iloc[0]
                            elif 'close' in price.columns:
                                price = price['close'].iloc[0]
                            else:
                                price = price.iloc[0, 0]
                        
                        # Convert to float
                        price = float(price)
                        
                        # Update position value
                        position.update_value(price)
                        positions_value += position.current_value
                    else:
                        # Use current value
                        positions_value += position.current_value
                        
                except Exception as e:
                    print(f"Error updating position value for {ticker} on {date}: {e}")
                    # Use current value
                    positions_value += position.current_value
        
        # Total portfolio value is cash plus positions
        total_value = self.current_capital + positions_value
        
        # Update equity curve
        self.equity_curve[date] = total_value
    
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

    def set_position_size(self, position_size=None, percent_of_equity=None, max_capital_per_position=None):
        """
        Set the position size for new trades.
        
        Args:
            position_size (int, optional): Fixed number of contracts/shares.
            percent_of_equity (float, optional): Percentage of current equity to use per trade (0.0-1.0).
            max_capital_per_position (float, optional): Maximum capital to allocate per position.
        """
        if position_size is not None:
            self.current_position_size = position_size
        
        if percent_of_equity is not None:
            equity = self.calculate_total_equity()
            self.current_position_size = int((equity * percent_of_equity) / self.calculate_avg_price())
        
        if max_capital_per_position is not None:
            self.max_capital_per_position = max_capital_per_position
        
        return self.current_position_size

    def update_positions(self, current_date, market_data):
        """
        Update all open positions with the latest market data.
        
        Args:
            current_date (datetime): Current simulation date.
            market_data (DataFrame or dict): Market data for the current day.
        """
        # Make a copy of open_positions keys to avoid modification during iteration
        tickers = list(self.open_positions.keys())
        
        for ticker in tickers:
            if ticker not in self.open_positions:
                continue
            
            position = self.open_positions[ticker]
            latest_price = None
            
            try:
                # Try to find price data for this ticker
                if isinstance(market_data, pd.DataFrame):
                    # Case 1: DataFrame with ticker column
                    if 'ticker' in market_data.columns:
                        ticker_data = market_data[market_data['ticker'] == ticker]
                        if not ticker_data.empty:
                            if 'close' in ticker_data.columns:
                                latest_price = ticker_data['close'].iloc[-1]
                            elif 'Close' in ticker_data.columns:
                                latest_price = ticker_data['Close'].iloc[-1]
                            elif 'price' in ticker_data.columns:
                                latest_price = ticker_data['price'].iloc[-1]
                            else:
                                latest_price = ticker_data.iloc[-1, 0]  # Use first column as fallback
                    # Case 2: DataFrame indexed by ticker
                    elif ticker in market_data.index:
                        ticker_data = market_data.loc[ticker]
                        if isinstance(ticker_data, pd.Series):
                            if 'close' in ticker_data.index:
                                latest_price = ticker_data['close']
                            elif 'Close' in ticker_data.index:
                                latest_price = ticker_data['Close']
                            elif 'price' in ticker_data.index:
                                latest_price = ticker_data['price']
                            else:
                                latest_price = ticker_data.iloc[0]  # Use first element as fallback
                # Case 3: Dictionary format
                elif isinstance(market_data, dict) and ticker in market_data:
                    ticker_data = market_data[ticker]
                    if isinstance(ticker_data, dict):
                        if 'close' in ticker_data:
                            latest_price = ticker_data['close']
                        elif 'Close' in ticker_data:
                            latest_price = ticker_data['Close']
                        elif 'price' in ticker_data:
                            latest_price = ticker_data['price']
                    else:
                        latest_price = ticker_data  # Use direct value
                
                # Update position if we found a price
                if latest_price is not None:
                    # Convert to float if needed
                    if not isinstance(latest_price, (int, float)):
                        latest_price = float(latest_price)
                    
                    # Update position value
                    position.update_value(latest_price)
                    
                    # Check stop loss condition
                    if position.stop_loss is not None:
                        if (position.direction == 1 and latest_price <= position.stop_loss) or \
                           (position.direction == -1 and latest_price >= position.stop_loss):
                            print(f"Stop loss triggered for {ticker} at {latest_price:.2f} (stop: {position.stop_loss:.2f})")
                            self.close_position(position, current_date, latest_price, "stop_loss")
                            continue
                    
                    # Check take profit condition
                    if position.take_profit is not None:
                        if (position.direction == 1 and latest_price >= position.take_profit) or \
                           (position.direction == -1 and latest_price <= position.take_profit):
                            print(f"Take profit triggered for {ticker} at {latest_price:.2f} (target: {position.take_profit:.2f})")
                            self.close_position(position, current_date, latest_price, "take_profit")
            except Exception as e:
                print(f"Error updating position for {ticker}: {e}")
        
        # Update equity curve
        self.update_equity_curve(current_date, market_data if hasattr(market_data, 'get_price_data') else None)

    def close_position(self, position, exit_date, exit_price, reason=None):
        """
        Close a position and move it to closed positions.
        
        Args:
            position (Position): The position to close.
            exit_date (datetime): The exit date.
            exit_price (float): The exit price.
            reason (str, optional): The reason for closing the position.
        
        Returns:
            float: The realized P&L from closing the position.
        """
        position.close_position(exit_date, exit_price, reason)
        
        # Calculate commission
        commission = exit_price * position.quantity * self.commission_rate
        
        # Update cash balance and account for commission
        self.current_capital += (exit_price * position.quantity) - commission
        
        # Find the position in open_positions dictionary (by ticker) and remove it
        # This is safer than checking if position is in open_positions as it might be a different object
        ticker = position.ticker
        if ticker in self.open_positions:
            del self.open_positions[ticker]
        
        # Add to closed positions list
        self.closed_positions.append(position)
        
        # Get direction text
        direction_text = "LONG" if position.direction == 1 else "SHORT"
        exit_action = "SELL" if position.direction == 1 else "COVER"
        
        # Add to trades history
        trade_record = {
            'date': exit_date,
            'ticker': position.ticker,
            'action': exit_action,
            'direction': direction_text,
            'price': exit_price,
            'quantity': position.quantity,
            'value': exit_price * position.quantity,
            'commission': commission,
            'pnl': position.pnl - commission,
            'exit_reason': reason,
            'entry_date': position.entry_date,
            'entry_price': position.entry_price,
            'trade_duration': (exit_date - position.entry_date).total_seconds() / 60  # in minutes
        }
        self.trades_history.append(trade_record)
        
        return position.pnl

    def calculate_total_equity(self):
        """
        Calculate the total equity (cash + positions value).
        
        Returns:
            float: Total equity value
        """
        positions_value = 0.0
        
        for ticker, position in self.open_positions.items():
            if position.current_price is not None:
                if position.direction == 1:  # Long position
                    positions_value += position.quantity * position.current_price
                else:  # Short position
                    positions_value += position.quantity * (2 * position.entry_price - position.current_price)
        
        return self.current_capital + positions_value

    def calculate_avg_price(self):
        """
        Calculate the average price of open positions or current market price.
        Used for position sizing when percentage of equity is specified.
        
        Returns:
            float: Average price or 1.0 if no positions/price available
        """
        if not self.open_positions:
            return 1.0  # Default if no positions
        
        total_price = 0.0
        count = 0
        
        for ticker, position in self.open_positions.items():
            if position.current_price is not None:
                total_price += position.current_price
                count += 1
        
        if count > 0:
            return total_price / count
        else:
            return 1.0  # Default if no valid prices

    def print_trade_summary(self):
        """
        Print a detailed summary of all trades with entry/exit information, direction, and outcomes.
        """
        if not self.trades_history:
            print("No trades executed during this backtest.")
            return
        
        # Create a DataFrame from trade history
        trades_df = pd.DataFrame(self.trades_history)
        
        # Filter to only include exit trades (SELL or COVER actions) that have PnL data
        exit_trades = trades_df[trades_df['action'].isin(['SELL', 'COVER'])]
        
        if exit_trades.empty:
            print("No completed trades (no exits) in this backtest.")
            return
        
        # Print summary
        print("\n=== TRADE-BY-TRADE ANALYSIS ===")
        print(f"Total Completed Trades: {len(exit_trades)}")
        
        # Group by direction and calculate metrics
        by_direction = exit_trades.groupby('direction')
        direction_summary = by_direction.agg({
            'pnl': ['count', 'sum', 'mean'],
            'ticker': 'count'
        })
        
        print("\nBy Direction:")
        for direction, stats in direction_summary.iterrows():
            count = stats[('pnl', 'count')]
            total_pnl = stats[('pnl', 'sum')]
            avg_pnl = stats[('pnl', 'mean')]
            print(f"{direction}: {count} trades, Total P&L: ${total_pnl:.2f}, Avg P&L per trade: ${avg_pnl:.2f}")
        
        # Win/Loss metrics
        winning_trades = exit_trades[exit_trades['pnl'] > 0]
        losing_trades = exit_trades[exit_trades['pnl'] <= 0]
        
        win_count = len(winning_trades)
        loss_count = len(losing_trades)
        win_rate = (win_count / len(exit_trades) * 100) if len(exit_trades) > 0 else 0
        
        avg_win = winning_trades['pnl'].mean() if not winning_trades.empty else 0
        avg_loss = losing_trades['pnl'].mean() if not losing_trades.empty else 0
        
        print(f"\nWin Rate: {win_rate:.2f}% ({win_count}/{len(exit_trades)})")
        print(f"Average Winner: ${avg_win:.2f}")
        print(f"Average Loser: ${avg_loss:.2f}")
        
        if avg_loss != 0:
            print(f"Win/Loss Ratio: {abs(avg_win/avg_loss):.2f}")
        
        print("\nIndividual Trade Details:")
        print("------------------------")
        
        for i, trade in exit_trades.iterrows():
            direction = trade['direction']
            win_loss = "WIN" if trade['pnl'] > 0 else "LOSS"
            pnl = trade['pnl']
            reason = trade.get('exit_reason', 'N/A')
            duration = trade.get('trade_duration', 0)
            
            # Format entry and exit times
            if isinstance(trade['entry_date'], (str, pd.Timestamp)):
                if isinstance(trade['entry_date'], str):
                    entry_time = trade['entry_date']
                else:
                    entry_time = trade['entry_date'].strftime('%Y-%m-%d %H:%M:%S')
            else:
                entry_time = str(trade['entry_date'])
            
            if isinstance(trade['date'], (str, pd.Timestamp)):
                if isinstance(trade['date'], str):
                    exit_time = trade['date']
                else:
                    exit_time = trade['date'].strftime('%Y-%m-%d %H:%M:%S')
            else:
                exit_time = str(trade['date'])
            
            ticker = trade['ticker']
            qty = trade['quantity']
            entry = trade['entry_price']
            exit = trade['price']
            
            print(f"Trade #{i+1}: {direction} {ticker} - {win_loss} (${pnl:.2f})")
            print(f"  Entry: {entry_time} @ ${entry:.2f} x {qty} shares")
            print(f"  Exit:  {exit_time} @ ${exit:.2f} ({reason})")
            print(f"  Duration: {duration:.1f} minutes")
            print("------------------------")

