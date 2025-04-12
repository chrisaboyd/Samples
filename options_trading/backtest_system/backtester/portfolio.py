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
        self.pnl = 0.0
        self.status = 'OPEN'
        self.exit_reason = None
        
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
        price_diff = (exit_price - self.entry_price) * self.direction
        self.pnl = price_diff * self.quantity
        
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
        
        price_diff = (current_price - self.entry_price) * self.direction
        return price_diff * self.quantity
    
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
    
    def __init__(self, initial_capital=100000.0, commission=0.001):
        """
        Initialize portfolio with starting capital.
        
        Args:
            initial_capital (float): Initial capital amount
            commission (float): Commission rate as decimal (e.g., 0.001 = 0.1%)
        """
        self.initial_capital = initial_capital
        self.current_capital = initial_capital
        self.commission = commission
        
        self.positions = []
        self.closed_positions = []
        self.open_positions = {}  # ticker -> Position
        
        # Performance tracking
        self.equity_curve = pd.Series(initial_capital)
        self.trades_history = []
    
    def buy(self, ticker, timestamp, price, stop_loss=None, take_profit=None):
        """
        Execute a buy order
        """
        if self.current_capital <= 0:
            return
            
        # Calculate position value (price * num_shares)
        position_value = price * self.current_position_size
        
        if position_value > self.current_capital:
            return
            
        self.open_positions[ticker] = Position(
            ticker=ticker,
            entry_time=timestamp,
            entry_price=price,
            size=self.current_position_size,
            direction=1,  # 1 for long
            stop_loss=stop_loss,
            take_profit=take_profit
        )
        
        # Update capital
        self.current_capital -= position_value
        
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
            entry_time=timestamp,
            entry_price=price,
            size=self.current_position_size,
            direction=-1,  # -1 for short
            stop_loss=stop_loss,
            take_profit=take_profit
        )
        
        # Update capital
        self.current_capital -= position_value
    
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
        cost = price * position.quantity
        commission_cost = cost * self.commission
        
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
                        else:
                            price = price.iloc[0]
                    elif isinstance(price, pd.DataFrame):
                        if 'Close' in price.columns:
                            price = price['Close'].iloc[0]
                        else:
                            price = price.iloc[0, 0]
                    
                    # Convert to float
                    price = float(price)
                    
                    # Calculate position value
                    if position.direction == 1:  # Long position
                        value = position.quantity * price
                    else:  # Short position
                        value = position.quantity * (2 * position.entry_price - price)
                    
                    positions_value += value
                else:
                    # Use last known value if date not in price data
                    positions_value += position.current_value
                    
            except Exception as e:
                print(f"Error updating position value for {ticker} on {date}: {e}")
                # Use last known value
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

