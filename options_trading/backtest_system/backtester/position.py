class Position:
    """
    Represents a trading position.
    """
    
    def __init__(self, ticker, entry_date, entry_price, quantity, direction=1):
        """
        Initialize a position.
        
        Args:
            ticker (str): The ticker symbol.
            entry_date (datetime): The entry date.
            entry_price (float): The entry price.
            quantity (int): The quantity of shares/contracts.
            direction (int): 1 for long, -1 for short.
        """
        self.ticker = ticker
        self.entry_date = entry_date
        self.entry_price = entry_price
        self.quantity = quantity
        self.direction = direction  # 1 for long, -1 for short
        self.exit_date = None
        self.exit_price = None
        self.current_price = entry_price
        self.pnl = 0.0
        self.exit_reason = None
        self.stop_loss = None
        self.take_profit = None
        self.status = "open"
        
    def update_value(self, current_price):
        """
        Update the current value of the position.
        
        Args:
            current_price (float): The current price.
        """
        self.current_price = current_price
        self.pnl = self.calculate_pnl(current_price)
        
    def calculate_pnl(self, price):
        """
        Calculate profit/loss at a given price.
        
        Args:
            price (float): The price to calculate P&L at.
            
        Returns:
            float: The profit/loss amount.
        """
        if self.direction == 1:  # Long position
            return (price - self.entry_price) * self.quantity
        else:  # Short position
            return (self.entry_price - price) * self.quantity
            
    def close(self, exit_date, exit_price, reason=None):
        """
        Close the position.
        
        Args:
            exit_date (datetime): The exit date.
            exit_price (float): The exit price.
            reason (str, optional): The reason for closing the position.
        """
        self.exit_date = exit_date
        self.exit_price = exit_price
        self.pnl = self.calculate_pnl(exit_price)
        self.exit_reason = reason
        self.status = "closed"
        
    def set_stop_loss(self, price=None, percentage=None):
        """
        Set a stop loss for the position.
        
        Args:
            price (float, optional): Specific price level for stop loss.
            percentage (float, optional): Percentage of entry price for stop loss.
        """
        if price is not None:
            self.stop_loss = price
        elif percentage is not None:
            if self.direction == 1:  # Long position
                self.stop_loss = self.entry_price * (1 - percentage)
            else:  # Short position
                self.stop_loss = self.entry_price * (1 + percentage)
                
    def set_take_profit(self, price=None, percentage=None):
        """
        Set a take profit level for the position.
        
        Args:
            price (float, optional): Specific price level for take profit.
            percentage (float, optional): Percentage of entry price for take profit.
        """
        if price is not None:
            self.take_profit = price
        elif percentage is not None:
            if self.direction == 1:  # Long position
                self.take_profit = self.entry_price * (1 + percentage)
            else:  # Short position
                self.take_profit = self.entry_price * (1 - percentage) 