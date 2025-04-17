from datetime import datetime, time
import pandas as pd
from .base_strategy import LiveStrategy

class LiveORBStrategy(LiveStrategy):
    def __init__(self):
        super().__init__("ORB")
        self.parameters.update({
            'market_open_time': time(9, 30),
            'market_close_time': time(16, 0),
            'opening_range_duration': 15,
            'tolerance': 0.001
        })
        self.orb_ranges = {}  # Store ORB ranges for each ticker
        
    def generate_signal(self, ticker: str, current_data: pd.DataFrame) -> dict:
        if ticker not in self.data_buffer:
            return {'signal': None}
            
        current_time = datetime.now().time()
        
        # Calculate ORB range during first 15 minutes
        if current_time <= time(9, 45):  # 9:30 + 15 minutes
            if ticker not in self.orb_ranges:
                self.orb_ranges[ticker] = {
                    'high': current_data['high'].max(),
                    'low': current_data['low'].min()
                }
            return {'signal': None}
            
        # Generate signals after ORB period
        if ticker in self.orb_ranges:
            current_price = current_data['close'].iloc[-1]
            orb_high = self.orb_ranges[ticker]['high']
            orb_low = self.orb_ranges[ticker]['low']
            orb_range = orb_high - orb_low
            
            # Long setup
            if (orb_high * (1 - self.parameters['tolerance']) <= 
                current_price <= orb_high * (1 + self.parameters['tolerance'])):
                
                stop_loss = current_price - (0.25 * orb_range)
                profit_target = current_price + (0.45 * orb_range)
                
                return {
                    'signal': 'buy',
                    'entry_price': float(current_price),
                    'stop_loss': float(stop_loss),
                    'profit_target': float(profit_target),
                    'orb_high': float(orb_high),
                    'orb_low': float(orb_low)
                }
                
            # Short setup
            if (orb_low * (1 - self.parameters['tolerance']) <= 
                current_price <= orb_low * (1 + self.parameters['tolerance'])):
                
                stop_loss = current_price + (0.25 * orb_range)
                profit_target = current_price - (0.45 * orb_range)
                
                return {
                    'signal': 'sell',
                    'entry_price': float(current_price),
                    'stop_loss': float(stop_loss),
                    'profit_target': float(profit_target),
                    'orb_high': float(orb_high),
                    'orb_low': float(orb_low)
                }
                
        return {'signal': None}
