from abc import ABC, abstractmethod
import pandas as pd

class LiveStrategy(ABC):
    def __init__(self, name: str):
        self.name = name
        self.parameters = {}
        self.data_buffer = {}  # Store data for each ticker
        
    @abstractmethod
    def generate_signal(self, ticker: str, current_data: pd.DataFrame) -> dict:
        """Generate trading signals from the current market data"""
        pass
    
    def update_data(self, ticker: str, bar_data: pd.DataFrame):
        """Update the strategy's data buffer with new bar data"""
        if ticker not in self.data_buffer:
            self.data_buffer[ticker] = bar_data
        else:
            self.data_buffer[ticker] = pd.concat([self.data_buffer[ticker], bar_data])
            # Keep only last 100 bars for memory efficiency
            self.data_buffer[ticker] = self.data_buffer[ticker].tail(100)
