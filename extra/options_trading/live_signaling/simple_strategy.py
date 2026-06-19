#!/usr/bin/env python3
"""
Simple strategy for testing data persistence
"""
import pandas as pd
import numpy as np
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class SimpleStrategy:
    """
    A simple strategy class for testing data persistence in live signaling.
    """
    
    def __init__(self):
        """Initialize the strategy"""
        self.name = "SimpleTestStrategy"
        self.data_buffer = {}  # To store market data by ticker
        logger.info(f"Initialized {self.name}")
        
    def update_data(self, ticker: str, new_data: pd.DataFrame):
        """
        Update the data buffer with new market data
        
        Args:
            ticker: The ticker symbol
            new_data: DataFrame with new price data
        """
        if ticker not in self.data_buffer:
            self.data_buffer[ticker] = new_data
        else:
            # Append new data to existing data
            self.data_buffer[ticker] = pd.concat([self.data_buffer[ticker], new_data])
            
            # Keep the buffer to a reasonable size (last 200 bars)
            if len(self.data_buffer[ticker]) > 200:
                self.data_buffer[ticker] = self.data_buffer[ticker].iloc[-200:]
    
    def generate_signal(self, ticker: str, data: pd.DataFrame) -> Dict[str, Any]:
        """
        Generate trading signals for a ticker
        
        Args:
            ticker: The ticker symbol
            data: DataFrame with market data
            
        Returns:
            dict: Signal data
        """
        # Initialize return values
        signal_dict = {
            'signal': None,
            'entry_price': None,
            'stop_loss': None,
            'profit_target': None,
            'rsi': None
        }
        
        # Skip if not enough data
        if len(data) < 5:
            return signal_dict
            
        # Simple random signal generation (0.5% chance of signal)
        if np.random.random() < 0.005:
            # Get latest price
            latest_price = data['close'].iloc[-1]
            
            # Randomly choose buy or sell
            signal_type = np.random.choice(['buy', 'sell'])
            signal_dict['signal'] = signal_type
            signal_dict['entry_price'] = latest_price
            
            # Set stop loss and target
            if signal_type == 'buy':
                signal_dict['stop_loss'] = latest_price * 0.98  # 2% stop loss
                signal_dict['profit_target'] = latest_price * 1.05  # 5% profit target
            else:  # sell
                signal_dict['stop_loss'] = latest_price * 1.02  # 2% stop loss
                signal_dict['profit_target'] = latest_price * 0.95  # 5% profit target
                
            # Simulate RSI
            signal_dict['rsi'] = np.random.uniform(20, 80)
            
        return signal_dict 