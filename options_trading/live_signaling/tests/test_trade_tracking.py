#!/usr/bin/env python3
"""
Test script for the trade tracking functionality
"""
import os
import sys
import time
import logging
import asyncio
import random
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
import pytz
from signal_generator import SignalGenerator, Trade, TradeTracker
from dotenv import load_dotenv

# Update the sys.path to include the parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Update import to use the parent directory module
from signal_generator import SignalGenerator, Trade, TradeTracker

# Set up logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Test symbols
TEST_SYMBOLS = ["AAPL", "MSFT", "AMZN", "TSLA", "NVDA"]

class MockStrategy:
    """Simple mock strategy for testing"""
    def __init__(self, name="MockStrategy"):
        self.name = name
        self.data_buffer = {}
        
    def update_data(self, ticker, new_data):
        """Update data buffer with new price data"""
        if ticker not in self.data_buffer:
            self.data_buffer[ticker] = new_data
        else:
            self.data_buffer[ticker] = pd.concat([self.data_buffer[ticker], new_data])
            # Keep only last 100 bars for memory efficiency
            self.data_buffer[ticker] = self.data_buffer[ticker].tail(100)
            
    def generate_signal(self, ticker, data):
        """Generate a random trading signal occasionally"""
        # Default signal structure
        signal = {
            'signal': None,
            'entry_price': None,
            'stop_loss': None,
            'profit_target': None,
            'rsi': None
        }
        
        # Only generate a signal 2% of the time
        if random.random() < 0.02 and len(data) > 0:
            # Get the latest price
            latest_price = data['close'].iloc[-1]
            
            # Randomly generate buy or sell
            signal_type = random.choice(['buy', 'sell'])
            signal['signal'] = signal_type
            signal['entry_price'] = latest_price
            
            # Calculate stop loss and take profit
            if signal_type == 'buy':
                signal['stop_loss'] = latest_price * 0.95  # 5% stop loss
                signal['profit_target'] = latest_price * 1.10  # 10% profit target
            else:  # sell
                signal['stop_loss'] = latest_price * 1.05  # 5% stop loss
                signal['profit_target'] = latest_price * 0.90  # 10% profit target
                
            # Add some technical indicators for fun
            signal['rsi'] = random.uniform(20, 80)
            
        return signal

class MockBar:
    """Mock price bar for testing"""
    def __init__(self, symbol, timestamp=None, base_price=None):
        self.symbol = symbol
        self.timestamp = timestamp or datetime.now()
        
        # Generate a realistic price (around $100-500 with some volatility)
        if base_price is None:
            if symbol == "AAPL":
                base_price = 180 + random.uniform(-5, 5)
            elif symbol == "MSFT":
                base_price = 350 + random.uniform(-8, 8)
            elif symbol == "AMZN":
                base_price = 130 + random.uniform(-4, 4)
            elif symbol == "TSLA":
                base_price = 175 + random.uniform(-10, 10)
            elif symbol == "NVDA":
                base_price = 450 + random.uniform(-15, 15)
            else:
                base_price = 100 + random.uniform(-3, 3)
                
        self.close = base_price
        self.open = base_price * (1 + random.uniform(-0.01, 0.01))
        self.high = max(self.open, self.close) * (1 + random.uniform(0, 0.01))
        self.low = min(self.open, self.close) * (1 - random.uniform(0, 0.01))
        self.volume = int(random.uniform(10000, 1000000))
        
    @staticmethod
    def create_price_series(symbol, days=30, base_price=None, trend=0.0):
        """Create a series of bars with a slight trend"""
        bars = []
        now = datetime.now()
        
        # If base price is not provided, use a default based on symbol
        if base_price is None:
            if symbol == "AAPL":
                base_price = 180
            elif symbol == "MSFT":
                base_price = 350
            elif symbol == "AMZN":
                base_price = 130
            elif symbol == "TSLA":
                base_price = 175
            elif symbol == "NVDA":
                base_price = 450
            else:
                base_price = 100
                
        current_price = base_price
        
        # Create bars for each day
        for i in range(days * 8):  # 8 bars per day
            # Add trend and some noise
            current_price *= (1 + trend + random.uniform(-0.02, 0.02))
            
            # Create timestamp (market hours)
            bar_time = now - timedelta(hours=i)
            # Only use times during market hours (9:30 AM - 4:00 PM ET)
            bar_time = bar_time.replace(hour=9 + (i % 6), minute=30 + ((i * 10) % 30))
            
            # Create the bar
            bar = MockBar(symbol, bar_time, current_price)
            bars.append(bar)
            
        return bars

def simulate_price_movement(base_price, trend_direction=0, volatility=0.01):
    """Generate a new price based on previous price with some randomness"""
    # Add trend direction (-1 to 1)
    trend = trend_direction * 0.005  # Scale trend to be subtle
    
    # Calculate price change with random noise
    price_change = trend + random.uniform(-volatility, volatility)
    
    # Return new price
    return base_price * (1 + price_change)

async def run_test_tracking():
    """Run a test of the trade tracking functionality"""
    # Load environment variables for Discord webhook (if available)
    load_dotenv()
    
    # Create a SignalGenerator with dummy API keys
    signal_gen = SignalGenerator("dummy_key", "dummy_secret")
    
    # Add a mock strategy
    strategy = MockStrategy("TradeTrackerTest")
    signal_gen.add_strategy(strategy)
    
    # Initialize price dictionary
    prices = {symbol: 0 for symbol in TEST_SYMBOLS}
    prices["AAPL"] = 180
    prices["MSFT"] = 350
    prices["AMZN"] = 130
    prices["TSLA"] = 175
    prices["NVDA"] = 450
    
    # Set price trends (positive or negative)
    trends = {
        "AAPL": 0.2,    # Bullish
        "MSFT": 0.1,    # Slightly bullish
        "AMZN": -0.1,   # Slightly bearish
        "TSLA": -0.3,   # Bearish
        "NVDA": 0.0     # Neutral
    }
    
    # Run for 100 simulated bars
    logger.info("Starting trade tracking test with simulated price data")
    logger.info(f"Monitoring {len(TEST_SYMBOLS)} symbols: {', '.join(TEST_SYMBOLS)}")
    
    # Create initial bars for each symbol
    for symbol in TEST_SYMBOLS:
        # Get historic bars
        historical_bars = MockBar.create_price_series(symbol, days=7, trend=trends[symbol]/10)
        historical_bars.reverse()  # Make time go forward
        
        # Process historical bars first
        for bar in historical_bars:
            await signal_gen.process_bar(bar)
    
    # Simulate 100 more live bars
    for i in range(100):
        # Generate a new bar for each symbol
        for symbol in TEST_SYMBOLS:
            # Update price based on previous price and trend
            prices[symbol] = simulate_price_movement(
                prices[symbol], 
                trend_direction=trends[symbol],
                volatility=0.02
            )
            
            # Create a bar
            timestamp = datetime.now() + timedelta(minutes=i)
            bar = MockBar(symbol, timestamp, prices[symbol])
            
            # Process the bar
            await signal_gen.process_bar(bar)
            
        # Add a small delay to simulate real-time processing
        await asyncio.sleep(0.1)
        
        # Show stats every 10 bars
        if i > 0 and i % 10 == 0:
            logger.info(f"Processed {i} bars")
            
            # Get trade stats
            signal_gen.print_trade_stats()
    
    # Show final statistics
    logger.info("\nTest completed!")
    signal_gen.print_trade_stats()
    
    # Save trade data
    signal_gen.save_trades()

if __name__ == "__main__":
    try:
        asyncio.run(run_test_tracking())
    except KeyboardInterrupt:
        logger.info("Test interrupted by user")
    except Exception as e:
        logger.error(f"Error during test: {e}", exc_info=True) 