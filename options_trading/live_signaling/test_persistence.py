#!/usr/bin/env python3
"""
Simplified script to test data persistence functionality
Everything needed is contained in this single file
"""
import os
import sys
import time
import logging
import asyncio
import signal
import argparse
import pandas as pd
import numpy as np
from datetime import datetime
import pickle
import atexit
import random

# Set up logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Test symbols
TEST_SYMBOLS = ["AAPL", "MSFT", "AMZN"]

class SimpleStrategy:
    """
    A simple strategy class for testing data persistence
    """
    def __init__(self):
        """Initialize the strategy"""
        self.name = "SimpleTestStrategy"
        self.data_buffer = {}  # To store market data by ticker
        logger.info(f"Initialized {self.name}")
        
    def update_data(self, ticker: str, new_data: pd.DataFrame):
        """Update the data buffer with new market data"""
        if ticker not in self.data_buffer:
            self.data_buffer[ticker] = new_data
        else:
            # Append new data to existing data
            self.data_buffer[ticker] = pd.concat([self.data_buffer[ticker], new_data])
            
            # Keep the buffer to a reasonable size (last 200 bars)
            if len(self.data_buffer[ticker]) > 200:
                self.data_buffer[ticker] = self.data_buffer[ticker].iloc[-200:]
    
    def generate_signal(self, ticker: str, data: pd.DataFrame):
        """Generate trading signals for a ticker"""
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

class SignalGenerator:
    """
    Simple SignalGenerator for testing data persistence
    """
    def __init__(self):
        """Initialize the generator with minimal setup"""
        self.strategies = []  # Will hold strategy objects
        self.bar_count = {}  # Track number of bars received per ticker
        self.last_bar_time = {}  # Track the timestamp of the last bar for each ticker
        
        # Data persistence settings
        self.data_directory = os.path.join(os.getcwd(), "saved_data")
        self.today_date = datetime.now().strftime("%Y-%m-%d")
        self.data_filename = os.path.join(self.data_directory, f"market_data_{self.today_date}.pkl")
        self.last_save_time = datetime.now()
        self.save_interval = 60  # Save every 60 seconds
        self.total_bars_since_save = 0
        self.bars_per_save = 10  # Save every 10 bars
        
        # Create data directory if it doesn't exist
        if not os.path.exists(self.data_directory):
            os.makedirs(self.data_directory)
            
        # Register save_data function to run on exit
        atexit.register(self.save_data)
        
        # Try to load existing data for today
        self.load_data()
        
    def set_persistence_config(self, save_interval_seconds=60, bars_per_save=10):
        """Configure data persistence settings"""
        self.save_interval = save_interval_seconds
        self.bars_per_save = bars_per_save
        logger.info(f"Data persistence configured: saving every {save_interval_seconds}s or {bars_per_save} bars")
        
    def add_strategy(self, strategy):
        """Add a trading strategy to the generator"""
        self.strategies.append(strategy)
        logger.info(f"Added strategy: {strategy.name}")
        
    def save_data(self):
        """Save all strategy data buffers to a file"""
        try:
            if not self.strategies:
                logger.warning("No strategies to save data for")
                return
                
            # Create a dictionary to hold all strategy data
            data_to_save = {}
            total_bars = 0
            
            # Store data from each strategy
            for strategy in self.strategies:
                strategy_data = {}
                for ticker, data in strategy.data_buffer.items():
                    # Convert DataFrame to dict for serialization
                    strategy_data[ticker] = data.to_dict()
                    total_bars += len(data)
                data_to_save[strategy.name] = strategy_data
            
            # Save to file
            with open(self.data_filename, 'wb') as f:
                pickle.dump(data_to_save, f)
                
            # Show a more visible message with save stats
            logger.info(f"✅ Data saved: {total_bars} total bars for {len(self.strategies)} strategies")
            logger.debug(f"Data file location: {self.data_filename}")
            
        except Exception as e:
            logger.error(f"Error saving market data: {e}", exc_info=True)
            
    def load_data(self):
        """Load market data from file if it exists for the current day"""
        try:
            if not os.path.exists(self.data_filename):
                logger.info(f"No saved data found for today ({self.today_date})")
                return
                
            # Load data from file
            with open(self.data_filename, 'rb') as f:
                saved_data = pickle.load(f)
                
            # Data existed but no strategies loaded yet
            if not self.strategies:
                logger.info("Data found but no strategies loaded yet. Will restore after strategies are added.")
                self._pending_data_load = saved_data
                return
                
            # Restore data for each strategy
            self._restore_strategy_data(saved_data)
                
        except Exception as e:
            logger.error(f"Error loading market data: {e}", exc_info=True)
            
    def _restore_strategy_data(self, saved_data):
        """Restore data to strategies from saved data"""
        loaded_count = 0
        loaded_tickers = set()
        strategies_loaded = 0
        
        for strategy in self.strategies:
            if strategy.name in saved_data:
                strategies_loaded += 1
                strategy_data = saved_data[strategy.name]
                ticker_count = 0
                
                for ticker, data_dict in strategy_data.items():
                    # Convert dict back to DataFrame
                    df = pd.DataFrame.from_dict(data_dict)
                    # Restore the index as DatetimeIndex
                    if 'index' in data_dict:
                        df.index = pd.DatetimeIndex(df.index)
                    strategy.data_buffer[ticker] = df
                    
                    # Update bar count and last bar time
                    if df.shape[0] > 0:
                        self.bar_count[ticker] = self.bar_count.get(ticker, 0) + df.shape[0]
                        self.last_bar_time[ticker] = df.index[-1]
                        loaded_count += df.shape[0]
                        loaded_tickers.add(ticker)
                        ticker_count += 1
        
        if loaded_count > 0:
            # Show a more detailed load message
            logger.info(f"🔄 Loaded {loaded_count} bars of market data for {len(loaded_tickers)} tickers")
            logger.info(f"   Data restored for {strategies_loaded} strategies")
            logger.debug(f"   From file: {self.data_filename}")
            
            # Show the most recent data point for each ticker
            for ticker in loaded_tickers:
                if ticker in self.last_bar_time:
                    logger.debug(f"   {ticker}: Last bar from {self.last_bar_time[ticker]}")
        else:
            logger.info("No market data loaded")
            
    async def process_bar(self, bar):
        """Process incoming bar data"""
        try:
            ticker = bar.symbol
            timestamp = bar.timestamp
            
            # Update bar count
            self.bar_count[ticker] = self.bar_count.get(ticker, 0) + 1
            self.last_bar_time[ticker] = timestamp
            self.total_bars_since_save += 1
            
            # Create DataFrame from bar data
            new_data = pd.DataFrame({
                'open': [bar.open],
                'high': [bar.high],
                'low': [bar.low],
                'close': [bar.close],
                'volume': [bar.volume]
            }, index=[timestamp])
            
            # Process through each strategy
            for strategy in self.strategies:
                strategy.update_data(ticker, new_data)
                signals = strategy.generate_signal(ticker, strategy.data_buffer[ticker])
                
                if signals['signal'] is not None:
                    logger.info(f"Signal generated for {ticker}: {signals['signal']}")
                    # Always save data immediately when a signal is generated
                    self.save_data()
                    self.total_bars_since_save = 0
                    self.last_save_time = datetime.now()
            
            # Check if we should save data based on time or bar count
            current_time = datetime.now()
            time_since_last_save = (current_time - self.last_save_time).total_seconds()
            
            if time_since_last_save >= self.save_interval or self.total_bars_since_save >= self.bars_per_save:
                logger.info(f"Saving data after {self.total_bars_since_save} bars or {time_since_last_save:.1f} seconds")
                self.save_data()
                self.total_bars_since_save = 0
                self.last_save_time = current_time
        
        except Exception as e:
            logger.error(f"Error processing bar: {e}", exc_info=True)
            
    async def shutdown(self):
        """Gracefully shut down the SignalGenerator"""
        logger.info("Starting graceful shutdown sequence...")
        
        # Save all data
        try:
            logger.info("Saving all market data...")
            self.save_data()
        except Exception as e:
            logger.error(f"Error saving data during shutdown: {e}")
            
        logger.info("Shutdown complete.")
            
    async def generate_mock_data(self, symbols, num_bars=100, delay=0.1):
        """Generate mock data for testing"""
        logger.info(f"Generating mock data for {symbols}")
        
        class MockBar:
            def __init__(self, symbol):
                self.symbol = symbol
                self.timestamp = pd.Timestamp.now()
                price = 100 + random.normalvariate(0, 5)
                self.open = price
                self.high = price * (1 + random.random() * 0.01)
                self.low = price * (1 - random.random() * 0.01)
                self.close = price * (1 + random.normalvariate(0, 0.005))
                self.volume = int(random.random() * 10000)
        
        try:
            # Generate data
            for i in range(num_bars):
                for symbol in symbols:
                    # Create and process a mock bar
                    bar = MockBar(symbol)
                    await self.process_bar(bar)
                    
                # Sleep to simulate time passing
                await asyncio.sleep(delay)
                
                # Print progress
                if i > 0 and i % 10 == 0:
                    logger.info(f"Generated {i} bars for each symbol")
                    
        except asyncio.CancelledError:
            logger.info("Mock data generation cancelled")
            await self.shutdown()
        except Exception as e:
            logger.error(f"Error generating mock data: {e}")
            await self.shutdown()

async def run_test(save_interval=5, bars_per_save=5, run_time=30):
    """Run the data persistence test"""
    # Create the signal generator
    signal_gen = SignalGenerator()
    
    # Configure persistence
    signal_gen.set_persistence_config(
        save_interval_seconds=save_interval,
        bars_per_save=bars_per_save
    )
    
    # Add a strategy
    strategy = SimpleStrategy()
    signal_gen.add_strategy(strategy)
    
    # Create a shutdown flag
    shutdown_in_progress = False
    
    # Set up signal handler for graceful shutdown
    def handle_signal(sig, frame):
        nonlocal shutdown_in_progress
        if shutdown_in_progress:
            logger.info("Shutdown already in progress, please wait...")
            return
            
        shutdown_in_progress = True
        logger.info(f"Received signal {sig}. Starting graceful shutdown...")
        
        # Create a new event loop for the shutdown
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(signal_gen.shutdown())
            logger.info("Graceful shutdown complete. Exiting...")
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
        finally:
            loop.close()
            sys.exit(0)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, handle_signal)   # Ctrl+C
    signal.signal(signal.SIGTERM, handle_signal)  # Terminal close
    
    # Start generating mock data
    logger.info(f"Starting mock data generation. Will run for {run_time} seconds or until Ctrl+C.")
    logger.info(f"Data will be saved every {save_interval} seconds or {bars_per_save} bars.")
    
    try:
        # Create a task for data generation
        data_task = asyncio.create_task(signal_gen.generate_mock_data(
            TEST_SYMBOLS, 
            num_bars=1000,  # More than we need
            delay=0.2       # Slower for testing
        ))
        
        # Run for specified time then cancel
        await asyncio.sleep(run_time)
        logger.info(f"Test completed after {run_time} seconds.")
        data_task.cancel()
        
        # Shutdown
        await signal_gen.shutdown()
        
    except KeyboardInterrupt:
        logger.info("Test interrupted. Shutting down...")
        await signal_gen.shutdown()
    except Exception as e:
        logger.error(f"Error during test: {e}")
        await signal_gen.shutdown()

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Test data persistence")
    parser.add_argument("--save-interval", type=int, default=5,
                        help="How often to save in seconds (default: 5)")
    parser.add_argument("--bars-per-save", type=int, default=5, 
                        help="How many bars to process before saving (default: 5)")
    parser.add_argument("--run-time", type=int, default=30,
                        help="How long to run the test in seconds (default: 30)")
    args = parser.parse_args()
    
    # Check if data already exists
    today = datetime.now().strftime("%Y-%m-%d")
    data_path = os.path.join(os.getcwd(), "saved_data", f"market_data_{today}.pkl")
    
    if os.path.exists(data_path):
        logger.info(f"Found existing data file at {data_path}")
        logger.info("The test will load this data and continue collecting")
    else:
        logger.info("No existing data found. Will start fresh data collection")
    
    # Run the test
    try:
        asyncio.run(run_test(
            save_interval=args.save_interval,
            bars_per_save=args.bars_per_save,
            run_time=args.run_time
        ))
    except KeyboardInterrupt:
        logger.info("Test interrupted by user. Exiting...")
    except Exception as e:
        logger.error(f"Error in main: {e}") 