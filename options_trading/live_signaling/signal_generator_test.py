#!/usr/bin/env python3
"""
Simplified SignalGenerator for testing data persistence
"""
import os
import logging
import pandas as pd
from datetime import datetime
import pickle
import atexit
from typing import List, Dict, Any, Optional

# Setup logging
logger = logging.getLogger(__name__)

class SignalGenerator:
    def __init__(self, api_key: str, api_secret: str):
        self.api_key = api_key
        self.api_secret = api_secret
        self.strategies = []  # Will hold strategy objects
        self.bar_count = {}  # Track number of bars received per ticker
        self.last_bar_time = {}  # Track the timestamp of the last bar for each ticker
        self.mock_mode = False  # Flag for running in mock mode
        
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
        """
        Configure data persistence settings
        
        Args:
            save_interval_seconds (int): How often to save in seconds
            bars_per_save (int): How many bars to process before saving
        """
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
            timestamp = pd.Timestamp(bar.timestamp)
            
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
                logger.debug(f"Saving data after {self.total_bars_since_save} bars or {time_since_last_save:.1f} seconds")
                self.save_data()
                self.total_bars_since_save = 0
                self.last_save_time = current_time
        
        except Exception as e:
            logger.error(f"Error processing bar: {e}", exc_info=True)
            
    async def shutdown(self):
        """
        Gracefully shut down the SignalGenerator.
        Call this method explicitly before exiting to ensure data is saved.
        """
        logger.info("Starting graceful shutdown sequence...")
        
        # Save all data
        try:
            logger.info("Saving all market data...")
            self.save_data()
        except Exception as e:
            logger.error(f"Error saving data during shutdown: {e}")
            
        logger.info("Shutdown complete.")
            
    async def start_streaming(self, symbols: List[str]):
        """Placeholder for the streaming method, will be mocked in test"""
        logger.warning("This is a placeholder method. It should be overridden in testing.")
        raise NotImplementedError("start_streaming method needs to be implemented or mocked") 