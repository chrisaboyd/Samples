#!/usr/bin/env python3
import os
import sys
import time
import logging
import asyncio
import signal
import argparse
import pandas as pd
import numpy as np
from dotenv import load_dotenv

# Add parent directory to path to allow imports from sibling directories
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Now we can import from other modules
from simple_strategy import SimpleStrategy
from tests.signal_generator_test import SignalGenerator

# Set up logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Test symbols
TEST_SYMBOLS = ["AAPL", "MSFT", "AMZN"]

async def run_test(save_interval, bars_per_save, use_mock=False):
    """Run a test of the data persistence functionality"""
    # Load environment variables
    load_dotenv()
    api_key = os.getenv("ALPACA_API_KEY")
    api_secret = os.getenv("ALPACA_API_SECRET")
    
    if (not api_key or not api_secret) and not use_mock:
        logger.warning("Alpaca API credentials not found in environment variables")
        logger.warning("Running in mock mode (no live data)")
        use_mock = True
    
    # Create SignalGenerator
    if use_mock:
        # Use dummy values for testing
        signal_gen = SignalGenerator("dummy_key", "dummy_secret")
        # Override the start_streaming method for mock mode
        signal_gen.mock_mode = True
        
        # Store the original method for later restoration
        original_start_streaming = signal_gen.start_streaming
        
        # Define a mock streaming method
        async def mock_streaming(symbols):
            logger.info(f"MOCK MODE: Simulating data stream for {symbols}")
            
            # Generate some sample data
            for i in range(100):
                for symbol in symbols:
                    # Create a mock bar
                    timestamp = pd.Timestamp.now()
                    price = 100 + np.random.normal(0, 5)
                    
                    class MockBar:
                        def __init__(self, symbol, timestamp, price):
                            self.symbol = symbol
                            self.timestamp = timestamp
                            self.open = price
                            self.high = price * (1 + np.random.random() * 0.01)
                            self.low = price * (1 - np.random.random() * 0.01)
                            self.close = price * (1 + np.random.normal(0, 0.005))
                            self.volume = int(np.random.random() * 10000)
                    
                    # Create mock bar
                    bar = MockBar(symbol, timestamp, price)
                    
                    # Process the bar
                    await signal_gen.process_bar(bar)
                    
                    # Log progress
                    if i % 10 == 0:
                        logger.info(f"Processed {i} mock bars for {symbol}")
                
                # Sleep to simulate real-time data
                await asyncio.sleep(0.1)
                
                # Every 10 bars, check if we should exit
                if i > 0 and i % 10 == 0:
                    logger.info(f"MOCK MODE: Processed {i} bars. Press Ctrl+C to exit.")
        
        # Replace the method
        signal_gen.start_streaming = mock_streaming
    else:
        signal_gen = SignalGenerator(api_key, api_secret)
    
    # Configure data persistence
    signal_gen.set_persistence_config(
        save_interval_seconds=save_interval,
        bars_per_save=bars_per_save
    )
    
    # Add strategy
    strategy = SimpleStrategy()
    signal_gen.add_strategy(strategy)
    
    # Create a shutdown flag to prevent multiple shutdown attempts
    shutdown_in_progress = False
    
    # Set up signal handler for graceful shutdown
    def handle_signal(sig, frame):
        nonlocal shutdown_in_progress
        if shutdown_in_progress:
            logger.info("Shutdown already in progress, please wait...")
            return
            
        shutdown_in_progress = True
        logger.info(f"Received signal {sig}. Starting graceful shutdown...")
        
        # We need to create a new event loop for the shutdown in the signal handler
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(signal_gen.shutdown())
            logger.info("Graceful shutdown complete. Exiting...")
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            logger.info("Attempting basic data save as fallback...")
            try:
                signal_gen.save_data()
                logger.info("Basic data save successful. Exiting...")
            except Exception as save_error:
                logger.error(f"Failed to save data during fallback: {save_error}")
        finally:
            loop.close()
            sys.exit(0)
    
    # Register signals for graceful interruption
    signal.signal(signal.SIGINT, handle_signal)   # Ctrl+C
    signal.signal(signal.SIGTERM, handle_signal)  # Terminal close
    
    # Start streaming (this will automatically load data if it exists)
    logger.info("Starting market data stream. Press CTRL+C to exit and save data.")
    try:
        # Start the stream for test symbols
        await signal_gen.start_streaming(TEST_SYMBOLS)
    except KeyboardInterrupt:
        logger.info("Test interrupted with KeyboardInterrupt. Starting shutdown sequence...")
        await signal_gen.shutdown()
        logger.info("Shutdown complete after keyboard interrupt.")
    except Exception as e:
        logger.error(f"Error during test: {e}", exc_info=True)
        # Also try to save on other exceptions
        try:
            logger.info("Starting shutdown sequence after error...")
            await signal_gen.shutdown()
            logger.info("Shutdown complete after error.")
        except Exception as shutdown_error:
            logger.error(f"Failed during shutdown: {shutdown_error}")
            logger.info("Attempting basic data save as last resort...")
            try:
                signal_gen.save_data()
                logger.info("Basic data save successful.")
            except Exception as save_error:
                logger.error(f"Failed to save data: {save_error}")

if __name__ == "__main__":
    # Add command line arguments for configuration
    parser = argparse.ArgumentParser(description="Test data persistence in the signal generator")
    parser.add_argument("--save-interval", type=int, default=60,
                        help="How often to save data in seconds (default: 60)")
    parser.add_argument("--bars-per-save", type=int, default=10,
                        help="How many bars to process before saving (default: 10)")
    parser.add_argument("--mock", action="store_true",
                        help="Run in mock mode without real Alpaca connection")
    args = parser.parse_args()
    
    # Check if saved data exists
    today = time.strftime("%Y-%m-%d")
    data_path = os.path.join(os.getcwd(), "saved_data", f"market_data_{today}.pkl")
    
    if os.path.exists(data_path):
        logger.info(f"Found existing data file at {data_path}")
        logger.info("Running test will load this data and continue collecting")
    else:
        logger.info("No existing data found. Will start fresh data collection")
    
    # Print configuration
    mode_str = "MOCK MODE" if args.mock else "LIVE MODE"
    logger.info(f"Running in {mode_str}")
    logger.info(f"Data will be saved every {args.save_interval} seconds or {args.bars_per_save} bars")
    
    # Run the test
    asyncio.run(run_test(args.save_interval, args.bars_per_save, args.mock)) 