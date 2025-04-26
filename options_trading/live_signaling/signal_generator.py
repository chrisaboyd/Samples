from alpaca.data.live import StockDataStream
from alpaca.trading.client import TradingClient
import pandas as pd
import logging
from typing import List, Dict
from datetime import datetime, date
import pytz
import requests
import json
import os
import dotenv
import atexit
import pickle
from strategies.base_strategy import LiveStrategy

# Enhanced logging setup with custom formatter
class CustomFormatter(logging.Formatter):
    def format(self, record):
        if getattr(record, 'is_signal', False):
            # Don't add timestamp for signal parts
            return record.getMessage()
        # Add timestamp for regular messages
        return f"{self.formatTime(record)} - {record.levelname} - {record.getMessage()}"

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(CustomFormatter())
logger.handlers = [handler]

class SignalGenerator:
    def __init__(self, api_key: str, api_secret: str):
        self.api_key = api_key
        self.api_secret = api_secret
        self.trading_client = TradingClient(api_key, api_secret)
        self.stream = StockDataStream(api_key, api_secret)
        self.strategies: List[LiveStrategy] = []
        self.bar_count: Dict[str, int] = {}
        self.last_bar_time: Dict[str, datetime] = {}
        self.debug_mode = False
        
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
        
        # Load Discord webhook URL
        dotenv.load_dotenv()
        self.discord_webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
        if self.discord_webhook_url:
            logger.info("Discord webhook URL loaded successfully")
        else:
            logger.warning("Discord webhook URL not found in environment variables")
        
    def add_strategy(self, strategy: LiveStrategy):
        """Add a trading strategy to the generator"""
        self.strategies.append(strategy)
        logger.info(f"Added strategy: {strategy.name}")
        
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
        
    def send_to_discord(self, strategy_name: str, ticker: str, signals: dict):
        """Send nicely formatted signal to Discord webhook"""
        if not self.discord_webhook_url:
            return
            
        try:
            # Extract signal data
            signal_type = signals['signal']
            signal_emoji = "🟢" if signal_type == 'buy' else "🔴"
            
            # Format all numeric values to two decimal places
            entry_price = f"${signals['entry_price']:.2f}"
            stop_loss = f"${signals['stop_loss']:.2f}"
            profit_target = f"${signals['profit_target']:.2f}"
            
            # Add emojis for stop loss and target
            stop_emoji = "🛑" # Stop sign emoji
            target_emoji = "🎯" # Target emoji
            
            # Calculate risk/reward
            risk = abs(signals['entry_price'] - signals['stop_loss'])
            reward = abs(signals['profit_target'] - signals['entry_price'])
            risk_reward = f"{(reward / risk if risk > 0 else 0):.2f}"
            
            # Get RSI value if available
            rsi_value = "N/A"
            if 'rsi' in signals and signals['rsi'] is not None:
                rsi_emoji = "📊" # Chart emoji
                rsi_value = f"{signals['rsi']:.1f}"
                # Add color indicators for RSI
                if signals['rsi'] >= 70:
                    rsi_value += " 🔴" # Overbought
                elif signals['rsi'] <= 30:
                    rsi_value += " 🟢" # Oversold
            
            # Build embedded message with the requested fields
            embed = {
                "title": f"{strategy_name} - {ticker}",
                "color": 65280 if signal_type == 'buy' else 16711680,  # Green for buy, Red for sell
                "fields": [
                    {
                        "name": "Signal",
                        "value": f"{signal_emoji} **{signal_type.upper()}**",
                        "inline": True
                    },
                    {
                        "name": "Entry Price",
                        "value": entry_price,
                        "inline": True
                    },
                    {
                        "name": f"{stop_emoji} Stop Loss",
                        "value": stop_loss,
                        "inline": True
                    },
                    {
                        "name": f"{target_emoji} Target",
                        "value": profit_target,
                        "inline": True
                    },
                    {
                        "name": "Risk/Reward",
                        "value": risk_reward,
                        "inline": True
                    },
                    {
                        "name": f"{rsi_emoji} RSI",
                        "value": rsi_value,
                        "inline": True
                    }
                ],
                "footer": {
                    "text": f"Time: {datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M:%S ET')}"
                }
            }
            
            # Send to Discord
            payload = {
                "embeds": [embed]
            }
            
            response = requests.post(
                self.discord_webhook_url, 
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            
        except Exception as e:
            logger.error(f"Error sending to Discord: {e}")
            
    def print_signal(self, strategy_name: str, ticker: str, signals: dict):
        """Pretty print the signal information"""
        logger.info("\n=== SIGNAL GENERATED ===", extra={'is_signal': True})
        logger.info(f"Time    : {datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M:%S ET')}", 
                   extra={'is_signal': True})
        logger.info(f"Strategy: {strategy_name}", extra={'is_signal': True})
        logger.info(f"Ticker  : {ticker}", extra={'is_signal': True})
        logger.info(f"Action  : {signals['signal'].upper()}", extra={'is_signal': True})
        logger.info("\nPrices:", extra={'is_signal': True})
        logger.info(f"  Current  : ${signals['entry_price']:.2f}", extra={'is_signal': True})
        logger.info(f"  Entry    : ${signals['entry_price']:.2f}", extra={'is_signal': True})
        logger.info(f"  Stop     : ${signals['stop_loss']:.2f}", extra={'is_signal': True})
        logger.info(f"  Target   : ${signals['profit_target']:.2f}", extra={'is_signal': True})
        
        # Calculate and display risk metrics
        risk = abs(signals['entry_price'] - signals['stop_loss'])
        reward = abs(signals['profit_target'] - signals['entry_price'])
        risk_reward = reward / risk if risk > 0 else 0
        
        logger.info("\nRisk Metrics:", extra={'is_signal': True})
        logger.info(f"  Risk     : ${risk:.2f}", extra={'is_signal': True})
        logger.info(f"  Reward   : ${reward:.2f}", extra={'is_signal': True})
        logger.info(f"  R/R Ratio: {risk_reward:.2f}", extra={'is_signal': True})
        
        # Print technical indicators if available
        if 'ema_short' in signals or 'ema_mid' in signals or 'ema_long' in signals:
            logger.info("\nTechnical Indicators:", extra={'is_signal': True})
            if 'ema_short' in signals:
                logger.info(f"  EMA Short: {signals['ema_short']:.2f}", extra={'is_signal': True})
            if 'ema_mid' in signals:
                logger.info(f"  EMA Mid  : {signals['ema_mid']:.2f}", extra={'is_signal': True})
            if 'ema_long' in signals:
                logger.info(f"  EMA Long : {signals['ema_long']:.2f}", extra={'is_signal': True})
                
        logger.info("=====================\n", extra={'is_signal': True})

    def print_debug_stats(self):
        """Print debug statistics"""
        if not self.debug_mode:
            return
            
        logger.info("\n=== Debug Statistics ===")
        for ticker in self.bar_count:
            logger.info(f"Ticker: {ticker}")
            logger.info(f"  Total bars received: {self.bar_count[ticker]}")
            logger.info(f"  Last bar time: {self.last_bar_time.get(ticker, 'No bars yet')}")
            logger.info(f"  Data buffer sizes:")
            for strategy in self.strategies:
                if ticker in strategy.data_buffer:
                    logger.info(f"    {strategy.name}: {len(strategy.data_buffer[ticker])} bars")
        logger.info("=====================\n")
        
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
                    self.print_signal(strategy.name, ticker, signals)
                    # Also send to Discord
                    self.send_to_discord(strategy.name, ticker, signals)
                    # Always save data immediately when a signal is generated
                    self.save_data()
                    self.total_bars_since_save = 0
                    self.last_save_time = datetime.now()
            
            # Print debug stats every 10 bars only if debug mode is on
            if self.debug_mode and self.bar_count[ticker] % 10 == 0:
                self.print_debug_stats()
                
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
            
        # Close any network connections
        try:
            if hasattr(self, 'stream') and self.stream:
                logger.info("Closing data stream connection...")
                await self.stream.close()
                logger.info("Data stream closed.")
        except Exception as e:
            logger.error(f"Error closing stream during shutdown: {e}")
            
        logger.info("Shutdown complete.")
        
    async def start_streaming(self, symbols: List[str]):
        """Start the data stream"""
        try:
            # Initialize counters
            for symbol in symbols:
                self.bar_count[symbol] = 0
            
            # If we have pending data to load after strategies were added
            if hasattr(self, '_pending_data_load'):
                self._restore_strategy_data(self._pending_data_load)
                delattr(self, '_pending_data_load')
                
            logger.info(f"Starting data stream for symbols: {symbols}")
            
            # Subscribe to minute bars
            self.stream.subscribe_bars(self.process_bar, *symbols)
            
            # Start streaming
            await self.stream._run_forever()
            
        except KeyboardInterrupt:
            logger.info("Stream interrupted by user")
            await self.shutdown()
            raise
        except Exception as e:
            logger.error(f"Error in stream: {e}", exc_info=True)
            await self.shutdown()
            raise 