from alpaca.data.live import StockDataStream
from alpaca.trading.client import TradingClient
import pandas as pd
import logging
from typing import List, Dict
from datetime import datetime
import pytz
from strategies.base_strategy import LiveStrategy
import requests
import json


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
        self.discord_webhook_url = "https://discord.com/api/webhooks/1337973080911249499/Ctf9bLlNFpt_j5oGdrzxmoSEOBZaqPvsX5tyWX2RwPgcmJd1cB0PHIzI1Zl6-_D60wCj"
        
    def add_strategy(self, strategy: LiveStrategy):
        """Add a trading strategy to the generator"""
        self.strategies.append(strategy)
        logger.info(f"Added strategy: {strategy.name}")
        
    def print_signal(self, strategy_name: str, ticker: str, signals: dict):
        """Pretty print the signal information"""
        logger.info("\n=== SIGNAL GENERATED ===", extra={'is_signal': True})
        logger.info(f"Time    : {datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M:%S ET')}", 
                    extra={'is_signal': True})
        logger.info(f"Strategy: {strategy_name}", extra={'is_signal': True})
        logger.info(f"Ticker  : {ticker}", extra={'is_signal': True})
        logger.info(f"Action  : {signals['signal'].upper()}", extra={'is_signal': True})
        logger.info("\nPrices:", extra={'is_signal': True})
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
    
    def send_discord_notification(self, strategy_name, ticker, signals):
        """Send signal notification to Discord channel via webhook"""
        signal_type = signals['signal']
        price = signals.get('price', 'N/A')
        
        # Set color based on signal type (green for buy, red for sell)
        color = 0x00FF00 if signal_type.lower() == "buy" else 0xFF0000
        
        # Create rich embed
        embed = {
            "title": f"{strategy_name} - {ticker}",
            "description": f"Signal: **{signal_type}**",
            "color": color,
            "fields": [
                {"name": "Price", "value": str(price), "inline": True}
            ]
        }
        
        # Add additional fields
        for key, value in signals.items():
            if key not in ['signal', 'price']:
                embed["fields"].append({
                    "name": key.capitalize(),
                    "value": str(value),
                    "inline": True
                })
        
        payload = {
            "embeds": [embed]
        }
        
        # Send the webhook request
        try:
            response = requests.post(
                self.discord_webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to send Discord notification: {e}")

    async def process_bar(self, bar):
        """Process incoming bar data"""
        try:
            ticker = bar.symbol
            timestamp = pd.Timestamp(bar.timestamp)
            
            # Update bar count
            self.bar_count[ticker] = self.bar_count.get(ticker, 0) + 1
            self.last_bar_time[ticker] = timestamp
            
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
                    self.send_discord_notification(strategy.name, ticker, signals)
            
            # Print debug stats every 10 bars only if debug mode is on
            if self.debug_mode and self.bar_count[ticker] % 10 == 0:
                self.print_debug_stats()
        
        except Exception as e:
            logger.error(f"Error processing bar: {e}", exc_info=True)
            
    async def start_streaming(self, symbols: List[str]):
        """Start the data stream"""
        try:
            # Initialize counters
            for symbol in symbols:
                self.bar_count[symbol] = 0
            
            logger.info(f"Starting data stream for symbols: {symbols}")
            
            # Subscribe to minute bars
            self.stream.subscribe_bars(self.process_bar, *symbols)
            
            # Start streaming
            await self.stream._run_forever()
            
        except Exception as e:
            logger.error(f"Error in stream: {e}", exc_info=True)
            raise 