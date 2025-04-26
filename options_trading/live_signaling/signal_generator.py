from alpaca.data.live import StockDataStream
from alpaca.trading.client import TradingClient
import pandas as pd
import logging
from typing import List, Dict
from datetime import datetime
import pytz
import requests
import json
import os
import dotenv
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
        
    def send_to_discord(self, strategy_name: str, ticker: str, signals: dict):
        """Send nicely formatted signal to Discord webhook"""
        if not self.discord_webhook_url:
            return
            
        try:
            # Extract signal data
            signal_type = signals['signal']
            emoji = "🟢" if signal_type == 'buy' else "🔴"
            
            # Format all numeric values to two decimal places
            entry_price = f"${signals['entry_price']:.2f}"
            stop_loss = f"${signals['stop_loss']:.2f}"
            profit_target = f"${signals['profit_target']:.2f}"
            
            # Format EMAs to two decimal places
            ema_short = f"{signals.get('ema_short', 0):.2f}"
            ema_mid = f"{signals.get('ema_mid', 0):.2f}"
            ema_long = f"{signals.get('ema_long', 0):.2f}"
            
            # Format orb levels
            orb_high = f"${signals.get('orb_high', 0):.2f}" if 'orb_high' in signals else "N/A"
            orb_low = f"${signals.get('orb_low', 0):.2f}" if 'orb_low' in signals else "N/A"
            
            # Current price (use entry price since that's current price at signal)
            current_price = f"${signals['entry_price']:.2f}"
            
            # Calculate risk/reward
            risk = abs(signals['entry_price'] - signals['stop_loss'])
            reward = abs(signals['profit_target'] - signals['entry_price'])
            risk_reward = f"{(reward / risk if risk > 0 else 0):.2f}"
            
            # Check if this is a reversal
            reversal = signals.get('reversal', False)
            reversal_text = "True" if reversal else "False"
            
            # Build embedded message
            embed = {
                "title": f"{strategy_name} - {ticker}",
                "color": 65280 if signal_type == 'buy' else 16711680,  # Green for buy, Red for sell
                "fields": [
                    {
                        "name": "Signal",
                        "value": f"{emoji} **{signal_type.upper()}**",
                        "inline": True
                    },
                    {
                        "name": "Price",
                        "value": current_price,
                        "inline": True
                    },
                    {
                        "name": "Entry_price",
                        "value": entry_price,
                        "inline": True
                    },
                    {
                        "name": "Stop_loss",
                        "value": stop_loss,
                        "inline": True
                    },
                    {
                        "name": "Profit_target",
                        "value": profit_target,
                        "inline": True
                    },
                    {
                        "name": "Risk/Reward",
                        "value": risk_reward,
                        "inline": True
                    },
                    {
                        "name": "Ema_mid",
                        "value": ema_mid,
                        "inline": True
                    },
                    {
                        "name": "Ema_short",
                        "value": ema_short,
                        "inline": True
                    },
                    {
                        "name": "Ema_long",
                        "value": ema_long,
                        "inline": True
                    }
                ],
                "footer": {
                    "text": f"Time: {datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M:%S ET')}"
                }
            }
            
            # Add ORB levels based on signal type
            if signal_type == 'buy':
                embed["fields"].append({
                    "name": "Orb_high",
                    "value": orb_high,
                    "inline": True
                })
            else:
                embed["fields"].append({
                    "name": "Orb_low",
                    "value": orb_low,
                    "inline": True
                })
                
            # Add reversal field
            embed["fields"].append({
                "name": "Reversal",
                "value": reversal_text,
                "inline": True
            })
            
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