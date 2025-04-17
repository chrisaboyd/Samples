from alpaca.data.live import StockDataStream
from alpaca.trading.client import TradingClient
import pandas as pd
import logging
from typing import List
from strategies.base_strategy import LiveStrategy

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SignalGenerator:
    def __init__(self, api_key: str, api_secret: str):
        self.api_key = api_key
        self.api_secret = api_secret
        self.trading_client = TradingClient(api_key, api_secret)
        self.stream = StockDataStream(api_key, api_secret)
        self.strategies: List[LiveStrategy] = []
        
    def add_strategy(self, strategy: LiveStrategy):
        """Add a trading strategy to the generator"""
        self.strategies.append(strategy)
        
    async def process_bar(self, bar):
        """Process incoming bar data"""
        try:
            ticker = bar.symbol
            
            # Create DataFrame from bar data
            new_data = pd.DataFrame({
                'open': [bar.open],
                'high': [bar.high],
                'low': [bar.low],
                'close': [bar.close],
                'volume': [bar.volume]
            }, index=[pd.Timestamp(bar.timestamp)])
            
            # Update each strategy's data buffer
            for strategy in self.strategies:
                strategy.update_data(ticker, new_data)
                signals = strategy.generate_signal(ticker, strategy.data_buffer[ticker])
                
                if signals['signal'] is not None:
                    logger.info(f"Strategy: {strategy.name}, Ticker: {ticker}")
                    logger.info(f"Signal: {signals}")
        
        except Exception as e:
            logger.error(f"Error processing bar: {e}")
            
    async def start_streaming(self, symbols: List[str]):
        """Start the data stream"""
        try:
            # Subscribe to minute bars
            self.stream.subscribe_bars(self.process_bar, *symbols)
            
            # Start streaming
            await self.stream._run_forever()
            
        except Exception as e:
            logger.error(f"Error in stream: {e}")
            raise 