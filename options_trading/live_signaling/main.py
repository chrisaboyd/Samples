import os
import asyncio
from signal_generator import SignalGenerator
from strategies.orb_strategy import LiveORBStrategy
from strategies.scalping_strategy import LiveScalpingStrategy
import logging

logger = logging.getLogger(__name__)

async def main():
    # Get API credentials
    api_key = os.getenv("ALPACA_API_KEY")
    api_secret = os.getenv("ALPACA_API_SECRET")
    
    if not api_key or not api_secret:
        raise ValueError("Please set ALPACA_API_KEY and ALPACA_API_SECRET environment variables")
    
    # Create signal generator
    generator = SignalGenerator(api_key, api_secret)
    
    # Add strategies
    generator.add_strategy(LiveORBStrategy())
    generator.add_strategy(LiveScalpingStrategy())
    
    # Define symbols to track
    symbols = ["SPY", "QQQ"]
    
    try:
        await generator.start_streaming(symbols)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(main())
    finally:
        loop.close()