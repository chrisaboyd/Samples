import os
import asyncio
from signal_generator import SignalGenerator
from strategies.orb_strategy import LiveORBStrategy
from strategies.scalping_strategy import LiveORB_EMA_Strategy
import logging
from datetime import datetime
import pytz

logger = logging.getLogger(__name__)

def is_market_hours():
    """Check if we're in market hours"""
    et_tz = pytz.timezone('US/Eastern')
    now = datetime.now(et_tz)
    
    # Check if it's a weekday
    if now.weekday() >= 5:  # 5 = Saturday, 6 = Sunday
        return False
    
    # Check if it's between 9:30 AM and 4:00 PM ET
    market_open = now.replace(hour=9, minute=30, second=0, microsecond=0)
    market_close = now.replace(hour=16, minute=0, second=0, microsecond=0)
    
    return market_open <= now <= market_close

async def main():
    # Get API credentials
    api_key = os.getenv("ALPACA_API_KEY")
    api_secret = os.getenv("ALPACA_API_SECRET")
    
    if not api_key or not api_secret:
        raise ValueError("Please set ALPACA_API_KEY and ALPACA_API_SECRET environment variables")
    
    # Market hours check
    if not is_market_hours():
        logger.warning("\nWarning: Market is currently closed!")
        logger.warning("You may not receive real-time data until market opens.")
    
    # Create signal generator
    generator = SignalGenerator(api_key, api_secret)
    
    # Add strategies
    generator.add_strategy(LiveORBStrategy())
    generator.add_strategy(LiveORB_EMA_Strategy())
    
    # Define symbols to track
    symbols = [ "SPY", "QQQ", "ASTS", "TSLA", "NVDA", "PLTR", "NFLX", "MSTR", "ISRG", "AAPL" ]
    
    try:
        logger.info("\nInitializing signal generator...")
        logger.info(f"Tracking symbols: {symbols}")
        logger.info("Press Ctrl+C to stop the stream")
        
        await generator.start_streaming(symbols)
    except KeyboardInterrupt:
        logger.info("\nShutting down gracefully...")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(main())
    finally:
        loop.close()