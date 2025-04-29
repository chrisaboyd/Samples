import os
import asyncio
from signal_generator import SignalGenerator
from strategies.orb_strategy import LiveORBStrategy
from strategies.scalping_strategy import LiveORB_EMA_Strategy
from strategies.bollinger_band_reversal import BollingerBandReversal
from strategies.bollinger_band_breakout import BollingerBandBreakout
import logging
from datetime import datetime, timedelta
import pytz
import dotenv
import pandas as pd
from alpaca.data import StockHistoricalDataClient
from alpaca.data.requests import StockBarsRequest
from alpaca.data.timeframe import TimeFrame
import pickle

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

def fetch_daily_data(api_key: str, api_secret: str, symbols: list) -> dict:
    """
    Fetch last 30 days of daily bars for each symbol
    
    Args:
        api_key: Alpaca API key
        api_secret: Alpaca API secret
        symbols: List of symbols to fetch data for
        
    Returns:
        Dictionary of daily bars by symbol
    """
    logger.info("\nFetching historical daily data...")
    
    # Initialize client
    client = StockHistoricalDataClient(api_key, api_secret)
    
    # Calculate date range (last 30 trading days)
    end = datetime.now(pytz.timezone('US/Eastern'))
    start = end - timedelta(days=45)  # Get 45 calendar days to ensure we have 30 trading days
    
    # Create request
    request = StockBarsRequest(
        symbol_or_symbols=symbols,
        timeframe=TimeFrame.Day,
        start=start,
        end=end,
        feed="iex"  # Use IEX feed for free tier
    )
    
    try:
        # Get the data
        bars = client.get_stock_bars(request)
        
        # Convert to dictionary format
        daily_data = {}
        for symbol in symbols:
            if symbol in bars:
                symbol_bars = bars[symbol]
                daily_data[symbol] = {
                    'open': {},
                    'high': {},
                    'low': {},
                    'close': {},
                    'volume': {}
                }
                
                for bar in symbol_bars:
                    daily_data[symbol]['open'][bar.timestamp] = bar.open
                    daily_data[symbol]['high'][bar.timestamp] = bar.high
                    daily_data[symbol]['low'][bar.timestamp] = bar.low
                    daily_data[symbol]['close'][bar.timestamp] = bar.close
                    daily_data[symbol]['volume'][bar.timestamp] = bar.volume
                
                logger.info(f"Fetched {len(symbol_bars)} daily bars for {symbol}")
        
        # Save to file
        os.makedirs('saved_data', exist_ok=True)
        save_path = os.path.join('saved_data', 'daily_bars.pkl')
        with open(save_path, 'wb') as f:
            pickle.dump(daily_data, f)
        logger.info(f"Saved daily bars to {save_path}")
        
        return daily_data
        
    except Exception as e:
        logger.error(f"Error fetching daily data: {e}")
        return {}

async def main():
    # Get API credentials
    dotenv.load_dotenv()
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
    generator.add_strategy(BollingerBandReversal())
    generator.add_strategy(BollingerBandBreakout())

    # Define symbols to track
    symbols = [ "SPY", "QQQ", "ASTS", "TSLA", "NVDA", "PLTR", "NFLX", "MSTR", "ISRG", "AAPL" ]
    
    try:
        logger.info("\nInitializing signal generator...")
        logger.info(f"Tracking symbols: {symbols}")
        logger.info("Press Ctrl+C to stop the stream")
        
        # Fetch and save daily data first
        daily_data = fetch_daily_data(api_key, api_secret, symbols)
        if not daily_data:
            logger.error("Failed to fetch daily data. Check your API credentials and internet connection.")
            return
            
        # Now populate intraday history and start streaming
        generator.populate_intraday_history(symbols)
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