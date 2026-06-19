#!/usr/bin/env python3
"""
Test script for options integration with trading signals
"""
import os
import sys
import logging
import dotenv
from datetime import datetime, timedelta
import requests
from typing import Dict, Any

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the necessary modules
from options_analyzer import OptionsAnalyzer
from simple_strategy import SimpleStrategy

# Set up logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_latest_prices(tickers, api_key, api_secret):
    """
    Get the latest prices for the given tickers.
    
    Args:
        tickers: List of ticker symbols
        api_key: Alpaca API key
        api_secret: Alpaca API secret
        
    Returns:
        Dictionary of ticker:price
    """
    try:
        # Try to get prices from Alpaca API
        from alpaca.data.historical import StockHistoricalDataClient
        from alpaca.data.requests import StockLatestQuoteRequest
        
        client = StockHistoricalDataClient(api_key, api_secret)
        request_params = StockLatestQuoteRequest(symbol_or_symbols=tickers)
        
        latest_quotes = client.get_stock_latest_quote(request_params)
        
        prices = {}
        for ticker in tickers:
            if ticker in latest_quotes:
                # Use the ask price as an approximation of current price
                prices[ticker] = latest_quotes[ticker].ask_price or latest_quotes[ticker].bid_price
            else:
                # Alternatively, try to read from saved data
                try:
                    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'saved_data')
                    data_file = os.path.join(data_dir, f"{ticker}_daily.csv")
                    if os.path.exists(data_file):
                        import pandas as pd
                        historical_data = pd.read_csv(data_file, index_col=0, parse_dates=True)
                        if not historical_data.empty:
                            last_close = historical_data['close'].iloc[-1]
                            logger.info(f"Using saved historical price for {ticker}: ${last_close:.2f}")
                            prices[ticker] = last_close
                except Exception as e:
                    logger.warning(f"Could not load saved data for {ticker}: {e}")
        
        # Log the prices we're using
        for ticker, price in prices.items():
            logger.info(f"Using price for {ticker}: ${price:.2f}")
            
        return prices
    
    except Exception as e:
        logger.error(f"Error getting latest prices: {e}")
        # Return empty dict as fallback
        return {}

def test_options_analyzer():
    """Test the options analyzer independently"""
    # Load environment variables for API keys
    dotenv.load_dotenv()
    api_key = os.getenv("ALPACA_API_KEY")
    api_secret = os.getenv("ALPACA_API_SECRET")
    
    if not api_key or not api_secret:
        logger.error("API keys not found. Please set ALPACA_API_KEY and ALPACA_API_SECRET in your .env file")
        return False
    
    # Create the options analyzer
    analyzer = OptionsAnalyzer(api_key, api_secret)
    
    # Test tickers
    test_tickers = ["AAPL", "MSFT", "SPY", "QQQ", "TSLA"]
    
    # Get latest prices for the tickers
    prices = get_latest_prices(test_tickers, api_key, api_secret)
    
    # Test both buy and sell signals
    signal_types = ["buy", "sell"]
    
    successful_tests = 0
    total_tests = len(test_tickers) * len(signal_types)
    
    print("\n" + "="*50)
    print("TESTING OPTIONS INTEGRATION")
    print("="*50)
    
    for ticker in test_tickers:
        # Use the latest market price if available, else fallback to fixed value
        current_price = prices.get(ticker, 100.0)
        
        for signal_type in signal_types:
            # Set tighter stop loss and take profit levels for testing
            if signal_type == "buy":
                stop_loss = current_price * 0.995  # 0.5% below for calls
                take_profit = current_price * 1.01  # 1% above for calls
            else:  # sell
                stop_loss = current_price * 1.005  # 0.5% above for puts
                take_profit = current_price * 0.99  # 1% below for puts
            
            print(f"\nTesting {signal_type.upper()} signal for {ticker} at ${current_price:.2f}...")
            print(f"Stop Loss: ${stop_loss:.2f}, Take Profit: ${take_profit:.2f}")
            
            # Get the ATM option
            option_data = analyzer.get_atm_option(ticker, signal_type, current_price)
            
            if not option_data:
                print(f"❌ No option data available for {ticker}")
                continue
                
            # Check if this is mock data
            if option_data.get('is_mock', False):
                print(f"⚠️ Using mock option data for {ticker}")
            
            # Print option details
            print(f"✅ Found ATM option: {option_data['symbol']}")
            print(f"  Strike: ${option_data['strike']:.2f}")
            print(f"  Type: {option_data['option_type']}")
            print(f"  Expiration: {option_data['expiration']} ({option_data['days_to_expiry']} days)")
            print(f"  Current Bid/Ask: ${option_data['bid']:.2f} / ${option_data['ask']:.2f}")
            
            # Estimate option prices
            estimates = analyzer.estimate_option_prices(option_data, stop_loss, take_profit)
            
            if not estimates:
                print(f"❌ Could not estimate option prices for {ticker}")
                continue
            
            # Print price estimates
            print(f"  Estimated Entry: ${estimates['entry']:.2f}")
            print(f"  Estimated Stop Loss: ${estimates['stop_loss']:.2f}")
            print(f"  Estimated Take Profit: ${estimates['take_profit']:.2f}")
            print(f"  Estimated Delta: {estimates['estimated_delta']:.2f}")
            
            # Calculate potential returns
            entry = estimates['entry']
            sl = estimates['stop_loss']
            tp = estimates['take_profit']
            
            risk_pct = abs(entry - sl) / entry * 100
            reward_pct = abs(tp - entry) / entry * 100
            rr_ratio = reward_pct / risk_pct if risk_pct > 0 else 0
            
            print(f"  Risk/Reward Analysis:")
            print(f"    Max Risk: {risk_pct:.1f}%")
            print(f"    Max Reward: {reward_pct:.1f}%")
            print(f"    R/R Ratio: {rr_ratio:.2f}")
            
            successful_tests += 1
    
    # Print summary
    print("\n" + "="*50)
    print(f"Tests completed: {successful_tests}/{total_tests} successful")
    print("="*50)
    
    return successful_tests > 0

def test_discord_integration():
    """Test sending a signal with options data to Discord"""
    # Load environment variables for API keys and Discord webhook
    dotenv.load_dotenv()
    api_key = os.getenv("ALPACA_API_KEY")
    api_secret = os.getenv("ALPACA_API_SECRET")
    discord_webhook = os.getenv("DISCORD_WEBHOOK_URL")
    
    if not api_key or not api_secret:
        logger.error("API keys not found. Please set ALPACA_API_KEY and ALPACA_API_SECRET in your .env file")
        return False
        
    if not discord_webhook:
        logger.error("Discord webhook URL not found. Please set DISCORD_WEBHOOK_URL in your .env file")
        return False
    
    # Import the SignalGenerator here to avoid circular imports
    from signal_generator import SignalGenerator
    
    # Create SignalGenerator and add a strategy
    signal_gen = SignalGenerator(api_key, api_secret)
    strategy = SimpleStrategy()
    signal_gen.add_strategy(strategy)
    
    # Test ticker
    ticker = "AAPL"
    
    # Create a sample signal for testing
    test_signal = {
        'signal': 'buy',
        'entry_price': 190.50,
        'stop_loss': 185.25,
        'profit_target': 200.75,
        'rsi': 62.3,
        'vwap': 189.85
    }
    
    # Send the signal to Discord
    print("\n" + "="*50)
    print("TESTING DISCORD INTEGRATION WITH OPTIONS DATA")
    print("="*50)
    print(f"Sending test {test_signal['signal'].upper()} signal for {ticker}...")
    
    result = signal_gen.send_to_discord("OptionsTest", ticker, test_signal)
    
    if result:
        print(f"✅ Successfully sent signal with options data to Discord")
    else:
        print(f"❌ Failed to send signal to Discord")
    
    return result

if __name__ == "__main__":
    # Run the tests
    analyzer_test = test_options_analyzer()
    
    # Only run Discord test if the analyzer test passed
    if analyzer_test:
        discord_test = test_discord_integration()
    else:
        print("\nSkipping Discord integration test due to failed analyzer test")
        discord_test = False
    
    # Print overall result
    if analyzer_test and discord_test:
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Some tests failed. Please check the logs for details.") 