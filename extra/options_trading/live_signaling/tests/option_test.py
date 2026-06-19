import requests
import json
import os
import random
import numpy as np
import pandas as pd

# underlying_symbol 
# The symbol of the underlying asset.
# feed 
# The source feed of the data. opra or indicative. 
# Default: opra if the user has the options subscription, indicative otherwise.

# limit 

# updated_since

# page_token

# type 
# Filter contracts by the type (call or put).

# strike_price_gte 
# Filter contracts with strike price greater than or equal to the specified value.

# strike_price_lte
# Filter contracts with strike price less than or equal to the specified value.


# expiration_date
# Filter contracts by the exact expiration date (format: YYYY-MM-DD).

# expiration_date_gte 
# Filter contracts with expiration date greater than or equal to the specified value.   

# expiration_date_lte
# Filter contracts with expiration date less than or equal to the specified value.


url = "https://data.alpaca.markets/v1beta1/options/snapshots/SPY?feed=indicative&limit=100&type=call&strike_price_gte=548&strike_price_lte=552&expiration_date=2025-04-28"


headers = {
    "accept": "application/json",
    "APCA-API-KEY-ID": "AKRIA712IN9DOFZ2QWAL",
    "APCA-API-SECRET-KEY": "yH0mEPJVRNXwlodMjNh6pR2k3UV1mz4gHD35iDrq"
}

response = requests.get(url, headers=headers)

print(json.dumps(response.json(), indent=4))

def _create_mock_option_contract(self, ticker, option_type, current_price, today, force_short_expiry=False):
    """
    Create a mock option contract for testing when API doesn't return expected data
    Uses historical data when available for more realistic pricing
    
    Args:
        ticker: Symbol of the underlying asset
        option_type: 'call' or 'put'
        current_price: Current price of the underlying
        today: Today's date
        force_short_expiry: Force a short-dated expiration (for SPY/QQQ)
        
    Returns:
        Dict with mock option contract details
    """
    # Try to get the last closing price from historical data
    try:
        # Check if we have historical data in the system
        if hasattr(self, 'data_buffer') and ticker in self.data_buffer:
            # Use last close price from the data buffer
            historical_data = self.data_buffer[ticker]
            if not historical_data.empty:
                last_close = historical_data['close'].iloc[-1]
                logger.info(f"Using historical closing price for {ticker}: ${last_close:.2f}")
                current_price = last_close
        else:
            # Try to load from saved data
            try:
                data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'saved_data')
                data_file = os.path.join(data_dir, f"{ticker}_daily.csv")
                if os.path.exists(data_file):
                    historical_data = pd.read_csv(data_file, index_col=0, parse_dates=True)
                    if not historical_data.empty:
                        last_close = historical_data['close'].iloc[-1]
                        logger.info(f"Using saved historical price for {ticker}: ${last_close:.2f}")
                        current_price = last_close
            except Exception as e:
                logger.warning(f"Could not load saved data for {ticker}: {e}")
    except Exception as e:
        logger.warning(f"Error getting historical price for {ticker}: {e}")
        # Continue with the provided current_price if historical data is unavailable
    
    # For SPY and QQQ, use shorter expirations that reflect their real-world availability
    if ticker in ['SPY', 'QQQ'] or force_short_expiry:
        # These ETFs have options expiring Monday, Wednesday, Friday 
        # Find the next expiration date (next Mon, Wed, or Fri)
        today_weekday = today.weekday()  # Monday=0, Sunday=6
        
        if today_weekday < 2:  # Mon, Tue -> next Wed
            days_to_next = 2 - today_weekday
        elif today_weekday < 4:  # Wed, Thu -> next Fri
            days_to_next = 4 - today_weekday
        else:  # Fri, Sat, Sun -> next Mon
            days_to_next = 7 - today_weekday if today_weekday != 0 else 0
            
        expiry_date = today + timedelta(days=days_to_next)
    else:
        # Regular stocks typically have weekly or monthly options
        expiry_date = today + timedelta(days=14)
    
    # Round strike to appropriate precision based on price
    if current_price < 50:
        # Use $0.50 increments for lower-priced stocks
        strike = round(current_price * 2) / 2
    elif current_price < 100:
        # Use $1.00 increments for mid-priced stocks  
        strike = round(current_price)
    else:
        # Use $5.00 increments for higher-priced stocks
        strike = round(current_price / 5) * 5
    
    # Calculate a reasonable mock bid/ask spread
    if option_type == 'call':
        # For calls, value increases with underlying price
        intrinsic = max(0, current_price - strike)
    else:
        # For puts, value increases as underlying price decreases
        intrinsic = max(0, strike - current_price)
    
    # SPY and QQQ usually have tighter spreads due to higher liquidity    
    if ticker in ['SPY', 'QQQ']:
        # Add time value (very rough approximation)
        time_value = current_price * 0.01  # ~1% of underlying price for liquid ETFs
        spread_factor = 0.02  # 2% bid/ask spread
    else:
        # Add time value (very rough approximation)
        time_value = current_price * 0.02  # ~2% of underlying price
        spread_factor = 0.05  # 5% bid/ask spread for normal stocks
        
    # Generate reasonable bid/ask values
    option_value = intrinsic + time_value
    bid = max(0.01, option_value * (1 - spread_factor/2))
    ask = option_value * (1 + spread_factor/2)
    
    # Create a reasonable option symbol
    month_code = "FGHJKMNQUVXZ"[expiry_date.month - 1]
    day_str = f"{expiry_date.day:02d}"
    year_str = f"{expiry_date.year % 100:02d}"
    option_code = f"{ticker}{year_str}{month_code}{day_str}{option_type[0].upper()}{int(strike*1000):08d}"
    
    # Calculate estimated delta for ATM options
    if option_type == 'call':
        delta = 0.5 + (current_price - strike) / (current_price * 0.2)  # Rough approximation
        delta = max(0.01, min(0.99, delta))
    else:
        delta = 0.5 - (current_price - strike) / (current_price * 0.2)  # Rough approximation
        delta = max(0.01, min(0.99, delta))
    
    # Calculate implied volatility (rough estimate based on market conditions)
    # SPY and QQQ typically have lower IV
    if ticker in ['SPY', 'QQQ']:
        implied_vol = 0.15 + random.uniform(-0.03, 0.03)  # ~15% +/- 3%
    else:
        implied_vol = 0.25 + random.uniform(-0.05, 0.05)  # ~25% +/- 5%
    
    # Create mock greeks
    days_to_expiry = (expiry_date - today).days
    T = days_to_expiry / 365  # Time in years
    
    # Square root of time factor for vega and gamma
    sqrt_t = np.sqrt(T)
    
    # Mock reasonable greeks
    greeks = {
        "delta": delta,
        "gamma": 0.03 * sqrt_t,
        "theta": -option_value * 0.1 / days_to_expiry,
        "vega": option_value * 0.2 * sqrt_t,
        "rho": 0.01 * T
    }
    
    logger.warning(f"Using mock option contract for testing: {option_code}")
    
    return {
        'symbol': option_code,
        'strike': float(strike),
        'expiration': expiry_date.strftime('%Y-%m-%d'),
        'option_type': option_type.upper(),
        'days_to_expiry': (expiry_date - today).days,
        'bid': bid,
        'ask': ask,
        'mark': (bid + ask) / 2,
        'underlying_price': current_price,
        'is_mock': True,
        'greeks': greeks,
        'impliedVolatility': implied_vol
    }