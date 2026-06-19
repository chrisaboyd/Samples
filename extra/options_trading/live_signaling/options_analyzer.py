from datetime import datetime, timedelta
import logging
import pandas as pd
import numpy as np
import requests
import random
import os
from typing import Dict, Any, List, Optional, Tuple
from alpaca.data.historical import StockHistoricalDataClient
from alpaca.data.requests import StockBarsRequest
from alpaca.data.timeframe import TimeFrame
from scipy.stats import norm

# Updated imports for options data
from alpaca.data import OptionHistoricalDataClient
from alpaca.data.requests import OptionChainRequest, OptionSnapshotRequest

logger = logging.getLogger(__name__)

class OptionsAnalyzer:
    """
    Utility class to analyze options data for trading signals.
    
    This class leverages Alpaca's Options API to:
    1. Retrieve options chains
    2. Find ATM contracts
    3. Calculate option prices at different underlying price levels
    """
    
    def __init__(self, api_key: str, api_secret: str):
        """
        Initialize the OptionsAnalyzer with API credentials
        
        Args:
            api_key: Alpaca API key
            api_secret: Alpaca API secret
        """
        self.api_key = api_key
        self.api_secret = api_secret
        self.stock_client = StockHistoricalDataClient(api_key, api_secret)
        self.options_client = OptionHistoricalDataClient(api_key, api_secret)
        
    def get_atm_option(self, ticker: str, signal_type: str, current_price: float) -> Dict[str, Any]:
        """
        Get the At-The-Money option contract for a given signal using direct REST API
        
        Args:
            ticker: Symbol of the underlying asset
            signal_type: 'buy' for calls, 'sell' for puts
            current_price: Current price of the underlying
            
        Returns:
            Dict containing option contract details or empty dict if no suitable contract found
        """
        try:
            # Determine option type based on signal
            option_type = 'call' if signal_type == 'buy' else 'put'
            
            # Get the nearest expiration date
            today = datetime.now().date()
            
            # Special handling for SPY and QQQ which have more frequent expirations
            if ticker in ['SPY', 'QQQ']:
                # For these ETFs, we can look for shorter-dated options (1-7 days)
                expiration_after = today + timedelta(days=1)
                expiration_before = today + timedelta(days=7)
                logger.info(f"Using shorter expiration window for {ticker}: {expiration_after} to {expiration_before}")
            else:
                # Standard window for most stocks (7-30 days)
                expiration_after = today + timedelta(days=7)
                expiration_before = today + timedelta(days=30)
            
            # Calculate strike price range (10% around current price)
            strike_min = current_price * 0.9
            strike_max = current_price * 1.1
            
            # Build the URL for direct API request
            url = f"https://data.alpaca.markets/v1beta1/options/snapshots/{ticker}?feed=indicative&limit=100"
            url += f"&type={option_type}"
            url += f"&strike_price_gte={strike_min:.2f}&strike_price_lte={strike_max:.2f}"
            url += f"&expiration_date_gte={expiration_after.strftime('%Y-%m-%d')}"
            url += f"&expiration_date_lte={expiration_before.strftime('%Y-%m-%d')}"
            
            headers = {
                "accept": "application/json",
                "APCA-API-KEY-ID": self.api_key,
                "APCA-API-SECRET-KEY": self.api_secret
            }
            
            # Log the exact URL being requested (without API keys)
            logger.info(f"API Request URL: {url}")
            
            response = requests.get(url, headers=headers)
            
            # Log response status and content preview
            if response.status_code == 200:
                try:
                    content = response.json()
                    logger.info(f"API Response: Status {response.status_code}")
                    
                    # Debug log the full response structure, safely handle various response types
                    if isinstance(content, dict):
                        logger.info(f"Response content keys: {list(content.keys())}")
                        
                        # Handle the response format with 'next_page_token' and 'snapshots'
                        if 'snapshots' in content:
                            # Extract the snapshots which contains the option data
                            chain_response = content['snapshots']
                            logger.info(f"Found {len(chain_response)} option contracts in snapshots")
                            
                            # Log a sample of the first item if available
                            if chain_response and len(chain_response) > 0:
                                try:
                                    sample_key = next(iter(chain_response))
                                    sample_item = chain_response[sample_key]
                                    logger.info(f"Sample option symbol: {sample_key}")
                                    
                                    # Log available data in the sample item
                                    if isinstance(sample_item, dict):
                                        data_keys = list(sample_item.keys())
                                        logger.info(f"Sample option data keys: {data_keys}")
                                        
                                        if 'latestQuote' in sample_item:
                                            quote = sample_item['latestQuote']
                                            logger.info(f"Quote data: bid={quote.get('bp', 'N/A')}, ask={quote.get('ap', 'N/A')}")
                                        if 'latestTrade' in sample_item:
                                            trade = sample_item['latestTrade']
                                            logger.info(f"Last trade: price={trade.get('p', 'N/A')}, time={trade.get('t', 'N/A')}")
                                        if 'greeks' in sample_item:
                                            logger.info(f"Greeks available: {list(sample_item['greeks'].keys()) if isinstance(sample_item['greeks'], dict) else 'Not dict'}")
                                        if 'impliedVolatility' in sample_item:
                                            logger.info(f"Implied Volatility: {sample_item['impliedVolatility']}")
                                except Exception as e:
                                    logger.warning(f"Error examining sample option data: {e}")
                        else:
                            # When the API response doesn't have 'snapshots' but is a direct dictionary with option symbols
                            logger.warning(f"No 'snapshots' key in API response")
                            
                            # Check if the response has option symbols directly as keys
                            # Format check: look for keys that match the pattern of option symbols (e.g., AAPL250516C00100000)
                            option_symbol_format = False
                            for key in list(content.keys())[:5]:  # Check first few keys
                                if isinstance(key, str) and len(key) > 15 and any(ticker in key for ticker in [ticker, 'SPY', 'QQQ', 'AAPL']):
                                    option_symbol_format = True
                                    break
                            
                            if option_symbol_format:
                                logger.info(f"Using direct dictionary format with {len(content)} option symbols")
                                chain_response = content  # Use the response directly
                            else:
                                logger.warning(f"Response format not recognized: {list(content.keys())[:10]}")
                                chain_response = {}
                    elif isinstance(content, list):
                        logger.info(f"Response is a list with {len(content)} items")
                        # Handle list response (unlikely but possible)
                        chain_response = {}
                    else:
                        logger.warning(f"Unexpected response type: {type(content)}")
                        chain_response = {}
                except Exception as e:
                    logger.error(f"Error parsing API response JSON: {e}")
                    logger.debug(f"Response content preview: {response.text[:500]}...")
                    chain_response = {}
            else:
                logger.warning(f"API Response: Status {response.status_code}, Content: {response.text[:200]}...")
                chain_response = {}
                
            # If no valid chain_response, return mock data
            if not chain_response or not isinstance(chain_response, dict) or len(chain_response) == 0:
                logger.warning(f"Using mock option data for {ticker} due to empty/invalid API response")
                return self._create_mock_option_contract(ticker, option_type, current_price, today, 
                                                       force_short_expiry=(ticker in ['SPY', 'QQQ']))
            
            # Parse the response - already have chain_response containing the snapshots
            if not chain_response or len(chain_response) == 0:
                logger.warning(f"No option chain available for {ticker}")
                return self._create_mock_option_contract(ticker, option_type, current_price, today, 
                                                     force_short_expiry=(ticker in ['SPY', 'QQQ']))
            
            # Extract and organize the options
            contracts = []
            for symbol, data in chain_response.items():
                try:
                    # Parse symbol to extract info (format: SPY250428C00560000)
                    symbol_parts = symbol.replace(ticker, '')
                    
                    # First 6 characters after ticker are the date: YYMMDD
                    date_str = symbol_parts[:6]
                    year = int('20' + date_str[:2])
                    month = int(date_str[2:4])
                    day = int(date_str[4:6])
                    expiration_date = datetime(year, month, day).date()
                    
                    # Option type is the next character
                    symbol_option_type = symbol_parts[6].upper()
                    
                    # Strike price is the rest (divided by 1000 to get actual price)
                    strike_str = symbol_parts[7:]
                    strike_price = float(int(strike_str)) / 1000.0
                    
                    # Get quote details - properly extract bid/ask from latestQuote
                    bid = 0.0
                    ask = 0.0
                    last_price = 0.0
                    
                    if 'latestQuote' in data:
                        quote = data['latestQuote']
                        bid = quote.get('bp', 0.0) or 0.0
                        ask = quote.get('ap', 0.0) or 0.0
                    
                    # Get last trade price if available
                    if 'latestTrade' in data:
                        trade = data['latestTrade']
                        last_price = trade.get('p', 0.0) or 0.0
                    
                    # Calculate mark price
                    if bid > 0 and ask > 0:
                        mark_price = (bid + ask) / 2
                    elif last_price > 0:
                        mark_price = last_price
                    else:
                        mark_price = 0.01  # Minimum default value
                    
                    # Get greeks and implied volatility
                    greeks = data.get('greeks', {})
                    iv = data.get('impliedVolatility', 0.0)
                    
                    # Create contract object with all available data
                    contract = {
                        'symbol': symbol,
                        'strike': strike_price,
                        'expiration': expiration_date.strftime('%Y-%m-%d'),
                        'option_type': option_type.upper(),
                        'days_to_expiry': (expiration_date - today).days,
                        'bid': bid,
                        'ask': ask,
                        'last_price': last_price,
                        'mark': mark_price,
                        'underlying_price': current_price,
                        'expiration_date': expiration_date,  # Used for sorting
                        'greeks': greeks,
                        'impliedVolatility': iv,
                        'is_mock': False
                    }
                    
                    contracts.append(contract)
                except Exception as e:
                    logger.warning(f"Error parsing option symbol {symbol}: {e}")
                    continue
            
            if not contracts:
                logger.warning(f"No valid contracts found for {ticker}")
                return self._create_mock_option_contract(ticker, option_type, current_price, today, 
                                                      force_short_expiry=(ticker in ['SPY', 'QQQ']))
            
            # Sort by expiration date (ascending)
            contracts.sort(key=lambda x: x['expiration_date'])
            
            # Find options with the nearest expiration date
            nearest_exp = contracts[0]['expiration_date']
            nearest_contracts = [c for c in contracts if c['expiration_date'] == nearest_exp]
            
            # Now find the strike price closest to the current price
            nearest_contracts.sort(key=lambda x: abs(x['strike'] - current_price))
            
            # Get the ATM contract
            atm_contract = nearest_contracts[0]
            
            # Remove the temporary key used for sorting
            del atm_contract['expiration_date']
            
            # Log the selected contract details
            logger.info(f"Selected ATM {option_type} for {ticker}: {atm_contract['symbol']}")
            logger.info(f"Strike: ${atm_contract['strike']:.2f}, Expiration: {atm_contract['expiration']}")
            logger.info(f"Bid: ${atm_contract['bid']:.2f}, Ask: ${atm_contract['ask']:.2f}, Mark: ${atm_contract['mark']:.2f}")
            
            return atm_contract
        
        except Exception as e:
            logger.error(f"Error retrieving ATM option for {ticker}: {e}", exc_info=True)
            return self._create_mock_option_contract(ticker, option_type, current_price, today, 
                                                  force_short_expiry=(ticker in ['SPY', 'QQQ']))
    
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
            # Try to load from saved data
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
            "theta": -option_value * 0.1 / days_to_expiry if days_to_expiry > 0 else -0.1,
            "vega": option_value * 0.2 * sqrt_t,
            "rho": 0.01 * T
        }
        
        logger.warning(f"Using mock option contract for testing: {option_code}")
        
        return {
            'symbol': option_code,
            'strike': float(strike),
            'expiration': expiry_date.strftime('%Y-%m-%d'),
            'option_type': option_type.upper(),
            'days_to_expiry': days_to_expiry,
            'bid': bid,
            'ask': ask,
            'last_price': (bid + ask) / 2,  # Use midpoint as last price
            'mark': (bid + ask) / 2,
            'underlying_price': current_price,
            'is_mock': True,
            'greeks': greeks,
            'impliedVolatility': implied_vol
        }
        
    def _bs_call(self, S, K, T, r, sigma, q=0):
        """Black-Scholes formula for call option price"""
        d1 = (np.log(S/K) + (r - q + sigma**2/2)*T) / (sigma*np.sqrt(T))
        d2 = d1 - sigma * np.sqrt(T)
        return S * np.exp(-q*T) * norm.cdf(d1) - K * np.exp(-r*T) * norm.cdf(d2)
    
    def _bs_put(self, S, K, T, r, sigma, q=0):
        """Black-Scholes formula for put option price"""
        d1 = (np.log(S/K) + (r - q + sigma**2/2)*T) / (sigma*np.sqrt(T))
        d2 = d1 - sigma * np.sqrt(T)
        return K * np.exp(-r*T) * norm.cdf(-d2) - S * np.exp(-q*T) * norm.cdf(-d1)

    def estimate_option_prices(self, option_data: Dict[str, Any], 
                              stop_loss_price: float, 
                              take_profit_price: float) -> Dict[str, Any]:
        """
        Estimate option prices at stop loss and take profit levels using Black-Scholes
        or delta approximation based on available data
        """
        try:
            if not option_data:
                return {}
                
            # Get current data
            current_price = option_data['underlying_price']
            strike = option_data['strike']
            option_type = option_data['option_type'].lower()
            days_to_expiry = option_data.get('days_to_expiry', 14)
            T = days_to_expiry / 365  # Time in years
            
            # Get mark price - ensure we have a valid non-zero price
            mark_price = option_data.get('mark', 0.0)
            
            # Check if mark price is realistic
            if mark_price < 0.01:
                # Check if we have a last trade price
                last_price = option_data.get('last_price', 0.0)
                if last_price > 0:
                    mark_price = last_price
                    logger.info(f"Using last trade price as mark: ${mark_price:.2f}")
                else:
                    # Check bid/ask
                    bid = option_data.get('bid', 0.0)
                    ask = option_data.get('ask', 0.0)
                    if bid > 0 and ask > 0:
                        mark_price = (bid + ask) / 2
                        logger.info(f"Using bid/ask midpoint as mark: ${mark_price:.2f}")
                    else:
                        # Generate a reasonable placeholder price
                        if option_type == 'call':
                            intrinsic = max(0, current_price - strike)
                        else:
                            intrinsic = max(0, strike - current_price)
                            
                        # Add time value based on days to expiry
                        time_factor = min(1.0, days_to_expiry / 30)  # Scale by days (max 1.0)
                        time_value = current_price * 0.01 * time_factor  # ~1% of price per month
                        mark_price = max(0.1, intrinsic + time_value)  # Ensure minimum price
                        logger.warning(f"Generated estimated mark price: ${mark_price:.2f}")
            
            # Check for greeks from API
            has_greeks = 'greeks' in option_data and isinstance(option_data['greeks'], dict)
            has_iv = 'impliedVolatility' in option_data and option_data['impliedVolatility'] > 0
            
            # Log what data we're working with
            logger.info(f"Price estimation for {option_data['symbol']}: "
                       f"mark=${mark_price:.2f}, has_greeks={has_greeks}, has_iv={has_iv}")
            
            # Method 1: Full Black-Scholes with IV (if available)
            if has_iv:
                sigma = option_data['impliedVolatility']
                r = 0.05  # Assume 5% risk-free rate
                
                # Use Black-Scholes to compute new prices
                if option_type == 'call':
                    sl_price = self._bs_call(stop_loss_price, strike, T, r, sigma)
                    tp_price = self._bs_call(take_profit_price, strike, T, r, sigma)
                else:
                    sl_price = self._bs_put(stop_loss_price, strike, T, r, sigma)
                    tp_price = self._bs_put(take_profit_price, strike, T, r, sigma)
                    
                logger.info(f"Black-Scholes estimates: SL=${sl_price:.2f}, TP=${tp_price:.2f}")
                return {
                    'entry': mark_price,
                    'stop_loss': max(0.01, sl_price),
                    'take_profit': max(0.01, tp_price),
                    'estimated_delta': option_data['greeks'].get('delta', 0.5) if has_greeks else 0.5
                }
                
            # Method 2: Delta approximation if greeks available
            if has_greeks and 'delta' in option_data['greeks']:
                delta = option_data['greeks']['delta']
                # Ensure put delta is negative
                if option_type == 'put' and delta > 0:
                    delta = -delta
                    
                # Calculate price differences
                if option_type == 'call':
                    sl_price_diff = stop_loss_price - current_price
                    tp_price_diff = take_profit_price - current_price
                else:
                    sl_price_diff = current_price - stop_loss_price
                    tp_price_diff = current_price - take_profit_price
                    
                # For very short-dated options, increase delta effect
                if days_to_expiry <= 3:
                    delta_multiplier = 2.0  # Increase effect for ultra-short expiry options
                elif days_to_expiry <= 7:
                    delta_multiplier = 1.5  # Increase effect for near-expiry options
                else:
                    delta_multiplier = 1.0
                    
                # Add gamma effect for more accuracy on larger price moves
                if 'gamma' in option_data['greeks']:
                    gamma = option_data['greeks']['gamma']
                    # Second-order approximation using gamma
                    sl_gamma_effect = 0.5 * gamma * sl_price_diff * sl_price_diff
                    tp_gamma_effect = 0.5 * gamma * tp_price_diff * tp_price_diff
                    
                    sl_option_price = max(0.01, mark_price + (sl_price_diff * delta * delta_multiplier) + sl_gamma_effect)
                    tp_option_price = max(0.01, mark_price + (tp_price_diff * delta * delta_multiplier) + tp_gamma_effect)
                else:
                    # First-order approximation with delta only
                    sl_option_price = max(0.01, mark_price + (sl_price_diff * delta * delta_multiplier))
                    tp_option_price = max(0.01, mark_price + (tp_price_diff * delta * delta_multiplier))
                
                logger.info(f"Delta approximation: SL=${sl_option_price:.2f}, TP=${tp_option_price:.2f}")
                return {
                    'entry': mark_price,
                    'stop_loss': sl_option_price,
                    'take_profit': tp_option_price,
                    'estimated_delta': delta
                }
                
            # Method 3: Basic approximation if no greeks or IV available
            # Estimate a reasonable delta based on moneyness
            moneyness = current_price / strike
            if option_type == 'call':
                delta_base = 0.5
                delta_adj = (moneyness - 1.0) * 2.0  # Increase delta if ITM, decrease if OTM
            else:
                delta_base = -0.5
                delta_adj = -(1.0 - moneyness) * 2.0  # More negative delta if ITM
                
            # Estimate delta (bounded between 0.1 and 0.9 for calls, -0.1 and -0.9 for puts)
            if option_type == 'call':
                delta = min(0.9, max(0.1, delta_base + delta_adj))
            else:
                delta = max(-0.9, min(-0.1, delta_base + delta_adj))
            
            # Calculate price differences
            if option_type == 'call':
                sl_price_diff = stop_loss_price - current_price
                tp_price_diff = take_profit_price - current_price
            else:
                sl_price_diff = current_price - stop_loss_price
                tp_price_diff = current_price - take_profit_price
                
            # Apply delta multiplier based on days to expiry
            if days_to_expiry <= 3:
                delta_multiplier = 2.5  # Much more sensitive for ultra-short-term options
            elif days_to_expiry <= 7:
                delta_multiplier = 2.0  # More sensitive for short-term options
            elif days_to_expiry <= 14:
                delta_multiplier = 1.5
            else:
                delta_multiplier = 1.0
                
            sl_option_price = max(0.01, mark_price + (sl_price_diff * delta * delta_multiplier))
            tp_option_price = max(0.01, mark_price + (tp_price_diff * delta * delta_multiplier))
            
            logger.info(f"Basic approximation: SL=${sl_option_price:.2f}, TP=${tp_option_price:.2f}")
            return {
                'entry': mark_price,
                'stop_loss': sl_option_price,
                'take_profit': tp_option_price,
                'estimated_delta': delta
            }
                
        except Exception as e:
            logger.error(f"Error estimating option prices: {e}", exc_info=True)
            return {} 