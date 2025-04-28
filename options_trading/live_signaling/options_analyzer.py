from datetime import datetime, timedelta
import logging
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from alpaca.data.historical import StockHistoricalDataClient
from alpaca.data.requests import StockBarsRequest
from alpaca.data.timeframe import TimeFrame

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
        self.stock_client = StockHistoricalDataClient(api_key, api_secret)
        self.options_client = OptionHistoricalDataClient(api_key, api_secret)
        
    def get_atm_option(self, ticker: str, signal_type: str, current_price: float) -> Dict[str, Any]:
        """
        Get the At-The-Money option contract for a given signal
        
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
            
            # Get option chain with updated parameter names
            request_params = OptionChainRequest(
                underlying_symbol=ticker,
                expiration_date_gte=expiration_after,
                expiration_date_lte=expiration_before,
                strike_price_gte=current_price * 0.9,
                strike_price_lte=current_price * 1.1,
                option_type=option_type,
                feed='indicative'  # Use the indicative feed which doesn't require OPRA agreement
            )
            
            # Use options_client for option chain
            chain_response = self.options_client.get_option_chain(request_params)
            
            # If no options returned, return empty dict
            if not chain_response:
                logger.warning(f"No option chain available for {ticker}")
                # For ETFs with known frequent options, try a mock with shorter expiry
                if ticker in ['SPY', 'QQQ']:
                    return self._create_mock_option_contract(ticker, option_type, current_price, today, force_short_expiry=True)
                return {}

            # Parse the response based on its structure
            logger.info(f"Chain response type: {type(chain_response)}")
            
            # More detailed logging to debug response structure
            if isinstance(chain_response, dict):
                # Check if response has 'snapshots' key (newer API format)
                if 'snapshots' in chain_response:
                    logger.info(f"Using 'snapshots' format with {len(chain_response['snapshots'])} contracts")
                    option_data = chain_response['snapshots']
                    # Log a sample symbol if available
                    if option_data:
                        sample_key = next(iter(option_data.keys()))
                        logger.info(f"Sample symbol: {sample_key}")
                else:
                    # Direct dictionary with symbols as keys (older API format)
                    logger.info(f"Using direct dictionary format with {len(chain_response)} option symbols")
                    option_data = chain_response
                    
                if not option_data:
                    logger.warning(f"Empty option data for {ticker}")
                    if ticker in ['SPY', 'QQQ']:
                        return self._create_mock_option_contract(ticker, option_type, current_price, today, force_short_expiry=True)
                    return self._create_mock_option_contract(ticker, option_type, current_price, today)
                
                # Extract and organize the options
                contracts = []
                for symbol, data in option_data.items():
                    try:
                        # Only process symbols for the underlying ticker
                        if ticker not in symbol:
                            continue
                            
                        # Parse symbol to extract info (format: SPY250428C00560000)
                        # Ticker + YY + MM + DD + C/P + Strike price (multiplied by 1000)
                        
                        # Get the call/put indicator
                        option_char = 'C' if option_type.lower() == 'call' else 'P'
                        
                        # Skip if it's not the option type we're looking for
                        if option_char not in symbol:
                            continue
                            
                        # Extract expiration date and strike price from the symbol
                        # Format example: SPY250428C00560000
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
                        
                        # Skip if not the right option type
                        if symbol_option_type != option_char:
                            continue
                            
                        # Get quote details from data if available
                        bid = 0.0
                        ask = 0.0
                        
                        # Handle different data structures
                        if isinstance(data, dict):
                            if 'latestQuote' in data:
                                bid = data['latestQuote'].get('bp', 0.0) or 0.0
                                ask = data['latestQuote'].get('ap', 0.0) or 0.0
                            # Some API responses might have these fields directly
                            elif 'bid' in data:
                                bid = data.get('bid', 0.0) or 0.0
                                ask = data.get('ask', 0.0) or 0.0
                        
                        # Create contract object
                        contract = {
                            'symbol': symbol,
                            'strike': strike_price,
                            'expiration': expiration_date.strftime('%Y-%m-%d'),
                            'option_type': option_type.upper(),
                            'days_to_expiry': (expiration_date - today).days,
                            'bid': bid,
                            'ask': ask,
                            'mark': (bid + ask) / 2 if (bid > 0 and ask > 0) else 1.0,
                            'underlying_price': current_price,
                            'expiration_date': expiration_date  # Used for sorting
                        }
                        
                        contracts.append(contract)
                    except Exception as e:
                        logger.warning(f"Error parsing option symbol {symbol}: {e}")
                        continue
                
                if not contracts:
                    logger.warning(f"No valid contracts found for {ticker}")
                    if ticker in ['SPY', 'QQQ']:
                        return self._create_mock_option_contract(ticker, option_type, current_price, today, force_short_expiry=True)
                    return self._create_mock_option_contract(ticker, option_type, current_price, today)
                
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
                
                return atm_contract
            else:
                # If response structure is not as expected, use mock data
                logger.warning(f"Unexpected chain response format: {type(chain_response)}")
                if ticker in ['SPY', 'QQQ']:
                    return self._create_mock_option_contract(ticker, option_type, current_price, today, force_short_expiry=True)
                return self._create_mock_option_contract(ticker, option_type, current_price, today)
                
        except Exception as e:
            logger.error(f"Error retrieving ATM option for {ticker}: {e}", exc_info=True)
            # For testing, create a mock option contract
            if ticker in ['SPY', 'QQQ']:
                return self._create_mock_option_contract(ticker, option_type, current_price, today, force_short_expiry=True)
            return self._create_mock_option_contract(ticker, option_type, current_price, today)
    
    def _create_mock_option_contract(self, ticker, option_type, current_price, today, force_short_expiry=False):
        """
        Create a mock option contract for testing when API doesn't return expected data
        
        Args:
            ticker: Symbol of the underlying asset
            option_type: 'call' or 'put'
            current_price: Current price of the underlying
            today: Today's date
            force_short_expiry: Force a short-dated expiration (for SPY/QQQ)
            
        Returns:
            Dict with mock option contract details
        """
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
            'is_mock': True
        }
    
    def estimate_option_prices(self, option_data: Dict[str, Any], 
                              stop_loss_price: float, 
                              take_profit_price: float) -> Dict[str, Any]:
        """
        Estimate option prices at stop loss and take profit levels
        
        This uses a simple delta-based approximation. For more accuracy, 
        a proper options pricing model would be needed.
        
        Args:
            option_data: Contract details from get_atm_option
            stop_loss_price: Price level for stop loss
            take_profit_price: Price level for take profit
            
        Returns:
            Dict with estimated option prices
        """
        try:
            if not option_data:
                return {}
                
            # Get mark price, default to 1.0 if not available
            mark_price = option_data.get('mark') 
            if mark_price is None:
                # If no mark price, estimate based on bid/ask or use default
                bid = option_data.get('bid', 0)
                ask = option_data.get('ask', 0)
                if bid > 0 and ask > 0:
                    mark_price = (bid + ask) / 2
                else:
                    # Default mark price for estimation
                    mark_price = 1.0
                    logger.warning(f"Using default mark price for {option_data.get('symbol', 'unknown')}")
                
            # Get current price data
            current_price = option_data['underlying_price']
            option_price = mark_price
            strike = option_data['strike']
            option_type = option_data['option_type'].lower()
            
            # Estimate delta (very rough approximation)
            # For ATM options, delta is ~0.5, adjust based on moneyness
            moneyness = current_price / strike
            
            if option_type == 'call':
                base_delta = 0.5
                # Adjust delta based on moneyness for calls
                # ITM calls have higher delta
                delta_adj = (moneyness - 1) * 2
                delta = min(0.95, max(0.05, base_delta + delta_adj))
                
                # DTE adjustment - shorter = more sensitive
                dte = option_data.get('days_to_expiry', 14)
                dte_factor = max(0.5, min(1.5, 14 / dte)) if dte > 0 else 1
                delta *= dte_factor
                
                # Calculate price adjustments
                sl_price_diff = stop_loss_price - current_price
                tp_price_diff = take_profit_price - current_price
                
            else:  # put
                base_delta = 0.5
                # Adjust delta based on moneyness for puts
                # ITM puts have higher delta (negative)
                delta_adj = (1 - moneyness) * 2
                delta = min(0.95, max(0.05, base_delta + delta_adj))
                
                # DTE adjustment
                dte = option_data.get('days_to_expiry', 14)
                dte_factor = max(0.5, min(1.5, 14 / dte)) if dte > 0 else 1
                delta *= dte_factor
                
                # For puts, price moves inversely to underlying
                sl_price_diff = current_price - stop_loss_price
                tp_price_diff = current_price - take_profit_price
            
            # Calculate estimated prices
            sl_option_price = max(0.01, option_price + (sl_price_diff * delta))
            tp_option_price = max(0.01, option_price + (tp_price_diff * delta))
            
            return {
                'entry': option_price,
                'stop_loss': sl_option_price,
                'take_profit': tp_option_price,
                'estimated_delta': delta
            }
            
        except Exception as e:
            logger.error(f"Error estimating option prices: {e}", exc_info=True)
            return {} 