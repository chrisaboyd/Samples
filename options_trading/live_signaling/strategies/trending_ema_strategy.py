from datetime import datetime, time
import pandas as pd
import numpy as np
from .base_strategy import LiveStrategy
import logging

class Trending_EMA(LiveStrategy):
    """
    ORB + EMA Pullback Strategy

    - Compute 15m Opening Range (ORB)
    - Track 3 EMAs (10, 35, 100)
    - Detect breakout of ORB high/low
    - On pullback to the 35‑EMA (medium) with at least 2 EMAs aligned in trend,
      generate entry signal.
    - Profit target: either daily high/low or half the ORB range width.
    """
    def __init__(self):
        super().__init__("Trending_EMA")
        self.parameters.update({
            'market_open_time': time(9, 30),
            'market_close_time': time(16, 0),
            'opening_range_duration': 15,
            'tolerance': 0.001,
            'ema_short': 10,
            'ema_mid': 35,
            'ema_long': 100,
            'pullback_to_mid': True,
            'profit_target_pct_orb': 0.5,  # half ORB range
            'rsi_period': 14,              # RSI period
        })
        # State
        self.orb = {}            # ticker -> dict(high, low)
        self.flags = {}          # ticker -> dict(break_long, break_short, taken)
        self.breakout_prices = {}          # Store prices at breakout for reference
        self.last_direction = {}           # Keep track of the last trade direction

    def generate_signal(self, ticker: str, data: pd.DataFrame) -> dict:
        logger = logging.getLogger(__name__)
        if self.parameters.get('debug', False):
            logger.info(f"[{self.name}] generate_signal called for {ticker}. Parameters: {self.parameters}")
        now = datetime.now().time()
        open_t = self.parameters['market_open_time']
        end_orb = (datetime.combine(datetime.today(), open_t)
                   + pd.Timedelta(minutes=self.parameters['opening_range_duration'])).time()

        # Initialize ticker data structures if first time seeing ticker
        if ticker not in self.orb:
            self.orb[ticker] = {}
            self.flags[ticker] = {
                'breakout_confirmed_long': False, 
                'breakout_confirmed_short': False, 
                'long_taken': False,
                'short_taken': False
            }
            self.breakout_prices[ticker] = {'long': None, 'short': None}
            self.last_direction[ticker] = None

        bars = data.copy()
        if len(bars) < 2:
            return {'signal': None}  # Need at least 2 bars for calculations
            
        # Calculate RSI and VWAP
        rsi_value = None
        vwap_value = None
        
        if len(bars) >= self.parameters['rsi_period']:
            rsi_series = self.calculate_rsi(bars['close'], periods=self.parameters['rsi_period'])
            rsi_value = rsi_series.iloc[-1]
            
            # Calculate VWAP as well
            vwap_series = self.calculate_vwap(bars)
            vwap_value = vwap_series.iloc[-1]

        # During ORB period: record high/low
        if now <= end_orb:
            h = bars['high'].max()
            l = bars['low'].min()
            self.orb[ticker].update({'high': h, 'low': l})
            return {'signal': None, 'rsi': rsi_value, 'vwap': vwap_value}

        # After ORB
        orb_h, orb_l = self.orb[ticker].get('high'), self.orb[ticker].get('low')
        if orb_h is None or orb_l is None:
            return {'signal': None, 'rsi': rsi_value, 'vwap': vwap_value}
            
        flags = self.flags[ticker]
        current_close = bars['close'].iloc[-1]
        previous_close = bars['close'].iloc[-2]
        current_high = bars['high'].iloc[-1]
        current_low = bars['low'].iloc[-1]
        orb_range = orb_h - orb_l

        # Check for reversal - price closing back inside the ORB after a breakout
        if self.parameters.get('allow_reversals', False) and (flags['breakout_confirmed_long'] or flags['breakout_confirmed_short']):
            # If price closes back inside the range, reset breakout flags
            if orb_l <= current_close <= orb_h:
                # Only reset the direction that hasn't been taken yet
                if not flags['long_taken'] and flags['breakout_confirmed_long']:
                    flags['breakout_confirmed_long'] = False
                    if self.parameters.get('debug', False):
                        print(f"[DEBUG] {ticker} - REVERSAL DETECTED: Price closed back inside ORB, resetting long breakout")
                
                if not flags['short_taken'] and flags['breakout_confirmed_short']:
                    flags['breakout_confirmed_short'] = False
                    if self.parameters.get('debug', False):
                        print(f"[DEBUG] {ticker} - REVERSAL DETECTED: Price closed back inside ORB, resetting short breakout")

        # Compute EMAs
        bars['ema_s'] = bars['close'].ewm(span=self.parameters['ema_short'], adjust=False).mean()
        bars['ema_m'] = bars['close'].ewm(span=self.parameters['ema_mid'], adjust=False).mean()
        bars['ema_l'] = bars['close'].ewm(span=self.parameters['ema_long'], adjust=False).mean()
        ema_s = bars['ema_s'].iloc[-1]
        ema_m = bars['ema_m'].iloc[-1]
        ema_l = bars['ema_l'].iloc[-1]

        # Detect breakout CONFIRMATION (bars must CLOSE beyond the ORB levels)
        if not flags['breakout_confirmed_long'] and previous_close > orb_h:
            flags['breakout_confirmed_long'] = True
            self.breakout_prices[ticker]['long'] = previous_close
            if self.parameters.get('debug', False):
                print(f"[DEBUG] {ticker} - Long breakout CONFIRMED at {previous_close:.2f} > ORB high {orb_h:.2f}")
        
        if not flags['breakout_confirmed_short'] and previous_close < orb_l:
            flags['breakout_confirmed_short'] = True
            self.breakout_prices[ticker]['short'] = previous_close
            if self.parameters.get('debug', False):
                print(f"[DEBUG] {ticker} - Short breakout CONFIRMED at {previous_close:.2f} < ORB low {orb_l:.2f}")

        # Calculate pullback tolerance in absolute price terms
        pullback_tolerance = self.parameters['tolerance'] * ema_m

        # Long entry criteria - PULLBACK TO 35 EMA after confirmed breakout
        if flags['breakout_confirmed_long'] and not flags['long_taken']:
            # Check if price is pulling back to the 35 EMA
            pullback_to_ema = abs(current_close - ema_m) <= pullback_tolerance
            
            if pullback_to_ema:
                # Debug
                if self.parameters.get('debug', False):
                    print(f"[DEBUG] {ticker} - Potential LONG pullback to 35 EMA:")
                    print(f"  Current price: {current_close:.2f}")
                    print(f"  35 EMA: {ema_m:.2f}")
                    print(f"  10 EMA: {ema_s:.2f}")
                    print(f"  100 EMA: {ema_l:.2f}")
                    print(f"  Tolerance: ±{pullback_tolerance:.2f}")
                
                # EMAs aligned: at least two rising (s>m>l)
                aligned = (ema_s > ema_m and ema_m > ema_l) or (ema_s > ema_l and ema_m > ema_l)
                
                if aligned:
                    # Determine targets and stops based on ORB width
                    stop_loss = current_close - 0.25 * orb_range
                    profit_target = max(bars['high'].max(), current_close + self.parameters['profit_target_pct_orb'] * orb_range)
                    flags['long_taken'] = True
                    self.last_direction[ticker] = 'long'
                    
                    if self.parameters.get('debug', False):
                        print(f"[DEBUG] {ticker} - GENERATING LONG SIGNAL:")
                        print(f"  EMAs aligned: 10 EMA={ema_s:.2f}, 35 EMA={ema_m:.2f}, 100 EMA={ema_l:.2f}")
                        print(f"  Entry: {current_close:.2f}")
                        print(f"  Stop: {stop_loss:.2f}")
                        print(f"  Target: {profit_target:.2f}")
                    
                    return {
                        'signal': 'buy', 
                        'entry_price': float(current_close),
                        'stop_loss': float(stop_loss), 
                        'profit_target': float(profit_target),
                        'ema_mid': float(ema_m),  # Include the 35 EMA for reference
                        'ema_short': float(ema_s),
                        'ema_long': float(ema_l),
                        'orb_high': float(orb_h),
                        'reversal': self.last_direction[ticker] == 'short',  # Flag if this is a reversal
                        'rsi': float(rsi_value) if rsi_value is not None else None,
                        'vwap': float(vwap_value) if vwap_value is not None else None
                    }
        
        # Short entry criteria - PULLBACK TO 35 EMA after confirmed breakout
        if flags['breakout_confirmed_short'] and not flags['short_taken']:
            # Check if price is pulling back to the 35 EMA
            pullback_to_ema = abs(current_close - ema_m) <= pullback_tolerance
            
            if pullback_to_ema:
                # Debug
                if self.parameters.get('debug', False):
                    print(f"[DEBUG] {ticker} - Potential SHORT pullback to 35 EMA:")
                    print(f"  Current price: {current_close:.2f}")
                    print(f"  35 EMA: {ema_m:.2f}")
                    print(f"  10 EMA: {ema_s:.2f}")
                    print(f"  100 EMA: {ema_l:.2f}")
                    print(f"  Tolerance: ±{pullback_tolerance:.2f}")
                
                # EMAs aligned: at least two declining (s<m<l)
                aligned = (ema_s < ema_m and ema_m < ema_l) or (ema_s < ema_l and ema_m < ema_l)
                
                if aligned:
                    daily_low = bars['low'].min()
                    profit_target = min(daily_low, current_close - self.parameters['profit_target_pct_orb'] * orb_range)
                    stop_loss = current_close + 0.25 * orb_range
                    flags['short_taken'] = True
                    self.last_direction[ticker] = 'short'
                    
                    if self.parameters.get('debug', False):
                        print(f"[DEBUG] {ticker} - GENERATING SHORT SIGNAL:")
                        print(f"  EMAs aligned: 10 EMA={ema_s:.2f}, 35 EMA={ema_m:.2f}, 100 EMA={ema_l:.2f}")
                        print(f"  Entry: {current_close:.2f}")
                        print(f"  Stop: {stop_loss:.2f}")
                        print(f"  Target: {profit_target:.2f}")
                    
                    return {
                        'signal': 'sell', 
                        'entry_price': float(current_close),
                        'stop_loss': float(stop_loss),
                        'profit_target': float(profit_target),
                        'ema_mid': float(ema_m),  # Include the 35 EMA for reference
                        'ema_short': float(ema_s),
                        'ema_long': float(ema_l),
                        'orb_low': float(orb_l),
                        'reversal': self.last_direction[ticker] == 'long',  # Flag if this is a reversal
                        'rsi': float(rsi_value) if rsi_value is not None else None,
                        'vwap': float(vwap_value) if vwap_value is not None else None
                    }

        return {'signal': None, 'rsi': rsi_value, 'vwap': vwap_value}
