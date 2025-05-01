from datetime import datetime, time
import pandas as pd
import numpy as np
from strategies.base_strategy import LiveStrategy

class LiveORBStrategy(LiveStrategy):
    def __init__(self):
        super().__init__("ORB")
        self.parameters.update({
            'market_open_time': time(9, 30),
            'market_close_time': time(16, 0),
            'opening_range_duration': 15,
            'tolerance': 0.001,
            # Additional filters:
            'min_volume_multiplier': 1.25,   # require volume >1.5× avg during ORB
            'vwap_period': 30,               # VWAP over first 30 min
            'macd_fast': 5,
            'macd_slow': 13,
            'macd_signal': 5,
            'rsi_period': 14,               # RSI period
        })
        self.orb_ranges = {}           # {ticker: {'high':float,'low':float,'avg_vol':float,'vwap':float}}
        self.breakout_flags = {}       # {ticker: {'long':bool,'short':bool,'trade_taken':bool}}

    def set_orb_from_history(self, ticker, minute_bars):
        """
        Set ORB high/low (and avg_vol, vwap) from historical minute bars.
        minute_bars: DataFrame with at least 'high', 'low', 'close', 'volume', indexed by datetime.
        """
        print(f"[DEBUG] {ticker} - Setting ORB from history. DataFrame shape: {minute_bars.shape}")
        print(f"[DEBUG] {ticker} - First bar: {minute_bars.index[0]}, Last bar: {minute_bars.index[-1]}")
        
        open_time = self.parameters['market_open_time']
        duration = self.parameters['opening_range_duration']
        
        if minute_bars.empty:
            print(f"[DEBUG] {ticker} - DataFrame is empty. Skipping ORB calculation.")
            return
            
        # Ensure the index is in ET
        if minute_bars.index.tz is None:
            minute_bars.index = minute_bars.index.tz_localize('US/Eastern')
        elif minute_bars.index.tz != 'US/Eastern':
            minute_bars.index = minute_bars.index.tz_convert('US/Eastern')
            
        # Get the date of the first bar
        first_bar_date = minute_bars.index[0].date()
        market_open = pd.Timestamp.combine(first_bar_date, open_time).tz_localize('US/Eastern')
        orb_end = market_open + pd.Timedelta(minutes=duration)
        
        print(f"[DEBUG] {ticker} - ORB window: {market_open} to {orb_end}")
        
        # Filter bars within the ORB window
        orb_bars = minute_bars[(minute_bars.index >= market_open) & (minute_bars.index < orb_end)]
        print(f"[DEBUG] {ticker} - Found {len(orb_bars)} bars in ORB window")
        
        if orb_bars.empty:
            print(f"[DEBUG] {ticker} - No bars in ORB window. Skipping ORB calculation.")
            return
            
        high = orb_bars['high'].max()
        low = orb_bars['low'].min()
        print(f"[DEBUG] {ticker} - ORB high: {high}, low: {low}")
        
        avg_vol = orb_bars['volume'].mean()
        vwap = (orb_bars['close'] * orb_bars['volume']).sum() / orb_bars['volume'].sum()
        
        # Initialize state for this ticker
        self.orb_ranges[ticker] = {'high': high, 'low': low, 'avg_vol': avg_vol, 'vwap': vwap}
        self.breakout_flags[ticker] = {'long': False, 'short': False, 'trade_taken': False}
        
        print(f"[DEBUG] {ticker} - Set ORB values: high={high}, low={low}, avg_vol={avg_vol}, vwap={vwap}")
        print(f"[DEBUG] {ticker} - Initialized breakout flags: {self.breakout_flags[ticker]}")

    def generate_signal(self, ticker: str, current_data: pd.DataFrame) -> dict:
        """
        current_data: DataFrame of 1m bars from market open up to now, with columns:
          ['high','low','close','volume']
        Returns dict with signal details or {'signal':None}.
        """
        # Initialize response with indicators
        response = {'signal': None}
        
        # Calculate RSI and VWAP if we have enough data
        if len(current_data) >= self.parameters['rsi_period']:
            rsi = self.calculate_rsi(current_data['close'], periods=self.parameters['rsi_period'])
            response['rsi'] = float(rsi.iloc[-1])
            
            vwap = self.calculate_vwap(current_data)
            response['vwap'] = float(vwap.iloc[-1])

        # Initialize per-ticker state
        if ticker not in self.orb_ranges:
            self.orb_ranges[ticker] = {}
            self.breakout_flags[ticker] = {'long': False, 'short': False, 'trade_taken': False}

        # Determine current time
        now = datetime.now().time()
        open_time = self.parameters['market_open_time']
        duration = self.parameters['opening_range_duration']
        cutoff = (datetime.combine(datetime.today(), open_time)
                  + pd.Timedelta(minutes=duration)).time()

        # During ORB period: accumulate high/low, average volume, VWAP
        if now <= cutoff:
            df = current_data.copy()
            high = df['high'].max()
            low  = df['low'].min()
            avg_vol = df['volume'].mean()
            # VWAP calculation
            pv = (df['close'] * df['volume']).cumsum()
            vcum = df['volume'].cumsum()
            vwap = (pv / vcum).iloc[-1]
            self.orb_ranges[ticker].update({
                'high': high,
                'low': low,
                'avg_vol': avg_vol,
                'vwap': vwap,
            })
            return response

        # After ORB
        orb = self.orb_ranges[ticker]
        if not orb:
            return response

        state = self.breakout_flags[ticker]
        bar = current_data.iloc[-1]
        price = bar['close']
        vol   = bar['volume']
        orb_high = orb['high']
        orb_low  = orb['low']
        orb_range = orb_high - orb_low

        # Volume filter: only after ORB, require bar.volume > min_volume_multiplier * avg_vol
        if vol < self.parameters['min_volume_multiplier'] * orb['avg_vol']:
            return response

        # Compute MACD for momentum confirmation
        prices = current_data['close']
        fast = prices.ewm(span=self.parameters['macd_fast'], adjust=False).mean()
        slow = prices.ewm(span=self.parameters['macd_slow'], adjust=False).mean()
        macd = fast - slow
        signal = macd.ewm(span=self.parameters['macd_signal'], adjust=False).mean()
        macd_ok_long = macd.iloc[-1] > signal.iloc[-1]
        macd_ok_short = macd.iloc[-1] < signal.iloc[-1]

        # Detect breakout
        if not state['long'] and bar['high'] > orb_high:
            state['long'] = True
        if not state['short'] and bar['low'] < orb_low:
            state['short'] = True

        # Only one trade per day
        if state['trade_taken']:
            return response

        t = self.parameters['tolerance']
        # Long retest & entry
        if state['long'] and macd_ok_long:
            if orb_high * (1 - t) <= price <= orb_high * (1 + t) and price > orb['vwap']:
                stop = price - 0.25 * orb_range
                target = price + 0.5 * orb_range  # 2:1 reward
                state['trade_taken'] = True
                response.update(dict(
                    signal='buy',
                    entry_price=float(price),
                    stop_loss=float(stop),
                    profit_target=float(target),
                    orb_high=float(orb_high), 
                    orb_low=float(orb_low)
                ))
                return response

        # Short retest & entry
        if state['short'] and macd_ok_short:
            if orb_low * (1 - t) <= price <= orb_low * (1 + t) and price < orb['vwap']:
                stop = price + 0.25 * orb_range
                target = price - 0.5 * orb_range
                state['trade_taken'] = True
                response.update(dict(
                    signal='sell',
                    entry_price=float(price),
                    stop_loss=float(stop),
                    profit_target=float(target),
                    orb_high=float(orb_high), 
                    orb_low=float(orb_low)
                ))
                return response

        return response
