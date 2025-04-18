from datetime import datetime, time
import pandas as pd
import numpy as np
from .base_strategy import LiveStrategy

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
        })
        self.orb_ranges = {}           # {ticker: {'high':float,'low':float,'avg_vol':float,'vwap':float}}
        self.breakout_flags = {}       # {ticker: {'long':bool,'short':bool,'trade_taken':bool}}

    def generate_signal(self, ticker: str, current_data: pd.DataFrame) -> dict:
        """
        current_data: DataFrame of 1m bars from market open up to now, with columns:
          ['high','low','close','volume']
        Returns dict with signal details or {'signal':None}.
        """
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
            return {'signal': None}

        # After ORB
        orb = self.orb_ranges[ticker]
        if not orb:
            return {'signal': None}

        state = self.breakout_flags[ticker]
        bar = current_data.iloc[-1]
        price = bar['close']
        vol   = bar['volume']
        orb_high = orb['high']
        orb_low  = orb['low']
        orb_range = orb_high - orb_low

        # Volume filter: only after ORB, require bar.volume > min_volume_multiplier * avg_vol
        if vol < self.parameters['min_volume_multiplier'] * orb['avg_vol']:
            return {'signal': None}

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
            return {'signal': None}

        t = self.parameters['tolerance']
        # Long retest & entry
        if state['long'] and macd_ok_long:
            if orb_high * (1 - t) <= price <= orb_high * (1 + t) and price > orb['vwap']:
                stop = price - 0.25 * orb_range
                target = price + 0.5 * orb_range  # 2:1 reward
                state['trade_taken'] = True
                return dict(
                    signal='buy',
                    entry_price=float(price),
                    stop_loss=float(stop),
                    profit_target=float(target),
                    orb_high=float(orb_high), orb_low=float(orb_low)
                )

        # Short retest & entry
        if state['short'] and macd_ok_short:
            if orb_low * (1 - t) <= price <= orb_low * (1 + t) and price < orb['vwap']:
                stop = price + 0.25 * orb_range
                target = price - 0.5 * orb_range
                state['trade_taken'] = True
                return dict(
                    signal='sell',
                    entry_price=float(price),
                    stop_loss=float(stop),
                    profit_target=float(target),
                    orb_high=float(orb_high), orb_low=float(orb_low)
                )

        return {'signal': None}
