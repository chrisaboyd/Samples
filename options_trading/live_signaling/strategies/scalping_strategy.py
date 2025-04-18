from datetime import datetime, time
import pandas as pd
import numpy as np
from .base_strategy import LiveStrategy

class LiveORB_EMA_Strategy(LiveStrategy):
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
        super().__init__("ORB_EMA")
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
        })
        # State
        self.orb = {}            # ticker -> dict(high, low)
        self.flags = {}          # ticker -> dict(break_long, break_short, taken)

    def generate_signal(self, ticker: str, data: pd.DataFrame) -> dict:
        now = datetime.now().time()
        open_t = self.parameters['market_open_time']
        end_orb = (datetime.combine(datetime.today(), open_t)
                   + pd.Timedelta(minutes=self.parameters['opening_range_duration'])).time()

        # initialize
        if ticker not in self.orb:
            self.orb[ticker] = {}
            self.flags[ticker] = {'break_long': False, 'break_short': False, 'taken': False}

        bars = data.copy()
        # During ORB period: record high/low
        if now <= end_orb:
            h = bars['high'].max()
            l = bars['low'].min()
            self.orb[ticker].update({'high': h, 'low': l})
            return {'signal': None}

        # After ORB
        orb_h, orb_l = self.orb[ticker].get('high'), self.orb[ticker].get('low')
        if orb_h is None or orb_l is None:
            return {'signal': None}
        flags = self.flags[ticker]
        price = bars['close'].iloc[-1]
        high = bars['high'].iloc[-1]
        low  = bars['low'].iloc[-1]
        rng = orb_h - orb_l

        # compute EMAs
        bars['ema_s'] = bars['close'].ewm(span=self.parameters['ema_short'], adjust=False).mean()
        bars['ema_m'] = bars['close'].ewm(span=self.parameters['ema_mid'], adjust=False).mean()
        bars['ema_l'] = bars['close'].ewm(span=self.parameters['ema_long'], adjust=False).mean()
        ema_s = bars['ema_s'].iloc[-1]
        ema_m = bars['ema_m'].iloc[-1]
        ema_l = bars['ema_l'].iloc[-1]

        # detect breakout
        if not flags['break_long'] and high > orb_h:
            flags['break_long'] = True
        if not flags['break_short'] and low < orb_l:
            flags['break_short'] = True

        # only one trade per day
        if flags['taken']:
            return {'signal': None}

        tol = self.parameters['tolerance']
        # Long entry criteria
        if flags['break_long']:
            # pullback to mid EMA
            if abs(price - ema_m) <= tol * price:
                # EMAs aligned: at least two rising (s>m>l)
                aligned = (ema_s > ema_m and ema_m > ema_l) or (ema_s > ema_l and ema_m > ema_l)
                if aligned:
                    # determine targets and stops based on ORB width
                    sl = price - 0.25 * rng   # stop at 1/4 ORB width below entry
                    pt = max(bars['high'].max(), price + self.parameters['profit_target_pct_orb'] * rng)
                    flags['taken'] = True
                    return {'signal': 'buy', 'entry_price': float(price),
                            'stop_loss': float(sl), 'profit_target': float(pt)}
                            'stop_loss':float(sl), 'profit_target':float(pt)}
        # Short entry criteria
        if flags['break_short']:
            if abs(price - ema_m) <= tol * price:
                aligned = (ema_s < ema_m and ema_m < ema_l) or (ema_s < ema_l and ema_m < ema_l)
                if aligned:
                    dt_low = data['low'].min()
                    pt = min(dt_low, price - self.parameters['profit_target_pct_orb'] * rng)
                    sl = ema_m
                    flags['taken'] = True
                    return {'signal': 'sell', 'entry_price':float(price),
                            'stop_loss':float(sl), 'profit_target':float(pt)}

        return {'signal': None}
