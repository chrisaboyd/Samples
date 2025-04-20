import pandas as pd
import numpy as np
from strategies.base_strategy import BaseStrategy

class ScalpingStrategy(BaseStrategy):
    """
    Intraday scalping strategy using EMA crossovers and Opening Range Breakout.
    
    Key features:
    1. Uses 1-minute data for intraday trading
    2. Employs three EMAs (10, 35, 100) for trend confirmation
    3. Identifies 15-minute opening range breakout
    4. Tracks high/low of day for profit targets
    5. Entry: ORB breakout with retest of 35 EMA and trend confirmation
    6. Stop loss: Half of ORB width
    7. Profit target: Full ORB width or high/low of day (whichever is closer)
    8. Options-focused calculations (ATM ~0.5 delta)
    """
    
    def __init__(self, market_data):
        super().__init__(market_data)
        self.parameters.update({
            'timeframe': '1min',            # Use 1-minute data
            'intraday': True,               # This is an intraday strategy
            'market_open_time': '09:30',
            'market_close_time': '16:00',
            
            # EMA parameters
            'ema_short': 10,                # Short-term EMA
            'ema_medium': 35,               # Medium-term EMA
            'ema_long': 100,                # Long-term EMA
            
            # Opening Range parameters
            'orb_duration': 15,             # 15-minute opening range duration
            
            # Entry parameters
            'retest_tolerance': 0.001,      # 0.1% tolerance for retest proximity
            
            # Options parameters
            'option_delta': 0.5,            # Approximate ATM delta
            
            # Time filters
            'morning_wait_minutes': 5,      # Wait after market open
            'avoid_lunch': False,
            'lunch_start': '12:00',
            'lunch_end': '13:00'
        })
    
    def is_valid_trading_time(self, timestamp):
        """
        Check if the timestamp is within valid trading hours.
        
        Args:
            timestamp (pd.Timestamp): Time to check.
            
        Returns:
            bool: Whether the time is valid for trading.
        """
        if not isinstance(timestamp, pd.Timestamp):
            timestamp = pd.Timestamp(timestamp)
        
        # Convert to timezone-naive for comparison if needed
        if timestamp.tz is not None:
            timestamp = timestamp.tz_localize(None)
            
        current_time = timestamp.time()
        market_open = pd.to_datetime(self.parameters['market_open_time']).time()
        market_close = pd.to_datetime(self.parameters['market_close_time']).time()
        
        # Morning wait period
        morning_cutoff = (pd.Timestamp(self.parameters['market_open_time']) + 
                         pd.Timedelta(minutes=self.parameters['morning_wait_minutes'])).time()
        
        # Lunch period
        avoid_lunch = self.parameters['avoid_lunch']
        lunch_start = pd.to_datetime(self.parameters['lunch_start']).time()
        lunch_end = pd.to_datetime(self.parameters['lunch_end']).time()
        
        # Check if within market hours
        is_market_hours = market_open <= current_time <= market_close
        
        # Check if after morning wait
        is_after_morning_wait = current_time >= morning_cutoff
        
        # Check if during lunch (if avoiding lunch)
        is_lunch_period = lunch_start <= current_time <= lunch_end if avoid_lunch else False
        
        return is_market_hours and is_after_morning_wait and not is_lunch_period
    
    def calculate_indicators(self, price_data):
        """
        Calculate EMAs and other indicators for the strategy.
        
        Args:
            price_data (pd.Series): Minute-by-minute price data.
            
        Returns:
            pd.DataFrame: DataFrame with calculated indicators.
        """
        df = pd.DataFrame(index=price_data.index)
        df['price'] = price_data
        
        # Calculate EMAs
        df['ema_short'] = price_data.ewm(span=self.parameters['ema_short'], adjust=False).mean()
        df['ema_medium'] = price_data.ewm(span=self.parameters['ema_medium'], adjust=False).mean()
        df['ema_long'] = price_data.ewm(span=self.parameters['ema_long'], adjust=False).mean()
        
        # Track daily high and low
        if df.index[0].tz is not None:
            day_grouper = df.index.tz_localize(None).date
        else:
            day_grouper = df.index.date
            
        for day, day_data in df.groupby(day_grouper):
            day_indices = day_data.index
            df.loc[day_indices, 'high_of_day'] = day_data['price'].cummax()
            df.loc[day_indices, 'low_of_day'] = day_data['price'].cummin()
        
        return df
    
    def calculate_orb(self, day_data):
        """
        Calculate the Opening Range Breakout (ORB) high, low, and width for a day.
        
        Args:
            day_data (pd.DataFrame): Price data for a single trading day.
            
        Returns:
            tuple: (orb_high, orb_low, orb_width, orb_end_time)
        """
        # Use the first timestamp as market open
        first_timestamp = day_data.index[0]
        market_open = first_timestamp
        end_range = market_open + pd.Timedelta(minutes=self.parameters['orb_duration'])
        
        # Format timestamps for cleaner logging
        market_open_str = market_open.strftime('%Y-%m-%d %H:%M:%S')
        end_range_str = end_range.strftime('%Y-%m-%d %H:%M:%S')
        print(f"ORB period: {market_open_str} to {end_range_str}")
        
        orb_bars = day_data[(day_data.index >= market_open) & (day_data.index < end_range)]
        
        if orb_bars.empty:
            print("No bars found in opening range")
            return None, None, None, None
        
        orb_high = orb_bars['price'].max()
        orb_low = orb_bars['price'].min()
        orb_width = orb_high - orb_low
        
        print(f"ORB range: ${orb_low:.2f} - ${orb_high:.2f} (Width: ${orb_width:.2f})")
        return orb_high, orb_low, orb_width, end_range
    
    def check_trend_confirmation(self, row, direction):
        """
        Check if at least two of the three EMAs confirm the trend direction.
        
        Args:
            row (pd.Series): DataFrame row with EMA values.
            direction (str): 'long' or 'short'.
            
        Returns:
            bool: Whether the trend is confirmed.
        """
        if direction == 'long':
            # For long trend, EMAs should be in ascending order
            count = 0
            if row['ema_short'] > row['ema_medium']: count += 1
            if row['ema_medium'] > row['ema_long']: count += 1
            if row['ema_short'] > row['ema_long']: count += 1
            return count >= 2
        else:
            # For short trend, EMAs should be in descending order
            count = 0
            if row['ema_short'] < row['ema_medium']: count += 1
            if row['ema_medium'] < row['ema_long']: count += 1
            if row['ema_short'] < row['ema_long']: count += 1
            return count >= 2
    
    def check_ema_retest(self, row, prev_row, direction):
        """
        Check if price is retesting the medium EMA.
        
        Args:
            row (pd.Series): Current DataFrame row.
            prev_row (pd.Series): Previous DataFrame row.
            direction (str): 'long' or 'short'.
            
        Returns:
            bool: Whether the medium EMA is being retested.
        """
        tolerance = self.parameters['retest_tolerance']
        
        if direction == 'long':
            # For long, price should dip down to test the medium EMA and then bounce up
            touched_ema = (row['price'] >= row['ema_medium'] * (1 - tolerance) and 
                          row['price'] <= row['ema_medium'] * (1 + tolerance))
            bouncing_up = row['price'] > prev_row['price']
            return touched_ema and bouncing_up
        else:
            # For short, price should rise up to test the medium EMA and then drop down
            touched_ema = (row['price'] >= row['ema_medium'] * (1 - tolerance) and 
                          row['price'] <= row['ema_medium'] * (1 + tolerance))
            dropping_down = row['price'] < prev_row['price']
            return touched_ema and dropping_down
    
    def calculate_option_risk(self, entry_price, stop_price):
        """
        Calculate option risk based on underlying price movement and delta.
        
        Args:
            entry_price (float): Entry price of the underlying.
            stop_price (float): Stop loss price of the underlying.
            
        Returns:
            float: Approximate dollar risk per contract (per 100 shares).
        """
        price_difference = abs(entry_price - stop_price)
        option_delta = self.parameters['option_delta']
        return price_difference * option_delta * 100  # Dollar risk per contract
    
    def generate_signals(self):
        """
        Generate signals based on EMA trend and Opening Range Breakout with retest.
        
        Returns:
            dict: Dictionary with tickers as keys and signal DataFrames as values.
        """
        tickers = self.market_data.get_tickers()
        self.signals = {}
        
        for ticker in tickers:
            print(f"\nProcessing {ticker}")
            
            # Get price data
            price_data = self.market_data.get_price_data(ticker)
            if price_data.empty:
                print(f"No price data for {ticker}")
                continue
                
            # Calculate indicators
            indicators = self.calculate_indicators(price_data)
            
            # Initialize signal columns with explicit dtypes
            signals = pd.DataFrame(
                index=indicators.index,
                columns=[
                    'buy_signal', 'sell_signal', 'entry_price', 'stop_loss', 
                    'profit_target', 'orb_high', 'orb_low', 'orb_width',
                    'option_risk', 'option_target', 'high_of_day', 'low_of_day'
                ]
            )
            
            # Set datatypes to float64 for all columns except buy/sell signals
            for col in signals.columns:
                if col in ['buy_signal', 'sell_signal']:
                    signals[col] = 0  # Integer signals
                else:
                    signals[col] = 0.0  # Float values
            
            # Group by day
            if indicators.index[0].tz is not None:
                day_grouper = indicators.index.tz_localize(None).date
            else:
                day_grouper = indicators.index.date
                
            for day, day_data in indicators.groupby(day_grouper):
                day_str = str(day)
                print(f"Analyzing {ticker} - {day_str}")
                if len(day_data) < self.parameters['orb_duration']:
                    print(f"Insufficient data for {day_str}: only {len(day_data)} bars")
                    continue
                
                # Calculate ORB for the day
                orb_high, orb_low, orb_width, orb_end_time = self.calculate_orb(day_data)
                if orb_high is None or orb_low is None or orb_width is None:
                    continue
                
                # Set ORB values in signals DataFrame
                day_indices = day_data.index
                # Store values with explicit float conversion
                signals.loc[day_indices, 'orb_high'] = float(orb_high)
                signals.loc[day_indices, 'orb_low'] = float(orb_low)
                signals.loc[day_indices, 'orb_width'] = float(orb_width)
                
                # Store high_of_day and low_of_day values
                for idx in day_indices:
                    signals.loc[idx, 'high_of_day'] = float(day_data.loc[idx, 'high_of_day'])
                    signals.loc[idx, 'low_of_day'] = float(day_data.loc[idx, 'low_of_day'])
                
                # Trading variables
                long_breakout = False
                short_breakout = False
                trade_taken_long = False
                trade_taken_short = False
                
                # Scan for setup after ORB period
                for i in range(1, len(day_data)):
                    timestamp = day_data.index[i]
                    if timestamp <= orb_end_time:
                        continue
                    if trade_taken_long and trade_taken_short:
                        break
                    if not self.is_valid_trading_time(timestamp):
                        continue
                        
                    curr_row = day_data.loc[timestamp]
                    prev_row = day_data.iloc[i-1]
                    current_price = curr_row['price']
                    
                    # Check for breakouts
                    if not long_breakout and current_price > orb_high:
                        long_breakout = True
                        ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        print(f"Long breakout at {ts_str}: ${current_price:.2f} > ${orb_high:.2f}")
                    if not short_breakout and current_price < orb_low:
                        short_breakout = True
                        ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        print(f"Short breakout at {ts_str}: ${current_price:.2f} < ${orb_low:.2f}")
                    
                    # Long trade setup
                    if long_breakout and not trade_taken_long:
                        # Check for EMA retest and trend confirmation
                        if (self.check_ema_retest(curr_row, prev_row, 'long') and 
                            self.check_trend_confirmation(curr_row, 'long')):
                            
                            # Calculate stop loss (half of ORB width)
                            stop_price = current_price - (orb_width / 2)
                            #stop_price = current_price - orb_width
                            
                            # Calculate profit targets
                            target_orb = current_price + orb_width
                            target_hod = curr_row['high_of_day']
                            # Choose whichever is closer
                            profit_target = min(target_orb, target_hod)
                            
                            # Calculate option price changes (approximate)
                            option_risk = self.calculate_option_risk(current_price, stop_price)
                            option_target = self.calculate_option_risk(current_price, profit_target)
                            
                            # Set values in signals DataFrame
                            signals.loc[timestamp, 'buy_signal'] = 1
                            signals.loc[timestamp, 'sell_signal'] = 0
                            signals.loc[timestamp, 'entry_price'] = float(current_price)
                            signals.loc[timestamp, 'stop_loss'] = float(stop_price)
                            signals.loc[timestamp, 'profit_target'] = float(profit_target)
                            signals.loc[timestamp, 'option_risk'] = float(option_risk)
                            signals.loc[timestamp, 'option_target'] = float(option_target)
                            signals.loc[timestamp, 'high_of_day'] = float(curr_row['high_of_day'])
                            signals.loc[timestamp, 'low_of_day'] = float(curr_row['low_of_day'])
                            
                            trade_taken_long = True
                            # Set signals in DataFrame
                            ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                            print(f"\nBUY SIGNAL at {ts_str}:")
                            print(f"Entry: ${current_price:.2f}")
                            print(f"Stop: ${stop_price:.2f} (Half ORB width)")
                            print(f"Target: ${profit_target:.2f}")
                            print(f"Option Risk: ${option_risk:.2f}")
                            print(f"Option Target: ${option_target:.2f}")
                    
                    # Short trade setup
                    if short_breakout and not trade_taken_short:
                        # Check for EMA retest and trend confirmation
                        if (self.check_ema_retest(curr_row, prev_row, 'short') and 
                            self.check_trend_confirmation(curr_row, 'short')):
                            
                            # Calculate stop loss (half of ORB width)
                            stop_price = current_price + (orb_width / 2)
                            #stop_price = current_price + orb_width
                            # Calculate profit targets
                            target_orb = current_price - orb_width
                            target_lod = curr_row['low_of_day']
                            # Choose whichever is closer
                            profit_target = max(target_orb, target_lod)
                            
                            # Calculate option price changes (approximate)
                            option_risk = self.calculate_option_risk(current_price, stop_price)
                            option_target = self.calculate_option_risk(current_price, profit_target)
                            
                            # Set values in signals DataFrame
                            signals.loc[timestamp, 'buy_signal'] = 0
                            signals.loc[timestamp, 'sell_signal'] = 1
                            signals.loc[timestamp, 'entry_price'] = float(current_price)
                            signals.loc[timestamp, 'stop_loss'] = float(stop_price)
                            signals.loc[timestamp, 'profit_target'] = float(profit_target)
                            signals.loc[timestamp, 'option_risk'] = float(option_risk)
                            signals.loc[timestamp, 'option_target'] = float(option_target)
                            signals.loc[timestamp, 'high_of_day'] = float(curr_row['high_of_day'])
                            signals.loc[timestamp, 'low_of_day'] = float(curr_row['low_of_day'])
                                
                            trade_taken_short = True
                            # Set signals in DataFrame
                            ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                            print(f"\nSELL SIGNAL at {ts_str}:")
                            print(f"Entry: ${current_price:.2f}")
                            print(f"Stop: ${stop_price:.2f} (Half ORB width)")
                            print(f"Target: ${profit_target:.2f}")
                            print(f"Option Risk: ${option_risk:.2f}")
                            print(f"Option Target: ${option_target:.2f}")
            
            # Signal summary
            total_longs = signals['buy_signal'].sum()
            total_shorts = signals['sell_signal'].sum()
            print(f"\n{ticker} Signal Summary:")
            print(f"Total long signals: {total_longs}")
            print(f"Total short signals: {total_shorts}")
            
            # Replace any invalid values
            signals = signals.replace([np.inf, -np.inf], 0)
            signals = signals.fillna(0)
            
            self.signals[ticker] = signals
            
        return self.signals
