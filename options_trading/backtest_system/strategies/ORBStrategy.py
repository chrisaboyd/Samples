import pandas as pd
import numpy as np
from strategies.base_strategy import BaseStrategy

class ORBStrategy(BaseStrategy):
    """
    Opening Range Breakout (ORB) Strategy.
    
    For each trading day, the strategy calculates the opening range (high and low) from
    the first 'opening_range_duration' minutes of data (e.g. 15 or 30 minutes). Once the
    price breaks the ORB range, the strategy waits for a retest:
    
      - For a long trade, if the price retests the ORB high within a specified tolerance
        (meaning the bar's low comes very close to the ORB high) and then bounces back upward,
        a buy signal is generated.
      - For a short trade, if the price retests the ORB low and then continues downward, a
        sell signal is generated.
    
    Entry price is set at the retest bar's close. The stop loss is determined from the
    recent candle wicks (based on a lookback window), and the profit target is set as a multiple
    of the ORB range.
    """
    
    def __init__(self, market_data):
        super().__init__(market_data)
        # Parameters for intraday ORB strategy
        self.parameters.update({
            'intraday': True,
            'timeframe': '1min',  # Trading on 1-minute bars
            'market_open_time': '09:30',
            'market_close_time': '16:00',
            'opening_range_duration': 15,      # Opening range in minutes (try 15 or 30)
            'tolerance': 0.001,                # 0.1% tolerance for retest proximity
            'stop_loss_lookback': 2,           # Look back this many bars for stop loss determination
            'profit_target_multiplier': 2.0,   # Profit target: multiple of the ORB range (e.g., 2:1 or 3:1)
        })
    
    def is_valid_trading_time(self, timestamp):
        """
        Only allow signals during market hours.
        """
        if not isinstance(timestamp, pd.Timestamp):
            timestamp = pd.Timestamp(timestamp)
        
        # Convert to timezone-naive for comparison
        if timestamp.tz is not None:
            timestamp = timestamp.tz_localize(None)
            
        current_time = timestamp.time()
        market_open = pd.to_datetime(self.parameters['market_open_time']).time()
        market_close = pd.to_datetime(self.parameters['market_close_time']).time()
        return market_open <= current_time <= market_close
    
    def calculate_orb(self, day_data):
        """
        Calculate the ORB (opening range high and low) for a day.
        """
        print(f"\nCalculating ORB for day starting at {day_data.index[0]}")
        print(f"Available columns: {day_data.columns.tolist()}")
        
        # Use the first timestamp as market open.
        first_timestamp = day_data.index[0]
        market_open = first_timestamp
        end_range = market_open + pd.Timedelta(minutes=self.parameters['opening_range_duration'])
        
        print(f"Looking for bars between {market_open} and {end_range}")
        
        orb_bars = day_data[(day_data.index >= market_open) & (day_data.index < end_range)]
        print(f"Found {len(orb_bars)} bars in opening range")
        
        if orb_bars.empty:
            print("No bars found in opening range")
            return None, None
        
        ticker_col = day_data.columns[0]
        orb_high = orb_bars[ticker_col].max()
        orb_low = orb_bars[ticker_col].min()
        
        print(f"ORB High: {orb_high:.2f}, Low: {orb_low:.2f}")
        return orb_high, orb_low
    
    def determine_stop_loss(self, data, current_idx, direction):
        """
        Determine the stop loss based on the lowest low (for long trades) or highest high (for shorts)
        over a lookback period.
        If there is insufficient lookback data, use the current bar's price offset by a small amount.
        """
        lookback = self.parameters.get('stop_loss_lookback', 2)
        if current_idx < lookback or current_idx == 0:
            ticker_col = data.columns[0]
            current_price = data.iloc[current_idx][ticker_col]
            return current_price - 0.01 if direction == 'long' else current_price + 0.01
        
        ticker_col = data.columns[0]
        recent = data.iloc[current_idx - lookback:current_idx]
        if recent.empty:
            return data.iloc[current_idx][ticker_col]
        
        if direction == 'long':
            return recent[ticker_col].min()
        else:
            return recent[ticker_col].max()
    
    def generate_signals(self):
        """
        Generate buy/sell signals using an ORB breakout with a retest.
        The signal DataFrame includes columns:
           - buy_signal / sell_signal: 1 if a signal occurs.
           - entry_price: The entry price.
           - stop_loss: The risk level.
           - profit_target: The target level based on the ORB range.
           - orb_high / orb_low: The opening range values.
        """
        tickers = self.market_data.get_tickers()
        self.signals = {}
        
        for ticker in tickers:
            data = self.market_data.get_price_data(ticker)
            if data.empty:
                continue
            
            print(f"\nAnalyzing {ticker}:")
            print(f"Data range: {data.index[0]} to {data.index[-1]}")
            print(f"Number of bars: {len(data)}")
            
            signals = pd.DataFrame(index=data.index, 
                                 columns=['buy_signal', 'sell_signal', 'entry_price', 
                                        'stop_loss', 'profit_target', 'orb_high', 'orb_low'],
                                 data=0)  # Initialize with zeros instead of NaN
            
            if data.index[0].tz is not None:
                day_grouper = data.index.tz_localize(None).date
            else:
                day_grouper = data.index.date
                
            for day, day_data in data.groupby(day_grouper):
                print(f"\nAnalyzing day: {day}")
                if len(day_data) < self.parameters['opening_range_duration']:
                    print(f"Insufficient data for day: only {len(day_data)} bars")
                    continue
                
                orb_high, orb_low = self.calculate_orb(day_data)
                if orb_high is None or orb_low is None:
                    print("Could not calculate ORB range")
                    continue
                    
                orb_range = orb_high - orb_low
                print(f"ORB Range: High=${orb_high:.2f}, Low=${orb_low:.2f}, Range=${orb_range:.2f}")
                
                signals.loc[day_data.index, 'orb_high'] = float(orb_high)
                signals.loc[day_data.index, 'orb_low'] = float(orb_low)
                
                day_str = pd.Timestamp(day).strftime("%Y-%m-%d")
                market_open = pd.to_datetime(day_str + ' ' + self.parameters['market_open_time'])
                start_time = market_open + pd.Timedelta(minutes=self.parameters['opening_range_duration'])
                if day_data.index[0].tz is not None:
                    market_open = market_open.tz_localize('UTC')
                    start_time = start_time.tz_localize('UTC')
                
                breakout_long = False
                breakout_short = False
                trade_taken = False
                
                print(f"Scanning for breakouts after {start_time}")
                
                for i, timestamp in enumerate(day_data.index):
                    if timestamp < start_time:
                        continue
                    if trade_taken:
                        continue
                    if not self.is_valid_trading_time(timestamp):
                        continue
                        
                    ticker_col = day_data.columns[0]
                    row = day_data.loc[timestamp]
                    current_price = row[ticker_col]
                    
                    # Check for initial breakouts
                    if not breakout_long and current_price > orb_high:
                        breakout_long = True
                        print(f"Long breakout at {timestamp}: ${current_price:.2f} > ${orb_high:.2f}")
                    if not breakout_short and current_price < orb_low:
                        breakout_short = True
                        print(f"Short breakout at {timestamp}: ${current_price:.2f} < ${orb_low:.2f}")

                    tolerance = self.parameters['tolerance']
                    
                    # Long trade setup
                    if breakout_long and not trade_taken:
                        if (orb_high * (1 - tolerance) <= current_price <= orb_high * (1 + tolerance)):
                            # Create a dictionary with ALL signal details
                            signal_details = {
                                'buy_signal': 1,
                                'sell_signal': 0,
                                'entry_price': float(current_price),
                                'stop_loss': float(self.determine_stop_loss(day_data, i, 'long')),
                                'profit_target': float(current_price + (self.parameters['profit_target_multiplier'] * orb_range)),
                                'orb_high': float(orb_high),
                                'orb_low': float(orb_low)
                            }
                            
                            # Set all values for this timestamp
                            for col, value in signal_details.items():
                                signals.loc[timestamp, col] = value
                            
                            trade_taken = True
                            print(f"\nBUY SIGNAL details at {timestamp}:")
                            for col, value in signal_details.items():
                                print(f"{col}: {value}")

                    # Short trade setup
                    if breakout_short and not trade_taken:
                        if (orb_low * (1 - tolerance) <= current_price <= orb_low * (1 + tolerance)):
                            # Create a dictionary with ALL signal details
                            signal_details = {
                                'buy_signal': 0,
                                'sell_signal': 1,
                                'entry_price': float(current_price),
                                'stop_loss': float(self.determine_stop_loss(day_data, i, 'short')),
                                'profit_target': float(current_price - (self.parameters['profit_target_multiplier'] * orb_range)),
                                'orb_high': float(orb_high),
                                'orb_low': float(orb_low)
                            }
                            
                            # Set all values for this timestamp
                            for col, value in signal_details.items():
                                signals.loc[timestamp, col] = value
                            
                            trade_taken = True
                            print(f"\nSELL SIGNAL details at {timestamp}:")
                            for col, value in signal_details.items():
                                print(f"{col}: {value}")
                
                if not trade_taken:
                    print("No valid setups found for this day")
            
            # Add final validation
            print("\nFinal signal check:")
            for col in signals.columns:
                non_zero = signals[signals[col] != 0][col]
                if not non_zero.empty:
                    print(f"\n{col} non-zero values:")
                    print(non_zero)
            
            total_longs = float(signals['buy_signal'].sum() or 0)
            total_shorts = float(signals['sell_signal'].sum() or 0)
            print(f"\nSummary for {ticker}:")
            print(f"Total long entries: {total_longs}")
            print(f"Total short entries: {total_shorts}")
            
            self.signals[ticker] = signals
        
        # Before returning signals, validate all numeric values
        for ticker, signal_df in self.signals.items():
            print("\nValidating signals for", ticker)
            print("Signal DataFrame columns:", signal_df.columns.tolist())
            
            # Replace any infinite values with 0
            signal_df = signal_df.replace([np.inf, -np.inf], 0)
            
            # Ensure all numeric columns are finite
            for col in ['buy_signal', 'sell_signal', 'entry_price', 'stop_loss', 'profit_target']:
                if col in signal_df.columns:
                    # Print any suspicious values
                    if signal_df[col].isin([np.inf, -np.inf]).any():
                        print(f"Found infinity in {col}")
                    if signal_df[col].isna().any():
                        print(f"Found NaN in {col}")
                    if (signal_df[col] == 0).all():
                        print(f"Column {col} is all zeros")
                    
                    # Show non-zero values
                    non_zero = signal_df[col][signal_df[col] != 0]
                    if not non_zero.empty:
                        print(f"\n{col} values:")
                        print(non_zero)

            self.signals[ticker] = signal_df

        return self.signals
