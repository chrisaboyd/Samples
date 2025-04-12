import pandas as pd

class MarketData:
    """
    Handles market data storage and access for backtesting.
    Provides methods to access price and volume data in a standardized way.
    """
    
    def __init__(self, data):
        """
        Initialize with market data.
        
        Args:
            data: Either a pandas DataFrame or a dictionary of DataFrames with tickers as keys
        """
        self.data = data
        self.is_multi_ticker = isinstance(data, dict)
        
    def get_price_data(self, ticker=None, field='Close'):
        """
        Get price data for a specific ticker and field.
        
        Args:
            ticker (str, optional): Ticker symbol. Required if multi-ticker data.
            field (str, optional): Price field ('Open', 'High', 'Low', 'Close', 'Adj Close').
                                   Defaults to 'Close'.
        
        Returns:
            pd.Series or pd.DataFrame: Price data
        """
        if self.is_multi_ticker:
            if ticker is None:
                # Return all tickers' data for the specified field
                return pd.DataFrame({t: df[field] for t, df in self.data.items()})
            elif ticker in self.data:
                return self.data[ticker][field]
            else:
                raise ValueError(f"Ticker {ticker} not found in data")
        else:
            # Single ticker data
            return self.data[field]
    
    def get_volume(self, ticker=None):
        """
        Get volume data for a specific ticker.
        
        Args:
            ticker (str, optional): Ticker symbol. Required if multi-ticker data.
        
        Returns:
            pd.Series: Volume data
        """
        return self.get_price_data(ticker, 'Volume')
    
    def get_tickers(self):
        """
        Get list of available tickers.
        
        Returns:
            list: List of ticker symbols
        """
        if self.is_multi_ticker:
            return list(self.data.keys())
        else:
            # If only one ticker, try to extract it from the data
            if 'Ticker' in self.data.columns:
                return [self.data['Ticker'].iloc[0]]
            else:
                return ['Unknown']
    
    def resample(self, rule):
        """
        Resample data to a different frequency.
        
        Args:
            rule (str): Pandas resample rule like '1H', '1D', '1W'
        
        Returns:
            MarketData: New MarketData object with resampled data
        """
        if self.is_multi_ticker:
            resampled_data = {}
            for ticker, df in self.data.items():
                resampled_df = df.resample(rule).agg({
                    'Open': 'first',
                    'High': 'max',
                    'Low': 'min',
                    'Close': 'last',
                    'Volume': 'sum'
                })
                if 'Adj Close' in df.columns:
                    resampled_df['Adj Close'] = df['Adj Close'].resample(rule).last()
                if 'Ticker' in df.columns:
                    resampled_df['Ticker'] = df['Ticker'].iloc[0]
                resampled_data[ticker] = resampled_df
            return MarketData(resampled_data)
        else:
            resampled_df = self.data.resample(rule).agg({
                'Open': 'first',
                'High': 'max',
                'Low': 'min',
                'Close': 'last',
                'Volume': 'sum'
            })
            if 'Adj Close' in self.data.columns:
                resampled_df['Adj Close'] = self.data['Adj Close'].resample(rule).last()
            if 'Ticker' in self.data.columns:
                resampled_df['Ticker'] = self.data['Ticker'].iloc[0]
            return MarketData(resampled_df)
    
    def slice_dates(self, start_date=None, end_date=None):
        """
        Slice the data between specified dates.
        
        Args:
            start_date (str, optional): Start date in 'YYYY-MM-DD' format
            end_date (str, optional): End date in 'YYYY-MM-DD' format
        
        Returns:
            MarketData: New MarketData object with sliced data
        """
        if self.is_multi_ticker:
            sliced_data = {}
            for ticker, df in self.data.items():
                sliced_data[ticker] = df.loc[start_date:end_date]
            return MarketData(sliced_data)
        else:
            return MarketData(self.data.loc[start_date:end_date])

