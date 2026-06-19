# data/data_loader.py
import yfinance as yf
import pandas as pd
from datetime import datetime, timedelta

class DataLoader:
    """
    Handles downloading and processing of financial data from various sources.
    Currently supports Yahoo Finance, but designed to be extendable to other APIs.
    """
    
    def __init__(self, data_source='yahoo'):
        """
        Initialize the DataLoader with a specified data source.
        
        Args:
            data_source (str): The source to fetch data from ('yahoo', 'alpha_vantage', etc.)
        """
        self.data_source = data_source
        
    def get_historical_data(self, ticker, start_date, end_date=None, interval='1d'):
        """
        Fetch historical price data for a given ticker.
        
        Args:
            ticker (str): The ticker symbol (e.g., 'AAPL', 'SPY')
            start_date (str): Start date in 'YYYY-MM-DD' format
            end_date (str, optional): End date in 'YYYY-MM-DD' format. Defaults to today.
            interval (str, optional): Data frequency. Defaults to '1d' (daily).
                Options: '1m', '2m', '5m', '15m', '30m', '60m', '90m', '1h', '1d', '5d', '1wk', '1mo', '3mo'
        
        Returns:
            pd.DataFrame: Historical price data with OHLCV and adjusted close
        """
        if end_date is None:
            end_date = datetime.now().strftime('%Y-%m-%d')
            
        if self.data_source == 'yahoo':
            data = yf.download(ticker, start=start_date, end=end_date, interval=interval)
            
            # Ensure all required columns exist and handle any missing data
            required_columns = ['Open', 'High', 'Low', 'Close', 'Volume']
            for col in required_columns:
                if col not in data.columns:
                    raise ValueError(f"Missing required column {col} in data")
            
            # Forward fill any missing data
            data = data.ffill()
            
            # Add ticker column for multi-ticker support
            data['Ticker'] = ticker
            
            return data
        else:
            raise NotImplementedError(f"Data source {self.data_source} not implemented.")
    
    def get_multi_ticker_data(self, tickers, start_date, end_date=None, interval='1d'):
        """
        Fetch historical data for multiple tickers and combine them.
        
        Args:
            tickers (list): List of ticker symbols
            start_date (str): Start date in 'YYYY-MM-DD' format
            end_date (str, optional): End date in 'YYYY-MM-DD' format
            interval (str, optional): Data frequency. Defaults to '1d'
        
        Returns:
            dict: Dictionary with tickers as keys and DataFrames as values
        """
        data_dict = {}
        
        for ticker in tickers:
            try:
                data = self.get_historical_data(ticker, start_date, end_date, interval)
                data_dict[ticker] = data
            except Exception as e:
                print(f"Error fetching data for {ticker}: {e}")
        
        return data_dict

