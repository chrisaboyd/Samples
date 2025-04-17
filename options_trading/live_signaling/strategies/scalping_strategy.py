import pandas as pd
from .base_strategy import LiveStrategy

class LiveScalpingStrategy(LiveStrategy):
    def __init__(self):
        super().__init__("Scalping")
        self.parameters.update({
            'price_movement_threshold': 0.0005,
            'volume_ma_period': 3,
            'volume_threshold': 1.5,
            'min_volume': 5000,
            'macd_fast': 5,
            'macd_slow': 13,
            'macd_signal': 5
        })
        
    def calculate_indicators(self, data: pd.DataFrame) -> pd.DataFrame:
        df = data.copy()
        
        # Calculate price change
        df['price_change'] = df['close'].pct_change()
        
        # Volume indicators
        df['volume_ma'] = df['volume'].rolling(
            window=self.parameters['volume_ma_period']).mean()
        df['volume_ratio'] = df['volume'] / df['volume_ma']
        
        # MACD
        df['ema_fast'] = df['close'].ewm(
            span=self.parameters['macd_fast'], adjust=False).mean()
        df['ema_slow'] = df['close'].ewm(
            span=self.parameters['macd_slow'], adjust=False).mean()
        df['macd'] = df['ema_fast'] - df['ema_slow']
        df['macd_signal'] = df['macd'].ewm(
            span=self.parameters['macd_signal'], adjust=False).mean()
        
        return df
        
    def generate_signal(self, ticker: str, current_data: pd.DataFrame) -> dict:
        if ticker not in self.data_buffer:
            return {'signal': None}
            
        # Calculate indicators
        indicators = self.calculate_indicators(current_data)
        latest = indicators.iloc[-1]
        
        price_movement = abs(latest['price_change']) > self.parameters['price_movement_threshold']
        volume_spike = latest['volume_ratio'] > self.parameters['volume_threshold']
        sufficient_volume = latest['volume'] > self.parameters['min_volume']
        
        if price_movement and volume_spike and sufficient_volume:
            if (latest['price_change'] > 0 and 
                latest['macd'] > latest['macd_signal']):
                return {
                    'signal': 'buy',
                    'entry_price': float(latest['close']),
                    'volume_ratio': float(latest['volume_ratio']),
                    'price_change': float(latest['price_change'])
                }
                
            if (latest['price_change'] < 0 and 
                latest['macd'] < latest['macd_signal']):
                return {
                    'signal': 'sell',
                    'entry_price': float(latest['close']),
                    'volume_ratio': float(latest['volume_ratio']),
                    'price_change': float(latest['price_change'])
                }
                
        return {'signal': None} 