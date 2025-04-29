import numpy as np
import pandas as pd

def detect_trend(data, short_period=5, long_period=15):
    """
    Comprehensive trend detection using multiple methods
    
    Args:
        data: DataFrame with price data
        short_period: Short-term period (5 days)
        long_period: Long-term period (15 days)
        
    Returns:
        Dictionary with trend assessments and overall score
    """
    # Calculate various trend indicators
    sma_trend_short = is_trending_with_sma(data, window=short_period)
    sma_trend_long = is_trending_with_sma(data, window=long_period)
    
    ema_signal = detect_ema_crossover(data, fast_period=short_period, slow_period=long_period)
    
    linear_trend_short = linear_regression_trend(data, period=short_period)
    linear_trend_long = linear_regression_trend(data, period=long_period)
    
    structure_short = analyze_price_structure(data, period=short_period)
    structure_long = analyze_price_structure(data, period=long_period)
    
    adx_result = calculate_adx(data)
    
    # Weight and combine indicators for an overall score
    # Higher weights for more reliable indicators in your specific context
    weights = {
        'sma_short': 0.5,
        'sma_long': 1.0,
        'ema_signal': 1.0,
        'linear_short': 0.75,
        'linear_long': 1.5,
        'structure_short': 0.5,
        'structure_long': 1.0,
        'adx': 1.5
    }
    
    trend_score = (
        weights['sma_short'] * sma_trend_short +
        weights['sma_long'] * sma_trend_long +
        weights['ema_signal'] * ema_signal +
        weights['linear_short'] * linear_trend_short['trend'] +
        weights['linear_long'] * linear_trend_long['trend'] +
        weights['structure_short'] * structure_short +
        weights['structure_long'] * structure_long +
        weights['adx'] * adx_result['trend']
    )
    
    # Normalize the score to a range of -10 to 10
    max_possible_score = sum(weights.values())
    normalized_score = (trend_score / max_possible_score) * 10
    
    # Determine overall trend category
    if normalized_score > 7:
        overall_trend = "Strong Uptrend"
    elif normalized_score > 3:
        overall_trend = "Moderate Uptrend"
    elif normalized_score > 0:
        overall_trend = "Weak Uptrend"
    elif normalized_score > -3:
        overall_trend = "Weak Downtrend"
    elif normalized_score > -7:
        overall_trend = "Moderate Downtrend"
    else:
        overall_trend = "Strong Downtrend"
    
    return {
        'short_term_indicators': {
            'sma': sma_trend_short,
            'linear_regression': linear_trend_short,
            'price_structure': structure_short
        },
        'long_term_indicators': {
            'sma': sma_trend_long,
            'linear_regression': linear_trend_long,
            'price_structure': structure_long
        },
        'crossover_signals': {
            'ema_crossover': ema_signal
        },
        'strength_indicators': {
            'adx': adx_result
        },
        'overall_score': normalized_score,
        'trend_rating': overall_trend
    }


def calculate_adx(data, period=14):
    """
    Calculate ADX for trend strength and direction
    
    Args:
        data: DataFrame with 'high', 'low', and 'close' prices
        period: Period for ADX calculation
        
    Returns:
        Dictionary with ADX, +DI, -DI, and trend assessment
    """
    # Make a copy of the data to avoid warnings
    df = data.copy()
    
    # Calculate True Range (TR)
    tr1 = abs(df['high'] - df['low'])
    tr2 = abs(df['high'] - df['close'].shift(1))
    tr3 = abs(df['low'] - df['close'].shift(1))
    df['tr'] = pd.concat([tr1, tr2, tr3], axis=1).max(axis=1)
    
    # Calculate +DM and -DM
    high_diff = df['high'] - df['high'].shift(1)
    low_diff = df['low'].shift(1) - df['low']
    
    df['+dm'] = np.where(
        (high_diff > low_diff) & (high_diff > 0),
        high_diff,
        0
    )
    
    df['-dm'] = np.where(
        (low_diff > high_diff) & (low_diff > 0),
        low_diff,
        0
    )
    
    # Calculate smoothed TR, +DM, and -DM
    df['smoothed_tr'] = df['tr'].rolling(period).sum()
    df['smoothed_+dm'] = df['+dm'].rolling(period).sum()
    df['smoothed_-dm'] = df['-dm'].rolling(period).sum()
    
    # Calculate +DI and -DI
    df['+di'] = 100 * df['smoothed_+dm'] / df['smoothed_tr']
    df['-di'] = 100 * df['smoothed_-dm'] / df['smoothed_tr']
    
    # Calculate DX
    df['dx'] = 100 * abs(df['+di'] - df['-di']) / (df['+di'] + df['-di'])
    
    # Calculate ADX
    df['adx'] = df['dx'].rolling(period).mean()
    
    # Get the latest values
    adx = df['adx'].iloc[-1]
    plus_di = df['+di'].iloc[-1]
    minus_di = df['-di'].iloc[-1]
    
    # Determine trend
    if adx > 25:
        if plus_di > minus_di:
            trend = 1  # Strong uptrend
        else:
            trend = -1  # Strong downtrend
    elif adx > 20:
        if plus_di > minus_di:
            trend = 0.5  # Moderate uptrend
        else:
            trend = -0.5  # Moderate downtrend
    else:
        trend = 0  # No strong trend
    
    return {
        'adx': adx,
        'plus_di': plus_di,
        'minus_di': minus_di,
        'trend': trend
    }


def analyze_price_structure(data, period=5):
    """
    Analyze price structure for Higher Highs/Higher Lows or Lower Highs/Lower Lows
    
    Args:
        data: DataFrame with 'high' and 'low' prices
        period: Number of days to analyze
        
    Returns:
        1 for uptrend, -1 for downtrend, 0 for no clear trend
    """
    # Extract relevant data
    highs = data['high'].iloc[-period:].values
    lows = data['low'].iloc[-period:].values
    
    # Divide the period in half for comparison
    mid_point = period // 2
    
    # Check for Higher Highs and Higher Lows
    higher_high = max(highs[mid_point:]) > max(highs[:mid_point])
    higher_low = min(lows[mid_point:]) > min(lows[:mid_point])
    
    # Check for Lower Highs and Lower Lows
    lower_high = max(highs[mid_point:]) < max(highs[:mid_point])
    lower_low = min(lows[mid_point:]) < min(lows[:mid_point])
    
    # Determine trend
    if higher_high and higher_low:
        return 1  # Uptrend
    elif lower_high and lower_low:
        return -1  # Downtrend
    else:
        return 0  # No clear trend
    

def linear_regression_trend(data, period=5):
    """
    Calculate trend direction and strength using linear regression
    
    Args:
        data: DataFrame with 'close' prices
        period: Number of days for regression (5 or 15)
        
    Returns:
        Dictionary with slope, r_squared, and trend direction
    """
    import numpy as np
    from scipy import stats
    
    # Get the last n days of prices
    prices = data['close'].iloc[-period:].values
    x = np.arange(period)
    
    # Calculate linear regression
    slope, intercept, r_value, p_value, std_err = stats.linregress(x, prices)
    
    # Normalize slope as percentage of average price
    avg_price = prices.mean()
    norm_slope = slope / avg_price
    
    # Calculate trend strength via R-squared
    r_squared = r_value ** 2
    
    # Determine trend
    if norm_slope > 0.003 and r_squared > 0.6:
        trend = 1  # Strong uptrend
    elif norm_slope > 0.001:
        trend = 0.5  # Weak uptrend
    elif norm_slope < -0.003 and r_squared > 0.6:
        trend = -1  # Strong downtrend
    elif norm_slope < -0.001:
        trend = -0.5  # Weak downtrend
    else:
        trend = 0  # No trend
        
    return {
        'slope': norm_slope,
        'r_squared': r_squared,
        'trend': trend
    }


def detect_ema_crossover(data, fast_period=5, slow_period=15):
    """
    Detect trend based on EMA crossovers
    
    Args:
        data: DataFrame with 'close' prices
        fast_period: Fast EMA period
        slow_period: Slow EMA period
        
    Returns:
        1 for uptrend, -1 for downtrend, 0 for no recent crossover
    """
    # Calculate EMAs
    data['ema_fast'] = data['close'].ewm(span=fast_period, adjust=False).mean()
    data['ema_slow'] = data['close'].ewm(span=slow_period, adjust=False).mean()
    
    # Current relationship
    current_relation = data['ema_fast'].iloc[-1] > data['ema_slow'].iloc[-1]
    
    # Previous relationship (5 days ago)
    previous_relation = data['ema_fast'].iloc[-6] > data['ema_slow'].iloc[-6]
    
    # Detect crossover
    if current_relation and not previous_relation:
        return 1  # Bullish crossover (uptrend starting)
    elif not current_relation and previous_relation:
        return -1  # Bearish crossover (downtrend starting)
    elif current_relation:
        return 0.5  # Continuing uptrend
    else:
        return -0.5  # Continuing downtrend
    

def is_trending_with_sma(data, window=5, threshold=0.01):
    """
    Determine if price is trending using SMA slope
    
    Args:
        data: DataFrame with 'close' prices
        window: Period for SMA calculation (5 or 15 days)
        threshold: Minimum slope to consider a valid trend
        
    Returns:
        1 for uptrend, -1 for downtrend, 0 for no trend
    """
    # Calculate SMA
    data['sma'] = data['close'].rolling(window=window).mean()
    
    # Calculate the slope of the SMA
    sma_slope = (data['sma'].iloc[-1] - data['sma'].iloc[-window]) / window
    
    # Normalize slope as percentage of price
    normalized_slope = sma_slope / data['close'].iloc[-1]
    
    # Determine trend
    if normalized_slope > threshold:
        return 1  # Uptrend
    elif normalized_slope < -threshold:
        return -1  # Downtrend
    else:
        return 0  # No significant trend