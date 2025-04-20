import pandas as pd
import numpy as np
import yfinance as yf
import datetime
from math import floor, log, sqrt, exp
from scipy.stats import norm

def black_scholes(S, K, T, r, sigma, option_type='call'):
    """
    Calculate option price using Black-Scholes model
    
    Parameters:
    -----------
    S : float
        Current stock price
    K : float
        Strike price
    T : float
        Time to expiration in years
    r : float
        Risk-free interest rate
    sigma : float
        Volatility of the underlying asset
    option_type : str
        'call' or 'put'
    
    Returns:
    --------
    float
        Option price
    """
    # Apply safeguards to prevent division by zero
    T = max(0.001, T)  # At least 0.001 years (about 8.76 hours)
    sigma = max(0.001, sigma)  # At least 0.1% volatility
    
    d1 = (log(S/K) + (r + 0.5 * sigma**2) * T) / (sigma * sqrt(T))
    d2 = d1 - sigma * sqrt(T)
    
    if option_type == 'call':
        price = S * norm.cdf(d1) - K * exp(-r * T) * norm.cdf(d2)
    else:  # put
        price = K * exp(-r * T) * norm.cdf(-d2) - S * norm.cdf(-d1)
        
    return price

def generate_price_table(entry_price, stop_loss, take_profit, option_data, increment=0.50):
    """
    Generate a table of option prices at different underlying prices
    
    Parameters:
    -----------
    entry_price : float
        Entry price for the underlying
    stop_loss : float
        Stop loss price
    take_profit : float
        Take profit price
    option_data : dict
        Dictionary containing option data (strike, T, r, sigma, option_type)
    increment : float
        Price increment to use
    
    Returns:
    --------
    pandas.DataFrame
        Table of prices
    """
    # Extract required data
    strike = option_data['strike']
    T = option_data['T']
    r = option_data['r']
    sigma = option_data['sigma']
    option_type = option_data['option_type']
    premium = option_data['premium']
    
    # Generate price ranges (downward and upward from entry)
    # For stop loss (if below entry)
    if stop_loss < entry_price:
        # Generate prices from entry down to stop loss
        downward_range = np.arange(entry_price, stop_loss - increment/2, -increment)
        downward_range = np.append(downward_range, stop_loss)  # Add exact stop loss
        downward_range = downward_range[::-1]  # Reverse to go from lowest to highest
    else:
        downward_range = np.array([])
    
    # For take profit (if above entry)
    if take_profit > entry_price:
        # Generate prices from entry up to take profit
        upward_range = np.arange(entry_price + increment, take_profit + increment/2, increment)
        upward_range = np.append(upward_range, take_profit)  # Add exact take profit
    else:
        upward_range = np.array([])
    
    # For stop loss (if above entry)
    if stop_loss > entry_price:
        # Generate prices from entry up to stop loss
        upward_range = np.arange(entry_price + increment, stop_loss + increment/2, increment)
        upward_range = np.append(upward_range, stop_loss)  # Add exact stop loss
    
    # For take profit (if below entry)
    if take_profit < entry_price:
        # Generate prices from entry down to take profit
        downward_range = np.arange(entry_price, take_profit - increment/2, -increment)
        downward_range = np.append(downward_range, take_profit)  # Add exact take profit
        downward_range = downward_range[::-1]  # Reverse to go from lowest to highest
    
    # Combine ranges and add entry price
    price_range = np.concatenate([downward_range, np.array([entry_price]), upward_range])
    
    # Remove any duplicates and sort
    price_range = np.unique(price_range)
    price_range = [round(p, 2) for p in price_range]  # Round to 2 decimal places
    
    # Calculate option prices at each underlying price
    option_prices = [black_scholes(price, strike, T, r, sigma, option_type) for price in price_range]
    option_prices = [round(p, 2) for p in option_prices]
    
    # Get price at entry (for reference in calculations)
    entry_option_price = option_prices[np.where(np.array(price_range) == entry_price)[0][0]]
    
    # Calculate dollar change from entry price
    dollar_change = [round((price - entry_option_price) * 100, 2) for price in option_prices]
    
    # Calculate percent change from entry price
    percent_change = [round((price / entry_option_price - 1) * 100, 2) for price in option_prices]
    
    # Mark special points
    labels = [''] * len(price_range)
    entry_idx = np.where(np.array(price_range) == entry_price)[0][0]
    stop_idx = np.where(np.array(price_range) == stop_loss)[0][0]
    target_idx = np.where(np.array(price_range) == take_profit)[0][0]
    
    labels[entry_idx] = '← ENTRY'
    labels[stop_idx] = '← STOP'
    labels[target_idx] = '← TARGET'
    
    # Create a DataFrame
    df = pd.DataFrame({
        'Underlying': price_range,
        'Option Price': option_prices,
        'Dollar Change': dollar_change,
        'Percent Change': percent_change,
        '': labels
    })
    
    return df

def estimate_implied_volatility(option_price, S, K, T, r, option_type='call'):
    """
    Estimate implied volatility using bisection method
    """
    precision = 0.00001
    max_iterations = 100
    
    # Initial guesses for volatility
    sigma_low = 0.01
    sigma_high = 2.0  # 200% volatility as upper bound
    
    price_low = black_scholes(S, K, T, r, sigma_low, option_type)
    price_high = black_scholes(S, K, T, r, sigma_high, option_type)
    
    # Check if the option price is within our bounds
    if option_price <= price_low:
        return sigma_low
    if option_price >= price_high:
        return sigma_high
    
    # Bisection search
    for i in range(max_iterations):
        sigma_mid = (sigma_low + sigma_high) / 2
        price_mid = black_scholes(S, K, T, r, sigma_mid, option_type)
        
        if abs(price_mid - option_price) < precision:
            return sigma_mid
        
        if price_mid < option_price:
            sigma_low = sigma_mid
        else:
            sigma_high = sigma_mid
    
    return (sigma_low + sigma_high) / 2

def select_options(ticker, entry_price, stop_loss, take_profit, direction="long", 
                  account_size=5000, risk_percent=2, days_to_expiration=30, 
                  expiration_type=None, specific_date=None, show_price_table=True):
    """
    Select option contracts based on backtester signals using Black-Scholes pricing model.
    
    Parameters:
    -----------
    ticker : str
        Stock ticker symbol
    entry_price : float
        Entry price for the underlying
    stop_loss : float
        Stop loss price for the underlying
    take_profit : float
        Take profit/target price for the underlying
    direction : str
        'long' or 'short'
    account_size : float
        Total account size
    risk_percent : float
        Percentage of account willing to risk (e.g., 2 for 2%)
    days_to_expiration : int
        Target days to expiration for options
    expiration_type : str
        'daily', 'weekly', or 'monthly'. If None, will use days_to_expiration.
    specific_date : str
        Specific expiration date in format 'YYYY-MM-DD'. Takes precedence over days_to_expiration and expiration_type.
    show_price_table : bool
        Whether to show a table of option prices at different underlying prices
    
    Returns:
    --------
    dict
        Dictionary containing selected options information
    """
    print(f"Processing options for {ticker} signal:")
    print(f"Entry: ${entry_price:.2f}, Stop: ${stop_loss:.2f}, Target: ${take_profit:.2f}, Direction: {direction}")
    
    # Determine if we're using calls or puts
    if direction == "long":
        option_type = "call"
        # For long positions, stop is below entry, target is above
        max_loss_per_share = entry_price - stop_loss
    else:  # short
        option_type = "put"
        # For short positions, stop is above entry, target is below
        max_loss_per_share = stop_loss - entry_price
    
    print(f"Using {option_type}s options")
    
    # Get risk amount based on specified percentage (used as a reference only)
    risk_amount = account_size * (risk_percent / 100)
    print(f"Account size: ${account_size:.2f}")
    print(f"Reference risk amount ({risk_percent}%): ${risk_amount:.2f}")
    
    # Get stock info and options chain
    stock = yf.Ticker(ticker)
    
    # Get available expiration dates
    expiration_dates = stock.options
    
    if not expiration_dates:
        return {"error": "No options available for this ticker"}
    
    # Sort expiration dates
    expiration_dates = sorted(expiration_dates)
    
    # Find the appropriate expiration date
    if specific_date is not None:
        # Check if the specific date is available
        if specific_date in expiration_dates:
            closest_date = specific_date
        else:
            print(f"Specified date {specific_date} not available. Available dates: {expiration_dates}")
            # Find the closest date
            closest_date = min(expiration_dates, key=lambda x: abs((datetime.datetime.strptime(x, '%Y-%m-%d') - datetime.datetime.strptime(specific_date, '%Y-%m-%d')).days))
            print(f"Using closest available date: {closest_date}")
    
    elif expiration_type is not None:
        today = datetime.datetime.now().date()
        
        if expiration_type == 'daily':
            # For daily, find the next available expiration
            future_dates = [d for d in expiration_dates if datetime.datetime.strptime(d, '%Y-%m-%d').date() > today]
            closest_date = future_dates[0] if future_dates else expiration_dates[-1]
            
        elif expiration_type == 'weekly':
            # Convert dates to datetime objects
            exp_datetime_objects = [datetime.datetime.strptime(d, '%Y-%m-%d') for d in expiration_dates]
            
            # Filter for future dates
            future_dates = [d for d in exp_datetime_objects if d.date() > today]
            
            # Find weekly expirations (typically Friday)
            weekly_expirations = [d for d in future_dates if d.weekday() == 4]  # 4 is Friday
            
            if weekly_expirations:
                # Get the nearest weekly expiration
                closest_date = min(weekly_expirations, key=lambda x: abs((x.date() - today).days)).strftime('%Y-%m-%d')
            else:
                # If no weekly expirations, use the closest date
                closest_date = min(future_dates, key=lambda x: abs((x.date() - today).days)).strftime('%Y-%m-%d') if future_dates else expiration_dates[-1]
        
        elif expiration_type == 'monthly':
            # Monthly expirations are typically the third Friday of each month
            exp_datetime_objects = [datetime.datetime.strptime(d, '%Y-%m-%d') for d in expiration_dates]
            future_dates = [d for d in exp_datetime_objects if d.date() > today]
            
            # Find monthly expirations (3rd Friday of month)
            monthly_expirations = []
            for d in future_dates:
                # Check if it's a Friday
                if d.weekday() == 4:
                    # Calculate the day of the month for the 3rd Friday
                    third_friday_day = 15 + (4 - datetime.date(d.year, d.month, 15).weekday()) % 7
                    # If this date is the third Friday of the month
                    if d.day >= third_friday_day and d.day < third_friday_day + 7:
                        monthly_expirations.append(d)
            
            if monthly_expirations:
                closest_date = min(monthly_expirations, key=lambda x: abs((x.date() - today).days)).strftime('%Y-%m-%d')
            else:
                closest_date = min(future_dates, key=lambda x: abs((x.date() - today).days)).strftime('%Y-%m-%d') if future_dates else expiration_dates[-1]
        
        else:
            print(f"Unknown expiration_type: {expiration_type}. Using days_to_expiration instead.")
            target_date = datetime.datetime.now() + datetime.timedelta(days=days_to_expiration)
            closest_date = min(expiration_dates, key=lambda x: abs((datetime.datetime.strptime(x, '%Y-%m-%d') - target_date).days))
    
    else:
        # Use days_to_expiration to find the closest date
        target_date = datetime.datetime.now() + datetime.timedelta(days=days_to_expiration)
        closest_date = min(expiration_dates, key=lambda x: abs((datetime.datetime.strptime(x, '%Y-%m-%d') - target_date).days))
    
    exp_date = datetime.datetime.strptime(closest_date, '%Y-%m-%d')
    T = (exp_date - datetime.datetime.now()).days / 365.0  # Time to expiration in years
    
    print(f"Selected expiration date: {closest_date} (T={T:.3f} years)")
    
    # Print available expiration dates if user might want to choose a different one
    print(f"Available expiration dates: {', '.join(expiration_dates[:5])}{' ...' if len(expiration_dates) > 5 else ''}")
    
    # Get the options chain for our expiration
    options = stock.option_chain(closest_date)
    
    # Select either calls or puts based on direction
    if option_type == "call":
        chain = options.calls
    else:
        chain = options.puts
    
    # Get current stock price
    current_price = stock.info['regularMarketPrice']
    print(f"Current {ticker} price: ${current_price:.2f}")
    
    # Find ATM strike (closest to current price)
    atm_strike = chain.loc[(chain['strike'] - current_price).abs().idxmin()]['strike']
    
    # Find slightly OTM strike (about 2% OTM)
    if option_type == "call":
        target_otm_price = current_price * 1.02
    else:
        target_otm_price = current_price * 0.98
    
    otm_strike = chain.loc[(chain['strike'] - target_otm_price).abs().idxmin()]['strike']
    
    # Risk-free rate (approximate with 1-year Treasury yield)
    r = 0.05  # This should ideally be fetched from an API but using 5% as approximation
    
    # Calculate for ATM option
    atm_option = chain[chain['strike'] == atm_strike].iloc[0]
    atm_premium = atm_option['lastPrice']
    
    # Calculate implied volatility
    try:
        iv_atm = atm_option['impliedVolatility']
    except KeyError:
        # If implied volatility is not provided by the API, estimate it
        iv_atm = estimate_implied_volatility(atm_premium, current_price, atm_strike, T, r, option_type)
    
    # Estimate option price at stop loss
    # For very short-term options, Black-Scholes can sometimes underestimate the value
    # We'll use a more realistic approach for the minimum value
    theta_decay_factor = 0.7  # Assuming ~70% of extrinsic value remains at stop
    
    # Calculate intrinsic value at stop loss
    if option_type == "call":
        intrinsic_at_stop = max(0, stop_loss - atm_strike)
    else:
        intrinsic_at_stop = max(0, atm_strike - stop_loss)
    
    # Calculate extrinsic value and apply decay
    extrinsic_value = atm_premium - max(0, current_price - atm_strike if option_type == "call" else atm_strike - current_price)
    min_extrinsic_at_stop = extrinsic_value * theta_decay_factor
    
    # Theoretical price from Black-Scholes
    bs_price_at_stop = black_scholes(stop_loss, atm_strike, T, r, iv_atm, option_type)
    
    # Use the higher of the calculated minimum or the Black-Scholes price
    atm_price_at_stop = max(intrinsic_at_stop + min_extrinsic_at_stop, bs_price_at_stop)
    
    print(f"DEBUG ATM - Intrinsic: ${intrinsic_at_stop:.2f}, Min Extrinsic: ${min_extrinsic_at_stop:.2f}, BS: ${bs_price_at_stop:.2f}")
    
    # Calculate risk per contract for ATM
    if direction == "long":
        atm_risk_per_contract = (atm_premium - atm_price_at_stop) * 100
    else:
        atm_risk_per_contract = (atm_price_at_stop - atm_premium) * 100
    
    # Ensure risk per contract is positive
    atm_risk_per_contract = max(0.01, abs(atm_risk_per_contract))
    
    # Calculate cost per contract for ATM
    atm_cost_per_contract = atm_premium * 100
    
    # Calculate risk as percentage of account
    atm_risk_percent = (atm_risk_per_contract / account_size) * 100
    
    # Calculate max contracts based on available capital
    atm_contracts_capital = floor(account_size / atm_cost_per_contract)
    atm_contracts = min(atm_contracts_capital, floor(account_size * 0.5 / atm_cost_per_contract))  # Limit to 50% of account by default
    
    if atm_contracts < 1:
        atm_contracts = 0  # Cannot afford any contracts
    
    atm_total_cost = atm_contracts * atm_cost_per_contract
    atm_max_loss = atm_contracts * atm_risk_per_contract
    
    # Calculate total risk percentage of account
    atm_total_risk_percent = (atm_max_loss / account_size) * 100
    
    # Calculate for OTM option
    otm_option = chain[chain['strike'] == otm_strike].iloc[0]
    otm_premium = otm_option['lastPrice']
    
    # Calculate implied volatility for OTM
    try:
        iv_otm = otm_option['impliedVolatility']
    except KeyError:
        # If implied volatility is not provided by the API, estimate it
        iv_otm = estimate_implied_volatility(otm_premium, current_price, otm_strike, T, r, option_type)
    
    # Estimate option price at stop loss with more realistic assumptions
    # Calculate intrinsic value at stop loss for OTM
    if option_type == "call":
        intrinsic_at_stop_otm = max(0, stop_loss - otm_strike)
    else:
        intrinsic_at_stop_otm = max(0, otm_strike - stop_loss)
    
    # Calculate extrinsic value and apply decay for OTM
    extrinsic_value_otm = otm_premium - max(0, current_price - otm_strike if option_type == "call" else otm_strike - current_price)
    min_extrinsic_at_stop_otm = extrinsic_value_otm * theta_decay_factor
    
    # Theoretical price from Black-Scholes for OTM
    bs_price_at_stop_otm = black_scholes(stop_loss, otm_strike, T, r, iv_otm, option_type)
    
    # Use the higher of the calculated minimum or the Black-Scholes price for OTM
    otm_price_at_stop = max(intrinsic_at_stop_otm + min_extrinsic_at_stop_otm, bs_price_at_stop_otm)
    
    print(f"DEBUG OTM - Intrinsic: ${intrinsic_at_stop_otm:.2f}, Min Extrinsic: ${min_extrinsic_at_stop_otm:.2f}, BS: ${bs_price_at_stop_otm:.2f}")
    
    # Calculate risk per contract for OTM
    if direction == "long":
        otm_risk_per_contract = (otm_premium - otm_price_at_stop) * 100
    else:
        otm_risk_per_contract = (otm_price_at_stop - otm_premium) * 100
    
    # Ensure risk per contract is positive
    otm_risk_per_contract = max(0.01, abs(otm_risk_per_contract))
    
    # Calculate cost per contract for OTM
    otm_cost_per_contract = otm_premium * 100
    
    # Calculate risk as percentage of account
    otm_risk_percent = (otm_risk_per_contract / account_size) * 100
    
    # Calculate max contracts based on available capital
    otm_contracts_capital = floor(account_size / otm_cost_per_contract)
    otm_contracts = min(otm_contracts_capital, floor(account_size * 0.5 / otm_cost_per_contract))  # Limit to 50% of account by default
    
    if otm_contracts < 1:
        otm_contracts = 0  # Cannot afford any contracts
    
    otm_total_cost = otm_contracts * otm_cost_per_contract
    otm_max_loss = otm_contracts * otm_risk_per_contract
    
    # Calculate total risk percentage of account
    otm_total_risk_percent = (otm_max_loss / account_size) * 100
    
    # Estimate profit at target price
    atm_price_at_target = black_scholes(take_profit, atm_strike, T, r, iv_atm, option_type)
    otm_price_at_target = black_scholes(take_profit, otm_strike, T, r, iv_otm, option_type)
    
    if direction == "long":
        atm_profit_per_contract = (atm_price_at_target - atm_premium) * 100
        otm_profit_per_contract = (otm_price_at_target - otm_premium) * 100
    else:
        atm_profit_per_contract = (atm_premium - atm_price_at_target) * 100
        otm_profit_per_contract = (otm_premium - otm_price_at_target) * 100
    
    atm_profit = atm_contracts * atm_profit_per_contract
    otm_profit = otm_contracts * otm_profit_per_contract
    
    # Calculate return on capital (ROC)
    atm_roc = (atm_profit / atm_total_cost) * 100 if atm_total_cost > 0 else 0
    otm_roc = (otm_profit / otm_total_cost) * 100 if otm_total_cost > 0 else 0
    
    # Calculate risk-reward ratio
    atm_risk_reward = round(atm_profit / atm_max_loss, 2) if atm_max_loss > 0 else 0
    otm_risk_reward = round(otm_profit / otm_max_loss, 2) if otm_max_loss > 0 else 0
    
    # Create data for price tables
    atm_option_data = {
        'strike': atm_strike,
        'T': T,
        'r': r,
        'sigma': iv_atm,
        'option_type': option_type,
        'premium': atm_premium
    }
    
    otm_option_data = {
        'strike': otm_strike,
        'T': T,
        'r': r,
        'sigma': iv_otm,
        'option_type': option_type,
        'premium': otm_premium
    }
    
    # Generate price tables if requested
    if show_price_table:
        print("\n=== ATM OPTION PRICE TABLE ===")
        atm_price_table = generate_price_table(entry_price, stop_loss, take_profit, atm_option_data, increment=0.50)
        print(atm_price_table.to_string(index=False))
        
        print("\n=== OTM OPTION PRICE TABLE ===")
        otm_price_table = generate_price_table(entry_price, stop_loss, take_profit, otm_option_data, increment=0.50)
        print(otm_price_table.to_string(index=False))
    
    # Build result dictionary
    result = {
        "ticker": ticker,
        "direction": direction,
        "option_type": option_type,
        "expiration_date": closest_date,
        "atm_option": {
            "strike": atm_strike,
            "premium": atm_premium,
            "iv": iv_atm,
            "price_at_stop": atm_price_at_stop,
            "risk_per_contract": atm_risk_per_contract,
            "risk_percent_per_contract": atm_risk_percent,
            "cost_per_contract": atm_cost_per_contract,
            "max_contracts": atm_contracts,
            "total_cost": atm_total_cost,
            "max_loss": atm_max_loss,
            "total_risk_percent": atm_total_risk_percent,
            "price_at_target": atm_price_at_target,
            "profit": atm_profit,
            "return_on_capital": atm_roc,
            "risk_reward_ratio": atm_risk_reward,
            "price_table": atm_price_table if show_price_table else None
        },
        "otm_option": {
            "strike": otm_strike,
            "premium": otm_premium,
            "iv": iv_otm,
            "price_at_stop": otm_price_at_stop,
            "risk_per_contract": otm_risk_per_contract,
            "risk_percent_per_contract": otm_risk_percent,
            "cost_per_contract": otm_cost_per_contract,
            "max_contracts": otm_contracts,
            "total_cost": otm_total_cost,
            "max_loss": otm_max_loss,
            "total_risk_percent": otm_total_risk_percent,
            "price_at_target": otm_price_at_target,
            "profit": otm_profit,
            "return_on_capital": otm_roc,
            "risk_reward_ratio": otm_risk_reward,
            "price_table": otm_price_table if show_price_table else None
        }
    }
    
    # Print summary
    print("\n=== ATM OPTION SELECTION ===")
    print(f"Strike: ${atm_strike:.2f}")
    print(f"Premium: ${atm_premium:.2f} per share (${atm_premium * 100:.2f} per contract)")
    print(f"Est. price at stop loss: ${atm_price_at_stop:.2f}")
    print(f"Risk per contract: ${atm_risk_per_contract:.2f} ({atm_risk_percent:.2f}% of account)")
    print(f"Cost per contract: ${atm_cost_per_contract:.2f}")
    print(f"Max contracts affordable: {atm_contracts_capital}")
    print(f"Actual contracts to use: {atm_contracts}")
    print(f"Total cost: ${atm_total_cost:.2f} ({(atm_total_cost/account_size)*100:.2f}% of account)")
    print(f"Max loss at stop: ${atm_max_loss:.2f} ({atm_total_risk_percent:.2f}% of account)")
    print(f"Est. price at target: ${atm_price_at_target:.2f}")
    print(f"Profit at target: ${atm_profit:.2f}")
    print(f"Return on capital: {atm_roc:.2f}%")
    print(f"Risk/Reward ratio: {atm_risk_reward}")
    
    print("\n=== 2% OTM OPTION SELECTION ===")
    print(f"Strike: ${otm_strike:.2f}")
    print(f"Premium: ${otm_premium:.2f} per share (${otm_premium * 100:.2f} per contract)")
    print(f"Est. price at stop loss: ${otm_price_at_stop:.2f}")
    print(f"Risk per contract: ${otm_risk_per_contract:.2f} ({otm_risk_percent:.2f}% of account)")
    print(f"Cost per contract: ${otm_cost_per_contract:.2f}")
    print(f"Max contracts affordable: {otm_contracts_capital}")
    print(f"Actual contracts to use: {otm_contracts}")
    print(f"Total cost: ${otm_total_cost:.2f} ({(otm_total_cost/account_size)*100:.2f}% of account)")
    print(f"Max loss at stop: ${otm_max_loss:.2f} ({otm_total_risk_percent:.2f}% of account)")
    print(f"Est. price at target: ${otm_price_at_target:.2f}")
    print(f"Profit at target: ${otm_profit:.2f}")
    print(f"Return on capital: {otm_roc:.2f}%")
    print(f"Risk/Reward ratio: {otm_risk_reward}")
    
    return result


# Example usage
if __name__ == "__main__":
    # Example from your backtester output
    result = select_options(
        ticker="SPY", 
        entry_price=510.26, 
        stop_loss=505.28, 
        take_profit=530.03, 
        direction="long", 
        account_size=5000, 
        risk_percent=2,
        # Uncomment one of the following to select specific expiration type:
        #expiration_type="daily",       # For 0DTE or nearest daily options
        expiration_type="weekly",      # For weekly Friday expirations
        # expiration_type="monthly",     # For monthly options (3rd Friday)
        # specific_date="2025-04-15",    # For a specific expiration date
    )
    
    # To use this function from another file:
    # from options_selector import select_options
    # result = select_options(ticker, entry_price, stop_loss, take_profit, direction, account_size, risk_percent)