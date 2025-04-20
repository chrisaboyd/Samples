from dataclasses import dataclass
import numpy as np
from scipy.stats import norm

@dataclass
class OptionInputs:
    spot_price: float       # Underlying price (S)
    strike_price: float     # Strike price (K)
    iv: float               # Implied volatility (σ, as a decimal)
    risk_free_rate: float   # Annual risk-free rate (r, as a decimal)
    T: float                # Time to expiration in years (e.g., 74/365)
    option_type: str        # 'call' or 'put'

@dataclass
class OptionGreeks:
    price: float
    delta: float
    gamma: float
    theta: float  # Theta per day
    vega: float   # Vega per 1% change in IV

def black_scholes_full(inputs: OptionInputs) -> OptionGreeks:
    """
    Calculate the Black-Scholes price and Greeks using the inputs provided.
    Time to expiration is assumed to be in years already.
    """
    S = inputs.spot_price
    K = inputs.strike_price
    T = inputs.T
    r = inputs.risk_free_rate
    sigma = inputs.iv
    option_type = inputs.option_type.lower()

    d1 = (np.log(S / K) + (r + 0.5 * sigma**2) * T) / (sigma * np.sqrt(T))
    d2 = d1 - sigma * np.sqrt(T)

    if option_type == 'call':
        price = S * norm.cdf(d1) - K * np.exp(-r * T) * norm.cdf(d2)
        delta = norm.cdf(d1)
        theta = - (S * norm.pdf(d1) * sigma) / (2 * np.sqrt(T)) - r * K * np.exp(-r * T) * norm.cdf(d2)
    elif option_type == 'put':
        price = K * np.exp(-r * T) * norm.cdf(-d2) - S * norm.cdf(-d1)
        delta = norm.cdf(d1) - 1
        theta = - (S * norm.pdf(d1) * sigma) / (2 * np.sqrt(T)) + r * K * np.exp(-r * T) * norm.cdf(-d2)
    else:
        raise ValueError("option_type must be 'call' or 'put'")

    gamma = norm.pdf(d1) / (S * sigma * np.sqrt(T))
    vega = S * norm.pdf(d1) * np.sqrt(T)

    # Convert theta to per day (assuming 365 days in a year)
    return OptionGreeks(
        price=price,
        delta=delta,
        gamma=gamma,
        theta=theta / 365,
        vega=vega / 100
    )

def display_option_greeks(greeks: OptionGreeks, optionInputs: OptionInputs):
    print("\n📊 Option Pricing & Greeks")
    print("-" * 35)
    print(f"{'Estimated Price ($)':<25}: {greeks.price:.4f}")
    print(f"{'Delta':<25}: {greeks.delta:.4f}")
    print(f"{'Gamma':<25}: {greeks.gamma:.4f}")
    print(f"{'Theta (per day)':<25}: {greeks.theta:.4f}")
    print(f"{'Vega (per 1% IV)':<25}: {greeks.vega:.4f}")
    print(f"{'Spot Price':<25}: {optionInputs.spot_price:.4f}")
    print(f"{'Strike Price':<25}: {optionInputs.strike_price:.4f}")


# === EXAMPLE USAGE ===
# Define your option inputs (time to expiry is already in years)
optionInputs = OptionInputs(
    spot_price = 160,             # Current SPY price
    strike_price = 160,           # Option strike
    T = 91 / 365,                 # 74 days to expiration, in years
    risk_free_rate = 0.04,        # 4% annual risk-free rate
    iv = 0.7943,                  # Implied volatility (83.23% - note this is unusually high)
    option_type = 'put'
)

# Calculate the option price and Greeks
result = black_scholes_full(optionInputs)
display_option_greeks(result, optionInputs)
