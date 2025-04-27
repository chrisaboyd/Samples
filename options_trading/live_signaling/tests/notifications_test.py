import os
import json
import requests
import pandas as pd
from datetime import datetime
import pytz
import dotenv

# Load environment variables
dotenv.load_dotenv()
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

def test_discord_notification():
    """Test sending a formatted signal notification to Discord"""
    if not DISCORD_WEBHOOK_URL:
        print("Error: DISCORD_WEBHOOK_URL not found in environment variables")
        return False
    
    # Create a sample signal that matches what our strategies would produce
    sample_signal = {
        'signal': 'buy',
        'entry_price': 154.25,
        'stop_loss': 152.75,
        'profit_target': 157.25,
        'ema_short': 155.32,
        'ema_mid': 153.87,
        'ema_long': 150.42,
        'orb_high': 154.50,
        'reversal': False,
        'rsi': 58.7,  # Sample RSI value
        'vwap': 154.10  # Sample VWAP value
    }
    
    # Test data
    strategy_name = "ORB_VolBreak"
    ticker = "AAPL"
    
    try:
        # Extract signal data
        signal_type = sample_signal['signal']
        signal_emoji = "🟢" if signal_type == 'buy' else "🔴"
        
        # Format all numeric values to two decimal places
        entry_price = f"${sample_signal['entry_price']:.2f}"
        stop_loss = f"${sample_signal['stop_loss']:.2f}"
        profit_target = f"${sample_signal['profit_target']:.2f}"
        
        # Add emojis for stop loss and target
        stop_emoji = "🛑" # Stop sign emoji
        target_emoji = "🎯" # Target emoji
        
        # Calculate risk/reward
        risk = abs(sample_signal['entry_price'] - sample_signal['stop_loss'])
        reward = abs(sample_signal['profit_target'] - sample_signal['entry_price'])
        risk_reward = f"{(reward / risk if risk > 0 else 0):.2f}"
        
        # Get RSI value if available
        rsi_value = "N/A"
        if 'rsi' in sample_signal and sample_signal['rsi'] is not None:
            rsi_emoji = "📊" # Chart emoji
            rsi_value = f"{sample_signal['rsi']:.1f}"
            # Add color indicators for RSI
            if sample_signal['rsi'] >= 70:
                rsi_value += " 🔴" # Overbought
            elif sample_signal['rsi'] <= 30:
                rsi_value += " 🟢" # Oversold
        
        # Build embedded message with the requested fields
        embed = {
            "title": f"{strategy_name} - {ticker}",
            "color": 65280 if signal_type == 'buy' else 16711680,  # Green for buy, Red for sell
            "fields": [
                {
                    "name": "Signal",
                    "value": f"{signal_emoji} **{signal_type.upper()}**",
                    "inline": True
                },
                {
                    "name": "Entry Price",
                    "value": entry_price,
                    "inline": True
                },
                {
                    "name": f"{stop_emoji} Stop Loss",
                    "value": stop_loss,
                    "inline": True
                },
                {
                    "name": f"{target_emoji} Target",
                    "value": profit_target,
                    "inline": True
                },
                {
                    "name": "Risk/Reward",
                    "value": risk_reward,
                    "inline": True
                },
                {
                    "name": f"{rsi_emoji} RSI",
                    "value": rsi_value,
                    "inline": True
                }
            ],
            "footer": {
                "text": f"Time: {datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M:%S ET')}"
            }
        }
        
        # Send to Discord
        payload = {
            "embeds": [embed]
        }
        
        print("Sending test notification to Discord...")
        response = requests.post(
            DISCORD_WEBHOOK_URL, 
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        
        print(f"Successfully sent notification to Discord! Status code: {response.status_code}")
        return True
        
    except Exception as e:
        print(f"Error sending notification: {e}")
        return False

def test_sell_signal():
    """Test sending a sell signal notification to Discord"""
    if not DISCORD_WEBHOOK_URL:
        print("Error: DISCORD_WEBHOOK_URL not found in environment variables")
        return False
    
    # Create a sample sell signal
    sample_signal = {
        'signal': 'sell',
        'entry_price': 187.50,
        'stop_loss': 189.25,
        'profit_target': 184.00,
        'ema_short': 187.12,
        'ema_mid': 188.45,
        'ema_long': 190.18,
        'orb_low': 186.75,
        'reversal': True,
        'rsi': 72.3,  # Sample RSI value - overbought
        'vwap': 187.80  # Sample VWAP value
    }
    
    # Test data
    strategy_name = "Trending_EMA"
    ticker = "META"
    
    try:
        # Extract signal data
        signal_type = sample_signal['signal']
        signal_emoji = "🟢" if signal_type == 'buy' else "🔴"
        
        # Format all numeric values to two decimal places
        entry_price = f"${sample_signal['entry_price']:.2f}"
        stop_loss = f"${sample_signal['stop_loss']:.2f}"
        profit_target = f"${sample_signal['profit_target']:.2f}"
        
        # Add emojis for stop loss and target
        stop_emoji = "🛑" # Stop sign emoji
        target_emoji = "🎯" # Target emoji
        
        # Calculate risk/reward
        risk = abs(sample_signal['entry_price'] - sample_signal['stop_loss'])
        reward = abs(sample_signal['profit_target'] - sample_signal['entry_price'])
        risk_reward = f"{(reward / risk if risk > 0 else 0):.2f}"
        
        # Get RSI value if available
        rsi_value = "N/A"
        if 'rsi' in sample_signal and sample_signal['rsi'] is not None:
            rsi_emoji = "📊" # Chart emoji
            rsi_value = f"{sample_signal['rsi']:.1f}"
            # Add color indicators for RSI
            if sample_signal['rsi'] >= 70:
                rsi_value += " 🔴" # Overbought
            elif sample_signal['rsi'] <= 30:
                rsi_value += " 🟢" # Oversold
        
        # Build embedded message with the requested fields
        embed = {
            "title": f"{strategy_name} - {ticker}",
            "color": 65280 if signal_type == 'buy' else 16711680,  # Green for buy, Red for sell
            "fields": [
                {
                    "name": "Signal",
                    "value": f"{signal_emoji} **{signal_type.upper()}**",
                    "inline": True
                },
                {
                    "name": "Entry Price",
                    "value": entry_price,
                    "inline": True
                },
                {
                    "name": f"{stop_emoji} Stop Loss",
                    "value": stop_loss,
                    "inline": True
                },
                {
                    "name": f"{target_emoji} Target",
                    "value": profit_target,
                    "inline": True
                },
                {
                    "name": "Risk/Reward",
                    "value": risk_reward,
                    "inline": True
                },
                {
                    "name": f"{rsi_emoji} RSI",
                    "value": rsi_value,
                    "inline": True
                }
            ],
            "footer": {
                "text": f"Time: {datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M:%S ET')}"
            }
        }
        
        # Send to Discord
        payload = {
            "embeds": [embed]
        }
        
        print("Sending test SELL notification to Discord...")
        response = requests.post(
            DISCORD_WEBHOOK_URL, 
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        
        print(f"Successfully sent SELL notification to Discord! Status code: {response.status_code}")
        return True
        
    except Exception as e:
        print(f"Error sending notification: {e}")
        return False

def test_bollinger_breakout_signal():
    """Test sending a Bollinger Band Breakout signal to Discord"""
    if not DISCORD_WEBHOOK_URL:
        print("Error: DISCORD_WEBHOOK_URL not found in environment variables")
        return False
    
    # Create a sample Bollinger Breakout Buy signal
    sample_signal = {
        'signal': 'buy',
        'entry_price': 425.75,
        'stop_loss': 419.50,
        'profit_target': 436.25,
        'profit_target2': 446.50,
        'atr': 5.25,
        'bb_breakout': 430.50,
        'breakout_price': 428.75,
        'rsi': 58.4,
        'vwap': 424.80
    }
    
    # Test data
    strategy_name = "BB_Breakout"
    ticker = "NVDA"
    
    try:
        # Extract signal data
        signal_type = sample_signal['signal']
        signal_emoji = "🟢" if signal_type == 'buy' else "🔴"
        
        # Format all numeric values to two decimal places
        entry_price = f"${sample_signal['entry_price']:.2f}"
        stop_loss = f"${sample_signal['stop_loss']:.2f}"
        profit_target = f"${sample_signal['profit_target']:.2f}"
        profit_target2 = f"${sample_signal['profit_target2']:.2f}"
        
        # Add emojis for stop loss and target
        stop_emoji = "🛑" # Stop sign emoji
        target_emoji = "🎯" # Target emoji
        bb_emoji = "📈" # Chart with upwards trend
        
        # Calculate risk/reward
        risk = abs(sample_signal['entry_price'] - sample_signal['stop_loss'])
        reward = abs(sample_signal['profit_target'] - sample_signal['entry_price'])
        risk_reward = f"{(reward / risk if risk > 0 else 0):.2f}"
        
        # Get RSI value if available
        rsi_value = "N/A"
        if 'rsi' in sample_signal and sample_signal['rsi'] is not None:
            rsi_emoji = "📊" # Chart emoji
            rsi_value = f"{sample_signal['rsi']:.1f}"
            # Add color indicators for RSI
            if sample_signal['rsi'] >= 70:
                rsi_value += " 🔴" # Overbought
            elif sample_signal['rsi'] <= 30:
                rsi_value += " 🟢" # Oversold
        
        # Build embedded message with the requested fields
        embed = {
            "title": f"{strategy_name} - {ticker}",
            "description": "Bollinger Band Breakout detected with volatility expansion",
            "color": 65280 if signal_type == 'buy' else 16711680,  # Green for buy, Red for sell
            "fields": [
                {
                    "name": "Signal",
                    "value": f"{signal_emoji} **{signal_type.upper()}**",
                    "inline": True
                },
                {
                    "name": "Entry Price",
                    "value": entry_price,
                    "inline": True
                },
                {
                    "name": f"{stop_emoji} Stop Loss",
                    "value": stop_loss,
                    "inline": True
                },
                {
                    "name": f"{target_emoji} Target 1 (1×ATR)",
                    "value": profit_target,
                    "inline": True
                },
                {
                    "name": f"{target_emoji} Target 2 (2×ATR)",
                    "value": profit_target2,
                    "inline": True
                },
                {
                    "name": "Risk/Reward",
                    "value": risk_reward,
                    "inline": True
                },
                {
                    "name": f"{bb_emoji} Breakout Level",
                    "value": f"${sample_signal['breakout_price']:.2f}",
                    "inline": True
                },
                {
                    "name": f"{rsi_emoji} RSI",
                    "value": rsi_value,
                    "inline": True
                }
            ],
            "footer": {
                "text": f"Time: {datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M:%S ET')}"
            }
        }
        
        # Send to Discord
        payload = {
            "embeds": [embed]
        }
        
        print("Sending Bollinger Breakout notification to Discord...")
        response = requests.post(
            DISCORD_WEBHOOK_URL, 
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        
        print(f"Successfully sent Bollinger Breakout notification to Discord! Status code: {response.status_code}")
        return True
        
    except Exception as e:
        print(f"Error sending notification: {e}")
        return False

def test_bollinger_reversal_signal():
    """Test sending a Bollinger Band Reversal signal to Discord"""
    if not DISCORD_WEBHOOK_URL:
        print("Error: DISCORD_WEBHOOK_URL not found in environment variables")
        return False
    
    # Create a sample Bollinger Reversal Sell signal
    sample_signal = {
        'signal': 'sell',
        'entry_price': 128.75,
        'stop_loss': 132.50,
        'profit_target': 122.25,
        'profit_target2': 117.80,
        'pattern': 'Shooting Star',
        'bb_upper': 130.25,
        'bb_middle': 125.10,
        'bb_lower': 119.95,
        'reversal_price': 129.30,
        'day_high': 132.75,
        'day_low': 127.80,
        'rsi': 73.5,
        'vwap': 129.10
    }
    
    # Test data
    strategy_name = "BB_Reversal"
    ticker = "AAPL"
    
    try:
        # Extract signal data
        signal_type = sample_signal['signal']
        signal_emoji = "🟢" if signal_type == 'buy' else "🔴"
        
        # Format all numeric values to two decimal places
        entry_price = f"${sample_signal['entry_price']:.2f}"
        stop_loss = f"${sample_signal['stop_loss']:.2f}"
        profit_target = f"${sample_signal['profit_target']:.2f}"
        profit_target2 = f"${sample_signal['profit_target2']:.2f}"
        
        # Add emojis for stop loss and target
        stop_emoji = "🛑" # Stop sign emoji
        target_emoji = "🎯" # Target emoji
        pattern_emoji = "🔄" # Reversal pattern emoji
        
        # Calculate risk/reward
        risk = abs(sample_signal['entry_price'] - sample_signal['stop_loss'])
        reward = abs(sample_signal['profit_target'] - sample_signal['entry_price'])
        risk_reward = f"{(reward / risk if risk > 0 else 0):.2f}"
        
        # Get RSI value if available
        rsi_value = "N/A"
        if 'rsi' in sample_signal and sample_signal['rsi'] is not None:
            rsi_emoji = "📊" # Chart emoji
            rsi_value = f"{sample_signal['rsi']:.1f}"
            # Add color indicators for RSI
            if sample_signal['rsi'] >= 70:
                rsi_value += " 🔴" # Overbought
            elif sample_signal['rsi'] <= 30:
                rsi_value += " 🟢" # Oversold
        
        # Build embedded message with the requested fields
        embed = {
            "title": f"{strategy_name} - {ticker}",
            "description": f"Bollinger Band Reversal with {sample_signal['pattern']} pattern",
            "color": 65280 if signal_type == 'buy' else 16711680,  # Green for buy, Red for sell
            "fields": [
                {
                    "name": "Signal",
                    "value": f"{signal_emoji} **{signal_type.upper()}**",
                    "inline": True
                },
                {
                    "name": "Entry Price",
                    "value": entry_price,
                    "inline": True
                },
                {
                    "name": f"{stop_emoji} Stop Loss",
                    "value": stop_loss,
                    "inline": True
                },
                {
                    "name": f"{target_emoji} Target 1 (Mid)",
                    "value": profit_target,
                    "inline": True
                },
                {
                    "name": f"{target_emoji} Target 2 (Band)",
                    "value": profit_target2,
                    "inline": True
                },
                {
                    "name": "Risk/Reward",
                    "value": risk_reward,
                    "inline": True
                },
                {
                    "name": f"{pattern_emoji} Pattern",
                    "value": sample_signal['pattern'],
                    "inline": True
                },
                {
                    "name": f"{rsi_emoji} RSI",
                    "value": rsi_value,
                    "inline": True
                }
            ],
            "footer": {
                "text": f"Time: {datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M:%S ET')}"
            }
        }
        
        # Send to Discord
        payload = {
            "embeds": [embed]
        }
        
        print("Sending Bollinger Reversal notification to Discord...")
        response = requests.post(
            DISCORD_WEBHOOK_URL, 
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        
        print(f"Successfully sent Bollinger Reversal notification to Discord! Status code: {response.status_code}")
        return True
        
    except Exception as e:
        print(f"Error sending notification: {e}")
        return False

if __name__ == "__main__":
    print("Running Discord notification tests...")
    
    # Test buy signal
    buy_result = test_discord_notification()
    
    # Test sell signal
    sell_result = test_sell_signal()
    
    # Test Bollinger Breakout signal
    bb_breakout_result = test_bollinger_breakout_signal()
    
    # Test Bollinger Reversal signal
    bb_reversal_result = test_bollinger_reversal_signal()
    
    # Check if all tests passed
    if buy_result and sell_result and bb_breakout_result and bb_reversal_result:
        print("All tests passed!")
    else:
        print("Some tests failed, please check the error messages above.")