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

if __name__ == "__main__":
    print("Running Discord notification tests...")
    
    # Test buy signal
    buy_result = test_discord_notification()
    
    # Test sell signal
    sell_result = test_sell_signal()
    
    if buy_result and sell_result:
        print("All tests passed!")
    else:
        print("Some tests failed, please check the error messages above.")