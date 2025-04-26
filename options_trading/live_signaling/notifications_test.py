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
        'reversal': False
    }
    
    # Test data
    strategy_name = "ORB_EMA"
    ticker = "AAPL"
    
    try:
        # Format all numeric values to two decimal places
        entry_price = f"${sample_signal['entry_price']:.2f}"
        stop_loss = f"${sample_signal['stop_loss']:.2f}"
        profit_target = f"${sample_signal['profit_target']:.2f}"
        
        # Format EMAs to two decimal places
        ema_short = f"{sample_signal.get('ema_short', 0):.2f}"
        ema_mid = f"{sample_signal.get('ema_mid', 0):.2f}"
        ema_long = f"{sample_signal.get('ema_long', 0):.2f}"
        
        # Format orb levels
        orb_high = f"${sample_signal.get('orb_high', 0):.2f}" if 'orb_high' in sample_signal else "N/A"
        orb_low = f"${sample_signal.get('orb_low', 0):.2f}" if 'orb_low' in sample_signal else "N/A"
        
        # Current price (use entry price since that's current price at signal)
        current_price = f"${sample_signal['entry_price']:.2f}"
        
        # Calculate risk/reward
        risk = abs(sample_signal['entry_price'] - sample_signal['stop_loss'])
        reward = abs(sample_signal['profit_target'] - sample_signal['entry_price'])
        risk_reward = f"{(reward / risk if risk > 0 else 0):.2f}"
        
        # Check if this is a reversal
        reversal = sample_signal.get('reversal', False)
        reversal_text = "True" if reversal else "False"
        
        # Signal emoji based on type
        emoji = "🟢" if sample_signal['signal'] == 'buy' else "🔴"
        
        # Build embedded message
        embed = {
            "title": f"{strategy_name} - {ticker}",
            "color": 65280 if sample_signal['signal'] == 'buy' else 16711680,  # Green for buy, Red for sell
            "fields": [
                {
                    "name": "Signal",
                    "value": f"{emoji} **{sample_signal['signal'].upper()}**",
                    "inline": True
                },
                {
                    "name": "Price",
                    "value": current_price,
                    "inline": True
                },
                {
                    "name": "Entry_price",
                    "value": entry_price,
                    "inline": True
                },
                {
                    "name": "Stop_loss",
                    "value": stop_loss,
                    "inline": True
                },
                {
                    "name": "Profit_target",
                    "value": profit_target,
                    "inline": True
                },
                {
                    "name": "Risk/Reward",
                    "value": risk_reward,
                    "inline": True
                },
                {
                    "name": "Ema_mid",
                    "value": ema_mid,
                    "inline": True
                },
                {
                    "name": "Ema_short",
                    "value": ema_short,
                    "inline": True
                },
                {
                    "name": "Ema_long",
                    "value": ema_long,
                    "inline": True
                }
            ],
            "footer": {
                "text": f"Time: {datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M:%S ET')}"
            }
        }
        
        # Add ORB levels based on signal type
        if sample_signal['signal'] == 'buy':
            embed["fields"].append({
                "name": "Orb_high",
                "value": orb_high,
                "inline": True
            })
        else:
            embed["fields"].append({
                "name": "Orb_low",
                "value": orb_low,
                "inline": True
            })
            
        # Add reversal field
        embed["fields"].append({
            "name": "Reversal",
            "value": reversal_text,
            "inline": True
        })
        
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
        'reversal': True
    }
    
    # Test data
    strategy_name = "ORB_EMA"
    ticker = "META"
    
    try:
        # Format all numeric values to two decimal places
        entry_price = f"${sample_signal['entry_price']:.2f}"
        stop_loss = f"${sample_signal['stop_loss']:.2f}"
        profit_target = f"${sample_signal['profit_target']:.2f}"
        
        # Format EMAs to two decimal places
        ema_short = f"{sample_signal.get('ema_short', 0):.2f}"
        ema_mid = f"{sample_signal.get('ema_mid', 0):.2f}"
        ema_long = f"{sample_signal.get('ema_long', 0):.2f}"
        
        # Format orb levels
        orb_high = f"${sample_signal.get('orb_high', 0):.2f}" if 'orb_high' in sample_signal else "N/A"
        orb_low = f"${sample_signal.get('orb_low', 0):.2f}" if 'orb_low' in sample_signal else "N/A"
        
        # Current price (use entry price since that's current price at signal)
        current_price = f"${sample_signal['entry_price']:.2f}"
        
        # Calculate risk/reward
        risk = abs(sample_signal['entry_price'] - sample_signal['stop_loss'])
        reward = abs(sample_signal['profit_target'] - sample_signal['entry_price'])
        risk_reward = f"{(reward / risk if risk > 0 else 0):.2f}"
        
        # Check if this is a reversal
        reversal = sample_signal.get('reversal', False)
        reversal_text = "True" if reversal else "False"
        
        # Signal emoji based on type
        emoji = "🟢" if sample_signal['signal'] == 'buy' else "🔴"
        
        # Build embedded message
        embed = {
            "title": f"{strategy_name} - {ticker}",
            "color": 65280 if sample_signal['signal'] == 'buy' else 16711680,  # Green for buy, Red for sell
            "fields": [
                {
                    "name": "Signal",
                    "value": f"{emoji} **{sample_signal['signal'].upper()}**",
                    "inline": True
                },
                {
                    "name": "Price",
                    "value": current_price,
                    "inline": True
                },
                {
                    "name": "Entry_price",
                    "value": entry_price,
                    "inline": True
                },
                {
                    "name": "Stop_loss",
                    "value": stop_loss,
                    "inline": True
                },
                {
                    "name": "Profit_target",
                    "value": profit_target,
                    "inline": True
                },
                {
                    "name": "Risk/Reward",
                    "value": risk_reward,
                    "inline": True
                },
                {
                    "name": "Ema_mid",
                    "value": ema_mid,
                    "inline": True
                },
                {
                    "name": "Ema_short",
                    "value": ema_short,
                    "inline": True
                },
                {
                    "name": "Ema_long",
                    "value": ema_long,
                    "inline": True
                }
            ],
            "footer": {
                "text": f"Time: {datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M:%S ET')}"
            }
        }
        
        # Add ORB levels based on signal type
        if sample_signal['signal'] == 'buy':
            embed["fields"].append({
                "name": "Orb_high",
                "value": orb_high,
                "inline": True
            })
        else:
            embed["fields"].append({
                "name": "Orb_low",
                "value": orb_low,
                "inline": True
            })
            
        # Add reversal field
        embed["fields"].append({
            "name": "Reversal",
            "value": reversal_text,
            "inline": True
        })
        
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