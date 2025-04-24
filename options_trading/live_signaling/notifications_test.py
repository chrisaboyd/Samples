import requests
import json
from dotenv import load_dotenv
import os

def test_discord_notification():
    # Your Discord webhook URL
    # Load the webhook URL from the .env file
    load_dotenv()
    webhook_url = os.getenv("WEBHOOK_URL")
    
    # Sample signal dictionary (using your provided structure)
    test_signal = {
        'signal': 'sell',
        'entry_price': 120.75,
        'stop_loss': 115.50,
        'profit_target': 125.25,
        'orb_high': 122.30, 
        'orb_low': 118.45
    }
    
    # Test strategy and ticker
    strategy_name = "ORB Strategy"
    ticker = "AAPL"
    
    # Set color based on signal type (red for sell)
    color = 0xFF0000  # Bright red for sell signal
    
    # Create rich embed
    embed = {
        "title": f"{strategy_name} - {ticker}",
        "description": f"Signal: **{test_signal['signal'].upper()}**",
        "color": color,
        "fields": [
            {"name": "Entry Price", "value": str(test_signal['entry_price']), "inline": True},
            {"name": "Stop Loss", "value": str(test_signal['stop_loss']), "inline": True},
            {"name": "Profit Target", "value": str(test_signal['profit_target']), "inline": True},
            {"name": "ORB High", "value": str(test_signal['orb_high']), "inline": True},
            {"name": "ORB Low", "value": str(test_signal['orb_low']), "inline": True}
        ]
    }
    
    payload = {
        "embeds": [embed]
    }
    
    # Send the webhook request
    try:
        response = requests.post(
            webhook_url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        print(f"Test notification sent successfully! Status code: {response.status_code}")
        return True
    except Exception as e:
        print(f"Failed to send test notification: {e}")
        return False

if __name__ == "__main__":
    print("Sending test Discord notification...")
    test_discord_notification()