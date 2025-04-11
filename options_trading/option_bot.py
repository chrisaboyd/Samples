import os
import time
import json
import requests
import logging
import discord
from dotenv import load_dotenv
import discord_bot as discord_bot
from discord.ext import commands
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("trading_bot.log"), 
                              logging.StreamHandler()])
logger = logging.getLogger()

# Load environment variables
load_dotenv()
TASTYTRADE_USERNAME = os.getenv("TASTYTRADE_USERNAME")
TASTYTRADE_PASSWORD = os.getenv("TASTYTRADE_PASSWORD")
TASTYTRADE_ACCOUNT_ID = os.getenv("TASTYTRADE_ACCOUNT_ID")
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")

# API Base URL
TASTYTRADE_MODE = os.getenv("TASTYTRADE_MODE")
API_PROD_URL = "https://api.tastytrade.com"
API_SANDBOX_URL = "https://api.cert.tastyworks.com"
SESSION_TOKEN = None

if TASTYTRADE_MODE == "sandbox":
    API_BASE_URL = API_SANDBOX_URL
else:
    API_BASE_URL = API_PROD_URL

class TastytradeAPI:
    def __init__(self):
        self.session = requests.Session()
        self.token = None
        self.logged_in = False
        self.active_orders = {}
        
    def login(self):
        """Login to Tastytrade account"""
        try:
            # Login endpoint
            login_url = f"{API_BASE_URL}/sessions"
            
            # Payload for login
            payload = {
                "login": TASTYTRADE_USERNAME,
                "password": TASTYTRADE_PASSWORD
            }
            
            # Make login request
            response = self.session.post(login_url, json=payload)
            response.raise_for_status()
            
            # Extract session token
            data = response.json()
            self.token = data['data']['session-token']
            
            # Add token to headers for future requests
            self.session.headers.update({"Authorization": self.token})
            
            self.logged_in = True
            logger.info("Successfully logged into Tastytrade")
            return True
            
        except Exception as e:
            logger.error(f"Login failed: {str(e)}")
            return False
    
    def get_account_info(self):
        """Get account information"""
        if not self.logged_in:
            if not self.login():
                return None
                
        try:
            url = f"{API_BASE_URL}/customers/me/accounts/{TASTYTRADE_ACCOUNT_ID}"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.error(f"Error getting account info: {str(e)}")
            return None
    
    def get_quote(self, symbol):
        """Get current quote for a symbol"""
        if not self.logged_in:
            if not self.login():
                return None
                
        try:
            url = f"{API_BASE_URL}/quotes/symbols/{symbol}"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()['data']
            
        except Exception as e:
            logger.error(f"Error getting quote for {symbol}: {str(e)}")
            return None
    
    def get_option_chain(self, symbol):
        """Get option chain for a symbol"""
        if not self.logged_in:
            if not self.login():
                return None
                
        try:
            # First get expiration dates
            url = f"{API_BASE_URL}/options-chains/{symbol}/expirations"
            response = self.session.get(url)
            response.raise_for_status()
            
            expirations = response.json()['data']['items']
            if not expirations:
                logger.error(f"No expirations found for {symbol}")
                return None
                
            # Sort by date and take the nearest one (but at least 2 days out)
            today = datetime.now().date()
            valid_dates = [
                exp for exp in expirations 
                if (datetime.strptime(exp['expiration-date'], '%Y-%m-%d').date() - today).days >= 2
            ]
            
            if not valid_dates:
                logger.error(f"No valid expiration dates found for {symbol}")
                return None
                
            # Sort and take the nearest expiration
            valid_dates.sort(key=lambda x: x['expiration-date'])
            expiration = valid_dates[0]['expiration-date']
            
            # Now get the option chain for this expiration
            url = f"{API_BASE_URL}/options-chains/{symbol}/nested"
            params = {"expiration": expiration}
            
            response = self.session.get(url, params=params)
            response.raise_for_status()
            
            return response.json()['data']['items']
            
        except Exception as e:
            logger.error(f"Error getting option chain for {symbol}: {str(e)}")
            return None
    
    def find_closest_option(self, symbol, target_price, direction="CALL"):
        """Find the closest option strike to the target price"""
        try:
            # Get current market data
            quote = self.get_quote(symbol)
            if not quote:
                return None
                
            current_price = float(quote['last'])
            logger.info(f"Current price for {symbol}: ${current_price}")
            
            # Get options chain
            option_chain = self.get_option_chain(symbol)
            if not option_chain:
                return None
            
            # Extract all strikes
            all_strikes = []
            for exp_date in option_chain:
                for strike_data in exp_date['strikes']:
                    strike_price = float(strike_data['strike-price'])
                    
                    # Get the appropriate option side
                    option_data = None
                    if direction.upper() == "CALL":
                        option_data = strike_data.get('call')
                    else:
                        option_data = strike_data.get('put')
                        
                    if option_data:
                        all_strikes.append({
                            'symbol': option_data['symbol'],
                            'strike_price': strike_price,
                            'bid': float(option_data.get('bid', 0)),
                            'ask': float(option_data.get('ask', 0)),
                            'expiration': exp_date['expiration-date'],
                            'direction': direction.upper()
                        })
            
            # Find closest strike to target
            if all_strikes:
                closest_option = min(all_strikes, key=lambda x: abs(x['strike_price'] - target_price))
                logger.info(f"Found closest {direction} option: Strike=${closest_option['strike_price']}")
                return closest_option
            else:
                logger.error(f"No valid options found for {symbol}")
                return None
                
        except Exception as e:
            logger.error(f"Error finding closest option: {str(e)}")
            return None
    
    def place_option_order(self, option_data, quantity=1):
        """Place an option buy order"""
        if not self.logged_in:
            if not self.login():
                return None
                
        try:
            url = f"{API_BASE_URL}/accounts/{TASTYTRADE_ACCOUNT_ID}/orders"
            
            # Prepare order payload
            payload = {
                "account-id": TASTYTRADE_ACCOUNT_ID,
                "source": "API",
                "order-type": "Market",
                "time-in-force": "Day",
                "legs": [
                    {
                        "instrument-type": "Equity Option",
                        "symbol": option_data['symbol'],
                        "action": "Buy to Open",
                        "quantity": quantity
                    }
                ]
            }
            
            # Submit order
            response = self.session.post(url, json=payload)
            response.raise_for_status()
            order_response = response.json()
            
            # Extract order ID
            order_id = order_response['data']['order-id']
            
            # Store order info for monitoring
            self.active_orders[order_id] = {
                'symbol': option_data['symbol'],
                'underlying': option_data.get('underlying', ''),
                'target_price': option_data['strike_price'],
                'direction': option_data['direction'],
                'entry_time': datetime.now().isoformat(),
                'status': 'OPEN'
            }
            
            logger.info(f"Order placed successfully: {order_id}")
            return order_id
            
        except Exception as e:
            logger.error(f"Error placing option order: {str(e)}")
            return None
    
    def sell_option_position(self, order_id):
        """Close an option position"""
        if not self.logged_in:
            if not self.login():
                return False
                
        try:
            # Get the order details
            order_info = self.active_orders.get(order_id)
            if not order_info:
                logger.error(f"Order {order_id} not found")
                return False
                
            url = f"{API_BASE_URL}/accounts/{TASTYTRADE_ACCOUNT_ID}/orders"
            
            # Prepare order payload for selling
            payload = {
                "account-id": TASTYTRADE_ACCOUNT_ID,
                "source": "API",
                "order-type": "Market",
                "time-in-force": "Day",
                "legs": [
                    {
                        "instrument-type": "Equity Option",
                        "symbol": order_info['symbol'],
                        "action": "Sell to Close",
                        "quantity": 1  # Assuming quantity was 1 when bought
                    }
                ]
            }
            
            # Submit sell order
            response = self.session.post(url, json=payload)
            response.raise_for_status()
            
            # Update order status
            self.active_orders[order_id]['status'] = 'CLOSED'
            self.active_orders[order_id]['exit_time'] = datetime.now().isoformat()
            
            logger.info(f"Position closed for order {order_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error closing position: {str(e)}")
            return False
    
    def check_exit_conditions(self):
        """Check if any positions need to be closed based on price targets"""
        for order_id, order_info in list(self.active_orders.items()):
            if order_info['status'] != 'OPEN':
                continue
                
            # Extract underlying symbol from the option symbol
            # This is a simplified approach - actual extraction depends on the symbol format
            underlying = order_info.get('underlying')
            if not underlying:
                # Try to extract from symbol - this is approximate and may need adjustment
                parts = order_info['symbol'].split('_')
                if len(parts) > 0:
                    underlying = parts[0]
                else:
                    logger.error(f"Could not determine underlying for {order_info['symbol']}")
                    continue
            
            target_price = order_info['target_price']
            option_type = order_info['direction']
            
            # Get current stock price
            try:
                quote = self.get_quote(underlying)
                if not quote:
                    continue
                    
                current_price = float(quote['last'])
                
                # Check exit condition (1$ off target)
                if (option_type == 'CALL' and current_price >= target_price - 1) or \
                   (option_type == 'PUT' and current_price <= target_price + 1):
                    
                    # Close the position
                    logger.info(f"Exit condition met for {underlying} {option_type} order {order_id}")
                    success = self.sell_option_position(order_id)
                    if success:
                        logger.info(f"Position closed at price: ${current_price}")
                    else:
                        logger.error(f"Failed to close position for order {order_id}")
            
            except Exception as e:
                logger.error(f"Error checking exit condition: {str(e)}")
    
    def execute_trade(self, symbol, target_price, direction):
        """Main method to execute a trade based on signal"""
        if not self.logged_in:
            if not self.login():
                return {"success": False, "message": "Failed to login"}
        
        # Determine option direction
        option_type = "CALL" if direction.upper() in ["CALL", "BUY", "LONG"] else "PUT"
        
        # Find appropriate option
        option_data = self.find_closest_option(symbol, target_price, option_type)
        if not option_data:
            return {"success": False, "message": f"Could not find appropriate option for {symbol} target {target_price}"}
        
        # Add underlying symbol to option data for later reference
        option_data['underlying'] = symbol
            
        # Place order
        order_id = self.place_option_order(option_data)
        if not order_id:
            return {"success": False, "message": "Failed to place order"}
            
        return {"success": True, "message": f"Order placed successfully: {order_id}", "order_id": order_id}
    
    def get_positions(self):
        """Get current positions"""
        return self.active_orders

# Discord Bot Setup
intents = discord.Intents.default()
intents.message_content = True  # Enable message content

bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

# Initialize API
tastytrade_api = TastytradeAPI()

@bot.event
async def on_ready():
    """Event handler when Discord bot is ready"""
    logger.info(f'Logged in as {bot.user.name} ({bot.user.id})')
    print(f'Bot is ready: {bot.user.name}')
    
    # Login to Tastytrade
    if tastytrade_api.login():
        print("Successfully logged into Tastytrade API")
    else:
        print("Failed to login to Tastytrade API")
    
    # Start monitoring thread
    bot.loop.create_task(monitoring_loop())

async def monitoring_loop():
    """Background task to monitor positions"""
    await bot.wait_until_ready()
    while not bot.is_closed():
        try:
            tastytrade_api.check_exit_conditions()
            await asyncio.sleep(30)  # Check every 30 seconds
        except Exception as e:
            logger.error(f"Error in monitoring loop: {str(e)}")
            await asyncio.sleep(60)  # Wait longer on error

@bot.command(name='trade')
async def trade_command(ctx, symbol: str, target_price: float, direction: str):
    """Command to execute a trade
    Example: !trade SPY 430 CALL
    """
    await ctx.send(f"Processing trade: {symbol} with target ${target_price}, direction {direction}")
    
    result = tastytrade_api.execute_trade(symbol, target_price, direction)
    
    if result["success"]:
        await ctx.send(f"✅ {result['message']}")
    else:
        await ctx.send(f"❌ {result['message']}")

@bot.command(name='status')
async def status_command(ctx):
    """Command to check active positions"""
    positions = tastytrade_api.get_positions()
    
    if not positions:
        await ctx.send("No active positions found")
        return
        
    status_message = "**Current Positions:**\n"
    for order_id, info in positions.items():
        status_message += f"- **Order {order_id}**: {info['symbol']} {info['direction']} @ ${info['target_price']}, Status: {info['status']}\n"
    
    await ctx.send(status_message)

@bot.command(name='account')
async def account_command(ctx):
    """Command to check account information"""
    account_info = tastytrade_api.get_account_info()
    
    if not account_info:
        await ctx.send("Failed to retrieve account information")
        return
        
    # Extract relevant account data
    try:
        data = account_info['data']
        account_number = data['account-number']
        buying_power = data.get('buying-power', 'N/A')
        cash_balance = data.get('cash-balance', 'N/A')
        
        message = f"**Account Information:**\n"
        message += f"- **Account Number**: {account_number}\n"
        message += f"- **Buying Power**: ${buying_power}\n"
        message += f"- **Cash Balance**: ${cash_balance}\n"
        
        await ctx.send(message)
    except Exception as e:
        await ctx.send(f"Error processing account information: {str(e)}")
        
@bot.command(name='help')
async def help_command(ctx):
    """Show available commands"""
    help_text = """
**Trading Bot Commands:**
`!trade <symbol> <target_price> <direction>` - Execute a trade (Example: !trade SPY 430 CALL)
`!status` - Check active positions
`!account` - View account information
`!help` - Show this help message
"""
    await ctx.send(help_text)

# Run the Discord bot
import asyncio

if __name__ == "__main__":
    logger.debug("Starting bot...")
    if not DISCORD_TOKEN:
        logger.error("Error: DISCORD_TOKEN not found in environment variables")
        exit(1)
    
    print("Starting bot... Press Ctrl+C to exit.")
    bot.run(DISCORD_TOKEN)