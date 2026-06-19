import os
import discord
from discord.ext import commands
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")

# Set up the bot with intents
intents = discord.Intents.default()  # Note: Using discord, not discord_bot
intents.message_content = True  # Needed to read message content
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

@bot.event
async def on_ready():
    """Event handler when Discord bot is ready"""
    print(f'Bot is connected to Discord as {bot.user.name} ({bot.user.id})')
    print(f'Bot is active in these servers:')
    for guild in bot.guilds:
        print(f'- {guild.name} (ID: {guild.id})')

@bot.command(name='ping')
async def ping_command(ctx):
    """Simple command to test if the bot is responsive"""
    await ctx.send('Pong! Bot is working!')

@bot.command(name='echo')
async def echo_command(ctx, *, message):
    """Echoes back whatever the user sends"""
    await ctx.send(f'You said: {message}')

@bot.command(name='help')
async def help_command(ctx):
    """Show available commands"""
    help_text = """
**Trading Bot Commands:**
`!ping` - Check if bot is responsive
`!echo <message>` - Bot will echo your message
`!help` - Show this help message

*Trading functionality will be added soon!*
"""
    await ctx.send(help_text)

# Run the Discord bot
if __name__ == "__main__":
    # Check if Discord token is available
    if not DISCORD_TOKEN:
        print("Error: DISCORD_TOKEN not found in environment variables")
        exit(1)
    
    print("Starting bot... Press Ctrl+C to exit.")
    bot.run(DISCORD_TOKEN)