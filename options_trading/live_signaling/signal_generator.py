from alpaca.data.live import StockDataStream
from alpaca.trading.client import TradingClient
from alpaca.data.historical import StockHistoricalDataClient
from alpaca.data.requests import StockBarsRequest
from alpaca.data.timeframe import TimeFrame
import pandas as pd
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, date, timedelta
import pytz
import requests
import json
import os
import dotenv
import atexit
import pickle
from strategies.base_strategy import LiveStrategy
import uuid
from options_analyzer import OptionsAnalyzer
from strategies.trending_ema_strategy import Trending_EMA

# Enhanced logging setup with custom formatter
class CustomFormatter(logging.Formatter):
    def format(self, record):
        if getattr(record, 'is_signal', False):
            # Don't add timestamp for signal parts
            return record.getMessage()
        # Add timestamp for regular messages
        return f"{self.formatTime(record)} - {record.levelname} - {record.getMessage()}"

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(CustomFormatter())
logger.handlers = [handler]

class Trade:
    """
    Represents a single trade with entry/exit information and status tracking
    """
    def __init__(self, 
                 ticker: str, 
                 strategy_name: str, 
                 trade_type: str, 
                 entry_price: float, 
                 stop_loss: float, 
                 take_profit: float,
                 quantity: float = 1.0,
                 entry_time: Optional[datetime] = None):
        """
        Initialize a new trade
        
        Args:
            ticker: Symbol being traded
            strategy_name: Name of the strategy that generated the signal
            trade_type: 'buy' (long) or 'sell' (short)
            entry_price: Entry price for the trade
            stop_loss: Stop loss price level
            take_profit: Take profit price level
            quantity: Size of the position (default 1)
            entry_time: When the trade was entered (default: now)
        """
        self.id = str(uuid.uuid4())[:8]  # Generate a unique trade ID
        self.ticker = ticker
        self.strategy_name = strategy_name
        self.trade_type = trade_type
        
        # Price levels
        self.entry_price = entry_price
        self.stop_loss = stop_loss
        self.take_profit = take_profit
        self.exit_price = None
        
        # Trade status
        self.entry_time = entry_time if entry_time else datetime.now()
        self.exit_time = None
        self.quantity = quantity
        self.status = "open"  # 'open', 'closed', 'canceled'
        self.exit_reason = None  # 'take_profit', 'stop_loss', 'manual', etc.
        
        # Risk metrics
        self.risk_per_share = abs(entry_price - stop_loss)
        self.reward_per_share = abs(take_profit - entry_price)
        self.risk_reward_ratio = self.reward_per_share / self.risk_per_share if self.risk_per_share > 0 else 0
        
        # Calculate risk as a percentage
        if trade_type == 'buy':
            self.risk_percent = (entry_price - stop_loss) / entry_price * 100
            self.reward_percent = (take_profit - entry_price) / entry_price * 100
        else:  # sell/short
            self.risk_percent = (stop_loss - entry_price) / entry_price * 100
            self.reward_percent = (entry_price - take_profit) / entry_price * 100

    def close(self, exit_price: float, exit_time: Optional[datetime] = None, reason: str = "manual"):
        """
        Close the trade with an exit price and reason
        
        Args:
            exit_price: Price at which the trade was closed
            exit_time: When the trade was closed (default: now)
            reason: Why the trade was closed
        
        Returns:
            float: P&L of the trade
        """
        self.exit_price = exit_price
        self.exit_time = exit_time if exit_time else datetime.now()
        self.status = "closed"
        self.exit_reason = reason
        
        # Calculate raw P&L
        if self.trade_type == 'buy':
            pnl = (exit_price - self.entry_price) * self.quantity
        else:  # sell/short
            pnl = (self.entry_price - exit_price) * self.quantity
            
        # Calculate P&L as a percentage
        if self.entry_price > 0:
            if self.trade_type == 'buy':
                self.pnl_percent = (exit_price - self.entry_price) / self.entry_price * 100
            else:  # sell/short
                self.pnl_percent = (self.entry_price - exit_price) / self.entry_price * 100
        else:
            self.pnl_percent = 0
            
        self.pnl = pnl
        self.duration = self.exit_time - self.entry_time
        
        return pnl
        
    def check_exit_conditions(self, current_price: float, current_time: datetime) -> Optional[str]:
        """
        Check if the trade should be closed based on current price
        
        Args:
            current_price: The current market price
            current_time: Current timestamp
            
        Returns:
            Optional[str]: Exit reason if conditions are met, None otherwise
        """
        if self.status != "open":
            return None
            
        # Check stop loss
        if self.trade_type == 'buy' and current_price <= self.stop_loss:
            return "stop_loss"
        elif self.trade_type == 'sell' and current_price >= self.stop_loss:
            return "stop_loss"
            
        # Check take profit
        if self.trade_type == 'buy' and current_price >= self.take_profit:
            return "take_profit"
        elif self.trade_type == 'sell' and current_price <= self.take_profit:
            return "take_profit"
            
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert trade to dictionary for storage
        
        Returns:
            Dict: Serializable dictionary of trade data
        """
        return {
            'id': self.id,
            'ticker': self.ticker,
            'strategy_name': self.strategy_name,
            'trade_type': self.trade_type,
            'entry_price': self.entry_price,
            'stop_loss': self.stop_loss,
            'take_profit': self.take_profit,
            'exit_price': self.exit_price,
            'entry_time': self.entry_time.isoformat() if self.entry_time else None,
            'exit_time': self.exit_time.isoformat() if self.exit_time else None,
            'quantity': self.quantity,
            'status': self.status,
            'exit_reason': self.exit_reason,
            'risk_per_share': self.risk_per_share,
            'reward_per_share': self.reward_per_share,
            'risk_reward_ratio': self.risk_reward_ratio,
            'risk_percent': self.risk_percent,
            'reward_percent': self.reward_percent,
            'pnl': getattr(self, 'pnl', None),
            'pnl_percent': getattr(self, 'pnl_percent', None),
            'duration': str(getattr(self, 'duration', None))
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Trade':
        """
        Create a Trade object from a dictionary
        
        Args:
            data: Dictionary with trade data
            
        Returns:
            Trade: Reconstructed Trade object
        """
        # Create a new Trade object
        trade = cls(
            ticker=data['ticker'],
            strategy_name=data['strategy_name'],
            trade_type=data['trade_type'],
            entry_price=data['entry_price'],
            stop_loss=data['stop_loss'],
            take_profit=data['take_profit'],
            quantity=data['quantity'],
            entry_time=datetime.fromisoformat(data['entry_time']) if data['entry_time'] else None
        )
        
        # Set additional fields
        trade.id = data['id']
        trade.exit_price = data['exit_price']
        trade.exit_time = datetime.fromisoformat(data['exit_time']) if data['exit_time'] else None
        trade.status = data['status']
        trade.exit_reason = data['exit_reason']
        
        if data.get('pnl') is not None:
            trade.pnl = data['pnl']
        if data.get('pnl_percent') is not None:
            trade.pnl_percent = data['pnl_percent']
        if data.get('duration') is not None:
            trade.duration = timedelta(seconds=0)  # Placeholder
            
        return trade

class TradeTracker:
    """
    Tracks open and closed trades, calculates statistics, and persists trade data
    """
    def __init__(self):
        """Initialize a new trade tracker"""
        self.open_trades: Dict[str, Trade] = {}  # Trade ID -> Trade
        self.closed_trades: List[Trade] = []
        
        # Statistics
        self.total_trades = 0
        self.winning_trades = 0
        self.losing_trades = 0
        self.break_even_trades = 0
        self.total_pnl = 0.0
        self.win_rate = 0.0
        self.avg_profit = 0.0
        self.avg_loss = 0.0
        self.avg_win_loss_ratio = 0.0
        self.avg_risk_reward = 0.0
        self.best_trade = 0.0
        self.worst_trade = 0.0
        self.avg_trade_duration = timedelta(0)
        self.last_updated = datetime.now()
        
    def add_trade(self, trade: Trade) -> None:
        """
        Add a new trade to the tracker
        
        Args:
            trade: The Trade object to add
        """
        self.open_trades[trade.id] = trade
        
    def close_trade(self, trade_id: str, exit_price: float, 
                    exit_time: Optional[datetime] = None, 
                    reason: str = "manual") -> Optional[Trade]:
        """
        Close an open trade
        
        Args:
            trade_id: The ID of the trade to close
            exit_price: Exit price
            exit_time: When the trade was closed
            reason: Why the trade was closed
            
        Returns:
            Optional[Trade]: The closed trade, or None if not found
        """
        if trade_id not in self.open_trades:
            return None
            
        trade = self.open_trades[trade_id]
        trade.close(exit_price, exit_time, reason)
        
        # Move to closed trades
        del self.open_trades[trade_id]
        self.closed_trades.append(trade)
        
        # Update statistics
        self._calculate_statistics()
        
        return trade
    
    def check_price_updates(self, ticker: str, current_price: float, 
                           current_time: datetime) -> List[Trade]:
        """
        Check if any open trades need to be closed based on price
        
        Args:
            ticker: Symbol to check
            current_price: Current market price
            current_time: Current timestamp
            
        Returns:
            List[Trade]: List of trades that were closed
        """
        closed_trades = []
        
        # Check all open trades for this ticker
        for trade_id, trade in list(self.open_trades.items()):
            if trade.ticker != ticker:
                continue
                
            # Check if trade should be closed
            exit_reason = trade.check_exit_conditions(current_price, current_time)
            if exit_reason:
                closed_trade = self.close_trade(trade_id, current_price, current_time, exit_reason)
                closed_trades.append(closed_trade)
                
        return closed_trades
                
    def _calculate_statistics(self) -> None:
        """Calculate and update trading statistics"""
        if not self.closed_trades:
            return
            
        self.total_trades = len(self.closed_trades)
        self.total_pnl = sum(trade.pnl for trade in self.closed_trades if hasattr(trade, 'pnl'))
        
        # Separate winning and losing trades
        winning_trades = [t for t in self.closed_trades if hasattr(t, 'pnl') and t.pnl > 0]
        losing_trades = [t for t in self.closed_trades if hasattr(t, 'pnl') and t.pnl < 0]
        break_even_trades = [t for t in self.closed_trades if hasattr(t, 'pnl') and t.pnl == 0]
        
        self.winning_trades = len(winning_trades)
        self.losing_trades = len(losing_trades)
        self.break_even_trades = len(break_even_trades)
        
        # Win rate
        self.win_rate = (self.winning_trades / self.total_trades * 100) if self.total_trades > 0 else 0
        
        # Average profit and loss
        self.avg_profit = sum(t.pnl for t in winning_trades) / len(winning_trades) if winning_trades else 0
        self.avg_loss = sum(t.pnl for t in losing_trades) / len(losing_trades) if losing_trades else 0
        
        # Win/loss ratio
        self.avg_win_loss_ratio = abs(self.avg_profit / self.avg_loss) if self.avg_loss and self.avg_loss != 0 else 0
        
        # Best and worst trades
        if self.closed_trades and hasattr(self.closed_trades[0], 'pnl'):
            self.best_trade = max(t.pnl for t in self.closed_trades)
            self.worst_trade = min(t.pnl for t in self.closed_trades)
        
        # Average risk/reward
        self.avg_risk_reward = sum(t.risk_reward_ratio for t in self.closed_trades) / len(self.closed_trades)
        
        # Average trade duration
        durations = [t.duration for t in self.closed_trades if hasattr(t, 'duration')]
        if durations:
            total_seconds = sum(d.total_seconds() for d in durations)
            self.avg_trade_duration = timedelta(seconds=total_seconds / len(durations))
            
        self.last_updated = datetime.now()
        
    def get_stats_summary(self) -> Dict[str, Any]:
        """
        Get a summary of trading statistics
        
        Returns:
            Dict: Trading statistics
        """
        return {
            'total_trades': self.total_trades,
            'open_trades': len(self.open_trades),
            'winning_trades': self.winning_trades,
            'losing_trades': self.losing_trades,
            'win_rate': self.win_rate,
            'total_pnl': self.total_pnl,
            'avg_profit': self.avg_profit,
            'avg_loss': self.avg_loss,
            'avg_win_loss_ratio': self.avg_win_loss_ratio,
            'avg_risk_reward': self.avg_risk_reward,
            'best_trade': self.best_trade,
            'worst_trade': self.worst_trade,
            'avg_trade_duration': str(self.avg_trade_duration),
            'last_updated': self.last_updated.isoformat()
        }
        
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert trade tracker to dictionary for storage
        
        Returns:
            Dict: Serializable dictionary of trade data
        """
        return {
            'open_trades': {tid: trade.to_dict() for tid, trade in self.open_trades.items()},
            'closed_trades': [trade.to_dict() for trade in self.closed_trades],
            'statistics': self.get_stats_summary()
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TradeTracker':
        """
        Create a TradeTracker object from a dictionary
        
        Args:
            data: Dictionary with trade data
            
        Returns:
            TradeTracker: Reconstructed TradeTracker object
        """
        tracker = cls()
        
        # Restore open trades
        for trade_id, trade_data in data.get('open_trades', {}).items():
            tracker.open_trades[trade_id] = Trade.from_dict(trade_data)
            
        # Restore closed trades
        for trade_data in data.get('closed_trades', []):
            tracker.closed_trades.append(Trade.from_dict(trade_data))
            
        # Recalculate statistics
        tracker._calculate_statistics()
        
        return tracker

class SignalGenerator:
    """
    Main class for generating signals from market data
    """
    def __init__(self, api_key: str, api_secret: str):
        """Initialize the generator with API credentials"""
        self.api_key = api_key
        self.api_secret = api_secret
        
        # Create API clients
        self.trading_client = TradingClient(api_key, api_secret)
        self.historical_client = StockHistoricalDataClient(api_key, api_secret)
        self.stream = StockDataStream(api_key, api_secret)
        
        # Create options analyzer
        self.options_analyzer = OptionsAnalyzer(api_key, api_secret)
        
        # Initialize variables for strategies and data tracking
        self.strategies = []
        self.bar_count = {}
        self.last_bar_time = {}
        
        # Initialize trade tracker
        self.trade_tracker = TradeTracker()
        
        # Load environment variables for Discord webhook
        discord_webhook = os.getenv("DISCORD_WEBHOOK_URL")
        self.discord_webhook_url = discord_webhook if discord_webhook else None
        
        # Load trades from file if exists
        self.trade_data_file = "trade_data.json"
        self.load_trades()
        
        # Data persistence settings
        self.data_directory = os.path.join(os.getcwd(), "saved_data")
        self.daily_bars_directory = os.path.join(self.data_directory, "daily_bars")
        self.today_date = datetime.now().strftime("%Y-%m-%d")
        self.data_filename = os.path.join(self.data_directory, f"market_data_{self.today_date}.pkl")
        
        # Make sure directories exist
        if not os.path.exists(self.data_directory):
            os.makedirs(self.data_directory)
        if not os.path.exists(self.daily_bars_directory):
            os.makedirs(self.daily_bars_directory)
            
        # Save settings
        self.last_save_time = datetime.now()
        self.save_interval = 60  # Save every 60 seconds
        self.total_bars_since_save = 0
        self.bars_per_save = 10  # Save every 10 bars
            
        # Register save functions to run on exit
        atexit.register(self.save_data)
        atexit.register(self.save_trades)
        
        # Debug mode setting
        self.debug_mode = True  # Default to False
        
        # Try to load existing data for today
        self.load_data()

    def add_strategy(self, strategy: LiveStrategy):
        """Add a trading strategy to the generator"""
        self.strategies.append(strategy)
        logger.info(f"Added strategy: {strategy.name}")
        
    def set_persistence_config(self, save_interval_seconds=60, bars_per_save=10):
        """
        Configure data persistence settings
        
        Args:
            save_interval_seconds (int): How often to save in seconds
            bars_per_save (int): How many bars to process before saving
        """
        self.save_interval = save_interval_seconds
        self.bars_per_save = bars_per_save
        logger.info(f"Data persistence configured: saving every {save_interval_seconds}s or {bars_per_save} bars")
        
    def save_data(self):
        """Save all strategy data buffers to a file"""
        try:
            if not self.strategies:
                logger.warning("No strategies to save data for")
                return
                
            # Create a dictionary to hold all strategy data
            data_to_save = {}
            total_bars = 0
            
            # Store data from each strategy
            for strategy in self.strategies:
                strategy_data = {}
                for ticker, data in strategy.data_buffer.items():
                    # Convert DataFrame to dict for serialization
                    strategy_data[ticker] = data.to_dict()
                    total_bars += len(data)
                data_to_save[strategy.name] = strategy_data
            
            # Save to file
            with open(self.data_filename, 'wb') as f:
                pickle.dump(data_to_save, f)
                
            # Show a more visible message with save stats
            logger.info(f"✅ Data saved: {total_bars} total bars for {len(self.strategies)} strategies")
            logger.debug(f"Data file location: {self.data_filename}")
            
        except Exception as e:
            logger.error(f"Error saving market data: {e}", exc_info=True)
            
    def load_data(self):
        """Load market data from file if it exists for the current day"""
        try:
            if not os.path.exists(self.data_filename):
                logger.info(f"No saved data found for today ({self.today_date})")
                return
                
            # Load data from file
            with open(self.data_filename, 'rb') as f:
                saved_data = pickle.load(f)
                
            # Data existed but no strategies loaded yet
            if not self.strategies:
                logger.info("Data found but no strategies loaded yet. Will restore after strategies are added.")
                self._pending_data_load = saved_data
                return
                
            # Restore data for each strategy
            self._restore_strategy_data(saved_data)
                
        except Exception as e:
            logger.error(f"Error loading market data: {e}", exc_info=True)
            
    def _restore_strategy_data(self, saved_data):
        """Restore data to strategies from saved data"""
        loaded_count = 0
        loaded_tickers = set()
        strategies_loaded = 0
        
        for strategy in self.strategies:
            if strategy.name in saved_data:
                strategies_loaded += 1
                strategy_data = saved_data[strategy.name]
                ticker_count = 0
                
                for ticker, data_dict in strategy_data.items():
                    # Convert dict back to DataFrame
                    df = pd.DataFrame.from_dict(data_dict)
                    # Restore the index as DatetimeIndex
                    if 'index' in data_dict:
                        df.index = pd.DatetimeIndex(df.index)
                    strategy.data_buffer[ticker] = df
                    
                    # Update bar count and last bar time
                    if df.shape[0] > 0:
                        self.bar_count[ticker] = self.bar_count.get(ticker, 0) + df.shape[0]
                        self.last_bar_time[ticker] = df.index[-1]
                        loaded_count += df.shape[0]
                        loaded_tickers.add(ticker)
                        ticker_count += 1
        
        if loaded_count > 0:
            # Show a more detailed load message
            logger.info(f"🔄 Loaded {loaded_count} bars of market data for {len(loaded_tickers)} tickers")
            logger.info(f"   Data restored for {strategies_loaded} strategies")
            logger.debug(f"   From file: {self.data_filename}")
            
            # Show the most recent data point for each ticker
            for ticker in loaded_tickers:
                if ticker in self.last_bar_time:
                    logger.debug(f"   {ticker}: Last bar from {self.last_bar_time[ticker]}")
        else:
            logger.info("No market data loaded")
        
    def save_trades(self):
        """Save trade tracking data to a file"""
        try:
            # Create a dictionary to hold all trade data
            data_to_save = self.trade_tracker.to_dict()
            
            # Save to file
            with open(self.trade_data_file, 'wb') as f:
                pickle.dump(data_to_save, f)
                
            # Show a message with trade stats
            stats = self.trade_tracker.get_stats_summary()
            logger.info(f"📊 Trades saved: {stats['total_trades']} total, {len(self.trade_tracker.open_trades)} open")
            logger.debug(f"Trades file location: {self.trade_data_file}")
            
        except Exception as e:
            logger.error(f"Error saving trade data: {e}", exc_info=True)
            
    def load_trades(self):
        """Load trade data from file if it exists for the current day"""
        try:
            if not os.path.exists(self.trade_data_file):
                logger.info(f"No saved trade data found for today ({self.today_date})")
                return
                
            # Load data from file
            with open(self.trade_data_file, 'rb') as f:
                saved_data = pickle.load(f)
                
            # Restore trade tracker
            self.trade_tracker = TradeTracker.from_dict(saved_data)
            
            # Show stats
            stats = self.trade_tracker.get_stats_summary()
            logger.info(f"📈 Loaded trade data: {stats['total_trades']} trades, Win rate: {stats['win_rate']:.1f}%")
            if stats['open_trades'] > 0:
                logger.info(f"   {stats['open_trades']} active trades to monitor")
                
        except Exception as e:
            logger.error(f"Error loading trade data: {e}", exc_info=True)

    def get_options_data(self, ticker: str, signal_type: str, 
                       entry_price: float, stop_loss: float, 
                       take_profit: float) -> Dict[str, Any]:
        """
        Get options data for a signal
        
        Args:
            ticker: Symbol to get options for
            signal_type: 'buy' or 'sell'
            entry_price: Signal entry price
            stop_loss: Stop loss level
            take_profit: Take profit level
            
        Returns:
            Dict with options data or empty dict if not available
        """
        try:
            # Get ATM option
            option_data = self.options_analyzer.get_atm_option(
                ticker, signal_type, entry_price
            )
            
            if not option_data:
                logger.debug(f"Could not find options data for {ticker}")
                return {}
                
            # Estimate prices at stop loss and take profit
            price_estimates = self.options_analyzer.estimate_option_prices(
                option_data, stop_loss, take_profit
            )
            
            if not price_estimates:
                logger.debug(f"Could not estimate option prices for {ticker}")
                return {}
                
            # Combine option data and price estimates
            options_data = {
                **option_data,
                'estimated_entry': price_estimates['entry'],
                'estimated_stop_loss': price_estimates['stop_loss'],
                'estimated_take_profit': price_estimates['take_profit'],
                'estimated_delta': price_estimates['estimated_delta']
            }
            
            return options_data
            
        except Exception as e:
            logger.error(f"Error getting options data for {ticker}: {e}", exc_info=True)
            return {}

    def send_to_discord(self, strategy_name: str, ticker: str, signals: dict):
        """Send signal to Discord webhook if configured"""
        if not self.discord_webhook_url:
            return
            
        try:
            signal_type = signals['signal']
            if signal_type not in ['buy', 'sell']:
                return
                
            signal_emoji = "🟢" if signal_type == 'buy' else "🔴"
            entry_price = signals['entry_price']
            stop_loss = signals['stop_loss']
            profit_target = signals['profit_target']
            
            # Add emojis for stop loss and target
            stop_emoji = "🛑" # Stop sign emoji
            target_emoji = "🎯" # Target emoji
            
            # Calculate risk/reward
            risk = abs(entry_price - stop_loss)
            reward = abs(profit_target - entry_price)
            risk_reward = f"{(reward / risk if risk > 0 else 0):.2f}"
            
            # Get RSI value if available
            rsi_value = "N/A"
            if 'rsi' in signals and signals['rsi'] is not None:
                rsi_emoji = "📊" # Chart emoji
                rsi_value = f"{signals['rsi']:.1f}"
                # Add color indicators for RSI
                if signals['rsi'] >= 70:
                    rsi_value += " 🔴" # Overbought
                elif signals['rsi'] <= 30:
                    rsi_value += " 🟢" # Oversold
            
            # Get options data
            options_data = self.get_options_data(
                ticker, signal_type, entry_price, stop_loss, profit_target
            )
            
            # Create embed fields list
            fields = [
                {
                    "name": "Signal",
                    "value": f"{signal_emoji} **{signal_type.upper()}**",
                    "inline": True
                },
                {
                    "name": "Entry Price",
                    "value": f"${entry_price:.2f}",
                    "inline": True
                },
                {
                    "name": f"{stop_emoji} Stop Loss",
                    "value": f"${stop_loss:.2f}",
                    "inline": True
                },
                {
                    "name": f"{target_emoji} Target",
                    "value": f"${profit_target:.2f}",
                    "inline": True
                },
                {
                    "name": "Risk/Reward",
                    "value": risk_reward,
                    "inline": True
                }
            ]
            
            # Add RSI if available
            if 'rsi' in signals and signals['rsi'] is not None:
                fields.append({
                    "name": f"{rsi_emoji} RSI",
                    "value": rsi_value,
                    "inline": True
                })
                
            # Add VWAP if available
            if 'vwap' in signals and signals['vwap'] is not None:
                fields.append({
                    "name": "VWAP",
                    "value": f"${signals['vwap']:.2f}",
                    "inline": True
                })
            
            # Add options data if available
            if options_data:
                # Add a divider
                fields.append({
                    "name": "─────────────",
                    "value": "**Options Data**",
                    "inline": False
                })
                
                # Add contract details
                option_type_emoji = "📈" if options_data['option_type'] == 'CALL' else "📉"
                fields.append({
                    "name": f"{option_type_emoji} Contract",
                    "value": f"{ticker} {options_data['strike']} {options_data['option_type']}",
                    "inline": True
                })
                
                fields.append({
                    "name": "Expiration",
                    "value": f"{options_data['expiration']} ({options_data['days_to_expiry']} days)",
                    "inline": True
                })
                
                fields.append({
                    "name": "Current Price",
                    "value": f"${options_data['estimated_entry']:.2f}",
                    "inline": True
                })
                
                fields.append({
                    "name": f"{stop_emoji} Option SL Est",
                    "value": f"${options_data['estimated_stop_loss']:.2f}",
                    "inline": True
                })
                
                fields.append({
                    "name": f"{target_emoji} Option TP Est",
                    "value": f"${options_data['estimated_take_profit']:.2f}",
                    "inline": True
                })
                
                # Add bid/ask spread
                fields.append({
                    "name": "Bid/Ask",
                    "value": f"${options_data['bid']:.2f} / ${options_data['ask']:.2f}",
                    "inline": True
                })
            
            # Build embedded message
            embed = {
                "title": f"{strategy_name} - {ticker}",
                "color": 65280 if signal_type == 'buy' else 16711680,  # Green for buy, Red for sell
                "fields": fields,
                "footer": {
                    "text": f"Time: {datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M:%S ET')}"
                }
            }
            
            # Send to Discord
            payload = {
                "embeds": [embed]
            }
            
            response = requests.post(
                self.discord_webhook_url, 
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            
            logger.info(f"Sent {signal_type.upper()} signal for {ticker} to Discord")
            return True
            
        except Exception as e:
            logger.error(f"Error sending Discord notification: {e}", exc_info=True)
            return False

    def print_trade_stats(self):
        """Print a summary of trade statistics"""
        stats = self.trade_tracker.get_stats_summary()
        
        logger.info("\n=== TRADE STATISTICS ===", extra={'is_signal': True})
        logger.info(f"Total Trades  : {stats['total_trades']}", extra={'is_signal': True})
        logger.info(f"Open Trades   : {stats['open_trades']}", extra={'is_signal': True})
        logger.info(f"Win Rate      : {stats['win_rate']:.1f}%", extra={'is_signal': True})
        logger.info(f"Total P&L     : ${stats['total_pnl']:.2f}", extra={'is_signal': True})
        
        if stats['winning_trades'] > 0:
            logger.info(f"Avg Win       : ${stats['avg_profit']:.2f}", extra={'is_signal': True})
        if stats['losing_trades'] > 0:
            logger.info(f"Avg Loss      : ${stats['avg_loss']:.2f}", extra={'is_signal': True})
        if stats['avg_win_loss_ratio'] > 0:
            logger.info(f"Win/Loss Ratio: {stats['avg_win_loss_ratio']:.2f}", extra={'is_signal': True})
            
        logger.info(f"Avg R/R Ratio : {stats['avg_risk_reward']:.2f}", extra={'is_signal': True})
        logger.info(f"Best Trade    : ${stats['best_trade']:.2f}", extra={'is_signal': True})
        logger.info(f"Worst Trade   : ${stats['worst_trade']:.2f}", extra={'is_signal': True})
        logger.info(f"Avg Duration  : {stats['avg_trade_duration']}", extra={'is_signal': True})
        
        # Show open trades
        if stats['open_trades'] > 0:
            logger.info("\nCurrent Open Trades:", extra={'is_signal': True})
            for trade_id, trade in self.trade_tracker.open_trades.items():
                logger.info(f"  {trade.ticker} ({trade.id}): {trade.trade_type.upper()} @ ${trade.entry_price:.2f}, SL: ${trade.stop_loss:.2f}, TP: ${trade.take_profit:.2f}", 
                           extra={'is_signal': True})
        
        logger.info("========================\n", extra={'is_signal': True})

    def print_signal(self, strategy_name: str, ticker: str, signals: dict):
        """Pretty print the signal information"""
        logger.info("\n=== SIGNAL GENERATED ===", extra={'is_signal': True})
        logger.info(f"Time    : {datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M:%S ET')}", 
                   extra={'is_signal': True})
        logger.info(f"Strategy: {strategy_name}", extra={'is_signal': True})
        logger.info(f"Ticker  : {ticker}", extra={'is_signal': True})
        logger.info(f"Action  : {signals['signal'].upper()}", extra={'is_signal': True})
        logger.info("\nPrices:", extra={'is_signal': True})
        logger.info(f"  Current  : ${signals['entry_price']:.2f}", extra={'is_signal': True})
        logger.info(f"  Entry    : ${signals['entry_price']:.2f}", extra={'is_signal': True})
        logger.info(f"  Stop     : ${signals['stop_loss']:.2f}", extra={'is_signal': True})
        logger.info(f"  Target   : ${signals['profit_target']:.2f}", extra={'is_signal': True})
        
        # Calculate and display risk metrics
        risk = abs(signals['entry_price'] - signals['stop_loss'])
        reward = abs(signals['profit_target'] - signals['entry_price'])
        risk_reward = reward / risk if risk > 0 else 0
        
        # Calculate price spread
        price_spread = abs(signals['profit_target'] - signals['entry_price'])
        
        logger.info("\nRisk Metrics:", extra={'is_signal': True})
        logger.info(f"  Risk      : ${risk:.2f}", extra={'is_signal': True})
        logger.info(f"  Reward    : ${reward:.2f}", extra={'is_signal': True})
        logger.info(f"  Spread    : ${price_spread:.2f}", extra={'is_signal': True})
        logger.info(f"  R/R Ratio : {risk_reward:.2f}", extra={'is_signal': True})
        
        # Print technical indicators if available
        if 'ema_short' in signals or 'ema_mid' in signals or 'ema_long' in signals:
            logger.info("\nTechnical Indicators:", extra={'is_signal': True})
            if 'ema_short' in signals:
                logger.info(f"  EMA Short: {signals['ema_short']:.2f}", extra={'is_signal': True})
            if 'ema_mid' in signals:
                logger.info(f"  EMA Mid  : {signals['ema_mid']:.2f}", extra={'is_signal': True})
            if 'ema_long' in signals:
                logger.info(f"  EMA Long : {signals['ema_long']:.2f}", extra={'is_signal': True})
                
        logger.info("=====================\n", extra={'is_signal': True})

    def print_debug_stats(self):
        """Print debug statistics"""
        if not self.debug_mode:
            return
            
        logger.info("\n=== Debug Statistics ===")
        for ticker in self.bar_count:
            logger.info(f"Ticker: {ticker}")
            logger.info(f"  Total bars received: {self.bar_count[ticker]}")
            logger.info(f"  Last bar time: {self.last_bar_time.get(ticker, 'No bars yet')}")
            logger.info(f"  Data buffer sizes:")
            for strategy in self.strategies:
                if ticker in strategy.data_buffer:
                    logger.info(f"    {strategy.name}: {len(strategy.data_buffer[ticker])} bars")
        logger.info("=====================\n")
        
    def validate_signal(self, signals):
        """
        Validate if a signal meets minimum criteria to be considered viable
        
        Args:
            signals: Signal dictionary with entry_price, profit_target, etc.
            
        Returns:
            bool: True if signal is valid, False otherwise
        """
        # Check if we have all required fields
        if not all(key in signals for key in ['entry_price', 'profit_target']):
            return False
            
        # Calculate the price spread between entry and take profit
        price_spread = abs(signals['profit_target'] - signals['entry_price'])
        
        # Signal is valid only if the spread is at least $1
        if price_spread < 1.0:
            logger.info(f"Signal rejected: Price spread (${price_spread:.2f}) is less than $1.00")
            return False
            
        return True
        
    async def process_bar(self, bar):
        """Process incoming bar data"""
        try:
            ticker = bar.symbol
            timestamp = pd.Timestamp(bar.timestamp)
            
            # Update bar count
            self.bar_count[ticker] = self.bar_count.get(ticker, 0) + 1
            self.last_bar_time[ticker] = timestamp
            self.total_bars_since_save += 1
            
            # Create DataFrame from bar data
            new_data = pd.DataFrame({
                'open': [bar.open],
                'high': [bar.high],
                'low': [bar.low],
                'close': [bar.close],
                'volume': [bar.volume]
            }, index=[timestamp])
            
            logger.info(f"Processing bar for {ticker} at {timestamp} - {new_data}")
            # Check for stop loss/take profit hits on existing trades
            current_price = bar.close
            closed_trades = self.trade_tracker.check_price_updates(ticker, current_price, timestamp)
            
            # Send alerts for any closed trades
            for trade in closed_trades:
                logger.info(f"\n{'🛑 STOP LOSS' if trade.exit_reason == 'stop_loss' else '🎯 TAKE PROFIT'} triggered for {trade.ticker}!")
                logger.info(f"Entry: ${trade.entry_price:.2f}, Exit: ${trade.exit_price:.2f}, P&L: ${trade.pnl:.2f}")
                
                # Send Discord notification
                self.send_to_discord(
                    strategy_name=trade.strategy_name,
                    ticker=trade.ticker,
                    signals={
                        'signal': trade.trade_type,
                        'entry_price': trade.entry_price,
                        'stop_loss': trade.stop_loss,
                        'profit_target': trade.take_profit
                    }
                )
                
                # Save trades immediately when one is closed
                self.save_trades()
            
            # Process through each strategy
            for strategy in self.strategies:
                strategy.update_data(ticker, new_data)
                signals = strategy.generate_signal(ticker, strategy.data_buffer[ticker])
                
                if signals['signal'] is not None:
                    # Validate signal before proceeding
                    if not self.validate_signal(signals):
                        continue
                        
                    # Print signal
                    self.print_signal(strategy.name, ticker, signals)
                    
                    # Create a new trade
                    new_trade = Trade(
                        ticker=ticker,
                        strategy_name=strategy.name,
                        trade_type=signals['signal'],
                        entry_price=signals['entry_price'],
                        stop_loss=signals['stop_loss'],
                        take_profit=signals['profit_target'],
                        entry_time=timestamp
                    )
                    
                    # Add to trade tracker
                    self.trade_tracker.add_trade(new_trade)
                    
                    # Send to Discord
                    self.send_to_discord(
                        strategy_name=strategy.name,
                        ticker=ticker,
                        signals=signals
                    )
                    
                    # Save data and trades immediately when a signal is generated
                    self.save_data()
                    self.save_trades()
                    self.total_bars_since_save = 0
                    self.last_save_time = datetime.now()
            
            # Print debug stats every 10 bars only if debug mode is on
            if self.debug_mode and self.bar_count[ticker] % 10 == 0:
                self.print_debug_stats()
                
            # Check if we should save data based on time or bar count
            current_time = datetime.now()
            time_since_last_save = (current_time - self.last_save_time).total_seconds()
            
            if time_since_last_save >= self.save_interval or self.total_bars_since_save >= self.bars_per_save:
                logger.debug(f"Saving data after {self.total_bars_since_save} bars or {time_since_last_save:.1f} seconds")
                self.save_data()
                self.save_trades()
                self.total_bars_since_save = 0
                self.last_save_time = current_time
                
            # Print trade statistics at regular intervals (e.g., every 100 bars)
            if self.bar_count[ticker] % 100 == 0 and ticker == list(self.bar_count.keys())[0]:
                self.print_trade_stats()
        
        except Exception as e:
            logger.error(f"Error processing bar: {e}", exc_info=True)
            
    async def shutdown(self):
        """
        Gracefully shut down the SignalGenerator.
        Call this method explicitly before exiting to ensure data is saved.
        """
        logger.info("Starting graceful shutdown sequence...")
        
        # Save all data
        try:
            logger.info("Saving all market data...")
            self.save_data()
            self.save_trades()
        except Exception as e:
            logger.error(f"Error saving data during shutdown: {e}")
            
        # Close any network connections
        try:
            if hasattr(self, 'stream') and self.stream:
                logger.info("Closing data stream connection...")
                await self.stream.close()
                logger.info("Data stream closed.")
        except Exception as e:
            logger.error(f"Error closing stream during shutdown: {e}")
            
        logger.info("Shutdown complete.")
        
    def check_and_fetch_daily_bars(self, symbols: List[str]):
        """
        Check if we have the latest daily bar data for each symbol and fetch it if needed
        
        Args:
            symbols: List of ticker symbols to check
        """
        logger.info("Checking for latest daily bar data...")
        
        # Get yesterday's date (or last trading day)
        today = datetime.now().date()
        yesterday = today - timedelta(days=1)
        
        # If yesterday was a weekend, go back to Friday
        if yesterday.weekday() == 5:  # Saturday
            yesterday = yesterday - timedelta(days=1)
        elif yesterday.weekday() == 6:  # Sunday
            yesterday = yesterday - timedelta(days=2)
            
        yesterday_str = yesterday.strftime("%Y-%m-%d")
        
        # Check each symbol
        missing_data_symbols = []
        for symbol in symbols:
            daily_file = os.path.join(self.daily_bars_directory, f"{symbol}_daily_{yesterday_str}.pkl")
            
            if os.path.exists(daily_file):
                # Load existing daily data for this symbol
                self.load_daily_bars(symbol, yesterday)
            else:
                missing_data_symbols.append(symbol)
                logger.info(f"Missing daily data for {symbol} on {yesterday_str}")
                
        # If we have symbols with missing data, fetch them
        if missing_data_symbols:
            logger.info(f"Fetching daily bar data for {len(missing_data_symbols)} symbols...")
            self.fetch_and_save_daily_bars(missing_data_symbols, yesterday)
        else:
            logger.info("All symbols have up-to-date daily bar data")
            
    def load_daily_bars(self, symbol: str, date_for: date):
        """
        Load saved daily bars for a specific symbol and date
        
        Args:
            symbol: Ticker symbol to load data for
            date_for: Date to load data for
        
        Returns:
            bool: True if data was loaded successfully, False otherwise
        """
        try:
            date_str = date_for.strftime("%Y-%m-%d")
            daily_file = os.path.join(self.daily_bars_directory, f"{symbol}_daily_{date_str}.pkl")
            
            if not os.path.exists(daily_file):
                logger.warning(f"No saved daily bars found for {symbol} on {date_str}")
                return False
                
            # Load the data
            with open(daily_file, 'rb') as f:
                df = pickle.load(f)
                
            # Update each strategy
            for strategy in self.strategies:
                strategy.update_daily_bars(symbol, df)
                
            logger.info(f"Loaded daily bars for {symbol} ({len(df)} bars)")
            return True
            
        except Exception as e:
            logger.error(f"Error loading daily bars for {symbol}: {e}")
            return False

    def fetch_and_save_daily_bars(self, symbols: List[str], last_date: date):
        """
        Fetch and save daily bar data for a list of symbols
        
        Args:
            symbols: List of ticker symbols to fetch data for
            last_date: The last date to fetch data for
        """
        try:
            # Set up time range for the request
            # Get 50 trading days of data to ensure we have enough context
            start_date = last_date - timedelta(days=50)  # Go back 50 calendar days to get ~50 trading days
            end_date = last_date + timedelta(days=1)  # Add 1 day to make the end date inclusive
            
            # Create the request
            request_params = StockBarsRequest(
                symbol_or_symbols=symbols,
                timeframe=TimeFrame.Day,
                start=datetime.combine(start_date, datetime.min.time()).replace(tzinfo=pytz.UTC),
                end=datetime.combine(end_date, datetime.min.time()).replace(tzinfo=pytz.UTC),
                adjustment='all',
                feed='sip'  # Use SIP data (all US exchanges)
            )
            
            # Make the request
            logger.info(f"Requesting daily bars from {start_date} to {last_date} for {len(symbols)} symbols...")
            daily_bars = self.historical_client.get_stock_bars(request_params)
            
            # Check if we got data back
            if not daily_bars or not hasattr(daily_bars, 'data'):
                logger.warning("No daily bar data returned from API")
                return
                
            # Process and save data for each symbol
            for symbol in symbols:
                if symbol in daily_bars.data:
                    symbol_data = daily_bars.data[symbol]
                    
                    # Convert to DataFrame - proper handling for Alpaca bars
                    bars_dict = {
                        'timestamp': [],
                        'open': [],
                        'high': [],
                        'low': [],
                        'close': [],
                        'volume': []
                    }
                    
                    for bar in symbol_data:
                        bars_dict['timestamp'].append(bar.timestamp)
                        bars_dict['open'].append(bar.open)
                        bars_dict['high'].append(bar.high)
                        bars_dict['low'].append(bar.low)
                        bars_dict['close'].append(bar.close)
                        bars_dict['volume'].append(bar.volume)
                    
                    df = pd.DataFrame(bars_dict)
                    df.set_index('timestamp', inplace=True)
                    
                    # Add the data to each strategy
                    for strategy in self.strategies:
                        # Check if we need to initialize the data buffer
                        if symbol not in strategy.data_buffer:
                            strategy.data_buffer[symbol] = pd.DataFrame()
                        
                        # Use daily bars to initialize/update the strategy's data buffer
                        # This provides context for generating signals when streaming starts
                        strategy.update_daily_bars(symbol, df)
                    
                    # Save the daily bars for this symbol
                    daily_file = os.path.join(self.daily_bars_directory, f"{symbol}_daily_{last_date.strftime('%Y-%m-%d')}.pkl")
                    with open(daily_file, 'wb') as f:
                        pickle.dump(df, f)
                        
                    logger.info(f"Saved daily bars for {symbol} ({len(df)} bars)")
                else:
                    logger.warning(f"No daily bar data available for {symbol}")
                    
        except Exception as e:
            logger.error(f"Error fetching daily bar data: {e}", exc_info=True)

    async def start_streaming(self, symbols: List[str]):
        """Start the data stream"""
        try:
            # Initialize counters
            for symbol in symbols:
                self.bar_count[symbol] = 0
            
            # Check and fetch the latest daily bar data
            self.check_and_fetch_daily_bars(symbols)
            
            # If we have pending data to load after strategies were added
            if hasattr(self, '_pending_data_load'):
                self._restore_strategy_data(self._pending_data_load)
                delattr(self, '_pending_data_load')
                
            logger.info(f"Starting data stream for symbols: {symbols}")
            
            # Subscribe to minute bars
            self.stream.subscribe_bars(self.process_bar, *symbols)
            
            # Start streaming
            await self.stream._run_forever()
            
        except KeyboardInterrupt:
            logger.info("Stream interrupted by user")
            await self.shutdown()
            raise
        except Exception as e:
            logger.error(f"Error in stream: {e}", exc_info=True)
            await self.shutdown()
            raise 
