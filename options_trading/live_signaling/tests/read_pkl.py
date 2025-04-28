import os
import pickle
import glob
import pandas as pd

# Path to the saved_data directory (adjust if needed)
DATA_DIR = os.path.join(os.path.dirname(__file__), '../saved_data')

# Find the latest market_data_*.pkl file
files = glob.glob(os.path.join(DATA_DIR, 'market_data_*.pkl'))
if not files:
    print("No market_data_*.pkl files found in saved_data/")
    exit(1)

latest_file = max(files, key=os.path.getmtime)
print(f"Loading: {latest_file}")

# Load the pickle file
with open(latest_file, 'rb') as f:
    data = pickle.load(f)

# Print a summary of the contents
for strategy, tickers in data.items():
    print(f"\nStrategy: {strategy}")
    for ticker, df_dict in tickers.items():
        print(f"  Ticker: {ticker}")
        try:
            df = pd.DataFrame.from_dict(df_dict)
            print(df.tail(3))  # Show last 3 rows
        except Exception as e:
            print(f"    Could not display DataFrame: {e}")

print("\nDone.")
