import pandas as pd
import matplotlib.pyplot as plt
import os

# Load the trading performance file
file_path = "C:\\Users\\chimp\\OneDrive\\Desktop\\Trading_Performance_Tracking.xlsx"  # Ensure the file is in the same directory as this script

print (os.getcwd())
# Read the Excel file
try:
    df = pd.read_excel(file_path)

    # Ensure "Date" is in datetime format
    df["Date"] = pd.to_datetime(df["Date"])

    # Sort data by Date
    df = df.sort_values(by="Date")

    # Create the visualization
    plt.figure(figsize=(10, 5))
    plt.plot(df["Date"], df["Profit/Loss ($)"], marker='o', linestyle='-', color='b', label="Daily P/L")
    
    # Add a cumulative profit line
    df["Cumulative P/L"] = df["Profit/Loss ($)"].cumsum()
    plt.plot(df["Date"], df["Cumulative P/L"], linestyle='--', color='g', label="Cumulative P/L")
    
    plt.axhline(0, color='black', linewidth=1, linestyle='--')  # Reference line at zero
    plt.xlabel("Date")
    plt.ylabel("Profit/Loss ($)")
    plt.title("Trading Performance Over Time")
    plt.legend()
    plt.xticks(rotation=45)
    plt.grid()

    # Show the graph
    plt.show()

except FileNotFoundError:
    print(f"Error: The file '{file_path}' was not found. Make sure it's in the same directory as this script.")
except Exception as e:
    print(f"An error occurred: {e}")
