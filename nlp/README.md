# Twitter Sentiment Analysis Preprocessing

This project demonstrates basic Natural Language Processing (NLP) preprocessing techniques using NLTK (Natural Language Toolkit) for Twitter sentiment analysis. The code provides a foundation for preparing tweet data for sentiment classification.

## Overview

The code performs several key preprocessing steps on Twitter data:
1. Downloads and loads Twitter samples (positive and negative tweets)
2. Tokenizes tweets ("this is an amazing sentence" -> ["this", "is", "an", "amazing", "sentence"])
3. Removes stopwords (["this", "amazing", "sentence"])
4. Applies stemming ("amaz")
5. Removes URLs, hashtags, and retweet markers
6. Visualizes the distribution of positive and negative tweets

## Key Features

- **Efficient Processing**: Processes tweets in chunks to optimize memory usage and performance
- **Progress Tracking**: Shows progress for large datasets
- **Modular Design**: Each preprocessing step is clearly separated and can be modified independently

## Prerequisites

- Python 3.x
- NLTK library
- Matplotlib (for visualization)

## Installation

1. Clone this repository
2. Install required packages:
```bash
pip install nltk matplotlib
```

## Project Structure

The main preprocessing script (`base_preprocessing.py`) contains several key functions:

### Data Loading and Setup
- `download_nltk_datasets()`: Downloads required NLTK datasets (twitter_samples and stopwords)
- `load_twitter_data()`: Loads positive and negative tweets from NLTK's twitter samples

### Text Preprocessing Functions
- `preprocess_tweets_chunk(tweets, chunk_size=1000)`: Main preprocessing pipeline that:
  - Processes tweets in chunks for memory efficiency
  - Removes RT (retweet) markers
  - Removes hyperlinks
  - Removes hashtags
  - Converts to lowercase
  - Tokenizes the tweets
  - Removes stopwords
  - Applies stemming
  - Shows progress for large datasets

### Visualization
- `plot_tweet_distribution(positive_tweets, negative_tweets)`: Creates a pie chart showing the distribution of positive and negative tweets
- `display_sample_tweets(tweets, label, count=5)`: Displays sample tweets for inspection

## Usage

Run the script:
```bash
python base_preprocessing.py
```

The script will:
1. Download required NLTK datasets if not already present
2. Load the Twitter samples
3. Display sample tweets
4. Show the distribution of positive and negative tweets
5. Preprocess tweets in chunks and display the results

## Preprocessing Steps Explained

1. **Special Character Handling**:
   - Removes URLs
   - Removes hashtags
   - Removes retweet markers (RT)
   - Converts text to lowercase

2. **Tokenization**: Breaks down tweets into individual words using NLTK's TweetTokenizer
   - Preserves case
   - Strips handles (usernames)
   - Reduces repeated characters (e.g., "loooove" → "love")

3. **Stopword Removal**: Removes common English words that don't contribute to sentiment
   - Removes articles (a, an, the)
   - Removes prepositions (in, on, at)
   - Removes punctuation

4. **Stemming**: Reduces words to their root form
   - "running" → "run"
   - "happiness" → "happi"
   - Uses Porter Stemmer algorithm

## Performance Considerations

The code processes tweets in chunks (default: 1000 tweets per chunk) to:
- Optimize memory usage
- Provide progress updates for large datasets
- Allow for better resource management
- Make the processing more efficient

You can adjust the chunk size based on your available memory and dataset size:
```python
preprocessed_tweets = preprocess_tweets_chunk(tweets, chunk_size=500)  # Smaller chunks
preprocessed_tweets = preprocess_tweets_chunk(tweets, chunk_size=2000)  # Larger chunks
```

## Example Output

The script will show:
- Number of positive and negative tweets
- Sample tweets before preprocessing
- Distribution visualization
- Progress updates during preprocessing
- Preprocessed versions of sample tweets

## Learning Resources

- [NLTK Documentation](https://www.nltk.org/)
- [NLTK Book](https://www.nltk.org/book/)
- [Twitter Sentiment Analysis Tutorial](https://www.nltk.org/howto/twitter.html)
