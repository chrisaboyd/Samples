import nltk
from nltk.corpus import twitter_samples, stopwords
from nltk.stem import PorterStemmer
from nltk.tokenize import TweetTokenizer
import matplotlib.pyplot as plt
import random
import os
import re
import string   


def download_nltk_datasets() -> None:
    """
    Download required NLTK datasets if they are not already present.
    Downloads twitter_samples and stopwords datasets.
    """
    datasets = ['twitter_samples', 'stopwords']
    
    for dataset in datasets:
        dataset_path = os.path.join(nltk.data.path[0], 'corpora', dataset)
        if not os.path.exists(dataset_path):
            nltk.download(dataset)
            print(f"Downloaded {dataset} dataset to {dataset_path}")
        else:
            print(f"{dataset} dataset already exists at {dataset_path}")


def load_twitter_data() -> tuple[list[str], list[str]]:
    """
    Load positive and negative tweets from the NLTK twitter samples.
    """
    positive_tweets = twitter_samples.strings('positive_tweets.json')
    negative_tweets = twitter_samples.strings('negative_tweets.json')
    
    print(f"Number of positive tweets: {len(positive_tweets)}")
    print(f"Number of negative tweets: {len(negative_tweets)}")
    
    return positive_tweets, negative_tweets


def display_sample_tweets(tweets: list[str], label: str, count: int = 5) -> None:
    """
    Display a sample of tweets with their label.
    """
    print(f"\nFirst {count} {label} tweets:")
    for tweet in tweets[:count]:
        print(tweet)


def plot_tweet_distribution(positive_tweets: list[str], negative_tweets: list[str]) -> None:
    """
    Create and display a pie chart showing the distribution of positive and negative tweets.
    """
    plt.figure(figsize=(5, 5))
    
    labels = 'Positives', 'Negatives'
    sizes = [len(positive_tweets), len(negative_tweets)]
    
    plt.pie(sizes,
            labels=labels,
            autopct='%1.1f%%',
            shadow=False,
            startangle=90)
    
    plt.axis('equal')
    plt.show()


def remove_stopwords(tweet_tokens) -> list[str]:
    """
    Remove stopwords from a list of tweet tokens.
    """
    stopwords_list = stopwords.words('english')
    cleaned_tokens = [word for word in tweet_tokens if word not in stopwords_list and word not in string.punctuation]

    return cleaned_tokens


def stem_words(tweet_tokens) -> list[str]:
    """
    Stem words in a list of tweet tokens.
    """
    stemmer = PorterStemmer()
    stemmed_tokens = [stemmer.stem(word) for word in tweet_tokens]
    return stemmed_tokens
    

def preprocess_tweets_chunk(tweets, chunk_size=1000) -> list[str]:
    """
    Preprocess a chunk of tweets efficiently by applying each step to the entire chunk.
    """
    preprocessed_tweets = []
    tokenizer = TweetTokenizer(preserve_case=False, strip_handles=True, reduce_len=True)
    stemmer = PorterStemmer()
    stopwords_list = stopwords.words('english')
    
    # Process tweets in chunks
    for i in range(0, len(tweets), chunk_size):
        chunk = tweets[i:i + chunk_size]
        
        # Step 1: Remove special characters and convert to lowercase for the entire chunk
        cleaned_chunk = [
            re.sub(r'^RT[\s]+', '', tweet)  # Remove RT
            for tweet in chunk
        ]
        cleaned_chunk = [
            re.sub(r'https?:\/\/\S+', '', tweet)  # Remove URLs
            for tweet in cleaned_chunk
        ]
        cleaned_chunk = [
            re.sub(r'#', '', tweet)  # Remove hashtags
            for tweet in cleaned_chunk
        ]
        cleaned_chunk = [tweet.lower() for tweet in cleaned_chunk]  # Convert to lowercase
        
        # Step 2: Tokenize the entire chunk
        tokenized_chunk = [tokenizer.tokenize(tweet) for tweet in cleaned_chunk]
        
        # Step 3: Remove stopwords and punctuation for the entire chunk
        cleaned_tokens_chunk = [
            [word for word in tokens if word not in stopwords_list and word not in string.punctuation]
            for tokens in tokenized_chunk
        ]
        
        # Step 4: Stem words for the entire chunk
        stemmed_chunk = [
            [stemmer.stem(word) for word in tokens]
            for tokens in cleaned_tokens_chunk
        ]
        
        preprocessed_tweets.extend(stemmed_chunk)
        
        # Optional: Print progress for large datasets
        if len(tweets) > chunk_size:
            print(f"Processed {min(i + chunk_size, len(tweets))}/{len(tweets)} tweets")
    
    return preprocessed_tweets


def main():

    # Download required datasets
    download_nltk_datasets()
    
    # Load and analyze tweets
    positive_tweets, negative_tweets = load_twitter_data()
    
    # Display sample tweets
    display_sample_tweets(positive_tweets, 'positive')
    
    # Visualize tweet distribution
    #plot_tweet_distribution(positive_tweets, negative_tweets)

    # Process tweets in chunks
    print("\nPreprocessing positive tweets...")
    preprocessed_positive_tweets = preprocess_tweets_chunk(positive_tweets)
    
    print("\nPreprocessing negative tweets...")
    preprocessed_negative_tweets = preprocess_tweets_chunk(negative_tweets)

    print("\nSample preprocessed positive tweet:")

    print(preprocessed_positive_tweets[0])
    print("\nSample preprocessed negative tweet:")

    print(preprocessed_negative_tweets[0])


if __name__ == "__main__":
    main()


