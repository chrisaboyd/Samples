import nltk
from nltk.corpus import twitter_samples, stopwords
from nltk.stem import PorterStemmer
from nltk.tokenize import TweetTokenizer
import matplotlib.pyplot as plt
import random
import os
import re
import string   


def download_nltk_datasets():
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


def load_twitter_data():
    """
    Load positive and negative tweets from the NLTK twitter samples.
    
    Returns:
        tuple: (positive_tweets, negative_tweets)
    """
    positive_tweets = twitter_samples.strings('positive_tweets.json')
    negative_tweets = twitter_samples.strings('negative_tweets.json')
    
    print(f"Number of positive tweets: {len(positive_tweets)}")
    print(f"Number of negative tweets: {len(negative_tweets)}")
    
    return positive_tweets, negative_tweets


def display_sample_tweets(tweets, label, count=5):
    """
    Display a sample of tweets with their label.
    
    Args:
        tweets (list): List of tweets to display
        label (str): Label for the tweets (e.g., 'positive')
        count (int): Number of tweets to display
    """
    print(f"\nFirst {count} {label} tweets:")
    for tweet in tweets[:count]:
        print(tweet)


def plot_tweet_distribution(positive_tweets, negative_tweets):
    """
    Create and display a pie chart showing the distribution of positive and negative tweets.
    
    Args:
        positive_tweets (list): List of positive tweets
        negative_tweets (list): List of negative tweets
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


def remove_stopwords(tweet_tokens):
    """
    Remove stopwords from a list of tweet tokens.
    """
    stopwords_list = stopwords.words('english')
    cleaned_tokens = [word for word in tweet_tokens if word not in stopwords_list and word not in string.punctuation]

    return cleaned_tokens


def stem_words(tweet_tokens):
    """
    Stem words in a list of tweet tokens.
    """
    stemmer = PorterStemmer()
    stemmed_tokens = [stemmer.stem(word) for word in tweet_tokens]
    return stemmed_tokens


def preprocess_tweet(tweet):
    """
    Preprocess a tweet by tokenizing it, removing stopwords, and stemming the words.
    
    Args: 
        tweet (str): The tweet to preprocess
        
    Returns:
        str: The preprocessed tweet
    """

    # remove old style retweet text "RT"
    tweet = re.sub(r'^RT[\s]+', '', tweet)

    # remove hyperlinks
    tweet = re.sub(r'https?:\/\/\S+', '', tweet)

    # remove hashtags
    tweet = re.sub(r'#', '', tweet)

    # convert to lowercase
    tweet = tweet.lower()

    # tokenize tweet
    tokenizer = TweetTokenizer(preserve_case=False, strip_handles=True, reduce_len=True)
    tweet_tokens = tokenizer.tokenize(tweet)

    # remove stopwords
    cleaned_tokens = remove_stopwords(tweet_tokens)

    # stem words
    stemmed_tokens = stem_words(cleaned_tokens)

    return stemmed_tokens
    


def main():
    """Main function to run the tweet analysis pipeline."""
    # Download required datasets
    download_nltk_datasets()
    
    # Load and analyze tweets
    positive_tweets, negative_tweets = load_twitter_data()
    
    # Display sample tweets
    display_sample_tweets(positive_tweets, 'positive')
    
    # Visualize tweet distribution
    #plot_tweet_distribution(positive_tweets, negative_tweets)

    preprocessed_positive_tweets = [preprocess_tweet(tweet) for tweet in positive_tweets]
    preprocessed_negative_tweets = [preprocess_tweet(tweet) for tweet in negative_tweets]

    print (preprocessed_positive_tweets[0])
    print (preprocessed_negative_tweets[0])


if __name__ == "__main__":
    main()


