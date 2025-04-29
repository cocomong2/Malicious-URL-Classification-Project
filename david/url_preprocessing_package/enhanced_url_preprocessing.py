import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import re
from urllib.parse import urlparse, parse_qs
import tldextract
from sklearn.preprocessing import StandardScaler
import math
from collections import Counter

def extract_enhanced_features(url):
    """
    Extract an enhanced set of features from a URL for phishing detection
    """
    # Basic URL parsing
    parsed_url = urlparse(url)
    extracted = tldextract.extract(url)
    
    # Get basic components
    domain = extracted.domain
    subdomain = extracted.subdomain
    tld = extracted.suffix
    
    # Original suspicious keywords
    suspicious_keywords = [
        'login', 'verify', 'account', 'update', 'secure', 'banking', 
        'paypal', 'confirm', 'signin', 'auth', 'redirect', 'free', 
        'bonus', 'admin', 'support', 'server', 'password', 'click', 
        'urgent', 'immediate', 'alert', 'security', 'prompt'
    ]
    
    # Additional suspicious keywords
    additional_keywords = [
        'verify', 'wallet', 'cryptocurrency', 'bitcoin', 'ethereum',
        'validation', 'authenticate', 'reset', 'recover', 'access',
        'limited', 'offer', 'prize', 'win', 'winner', 'payment',
        'bank', 'credit', 'debit', 'card', 'expire', 'suspension',
        'unusual', 'activity', 'verify', 'document', 'invoice'
    ]
    
    # Combine all keywords
    all_keywords = list(set(suspicious_keywords + additional_keywords))
    
    # Popular brands often targeted in phishing
    popular_brands = [
        'paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'google',
        'facebook', 'instagram', 'twitter', 'linkedin', 'chase', 'wellsfargo',
        'bankofamerica', 'citibank', 'amex', 'americanexpress', 'dropbox',
        'yahoo', 'outlook', 'office365', 'onedrive', 'icloud', 'gmail'
    ]
    
    # URL length features
    url_length = len(url)
    
    # URL length category (keeping the original categorization)
    if url_length <= 13:
        url_length_cat = 0  
    elif url_length <= 18:
        url_length_cat = 1 
    elif url_length <= 25:
        url_length_cat = 2 
    else:
        url_length_cat = 3
    
    # 1. DOMAIN-SPECIFIC FEATURES
    # --------------------------
    # Domain length
    domain_length = len(domain) if domain else 0
    
    # Subdomain features
    has_subdomain = 1 if subdomain else 0
    subdomain_length = len(subdomain) if subdomain else 0
    subdomain_count = len(subdomain.split('.')) if subdomain else 0
    
    # TLD features
    tld_length = len(tld) if tld else 0
    
    # Common vs uncommon TLD
    common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'info', 'biz']
    is_common_tld = 1 if tld in common_tlds else 0
    
    # Check for country code TLDs
    country_tlds = ['us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'ru', 'br', 'in', 'it', 'es']
    is_country_tld = 1 if tld in country_tlds else 0
    
    # Check for suspicious TLDs often used in phishing
    suspicious_tlds = ['xyz', 'top', 'club', 'online', 'site', 'icu', 'vip', 'work', 'rest', 'fit']
    is_suspicious_tld = 1 if tld in suspicious_tlds else 0
    
    # 2. URL STRUCTURE ANALYSIS
    # ------------------------
    # Path analysis
    path = parsed_url.path
    path_length = len(path)
    path_depth = path.count('/') if path else 0
    
    # Query parameter analysis
    query = parsed_url.query
    has_query = 1 if query else 0
    query_length = len(query) if query else 0
    
    # Count query parameters
    query_params = parse_qs(query)
    query_param_count = len(query_params) if query_params else 0
    
    # Fragment analysis
    has_fragment = 1 if parsed_url.fragment else 0
    fragment_length = len(parsed_url.fragment) if parsed_url.fragment else 0
    
    # Check for IP address instead of domain name
    ip_pattern = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    is_ip_address = 1 if re.match(ip_pattern, domain) else 0
    
    # Check for URL shorteners
    url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc']
    is_shortened = 1 if any(shortener in url.lower() for shortener in url_shorteners) else 0
    
    # 3. ADVANCED TEXT ANALYSIS
    # ------------------------
    # Character distribution and entropy
    if url:
        char_counts = Counter(url)
        total_chars = len(url)
        char_frequencies = {char: count/total_chars for char, count in char_counts.items()}
        entropy = -sum(freq * math.log2(freq) for freq in char_frequencies.values())
    else:
        entropy = 0
    
    # Character type ratios
    letter_count = sum(c.isalpha() for c in url)
    digit_count = sum(c.isdigit() for c in url)
    special_char_count = len(re.findall(r'[^a-zA-Z0-9]', url))
    
    letter_ratio = letter_count / url_length if url_length > 0 else 0
    digit_ratio = digit_count / url_length if url_length > 0 else 0
    special_char_ratio = special_char_count / url_length if url_length > 0 else 0
    
    # Brand name detection
    contains_brand = 0
    detected_brand = None
    for brand in popular_brands:
        if brand in url.lower():
            contains_brand = 1
            detected_brand = brand
            break
    
    # Suspicious keyword detection (enhanced)
    contains_keyword = 0
    keyword_count = 0
    detected_keywords = []
    
    for keyword in all_keywords:
        if re.search(r'\b' + keyword + r'\b', url, re.IGNORECASE):
            contains_keyword = 1
            keyword_count += 1
            detected_keywords.append(keyword)
    
    # 4. ADVANCED PATTERN DETECTION
    # ----------------------------
    # Detect excessive subdomains (potential for phishing)
    excessive_subdomains = 1 if subdomain_count > 3 else 0
    
    # Detect numeric subdomain (often used in phishing)
    has_numeric_subdomain = 1 if subdomain and any(c.isdigit() for c in subdomain) else 0
    
    # Detect hyphens in domain (potential for phishing)
    has_hyphen_in_domain = 1 if '-' in domain else 0
    hyphen_count = domain.count('-') if domain else 0
    
    # Detect repeated characters (potential for typosquatting)
    has_repeated_chars = 1 if re.search(r'([a-zA-Z0-9])\1{2,}', domain) else 0
    
    # Detect homoglyph attack patterns (similar-looking characters)
    homoglyph_chars = ['0', 'o', 'O', '1', 'l', 'I', '5', 'S', 'rn', 'm']
    has_homoglyphs = 0
    
    if domain:
        domain_lower = domain.lower()
        if ('0' in domain_lower and 'o' in domain_lower) or \
           ('1' in domain_lower and 'l' in domain_lower) or \
           ('5' in domain_lower and 's' in domain_lower) or \
           ('rn' in domain_lower):
            has_homoglyphs = 1
    
    # Return all features as a dictionary
    return {
        # Original features (keeping for compatibility)
        "url_length": url_length,
        "url_length_cat": url_length_cat,
        "num_dots": url.count("."),
        "num_slashes": url.count("/"),
        "num_digits": digit_count,
        "num_special_chars": special_char_count,
        "url_keyword": contains_keyword,
        "url_keyword_count": keyword_count,
        "num_underbar": url.count("_"),
        "extract_consecutive_numbers": int(bool(re.findall(r'(\d)\1+', url))),
        "numer": int(bool(len(re.findall(r'(\d)(?!\1)(\d)(?!\2)(\d)', url)))),
        "upper": int(any(c.isupper() for c in url)),
        
        # New domain-specific features
        "domain_length": domain_length,
        "has_subdomain": has_subdomain,
        "subdomain_length": subdomain_length,
        "subdomain_count": subdomain_count,
        "tld_length": tld_length,
        "is_common_tld": is_common_tld,
        "is_country_tld": is_country_tld,
        "is_suspicious_tld": is_suspicious_tld,
        
        # URL structure analysis
        "path_length": path_length,
        "path_depth": path_depth,
        "has_query": has_query,
        "query_length": query_length,
        "query_param_count": query_param_count,
        "has_fragment": has_fragment,
        "fragment_length": fragment_length,
        "is_ip_address": is_ip_address,
        "is_shortened": is_shortened,
        
        # Advanced text analysis
        "entropy": entropy,
        "letter_ratio": letter_ratio,
        "digit_ratio": digit_ratio,
        "special_char_ratio": special_char_ratio,
        "contains_brand": contains_brand,
        
        # Advanced pattern detection
        "excessive_subdomains": excessive_subdomains,
        "has_numeric_subdomain": has_numeric_subdomain,
        "has_hyphen_in_domain": has_hyphen_in_domain,
        "hyphen_count": hyphen_count,
        "has_repeated_chars": has_repeated_chars,
        "has_homoglyphs": has_homoglyphs
    }

def process_url_data(df, url_column="URL", chunk_size=100000):
    """
    Process URL data with enhanced feature extraction
    
    Parameters:
    -----------
    df : pandas DataFrame
        DataFrame containing the URL data
    url_column : str
        Name of the column containing URLs
    chunk_size : int
        Size of chunks to process at a time
    
    Returns:
    --------
    pandas DataFrame
        DataFrame with extracted features
    """
    # Split data into chunks for memory efficiency
    chunks = [df[url_column][i:i + chunk_size] for i in range(0, len(df), chunk_size)]
    
    # Process each chunk
    chunk_results = []
    for i, chunk in enumerate(chunks):
        print(f"Processing chunk {i+1}/{len(chunks)}...")
        
        # Extract features for each URL in the chunk
        chunk_features = chunk.apply(extract_enhanced_features)
        
        # Convert to DataFrame
        chunk_df = pd.json_normalize(chunk_features)
        chunk_results.append(chunk_df)
    
    # Combine all chunks
    features_df = pd.concat(chunk_results, ignore_index=True)
    
    return features_df

def normalize_features(features_df, exclude_cols=None):
    """
    Normalize numerical features using StandardScaler
    
    Parameters:
    -----------
    features_df : pandas DataFrame
        DataFrame with extracted features
    exclude_cols : list
        List of column names to exclude from normalization
    
    Returns:
    --------
    pandas DataFrame
        DataFrame with normalized features
    """
    if exclude_cols is None:
        exclude_cols = []
    
    # Identify numerical columns to normalize
    num_cols = features_df.select_dtypes(include=['int64', 'float64']).columns
    num_cols = [col for col in num_cols if col not in exclude_cols]
    
    # Create a copy of the DataFrame
    normalized_df = features_df.copy()
    
    # Apply StandardScaler to numerical columns
    scaler = StandardScaler()
    normalized_df[num_cols] = scaler.fit_transform(features_df[num_cols])
    
    return normalized_df

def calculate_feature_importance(features_df, target, top_n=20):
    """
    Calculate feature importance using Random Forest
    
    Parameters:
    -----------
    features_df : pandas DataFrame
        DataFrame with extracted features
    target : pandas Series
        Target variable (labels)
    top_n : int
        Number of top features to return
    
    Returns:
    --------
    pandas DataFrame
        DataFrame with feature importance scores
    """
    from sklearn.ensemble import RandomForestClassifier
    
    # Train a Random Forest model
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(features_df, target)
    
    # Get feature importance
    importance = rf.feature_importances_
    
    # Create a DataFrame with feature names and importance scores
    feature_importance = pd.DataFrame({
        'feature': features_df.columns,
        'importance': importance
    })
    
    # Sort by importance
    feature_importance = feature_importance.sort_values('importance', ascending=False)
    
    # Return top N features
    return feature_importance.head(top_n)

def visualize_feature_importance(feature_importance, figsize=(12, 8)):
    """
    Visualize feature importance
    
    Parameters:
    -----------
    feature_importance : pandas DataFrame
        DataFrame with feature importance scores
    figsize : tuple
        Figure size
    """
    plt.figure(figsize=figsize)
    plt.barh(feature_importance['feature'], feature_importance['importance'])
    plt.xlabel('Importance')
    plt.ylabel('Feature')
    plt.title('Feature Importance')
    plt.tight_layout()
    plt.savefig('feature_importance.png')
    plt.close()

def reduce_dimensions(features_df, n_components=2, method='pca'):
    """
    Reduce dimensions using PCA or t-SNE
    
    Parameters:
    -----------
    features_df : pandas DataFrame
        DataFrame with extracted features
    n_components : int
        Number of components to reduce to
    method : str
        Method to use for dimensionality reduction ('pca' or 'tsne')
    
    Returns:
    --------
    pandas DataFrame
        DataFrame with reduced dimensions
    """
    if method == 'pca':
        from sklearn.decomposition import PCA
        reducer = PCA(n_components=n_components)
    elif method == 'tsne':
        from sklearn.manifold import TSNE
        reducer = TSNE(n_components=n_components, random_state=42)
    else:
        raise ValueError("Method must be 'pca' or 'tsne'")
    
    # Apply dimensionality reduction
    reduced_features = reducer.fit_transform(features_df)
    
    # Create a DataFrame with reduced dimensions
    reduced_df = pd.DataFrame(
        reduced_features, 
        columns=[f'{method.upper()}{i+1}' for i in range(n_components)]
    )
    
    return reduced_df

def visualize_reduced_dimensions(reduced_df, labels, method='pca', figsize=(10, 8)):
    """
    Visualize reduced dimensions
    
    Parameters:
    -----------
    reduced_df : pandas DataFrame
        DataFrame with reduced dimensions
    labels : pandas Series
        Target variable (labels)
    method : str
        Method used for dimensionality reduction ('pca' or 'tsne')
    figsize : tuple
        Figure size
    """
    plt.figure(figsize=figsize)
    
    # Get column names
    x_col = f'{method.upper()}1'
    y_col = f'{method.upper()}2'
    
    # Create scatter plot
    plt.scatter(reduced_df[x_col], reduced_df[y_col], c=labels, alpha=0.5, cmap='viridis')
    plt.colorbar(label='Label')
    plt.xlabel(x_col)
    plt.ylabel(y_col)
    plt.title(f'{method.upper()} Visualization')
    plt.tight_layout()
    plt.savefig(f'{method.lower()}_visualization.png')
    plt.close()

# Example usage
if __name__ == "__main__":
    # Load data
    train = pd.read_csv("../../train.csv")
    
    # Fix URL format (as in original code)
    train["URL"] = train["URL"].str.replace("[.]", ".", regex=False)
    
    # Extract enhanced features
    features_df = process_url_data(train)
    
    # Save features to CSV
    features_df.to_csv("enhanced_url_features.csv", index=False)
    
    # Normalize features
    normalized_df = normalize_features(features_df)
    
    # Calculate feature importance
    feature_importance = calculate_feature_importance(normalized_df, train['label'])
    
    # Visualize feature importance
    visualize_feature_importance(feature_importance)
    
    # Reduce dimensions for visualization
    reduced_df = reduce_dimensions(normalized_df, method='pca')
    
    # Visualize reduced dimensions
    visualize_reduced_dimensions(reduced_df, train['label'], method='pca')
    
    print("Enhanced URL preprocessing completed!")
