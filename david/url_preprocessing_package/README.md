# Enhanced URL Preprocessing for Phishing Detection

This repository contains code for enhanced URL preprocessing techniques to improve phishing detection models.

## Overview

The implementation builds upon the existing preprocessing pipeline and adds several advanced features:

1. **Domain-specific features**:
   - Domain length and structure analysis
   - Subdomain detection and analysis
   - TLD (Top-Level Domain) analysis
   - Common vs. suspicious TLD detection

2. **URL structure analysis**:
   - Path length and depth analysis
   - Query parameter analysis
   - Fragment analysis
   - IP address detection
   - URL shortener detection

3. **Advanced text analysis**:
   - Character distribution entropy
   - Character type ratios
   - Brand name detection
   - Enhanced suspicious keyword detection

4. **Advanced pattern detection**:
   - Excessive subdomain detection
   - Numeric subdomain detection
   - Hyphen analysis
   - Repeated character detection
   - Homoglyph attack detection

5. **Feature engineering improvements**:
   - Feature normalization
   - Feature importance calculation
   - Dimensionality reduction (PCA, t-SNE)
   - Visualization tools

## Files

- `enhanced_url_preprocessing.py`: Main implementation with all preprocessing functions
- `feature_importance.png`: Visualization of feature importance (generated when script is run)
- `pca_visualization.png`: PCA visualization of reduced dimensions (generated when script is run)

## Usage

To use the enhanced preprocessing:

```python
import pandas as pd
from enhanced_url_preprocessing import process_url_data, normalize_features

# Load your data
data = pd.read_csv("your_data.csv")

# Extract enhanced features
features_df = process_url_data(data, url_column="URL")

# Normalize features (optional)
normalized_df = normalize_features(features_df)

# Save processed features
features_df.to_csv("enhanced_features.csv", index=False)
```

## Requirements

The implementation requires the following Python packages:
- numpy
- pandas
- matplotlib
- scikit-learn
- tldextract

Install with:
```
pip install numpy pandas matplotlib scikit-learn tldextract
```

## Feature Details

### Domain-specific Features

- `domain_length`: Length of the domain name
- `has_subdomain`: Whether the URL has a subdomain
- `subdomain_length`: Length of the subdomain
- `subdomain_count`: Number of subdomains
- `tld_length`: Length of the TLD
- `is_common_tld`: Whether the TLD is common (com, org, net, etc.)
- `is_country_tld`: Whether the TLD is a country code
- `is_suspicious_tld`: Whether the TLD is commonly used in phishing

### URL Structure Analysis

- `path_length`: Length of the URL path
- `path_depth`: Depth of the URL path (number of directories)
- `has_query`: Whether the URL has query parameters
- `query_length`: Length of the query string
- `query_param_count`: Number of query parameters
- `has_fragment`: Whether the URL has a fragment
- `fragment_length`: Length of the fragment
- `is_ip_address`: Whether the domain is an IP address
- `is_shortened`: Whether the URL is shortened

### Advanced Text Analysis

- `entropy`: Shannon entropy of character distribution
- `letter_ratio`: Ratio of letters to total characters
- `digit_ratio`: Ratio of digits to total characters
- `special_char_ratio`: Ratio of special characters to total characters
- `contains_brand`: Whether the URL contains a popular brand name

### Advanced Pattern Detection

- `excessive_subdomains`: Whether the URL has excessive subdomains
- `has_numeric_subdomain`: Whether the subdomain contains numbers
- `has_hyphen_in_domain`: Whether the domain contains hyphens
- `hyphen_count`: Number of hyphens in the domain
- `has_repeated_chars`: Whether the domain has repeated characters
- `has_homoglyphs`: Whether the domain contains homoglyphs (similar-looking characters)
