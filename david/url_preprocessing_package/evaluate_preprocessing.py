import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score, roc_curve
import time

# Import our enhanced preprocessing module
from enhanced_url_preprocessing import process_url_data, normalize_features, calculate_feature_importance, visualize_feature_importance, reduce_dimensions, visualize_reduced_dimensions

# Create a small sample dataset for demonstration
def create_sample_dataset():
    # Sample phishing URLs
    phishing_urls = [
        "open24.ie-news.irish/online/Login",
        "93fm.radio.br/file",
        "ps.com.vu/wp-config/wp-incluides/soft/ursnbxmmvd",
        "165.232.173.145/mobile.html",
        "apollo.baby",
        "employeesalaryschedule70.000webhostapp.com/adblock/",
        "rthe.top/",
        "www2.ml.meiceaord.com",
        "10rtggdoffice.duckdns.org",
        "posts-8012419782.smarttechno.hr"
    ]
    
    # Sample legitimate URLs
    legitimate_urls = [
        "google.com",
        "facebook.com",
        "amazon.com",
        "youtube.com",
        "twitter.com",
        "instagram.com",
        "linkedin.com",
        "microsoft.com",
        "apple.com",
        "github.com"
    ]
    
    # Create DataFrame
    urls = phishing_urls + legitimate_urls
    labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)
    ids = [f"SAMPLE_{i}" for i in range(len(urls))]
    
    df = pd.DataFrame({
        "ID": ids,
        "URL": urls,
        "label": labels
    })
    
    return df

def evaluate_model(X_train, X_test, y_train, y_test):
    """
    Train a Random Forest model and evaluate its performance
    """
    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Make predictions
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    
    # Print results
    print(f"Accuracy: {accuracy:.4f}")
    print(f"AUC: {auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Plot confusion matrix
    plt.figure(figsize=(8, 6))
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False)
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix')
    plt.savefig('confusion_matrix.png')
    plt.close()
    
    # Plot ROC curve
    plt.figure(figsize=(8, 6))
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    plt.plot(fpr, tpr, label=f'AUC = {auc:.4f}')
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve')
    plt.legend()
    plt.savefig('roc_curve.png')
    plt.close()
    
    return model

def compare_feature_sets(original_features, enhanced_features, labels):
    """
    Compare performance between original and enhanced feature sets
    """
    # Split data
    X_orig_train, X_orig_test, X_enh_train, X_enh_test, y_train, y_test = train_test_split(
        original_features, enhanced_features, labels, test_size=0.3, random_state=42
    )
    
    # Evaluate original features
    print("\n=== Original Features ===")
    start_time = time.time()
    orig_model = evaluate_model(X_orig_train, X_orig_test, y_train, y_test)
    orig_time = time.time() - start_time
    print(f"Training time: {orig_time:.2f} seconds")
    
    # Evaluate enhanced features
    print("\n=== Enhanced Features ===")
    start_time = time.time()
    enh_model = evaluate_model(X_enh_train, X_enh_test, y_train, y_test)
    enh_time = time.time() - start_time
    print(f"Training time: {enh_time:.2f} seconds")
    
    return orig_model, enh_model

def analyze_feature_importance(model, feature_names, title, filename):
    """
    Analyze and visualize feature importance from a trained model
    """
    # Get feature importance
    importance = model.feature_importances_
    
    # Create DataFrame
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': importance
    })
    
    # Sort by importance
    feature_importance = feature_importance.sort_values('importance', ascending=False)
    
    # Print top 10 features
    print(f"\nTop 10 {title}:")
    print(feature_importance.head(10))
    
    # Plot feature importance
    plt.figure(figsize=(12, 8))
    plt.barh(feature_importance.head(20)['feature'], feature_importance.head(20)['importance'])
    plt.xlabel('Importance')
    plt.ylabel('Feature')
    plt.title(f'Top 20 {title}')
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()
    
    return feature_importance

def main():
    print("=== URL Preprocessing Evaluation ===")
    
    # Create sample dataset
    print("Creating sample dataset...")
    sample_df = create_sample_dataset()
    print(f"Sample dataset created with {len(sample_df)} URLs")
    
    # Extract original features (based on the notebook)
    print("\nExtracting original features...")
    
    def extract_original_features(url):
        from urllib.parse import urlparse
        import re
        
        parsed_url = urlparse(url)
        keywords = 'login|verify|account|update|secure|banking|paypal|confirm|signin|auth|redirect|free|bonus|admin|support|server|password|click|urgent|immediate|alert|security|prompt'

        contains_keyword = int(bool(re.search(keywords, url, flags=re.IGNORECASE)))
        
        url_length = len(url)
        
        if url_length <= 13:
            url_length_cat = 0  
        elif url_length <= 18:
            url_length_cat = 1 
        elif url_length <= 25:
            url_length_cat = 2 
        else:
            url_length_cat = 3 

        return {
            "url_length": url_length,
            "url_length_cat": url_length_cat,
            "num_dots": url.count("."),
            "num_slashes": url.count("/"),
            "num_digits": sum(c.isdigit() for c in url),
            "num_special_chars": len(re.findall(r"[^a-zA-Z0-9]", url)),
            "url_keyword": contains_keyword,
            "url_keyword_count": len(re.findall(keywords, url, flags=re.IGNORECASE)),
            "num_underbar": url.count("_"),
            "extract_consecutive_numbers": int(bool(re.findall(r'(\d)\1+', url))),
            "numer": int(bool(len(re.findall(r'(\d)(?!\1)(\d)(?!\2)(\d)', url)))),
            "upper": int(any(c.isupper() for c in url))
        }
    
    # Extract original features
    original_features = pd.json_normalize(sample_df["URL"].apply(extract_original_features))
    print(f"Original features extracted: {original_features.shape[1]} features")
    
    # Extract enhanced features
    print("\nExtracting enhanced features...")
    enhanced_features = process_url_data(sample_df)
    print(f"Enhanced features extracted: {enhanced_features.shape[1]} features")
    
    # Compare feature sets
    print("\nComparing feature sets...")
    orig_model, enh_model = compare_feature_sets(
        original_features, enhanced_features, sample_df['label']
    )
    
    # Analyze feature importance
    print("\nAnalyzing feature importance...")
    orig_importance = analyze_feature_importance(
        orig_model, original_features.columns, 
        "Original Features Importance", "original_feature_importance.png"
    )
    
    enh_importance = analyze_feature_importance(
        enh_model, enhanced_features.columns, 
        "Enhanced Features Importance", "enhanced_feature_importance.png"
    )
    
    # Visualize data with dimensionality reduction
    print("\nVisualizing data with dimensionality reduction...")
    
    # Normalize features
    normalized_features = normalize_features(enhanced_features)
    
    # PCA visualization
    pca_features = reduce_dimensions(normalized_features, method='pca')
    visualize_reduced_dimensions(pca_features, sample_df['label'], method='pca')
    
    print("\nEvaluation complete! Check the generated visualizations:")
    print("- confusion_matrix.png")
    print("- roc_curve.png")
    print("- original_feature_importance.png")
    print("- enhanced_feature_importance.png")
    print("- pca_visualization.png")

if __name__ == "__main__":
    main()
