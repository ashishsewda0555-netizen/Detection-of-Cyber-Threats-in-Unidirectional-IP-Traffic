import os
import joblib
import pandas as pd
import shap
import matplotlib.pyplot as plt
import numpy as np

def run_shap_analysis():
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "ddos_unified_model.joblib")
    DATA_PATH = os.path.join(os.path.dirname(__file__), "unified_features.csv")
    
    if not os.path.exists(MODEL_PATH) or not os.path.exists(DATA_PATH):
        print("Model or data not found.")
        return
        
    print("Loading model and data for SHAP analysis...")
    bundle = joblib.load(MODEL_PATH)
    clf = bundle["clf"]
    scaler = bundle["scaler"]
    feature_cols = bundle["feature_cols"]
    
    df = pd.read_csv(DATA_PATH)
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
    
    X_raw = df[feature_cols]
    X_scaled = scaler.transform(X_raw)
    
    print("Computing SHAP values (TreeExplainer)...")
    explainer = shap.TreeExplainer(clf)
    
    # We sample down if it's too large, but 1700 rows is fine
    shap_values = explainer.shap_values(X_scaled)
    
    # Get mean absolute SHAP value for each feature
    if isinstance(shap_values, list):
        mean_shap = np.abs(np.array(shap_values)).mean(axis=0).mean(axis=0)
    else:
        mean_shap = np.abs(shap_values).mean(axis=0)
        if mean_shap.ndim > 1:
            mean_shap = mean_shap.mean(axis=1)
            
    # Ensure it's 1D and matches feature_cols length
    if len(mean_shap) != len(feature_cols):
        print(f"Warning: mean_shap length {len(mean_shap)} != feature_cols {len(feature_cols)}. Truncating/padding.")
        if len(mean_shap) > len(feature_cols):
            mean_shap = mean_shap[:len(feature_cols)]
        else:
            mean_shap = np.pad(mean_shap, (0, len(feature_cols) - len(mean_shap)))
            
    feature_importance = pd.DataFrame({
        "Feature": feature_cols,
        "Mean_Absolute_SHAP": mean_shap
    }).sort_values(by="Mean_Absolute_SHAP", ascending=False)
    
    print("\n--- Top Features by Mean Absolute SHAP ---")
    print(feature_importance.to_string(index=False))

if __name__ == "__main__":
    run_shap_analysis()
