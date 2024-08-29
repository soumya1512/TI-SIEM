import pandas as pd
import random
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Step 1: Load the Real Threat Intelligence Data
def load_threat_intel_data(file_path):
    logging.info(f"Loading threat intelligence data from {file_path}")
    try:
        threat_intel = pd.read_csv(file_path)
        logging.info(f"Successfully loaded {len(threat_intel)} records from {file_path}")
        return threat_intel
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        raise
    except pd.errors.EmptyDataError:
        logging.error(f"No data found in file: {file_path}")
        raise
    except Exception as e:
        logging.error(f"An error occurred while loading the file: {e}")
        raise

# Step 2: Preprocess the Threat Intelligence Data
def preprocess_threat_intel_data(threat_intel):
    logging.info("Preprocessing threat intelligence data")
    
    # Handle missing values
    threat_intel = threat_intel.dropna()
    
    # Encode categorical variables
    label_encoder = LabelEncoder()
    if 'event_type' in threat_intel.columns:
        threat_intel['event_type_encoded'] = label_encoder.fit_transform(threat_intel['event_type'])
    else:
        logging.error("The column 'event_type' is not found in the dataset.")
        raise Exception("Required column missing.")
    
    return threat_intel

# Step 3: Train the Random Forest Model
def train_random_forest_model(threat_intel):
    logging.info("Training Random Forest model")
    
    X = threat_intel[['confidence_score', 'event_type_encoded']]
    y = threat_intel['severity']  # Assuming 'severity' is the target variable

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    
    logging.info(f"Model Accuracy: {accuracy_score(y_test, y_pred)}")
    logging.info(f"Classification Report:\n{classification_report(y_test, y_pred)}")
    
    return model

# Step 4: Enrich SIEM Alerts with Threat Intelligence
def enrich_siem_alerts(siem_alerts, threat_intel, model):
    logging.info("Enriching SIEM alerts with threat intelligence")
    enriched_alerts = siem_alerts.merge(threat_intel, on='ip', how='left')
    
    if 'threat_score' in enriched_alerts.columns:
        enriched_alerts['predicted_priority'] = model.predict(enriched_alerts[['threat_score']])
    else:
        logging.error("The column 'threat_score' is not found in the merged dataset.")
        raise Exception("Required column missing.")
    
    return enriched_alerts

# Step 5: Load SIEM Data and Run the Integration Process
def load_siem_data(file_name):
    logging.info(f"Loading SIEM data from {file_name}")
    try:
        siem_data = pd.read_csv(file_name)
        logging.info(f"Successfully loaded {len(siem_data)} records from {file_name}")
        return siem_data
    except FileNotFoundError:
        logging.error(f"File not found: {file_name}")
        raise
    except pd.errors.EmptyDataError:
        logging.error(f"No data found in file: {file_name}")
        raise
    except Exception as e:
        logging.error(f"An error occurred while loading the file: {e}")
        raise

def run_real_time_integration(siem_file, threat_intel_file):
    logging.info("Starting real-time integration process with real data")

    # Load data
    siem_data = load_siem_data('ai_ml_cybersecurity_dataset.csv')
    threat_intel_data = load_threat_intel_data(threat_intel_file)
    
    # Preprocess threat intelligence data
    threat_intel_data = preprocess_threat_intel_data(threat_intel_data)
    
    # Train the model
    model = train_random_forest_model(threat_intel_data)
    
    # Enrich SIEM alerts with threat intelligence and prioritize them
    enriched_alerts = enrich_siem_alerts(siem_data, threat_intel_data, model)
    
    # Generate a report
    generate_report(enriched_alerts)
    
    logging.info("Real-time integration process completed.")

# Step 6: Generate a Report
def generate_report(enriched_alerts, report_file='report.txt'):
    logging.info(f"Generating report: {report_file}")
    try:
        with open(report_file, 'w') as file:
            high_priority_alerts = enriched_alerts[enriched_alerts['predicted_priority'] == 'High']
            file.write(f"Total Alerts Processed: {len(enriched_alerts)}\n")
            file.write(f"High Priority Alerts: {len(high_priority_alerts)}\n")
            file.write(f"Percentage of High Priority Alerts: {(len(high_priority_alerts) / len(enriched_alerts)) * 100:.2f}%\n")
        logging.info(f"Report generated successfully: {report_file}")
    except Exception as e:
        logging.error(f"An error occurred while generating the report: {e}")
        raise

if __name__ == "__main__":
    # Run the real-time integration process using the loaded CSV files
    run_real_time_integration('mock_siem_data.csv', 'ai_ml_cybersecurity_dataset.csv')