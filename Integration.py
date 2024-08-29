
import os
import pandas as pd
import requests
import logging
import time
from sklearn.ensemble import RandomForestClassifier
import yaml
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_schema_mapping(config_file='schema_mapping.yaml'):
    """
    Load schema mapping from a YAML file.
    :param config_file: Path to the YAML configuration file.
    :return: Dictionary containing the schema mapping.
    """
    logging.info("Loading schema mapping")
    try:
        with open(config_file, 'r') as file:
            mapping = yaml.safe_load(file)
        logging.info("Schema mapping loaded successfully")
        return mapping
    except FileNotFoundError:
        logging.error(f"Schema mapping file not found: {config_file}")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file: {e}")
        raise

def fetch_binaryedge_data(api_key, query):
    url = "https://api.binaryedge.io/v2/query/search"
    headers = {"X-Key": api_key}
    params = {"query": query}
    
    for attempt in range(3):
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()  # This will raise an HTTPError for bad responses
            return response.json()
        except requests.exceptions.HTTPError as err:
            logging.error(f"Attempt {attempt + 1} failed: {err}")
            if attempt == 2:
                raise Exception("All retry attempts failed")
            time.sleep(2)  # Wait before retrying

# Load API key from environment variable
binaryedge_api_key = os.getenv('BINARYEDGE_API_KEY')

if not binaryedge_api_key:
    binaryedge_api_key = "b0a47305-8f18-445b-827f-bd5945b6c583"

if not binaryedge_api_key:
    raise ValueError("BinaryEdge API key not found. Please set the BINARYEDGE_API_KEY environment variable.")

else:
    print(f"BinaryEdge API Key: {binaryedge_api_key}")


def fetch_siem_data(api_url, api_key, retries=3, backoff_factor=1):
    """
    Fetch SIEM alerts from the SIEM API.
    :param api_url: API URL for fetching SIEM alerts.
    :param api_key: API key for the SIEM.
    :param retries: Number of retry attempts in case of failure.
    :param backoff_factor: Backoff factor for exponential backoff.
    :return: DataFrame containing SIEM alerts.
    """
    logging.info("Fetching SIEM data")
    attempt = 0
    while attempt < retries:
        try:
            headers = {'Authorization': f'Bearer {api_key}'}
            response = requests.get(api_url, headers=headers, timeout=30)
            response.raise_for_status()
            return pd.DataFrame(response.json())
        except requests.RequestException as e:
            logging.error(f"Attempt {attempt + 1} failed: {e}")
            time.sleep(backoff_factor * (2 ** attempt))
            attempt += 1
    raise Exception("All retry attempts failed")

def normalize_threat_data(threat_data, schema_mapping):
    # Ensure threat_data is a pandas DataFrame
    if isinstance(threat_data, dict):
        threat_data = pd.DataFrame(threat_data)

    # Rename the columns according to schema_mapping
    threat_data.rename(columns=schema_mapping, inplace=True)
    
    return threat_data

def enrich_siem_alerts(siem_alerts, threat_intel):
    """
    Enrich SIEM alerts with threat intelligence data.
    :param siem_alerts: DataFrame containing SIEM alerts.
    :param threat_intel: DataFrame containing normalized threat intelligence data.
    :return: DataFrame containing enriched SIEM alerts.
    """
    logging.info("Enriching SIEM alerts with threat intelligence")
    try:
        enriched_alerts = siem_alerts.merge(threat_intel, on='ip', how='left')
        enriched_alerts['priority'] = enriched_alerts.apply(lambda x: 'High' if pd.notnull(x['threat_score']) else 'Low', axis=1)
        return enriched_alerts
    except Exception as e:
        logging.error(f"Error during alert enrichment: {e}")
        raise

def prioritize_and_analyze_alerts(enriched_alerts, model=None):
    """
    Prioritize SIEM alerts using a Random Forest model and analyze them.
    :param enriched_alerts: DataFrame containing enriched SIEM alerts.
    :param model: Pre-trained Random Forest model (if available).
    :return: Tuple containing analyzed alerts and the trained model.
    """
    logging.info("Prioritizing and analyzing alerts")
    try:
        if model is None:
            model = RandomForestClassifier()
            model.fit(enriched_alerts[['threat_score']], enriched_alerts['priority'])
        
        enriched_alerts['predicted_priority'] = model.predict(enriched_alerts[['threat_score']])
        return enriched_alerts, model
    except Exception as e:
        logging.error(f"Error during alert prioritization or analysis: {e}")
        raise

def store_enriched_alerts(enriched_alerts, db_connection_string):
    """
    Store the enriched SIEM alerts in a database.
    :param enriched_alerts: DataFrame containing enriched SIEM alerts.
    :param db_connection_string: Database connection string.
    """
    logging.info("Storing enriched alerts in the database")
    try:
        engine = create_engine(db_connection_string)
        enriched_alerts.to_sql('enriched_alerts', engine, if_exists='append', index=False)
    except SQLAlchemyError as e:
        logging.error(f"Database error occurred: {e}")
        raise

def real_time_integration_process(siem_api_url, siem_token, binaryedge_api_key, config_file, db_connection_string, interval=60):
    """
    Main process that runs in real-time to integrate SIEM alerts with threat intelligence.
    :param siem_api_url: API URL for fetching SIEM alerts.
    :param siem_token: API key/token for SIEM.
    :param binaryedge_api_key: API key for BinaryEdge.
    :param config_file: Path to the schema mapping YAML file.
    :param db_connection_string: Database connection string.
    :param interval: Time interval between each run of the integration process.
    """
    logging.info("Starting real-time integration process")
    schema_mapping = load_schema_mapping(config_file)
    model = None
    last_run_time = datetime.now() - timedelta(seconds=interval)
    
    while True:
        current_time = datetime.now()
        
        # Fetch threat intel from BinaryEdge
        binaryedge_query = "type:scan OR type:vulnerability"  # Adjust this query as needed
        threat_intel = fetch_binaryedge_data(binaryedge_api_key, binaryedge_query)
        normalized_threat_intel = normalize_threat_data(threat_intel, schema_mapping)
        
        # Fetch SIEM alerts
        siem_alerts = fetch_siem_data(siem_api_url, siem_token)
        siem_alerts = siem_alerts[pd.to_datetime(siem_alerts['timestamp']) > last_run_time]
        
        if not siem_alerts.empty:
            enriched_alerts = enrich_siem_alerts(siem_alerts, normalized_threat_intel)
            analyzed_alerts, model = prioritize_and_analyze_alerts(enriched_alerts, model)
            
            initial_count = len(siem_alerts)
            final_count = len(analyzed_alerts[analyzed_alerts['priority'] != 'Low'])
            reduction_in_false_positives = initial_count - final_count
            efficiency_increase = (reduction_in_false_positives / initial_count) * 100 if initial_count > 0 else 0
            
            logging.info(f"Reduction in False Positives: {reduction_in_false_positives}")
            logging.info(f"Efficiency Increase: {efficiency_increase:.2f}%")
            
            store_enriched_alerts(analyzed_alerts, db_connection_string)
        else:
            logging.info("No new SIEM alerts to process")
        
        last_run_time = current_time
        time.sleep(interval)

if __name__ == "__main__":
    real_time_integration_process(
        siem_api_url=os.getenv('https://my-deployment-5fec7c.kb.asia-south1.gcp.elastic-cloud.com:9243'),
        siem_token=os.getenv('TnowcmtKRUJHUWM5ZXRSOGRRdTg6cWtzc0hQT0ZSOG1vNlpWTHRudm05dw=='),
        binaryedge_api_key = os.getenv('BINARYEDGE_API_KEY'),
        config_file = r"schema_mapping.yaml",
        db_connection_string=os.getenv('sqlite:///enriched_alerts.db'),
        interval = int(os.getenv('INTERVAL', 60))

    )
