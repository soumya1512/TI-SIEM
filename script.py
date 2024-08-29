import os
import pandas as pd
import requests
import logging
import time
from sklearn.ensemble import RandomForestClassifier
from joblib import dump, load
import yaml
from sqlalchemy import create_engine, MetaData
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
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as err:
            logging.error(f"Attempt {attempt + 1} failed: {err}")
            if attempt == 2:
                raise Exception("All retry attempts failed")
            time.sleep(2)  # Wait before retrying

def fetch_siem_data(base_url, api_key, endpoint='', retries=3, backoff_factor=1):
    """
    Fetch SIEM data with improved error handling.
    """
    logging.info(f"Fetching SIEM data from {base_url}")
    for attempt in range(retries):
        try:
            headers = {'Authorization': f'ApiKey {api_key}'}
            full_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
            response = requests.get(full_url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, list):
                return pd.DataFrame(data)
            elif isinstance(data, dict):
                return pd.DataFrame([data])
            else:
                raise ValueError(f"Unexpected data format: {type(data)}")
        except requests.RequestException as e:
            logging.error(f"Attempt {attempt + 1} failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logging.error(f"Error response content: {e.response.text}")
        except Exception as e:
            logging.error(f"Unexpected error on attempt {attempt + 1}: {str(e)}")
        
        if attempt < retries - 1:
            time.sleep(backoff_factor * (2 ** attempt))
    
    raise Exception("All retry attempts failed")

def normalize_threat_data(threat_data, schema_mapping):
    # Ensure threat_data is a pandas DataFrame
    if isinstance(threat_data, dict):
        threat_data = pd.DataFrame(threat_data)

    # Rename the columns according to schema_mapping
    threat_data.rename(columns=schema_mapping, inplace=True)
    
    # Validate schema compliance
    for field in schema_mapping.values():
        if field not in threat_data.columns:
            logging.warning(f"Missing expected field: {field}")

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
        enriched_alerts['priority'] = enriched_alerts.apply(
            lambda x: 'High' if pd.notnull(x['threat_score']) and x['threat_score'] > 7 else 'Low', axis=1
        )
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
            dump(model, 'random_forest_model.joblib')  # Persist the model
        
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
        metadata = MetaData()
        metadata.reflect(bind=engine)
        
        # Add indexes if they don't exist
        with engine.connect() as connection:
            for column in ['ip', 'timestamp', 'priority']:
                if column not in metadata.tables['enriched_alerts'].columns:
                    logging.info(f"Creating index on {column}")
                    connection.execute(f"CREATE INDEX idx_{column} ON enriched_alerts ({column})")

        enriched_alerts.to_sql('enriched_alerts', engine, if_exists='append', index=False)
    except SQLAlchemyError as e:
        logging.error(f"Database error occurred: {e}")
        raise

def generate_report(enriched_alerts, report_file='report.txt'):
    """
    Generate a report summarizing key metrics.
    :param enriched_alerts: DataFrame containing enriched SIEM alerts.
    :param report_file: Path to the report file.
    """
    try:
        high_priority_alerts = enriched_alerts[enriched_alerts['predicted_priority'] == 'High']
        total_alerts = len(enriched_alerts)
        high_priority_count = len(high_priority_alerts)
        
        with open(report_file, 'w') as f:
            f.write(f"Total Alerts Processed: {total_alerts}\n")
            f.write(f"High Priority Alerts: {high_priority_count}\n")
            f.write(f"Percentage of High Priority Alerts: {high_priority_count / total_alerts * 100:.2f}%\n")
        
        logging.info(f"Report generated successfully: {report_file}")
    except Exception as e:
        logging.error(f"Error generating report: {e}")
        raise

def real_time_integration_process(siem_base_url, siem_token, binaryedge_api_key, config_file, db_connection_string, interval=60):
    logging.info("Starting real-time integration process")
    schema_mapping = load_schema_mapping(config_file)
    model = None
    last_run_time = datetime.now() - timedelta(seconds=interval)
    
    # Load the existing model if available
    if os.path.exists('random_forest_model.joblib'):
        model = load('random_forest_model.joblib')
    
    while True:
        current_time = datetime.now()
        
        # Fetch threat intel from BinaryEdge
        binaryedge_query = "type:scan OR type:vulnerability"
        threat_intel = fetch_binaryedge_data(binaryedge_api_key, binaryedge_query)
        normalized_threat_intel = normalize_threat_data(threat_intel, schema_mapping)
        
        # Fetch SIEM alerts
        endpoints = ['', 'api/alerts', 'api/v1/alerts', '_search']
        for endpoint in endpoints:
            try:
                siem_alerts = fetch_siem_data(siem_base_url, siem_token, endpoint)
                logging.info(f"Successfully fetched data from endpoint: {endpoint}")
                break
            except Exception as e:
                logging.error(f"Failed to fetch data from endpoint {endpoint}: {e}")
        else:
            logging.error("Failed to fetch SIEM data from all attempted endpoints")
            siem_alerts = pd.DataFrame() 
        
        if not siem_alerts.empty:
            enriched_alerts = enrich_siem_alerts(siem_alerts, normalized_threat_intel)
            analyzed_alerts, model = prioritize_and_analyze_alerts(enriched_alerts, model)
            
            initial_count = len(siem_alerts)
            final_count = len(analyzed_alerts[analyzed_alerts['predicted_priority'] == 'High'])
            reduction_in_false_positives = initial_count - final_count
            efficiency_increase = (reduction_in_false_positives / initial_count) * 100 if initial_count > 0 else 0
            
            logging.info(f"Reduction in False Positives: {reduction_in_false_positives}")
            logging.info(f"Efficiency Increase: {efficiency_increase:.2f}%")
            
            store_enriched_alerts(analyzed_alerts, db_connection_string)
            generate_report(analyzed_alerts)
        else:
            logging.info("No new SIEM alerts to process")
        
        last_run_time = current_time
        time.sleep(interval)


if __name__ == "__main__":
    real_time_integration_process(
        siem_base_url="https://my-deployment-5fec7c.kb.asia-south1.gcp.elastic-cloud.com:9243",
        siem_token="TnowcmtKRUJHUWM5ZXRSOGRRdTg6cWtzc0hQT0ZSOG1vNlpWTHRudm05dw==",
        binaryedge_api_key='a0858ade-936e-48a4-b218-80bd37db258d',
        config_file="schema_mapping.yaml",
        db_connection_string="sqlite:///enriched_alerts.db",
        interval=60
    )
