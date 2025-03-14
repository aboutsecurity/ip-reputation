import streamlit as st
import requests
import ipaddress
import json
import os
import time
from dotenv import load_dotenv
from ratelimit import limits, sleep_and_retry
import pandas as pd
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# API Keys
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')

# Constants
ONE_MINUTE = 60
INDUSTRY_KEYWORDS = ["finance", "healthcare", "technology", "education", "government", "retail", "manufacturing"]

# App configuration
st.set_page_config(
    page_title="IP Reputation Analyzer",
    page_icon="🔍",
    layout="wide"
)

# Define rate-limited API requests
@sleep_and_retry
@limits(calls=5, period=ONE_MINUTE)
def call_abuseipdb_api(ip_address):
    """Rate-limited AbuseIPDB API call"""
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json',
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90,
        'verbose': True
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Error querying AbuseIPDB: {e}")
        return None

@sleep_and_retry
@limits(calls=4, period=ONE_MINUTE)
def call_virustotal_api(ip_address):
    """Rate-limited VirusTotal API call"""
    if not VIRUSTOTAL_API_KEY:
        return None
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Error querying VirusTotal: {e}")
        return None

@sleep_and_retry
@limits(calls=1, period=ONE_MINUTE)
def call_shodan_api(ip_address):
    """Rate-limited Shodan API call"""
    if not SHODAN_API_KEY:
        return None
        
    url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Error querying Shodan: {e}")
        return None

def is_valid_ip(ip):
    """Validate if the input is a valid IPv4 or IPv6 address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def calculate_recency_score(last_reported_days):
    """Calculate a score based on how recently the IP was reported"""
    if last_reported_days is None:
        return 0
    
    if last_reported_days < 7:
        return 1.0  # Very recent (last week)
    elif last_reported_days < 30:
        return 0.7  # Recent (last month)
    elif last_reported_days < 90:
        return 0.4  # Not so recent (last 3 months)
    else:
        return 0.1  # Old report

def calculate_industry_relevance(reports, industry_keywords):
    """Calculate relevance to the user's industry based on keywords"""
    relevance_score = 0
    
    # Check if there are any reports
    if not reports:
        return 0
    
    # Analyze report data
    keywords_found = 0
    for report in reports:
        report_text = str(report).lower()
        for keyword in industry_keywords:
            if keyword.lower() in report_text:
                keywords_found += 1
                
    # Calculate a relevance score
    if keywords_found > 0:
        relevance_score = min(1.0, keywords_found / len(industry_keywords))
        
    return relevance_score

def calculate_confidence_score(results):
    """Calculate overall confidence score based on multiple factors"""
    sources_count = sum(1 for source in results.values() if source)
    if sources_count == 0:
        return 0
    
    # Base score based on the number of sources that returned results
    multiple_sources_score = min(1.0, sources_count / 3)
    
    # Reputation scores from different sources
    reputation_score = 0
    if results['abuseipdb']:
        abuse_confidence_score = results['abuseipdb'].get('data', {}).get('abuseConfidenceScore', 0)
        reputation_score += abuse_confidence_score / 100  # Normalize to 0-1
    
    if results['virustotal']:
        vt_data = results['virustotal'].get('data', {}).get('attributes', {})
        malicious_count = vt_data.get('last_analysis_stats', {}).get('malicious', 0)
        total_count = sum(vt_data.get('last_analysis_stats', {}).values() or [0])
        if total_count > 0:
            reputation_score += (malicious_count / total_count)

    # Normalize reputation score
    if sources_count > 0:
        reputation_score /= sources_count
    
    # Calculate recency score
    recency_score = 0
    last_reported_days = None
    if results['abuseipdb']:
        reports = results['abuseipdb'].get('data', {}).get('reports', [])
        if reports:
            try:
                most_recent = min([datetime.strptime(report.get('reportedAt', '2000-01-01'), "%Y-%m-%dT%H:%M:%S%z")
                                  for report in reports])
                last_reported_days = (datetime.now(most_recent.tzinfo) - most_recent).days
            except:
                last_reported_days = None
    
    recency_score = calculate_recency_score(last_reported_days)
    
    # Industry relevance
    industry_relevance = 0
    if results['abuseipdb']:
        reports = results['abuseipdb'].get('data', {}).get('reports', [])
        industry_relevance = calculate_industry_relevance(reports, INDUSTRY_KEYWORDS)
    
    # Weighted confidence score
    confidence_score = (
        0.3 * multiple_sources_score +
        0.3 * reputation_score +
        0.25 * recency_score +
        0.15 * industry_relevance
    )
    
    return min(1.0, confidence_score)

def format_results(results, confidence_score, ip_address):
    """Format the results for display"""
    formatted_results = {}
    
    # AbuseIPDB
    if results['abuseipdb']:
        abuse_data = results['abuseipdb'].get('data', {})
        formatted_results['AbuseIPDB'] = {
            'IP Address': abuse_data.get('ipAddress'),
            'Abuse Confidence Score': f"{abuse_data.get('abuseConfidenceScore')}%",
            'Country': abuse_data.get('countryCode'),
            'ISP': abuse_data.get('isp'),
            'Domain': abuse_data.get('domain'),
            'Total Reports': abuse_data.get('totalReports'),
            'Last Reported': abuse_data.get('lastReportedAt'),
            'More Info': f"[View on AbuseIPDB](https://www.abuseipdb.com/check/{ip_address})"
        }
    
    # VirusTotal
    if results['virustotal']:
        vt_data = results['virustotal'].get('data', {}).get('attributes', {})
        stats = vt_data.get('last_analysis_stats', {})
        formatted_results['VirusTotal'] = {
            'Malicious': stats.get('malicious', 0),
            'Suspicious': stats.get('suspicious', 0),
            'Harmless': stats.get('harmless', 0),
            'Undetected': stats.get('undetected', 0),
            'Country': vt_data.get('country'),
            'AS Owner': vt_data.get('as_owner'),
            'More Info': f"[View on VirusTotal](https://www.virustotal.com/gui/ip-address/{ip_address})"
        }
    
    # Shodan
    if results['shodan']:
        shodan_data = results['shodan']
        ports = shodan_data.get('ports', [])
        tags = shodan_data.get('tags', [])
        formatted_results['Shodan'] = {
            'Country': shodan_data.get('country_name'),
            'City': shodan_data.get('city'),
            'Organization': shodan_data.get('org'),
            'ISP': shodan_data.get('isp'),
            'Open Ports': ', '.join(map(str, ports)) if ports else 'None',
            'Tags': ', '.join(tags) if tags else 'None',
            'Last Update': shodan_data.get('last_update'),
            'More Info': f"[View on Shodan](https://www.shodan.io/host/{ip_address})"
        }
    
    # Add overall confidence score
    formatted_results['Confidence'] = {
        'Overall Score': f"{confidence_score:.2%}",
        'Classification': get_classification(confidence_score)
    }
    
    return formatted_results

def get_classification(score):
    """Get a classification based on the confidence score"""
    if score >= 0.8:
        return "High Risk"
    elif score >= 0.5:
        return "Medium Risk"
    elif score >= 0.2:
        return "Low Risk"
    else:
        return "Minimal Risk"

def main():
    st.title("IP Reputation Analyzer")
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("Configuration")
        industry = st.multiselect(
            "Select Your Industry",
            options=INDUSTRY_KEYWORDS,
            default=["technology"]
        )
        
        # API key inputs
        st.header("API Keys")
        abuseipdb_key = st.text_input("AbuseIPDB API Key", value=ABUSEIPDB_API_KEY or "", type="password")
        virustotal_key = st.text_input("VirusTotal API Key (Optional)", value=VIRUSTOTAL_API_KEY or "", type="password")
        shodan_key = st.text_input("Shodan API Key (Optional)", value=SHODAN_API_KEY or "", type="password")
        
        # Save keys to .env
        if st.button("Save API Keys"):
            with open(".env", "w") as f:
                f.write(f"ABUSEIPDB_API_KEY={abuseipdb_key}\n")
                f.write(f"VIRUSTOTAL_API_KEY={virustotal_key}\n")
                f.write(f"SHODAN_API_KEY={shodan_key}\n")
            st.success("API keys saved to .env file")
    
    st.header("IP Reputation Analysis")
    ip_address = st.text_input("Enter IP Address to Check", "")
    
    if st.button("Analyze IP") and ip_address:
        if not is_valid_ip(ip_address):
            st.error("Invalid IP address. Please enter a valid IPv4 or IPv6 address.")
        else:
            with st.spinner("Analyzing IP reputation..."):
                # Check if API key is provided
                if not ABUSEIPDB_API_KEY and not abuseipdb_key:
                    st.error("AbuseIPDB API key is required. Please enter it in the sidebar.")
                else:
                    # Query all available APIs
                    results = {
                        'abuseipdb': call_abuseipdb_api(ip_address),
                        'virustotal': call_virustotal_api(ip_address) if VIRUSTOTAL_API_KEY or virustotal_key else None,
                        'shodan': call_shodan_api(ip_address) if SHODAN_API_KEY or shodan_key else None,
                    }
                    
                    # Calculate confidence score
                    confidence_score = calculate_confidence_score(results)
                    
                    # Format results
                    formatted_results = format_results(results, confidence_score, ip_address)
                    
                    # Display results
                    st.header(f"Results for {ip_address}")
                
                    # Display confidence score with color
                    confidence = formatted_results.get('Confidence', {})
                    classification = confidence.get('Classification', 'Unknown')
                    score = confidence.get('Overall Score', '0%')
                    
                    if "High Risk" in classification:
                        st.error(f"Confidence: {score} - {classification}")
                    elif "Medium Risk" in classification:
                        st.warning(f"Confidence: {score} - {classification}")
                    elif "Low Risk" in classification:
                        st.info(f"Confidence: {score} - {classification}")
                    else:
                        st.success(f"Confidence: {score} - {classification}")
                    
                    # Display sources data in tabs
                    tabs = st.tabs(list(formatted_results.keys())[:-1])  # Exclude confidence tab
                    
                    for i, (source, data) in enumerate(list(formatted_results.items())[:-1]):  # Exclude confidence data
                        with tabs[i]:
                            # Convert to DataFrame for better display
                            df = pd.DataFrame(list(data.items()), columns=['Attribute', 'Value'])
                            for idx, row in df.iterrows():
                                if row['Attribute'] == 'More Info' and '[' in str(row['Value']):
                                    # Display markdown link
                                    st.markdown(f"**{row['Attribute']}**: {row['Value']}")
                                    # Remove this row from dataframe
                                    df = df.drop(idx)
                            
                            # Display the rest of the data as a table
                            st.table(df)
                    
                    # Show raw data in expander
                    with st.expander("Show Raw API Response Data"):
                        st.json(results)

if __name__ == "__main__":
    main()