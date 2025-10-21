import os
import json
import csv
import yaml
from datetime import datetime
import shutil
import logging
from ipaddress import ip_address
import requests
import time

# --- Configuration ---
OBSERVATIONS_INPUT_DIR = 'observations'
ENRICHED_OUTPUT_DIR = 'enriched-observations'
ASSET_INVENTORY_FILE = 'asset_inventory.csv'
CONFIG_FILE = 'config/settings.yaml'
ROTATION_INTERVAL_MINUTES = 15

# GeoIP API Configuration
USE_API = True  # Set to False to disable API lookups
API_RATE_LIMIT = 45  # ip-api.com free tier: 45 requests per minute
API_CACHE_FILE = 'geoip_cache.json'

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# API rate limiting
api_request_times = []

# Load configuration
def load_config():
    """Load settings from YAML configuration file."""
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning(f"Configuration file {CONFIG_FILE} not found. Using defaults.")
        return {}
    except yaml.YAMLError as e:
        logger.error(f"Error parsing {CONFIG_FILE}: {e}")
        return {}

CONFIG = load_config()

# --- MITRE ATT&CK Mapping (Knowledge Base) ---
MITRE_MAP = {
    "Recon: Suspicious User-Agent": {"technique_id": "T1595.002", "technique_name": "Active Scanning: Vulnerability Scanning", "tactic": "Reconnaissance"},
    "Recon: DNS Zone Transfer Attempt (AXFR)": {"technique_id": "T1589", "technique_name": "Gather Victim Identity Information", "tactic": "Reconnaissance"},
    "Recon: Connection Refused (Potential Port Scan)": {"technique_id": "T1595.001", "technique_name": "Active Scanning: IP Blocks", "tactic": "Reconnaissance"},
    "Initial Access: SSH Login Failure": {"technique_id": "T1110.001", "technique_name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "Initial Access: SSH Login Success": {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Initial Access"},
    "Initial Access: FTP Login": {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Initial Access"},
    "Initial Access: MySQL Root Login Attempt": {"technique_id": "T1078.001", "technique_name": "Valid Accounts: Default Accounts", "tactic": "Initial Access"},
    "Initial Access: RDP Connection Detected": {"technique_id": "T1133", "technique_name": "External Remote Services", "tactic": "Initial Access"},
    "Initial Access: Insecure Telnet Protocol Use": {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Initial Access"},
    "Execution: HTTP Request to Executable": {"technique_id": "T1204.002", "technique_name": "User Execution: Malicious File", "tactic": "Execution"},
    "Execution: SMB Transfer of Executable": {"technique_id": "T1021.002", "technique_name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "Delivery: Known Malicious Executable Downloaded (jovgraph.exe)": {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "Delivery: Office Document with Macros Transferred": {"technique_id": "T1566.001", "technique_name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access"},
    "Delivery: Java Archive Downloaded via HTTP": {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "Delivery: Script File Transferred (VBS/JS)": {"technique_id": "T1566.001", "technique_name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access"},
    "Credential Access: NTLM Hash Transmitted": {"technique_id": "T1550.002", "technique_name": "Use Alternate Authentication Material: Pass the Hash", "tactic": "Lateral Movement"},
    "Credential Access: Cleartext SMTP Authentication": {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Credential Access"},
    "Defense Evasion: Outdated & Suspicious User-Agent (IE6)": {"technique_id": "T1071.001", "technique_name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
    "Defense Evasion: Unescaped Characters in URI": {"technique_id": "T1027.004", "technique_name": "Obfuscated Files or Information: Compile After Delivery", "tactic": "Defense Evasion"},
    "Defense Evasion: Connection to High Ephemeral Port": {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": "Command and Control"},
    "Defense Evasion: Suricata Alert Suppression Detected": {"technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion"},
    "C2: Potential DNS Tunneling (Long Query)": {"technique_id": "T1071.004", "technique_name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
    "C2: Self-Signed SSL/TLS Certificate": {"technique_id": "T1573", "technique_name": "Encrypted Channel", "tactic": "Command and Control"},
    "C2: BitTorrent Tracker Communication": {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "C2: IRC Communication Detected": {"technique_id": "T1071.003", "technique_name": "Application Layer Protocol: Mail Protocols", "tactic": "Command and Control"},
    "C2: Connection to Dynamic DNS Domain": {"technique_id": "T1568.002", "technique_name": "Dynamic Resolution: Dynamic DNS", "tactic": "Command and Control"},
    "Lateral Movement: SMB Share Access": {"technique_id": "T1021.002", "technique_name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "Lateral Movement: SMB Write to Admin Share (ADMIN$ or C$)": {"technique_id": "T1021.002", "technique_name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "Impact: Potential SQL Injection Attempt": {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Impact: Suricata Web Application Attack": {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Impact: MySQL Sensitive Command (DROP/DELETE)": {"technique_id": "T1485", "technique_name": "Data Destruction", "tactic": "Impact"},
    "Impact: Suricata RPC Portmap Decode Alert": {"technique_id": "T1210", "technique_name": "Exploitation of Remote Services", "tactic": "Lateral Movement"}
}

# --- GeoIP Cache Management ---
def load_geoip_cache():
    """Load cached GeoIP lookups from disk."""
    if os.path.exists(API_CACHE_FILE):
        try:
            with open(API_CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Could not load GeoIP cache: {e}")
    return {}

def save_geoip_cache(cache):
    """Save GeoIP cache to disk."""
    try:
        with open(API_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2)
    except IOError as e:
        logger.warning(f"Could not save GeoIP cache: {e}")

geoip_cache = load_geoip_cache()

# --- IP Validation ---
def is_private_ip(ip):
    """Check if an IP is private (RFC 1918)."""
    try:
        ip_obj = ip_address(ip)
        return ip_obj.is_private
    except ValueError as e:
        logger.warning(f"Invalid IP {ip}: {e}")
        return False

# --- API Rate Limiting ---
def wait_for_rate_limit():
    """Enforce API rate limiting."""
    global api_request_times
    current_time = time.time()
    
    # Remove requests older than 60 seconds
    api_request_times = [t for t in api_request_times if current_time - t < 60]
    
    # If we've hit the limit, wait
    if len(api_request_times) >= API_RATE_LIMIT:
        sleep_time = 60 - (current_time - api_request_times[0])
        if sleep_time > 0:
            logger.info(f"Rate limit reached. Waiting {sleep_time:.2f} seconds...")
            time.sleep(sleep_time)
            api_request_times = []
    
    api_request_times.append(time.time())

# --- GeoIP Enrichment via API ---
def enrich_geoip_api(ip):
    """Enrich an IP with GeoIP data using ip-api.com (free tier)."""
    if is_private_ip(ip):
        return {
            'country': 'Internal',
            'city': 'Private Network',
            'latitude': None,
            'longitude': None,
            'asn': '',
            'asn_organization': 'Internal Network',
            'isp': 'Internal',
            'timezone': 'N/A'
        }
    
    # Check cache first
    if ip in geoip_cache:
        logger.debug(f"Using cached GeoIP data for {ip}")
        return geoip_cache[ip]
    
    if not USE_API:
        logger.debug(f"API disabled, skipping lookup for {ip}")
        return {}
    
    try:
        # Rate limiting
        wait_for_rate_limit()
        
        # Make API request
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon,isp,as,timezone"
        response = requests.get(url, timeout=5)
        
        if response.status_code != 200:
            logger.warning(f"API request failed for {ip}: HTTP {response.status_code}")
            return {}
        
        data = response.json()
        
        if data.get('status') != 'success':
            logger.warning(f"API lookup failed for {ip}: {data.get('message', 'Unknown error')}")
            return {}
        
        # Parse AS number from "AS15169 Google LLC" format
        asn = ''
        asn_org = data.get('as', '')
        if asn_org:
            parts = asn_org.split(' ', 1)
            if parts[0].startswith('AS'):
                asn = parts[0][2:]  # Remove 'AS' prefix
                asn_org = parts[1] if len(parts) > 1 else asn_org
        
        geo_data = {
            'country': data.get('country', ''),
            'city': data.get('city', ''),
            'latitude': data.get('lat'),
            'longitude': data.get('lon'),
            'asn': asn,
            'asn_organization': asn_org,
            'isp': data.get('isp', ''),
            'timezone': data.get('timezone', '')
        }
        
        # Cache the result
        geoip_cache[ip] = geo_data
        
        logger.debug(f"GeoIP lookup successful for {ip}: {geo_data['country']}, {geo_data['city']}")
        return geo_data
        
    except requests.exceptions.RequestException as e:
        logger.warning(f"Network error during GeoIP lookup for {ip}: {e}")
        return {}
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Error parsing GeoIP response for {ip}: {e}")
        return {}

# --- Asset Inventory (Static Only) ---
def load_asset_inventory():
    """Loads the asset inventory CSV into a dictionary for quick lookups."""
    inventory = {}
    if not os.path.exists(ASSET_INVENTORY_FILE):
        logger.warning(f"Asset inventory file not found: {ASSET_INVENTORY_FILE}")
        return inventory
    
    logger.info(f"Loading asset inventory from {ASSET_INVENTORY_FILE}")
    with open(ASSET_INVENTORY_FILE, mode='r', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            ip = row.get('ip', '').strip()
            if ip:
                inventory[ip] = {
                    'hostname': row.get('hostname', ''),
                    'business_unit': row.get('business_unit', ''),
                    'owner': row.get('owner', ''),
                    'criticality': row.get('criticality', ''),
                    'exposure': row.get('exposure', ''),
                    'vulnerability_score': row.get('vulnerability_score', '')
                }
    return inventory

# --- Risk Modifiers ---
def get_risk_modifiers(observation, inventory):
    """Calculates risk modifiers based on the asset inventory (NIST model simulation)."""
    modifiers = {}
    src_ip = observation.get("observation", {}).get("source_event", {}).get("source", {}).get("ip")
    dst_ip = observation.get("observation", {}).get("source_event", {}).get("destination", {}).get("ip")

    asset_info = inventory.get(src_ip) or inventory.get(dst_ip)
    if asset_info:
        criticality = asset_info.get('criticality', '').lower()
        if criticality == 'high':
            modifiers['impact_multiplier'] = 2.0
        elif criticality == 'medium':
            modifiers['impact_multiplier'] = 1.5
        
        vulnerability = asset_info.get('vulnerability_score', '').lower()
        if vulnerability == 'critical':
            modifiers['vulnerability_multiplier'] = 2.0
        elif vulnerability == 'medium':
            modifiers['vulnerability_multiplier'] = 1.5
    return modifiers

# --- Main Enrichment Logic ---
def process_observations(inventory):
    """Reads observations, enriches with MITRE and GeoIP, and writes to new files."""
    logger.info("Starting Enrichment Engine...")
    if not os.path.exists(OBSERVATIONS_INPUT_DIR):
        logger.error(f"Observations directory not found: {OBSERVATIONS_INPUT_DIR}")
        return

    if os.path.exists(ENRICHED_OUTPUT_DIR):
        shutil.rmtree(ENRICHED_OUTPUT_DIR)
    os.makedirs(ENRICHED_OUTPUT_DIR, exist_ok=True)

    private_ip_count = 0
    api_lookup_count = 0
    cache_hit_count = 0
    
    for filename in sorted(os.listdir(OBSERVATIONS_INPUT_DIR)):
        if not filename.endswith('.jsonl'):
            continue

        logger.info(f"Processing file: {filename}")
        input_path = os.path.join(OBSERVATIONS_INPUT_DIR, filename)
        output_path = os.path.join(ENRICHED_OUTPUT_DIR, filename.replace('observation-', 'enriched-'))
        
        with open(input_path, 'r', encoding='utf-8') as infile, \
             open(output_path, 'w', encoding='utf-8') as outfile:
            
            for line in infile:
                try:
                    obs = json.loads(line)
                    observation = obs.get("observation", {})
                    obs_name = observation.get("name", "")
                    source_event = observation.get("source_event", {})

                    # 1. MITRE ATT&CK Enrichment
                    if obs_name in MITRE_MAP:
                        obs["observation"]["mitre_attack"] = MITRE_MAP[obs_name]

                    # 2. NIST Risk Model Enrichment
                    modifiers = get_risk_modifiers(obs, inventory)
                    if modifiers:
                        obs["observation"]["risk_modifiers"] = modifiers

                    # 3. GeoIP Enrichment via API
                    src_ip = source_event.get("source", {}).get("ip")
                    dst_ip = source_event.get("destination", {}).get("ip")
                    
                    if src_ip:
                        if is_private_ip(src_ip):
                            private_ip_count += 1
                        else:
                            if src_ip in geoip_cache:
                                cache_hit_count += 1
                            else:
                                api_lookup_count += 1
                        
                        geo_data = enrich_geoip_api(src_ip)
                        if geo_data:
                            obs["observation"]["geoip"] = obs["observation"].get("geoip", {})
                            obs["observation"]["geoip"]["source_ip"] = geo_data
                    
                    if dst_ip:
                        if is_private_ip(dst_ip):
                            private_ip_count += 1
                        else:
                            if dst_ip in geoip_cache:
                                cache_hit_count += 1
                            else:
                                api_lookup_count += 1
                        
                        geo_data = enrich_geoip_api(dst_ip)
                        if geo_data:
                            obs["observation"]["geoip"] = obs["observation"].get("geoip", {})
                            obs["observation"]["geoip"]["destination_ip"] = geo_data

                    outfile.write(json.dumps(obs) + '\n')

                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning(f"Skipping invalid line in {filename}: {e}")
                    continue
    
    # Save cache
    save_geoip_cache(geoip_cache)
    
    logger.info(f"GeoIP Statistics:")
    logger.info(f"  - Private IPs (skipped): {private_ip_count}")
    logger.info(f"  - API lookups performed: {api_lookup_count}")
    logger.info(f"  - Cache hits: {cache_hit_count}")
    logger.info(f"  - Total cached entries: {len(geoip_cache)}")

def main():
    """Main function to run the enrichment engine."""
    logger.info("=" * 60)
    logger.info("Context Engine - GeoIP Enrichment via ip-api.com")
    logger.info("=" * 60)
    
    # Load static asset inventory
    asset_inventory = load_asset_inventory()
    
    # Process observations
    process_observations(asset_inventory)
    
    logger.info("Enrichment Engine finished.")
    logger.info(f"Output enriched observations are in the '{ENRICHED_OUTPUT_DIR}' directory.")

if __name__ == "__main__":
    main()