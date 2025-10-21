import os
import json
from datetime import datetime, timezone, timedelta
import shutil
import logging

# --- Configuration ---
NORMALIZED_INPUT_DIR = 'normalized-logs'
OBSERVATIONS_OUTPUT_DIR = 'observations'
PROFILES_INPUT_FILE = 'entity_profiles_statistical.json'
ROTATION_INTERVAL_MINUTES = 15
RULES_CONFIG_PATH = os.path.join("config", "correlation_rules.json")
GEOIP_CONFIG_PATH = os.path.join("config", "geoip_risk.json")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- UEBA Configuration ---
RARITY_THRESHOLD_PERCENT = 1.0  # Alert if behavior occurs less than 1% of the time
GEOIP_NEW_COUNTRY_THRESHOLD = 100  # Alert if country was contacted less than 0.5% of the time

# --- GeoIP Cache ---
geoip_cache = {}

# --- Helper Functions ---
def load_json_config(path, default=None):
    """Load JSON config file with default fallback."""
    if default is None:
        default = []
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load {path}: {e}. Using default.")
            return default
    logger.info(f"Config file {path} not found. Using default.")
    return default

# Load configurations
GEOIP_CONFIG = load_json_config(GEOIP_CONFIG_PATH, {})
RULES = load_json_config(RULES_CONFIG_PATH, [])

def load_profiles():
    """Load statistical profiles for UEBA."""
    if os.path.exists(PROFILES_INPUT_FILE):
        try:
            with open(PROFILES_INPUT_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load profiles from {PROFILES_INPUT_FILE}: {e}")
    return {}

def get_nested_value(d, key_path):
    """Safely gets a value from a nested dictionary using a dot-separated path."""
    keys = key_path.split('.')
    for key in keys:
        if isinstance(d, dict):
            d = d.get(key)
        else:
            return None
    return d

def check_condition(event, field, condition, profiles):
    """Evaluates a single condition against an event."""
    event_value = get_nested_value(event, field)
    if event_value is None:
        return False

    # Handle simple equality checks
    if not isinstance(condition, dict):
        return str(event_value).lower() == str(condition).lower()

    cond_type = condition.get("type")
    cond_value = condition.get("value", condition.get("threshold"))

    # --- GeoIP-Based UEBA Checks ---
    if cond_type in ["is_new_country", "is_rare_asn", "is_rare_isp", "is_high_risk_country"]:
        if not profiles:
            logger.debug(f"No profiles available for {cond_type} check")
            return False
        source_ip = get_nested_value(event, 'source.ip')
        profile = profiles.get(source_ip)
        if not profile:
            logger.debug(f"No profile for source IP {source_ip}")
            return True

        dest_ip = get_nested_value(event, 'destination.ip')
        if not dest_ip or dest_ip not in geoip_cache:
            logger.debug(f"No GeoIP data for destination IP {dest_ip}")
            return False

        geo_data = geoip_cache.get(dest_ip, {})
        if not geo_data:
            logger.debug(f"Empty GeoIP data for destination IP {dest_ip}")
            return False

        if cond_type == "is_new_country":
            country = geo_data.get('country')
            if not country:
                return False
            country_counts = profile.get('geoip', {}).get('countries_contacted', {})
            count = country_counts.get(country, 0)
            threshold = condition.get("threshold", GEOIP_NEW_COUNTRY_THRESHOLD)
            result = count < threshold
            logger.debug(f"is_new_country: country={country}, count={count}, threshold={threshold}, result={result}")
            return result

        if cond_type == "is_rare_asn":
            asn = geo_data.get('asn')
            if not asn:
                return False
            asn_counts = profile.get('geoip', {}).get('asn_contacted', {})
            count = asn_counts.get(asn, 0)
            total_connections = profile.get('total_connections', 1)
            frequency = (count / total_connections) * 100 if total_connections > 0 else 0
            threshold = condition.get("threshold", RARITY_THRESHOLD_PERCENT)
            result = frequency < threshold
            logger.debug(f"is_rare_asn: asn={asn}, frequency={frequency}, threshold={threshold}, result={result}")
            return result

        if cond_type == "is_rare_isp":
            isp = geo_data.get('isp')
            if not isp:
                return False
            isp_counts = profile.get('geoip', {}).get('isp_contacted', {})
            count = isp_counts.get(isp, 0)
            total_connections = profile.get('total_connections', 1)
            frequency = (count / total_connections) * 100 if total_connections > 0 else 0
            threshold = condition.get("threshold", RARITY_THRESHOLD_PERCENT)
            result = frequency < threshold
            logger.debug(f"is_rare_isp: isp={isp}, frequency={frequency}, threshold={threshold}, result={result}")
            return result

        if cond_type == "is_high_risk_country":
            country = geo_data.get('country')
            if not country:
                return False
            high_risk_countries = GEOIP_CONFIG.get("high_risk_countries", [])
            result = country in high_risk_countries
            logger.debug(f"is_high_risk_country: country={country}, high_risk={high_risk_countries}, result={result}")
            return result

    # --- UEBA Checks ---
    if cond_type == "is_rare_port":
        if not profiles:
            return False
        source_ip = get_nested_value(event, 'source.ip')
        profile = profiles.get(source_ip)
        if not profile:
            return True
        port_counts = profile.get('port_counts', {})
        count_for_this_port = port_counts.get(str(event_value), 0)
        frequency = (count_for_this_port / profile['total_connections']) * 100 if profile['total_connections'] > 0 else 0
        result = frequency < condition.get("threshold", RARITY_THRESHOLD_PERCENT)
        logger.debug(f"is_rare_port: port={event_value}, frequency={frequency}, threshold={condition.get('threshold', RARITY_THRESHOLD_PERCENT)}, result={result}")
        return result

    if cond_type == "is_new_user_agent":
        if not profiles:
            return True
        source_ip = get_nested_value(event, 'source.ip')
        profile = profiles.get(source_ip)
        if not profile:
            return True
        known_agents = profile.get('user_agent_counts', {})
        result = str(event_value) not in known_agents
        logger.debug(f"is_new_user_agent: user_agent={event_value}, known={known_agents.keys()}, result={result}")
        return result

    # --- Standard Static Checks ---
    if cond_type == "length_gt":
        result = isinstance(event_value, str) and len(event_value) > cond_value
        logger.debug(f"length_gt: value={event_value}, length={len(event_value) if isinstance(event_value, str) else 'N/A'}, threshold={cond_value}, result={result}")
        return result
    elif cond_type == "gt":
        try:
            result = int(event_value) > cond_value
            logger.debug(f"gt: value={event_value}, threshold={cond_value}, result={result}")
            return result
        except (ValueError, TypeError):
            logger.debug(f"gt: Invalid value {event_value} for comparison with {cond_value}")
            return False
    elif cond_type == "ends_with_any":
        result = isinstance(event_value, str) and any(event_value.lower().endswith(sub.lower()) for sub in cond_value)
        logger.debug(f"ends_with_any: value={event_value}, suffixes={cond_value}, result={result}")
        return result
    elif cond_type == "contains_any":
        result = isinstance(event_value, str) and any(sub.lower() in event_value.lower() for sub in cond_value)
        logger.debug(f"contains_any: value={event_value}, substrings={cond_value}, result={result}")
        return result
    elif cond_type == "is_in":
        result = str(event_value) in cond_value
        logger.debug(f"is_in: value={event_value}, set={cond_value}, result={result}")
        return result
    elif cond_type == "not_in":
        result = str(event_value) not in cond_value if isinstance(event_value, (str, int)) else False
        logger.debug(f"not_in: value={event_value}, set={cond_value}, result={result}")
        return result
    elif cond_type == "not_equals":
        result = event_value != cond_value if isinstance(event_value, bool) else str(event_value).lower() != str(cond_value).lower()
        logger.debug(f"not_equals: value={event_value}, expected={cond_value}, result={result}")
        return result
    elif cond_type == "equals_field":
        other_field_value = get_nested_value(event, cond_value)
        result = other_field_value is not None and event_value == other_field_value
        logger.debug(f"equals_field: value={event_value}, other_field={cond_value}, other_value={other_field_value}, result={result}")
        return result
    
    logger.debug(f"Unknown condition type: {cond_type}")
    return False

def process_normalized_files(profiles):
    """Reads logs, applies rules (including GeoIP UEBA), and writes observations."""
    logger.info("=" * 60)
    logger.info("SIEM Correlation Engine with GeoIP UEBA")
    logger.info("=" * 60)
    
    if not os.path.exists(NORMALIZED_INPUT_DIR):
        logger.error(f"Normalized log directory not found: {NORMALIZED_INPUT_DIR}")
        return

    if os.path.exists(OBSERVATIONS_OUTPUT_DIR):
        shutil.rmtree(OBSERVATIONS_OUTPUT_DIR)
    os.makedirs(OBSERVATIONS_OUTPUT_DIR, exist_ok=True)

    # Load GeoIP cache
    global geoip_cache
    if os.path.exists('geoip_cache.json'):
        try:
            with open('geoip_cache.json', 'r', encoding='utf-8') as f:
                geoip_cache = json.load(f)
            logger.info(f"Loaded {len(geoip_cache)} GeoIP cache entries")
        except Exception as e:
            logger.warning(f"Could not load GeoIP cache: {e}")

    # Load all rules
    all_rules = load_json_config(RULES_CONFIG_PATH)
    logger.info(f"Loaded {len(all_rules)} rules from {RULES_CONFIG_PATH}")
    # Filter only enabled rules
    CORRELATION_RULES = [rule for rule in all_rules if rule.get("enabled", True)]
    logger.info(f"Using {len(CORRELATION_RULES)} enabled rules for correlation")

    current_file = None
    current_window_start = None
    observation_count = 0
    rule_hit_counts = {}

    try:
        for filename in sorted(os.listdir(NORMALIZED_INPUT_DIR)):
            if not filename.endswith('.jsonl'):
                continue
            logger.info(f"Processing file: {filename}")
            file_path = os.path.join(NORMALIZED_INPUT_DIR, filename)
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        for rule in CORRELATION_RULES:
                            match = all(check_condition(event, field, cond, profiles) for field, cond in rule["conditions"].items())
                            if match:
                                observation_count += 1
                                rule_name = rule["name"]
                                rule_hit_counts[rule_name] = rule_hit_counts.get(rule_name, 0) + 1
                                
                                event_dt = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
                                observation = {
                                    "@timestamp": event['@timestamp'],
                                    "observation": {
                                        "name": rule["name"],
                                        "base_risk_score": rule["base_score"],
                                        "source_event": event,
                                        "mitre_attack": {
                                            "technique_id": rule.get("mitre_technique_id", ""),
                                            "tactic": rule.get("mitre_tactic", "")
                                        }
                                    }
                                }
                                
                                minute_window = (event_dt.minute // ROTATION_INTERVAL_MINUTES) * ROTATION_INTERVAL_MINUTES
                                event_window_start = event_dt.replace(minute=minute_window, second=0, microsecond=0)

                                if event_window_start != current_window_start:
                                    if current_file:
                                        current_file.close()
                                    current_window_start = event_window_start
                                    out_filename = f"observation-{current_window_start.strftime('%Y%m%d-%H%M%S')}.jsonl"
                                    current_file_path = os.path.join(OBSERVATIONS_OUTPUT_DIR, out_filename)
                                    logger.info(f"  -> Creating observation file: {current_file_path}")
                                    current_file = open(current_file_path, 'w', encoding='utf-8')
                                
                                if current_file:
                                    current_file.write(json.dumps(observation) + '\n')
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.debug(f"Skipping invalid event in {filename}: {e}")
                        continue
    except Exception as e:
        logger.error(f"Error processing files: {e}")
    finally:
        if current_file:
            current_file.close()
    
    # Display statistics
    logger.info("=" * 60)
    logger.info(f"✅ Correlation complete!")
    logger.info(f"Total observations generated: {observation_count}")
    logger.info("=" * 60)
    
    if rule_hit_counts:
        logger.info("\nTop 10 triggered rules:")
        sorted_rules = sorted(rule_hit_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for rule_name, count in sorted_rules:
            logger.info(f"  {count:4d}x - {rule_name}")
    
    logger.info(f"\nOutput observations are in '{OBSERVATIONS_OUTPUT_DIR}' directory.")

if __name__ == "__main__":
    entity_profiles = load_profiles()
    process_normalized_files(entity_profiles)
    logger.info("\n✅ Correlation Engine with GeoIP UEBA finished.")