import os
import json
from collections import defaultdict
import requests
import time
import logging
from ipaddress import ip_address

# --- Configuration ---
NORMALIZED_INPUT_DIR = 'normalized-logs'
PROFILES_OUTPUT_FILE = 'entity_profiles_statistical.json'

# GeoIP API Configuration
USE_API = True
API_RATE_LIMIT = 45  # ip-api.com free tier: 45 requests per minute
API_CACHE_FILE = 'geoip_cache.json'

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# API rate limiting
api_request_times = []

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
    except ValueError:
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
        return geoip_cache[ip]
    
    if not USE_API:
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
                asn = parts[0][2:]
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
        
        logger.debug(f"GeoIP lookup for {ip}: {geo_data['country']}, {geo_data['city']}")
        return geo_data
        
    except requests.exceptions.RequestException as e:
        logger.warning(f"Network error during GeoIP lookup for {ip}: {e}")
        return {}
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Error parsing GeoIP response for {ip}: {e}")
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

def build_statistical_profiles():
    """Reads all normalized logs to build a statistical baseline for each entity with GeoIP."""
    logger.info("=" * 60)
    logger.info("UEBA Statistical Profiler with GeoIP Support")
    logger.info("=" * 60)
    
    if not os.path.exists(NORMALIZED_INPUT_DIR):
        logger.error(f"Normalized log directory not found: {NORMALIZED_INPUT_DIR}")
        return

    # Enhanced profile structure with GeoIP
    entity_profiles = defaultdict(lambda: {
        "port_counts": defaultdict(int),
        "protocol_counts": defaultdict(int),
        "user_agent_counts": defaultdict(int),
        "dns_query_counts": defaultdict(int),
        "total_connections": 0,
        "geoip": {
            "countries_contacted": defaultdict(int),
            "cities_contacted": defaultdict(int),
            "asn_contacted": defaultdict(int),
            "isp_contacted": defaultdict(int)
        },
        "geo_metadata": {}  # Store the entity's own GeoIP data
    })

    # Track unique IPs for GeoIP lookup
    unique_ips = set()
    
    logger.info("Phase 1: Collecting unique IPs for GeoIP lookup...")
    for filename in sorted(os.listdir(NORMALIZED_INPUT_DIR)):
        if not filename.endswith('.jsonl'):
            continue
        
        file_path = os.path.join(NORMALIZED_INPUT_DIR, filename)
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    src_ip = get_nested_value(event, 'source.ip')
                    dst_ip = get_nested_value(event, 'destination.ip')
                    
                    if src_ip and not is_private_ip(src_ip):
                        unique_ips.add(src_ip)
                    if dst_ip and not is_private_ip(dst_ip):
                        unique_ips.add(dst_ip)
                        
                except (json.JSONDecodeError, KeyError):
                    continue
    
    logger.info(f"Found {len(unique_ips)} unique public IPs to lookup")
    
    # Pre-fetch GeoIP data for all unique IPs
    logger.info("Phase 2: Fetching GeoIP data...")
    geoip_lookup_count = 0
    for ip in unique_ips:
        if ip not in geoip_cache:
            geoip_lookup_count += 1
            enrich_geoip_api(ip)
    
    logger.info(f"Performed {geoip_lookup_count} new GeoIP lookups")
    logger.info(f"Using {len(geoip_cache)} cached GeoIP entries")
    
    # Save cache after bulk lookups
    save_geoip_cache(geoip_cache)

    logger.info("Phase 3: Building behavioral profiles...")
    for filename in sorted(os.listdir(NORMALIZED_INPUT_DIR)):
        if not filename.endswith('.jsonl'):
            continue

        logger.info(f"  -> Profiling file: {filename}")
        file_path = os.path.join(NORMALIZED_INPUT_DIR, filename)
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    
                    source_ip = get_nested_value(event, 'source.ip')
                    if not source_ip:
                        continue

                    # Get entity's own GeoIP data
                    if not entity_profiles[source_ip]['geo_metadata']:
                        geo_data = enrich_geoip_api(source_ip)
                        if geo_data:
                            entity_profiles[source_ip]['geo_metadata'] = geo_data

                    # Increment total connection count for this IP
                    if get_nested_value(event, 'event.dataset') == 'conn':
                        entity_profiles[source_ip]['total_connections'] += 1

                    # Behavioral counts
                    dest_port = get_nested_value(event, 'destination.port')
                    if dest_port:
                        entity_profiles[source_ip]['port_counts'][str(dest_port)] += 1
                    
                    protocol = get_nested_value(event, 'network.protocol')
                    if protocol:
                        entity_profiles[source_ip]['protocol_counts'][protocol] += 1
                        
                    user_agent = get_nested_value(event, 'user_agent.original')
                    if user_agent:
                        entity_profiles[source_ip]['user_agent_counts'][user_agent] += 1
                        
                    dns_query = get_nested_value(event, 'dns.question.name')
                    if dns_query:
                        entity_profiles[source_ip]['dns_query_counts'][dns_query] += 1
                    
                    # GeoIP profiling - track destinations contacted
                    dest_ip = get_nested_value(event, 'destination.ip')
                    if dest_ip and not is_private_ip(dest_ip):
                        dest_geo = enrich_geoip_api(dest_ip)
                        if dest_geo:
                            country = dest_geo.get('country')
                            if country:
                                entity_profiles[source_ip]['geoip']['countries_contacted'][country] += 1
                            
                            city = dest_geo.get('city')
                            if city:
                                entity_profiles[source_ip]['geoip']['cities_contacted'][city] += 1
                            
                            asn = dest_geo.get('asn')
                            if asn:
                                entity_profiles[source_ip]['geoip']['asn_contacted'][asn] += 1
                            
                            isp = dest_geo.get('isp')
                            if isp:
                                entity_profiles[source_ip]['geoip']['isp_contacted'][isp] += 1

                except (json.JSONDecodeError, KeyError):
                    continue
    
    # Convert defaultdicts to regular dicts for JSON serialization
    logger.info("Phase 4: Finalizing profiles...")
    final_profiles = {}
    for ip, profile in entity_profiles.items():
        final_profiles[ip] = {
            'port_counts': dict(profile['port_counts']),
            'protocol_counts': dict(profile['protocol_counts']),
            'user_agent_counts': dict(profile['user_agent_counts']),
            'dns_query_counts': dict(profile['dns_query_counts']),
            'total_connections': profile['total_connections'],
            'geoip': {
                'countries_contacted': dict(profile['geoip']['countries_contacted']),
                'cities_contacted': dict(profile['geoip']['cities_contacted']),
                'asn_contacted': dict(profile['geoip']['asn_contacted']),
                'isp_contacted': dict(profile['geoip']['isp_contacted'])
            },
            'geo_metadata': profile['geo_metadata']
        }
    
    # Save profiles
    with open(PROFILES_OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(final_profiles, f, indent=2)

    # Save final cache state
    save_geoip_cache(geoip_cache)

    # Statistics
    logger.info("=" * 60)
    logger.info(f"✅ Statistical profiling complete!")
    logger.info(f"  - Profiled entities: {len(final_profiles)}")
    logger.info(f"  - Total GeoIP cache entries: {len(geoip_cache)}")
    logger.info(f"  - Output file: {PROFILES_OUTPUT_FILE}")
    logger.info("=" * 60)

if __name__ == "__main__":
    build_statistical_profiles()