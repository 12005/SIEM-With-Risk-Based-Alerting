import os
import json
from datetime import datetime, timezone, timedelta
import shutil

# --- Configuration ---
ZEEK_INPUT_DIR = 'zeek-logs'
SURICATA_INPUT_DIR = 'suricata-logs'
NORMALIZED_OUTPUT_DIR = 'normalized-logs'
ROTATION_INTERVAL_MINUTES = 15 # Create a new file every 15 minutes

# --- ECS-like Field Mappings ---
# Maps source field names to our target normalized field names.
FIELD_MAPS = {
    'zeek_conn': {
        'ts': '@timestamp',
        'uid': 'event.id',
        'id.orig_h': 'source.ip',
        'id.orig_p': 'source.port',
        'id.resp_h': 'destination.ip',
        'id.resp_p': 'destination.port',
        'proto': 'network.transport',
        'service': 'network.protocol',
        'duration': 'event.duration',
        'orig_bytes': 'source.bytes',
        'resp_bytes': 'destination.bytes',
        'conn_state': 'network.state',
        'history': 'network.history'
    },
    'zeek_dns': {
        'ts': '@timestamp',
        'uid': 'event.id',
        'id.orig_h': 'source.ip',
        'id.orig_p': 'source.port',
        'id.resp_h': 'destination.ip',
        'id.resp_p': 'destination.port',
        'proto': 'network.transport',
        'query': 'dns.question.name',
        'qtype_name': 'dns.question.type',
        'rcode_name': 'dns.answer.rcode',
        'answers': 'dns.answers'
    },
    'zeek_http': {
        'ts': '@timestamp',
        'uid': 'event.id',
        'id.orig_h': 'source.ip',
        'id.orig_p': 'source.port',
        'id.resp_h': 'destination.ip',
        'id.resp_p': 'destination.port',
        'method': 'http.request.method',
        'host': 'url.domain',
        'uri': 'url.path',
        'user_agent': 'user_agent.original',
        'status_code': 'http.response.status_code',
        'resp_mime_types': 'http.response.mime_type'
    },
    'zeek_weird': {
        'ts': '@timestamp',
        'uid': 'event.id',
        'id.orig_h': 'source.ip',
        'id.orig_p': 'source.port',
        'id.resp_h': 'destination.ip',
        'id.resp_p': 'destination.port',
        'name': 'rule.name',
        'addl': 'event.reason',
        'notice': 'event.action'
    },
    'zeek_ssl': {
        'ts': '@timestamp',
        'uid': 'event.id',
        'id.orig_h': 'source.ip',
        'id.orig_p': 'source.port',
        'id.resp_h': 'destination.ip',
        'id.resp_p': 'destination.port',
        'version': 'tls.version',
        'cipher': 'tls.cipher',
        'server_name': 'tls.server.name',
        'subject': 'tls.server.subject',
        'issuer_subject': 'tls.server.issuer'
    },
    'zeek_files': {
        'ts': '@timestamp',
        'fuid': 'file.id',
        'tx_hosts': 'source.ip',
        'rx_hosts': 'destination.ip',
        'conn_uids': 'event.id',
        'mime_type': 'file.mime_type',
        'filename': 'file.name',
        'md5': 'file.hash.md5',
        'sha1': 'file.hash.sha1'
    },
    'zeek_smb_mapping': {
        'ts': '@timestamp',
        'uid': 'event.id',
        'id.orig_h': 'source.ip',
        'id.orig_p': 'source.port',
        'id.resp_h': 'destination.ip',
        'id.resp_p': 'destination.port',
        'path': 'file.path',
        'service': 'network.protocol',
        'native_file_system': 'file.system',
        'share_type': 'file.share_type'
    },
    'zeek_smb_files': {
        'ts': '@timestamp',
        'uid': 'event.id',
        'id.orig_h': 'source.ip',
        'id.orig_p': 'source.port',
        'id.resp_h': 'destination.ip',
        'id.resp_p': 'destination.port',
        'action': 'event.action',
        'path': 'file.path',
        'name': 'file.name',
        'size': 'file.size'
    },
    # --- ADDED FINAL SET OF MAPPINGS ---
    'zeek_ssh': {
        'ts': '@timestamp',
        'uid': 'event.id',
        'id.orig_h': 'source.ip',
        'id.orig_p': 'source.port',
        'id.resp_h': 'destination.ip',
        'id.resp_p': 'destination.port',
        'auth_success': 'event.outcome',
        'client': 'source.software',
        'server': 'destination.software'
    },
    'zeek_smtp': {
        'ts': '@timestamp',
        'uid': 'event.id',
        'id.orig_h': 'source.ip',
        'id.orig_p': 'source.port',
        'id.resp_h': 'destination.ip',
        'id.resp_p': 'destination.port',
        'from': 'source.user.email',
        'to': 'destination.user.email',
        'subject': 'email.subject',
        'agent': 'user_agent.original'
    },
    'zeek_mysql': {
        'ts': '@timestamp',
        'uid': 'event.id',
        'id.orig_h': 'source.ip',
        'id.orig_p': 'source.port',
        'id.resp_h': 'destination.ip',
        'id.resp_p': 'destination.port',
        'cmd': 'event.action',
        'arg': 'database.query'
    },
    'zeek_dhcp': {
        'ts': '@timestamp',
        'uid': 'event.id',
        'id.orig_h': 'source.ip',
        'id.resp_h': 'destination.ip',
        'mac': 'source.mac',
        'assigned_ip': 'destination.ip',
        'lease_time': 'event.duration',
        'host_name': 'source.host'
    },
    'suricata_alert': {
        'timestamp': '@timestamp',
        'flow_id': 'event.id',
        'event_type': 'event.kind',
        'src_ip': 'source.ip',
        'src_port': 'source.port',
        'dest_ip': 'destination.ip',
        'dest_port': 'destination.port',
        'proto': 'network.transport',
        'alert.signature': 'rule.name',
        'alert.category': 'rule.category',
        'alert.severity': 'rule.severity'
    },
    'suricata_http': {
        'timestamp': '@timestamp',
        'flow_id': 'event.id',
        'event_type': 'event.kind',
        'src_ip': 'source.ip',
        'src_port': 'source.port',
        'dest_ip': 'destination.ip',
        'dest_port': 'destination.port',
        'http.hostname': 'url.domain',
        'http.url': 'url.path',
        'http.http_user_agent': 'user_agent.original',
        'http.status': 'http.response.status_code',
        'http.method': 'http.request.method'
    },
    'suricata_dns': {
        'timestamp': '@timestamp',
        'flow_id': 'event.id',
        'event_type': 'event.kind',
        'src_ip': 'source.ip',
        'src_port': 'source.port',
        'dest_ip': 'destination.ip',
        'dest_port': 'destination.port',
        'dns.type': 'dns.question.type',
        'dns.rrname': 'dns.question.name',
        'dns.rcode': 'dns.answer.rcode'
    },
    'suricata_fileinfo': {
        'timestamp': '@timestamp',
        'flow_id': 'event.id',
        'event_type': 'event.kind',
        'src_ip': 'source.ip',
        'dest_ip': 'destination.ip',
        'filename': 'file.name',
        'size': 'file.size',
        'state': 'file.state',
        'stored': 'file.stored'
    }
}

def parse_zeek_log(line, headers):
    """Parses a single tab-separated Zeek log line into a dictionary."""
    if line.startswith('#') or not line.strip():
        return None
    values = line.strip().split('\t')
    return dict(zip(headers, values))

def normalize_event(event_dict, mapping, module, dataset):
    """Normalizes a single parsed event dictionary to the target schema."""
    normalized = {'event': {'module': module, 'dataset': dataset}}
    for src_field, value in event_dict.items():
        if src_field in mapping:
            target_field = mapping[src_field]
            keys = target_field.split('.')
            d = normalized
            for key in keys[:-1]:
                d = d.setdefault(key, {})
            d[keys[-1]] = value
    return normalized

def process_zeek_files(all_events):
    """Reads, parses, and normalizes all Zeek log files."""
    print("[i] Processing Zeek logs...")
    if not os.path.exists(ZEEK_INPUT_DIR):
        print(f"[!] Zeek log directory not found: {ZEEK_INPUT_DIR}")
        return

    for filename in os.listdir(ZEEK_INPUT_DIR):
        if not filename.startswith('merged_'):
            continue
        
        log_type_key = f"zeek_{filename.replace('merged_', '').replace('.log', '')}"
        if log_type_key not in FIELD_MAPS:
            print(f"  -> Skipping {filename} (no mapping defined)")
            continue

        print(f"  -> Processing {filename}")
        file_path = os.path.join(ZEEK_INPUT_DIR, filename)
        
        headers = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.startswith('#fields'):
                    headers = line.strip().split('\t')[1:]
                    break
        
        if not headers:
            continue

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parsed = parse_zeek_log(line, headers)
                if parsed:
                    normalized = normalize_event(parsed, FIELD_MAPS[log_type_key], 'zeek', log_type_key.split('_')[1])
                    ts = float(normalized['@timestamp'])
                    normalized['@timestamp'] = datetime.fromtimestamp(ts, tz=timezone.utc)
                    all_events.append(normalized)

def process_suricata_files(all_events):
    """Reads, parses, and normalizes all Suricata log files."""
    print("[i] Processing Suricata logs...")
    if not os.path.exists(SURICATA_INPUT_DIR):
        print(f"[!] Suricata log directory not found: {SURICATA_INPUT_DIR}")
        return

    for filename in os.listdir(SURICATA_INPUT_DIR):
        if filename != 'eve.json':
            continue
            
        print(f"  -> Processing {filename}")
        file_path = os.path.join(SURICATA_INPUT_DIR, filename)

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                try:
                    parsed = json.loads(line)
                    event_type = parsed.get('event_type', '')
                    log_type_key = f"suricata_{event_type}"

                    if log_type_key in FIELD_MAPS:
                        normalized = normalize_event(parsed, FIELD_MAPS[log_type_key], 'suricata', event_type)
                        ts_str = normalized['@timestamp']
                        normalized['@timestamp'] = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                        all_events.append(normalized)
                except json.JSONDecodeError:
                    continue

def write_events_to_rotated_files(sorted_events):
    """Writes sorted events to time-rotated files."""
    print(f"[i] Writing {len(sorted_events)} events to rotated files...")
    if not sorted_events:
        return

    if os.path.exists(NORMALIZED_OUTPUT_DIR):
        shutil.rmtree(NORMALIZED_OUTPUT_DIR)
    os.makedirs(NORMALIZED_OUTPUT_DIR, exist_ok=True)

    current_file = None
    current_file_path = ""
    current_window_start = None

    try:
        for event in sorted_events:
            event_dt = event['@timestamp']
            minute_window = (event_dt.minute // ROTATION_INTERVAL_MINUTES) * ROTATION_INTERVAL_MINUTES
            event_window_start = event_dt.replace(minute=minute_window, second=0, microsecond=0)

            if event_window_start != current_window_start:
                if current_file:
                    current_file.close()
                
                current_window_start = event_window_start
                filename = f"normalized-{current_window_start.strftime('%Y%m%d-%H%M%S')}.jsonl"
                current_file_path = os.path.join(NORMALIZED_OUTPUT_DIR, filename)
                print(f"  -> Creating new log file: {current_file_path}")
                current_file = open(current_file_path, 'w', encoding='utf-8')

            event['@timestamp'] = event['@timestamp'].isoformat()
            current_file.write(json.dumps(event) + '\n')

    finally:
        if current_file:
            current_file.close()

if __name__ == "__main__":
    all_events = []
    
    process_suricata_files(all_events)
    process_zeek_files(all_events)
    
    if not all_events:
        print("[!] No events were processed. Exiting.")
        exit()

    print(f"[i] Sorting {len(all_events)} events by timestamp...")
    all_events.sort(key=lambda x: x['@timestamp'])
    
    write_events_to_rotated_files(all_events)
    
    print("\n[✅] Normalization and rotation complete.")
    print(f"[i] Output logs are in the '{NORMALIZED_OUTPUT_DIR}' directory.")
