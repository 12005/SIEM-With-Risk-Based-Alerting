import os
import random
import time
import json
from datetime import datetime, timedelta
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap
import ipaddress
import logging

# --- Configuration ---
OBSERVATIONS_DIR = 'observations'
PCAP_DIR = 'pcaps'
ATTACKER_CIDR = "192.168.1.0/24"  # Private range for internal attackers

# High-Risk Country IP Ranges (simulated public IPs from these regions)
HIGH_RISK_IP_RANGES = {
    "North Korea": ["175.45.176.0/24"],
    "Iran": ["5.202.0.0/16", "31.2.0.0/16"],
    "Syria": ["5.0.0.0/16", "78.155.0.0/16"],
    "Russia": ["5.61.0.0/16", "31.13.0.0/16", "46.17.0.0/16"],
    "China": ["1.0.0.0/8", "27.0.0.0/8", "36.0.0.0/8"]
}

# Known malicious ASN ranges (simulated)
MALICIOUS_ASN_RANGES = {
    "197988": ["185.220.100.0/24", "185.220.101.0/24"],
    "398705": ["45.95.168.0/24", "45.95.169.0/24"],
    "201011": ["193.218.118.0/24"]
}

PUBLIC_IP_RANGES = [
    "8.8.8.0/24",      # Google DNS
    "1.1.1.0/24",      # Cloudflare
    "34.192.0.0/10",   # AWS US-East-1
    "104.16.0.0/12",   # Cloudflare
    "172.217.0.0/16",  # Google
    "13.107.0.0/16",   # Microsoft Azure
]

C2_DOMAIN = "malicious.example.com"
DYNAMIC_DNS_DOMAIN = "evil.ddns.net"
PCAP_FILE = f"{PCAP_DIR}/simulated_attacks-{int(time.time())}.pcap"
OBSERVATION_FILE = f"{OBSERVATIONS_DIR}/observation-{datetime.now().strftime('%Y%m%d-%H%M%S')}.jsonl"
START_TIME = int(time.time())

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Observation Types for JSONL ---
OBSERVATION_TYPES = {
    "ssh_brute_force": {
        "name": "Initial Access: SSH Login Failure",
        "base_risk_score": 60,
        "mitre_technique": "T1110.001"
    },
    "port_scan": {
        "name": "Recon: Connection Refused (Potential Port Scan)",
        "base_risk_score": 50,
        "mitre_technique": "T1595.001"
    },
    "c2_communication": {
        "name": "C2: Potential DNS Tunneling (Long Query)",
        "base_risk_score": 80,
        "mitre_technique": "T1071.004"
    },
    "dns_zone_transfer": {
        "name": "Recon: DNS Zone Transfer Attempt (AXFR)",
        "base_risk_score": 55,
        "mitre_technique": "T1589"
    },
    "suspicious_user_agent": {
        "name": "Recon: Suspicious User-Agent",
        "base_risk_score": 40,
        "mitre_technique": "T1595.002"
    },
    "ftp_login": {
        "name": "Initial Access: FTP Login",
        "base_risk_score": 50,
        "mitre_technique": "T1078"
    },
    "mysql_root_login": {
        "name": "Initial Access: MySQL Root Login Attempt",
        "base_risk_score": 65,
        "mitre_technique": "T1078.001"
    },
    "http_executable_download": {
        "name": "Execution: HTTP Request to Executable",
        "base_risk_score": 70,
        "mitre_technique": "T1204.002"
    },
    "sql_injection": {
        "name": "Impact: Potential SQL Injection Attempt",
        "base_risk_score": 70,
        "mitre_technique": "T1190"
    },
    "dns_tunneling": {
        "name": "C2: Potential DNS Tunneling (Long Query)",
        "base_risk_score": 80,
        "mitre_technique": "T1071.004"
    }
}

def generate_ip_from_cidr(cidr):
    """Generate a random IP from a CIDR range."""
    network = ipaddress.ip_network(cidr, strict=False)
    ip_int = random.randint(int(network.network_address), int(network.broadcast_address))
    return str(ipaddress.ip_address(ip_int))

def generate_high_risk_ip():
    """Generate a random IP from high-risk country ranges."""
    country = random.choice(list(HIGH_RISK_IP_RANGES.keys()))
    cidr = random.choice(HIGH_RISK_IP_RANGES[country])
    ip = generate_ip_from_cidr(cidr)
    logger.debug(f"Generated high-risk IP {ip} from {country}")
    return ip

def generate_malicious_asn_ip():
    """Generate a random IP from known malicious ASN ranges."""
    asn = random.choice(list(MALICIOUS_ASN_RANGES.keys()))
    cidr = random.choice(MALICIOUS_ASN_RANGES[asn])
    ip = generate_ip_from_cidr(cidr)
    logger.debug(f"Generated malicious ASN IP {ip} from AS{asn}")
    return ip

def generate_public_ip():
    """Generate a random public IP from PUBLIC_IP_RANGES."""
    cidr = random.choice(PUBLIC_IP_RANGES)
    return generate_ip_from_cidr(cidr)

def generate_private_ip():
    """Generate a random private IP from ATTACKER_CIDR."""
    return generate_ip_from_cidr(ATTACKER_CIDR)

def select_attacker_ip(use_high_risk=False, use_malicious_asn=False):
    """Select appropriate attacker IP based on attack type."""
    if use_malicious_asn:
        return generate_malicious_asn_ip()
    elif use_high_risk:
        return generate_high_risk_ip()
    elif random.random() < 0.3:  # 30% chance of external attacker
        return generate_public_ip()
    else:
        return generate_private_ip()

def create_packet(src_ip, dst_ip, sport, dport, flags=None, payload=None):
    """Generate a timestamped packet."""
    eth = Ether(dst="00:11:22:33:44:55", src="00:66:77:88:99:00")
    ip = IP(src=src_ip, dst=dst_ip)
    if flags:  # TCP packet
        tcp = TCP(sport=sport, dport=dport, flags=flags)
        packet = eth / ip / tcp
        if payload:
            packet = packet / Raw(load=payload)
    else:  # UDP or application layer
        udp = UDP(sport=sport, dport=dport)
        packet = eth / ip / udp
        if payload:
            packet = packet / Raw(load=payload)
    packet.time = START_TIME + random.uniform(0, 120)
    return packet

def create_observation(attack_type, src_ip, dst_ip, timestamp):
    """Generate a JSONL observation entry."""
    obs_type = OBSERVATION_TYPES[attack_type]
    return {
        "@timestamp": timestamp.isoformat(),
        "observation": {
            "name": obs_type["name"],
            "base_risk_score": obs_type["base_risk_score"],
            "source_event": {
                "source": {"ip": src_ip},
                "destination": {"ip": dst_ip},
                "dns": {"question": {"name": C2_DOMAIN if attack_type == "c2_communication" else "example.com"}} if attack_type in ["c2_communication", "dns_zone_transfer", "dns_tunneling"] else {},
                "url": {"domain": "example.com"} if attack_type in ["suspicious_user_agent", "http_executable_download", "sql_injection"] else {}
            }
        }
    }

# 1. Simulate Brute Force Attack from High-Risk Countries
def simulate_ssh_brute_force(packets, observations):
    """Simulate SSH brute force with high-risk country IPs."""
    usernames = ["root", "admin", "user"]
    passwords = ["wrongpass1", "wrongpass2", "wrongpass3", "pass123", "test"]
    
    # 50% from high-risk countries, 50% from malicious ASNs
    use_high_risk = random.random() < 0.5
    use_malicious_asn = not use_high_risk
    
    for _ in range(5):
        src_ip = select_attacker_ip(use_high_risk=use_high_risk, use_malicious_asn=use_malicious_asn)
        dst_ip = generate_public_ip()
        sport = random.randint(1024, 65535)
        username = random.choice(usernames)
        password = random.choice(passwords)
        timestamp = datetime.fromtimestamp(START_TIME + random.uniform(0, 120))

        syn = create_packet(src_ip, dst_ip, sport, 22, flags="S")
        syn_ack = create_packet(dst_ip, src_ip, 22, sport, flags="SA")
        ack = create_packet(src_ip, dst_ip, sport, 22, flags="A")
        client_banner = b"SSH-2.0-OpenSSH_7.4\r\n"
        banner_pkt = create_packet(src_ip, dst_ip, sport, 22, flags="PA", payload=client_banner)
        server_banner = b"SSH-2.0-OpenSSH_7.4\r\n"
        server_banner_pkt = create_packet(dst_ip, src_ip, 22, sport, flags="PA", payload=server_banner)
        login_attempt = f"USER {username}\r\nPASS {password}\r\n".encode()
        login_pkt = create_packet(src_ip, dst_ip, sport, 22, flags="PA", payload=login_attempt)
        rst = create_packet(dst_ip, src_ip, 22, sport, flags="R")
        
        packets.extend([syn, syn_ack, ack, banner_pkt, server_banner_pkt, login_pkt, rst])
        observations.append(create_observation("ssh_brute_force", src_ip, dst_ip, timestamp))

# 2. Simulate Port Scan from Malicious ASN
def simulate_port_scan(packets, observations):
    """Simulate port scan from malicious ASN."""
    ports = [21, 22, 23, 80, 443, 445, 3389, 8080, 53, 1433, 3306, 25]
    src_ip = generate_malicious_asn_ip()
    dst_ip = generate_public_ip()
    timestamp = datetime.fromtimestamp(START_TIME + random.uniform(0, 120))
    
    for port in ports:
        sport = random.randint(1024, 65535)
        syn = create_packet(src_ip, dst_ip, sport, port, flags="S")
        response_flags = "SA" if port in [22, 80, 443, 21, 25, 3306] else "R"
        response = create_packet(dst_ip, src_ip, port, sport, flags=response_flags)
        packets.extend([syn, response])
    
    observations.append(create_observation("port_scan", src_ip, dst_ip, timestamp))

# 3. Simulate C2 Communication from High-Risk Country
def simulate_c2_communication(packets, observations):
    """Simulate C2 communication from high-risk country."""
    src_ip = generate_private_ip()
    dns_server = "8.8.8.8"
    c2_ip = generate_high_risk_ip()  # C2 server in high-risk country
    sport = random.randint(1024, 65535)
    timestamp = datetime.fromtimestamp(START_TIME + random.uniform(0, 120))

    # DNS query
    dns_query_payload = DNS(rd=1, qd=DNSQR(qname=C2_DOMAIN, qtype="A"))
    eth = Ether(dst="00:11:22:33:44:55", src="00:66:77:88:99:00")
    ip_layer = IP(src=src_ip, dst=dns_server)
    udp_layer = UDP(sport=sport, dport=53)
    dns_query = eth / ip_layer / udp_layer / dns_query_payload
    dns_query.time = START_TIME + random.uniform(0, 120)
    
    # DNS response
    dns_response_payload = DNS(
        id=dns_query[DNS].id, 
        qr=1, 
        aa=1, 
        qd=dns_query[DNS].qd, 
        an=DNSRR(rrname=C2_DOMAIN, type="A", rdata=c2_ip)
    )
    eth_resp = Ether(dst="00:66:77:88:99:00", src="00:11:22:33:44:55")
    ip_resp = IP(src=dns_server, dst=src_ip)
    udp_resp = UDP(sport=53, dport=sport)
    dns_response = eth_resp / ip_resp / udp_resp / dns_response_payload
    dns_response.time = START_TIME + random.uniform(0, 120)
    
    # HTTP beacon to C2
    http_request = create_packet(
        src_ip, c2_ip, sport, 80, flags="PA",
        payload=b"GET /beacon HTTP/1.1\r\nHost: malicious.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    )
    http_response = create_packet(
        c2_ip, src_ip, 80, sport, flags="PA",
        payload=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )
    packets.extend([dns_query, dns_response, http_request, http_response])
    observations.append(create_observation("c2_communication", src_ip, c2_ip, timestamp))

# 4. Simulate DNS Zone Transfer from Malicious ASN
def simulate_dns_zone_transfer(packets, observations):
    """Simulate DNS AXFR from malicious ASN."""
    src_ip = generate_malicious_asn_ip()
    dst_ip = generate_public_ip()
    sport = random.randint(1024, 65535)
    timestamp = datetime.fromtimestamp(START_TIME + random.uniform(0, 120))

    axfr_query_payload = DNS(rd=1, qd=DNSQR(qname="example.com", qtype="AXFR"))
    eth = Ether(dst="00:11:22:33:44:55", src="00:66:77:88:99:00")
    ip_layer = IP(src=src_ip, dst=dst_ip)
    udp_layer = UDP(sport=sport, dport=53)
    axfr_query = eth / ip_layer / udp_layer / axfr_query_payload
    axfr_query.time = START_TIME + random.uniform(0, 120)
    
    axfr_response_payload = DNS(
        id=axfr_query[DNS].id, 
        qr=1, 
        aa=1, 
        qd=axfr_query[DNS].qd, 
        an=DNSRR(rrname="example.com", type="SOA", rdata="ns.example.com")
    )
    eth_resp = Ether(dst="00:66:77:88:99:00", src="00:11:22:33:44:55")
    ip_resp = IP(src=dst_ip, dst=src_ip)
    udp_resp = UDP(sport=53, dport=sport)
    axfr_response = eth_resp / ip_resp / udp_resp / axfr_response_payload
    axfr_response.time = START_TIME + random.uniform(0, 120)
    
    packets.extend([axfr_query, axfr_response])
    observations.append(create_observation("dns_zone_transfer", src_ip, dst_ip, timestamp))

# 5. Simulate Suspicious User-Agent from High-Risk Country
def simulate_suspicious_user_agent(packets, observations):
    """Simulate HTTP scanning from high-risk countries."""
    user_agents = ["nmap", "sqlmap", "nikto"]
    src_ip = generate_high_risk_ip()
    dst_ip = generate_public_ip()
    timestamp = datetime.fromtimestamp(START_TIME + random.uniform(0, 120))
    
    for ua in user_agents:
        sport = random.randint(1024, 65535)
        syn = create_packet(src_ip, dst_ip, sport, 80, flags="S")
        syn_ack = create_packet(dst_ip, src_ip, 80, sport, flags="SA")
        ack = create_packet(src_ip, dst_ip, sport, 80, flags="A")
        http_request = create_packet(
            src_ip, dst_ip, sport, 80, flags="PA",
            payload=f"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: {ua}\r\n\r\n".encode()
        )
        http_response = create_packet(
            dst_ip, src_ip, 80, sport, flags="PA",
            payload=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        )
        rst = create_packet(dst_ip, src_ip, 80, sport, flags="R")
        packets.extend([syn, syn_ack, ack, http_request, http_response, rst])
    
    observations.append(create_observation("suspicious_user_agent", src_ip, dst_ip, timestamp))

# 6-10: Other attack simulations (simplified with high-risk IPs)
def simulate_ftp_login(packets, observations):
    src_ip = select_attacker_ip(use_high_risk=True)
    dst_ip = generate_public_ip()
    sport = random.randint(1024, 65535)
    timestamp = datetime.fromtimestamp(START_TIME + random.uniform(0, 120))

    syn = create_packet(src_ip, dst_ip, sport, 21, flags="S")
    syn_ack = create_packet(dst_ip, src_ip, 21, sport, flags="SA")
    ack = create_packet(src_ip, dst_ip, sport, 21, flags="A")
    banner = b"220 FTP Server ready.\r\n"
    banner_pkt = create_packet(dst_ip, src_ip, 21, sport, flags="PA", payload=banner)
    user_cmd = b"USER anonymous\r\n"
    user_pkt = create_packet(src_ip, dst_ip, sport, 21, flags="PA", payload=user_cmd)
    pass_cmd = b"PASS ftp@example.com\r\n"
    pass_pkt = create_packet(src_ip, dst_ip, sport, 21, flags="PA", payload=pass_cmd)
    login_resp = b"230 Login successful.\r\n"
    login_resp_pkt = create_packet(dst_ip, src_ip, 21, sport, flags="PA", payload=login_resp)
    rst = create_packet(dst_ip, src_ip, 21, sport, flags="R")
    
    packets.extend([syn, syn_ack, ack, banner_pkt, user_pkt, pass_pkt, login_resp_pkt, rst])
    observations.append(create_observation("ftp_login", src_ip, dst_ip, timestamp))

def simulate_mysql_root_login(packets, observations):
    src_ip = generate_malicious_asn_ip()
    dst_ip = generate_public_ip()
    sport = random.randint(1024, 65535)
    timestamp = datetime.fromtimestamp(START_TIME + random.uniform(0, 120))

    syn = create_packet(src_ip, dst_ip, sport, 3306, flags="S")
    syn_ack = create_packet(dst_ip, src_ip, 3306, sport, flags="SA")
    ack = create_packet(src_ip, dst_ip, sport, 3306, flags="A")
    greeting = b"\x0a5.7.00\x00\x01\x08\x00\x00\x00"
    greeting_pkt = create_packet(dst_ip, src_ip, 3306, sport, flags="PA", payload=greeting)
    login_req = b"\x85\xa6\xff\x01\x00\x00\x00\x01\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00root\x00"
    login_pkt = create_packet(src_ip, dst_ip, sport, 3306, flags="PA", payload=login_req)
    error_resp = b"\xff\x15\x04#28000Access denied for user 'root'"
    error_pkt = create_packet(dst_ip, src_ip, 3306, sport, flags="PA", payload=error_resp)
    rst = create_packet(dst_ip, src_ip, 3306, sport, flags="R")
    
    packets.extend([syn, syn_ack, ack, greeting_pkt, login_pkt, error_pkt, rst])
    observations.append(create_observation("mysql_root_login", src_ip, dst_ip, timestamp))

def simulate_http_executable_download(packets, observations):
    src_ip = generate_high_risk_ip()
    dst_ip = generate_public_ip()
    sport = random.randint(1024, 65535)
    timestamp = datetime.fromtimestamp(START_TIME + random.uniform(0, 120))

    syn = create_packet(src_ip, dst_ip, sport, 80, flags="S")
    syn_ack = create_packet(dst_ip, src_ip, 80, sport, flags="SA")
    ack = create_packet(src_ip, dst_ip, sport, 80, flags="A")
    http_get = b"GET /malware.exe HTTP/1.1\r\nHost: example.com\r\n\r\n"
    get_pkt = create_packet(src_ip, dst_ip, sport, 80, flags="PA", payload=http_get)
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    resp_pkt = create_packet(dst_ip, src_ip, 80, sport, flags="PA", payload=http_resp)
    rst = create_packet(dst_ip, src_ip, 80, sport, flags="R")
    
    packets.extend([syn, syn_ack, ack, get_pkt, resp_pkt, rst])
    observations.append(create_observation("http_executable_download", src_ip, dst_ip, timestamp))

def simulate_sql_injection(packets, observations):
    src_ip = select_attacker_ip(use_malicious_asn=True)
    dst_ip = generate_public_ip()
    sport = random.randint(1024, 65535)
    timestamp = datetime.fromtimestamp(START_TIME + random.uniform(0, 120))

    syn = create_packet(src_ip, dst_ip, sport, 80, flags="S")
    syn_ack = create_packet(dst_ip, src_ip, 80, sport, flags="SA")
    ack = create_packet(src_ip, dst_ip, sport, 80, flags="A")
    sql_payload = b"GET /login?user=admin' OR '1'='1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    sql_pkt = create_packet(src_ip, dst_ip, sport, 80, flags="PA", payload=sql_payload)
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    resp_pkt = create_packet(dst_ip, src_ip, 80, sport, flags="PA", payload=http_resp)
    rst = create_packet(dst_ip, src_ip, 80, sport, flags="R")
    
    packets.extend([syn, syn_ack, ack, sql_pkt, resp_pkt, rst])
    observations.append(create_observation("sql_injection", src_ip, dst_ip, timestamp))

def simulate_dns_tunneling(packets, observations):
    src_ip = generate_private_ip()
    dst_ip = generate_high_risk_ip()  # DNS to high-risk country
    sport = random.randint(1024, 65535)
    timestamp = datetime.fromtimestamp(START_TIME + random.uniform(0, 120))

    long_query = "a" * 200 + ".example.com"
    tunneling_query_payload = DNS(rd=1, qd=DNSQR(qname=long_query, qtype="TXT"))
    
    eth = Ether(dst="00:11:22:33:44:55", src="00:66:77:88:99:00")
    ip_layer = IP(src=src_ip, dst=dst_ip)
    udp_layer = UDP(sport=sport, dport=53)
    tunneling_query = eth / ip_layer / udp_layer / tunneling_query_payload
    tunneling_query.time = START_TIME + random.uniform(0, 120)
    
    tunneling_response_payload = DNS(
        id=tunneling_query[DNS].id, 
        qr=1, 
        aa=1, 
        qd=tunneling_query[DNS].qd, 
        an=DNSRR(rrname=long_query, type="TXT", rdata="tunneled_data")
    )
    
    eth_resp = Ether(dst="00:66:77:88:99:00", src="00:11:22:33:44:55")
    ip_resp = IP(src=dst_ip, dst=src_ip)
    udp_resp = UDP(sport=53, dport=sport)
    tunneling_response = eth_resp / ip_resp / udp_resp / tunneling_response_payload
    tunneling_response.time = START_TIME + random.uniform(0, 120)
    
    packets.extend([tunneling_query, tunneling_response])
    observations.append(create_observation("dns_tunneling", src_ip, dst_ip, timestamp))

def generate_pcap_and_observations():
    """Generate PCAP and observation files with high-risk GeoIP sources."""
    os.makedirs(PCAP_DIR, exist_ok=True)
    os.makedirs(OBSERVATIONS_DIR, exist_ok=True)

    packets = []
    observations = []

    logger.info("=" * 60)
    logger.info("Generating Attack Traffic with High-Risk GeoIP Sources")
    logger.info("=" * 60)

    # Generate multiple instances of each attack
    for i in range(3):
        logger.info(f"Generating attack sequence {i+1}/3...")
        simulate_ssh_brute_force(packets, observations)
        simulate_port_scan(packets, observations)
        simulate_c2_communication(packets, observations)
        simulate_dns_zone_transfer(packets, observations)
        simulate_suspicious_user_agent(packets, observations)
        simulate_ftp_login(packets, observations)
        simulate_mysql_root_login(packets, observations)
        simulate_http_executable_download(packets, observations)
        simulate_sql_injection(packets, observations)
        simulate_dns_tunneling(packets, observations)

    # Sort packets by timestamp
    packets.sort(key=lambda x: x.time)

    # Write PCAP file
    wrpcap(PCAP_FILE, packets)
    logger.info(f"✅ Generated PCAP: {PCAP_FILE} with {len(packets)} packets")

    # Write observation file
    with open(OBSERVATION_FILE, 'w', encoding='utf-8') as outfile:
        for obs in observations:
            outfile.write(json.dumps(obs) + '\n')
    logger.info(f"✅ Generated observations: {OBSERVATION_FILE} with {len(observations)} observations")
    logger.info("=" * 60)

if __name__ == "__main__":
    generate_pcap_and_observations()