import os
import csv
import json
from flask import Flask, render_template, jsonify, request, redirect, url_for
from datetime import datetime

app = Flask(__name__)

REPORTS_DIR = "reports"
ASSET_INVENTORY_PATH = "asset_inventory.csv"
SEVERITY_CONFIG_PATH = os.path.join("config", "severity_weights.json")
GEOIP_RISK_CONFIG_PATH = os.path.join("config", "geoip_risk.json")
RULES_CONFIG_PATH = os.path.join("config", "correlation_rules.json")
MITRE_ATTACK_TREE_PATH = os.path.join("config", "mitre_attack_trees.json")

# --------------------------
# Asset Inventory Loader
# --------------------------
def load_asset_inventory():
    """Load asset inventory CSV into a dict keyed by IP."""
    assets = {}
    if not os.path.exists(ASSET_INVENTORY_PATH):
        return assets

    with open(ASSET_INVENTORY_PATH, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [h.lower() for h in reader.fieldnames]
        for row in reader:
            ip = (row.get("ip") or "").strip()
            if not ip:
                continue
            assets[ip] = {
                "hostname": (row.get("hostname") or "").strip(),
                "business_unit": (row.get("business_unit") or "").strip(),
                "owner": (row.get("owner") or "").strip(),
                "criticality": (row.get("criticality") or "").strip(),
                "exposure": (row.get("exposure") or "").strip(),
                "vulnerability_score": row.get("vulnerability_score") or "",
            }
    return assets

ASSET_MAP = load_asset_inventory()

# --------------------------
# Configuration Loaders
# --------------------------
def load_json_config(path, default=None):
    """Load JSON config file with default fallback."""
    if default is None:
        default = {}
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return default
    return default

def save_json_config(path, data):
    """Save JSON config file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    return True

# --------------------------
# MITRE Attack Tree Builder
# --------------------------
def build_attack_tree():
    """Build comprehensive MITRE attack tree with next steps and mitigations."""
    return {
        "T1595.002": {
            "name": "Active Scanning: Vulnerability Scanning",
            "tactic": "Reconnaissance",
            "description": "Adversary is probing for vulnerabilities in your systems",
            "next_possible_attacks": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "probability": "HIGH"},
                {"id": "T1210", "name": "Exploitation of Remote Services", "probability": "MEDIUM"},
                {"id": "T1133", "name": "External Remote Services", "probability": "MEDIUM"}
            ],
            "mitigations": [
                "Implement Web Application Firewall (WAF)",
                "Regular vulnerability scanning and patching",
                "Network segmentation to limit scan scope",
                "Rate limiting and IP blocking for suspicious scanners",
                "Deploy IDS/IPS signatures for common scanning tools"
            ],
            "severity": "MEDIUM",
            "detection_methods": ["Network traffic analysis", "User-Agent analysis", "Connection pattern analysis"]
        },
        "T1110.001": {
            "name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
            "description": "Adversary is attempting to gain access through credential guessing",
            "next_possible_attacks": [
                {"id": "T1078", "name": "Valid Accounts", "probability": "HIGH"},
                {"id": "T1021.004", "name": "SSH Remote Services", "probability": "HIGH"},
                {"id": "T1550.002", "name": "Pass the Hash", "probability": "MEDIUM"}
            ],
            "mitigations": [
                "Implement multi-factor authentication (MFA)",
                "Account lockout policies after failed attempts",
                "Strong password policies",
                "Monitor and alert on failed login attempts",
                "Use CAPTCHA for web-based logins",
                "Implement geo-blocking for suspicious regions"
            ],
            "severity": "HIGH",
            "detection_methods": ["Failed authentication logs", "Account lockout events", "Time-based analysis"]
        },
        "T1078": {
            "name": "Valid Accounts",
            "tactic": "Initial Access",
            "description": "Adversary has successfully authenticated - potential breach",
            "next_possible_attacks": [
                {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "probability": "HIGH"},
                {"id": "T1070", "name": "Indicator Removal", "probability": "HIGH"},
                {"id": "T1087", "name": "Account Discovery", "probability": "MEDIUM"},
                {"id": "T1057", "name": "Process Discovery", "probability": "MEDIUM"}
            ],
            "mitigations": [
                "IMMEDIATE: Review account for compromise",
                "Implement privileged access management (PAM)",
                "Session recording and monitoring",
                "Behavioral analytics for anomalous activity",
                "Least privilege access principles",
                "Regular credential rotation"
            ],
            "severity": "CRITICAL",
            "detection_methods": ["Login anomaly detection", "Geo-location analysis", "User behavior analytics"]
        },
        "T1078.001": {
            "name": "Valid Accounts: Default Accounts",
            "tactic": "Initial Access",
            "description": "Adversary is using default or known credentials, such as MySQL root accounts",
            "next_possible_attacks": [
                {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "probability": "HIGH"},
                {"id": "T1070", "name": "Indicator Removal", "probability": "HIGH"},
                {"id": "T1087", "name": "Account Discovery", "probability": "MEDIUM"}
            ],
            "mitigations": [
                "IMMEDIATE: Disable or rename default accounts",
                "Implement strong password policies",
                "Monitor for default account usage",
                "Restrict database access to authorized IPs",
                "Implement least privilege for database accounts"
            ],
            "severity": "CRITICAL",
            "detection_methods": ["Login monitoring for default accounts", "Authentication log analysis"]
        },
        "T1105": {
            "name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "description": "Adversary is downloading tools or malware to compromised system",
            "next_possible_attacks": [
                {"id": "T1059", "name": "Command and Scripting Interpreter", "probability": "HIGH"},
                {"id": "T1053", "name": "Scheduled Task/Job", "probability": "HIGH"},
                {"id": "T1485", "name": "Data Destruction", "probability": "MEDIUM"},
                {"id": "T1486", "name": "Data Encrypted for Impact", "probability": "MEDIUM"}
            ],
            "mitigations": [
                "URGENT: Isolate affected system immediately",
                "Application whitelisting",
                "Network-based file blocking",
                "Sandbox unknown executables",
                "Block known malicious hashes",
                "Restrict PowerShell and script execution"
            ],
            "severity": "CRITICAL",
            "detection_methods": ["File integrity monitoring", "Network traffic analysis", "Hash reputation"]
        },
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": "Adversary attempting to exploit web application vulnerabilities",
            "next_possible_attacks": [
                {"id": "T1505.003", "name": "Web Shell", "probability": "HIGH"},
                {"id": "T1059.004", "name": "Unix Shell", "probability": "HIGH"},
                {"id": "T1071.001", "name": "Web Protocols C2", "probability": "MEDIUM"}
            ],
            "mitigations": [
                "Emergency patch vulnerable applications",
                "Deploy WAF with virtual patching",
                "Input validation and sanitization",
                "Security code review and testing",
                "Principle of least privilege for web services",
                "Network segmentation for DMZ"
            ],
            "severity": "CRITICAL",
            "detection_methods": ["WAF alerts", "Application logs", "Anomalous HTTP requests"]
        },
        "T1071": {
            "name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "description": "Adversary is using application layer protocols for command and control",
            "next_possible_attacks": [
                {"id": "T1041", "name": "Exfiltration Over C2 Channel", "probability": "HIGH"},
                {"id": "T1105", "name": "Ingress Tool Transfer", "probability": "HIGH"},
                {"id": "T1020", "name": "Automated Exfiltration", "probability": "MEDIUM"}
            ],
            "mitigations": [
                "Monitor application layer traffic",
                "Implement protocol-specific filtering",
                "Use deep packet inspection",
                "Block known malicious domains",
                "Restrict outbound connections"
            ],
            "severity": "HIGH",
            "detection_methods": ["Network traffic analysis", "Protocol anomaly detection", "Domain reputation checks"]
        },
        "T1071.001": {
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "description": "Adversary is using web protocols (e.g., HTTP/HTTPS) for command and control, possibly with outdated user-agents",
            "next_possible_attacks": [
                {"id": "T1041", "name": "Exfiltration Over C2 Channel", "probability": "HIGH"},
                {"id": "T1105", "name": "Ingress Tool Transfer", "probability": "HIGH"},
                {"id": "T1505.003", "name": "Web Shell", "probability": "MEDIUM"}
            ],
            "mitigations": [
                "Monitor HTTP/HTTPS traffic for anomalies",
                "Block outdated or suspicious user-agents",
                "Implement WAF rules for user-agent filtering",
                "Use network intrusion detection systems",
                "Restrict outbound web traffic to known domains"
            ],
            "severity": "HIGH",
            "detection_methods": ["User-Agent analysis", "HTTP request monitoring", "Traffic pattern analysis"]
        },
        "T1071.004": {
            "name": "Application Layer Protocol: DNS",
            "tactic": "Command and Control",
            "description": "Potential DNS tunneling for covert C2 communication",
            "next_possible_attacks": [
                {"id": "T1041", "name": "Exfiltration Over C2 Channel", "probability": "HIGH"},
                {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "probability": "MEDIUM"},
                {"id": "T1020", "name": "Automated Exfiltration", "probability": "MEDIUM"}
            ],
            "mitigations": [
                "DNS query length monitoring",
                "Block suspicious domains",
                "Implement DNS sinkholing",
                "Use DNS security solutions (DNSSEC)",
                "Restrict DNS queries to authorized servers",
                "Deep packet inspection on DNS traffic"
            ],
            "severity": "HIGH",
            "detection_methods": ["DNS query analysis", "Entropy analysis", "Query frequency monitoring"]
        },
        "T1021.002": {
            "name": "Remote Services: SMB/Windows Admin Shares",
            "tactic": "Lateral Movement",
            "description": "Adversary moving laterally through network using SMB",
            "next_possible_attacks": [
                {"id": "T1003", "name": "Credential Dumping", "probability": "HIGH"},
                {"id": "T1569.002", "name": "Service Execution", "probability": "HIGH"},
                {"id": "T1486", "name": "Data Encrypted for Impact", "probability": "MEDIUM"}
            ],
            "mitigations": [
                "CRITICAL: Contain lateral movement immediately",
                "Disable SMBv1 protocol",
                "Restrict admin share access",
                "Network segmentation and microsegmentation",
                "Monitor for unusual SMB traffic",
                "Implement SMB signing"
            ],
            "severity": "CRITICAL",
            "detection_methods": ["SMB traffic monitoring", "Admin share access logs", "Lateral movement detection"]
        },
        "T1485": {
            "name": "Data Destruction",
            "tactic": "Impact",
            "description": "Adversary is destroying data - possible ransomware or wiper",
            "next_possible_attacks": [
                {"id": "T1490", "name": "Inhibit System Recovery", "probability": "HIGH"},
                {"id": "T1489", "name": "Service Stop", "probability": "MEDIUM"}
            ],
            "mitigations": [
                "EMERGENCY: Isolate all affected systems NOW",
                "Activate incident response plan",
                "Restore from clean backups",
                "Preserve forensic evidence",
                "Implement immutable backups",
                "Enable versioning on critical data"
            ],
            "severity": "CRITICAL",
            "detection_methods": ["File deletion monitoring", "Backup integrity checks", "Volume shadow copy deletion"]
        },
        "T1568.002": {
            "name": "Dynamic Resolution: Dynamic DNS",
            "tactic": "Command and Control",
            "description": "C2 infrastructure using dynamic DNS for resilience",
            "next_possible_attacks": [
                {"id": "T1105", "name": "Ingress Tool Transfer", "probability": "HIGH"},
                {"id": "T1041", "name": "Exfiltration Over C2 Channel", "probability": "HIGH"}
            ],
            "mitigations": [
                "Block known dynamic DNS providers",
                "DNS reputation filtering",
                "Monitor for newly registered domains",
                "Implement DNS firewall",
                "Restrict outbound connections to known-good domains"
            ],
            "severity": "HIGH",
            "detection_methods": ["DNS query reputation", "Domain age analysis", "Connection pattern analysis"]
        }
    }

# Initialize attack tree
ATTACK_TREE = build_attack_tree()
if not os.path.exists(MITRE_ATTACK_TREE_PATH):
    save_json_config(MITRE_ATTACK_TREE_PATH, ATTACK_TREE)
else:
    ATTACK_TREE = load_json_config(MITRE_ATTACK_TREE_PATH, ATTACK_TREE)

# --------------------------
# Report helpers
# --------------------------
def get_latest_report():
    """Fetch the most recent risk report JSON."""
    if not os.path.exists(REPORTS_DIR):
        return None

    reports = [f for f in os.listdir(REPORTS_DIR) if f.endswith(".json")]
    if not reports:
        return None

    reports.sort(reverse=True)
    latest = reports[0]
    with open(os.path.join(REPORTS_DIR, latest), "r", encoding="utf-8") as f:
        return json.load(f)

def format_entity_data(entity):
    """Merge entity record with asset inventory and shape for UI."""
    ip = entity.get("ip")
    asset = ASSET_MAP.get(ip, {})

    return {
        "ip": ip,
        "hostname": asset.get("hostname") or "—",
        "business_unit": asset.get("business_unit") or "—",
        "owner": asset.get("owner") or "—",
        "criticality": asset.get("criticality") or "—",
        "exposure": asset.get("exposure") or "—",
        "vulnerability_score": asset.get("vulnerability_score") or "—",
        "total_score": round(float(entity.get("total_score", 0)), 2),
        "observation_count": int(entity.get("observation_count", 0)),
        "contributing_observations": [
            {
                "name": obs.get("name", "—"),
                "final_risk_score": round(float(obs.get("final_risk_score", 0)), 2),
                "tactic": (obs.get("mitre_attack", {}) or {}).get("tactic", "—"),
                "technique": (obs.get("mitre_attack", {}) or {}).get("technique_id", "—"),
                "count": int(obs.get("count", 1)),
            }
            for obs in entity.get("contributing_observations", [])
        ],
    }

def calculate_observation_breakdown(observation):
    """Calculate detailed breakdown of how an observation's score was computed."""
    base_score = observation.get("base_risk_score", 0)
    count = observation.get("count", 1)
    modifiers = observation.get("risk_modifiers", {})
    geoip = observation.get("geoip", {})
    
    # Load configs
    severity_weights = load_json_config(SEVERITY_CONFIG_PATH, {})
    geoip_config = load_json_config(GEOIP_RISK_CONFIG_PATH, {})
    
    obs_name = observation.get("name", "")
    weight = severity_weights.get(obs_name, 1.0)
    
    # Calculate multipliers
    impact_mult = modifiers.get("impact_multiplier", 1.0)
    vuln_mult = modifiers.get("vulnerability_multiplier", 1.0)
    
    # GeoIP multiplier
    geoip_mult = 1.0
    geoip_factors = []
    
    dest_geo = geoip.get("destination_ip", {})
    dest_country = dest_geo.get("country", "")
    
    high_risk_countries = geoip_config.get("high_risk_countries", [])
    if dest_country in high_risk_countries:
        country_mult = geoip_config.get("country_risk_multiplier", 1.5)
        geoip_mult *= country_mult
        geoip_factors.append(f"High-risk country ({dest_country}): ×{country_mult}")
    
    if "New Country" in obs_name:
        new_country_mult = geoip_config.get("new_country_multiplier", 1.3)
        geoip_mult *= new_country_mult
        geoip_factors.append(f"New country behavior: ×{new_country_mult}")
    
    if "Rare ASN" in obs_name:
        rare_asn_mult = geoip_config.get("rare_asn_multiplier", 1.2)
        geoip_mult *= rare_asn_mult
        geoip_factors.append(f"Rare ASN behavior: ×{rare_asn_mult}")
    
    # Calculate step by step
    import math
    after_modifiers = base_score * impact_mult * vuln_mult
    after_weight = after_modifiers * weight
    after_geoip = after_weight * geoip_mult
    final_score = after_geoip * math.log1p(count)
    
    return {
        "base_score": base_score,
        "count": count,
        "severity_weight": weight,
        "impact_multiplier": impact_mult,
        "vulnerability_multiplier": vuln_mult,
        "geoip_multiplier": geoip_mult,
        "geoip_factors": geoip_factors,
        "after_modifiers": round(after_modifiers, 2),
        "after_weight": round(after_weight, 2),
        "after_geoip": round(after_geoip, 2),
        "log_scaling_factor": round(math.log1p(count), 3),
        "final_score": round(final_score, 2)
    }

# --------------------------
# Routes - Main Dashboard
# --------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/report")
def api_report():
    report = get_latest_report()
    if not report:
        return jsonify({"error": "No reports found"}), 404
    return jsonify(report)

@app.route("/api/entities")
def api_entities():
    report = get_latest_report()
    if not report:
        return jsonify({"entities": []})

    entities = [format_entity_data(ent) for ent in report.get("high_risk_entities", [])]
    return jsonify({"entities": entities})

# --------------------------
# Routes - Configuration
# --------------------------
@app.route("/config")
def config_page():
    return render_template("config.html")

@app.route("/api/config/severity", methods=["GET", "POST"])
def config_severity():
    if request.method == "GET":
        weights = load_json_config(SEVERITY_CONFIG_PATH, {})
        return jsonify(weights)
    
    if request.method == "POST":
        data = request.json
        save_json_config(SEVERITY_CONFIG_PATH, data)
        return jsonify({"status": "success", "message": "Severity weights updated"})

@app.route("/api/config/geoip", methods=["GET", "POST"])
def config_geoip():
    if request.method == "GET":
        config = load_json_config(GEOIP_RISK_CONFIG_PATH, {})
        return jsonify(config)
    
    if request.method == "POST":
        data = request.json
        save_json_config(GEOIP_RISK_CONFIG_PATH, data)
        return jsonify({"status": "success", "message": "GeoIP risk config updated"})

# --------------------------
# Routes - Custom Rules
# --------------------------
@app.route("/rules")
def rules_page():
    return render_template("rules.html")

@app.route("/api/rules", methods=["GET", "POST"])
def api_rules():
    if request.method == "GET":
        rules = load_json_config(RULES_CONFIG_PATH, [])
        return jsonify({"rules": rules})
    
    if request.method == "POST":
        data = request.json
        rules = load_json_config(RULES_CONFIG_PATH, [])
        
        # Add new rule with ID and timestamp
        new_rule = data.get("rule", {})
        new_rule["id"] = len(rules) + 1
        new_rule["created_at"] = datetime.now().isoformat()
        new_rule["enabled"] = True
        
        rules.append(new_rule)
        save_json_config(RULES_CONFIG_PATH, rules)
        
        return jsonify({"status": "success", "message": "Custom rule added", "rule": new_rule})

@app.route("/api/rules/<int:rule_id>", methods=["PUT", "DELETE"])
def api_rule_detail(rule_id):
    rules = load_json_config(RULES_CONFIG_PATH, [])
    
    if request.method == "DELETE":
        rules = [r for r in rules if r.get("id") != rule_id]
        save_json_config(RULES_CONFIG_PATH, rules)
        return jsonify({"status": "success", "message": "Rule deleted"})
    
    if request.method == "PUT":
        data = request.json
        for i, rule in enumerate(rules):
            if rule.get("id") == rule_id:
                rules[i] = {**rule, **data, "id": rule_id, "updated_at": datetime.now().isoformat()}
                break
        save_json_config(RULES_CONFIG_PATH, rules)
        return jsonify({"status": "success", "message": "Rule updated"})

# --------------------------
# Routes - Detailed Analysis
# --------------------------
@app.route("/analysis")
def analysis_page():
    return render_template("analysis.html")

@app.route("/api/analysis/ip/<ip>")
def api_analysis_ip(ip):
    """Get detailed analysis for a specific IP."""
    report = get_latest_report()
    if not report:
        return jsonify({"error": "No reports found"}), 404
    
    # Find entity
    entity = None
    for ent in report.get("high_risk_entities", []):
        if ent.get("ip") == ip:
            entity = ent
            break
    
    if not entity:
        return jsonify({"error": "IP not found in report"}), 404
    
    # Get asset info
    asset = ASSET_MAP.get(ip, {})
    
    # Build all attacks and attack chain
    observations = entity.get("contributing_observations", [])
    attack_chain = []
    all_attacks = []
    next_attacks = {}
    all_mitigations = []
    
    # Populate all_attacks with all observations
    for obs in observations:
        mitre = obs.get("mitre_attack", {})
        technique_id = mitre.get("technique_id", "")
        
        breakdown = calculate_observation_breakdown(obs)
        
        # Default values for observations without ATTACK_TREE entry
        attack_info = ATTACK_TREE.get(technique_id, {
            "name": obs.get("name", "Unknown Technique"),
            "tactic": mitre.get("tactic", "Unknown"),
            "description": "No MITRE ATT&CK mapping available",
            "mitigations": ["Investigate observation for manual analysis"],
            "severity": "MEDIUM",
            "detection_methods": ["Manual log review"]
        })
        
        all_attacks.append({
            "observation_name": obs.get("name", "Unknown"),
            "technique_id": technique_id or "N/A",
            "technique_name": attack_info.get("name"),
            "tactic": attack_info.get("tactic"),
            "description": attack_info.get("description"),
            "count": obs.get("count", 1),
            "severity": attack_info.get("severity"),
            "breakdown": breakdown,
            "mitigations": attack_info.get("mitigations", []),
            "detection_methods": attack_info.get("detection_methods", [])
        })
    
    # Populate attack_chain (only observations with valid technique_id)
    for obs in observations:
        mitre = obs.get("mitre_attack", {})
        technique_id = mitre.get("technique_id", "")
        
        if technique_id and technique_id in ATTACK_TREE:
            attack_info = ATTACK_TREE[technique_id]
            
            breakdown = calculate_observation_breakdown(obs)
            
            attack_chain.append({
                "observation_name": obs.get("name"),
                "technique_id": technique_id,
                "technique_name": attack_info.get("name"),
                "tactic": attack_info.get("tactic"),
                "description": attack_info.get("description"),
                "count": obs.get("count"),
                "severity": attack_info.get("severity"),
                "breakdown": breakdown,
                "mitigations": attack_info.get("mitigations", []),
                "detection_methods": attack_info.get("detection_methods", [])
            })
            
            # Collect next possible attacks
            for next_attack in attack_info.get("next_possible_attacks", []):
                next_id = next_attack["id"]
                if next_id not in next_attacks:
                    next_attacks[next_id] = {
                        **next_attack,
                        "count": 1,
                        "current_techniques": [technique_id]
                    }
                else:
                    next_attacks[next_id]["count"] += 1
                    next_attacks[next_id]["current_techniques"].append(technique_id)
            
            # Collect unique mitigations
            for mitigation in attack_info.get("mitigations", []):
                if mitigation not in all_mitigations:
                    all_mitigations.append(mitigation)
    
    # Sort next attacks by count (most likely)
    next_attacks_list = sorted(
        next_attacks.values(),
        key=lambda x: x["count"],
        reverse=True
    )
    
    # Enhance with attack tree details
    for attack in next_attacks_list:
        attack_id = attack["id"]
        if attack_id in ATTACK_TREE:
            attack.update({
                "name": ATTACK_TREE[attack_id].get("name"),
                "description": ATTACK_TREE[attack_id].get("description"),
                "severity": ATTACK_TREE[attack_id].get("severity"),
                "mitigations": ATTACK_TREE[attack_id].get("mitigations", [])
            })
    
    return jsonify({
        "ip": ip,
        "asset": asset,
        "total_score": entity.get("total_score"),
        "observation_count": entity.get("observation_count"),
        "attack_chain": attack_chain,
        "all_attacks": all_attacks,
        "next_possible_attacks": next_attacks_list[:10],  # Top 10
        "recommended_mitigations": all_mitigations,
        "risk_level": "CRITICAL" if entity.get("total_score", 0) > 500 else "HIGH" if entity.get("total_score", 0) > 200 else "MEDIUM"
    })

@app.route("/api/analysis/observation")
def api_analysis_observation():
    """Get detailed breakdown for a specific observation."""
    obs_name = request.args.get("name")
    technique_id = request.args.get("technique")
    
    if not obs_name:
        return jsonify({"error": "Observation name required"}), 400
    
    report = get_latest_report()
    if not report:
        return jsonify({"error": "No reports found"}), 404
    
    # Find observation across all entities
    for entity in report.get("high_risk_entities", []):
        for obs in entity.get("contributing_observations", []):
            if obs.get("name") == obs_name:
                breakdown = calculate_observation_breakdown(obs)
                
                mitre = obs.get("mitre_attack", {})
                tech_id = mitre.get("technique_id", "")
                
                attack_info = ATTACK_TREE.get(tech_id, {
                    "name": obs.get("name", "Unknown Technique"),
                    "tactic": mitre.get("tactic", "Unknown"),
                    "description": "No MITRE ATT&CK mapping available",
                    "mitigations": ["Investigate observation for manual analysis"],
                    "severity": "MEDIUM",
                    "detection_methods": ["Manual log review"]
                })
                
                return jsonify({
                    "observation": obs,
                    "breakdown": breakdown,
                    "attack_info": attack_info
                })
    
    return jsonify({"error": "Observation not found"}), 404

if __name__ == "__main__":
    # Ensure config directory exists
    os.makedirs("config", exist_ok=True)
    
    # Initialize default configs if they don't exist
    if not os.path.exists(RULES_CONFIG_PATH):
        save_json_config(RULES_CONFIG_PATH, [])
    
    app.run(debug=True, port=5000)