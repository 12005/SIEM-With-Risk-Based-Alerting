import os
import json
import math
from collections import defaultdict
from datetime import datetime, timezone

# --- Configuration ---
ENRICHED_INPUT_DIR = "enriched-observations"
RISK_THRESHOLD = 0
REPORT_OUTPUT_DIR = "reports"
SEVERITY_CONFIG_PATH = os.path.join("config", "severity_weights.json")
GEOIP_RISK_CONFIG_PATH = os.path.join("config", "geoip_risk.json")

def load_severity_weights():
    """Load observation severity weights from config file."""
    if os.path.exists(SEVERITY_CONFIG_PATH):
        with open(SEVERITY_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def load_geoip_risk_config():
    """Load GeoIP risk config, create default if missing."""
    default_config = {
        "high_risk_countries": ["North Korea", "Iran", "Syria", "Russia", "China"],
        "high_risk_asn": [],
        "country_risk_multiplier": 1.5,
        "high_risk_asn_multiplier": 1.4,
        "new_country_multiplier": 1.3,
        "rare_asn_multiplier": 1.2
    }
    
    if os.path.exists(GEOIP_RISK_CONFIG_PATH):
        with open(GEOIP_RISK_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    
    # Create default config
    os.makedirs(os.path.dirname(GEOIP_RISK_CONFIG_PATH), exist_ok=True)
    with open(GEOIP_RISK_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(default_config, f, indent=2)
    print(f"[i] Created default GeoIP risk config at {GEOIP_RISK_CONFIG_PATH}")
    return default_config

SEVERITY_WEIGHTS = load_severity_weights()
GEOIP_CONFIG = load_geoip_risk_config()

def calculate_geoip_multiplier(obs_data):
    """Calculate GeoIP risk multiplier based on enrichment data."""
    multiplier = 1.0
    geoip = obs_data.get("geoip", {})
    dest_geo = geoip.get("destination_ip", {})
    
    # High-risk country
    high_risk_countries = GEOIP_CONFIG.get("high_risk_countries", [])
    if dest_geo.get("country") in high_risk_countries:
        multiplier *= GEOIP_CONFIG.get("country_risk_multiplier", 1.5)
    
    # Behavioral anomalies
    obs_name = obs_data.get("name", "")
    if "New Country" in obs_name:
        multiplier *= GEOIP_CONFIG.get("new_country_multiplier", 1.3)
    if "Rare ASN" in obs_name:
        multiplier *= GEOIP_CONFIG.get("rare_asn_multiplier", 1.2)
    
    return multiplier

def calculate_base_score(obs_data):
    """Compute raw score from modifiers."""
    base_score = obs_data.get("base_risk_score", 0)
    modifiers = obs_data.get("risk_modifiers", {})
    
    impact = modifiers.get("impact_multiplier", 1.0)
    vuln = modifiers.get("vulnerability_multiplier", 1.0)
    
    return base_score * impact * vuln

def calculate_final_score(obs, count):
    """Apply all multipliers + log scaling for deduplication."""
    base_score = calculate_base_score(obs)
    weight = SEVERITY_WEIGHTS.get(obs.get("name"), 1.0)
    geoip_mult = calculate_geoip_multiplier(obs)
    
    return base_score * weight * geoip_mult * math.log1p(count)

def process_enriched_observations():
    print("[i] Starting Risk Scorer Engine...")

    if not os.path.exists(ENRICHED_INPUT_DIR):
        print(f"[!] Enriched observations directory not found: {ENRICHED_INPUT_DIR}")
        return

    entity_risk_scores = defaultdict(lambda: {"total_score": 0, "observations": {}})

    print("[i] Aggregating risk scores from enriched observations...")
    for filename in sorted(os.listdir(ENRICHED_INPUT_DIR)):
        if not filename.endswith(".jsonl"):
            continue

        file_path = os.path.join(ENRICHED_INPUT_DIR, filename)
        print(f"  -> Processing file: {filename}")

        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    enriched_obs = json.loads(line)
                    obs_data = enriched_obs.get("observation", {})

                    entity_ip = obs_data.get("source_event", {}).get("destination", {}).get("ip")
                    if not entity_ip:
                        continue

                    mitre = obs_data.get("mitre_attack", {})
                    if not mitre.get("tactic"):
                        mitre["tactic"] = "Heuristic / Non-MITRE"

                    sig = (obs_data.get("name"), mitre.get("technique_id"), mitre.get("tactic"))

                    if sig not in entity_risk_scores[entity_ip]["observations"]:
                        entity_risk_scores[entity_ip]["observations"][sig] = {
                            "name": obs_data.get("name"),
                            "base_risk_score": obs_data.get("base_risk_score", 0),
                            "mitre_attack": mitre,
                            "risk_modifiers": obs_data.get("risk_modifiers", {}),
                            "source_event": obs_data.get("source_event", {}),
                            "geoip": obs_data.get("geoip", {}),
                            "count": 0,
                        }

                    entity_risk_scores[entity_ip]["observations"][sig]["count"] += 1

                except json.JSONDecodeError:
                    continue

    print("\n[i] Generating high-risk entity report...")
    high_risk_entities = []

    for ip, data in entity_risk_scores.items():
        total_score = 0
        contributing_obs = []

        for sig, obs in data["observations"].items():
            count = obs["count"]
            effective_score = calculate_final_score(obs, count)
            obs["final_risk_score"] = effective_score
            total_score += effective_score
            contributing_obs.append(obs)

        if total_score >= RISK_THRESHOLD:
            high_risk_entities.append({
                "ip": ip,
                "total_score": total_score,
                "observation_count": sum(obs["count"] for obs in data["observations"].values()),
                "contributing_observations": contributing_obs,
            })

    high_risk_entities.sort(key=lambda x: x["total_score"], reverse=True)

    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
    report_timestamp = datetime.now(timezone.utc)
    report_filename = f"risk-report-{report_timestamp.strftime('%Y%m%d-%H%M%S')}.json"
    report_output_path = os.path.join(REPORT_OUTPUT_DIR, report_filename)

    report_data = {
        "report_generated_utc": report_timestamp.isoformat(),
        "risk_threshold": RISK_THRESHOLD,
        "high_risk_entities": high_risk_entities,
    }

    with open(report_output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)

    print(f"\n[i] High-risk entity report saved to: {report_output_path}")

if __name__ == "__main__":
    process_enriched_observations()