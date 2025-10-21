import os
import subprocess
import sys
from utils.config_loader import load_yaml

def run(cmd: list, env=None):
    print(f"[pipeline] ➤ {' '.join(cmd)}")
    res = subprocess.run(cmd, env=env)
    if res.returncode != 0:
        raise SystemExit(res.returncode)

def main():
    settings = load_yaml(os.path.join('config','settings.yaml'))
    paths = settings.get('paths', {})
    # Ensure output dirs exist
    for p in ['zeek_log_dir','suricata_log_dir','normalized_dir','observations_dir','enriched_dir','reports_dir']:
        os.makedirs(paths[p], exist_ok=True)

    # 1. Ingest PCAPs
    run([sys.executable, 'run_merge.py'])

    # 2. Normalize logs
    run([sys.executable, 'log_aggregator_normalizer.py'])

    # 3. Build UEBA profiles
    run([sys.executable, 'profiler.py'])

    # 4. Correlation (static + UEBA)
    run([sys.executable, 'correlation_engine.py'])

    # 5. Enrichment (MITRE + asset DB)
    run([sys.executable, 'context_engine.py'])

    # 6. Risk scoring (with decay + config)
    run([sys.executable, 'risk_score_engine.py'])

    print("\n[pipeline] ✅ Completed. Launch dashboard separately:")
    print("  python dashboard.py")

if __name__ == '__main__':
    main()
