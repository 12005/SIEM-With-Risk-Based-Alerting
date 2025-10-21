import os
import subprocess
import shutil
from collections import defaultdict

# --- Configuration ---
PCAP_DIR = 'pcap'
ZEEK_LOG_DIR = 'zeek-logs'
SURICATA_LOG_DIR = 'suricata-logs'

# --- Setup: Ensure output folders are clean and exist ---
def setup_directories():
    """Create and clean log directories before a run."""
    print("[i] Setting up directories...")
    # Clean and create Zeek directory
    if os.path.exists(ZEEK_LOG_DIR):
        shutil.rmtree(ZEEK_LOG_DIR)
    os.makedirs(ZEEK_LOG_DIR, exist_ok=True)

    # Clean and create Suricata directory
    if os.path.exists(SURICATA_LOG_DIR):
        shutil.rmtree(SURICATA_LOG_DIR)
    os.makedirs(SURICATA_LOG_DIR, exist_ok=True)

# --- Zeek Processing ---
def process_pcap_with_zeek(pcap_file):
    """Runs the Zeek docker container on a single pcap file."""
    print(f"  [Zeek] Processing: {pcap_file}")
    try:
        # We use 'bash -c' to first change directory into the mounted log volume
        # and *then* execute Zeek. This ensures logs are written to the correct place.
        command = [
            "docker", "run", "--rm",
            "-v", f"{os.path.abspath(PCAP_DIR)}:/pcap:ro",
            "-v", f"{os.path.abspath(ZEEK_LOG_DIR)}:/logs",
            "zeek/zeek",
            "bash", "-c", f"cd /logs && zeek -Cr /pcap/{pcap_file}"
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Zeek failed on {pcap_file}:\n{e.stderr}")

# --- Zeek Log Merging (Header-Aware) ---
def merge_zeek_logs():
    """Merges all generated Zeek logs of the same type into single files."""
    print("[+] Merging Zeek logs (header-aware)...")
    # Use a defaultdict to store lines for each log type (conn.log, http.log, etc.)
    log_data = defaultdict(list)
    processed_headers = set()

    # Create a list of files to process to avoid issues with directory changes
    zeek_files = [f for f in os.listdir(ZEEK_LOG_DIR) if os.path.isfile(os.path.join(ZEEK_LOG_DIR, f))]

    for filename in sorted(zeek_files):
        file_path = os.path.join(ZEEK_LOG_DIR, filename)
        log_type = filename # e.g., 'conn.log'
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # If we haven't seen this log type before, add its full content (header + data)
        if log_type not in processed_headers:
            log_data[log_type].extend(lines)
            processed_headers.add(log_type)
        else:
            # If we have seen it, only add data lines (skip headers)
            data_lines = [line for line in lines if not line.startswith('#')]
            log_data[log_type].extend(data_lines)
            
        # Remove the individual log file after processing
        os.remove(file_path)

    # Write the truly merged logs
    for log_type, lines in log_data.items():
        merged_path = os.path.join(ZEEK_LOG_DIR, f"merged_{log_type}")
        print(f"  -> Writing merged file: {merged_path}")
        with open(merged_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)

# --- Suricata Processing ---
def process_pcap_with_suricata(pcap_file):
    """Runs Suricata on a single PCAP, appending output to a combined log."""
    print(f"  [Suricata] Processing: {pcap_file}")
    try:
        # Base command for Suricata
        command = [
            "docker", "run", "--rm",
            "-v", f"{os.path.abspath(PCAP_DIR)}:/pcap:ro",
            "-v", f"{os.path.abspath(SURICATA_LOG_DIR)}:/logs",
        ]
        
        # --- PLATFORM-SPECIFIC FIX ---
        # os.getuid() is not available on Windows. Only add the --user flag on non-Windows systems.
        if os.name != 'nt':
            current_user = f"{os.getuid()}:{os.getgid()}"
            command.extend(["--user", current_user])
        
        # Add the rest of the command
        command.extend([
            "jasonish/suricata",
            "suricata", "-r", f"/pcap/{pcap_file}", "-l", "/logs"
        ])

        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Suricata failed on {pcap_file}:\n{e.stderr}")

# --- Main Execution Logic ---
if __name__ == "__main__":
    setup_directories()
    
    pcap_files = [f for f in os.listdir(PCAP_DIR) if f.endswith(('.pcap', '.pcapng'))]

    if not pcap_files:
        print("[!] No .pcap or .pcapng files found in the 'pcap' directory. Exiting.")
        exit()

    # --- Run Zeek on all PCAPs ---
    print("\n[+] Starting Zeek processing...")
    for pcap in pcap_files:
        process_pcap_with_zeek(pcap)
    
    # --- Merge all Zeek logs ---
    merge_zeek_logs()
    
    # --- Run Suricata on all PCAPs ---
    print("\n[+] Starting Suricata processing...")
    for pcap in pcap_files:
        process_pcap_with_suricata(pcap)

    print("\n[✅] All PCAPs processed and logs generated successfully.")