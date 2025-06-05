import subprocess
import json
import re
import time

def scan_network(ip_range, use_real_nmap=True):
    """
    Performs a network scan using exactly: nmap -sS <ip_range>
    100% REAL DATA - exactly like your original script
    
    Args:
        ip_range: The IP range to scan (e.g., "192.168.15.0/24")
        use_real_nmap: Whether to use real nmap (if False, returns empty results)
        
    Returns:
        dict: Scan results in a structured format - exactly what nmap -sS returns
    """
    print(f"[INFO] Realizando scan SYN na rede: {ip_range} ...")
    
    if not use_real_nmap:
        print("[INFO] Real nmap disabled, returning empty results")
        return {
            "scan_range": ip_range,
            "hosts": [],
            "scan_time": "0:00",
            "total_hosts": 0,
            "total_ports": 0,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scanner_version": "ENSA v1.0 (Disabled)",
            "note": "Real scanning disabled"
        }
    
    try:
        # Check if nmap is available
        result = subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        nmap_version = result.stdout.decode().split('\n')[0] if result.stdout else 'Unknown'
        print(f"[INFO] Nmap detected: {nmap_version}")
        
        start_time = time.time()
        hosts = perform_syn_scan(ip_range)
        end_time = time.time()
        
        # Calculate actual scan time
        scan_duration = end_time - start_time
        scan_minutes = int(scan_duration // 60)
        scan_seconds = int(scan_duration % 60)
        scan_time = f"{scan_minutes}:{scan_seconds:02d}"
        
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[ERROR] Nmap not available: {e}")
        return {
            "scan_range": ip_range,
            "hosts": [],
            "scan_time": "0:00",
            "total_hosts": 0,
            "total_ports": 0,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scanner_version": "ENSA v1.0 (Error)",
            "error": "Nmap not installed or not accessible",
            "note": "Install nmap to perform real network scanning"
        }
    
    scan_results = {
        "scan_range": ip_range,
        "hosts": hosts,
        "scan_time": scan_time,
        "total_hosts": len(hosts),
        "total_ports": sum(len(host['ports']) for host in hosts),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scanner_version": f"ENSA v1.0 (Real SYN Scan) - {nmap_version}",
        "nmap_command_used": f"nmap -sS {ip_range}"
    }
    
    print(f"[INFO] SYN scan completed in {scan_time}. Found {len(hosts)} hosts with {scan_results['total_ports']} open ports.")
    return scan_results

def perform_syn_scan(ip_range):
    """
    Perform exactly: nmap -sS <ip_range>
    Just like your original script - NO MODIFICATIONS
    """
    print(f"[INFO] Executing: nmap -sS {ip_range}")
    
    try:
        # Execute exactly the same command as your script
        comando = ['nmap', '-sS', ip_range]
        resultado = subprocess.run(comando, capture_output=True, text=True)
        
        if resultado.returncode == 0:
            print("[INFO] Resultado do scan:")
            print(resultado.stdout)
            
            # Parse the output to extract host information
            hosts = parse_syn_scan_output(resultado.stdout)
            return hosts
        else:
            print("[ERROR] Erro ao executar o Nmap:")
            print(resultado.stderr)
            return []
            
    except Exception as e:
        print(f"[ERROR] Ocorreu um erro: {e}")
        return []

def parse_syn_scan_output(nmap_output):
    """
    Parse the output from nmap -sS command
    Extract exactly what nmap returns - nothing more, nothing less
    """
    hosts = []
    lines = nmap_output.split('\n')
    current_host = None
    
    for line in lines:
        line = line.strip()
        
        # Look for host scan reports
        if line.startswith('Nmap scan report for'):
            # Save previous host if exists
            if current_host and current_host.get('ports'):
                hosts.append(current_host)
            
            # Extract hostname and IP
            if '(' in line and ')' in line:
                # Format: "Nmap scan report for hostname (192.168.1.1)"
                parts = line.split('(')
                hostname = parts[0].replace('Nmap scan report for', '').strip()
                ip = parts[1].replace(')', '').strip()
            else:
                # Format: "Nmap scan report for 192.168.1.1"
                target = line.replace('Nmap scan report for', '').strip()
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
                    hostname = target
                    ip = target
                else:
                    hostname = target
                    ip = target
            
            current_host = {
                "hostname": hostname,
                "ip": ip,
                "mac": None,
                "vendor": None,
                "status": "up",
                "ports": []
            }
        
        # Look for host status
        elif line.startswith('Host is up'):
            if current_host:
                # Extract latency if available
                latency_match = re.search(r'$$([0-9.]+s)$$', line)
                if latency_match:
                    current_host["latency"] = latency_match.group(1)
        
        # Look for MAC address
        elif line.startswith('MAC Address:'):
            if current_host:
                mac_match = re.search(r'MAC Address: ([0-9A-F:]{17})', line, re.IGNORECASE)
                if mac_match:
                    current_host["mac"] = mac_match.group(1).upper()
                
                # Extract vendor
                vendor_match = re.search(r'MAC Address: [0-9A-F:]+ $$([^)]+)$$', line, re.IGNORECASE)
                if vendor_match:
                    current_host["vendor"] = vendor_match.group(1)
        
        # Look for port information
        elif re.match(r'^\d+/(tcp|udp)\s+\w+\s+\w+', line):
            if current_host:
                # Parse port line: "22/tcp   open  ssh"
                parts = line.split()
                if len(parts) >= 3:
                    port_protocol = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    
                    port_num, protocol = port_protocol.split('/')
                    
                    port_data = {
                        "port": port_num,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "version": ""  # SYN scan doesn't detect versions
                    }
                    current_host["ports"].append(port_data)
    
    # Add the last host if it exists and has ports
    if current_host and current_host.get('ports'):
        hosts.append(current_host)
    
    return hosts

if __name__ == "__main__":
    # Test exactly like your original script
    ip = input("Digite o IP da rede (ex: 192.168.0.0/24): ")
    results = scan_network(ip, use_real_nmap=True)
    print(json.dumps(results, indent=2))
