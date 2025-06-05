from flask import Flask, jsonify, request
from flask_cors import CORS
import scan_network
import os
import json
import time

app = Flask(__name__)

# Configure CORS more explicitly
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://192.168.15.107", "http://localhost", "http://127.0.0.1"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

@app.route('/api/scan', methods=['GET', 'OPTIONS'])
def scan():
    """
    Endpoint to perform exactly: nmap -sS <ip_range>
    100% like your original script - no modifications
    """
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response
    
    # Get parameters from the request
    ip = request.args.get('ip', '192.168.15.1')
    subnet = request.args.get('subnet', '255.255.255.0')
    
    # Validate subnet mask
    valid_subnets = [
        '255.0.0.0', '255.128.0.0', '255.192.0.0', '255.224.0.0', 
        '255.240.0.0', '255.248.0.0', '255.252.0.0', '255.254.0.0', 
        '255.255.0.0', '255.255.128.0', '255.255.192.0', '255.255.224.0', 
        '255.255.240.0', '255.255.248.0', '255.255.252.0', '255.255.254.0', 
        '255.255.255.0', '255.255.255.128', '255.255.255.192', '255.255.255.224', 
        '255.255.255.240', '255.255.255.248', '255.255.255.252'
    ]
    
    if subnet not in valid_subnets:
        error_response = jsonify({
            "error": f"Invalid subnet mask: {subnet}",
            "status": "error"
        })
        error_response.headers.add('Access-Control-Allow-Origin', '*')
        return error_response, 400
    
    # Convert IP and subnet to CIDR notation for nmap
    if subnet == '255.255.255.0':
        ip_range = f"{ip.rsplit('.', 1)[0]}.0/24"
    elif subnet == '255.255.0.0':
        ip_range = f"{ip.rsplit('.', 2)[0]}.0.0/16"
    elif subnet == '255.0.0.0':
        ip_range = f"{ip.split('.')[0]}.0.0.0/8"
    else:
        # Calculate CIDR prefix from subnet mask
        subnet_parts = subnet.split('.')
        cidr = sum([bin(int(x)).count('1') for x in subnet_parts])
        ip_base = ip.split('.')
        
        # Calculate network address based on subnet mask
        network = []
        for i in range(4):
            subnet_octet = int(subnet_parts[i])
            ip_octet = int(ip_base[i])
            network.append(str(ip_octet & subnet_octet))
        
        ip_range = f"{'.'.join(network)}/{cidr}"
    
    print(f"[INFO] Received SYN scan request for IP: {ip}, Subnet: {subnet}")
    print(f"[INFO] Will execute: nmap -sS {ip_range}")
    
    try:
        # Check if nmap is available
        import subprocess
        try:
            result = subprocess.run(['nmap', '--version'], capture_output=True, check=True)
            nmap_version = result.stdout.decode().split('\n')[0] if result.stdout else 'Unknown'
            print(f"[INFO] Nmap version: {nmap_version}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("[ERROR] Nmap not found!")
            error_response = jsonify({
                "error": "Nmap not installed or not accessible",
                "status": "error",
                "hosts": [],
                "note": "Please install nmap: sudo apt-get install nmap"
            })
            error_response.headers.add('Access-Control-Allow-Origin', '*')
            return error_response, 500
        
        print(f"[INFO] Starting SYN scan: nmap -sS {ip_range}")
        
        # Perform exactly: nmap -sS <ip_range>
        scan_results = scan_network.scan_network(ip_range, use_real_nmap=True)
        
        print(f"[INFO] SYN scan completed successfully.")
        print(f"[INFO] Found {len(scan_results.get('hosts', []))} hosts with {scan_results.get('total_ports', 0)} total open ports")
        
        # Add CORS headers to response
        response = jsonify(scan_results)
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
        
    except Exception as e:
        print(f"[ERROR] SYN scan failed: {str(e)}")
        
        error_response = jsonify({
            "error": f"SYN scan failed: {str(e)}", 
            "status": "error",
            "hosts": [],
            "scan_range": ip_range,
            "note": "Only real nmap -sS data is returned"
        })
        error_response.headers.add('Access-Control-Allow-Origin', '*')
        return error_response, 500

@app.route('/api/health', methods=['GET', 'OPTIONS'])
def health_check():
    """
    Health check endpoint
    """
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response
    
    print("[INFO] Health check requested")
    
    # Check nmap availability
    nmap_available = False
    nmap_version = "Not installed"
    try:
        import subprocess
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, check=True)
        nmap_available = True
        nmap_version = result.stdout.split('\n')[0] if result.stdout else "Unknown version"
    except (subprocess.CalledProcessError, FileNotFoundError):
        nmap_available = False
    
    response = jsonify({
        "status": "ok", 
        "message": "ENSA Vulnerability Scanner API is running (SYN SCAN MODE)",
        "server": "192.168.15.13:5000",
        "nmap_available": nmap_available,
        "nmap_version": nmap_version,
        "scan_mode": "Real nmap -sS scanning" if nmap_available else "Nmap not available",
        "command": "nmap -sS <target>"
    })
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

if __name__ == '__main__':
    print("=" * 60)
    print("Starting ENSA Vulnerability Scanner API - SYN SCAN MODE")
    print("Backend Server IP: 192.168.15.13")
    print("Frontend Server IP: 192.168.15.107")
    print("API will be available at: http://192.168.15.13:5000")
    print("=" * 60)
    print("📡 Command executed: nmap -sS <target>")
    print("🎯 100% Real SYN scan - exactly like your original script")
    print("⚡ Fast and efficient - only SYN packets")
    print("=" * 60)
    
    # Check nmap availability on startup
    try:
        import subprocess
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, check=True)
        nmap_version = result.stdout.split('\n')[0] if result.stdout else 'Unknown'
        print(f"[INFO] Nmap detected: {nmap_version}")
        print("[INFO] Real SYN scanning enabled")
        print("[INFO] Command: nmap -sS <target>")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[ERROR] Nmap not found! Scanner will not work.")
        print("[INFO] To install nmap: sudo apt-get install nmap")
    
    print("=" * 60)
    
    # Run the Flask app on the specified IP and port
    app.run(host='0.0.0.0', port=5000, debug=True)
