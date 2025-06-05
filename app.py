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

# Modifique a função scan para validar a máscara de sub-rede
@app.route('/api/scan', methods=['GET', 'OPTIONS'])
def scan():
    """
    Endpoint to perform a network scan using nmap
    Returns scan results as JSON
    """
    if request.method == 'OPTIONS':
        # Handle preflight request
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
    
    print(f"[INFO] Received scan request for IP: {ip}, Subnet: {subnet}")
    print(f"[INFO] Scanning range: {ip_range}")
    
    try:
        # Check if nmap is available
        import subprocess
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
            print("[INFO] Nmap is available and ready to use")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("[WARNING] Nmap not found! Installing nmap...")
            # Try to install nmap
            try:
                subprocess.run(['apt-get', 'update'], check=True)
                subprocess.run(['apt-get', 'install', '-y', 'nmap'], check=True)
                print("[INFO] Nmap installed successfully")
            except subprocess.CalledProcessError:
                print("[ERROR] Failed to install nmap. Using mock data instead.")
                # Fall back to mock data if nmap installation fails
                scan_results = scan_network.generate_mock_scan_data(ip_range)
                response = jsonify({
                    "scan_range": ip_range,
                    "hosts": scan_results,
                    "scan_time": "1:45",
                    "total_hosts": len(scan_results),
                    "total_ports": sum(len(host['ports']) for host in scan_results),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "scanner_version": "ENSA v1.0 (Mock Mode)",
                    "note": "Using mock data - nmap not available"
                })
                response.headers.add('Access-Control-Allow-Origin', '*')
                return response
        
        print("[INFO] Starting network scan with nmap...")
        
        # Perform the scan using nmap
        scan_results = scan_network.scan_network(ip_range, use_real_nmap=True)
        
        print(f"[INFO] Scan completed successfully. Found {len(scan_results.get('hosts', []))} hosts")
        
        # Add CORS headers to response
        response = jsonify(scan_results)
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
        
    except Exception as e:
        print(f"[ERROR] Scan failed: {str(e)}")
        
        # If real scan fails, provide mock data as fallback
        print("[INFO] Falling back to mock data due to error")
        try:
            mock_hosts = scan_network.generate_mock_scan_data(ip_range)
            fallback_response = jsonify({
                "scan_range": ip_range,
                "hosts": mock_hosts,
                "scan_time": "1:45",
                "total_hosts": len(mock_hosts),
                "total_ports": sum(len(host['ports']) for host in mock_hosts),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scanner_version": "ENSA v1.0 (Fallback Mode)",
                "error": f"Real scan failed: {str(e)}",
                "note": "Using mock data as fallback"
            })
            fallback_response.headers.add('Access-Control-Allow-Origin', '*')
            return fallback_response
        except Exception as fallback_error:
            error_response = jsonify({
                "error": f"Scan failed: {str(e)}, Fallback failed: {str(fallback_error)}", 
                "status": "error"
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
        "message": "ENSA Vulnerability Scanner API is running",
        "server": "192.168.15.13:5000",
        "nmap_available": nmap_available,
        "nmap_version": nmap_version,
        "scan_mode": "Real nmap scanning" if nmap_available else "Mock data mode"
    })
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

@app.route('/api/scan/status', methods=['GET', 'OPTIONS'])
def scan_status():
    """
    Get scan status - for future implementation of real-time updates
    """
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response
    
    response = jsonify({
        "status": "scanning",
        "progress": 75,
        "message": "Analisando hosts na rede com nmap..."
    })
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

if __name__ == '__main__':
    print("=" * 60)
    print("Starting ENSA Vulnerability Scanner API...")
    print("Backend Server IP: 192.168.15.13")
    print("Frontend Server IP: 192.168.15.107")
    print("API will be available at: http://192.168.15.13:5000")
    print("=" * 60)
    
    # Check nmap availability on startup
    try:
        import subprocess
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, check=True)
        print(f"[INFO] Nmap detected: {result.stdout.split()[1] if result.stdout else 'Unknown version'}")
        print("[INFO] Real network scanning enabled")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[WARNING] Nmap not found! Scanner will use mock data.")
        print("[INFO] To install nmap: sudo apt-get install nmap")
    
    print("=" * 60)
    
    # Run the Flask app on the specified IP and port
    app.run(host='0.0.0.0', port=5000, debug=True)
