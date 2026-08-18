from flask import Flask, request, jsonify
import time
import os
import requests

app = Flask(__name__)
# Dummy data - Ideal to use fullfledged OAUTH2 Intrceptors for AuthZ 
authenticated_clients = set()
NVD_TOKEN = os.environ.get("NVD_API_KEY")

@app.route('/authenticate', methods=['POST'])
def authenticate():
    api_key = request.headers.get('Authorization', '').replace('Bearer ', '')
    if api_key == 'your_api_key':
        authenticated_clients.add(api_key)
        return jsonify({'message': 'Authentication successful'}), 200
    else:
        return jsonify({'error': 'Authentication failed'}), 401

@app.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    api_key = request.headers.get('Authorization', '').replace('Bearer ', '')
    if api_key in authenticated_clients:
        # Replace the following line with your logic to retrieve vulnerabilities
        vulnerabilities = {'CVE-2010-0026': 'Example vulnerability'}
        return jsonify(vulnerabilities), 200
    else:
        return jsonify({'error': 'Unauthorized'}), 401
@app.route('/getVuln', methods=['GET'])
def get_vuln():
    """
    Fetches details for a single CVE ID directly from the NIST NVD 2.0 API
    Example: /getVuln?cveId=CVE-2023-38408
    """
    cve_id = request.args.get('cveId')
    
    if not cve_id:
        return jsonify({'error': 'Missing required query parameter: cveId'}), 400

    # Ensure our secret API key is available
    if not NVD_TOKEN:
        return jsonify({'error': 'Cluster Configuration Error: NVD API Token not found'}), 500

    # NIST NVD API 2.0 URL layout
    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    headers = {
        "apiKey": NVD_TOKEN  # NVD 2.0 requires the key in the headers
    }
    params = {
        "cveId": cve_id
    }

    try:
        # Request data from NIST with a 10-second timeout window
        response = requests.get(nvd_url, headers=headers, params=params, timeout=10)
        
        if response.status_code != 200:
            return jsonify({
                'error': f'NIST API returned an error status code: {response.status_code}',
                'details': response.text
            }), response.status_code

        nvd_data = response.json()
        
        # Verify that the vulnerability actually exists in the return dictionary
        if not nvd_data.get('vulnerabilities'):
            return jsonify({'error': f'Vulnerability {cve_id} not found in NIST database'}), 404

        # Return the clean, live payload
        return jsonify(nvd_data), 200
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Failed to reach NIST NVD API connection grid', 'details': str(e)}), 502


if __name__ == '__main__':
    # OKD injects the PORT environment variable (usually 8080). Fall back to 8080 if not set.
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=True)
