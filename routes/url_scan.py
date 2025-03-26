#routes/url_scan.py
"""
Documentation:

Request:
    Method: POST 
    Endpoint: /url_scan
    Parameters: None required
    Headers: None required

Body:
    Format: JSON
    Example body:
    {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "url": "https://example.com/path"
    }

Response:
    Format: JSON
    Example response:
    {
        "result": {
            "domain_info": {
                "domain_name": "example.com",
                "registrar": "Example Registrar",
                "creation_date": "2020-01-01 00:00",
                "emails": ["admin@example.com"],
                "country": "US"
            },
            "issues": [
                "URL uses non-standard port: 8080"
            ],
            "risk_rating": 2,
            "risk_level": "SAFE",
            "path": "/path",
            "domain": "example.com"
        }
    }
    Note: Risk level will be one of: "SAFE", "CAUTION", or "DANGEROUS"

Example curl command:
    curl -X POST http://localhost:5000/url_scan \
         -H "Content-Type: application/json" \
         -d '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzcxMTg1NzV9.5rGCXz9mcX-kCxG-5Z4tUNQaGmZrsIcqkJF64EUwE54", "url": "https://example.com/path"}'

Notes:
- The token must be valid (obtained from /get_token endpoint)
- URL must be a valid HTTP/HTTPS URL
- Result includes domain information, security issues found, risk rating (0-10), and risk level
- Domain info may be incomplete if WHOIS lookup fails
- Risk factors include: suspicious TLDs, IP-based URLs, non-standard ports, and suspicious URL patterns

"""


from flask import Blueprint, request, jsonify
from utils.token_validator import validate_token
from urllib.parse import urlparse
import re
import requests
import dns.resolver
import hashlib
import json
import tldextract

url_scan_blueprint = Blueprint('url_scan', __name__)

def scan_url(url):
    result = {}
    try:
        # Check URL status (following redirects for complete chain)
        response = requests.get(url, timeout=5, allow_redirects=True)
        result['status_code'] = response.status_code
        result['final_url'] = response.url
        result['redirect_count'] = len(response.history)
        result['redirect_chain'] = [resp.url for resp in response.history]
        result['redirected'] = True if response.history else False

        # Parse URL and extract domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        result['input_url'] = url
        result['domain'] = domain

        # Resolve IP address using dns.resolver
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ip_address = answers[0].to_text()
            result['ip_address'] = ip_address
        except Exception as e:
            result['ip_address'] = f'Could not resolve: {e}'

        # Deep Dive URL Static Structure Analysis
        result['url_length'] = len(url)
        # Check if an IP address is directly used in the URL
        result['has_ip_in_url'] = bool(re.search(r'\d+\.\d+\.\d+\.\d+', domain))
        # Check for suspicious characters in URL
        result['has_suspicious_chars'] = bool(re.search(r'[@!#$%^&*()+=,\[\]{};:\'\"<>?\\]', url))
        # Count special characters
        result['special_char_count'] = len(re.findall(r'[@!#$%^&*()+=,\[\]{};:\'\"<>?\\]', url))
        # URL Fingerprinting (Hashes)
        result['hash_md5'] = hashlib.md5(url.encode()).hexdigest()
        result['hash_sha256'] = hashlib.sha256(url.encode()).hexdigest()

        # Domain Breakdown using tldextract
        ext = tldextract.extract(domain)
        result['subdomain'] = ext.subdomain
        result['registered_domain'] = ext.registered_domain
        result['suffix'] = ext.suffix

    except requests.RequestException as e:
        result['error'] = f'Request error: {e}'
    except Exception as ex:
        result['error'] = f'General error: {ex}'

    return result


@url_scan_blueprint.route('/url_scan', methods=['POST'])
def url_scan():
    try:
        data = request.get_json()

        if not data:
            print(f"[ LOG (url_scan) ]: No JSON data provided")
            return jsonify({
                'status': 'error',
                'message': 'No JSON data provided'
            }), 400

        if 'token' not in data or 'url' not in data:
            print(f"[ LOG (url_scan) ]: Token or URL were not found in data")
            response = {
                'status': 'error',
                'message': 'Token and URL are required'
            }
            return jsonify(response), 400

        print(f"[ LOG (url_scan) ]: Data is valid containing token and URL")

        # Validate the token
        if not validate_token(data['token']):
            print(f"[ LOG (url_scan) ]: Token is invalid")
            response = {
                'status': 'error',
                'message': 'Invalid token'
            }
            return jsonify(response), 401

        url = data['url']
        result = scan_url(url)
        return jsonify({'result': result})
    
    except Exception as e:
        print(f"[ LOG (url_scan) ]: Unexpected error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500
