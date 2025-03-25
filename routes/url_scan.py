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
import whois
import re
from datetime import datetime
import math
from collections import Counter

url_scan_blueprint = Blueprint('url_scan', __name__)

# def scan_url(url):
#     try:
#         result_data = {
#             "domain_info": {},
#             "issues": [],
#             "risk_rating": 0,
#             "risk_level": "",
#             "path": "",
#             "domain": ""
#         }

#         # Parse URL
#         try:
#             parsed_url = urlparse(url)
#             result_data["domain"] = parsed_url.netloc
#             result_data["path"] = parsed_url.path if parsed_url.path and parsed_url.path != "/" else "No path specified"
#         except Exception as e:
#             print(f"[ LOG (url_scan) ]: Error parsing URL: {str(e)}")
#             result_data["issues"].append("Invalid URL format")
#             return result_data

#         # Get domain info
#         try:
#             domain_info = whois.whois(parsed_url.netloc)
#             fields = ["domain_name", "registrar", "registrar_url", "org", "organization", "creation_date", "emails", "dnssec", "country"]
            
#             for field in fields:
#                 try:
#                     field_value = domain_info.get(field)
#                     if field_value is not None:
#                         if field == "creation_date" and isinstance(field_value, list):
#                             field_value = [date.strftime("%Y-%m-%d %H:%M") if hasattr(date, 'strftime') else str(date) for date in field_value]
#                         result_data["domain_info"][field] = field_value
#                 except Exception as e:
#                     print(f"[ LOG (url_scan) ]: Error processing field {field}: {str(e)}")
#                     continue
#         except Exception as e:
#             print(f"[ LOG (url_scan) ]: Error getting domain info: {str(e)}")
#             result_data["issues"].append("Could not retrieve domain information")

#         # Check for suspicious patterns
#         suspicious_patterns = [
#             (r'\.cn$', "Ends with .cn"),
#             (r'\.ru$', "Ends with .ru"), 
#             (r'\.zip$', "Ends with .zip"),
#             (r'@', "Contains @"),
#             (r'\/\/.*\/\/', "Contains double slashes"),
#             (r'[\w\-\.]+\.tk', "Uses .tk domain"),
#             (r'\d{4,}', "Contains long numeric sequence")
#         ]

#         risk_score = 0
#         for pattern, message in suspicious_patterns:
#             if re.search(pattern, url):
#                 result_data["issues"].append(message)
#                 risk_score += 3

#         # Check URL structure
#         if re.match(r'^http[s]?:\/\/\d{1,3}(\.\d{1,3}){3}', url):
#             result_data["issues"].append("URL uses an IP address instead of a domain name")
#             risk_score += 3

#         if len(url) > 2083:
#             result_data["issues"].append("URL is unusually long")
#             risk_score += 1

#         if re.search(r':\d+', url):
#             try:
#                 port = int(re.search(r':(\d+)', url).group(1))
#                 if port not in [80, 443]:
#                     result_data["issues"].append(f"URL uses non-standard port: {port}")
#                     risk_score += 2
#             except Exception as e:
#                 print(f"[ LOG (url_scan) ]: Error checking port: {str(e)}")

#         # Calculate final risk score
#         risk_score = max(0, min(10, risk_score))
#         result_data["risk_rating"] = risk_score

#         if risk_score <= 3:
#             result_data["risk_level"] = "SAFE"
#         elif risk_score <= 6:
#             result_data["risk_level"] = "CAUTION"
#         else:
#             result_data["risk_level"] = "DANGEROUS"

#         return result_data

#     except Exception as e:
#         print(f"[ LOG (url_scan) ]: Unexpected error in scan_url: {str(e)}")
#         return {"error": str(e)}

def scan_url(url):
    """Analyze a URL for potential security risks and return analysis results as a dictionary."""
    
    # URL format validation
    if not url.startswith(('http://', 'https://')):
        return {"error": "Invalid URL format. URL must start with http:// or https://"}
    
    # Initialize lists and dictionaries for analysis
    suspicious_terms = ['login', 'signin', 'account', 'update', 'secure', 'banking', 
                          'verify', 'password', 'credential']
    suspicious_extensions = ['.exe', '.zip', '.rar', '.pdf', '.doc', '.php']
    malicious_country_codes = ['CN','TR','RU','TW','BR','RO','PK', 'IT','HU']
    suspicious_tlds = ['.tk', '.cc', '.ru','.xyz','.sh']
    popular_brands = ['paypal', 'google', 'facebook', 'amazon', 'apple', 'microsoft', 
                        'netflix', 'twitter', 'instagram', 'linkedin']
    
    # Parse URL
    parsed = urlparse(url)
    
    # Calculate entropy for a given text
    def calculate_entropy(text):
        if not text:
            return 0.0
        char_freq = Counter(text)
        length = len(text)
        entropy = 0.0
        for freq in char_freq.values():
            prob = freq / length
            entropy -= prob * math.log2(prob)
        return entropy
    
    # Domain analysis
    domain = parsed.netloc
    domain_parts = domain.split('.')
    
    # Extract TLD
    tld = '.' + domain_parts[-1] if len(domain_parts) > 1 else "Unknown"
    
    # Extract server section
    server_section = '.'.join(domain_parts[:-1]) if len(domain_parts) > 1 else "Unknown"
    
    # Check brand impersonation
    domain_lower = domain.lower()
    brand_impersonation = "No brand impersonation detected"
    for brand in popular_brands:
        if brand in domain_lower and not domain_lower.endswith(brand) and not domain_lower.startswith(brand):
            brand_impersonation = f"Potential {brand.title()} impersonation detected"
            break
    
    # Extract country code
    country_code = domain_parts[-1].upper() if len(domain_parts) > 1 and len(domain_parts[-1]) == 2 else "Unknown"
    
    # Create domain features
    domain_features = {
        'Domain Length': len(domain),
        'Number of Dots': domain.count('.'),
        'Number of Hyphens': domain.count('-'),
        'Number of Digits': sum(c.isdigit() for c in domain),
        'Top Level Domain': tld,
        'Server Section': server_section,
        'Potential Brand Impersonation': brand_impersonation,
        'Country Code': country_code
    }
    
    # Get domain registration info
    try:
        domain_info = whois.whois(domain)
        if domain_info.creation_date:
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            domain_features['Domain Age (days)'] = (datetime.now() - creation_date).days
        else:
            domain_features['Domain Age (days)'] = "Unknown"
        domain_features['Registration Status'] = "Registered" if domain_info.domain_name else "Unregistered"
    except Exception:
        domain_features['Domain Age (days)'] = "Unknown"
        domain_features['Registration Status'] = "Unknown"
    
    # Path analysis
    path = parsed.path
    path_features = {
        'Path Length': len(path),
        'Number of Slashes': path.count('/'),
        'Number of Parameters': path.count('?'),
        'Number of Fragments': path.count('#'),
        'Suspicious Extensions': "Yes" if any(ext in path.lower() for ext in suspicious_extensions) else "No"
    }
    
    # Lexical analysis
    url_lower = url.lower()
    lexical_features = {
        'Suspicious Terms Count': sum(term in url_lower for term in suspicious_terms),
        'Special Character Ratio': f"{len(re.findall(r'[^a-zA-Z0-9.]', url)) / len(url):.2%}"
    }
    
    # Entropy analysis
    entropy_features = {
        'Full URL Entropy': f"{calculate_entropy(url):.2f}",
        'Domain Entropy': f"{calculate_entropy(parsed.netloc):.2f}",
        'Path Entropy': f"{calculate_entropy(parsed.path):.2f}"
    }
    
    if parsed.query:
        entropy_features['Query Parameters Entropy'] = f"{calculate_entropy(parsed.query):.2f}"
    if parsed.fragment:
        entropy_features['Fragment Entropy'] = f"{calculate_entropy(parsed.fragment):.2f}"
    
    # Security risk assessment
    risks = []
    
    # Domain-based risks
    if domain_features['Domain Age (days)'] == "Unknown":
        risks.append("Domain age information unavailable - potential risk")
    elif isinstance(domain_features['Domain Age (days)'], int) and domain_features['Domain Age (days)'] < 30:
        risks.append("New domain (less than 30 days old) - potential risk")
    
    if domain_features['Registration Status'] == "Unregistered":
        risks.append("Domain appears to be unregistered - high risk")
    
    if domain_features['Number of Dots'] > 2:
        risks.append("Multiple subdomains detected - potential risk")
    
    if domain_features['Country Code'] in malicious_country_codes:
        risks.append(f"Domain registered in potentially malicious country ({domain_features['Country Code']}) - increased risk")
    
    if domain_features['Top Level Domain'] in suspicious_tlds:
        risks.append(f"Suspicious top-level domain detected ({domain_features['Top Level Domain']}) - potential risk")
    
    if len(domain_features['Server Section']) > 20:
        risks.append("Long server section detected - potential risk of domain impersonation")
    
    if "impersonation" in domain_features['Potential Brand Impersonation'].lower():
        risks.append(domain_features['Potential Brand Impersonation'])
    
    # Path-based risks
    if path_features['Suspicious Extensions'] == "Yes":
        risks.append("Contains suspicious file extensions - potential risk")
    
    if path_features['Number of Parameters'] > 3:
        risks.append("Multiple URL parameters detected - potential risk")
    
    # Lexical-based risks
    if lexical_features['Suspicious Terms Count'] > 0:
        risks.append("Contains suspicious terms - potential risk")
    
    if float(lexical_features['Special Character Ratio'].strip('%')) / 100 > 0.3:
        risks.append("High ratio of special characters - potential risk")
    
    # Entropy-based risks
    try:
        if float(entropy_features['Full URL Entropy']) > 4.5:
            risks.append("High URL entropy detected - potential obfuscation")
        if float(entropy_features['Domain Entropy']) > 4.0:
            risks.append("High domain entropy detected - potential malicious domain")
    except Exception:
        pass
    
    if not risks:
        risks.append("No significant security risks detected")
    
    # Build and return the result dictionary
    result = {
        "Analyzing URL": url,
        "Domain Analysis": domain_features,
        "Path Analysis": path_features,
        "Lexical Analysis": lexical_features,
        "Entropy Analysis": entropy_features,
        "Security Assessment": risks
    }
    
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
