    #routes/message_scan.py
"""
Documentation:

Request:
    Method: POST
    Endpoint: /message_scan 
    Parameters: None required
    Headers: None required

Body:
    Format: JSON
    Example body:
    {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "message": "Hello, please check this message for safety"
    }

Response:
    Format: JSON
    Example response:
    {
        "status": "success",
        "data": {
            "result": "safe",
            "reason": "Message appears legitimate with no suspicious elements"
        }
    }
    Note: Result will be either "safe" or "malicious"

Example curl command:
    curl -X POST http://localhost:5000/message_scan \
         -H "Content-Type: application/json" \
         -d '{"token": "eyJhbGciOiJIUzI1NiIsIn....", "message": "Hello, please check this message for safety"}'.

Notes:
- The token must be valid (obtained from /get_token endpoint)
- Message cannot be empty
- Result indicates if the message content is considered malicious or safe

"""
from flask import Blueprint, request, jsonify
from utils.token_validator import validate_token
import os
import requests

message_scan_blueprint = Blueprint('message_scan', __name__)

def scan_message(message):
    """
    Uses Mistral 7B via OpenRouter to classify an email as 'Phishing' or 'Safe' 
    and provide a logical explanation (50 words).
    
    Args:
        message (str): The email/message content to analyze.
    
    Returns:
        dict: Contains classification ('Phishing' or 'Safe') and explanation.
    """
    print(f"[ LOG (message_scan) ]: Scanning message: {message}")
    
    API_KEY = os.getenv("OPENROUTER_API_KEY")
    if not API_KEY:
        print(f"[ LOG (message_scan) ]: No API key found")
        return {"result": "error", "reason": "No API key found"}

    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    data = {
        "model": "mistralai/mistral-7b-instruct",
        "messages": [
            {"role": "system", "content": (
                "You analyze emails for phishing. Flag only clear red flags: urgency, suspicious links, "
                "requests for sensitive data, or poor grammar. Otherwise, classify as 'Safe'. "
                "Give a 50-word objective explanation."
            )},
            {"role": "user", "content": f"Analyze this message:\n\n{message}"}
        ],
        "temperature": 0.1
    }


    try:
        response = requests.post(url, headers=headers, json=data)
        
        if response.status_code == 200:
            ai_response = response.json()["choices"][0]["message"]["content"].strip()
            # Parse AI response to extract result and reason
            if "Phishing" in ai_response:
                result = "malicious"
            else:
                result = "safe"
            return {"result": result, "reason": ai_response}
        else:
            print(f"[ LOG (message_scan) ]: API Error: {response.status_code} - {response.text}")
            return {"result": "error", "reason": f"API error: {response.status_code}"}
    except Exception as e:
        print(f"[ LOG (message_scan) ]: Request Error: {str(e)}")
        return {"result": "error", "reason": "Request failed"}

@message_scan_blueprint.route('/message_scan', methods=['POST'])
def message_scan():
    try:
        data = request.get_json()
        print(f"[ LOG (message_scan) ]: Got Data: {data}")

        if not data:
            print(f"[ LOG (message_scan) ]: No JSON data provided")
            response = {
                'status': 'error',
                'data': {
                    'result': 'error',
                    'reason': 'No JSON data provided'
                }
            }
            return jsonify(response), 400

        if 'token' not in data or 'message' not in data:
            print(f"[ LOG (message_scan) ]: Token or message were not found in data")
            response = {
                'status': 'error',
                'data': {
                    'result': 'error',
                    'reason': 'Token and message are required'
                }
            }
            return jsonify(response), 400
        
        if not validate_token(data['token']):
            print(f"[ LOG (message_scan) ]: Token is invalid")
            response = {
                'status': 'error',
                'data': {
                    'result': 'error',
                    'reason': 'Invalid token'
                }
            }
            return jsonify(response), 401
        
        message = data['message']

        if not message or message.strip() == "":
            print(f"[ LOG (message_scan) ]: Message is empty")
            response = {
                'status': 'error',
                'data': {
                    'result': 'error',
                    'reason': 'Message is required'
                }
            }
            return jsonify(response), 400

        if len(message) > 500:
            print(f"[ LOG (message_scan) ]: Message exceeds 500 characters")
            response = {
                'status': 'error',
                'data': {
                    'result': 'error',
                    'reason': 'Message must not exceed 100 characters'
                }
            }
            return jsonify(response), 400
        
        scan_result = scan_message(message)
        
        print(f"[ LOG (message_scan) ]: Scan result: {scan_result}")
        response = {
            'status': 'success',
            'data': scan_result
        }
        return jsonify(response)
    
    except Exception as e:
        print(f"[ LOG (message_scan) ]: Error: {e}")
        response = {
            'status': 'error',
            'data': {
                'result': 'error',
                'reason': 'Internal server error'
            }
        }
        return jsonify(response), 500
