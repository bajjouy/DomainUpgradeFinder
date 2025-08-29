"""
Utility functions for Serper API credit checking and management
"""
import requests
from typing import Dict, Optional
import os

def check_serper_credits(api_key: str) -> Dict:
    """
    Check remaining credits for a Serper API key
    
    Returns:
        Dict with 'credits_left', 'total_credits', 'error' keys
    """
    try:
        # Serper API endpoint for checking credits
        url = "https://google.serper.dev/account"
        headers = {
            'X-API-KEY': api_key,
            'Content-Type': 'application/json'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'credits_left': data.get('credits_left', 0),
                'total_credits': data.get('total_credits', 0),
                'plan': data.get('plan', 'Unknown'),
                'error': None
            }
        else:
            return {
                'credits_left': 0,
                'total_credits': 0,
                'plan': 'Unknown',
                'error': f"API returned status {response.status_code}"
            }
            
    except requests.exceptions.RequestException as e:
        return {
            'credits_left': 0,
            'total_credits': 0,
            'plan': 'Unknown', 
            'error': f"Network error: {str(e)}"
        }
    except Exception as e:
        return {
            'credits_left': 0,
            'total_credits': 0,
            'plan': 'Unknown',
            'error': f"Unexpected error: {str(e)}"
        }

def bulk_check_all_keys(api_keys: list) -> Dict:
    """
    Check credits for multiple API keys
    
    Args:
        api_keys: List of APIKey model objects
    
    Returns:
        Dict with aggregated credit information
    """
    total_live_credits = 0
    total_live_used = 0
    key_details = []
    errors = []
    
    for api_key in api_keys:
        if api_key.status.value == 'ACTIVE':
            result = check_serper_credits(api_key.key_value)
            
            if result['error']:
                errors.append(f"{api_key.key_name}: {result['error']}")
                # Use database fallback values
                key_details.append({
                    'name': api_key.key_name,
                    'credits_left': api_key.remaining_credits,
                    'total_credits': api_key.total_credits,
                    'plan': 'Database fallback',
                    'is_live': False
                })
            else:
                key_details.append({
                    'name': api_key.key_name,
                    'credits_left': result['credits_left'],
                    'total_credits': result['total_credits'],
                    'plan': result['plan'],
                    'is_live': True
                })
                total_live_credits += result['total_credits']
                total_live_used += (result['total_credits'] - result['credits_left'])
    
    return {
        'total_live_remaining': sum(k['credits_left'] for k in key_details),
        'total_live_credits': total_live_credits,
        'total_live_used': total_live_used,
        'key_details': key_details,
        'errors': errors,
        'live_data_available': len([k for k in key_details if k['is_live']]) > 0
    }