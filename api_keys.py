"""
API key management for Serper.dev integration
"""
import os
from typing import Optional

def get_working_serper_key() -> Optional[str]:
    """
    Get a working Serper API key from environment variables or configuration
    
    Returns:
        str: A valid Serper API key, or None if not found
    """
    # Try to get from environment variable first
    api_key = os.environ.get('SERPER_API_KEY')
    if api_key:
        return api_key
    
    # List of potential API keys (you can add your keys here)
    potential_keys = [
        # Add your Serper API keys here
        "your_serper_api_key_here",
    ]
    
    # Return the first available key (you might want to add validation logic here)
    for key in potential_keys:
        if key and key != "your_serper_api_key_here":
            return key
    
    # If no key found, return None
    return None

def validate_serper_key(api_key: str) -> bool:
    """
    Validate if a Serper API key is working
    
    Args:
        api_key: The API key to validate
        
    Returns:
        bool: True if key is valid, False otherwise
    """
    try:
        from serper_api_utils import check_serper_credits
        result = check_serper_credits(api_key)
        return result.get('error') is None and result.get('credits_left', 0) > 0
    except:
        return False