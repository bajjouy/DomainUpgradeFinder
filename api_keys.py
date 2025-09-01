"""
API key management for Serper.dev integration
"""
import os
from typing import Optional

def get_working_serper_key() -> Optional[str]:
    """
    Get a working Serper API key using the existing API rotation system
    
    Returns:
        str: A valid Serper API key, or None if not found
    """
    try:
        # Use the existing API rotation system for best key selection
        from api_rotation import APIRotationManager
        from models import db
        
        # Initialize the API rotation manager
        api_manager = APIRotationManager()
        
        # Get the API key with highest credits
        api_key = api_manager.get_next_api_key()
        
        if api_key:
            print(f"🔑 Using API key '{api_key.key_name}' with {api_key.remaining_credits} credits")
            return api_key.key_value
        else:
            print("❌ No active API keys available in rotation system")
            return None
            
    except Exception as e:
        print(f"⚠️ Error accessing API rotation system: {str(e)}")
        
        # Fallback to environment variable
        api_key = os.environ.get('SERPER_API_KEY')
        if api_key:
            print("🔄 Using fallback environment API key")
            return api_key
        
        print("❌ No API keys available")
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