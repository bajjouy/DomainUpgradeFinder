"""
Security utilities for input validation and protection
"""
import re
import html
from typing import Optional, List, Dict, Any
from flask import request, abort, flash, current_app
from functools import wraps
import logging

logger = logging.getLogger(__name__)

# Input validation patterns
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$')
SAFE_STRING_PATTERN = re.compile(r'^[a-zA-Z0-9\s\-_.,!?@#$%&*+=<>(){}\[\]|\\:;"\'/~`^]+$')

def validate_email(email: str) -> bool:
    """Validate email format"""
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_PATTERN.match(email.strip()))

def validate_domain(domain: str) -> bool:
    """Validate domain format"""
    if not domain or len(domain) > 253:
        return False
    domain = domain.strip().lower()
    return bool(DOMAIN_PATTERN.match(domain))

def validate_safe_string(text: str, max_length: int = 1000) -> bool:
    """Validate string contains only safe characters"""
    if not text or len(text) > max_length:
        return False
    return bool(SAFE_STRING_PATTERN.match(text.strip()))

def sanitize_input(text: str) -> str:
    """Sanitize user input by escaping HTML and removing dangerous characters"""
    if not text:
        return ""
    
    # Strip whitespace and escape HTML
    sanitized = html.escape(text.strip())
    
    # Remove null bytes and other control characters
    sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\n\r\t')
    
    return sanitized

def validate_search_keywords(keywords: str) -> tuple[bool, str]:
    """Validate search keywords input"""
    if not keywords:
        return False, "Keywords cannot be empty"
    
    keywords = keywords.strip()
    
    if len(keywords) > 5000:
        return False, "Keywords too long (maximum 5000 characters)"
    
    if len(keywords) < 2:
        return False, "Keywords too short (minimum 2 characters)"
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'<script',
        r'javascript:',
        r'data:',
        r'vbscript:',
        r'onload=',
        r'onerror=',
        r'onclick='
    ]
    
    keywords_lower = keywords.lower()
    for pattern in suspicious_patterns:
        if re.search(pattern, keywords_lower):
            return False, "Invalid characters detected in keywords"
    
    return True, ""

def validate_coin_amount(amount: Any) -> tuple[bool, str]:
    """Validate coin amount for transactions"""
    try:
        amount = int(amount)
    except (ValueError, TypeError):
        return False, "Invalid coin amount format"
    
    if amount <= 0:
        return False, "Coin amount must be positive"
    
    if amount > 100000:
        return False, "Coin amount too large (maximum 100,000)"
    
    return True, ""

def validate_api_key(api_key: str) -> tuple[bool, str]:
    """Validate API key format"""
    if not api_key:
        return False, "API key cannot be empty"
    
    api_key = api_key.strip()
    
    if len(api_key) < 10 or len(api_key) > 200:
        return False, "Invalid API key length"
    
    # Basic format check for common API key patterns
    if not re.match(r'^[a-zA-Z0-9\-_]+$', api_key):
        return False, "API key contains invalid characters"
    
    return True, ""

def rate_limit_exceeded():
    """Handle rate limit exceeded"""
    logger.warning(f"Rate limit exceeded for IP: {request.remote_addr}")
    abort(429, description="Too many requests. Please try again later.")

def validate_form_data(form_data: Dict[str, Any], validation_rules: Dict[str, Dict]) -> tuple[bool, List[str]]:
    """
    Validate form data against rules
    
    Args:
        form_data: Dictionary of form field values
        validation_rules: Dictionary of validation rules per field
            Example: {
                'email': {'required': True, 'type': 'email'},
                'keywords': {'required': True, 'type': 'search_keywords'},
                'amount': {'required': True, 'type': 'coin_amount'}
            }
    
    Returns:
        (is_valid, list_of_errors)
    """
    errors = []
    
    for field_name, rules in validation_rules.items():
        value = form_data.get(field_name, '')
        
        # Check required fields
        if rules.get('required', False) and not value:
            errors.append(f"{field_name.title()} is required")
            continue
        
        # Skip validation for empty optional fields
        if not value and not rules.get('required', False):
            continue
        
        # Type-specific validation
        field_type = rules.get('type')
        
        if field_type == 'email':
            if not validate_email(value):
                errors.append(f"Invalid email format for {field_name}")
        
        elif field_type == 'domain':
            if not validate_domain(value):
                errors.append(f"Invalid domain format for {field_name}")
        
        elif field_type == 'search_keywords':
            is_valid, error_msg = validate_search_keywords(value)
            if not is_valid:
                errors.append(f"{field_name.title()}: {error_msg}")
        
        elif field_type == 'coin_amount':
            is_valid, error_msg = validate_coin_amount(value)
            if not is_valid:
                errors.append(f"{field_name.title()}: {error_msg}")
        
        elif field_type == 'api_key':
            is_valid, error_msg = validate_api_key(value)
            if not is_valid:
                errors.append(f"{field_name.title()}: {error_msg}")
        
        elif field_type == 'safe_string':
            max_length = rules.get('max_length', 1000)
            if not validate_safe_string(value, max_length):
                errors.append(f"{field_name.title()} contains invalid characters or is too long")
    
    return len(errors) == 0, errors

def secure_headers(f):
    """Add security headers to responses"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        
        # Add security headers
        if hasattr(response, 'headers'):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            
        return response
    return decorated_function

def log_security_event(event_type: str, details: str, user_id: Optional[int] = None):
    """Log security-related events"""
    from models import SystemLog, db
    from datetime import datetime
    
    try:
        log = SystemLog()
        log.level = 'warning'
        log.message = f"SECURITY: {event_type} - {details} (IP: {request.remote_addr})"
        log.user_id = user_id
        db.session.add(log)
        db.session.commit()
        
        logger.warning(f"Security event: {event_type} - {details}")
    except Exception as e:
        logger.error(f"Failed to log security event: {str(e)}")