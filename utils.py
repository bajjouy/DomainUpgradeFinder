import re
from typing import List

def validate_domain(domain: str) -> bool:
    """
    Validate if a string is a valid domain name
    """
    if not domain or not isinstance(domain, str):
        return False
    
    domain = domain.strip().lower()
    
    # Basic domain regex pattern
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    
    return bool(re.match(pattern, domain))

def parse_domain_list(text: str) -> List[str]:
    """
    Parse a text input containing domain names (one per line or comma-separated)
    """
    if not text:
        return []
    
    # Split by newlines first
    lines = text.strip().split('\n')
    
    domains = []
    for line in lines:
        # Also split by commas in case multiple domains are on one line
        line_domains = [d.strip() for d in line.split(',') if d.strip()]
        domains.extend(line_domains)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_domains = []
    for domain in domains:
        domain_lower = domain.lower()
        if domain_lower not in seen:
            seen.add(domain_lower)
            unique_domains.append(domain)
    
    return unique_domains

def clean_domain_name(domain: str) -> str:
    """
    Clean domain name by removing protocol and www prefix
    """
    if not domain:
        return ""
    
    domain = domain.strip().lower()
    
    # Remove protocol
    if domain.startswith('http://'):
        domain = domain[7:]
    elif domain.startswith('https://'):
        domain = domain[8:]
    
    # Remove www prefix
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Remove trailing slash
    if domain.endswith('/'):
        domain = domain[:-1]
    
    return domain

def format_keywords(keywords: List[str]) -> str:
    """
    Format keywords list into a readable string
    """
    if not keywords:
        return ""
    
    return ', '.join(keywords)

def calculate_match_percentage(matched: int, total: int) -> float:
    """
    Calculate match percentage
    """
    if total == 0:
        return 0.0
    
    return round((matched / total) * 100, 1)
