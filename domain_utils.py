"""
Domain utilities for extracting main domains and filtering duplicates/blacklisted domains
"""
from urllib.parse import urlparse
from typing import List, Dict, Set
import re

def extract_main_domain(url: str) -> str:
    """
    Extract the main domain from a URL, removing subdomains and paths
    
    Examples:
        'https://www.example.com/path' -> 'example.com'
        'https://subdomain.example.com' -> 'example.com'
        'https://shop.example.co.uk' -> 'example.co.uk'
        'example.com' -> 'example.com'
    """
    if not url:
        return ''
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return ''
        
        # Remove www prefix
        if hostname.startswith('www.'):
            hostname = hostname[4:]
        
        # For common country code domains, keep the last 3 parts
        # For regular domains, keep the last 2 parts
        parts = hostname.split('.')
        
        if len(parts) >= 3:
            # Check for common country code TLDs
            if parts[-1] in ['uk', 'au', 'ca', 'de', 'fr', 'jp', 'in', 'br']:
                # Keep domain.co.uk, domain.com.au, etc.
                return '.'.join(parts[-3:]) if len(parts) >= 3 else hostname
            else:
                # Regular domain: keep last 2 parts (domain.com)
                return '.'.join(parts[-2:])
        
        return hostname
        
    except Exception:
        # Fallback: clean the input as much as possible
        cleaned = re.sub(r'^https?://', '', url)
        cleaned = re.sub(r'^www\.', '', cleaned)
        cleaned = re.sub(r'/.*$', '', cleaned)
        return cleaned.lower()

def filter_unique_domains(businesses: List[Dict], blacklisted_domains: Set[str] = None) -> List[Dict]:
    """
    Filter businesses to keep only unique domains and remove blacklisted domains
    
    Args:
        businesses: List of business dictionaries with URL/website fields
        blacklisted_domains: Set of blacklisted domain names to exclude
    
    Returns:
        Filtered list with unique domains only
    """
    if blacklisted_domains is None:
        blacklisted_domains = set()
    
    seen_domains = set()
    filtered_businesses = []
    
    for business in businesses:
        # Get URL from various possible field names
        url = business.get('URL') or business.get('website') or business.get('url') or ''
        
        if not url:
            continue
            
        main_domain = extract_main_domain(url)
        
        if not main_domain:
            continue
            
        # Skip if domain is blacklisted
        if main_domain in blacklisted_domains:
            continue
            
        # Skip if we've already seen this domain
        if main_domain in seen_domains:
            continue
            
        # Add to seen domains and include in results
        seen_domains.add(main_domain)
        
        # Add extracted domain info to business data
        business['main_domain'] = main_domain
        business['is_unique_domain'] = True
        
        filtered_businesses.append(business)
    
    return filtered_businesses

def get_domain_statistics(businesses: List[Dict]) -> Dict:
    """
    Get statistics about domains in the business list
    
    Returns:
        Dict with domain counts and duplicates info
    """
    domain_counts = {}
    total_businesses = len(businesses)
    
    for business in businesses:
        url = business.get('URL') or business.get('website') or business.get('url') or ''
        if url:
            domain = extract_main_domain(url)
            if domain:
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
    
    duplicates = {domain: count for domain, count in domain_counts.items() if count > 1}
    unique_domains = len(domain_counts)
    
    return {
        'total_businesses': total_businesses,
        'unique_domains': unique_domains,
        'duplicate_domains': duplicates,
        'domain_counts': domain_counts,
        'deduplication_ratio': unique_domains / total_businesses if total_businesses > 0 else 0
    }

def is_valid_business_domain(domain: str) -> bool:
    """
    Check if a domain is likely to be a valid business domain
    Filters out common non-business domains
    """
    if not domain:
        return False
    
    # Common non-business domains to filter out
    non_business_domains = {
        'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 
        'youtube.com', 'google.com', 'wikipedia.org', 'amazon.com',
        'ebay.com', 'craigslist.org', 'yelp.com', 'foursquare.com',
        'pinterest.com', 'reddit.com', 'tiktok.com', 'snapchat.com',
        'telegram.me', 'whatsapp.com', 'messenger.com', 'skype.com'
    }
    
    return domain.lower() not in non_business_domains

def add_common_blacklist_domains() -> List[str]:
    """
    Return a list of common domains that should typically be blacklisted
    for business searches
    """
    return [
        'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
        'youtube.com', 'google.com', 'wikipedia.org', 'amazon.com',
        'ebay.com', 'craigslist.org', 'yelp.com', 'foursquare.com',
        'pinterest.com', 'reddit.com', 'tiktok.com', 'snapchat.com',
        'telegram.me', 'whatsapp.com', 'tripadvisor.com', 'booking.com',
        'expedia.com', 'hotels.com', 'airbnb.com', 'uber.com',
        'lyft.com', 'doordash.com', 'grubhub.com', 'postmates.com'
    ]