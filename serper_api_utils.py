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
            # Serper API returns 'balance' instead of 'credits_left'
            balance = data.get('balance', 0)
            # Estimate total based on common Serper plans
            if balance <= 2500:
                estimated_total = 2500  # Free plan
            elif balance <= 10000:
                estimated_total = max(balance + 500, 5000)  # Small paid plan
            else:
                estimated_total = balance + 1000  # Larger paid plan
            
            return {
                'credits_left': balance,
                'total_credits': estimated_total,
                'plan': 'Serper Free' if balance <= 2500 else 'Serper Paid',
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
        'total_live_remaining': sum(k['credits_left'] or 0 for k in key_details),
        'total_live_credits': total_live_credits,
        'total_live_used': total_live_used,
        'key_details': key_details,
        'errors': errors,
        'live_data_available': len([k for k in key_details if k.get('is_live', False)]) > 0
    }

def search_google_web_serper(api_key: str, query: str, location: str = None, num_results: int = 20, start: int = 0) -> Dict:
    """
    Search Google web results and extract business data from the results
    
    Args:
        api_key: Serper API key
        query: Business search query (e.g., "restaurants", "coffee shops")
        location: Location to search in (e.g., "New York, NY", "Los Angeles, CA") 
        num_results: Number of results to return (default 20, max 100)
        start: Starting index for pagination (default 0)
    
    Returns:
        Dict with 'businesses', 'error', 'credits_used' keys
    """
    try:
        url = "https://google.serper.dev/search"
        headers = {
            'X-API-KEY': api_key,
            'Content-Type': 'application/json'
        }
        
        # For keyword matching - avoid quotes for sensitive terms to prevent API restrictions
        # Instead of exact quotes, use the query directly to avoid "Query not allowed" errors
        search_query = query
        
        payload = {
            'q': search_query,
            'num': min(num_results, 100),  # Cap at 100 per API limits
            'gl': 'us',  # Country code
            'hl': 'en'   # Language
        }
        
        # Add pagination start parameter if provided
        if start > 0:
            payload['start'] = start
        
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract businesses from organic results
            businesses = []
            organic_results = data.get('organic', [])
            
            for result in organic_results:
                # For exact keyword searches - use simplified web result extraction
                web_result = _extract_web_result_from_search(result)
                if web_result:
                    businesses.append(web_result)
            
            # Also check knowledge graph for business info
            knowledge_graph = data.get('knowledgeGraph', {})
            if knowledge_graph and _is_business_knowledge_graph(knowledge_graph):
                kg_business = _extract_business_from_knowledge_graph(knowledge_graph, location or '')
                if kg_business:
                    businesses.insert(0, kg_business)  # Put at top since it's most relevant
            
            return {
                'businesses': businesses,
                'total_found': len(businesses),
                'credits_used': 1,  # Serper uses 1 credit per search
                'search_info': data.get('searchParameters', {}),
                'error': None
            }
        else:
            return {
                'businesses': [],
                'total_found': 0,
                'credits_used': 0,
                'error': f"API returned status {response.status_code}: {response.text}"
            }
            
    except requests.exceptions.RequestException as e:
        return {
            'businesses': [],
            'total_found': 0,
            'credits_used': 0,
            'error': f"Network error: {str(e)}"
        }
    except Exception as e:
        return {
            'businesses': [],
            'total_found': 0,
            'credits_used': 0,
            'error': f"Unexpected error: {str(e)}"
        }

def search_places_serper(api_key: str, query: str, location: str = None, num_results: int = 20) -> Dict:
    """
    Search for businesses using Serper.dev Places API
    
    Args:
        api_key: Serper API key
        query: Search query (e.g., "restaurants", "coffee shops")
        location: Location to search in (e.g., "New York, NY", "Los Angeles, CA")
        num_results: Number of results to return (default 20, max 100)
    
    Returns:
        Dict with 'places', 'error', 'credits_used' keys
    """
    try:
        url = "https://google.serper.dev/places"
        headers = {
            'X-API-KEY': api_key,
            'Content-Type': 'application/json'
        }
        
        # Construct search query - combine query with location
        search_query = query
        if location:
            search_query = f"{query} in {location}"
        
        payload = {
            'q': search_query,
            'num': min(num_results, 100),  # Cap at 100 per API limits
            'gl': 'us',  # Country code
            'hl': 'en'   # Language
        }
        
        if location:
            payload['location'] = location
        
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            places = data.get('places', [])
            
            # Standardize place data format
            standardized_places = []
            for place in places:
                # Safely extract business status
                open_info = place.get('open', {})
                if isinstance(open_info, dict):
                    business_status = open_info.get('status', 'UNKNOWN')
                else:
                    # Handle boolean or other types
                    business_status = 'OPEN' if open_info else 'UNKNOWN'
                
                # Safely extract position data  
                position_info = place.get('position', {})
                if isinstance(position_info, dict):
                    latitude = position_info.get('lat')
                    longitude = position_info.get('lng')
                else:
                    latitude = None
                    longitude = None
                
                standardized_place = {
                    'name': place.get('title', ''),
                    'address': place.get('address', ''),
                    'phone': place.get('phoneNumber', ''),
                    'website': place.get('website', ''),
                    'rating': place.get('rating'),
                    'user_ratings_total': place.get('ratingCount'),
                    'price_level': _parse_price_level(place.get('priceRange', '')),
                    'business_status': business_status,
                    'types': place.get('type', '').split(', ') if place.get('type') else [],
                    'latitude': latitude,
                    'longitude': longitude,
                    'place_id': place.get('place_id', ''),
                    'opening_hours': place.get('hours', []),
                    'thumbnail': place.get('imageUrl', ''),
                    'cid': place.get('cid', ''),  # Google's internal place ID
                    'source': 'serper.dev'
                }
                standardized_places.append(standardized_place)
            
            return {
                'places': standardized_places,
                'total_found': len(standardized_places),
                'credits_used': 1,  # Serper uses 1 credit per search
                'search_info': data.get('searchParameters', {}),
                'error': None
            }
        else:
            return {
                'places': [],
                'total_found': 0,
                'credits_used': 0,
                'error': f"API returned status {response.status_code}: {response.text}"
            }
            
    except requests.exceptions.RequestException as e:
        return {
            'places': [],
            'total_found': 0,
            'credits_used': 0,
            'error': f"Network error: {str(e)}"
        }
    except Exception as e:
        return {
            'places': [],
            'total_found': 0,
            'credits_used': 0,
            'error': f"Unexpected error: {str(e)}"
        }

def _extract_web_result_from_search(result: Dict) -> Optional[Dict]:
    """
    Extract URL and title from a Google web search result - simplified for exact keyword matching
    """
    title = result.get('title', '')
    snippet = result.get('snippet', '')
    link = result.get('link', '')
    
    # Skip common non-useful sites for domain research
    non_useful_sites = ['google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'linkedin.com']
    
    # Only filter out obvious non-useful sites
    is_non_useful = any(site in link.lower() for site in non_useful_sites)
    
    if is_non_useful or not link or not title:
        return None
    
    return {
        'name': title.strip(),  # Page title
        'website': link,        # URL
        'description': snippet.strip(),  # Page snippet/description
        'phone': '',           # Not needed for URL/title focus
        'rating': None,        # Not needed for URL/title focus
        'address': '',         # Not needed for URL/title focus
        'user_ratings_total': None,
        'price_level': None,
        'business_status': 'UNKNOWN',
        'types': [],
        'latitude': None,
        'longitude': None,
        'place_id': '',
        'opening_hours': [],
        'source': 'google_web_search'
    }

def _extract_business_from_search_result(result: Dict, location: str) -> Optional[Dict]:
    """
    Extract business information from a Google search result
    """
    import re
    
    title = result.get('title', '')
    snippet = result.get('snippet', '')
    link = result.get('link', '')
    
    # Skip common non-useful sites only (keep filtering minimal)
    non_useful_sites = ['google.com', 'youtube.com', 'facebook.com', 'wikipedia.org']
    
    # Only filter out obvious non-useful sites
    is_non_useful = any(site in link.lower() for site in non_useful_sites)
    
    if is_non_useful:
        return None
    
    # Keep full title as the name
    name = title.strip()
    
    # Extract phone number from snippet
    phone_pattern = r'(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})'
    phone_match = re.search(phone_pattern, snippet)
    phone = phone_match.group(1) if phone_match else ''
    
    # Extract address from snippet
    address_pattern = r'\d+\s+[\w\s,]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Place|Pl)\s*,?\s*[\w\s,]*\d{5}'
    address_match = re.search(address_pattern, snippet, re.IGNORECASE)
    address = address_match.group(0) if address_match else ''
    
    # Extract rating if present
    rating_pattern = r'(\d+(?:\.\d+)?)\s*(?:stars?|★|out of|\/)'
    rating_match = re.search(rating_pattern, snippet, re.IGNORECASE)
    rating = float(rating_match.group(1)) if rating_match else None
    
    return {
        'name': title,  # Full page title
        'website': link,  # URL 
        'description': snippet,  # Page description
        'phone': phone,  # Optional phone if found
        'rating': rating,  # Optional rating if found
        'address': address,  # Optional address if found
        'user_ratings_total': None,
        'price_level': None,
        'business_status': 'UNKNOWN',
        'types': [],
        'latitude': None,
        'longitude': None,
        'place_id': '',
        'opening_hours': [],
        'source': 'google_web_search'
    }

def _extract_business_from_knowledge_graph(kg: Dict, location: str) -> Optional[Dict]:
    """
    Extract business information from Google Knowledge Graph
    """
    if not kg.get('title'):
        return None
        
    # Check for business attributes
    attributes = kg.get('attributes', {})
    
    return {
        'name': kg.get('title', ''),
        'address': attributes.get('Address', ''),
        'phone': attributes.get('Phone', ''),
        'website': kg.get('website', ''),
        'rating': None,
        'user_ratings_total': None,
        'price_level': None,
        'business_status': 'UNKNOWN',
        'types': [kg.get('type', '')] if kg.get('type') else [],
        'latitude': None,
        'longitude': None,
        'place_id': '',
        'opening_hours': [],
        'source': 'knowledge_graph'
    }

def _is_business_knowledge_graph(kg: Dict) -> bool:
    """
    Check if knowledge graph represents a business
    """
    business_types = ['Organization', 'LocalBusiness', 'Restaurant', 'Store', 'Company']
    kg_type = kg.get('type', '')
    return any(btype in kg_type for btype in business_types)

def _parse_price_level(price_range: str) -> Optional[int]:
    """
    Convert price range string to numeric level (0-4)
    
    Args:
        price_range: String like "$", "$$", "$$$", "$$$$" or descriptive text
    
    Returns:
        Integer 0-4 or None if not parseable
    """
    if not price_range:
        return None
    
    # Count dollar signs
    dollar_count = price_range.count('$')
    if dollar_count > 0:
        return min(dollar_count - 1, 4)  # Convert to 0-4 scale
    
    # Handle descriptive text
    price_lower = price_range.lower()
    if 'inexpensive' in price_lower or 'cheap' in price_lower:
        return 1
    elif 'moderate' in price_lower:
        return 2
    elif 'expensive' in price_lower:
        return 3
    elif 'very expensive' in price_lower or 'luxury' in price_lower:
        return 4
    
    return None

def extract_email_from_website(website_url: str) -> Optional[str]:
    """
    Extract email from business website using web scraping
    
    Args:
        website_url: Business website URL
    
    Returns:
        Email address if found, None otherwise
    """
    try:
        if not website_url or not website_url.startswith(('http://', 'https://')):
            return None
        
        import re
        response = requests.get(website_url, timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        if response.status_code == 200:
            # Look for email patterns in the page
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, response.text)
            
            # Filter out common non-business emails
            filtered_emails = [
                email for email in emails 
                if not any(skip in email.lower() for skip in [
                    'noreply', 'no-reply', 'donotreply', 'example.com', 
                    'test.com', 'gmail.com', 'yahoo.com', 'hotmail.com'
                ])
            ]
            
            return filtered_emails[0] if filtered_emails else None
            
    except Exception:
        return None
    
    return None