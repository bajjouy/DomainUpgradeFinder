import requests
import re
from urllib.parse import urlparse
import time
import json
from typing import List, Dict, Optional, Tuple
from models import APIKey, SystemLog, APIKeyStatus, db
from datetime import datetime, timedelta
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class APIRotationManager:
    def __init__(self):
        self.base_url = "https://google.serper.dev/search"
        self._current_key_index = 0
        self._batch_size = 5  # Maximum concurrent searches
        self._rate_limit_delay = 0.2  # Delay between batches in seconds
    
    def get_active_api_keys(self) -> List[APIKey]:
        """Get all active API keys ordered by priority (highest credits first)"""
        active_keys = APIKey.query.filter_by(status=APIKeyStatus.ACTIVE).all()
        # Sort by priority score (highest first) - this prioritizes keys with more credits
        return sorted(active_keys, key=lambda k: k.priority_score, reverse=True)
    
    def get_next_api_key(self) -> Optional[APIKey]:
        """Get the API key with highest credits (always prioritize high-credit keys)"""
        active_keys = self.get_active_api_keys()
        
        if not active_keys:
            self._log_system("error", "No active API keys available")
            return None
        
        # Always return the key with highest credits (first in sorted list)
        # This ensures we always use the API key with the most remaining credits
        key = active_keys[0]
        print(f"DEBUG: Selected API key with {key.remaining_credits} credits (highest available)")
        
        return key
    
    def search_google_bulk(self, queries: List[str], max_results: int = 10, progress_callback=None, flask_app=None) -> List[Tuple[str, List[Dict], Optional[str]]]:
        """
        Perform bulk searches with PARALLEL processing (10 simultaneous searches)
        Returns: List of (query, results, api_key_used) tuples
        """
        print(f"DEBUG: Starting PARALLEL bulk search with {len(queries)} queries")
        results = []
        total_queries = len(queries)
        
        if total_queries == 0:
            print("DEBUG: No queries to process")
            return results
        
        completed_count = 0
        max_workers = 10  # Run 10 searches simultaneously
        
        def search_single_query(query):
            """Single query search function for parallel execution with Flask context"""
            try:
                if flask_app:
                    # Each thread needs its own application context for database access
                    with flask_app.app_context():
                        print(f"DEBUG: PARALLEL search starting for query: '{query}'")
                        search_results, api_key_used = self.search_google_with_rotation(query, max_results)
                        print(f"DEBUG: PARALLEL search completed for query: '{query}' - got {len(search_results)} results")
                        return (query, search_results, api_key_used)
                else:
                    print(f"DEBUG: PARALLEL search starting for query: '{query}' (no Flask app context)")
                    search_results, api_key_used = self.search_google_with_rotation(query, max_results)
                    print(f"DEBUG: PARALLEL search completed for query: '{query}' - got {len(search_results)} results")
                    return (query, search_results, api_key_used)
            except Exception as e:
                print(f"DEBUG: PARALLEL search error for query '{query}': {str(e)}")
                if flask_app:
                    with flask_app.app_context():
                        self._log_system("error", f"Parallel bulk search failed for query '{query}': {str(e)}")
                return (query, [], None)
        
        # Execute searches in parallel with ThreadPoolExecutor
        print(f"DEBUG: Starting ThreadPoolExecutor with {max_workers} workers")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all queries for parallel execution
            future_to_query = {executor.submit(search_single_query, query): query for query in queries}
            
            # Process completed searches as they finish
            for future in as_completed(future_to_query):
                try:
                    result = future.result()
                    results.append(result)
                    completed_count += 1
                    
                    # Progress callback
                    if progress_callback:
                        progress = (completed_count / total_queries) * 100
                        print(f"DEBUG: PARALLEL progress: {progress:.1f}% ({completed_count}/{total_queries}) completed")
                        progress_callback(progress, result[0])  # result[0] is the query
                        
                except Exception as e:
                    query = future_to_query[future]
                    print(f"DEBUG: PARALLEL search exception for query '{query}': {str(e)}")
                    results.append((query, [], None))
                    completed_count += 1
        
        print(f"DEBUG: PARALLEL bulk search completed with {len(results)} total results")
        return results
    
    def search_google_with_rotation(self, query: str, max_results: int = 10, max_retries: Optional[int] = None) -> Tuple[List[Dict], Optional[str]]:
        """
        Search Google with API key rotation and failover with smart result count reduction
        Returns: (results, api_key_used)
        """
        active_keys = self.get_active_api_keys()
        
        if not active_keys:
            raise Exception("No active API keys available")
        
        # If max_retries not specified, try all available keys
        if max_retries is None:
            max_retries = len(active_keys)
        
        last_error = None
        attempts = 0
        current_max_results = max_results
        
        # Try with progressively smaller result counts if "Query not allowed"
        result_fallbacks = [max_results, 50, 30, 20, 10] if max_results > 10 else [max_results]
        
        for fallback_results in result_fallbacks:
            current_max_results = fallback_results
            
            for attempt in range(min(max_retries, len(active_keys))):
                api_key = self.get_next_api_key()
                
                if not api_key:
                    break
                
                try:
                    results = self._search_with_key(query, api_key, current_max_results)
                    
                    # Record successful usage
                    api_key.record_usage(success=True)
                    db.session.commit()
                    
                    if current_max_results < max_results:
                        self._log_system("info", f"Successful search with reduced results ({current_max_results}) for query: {query}")
                    else:
                        self._log_system("info", f"Successful search with API key: {api_key.key_name}")
                    
                    return results, api_key.key_name
                    
                except Exception as e:
                    last_error = str(e)
                    attempts += 1
                    
                    # Record failed usage
                    api_key.record_usage(success=False)
                    
                    # Check if we should deactivate this key
                    if self._should_deactivate_key(api_key, str(e)):
                        api_key.status = APIKeyStatus.FAILED
                        self._log_system("warning", f"Deactivated API key {api_key.key_name}: {str(e)}")
                    
                    db.session.commit()
                    
                    self._log_system("warning", f"API key {api_key.key_name} failed with {current_max_results} results: {str(e)}")
                    
                    # If it's a "Query not allowed" error, try with fewer results first
                    if "Query not allowed" in str(e):
                        if current_max_results > 10:
                            self._log_system("info", f"Trying with fewer results due to query restriction")
                            break  # Break to try next fallback count
                        else:
                            # If we're already at minimum results and still getting "Query not allowed"
                            # This query is fundamentally blocked, skip it entirely
                            self._log_system("warning", f"Query '{query}' is blocked by content policy, skipping")
                            return [], None
                    
                    # Wait before trying next key (reduced for bulk processing)
                    time.sleep(0.1)
            
            # If we got "Query not allowed", try next fallback count
            if last_error and "Query not allowed" in last_error:
                if current_max_results > 10:
                    continue  # Try with fewer results
                else:
                    # Query is fundamentally blocked, return empty results
                    self._log_system("warning", f"Query '{query}' is blocked by content policy after all attempts")
                    return [], None
            else:
                break  # If other error, stop trying
        
        # All keys and fallbacks failed
        error_msg = f"All API keys failed after {attempts} attempts. Last error: {last_error}"
        self._log_system("error", error_msg)
        raise Exception(error_msg)
    
    def _search_with_key(self, query: str, api_key: APIKey, max_results: int) -> List[Dict]:
        """Search with a specific API key"""
        headers = {
            'X-API-KEY': api_key.key_value,
            'Content-Type': 'application/json'
        }
        
        payload = {
            'q': query,  # Search without quotes to avoid API restrictions
            'num': max_results,
            'gl': 'us',
            'hl': 'en'
        }
        
        response = requests.post(self.base_url, headers=headers, json=payload, timeout=30)
        
        # Handle different error types
        if response.status_code == 429:
            raise Exception("Rate limit exceeded")
        elif response.status_code == 401:
            raise Exception("Invalid API key")
        elif response.status_code == 400:
            # Parse the error message for more specific handling
            try:
                error_data = response.json()
                error_message = error_data.get('message', response.text)
                if 'Query not allowed' in error_message:
                    raise Exception(f"Query not allowed. Contact support.")
                else:
                    raise Exception(f"HTTP 400: {error_message}")
            except (ValueError, KeyError):
                raise Exception(f"HTTP 400: {response.text}")
        elif response.status_code >= 400:
            raise Exception(f"HTTP {response.status_code}: {response.text}")
        
        response.raise_for_status()
        data = response.json()
        
        if 'message' in data and 'error' in data.get('message', '').lower():
            raise Exception(f"Serper API Error: {data['message']}")
        
        results = []
        organic_results = data.get('organic', [])
        
        for i, result in enumerate(organic_results[:max_results]):
            link = result.get('link', '')
            title = result.get('title', '')
            snippet = result.get('snippet', '')
            
            if link:
                results.append({
                    'url': link,
                    'title': title,
                    'snippet': snippet,
                    'rank': i + 1
                })
        
        return results
    
    def _should_deactivate_key(self, api_key: APIKey, error_message: str) -> bool:
        """Determine if an API key should be deactivated based on the error"""
        deactivate_errors = [
            'invalid api key',
            'authentication failed',
            'quota exceeded',
            'subscription expired',
            'account suspended'
        ]
        
        error_lower = error_message.lower()
        return any(err in error_lower for err in deactivate_errors)
    
    def _log_system(self, level: str, message: str, api_key_id: Optional[int] = None):
        """Log system events"""
        log = SystemLog()
        log.level = level
        log.message = message
        log.api_key_id = api_key_id
        db.session.add(log)
        
        # Also log to Python logger
        logger = logging.getLogger(__name__)
        if level == 'error':
            logger.error(message)
        elif level == 'warning':
            logger.warning(message)
        else:
            logger.info(message)

class EnhancedDomainAnalyzer:
    """Enhanced domain analyzer with API rotation support"""
    
    def __init__(self):
        self.api_manager = APIRotationManager()
    
    def parse_keywords(self, keywords_text: str) -> List[str]:
        """Parse keywords from text input and clean them"""
        if not keywords_text:
            return []
        
        # Split keywords by spaces and clean them
        keywords = [word.strip().lower() for word in keywords_text.split() if word.strip()]
        
        # Remove common words that don't add value
        stop_words = {'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        keywords = [word for word in keywords if word not in stop_words and len(word) > 1]
        
        return keywords
    
    def extract_domain_from_url(self, url: str) -> str:
        """Extract domain name from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain
        except:
            return ""
    
    def check_keyword_match(self, my_keywords: List[str], competitor_domain: str) -> Dict:
        """Check if all keywords from my domain are present in competitor domain"""
        # Remove TLD from competitor domain
        competitor_clean = re.sub(r'\\.(com|net|org|edu|gov|mil|int|biz|info|name|pro|aero|coop|museum)$', '', competitor_domain.lower())
        
        # Create a searchable string from competitor domain
        competitor_text = re.sub(r'[-_.]', ' ', competitor_clean).lower()
        competitor_text = re.sub(r'([a-z])([A-Z])', r'\\1 \\2', competitor_text)
        
        matches = []
        for keyword in my_keywords:
            if keyword in competitor_text:
                matches.append(keyword)
        
        return {
            'matches': matches,
            'match_count': len(matches),
            'total_keywords': len(my_keywords),
            'is_upgrade': len(matches) == len(my_keywords) and len(matches) > 0
        }
    
    def analyze_keywords(self, keywords_text: str, max_results: int = 10) -> Tuple[List[Dict], Optional[str]]:
        """
        Search keywords and return ALL search results with full data (no filtering)
        Returns: (all_search_results, api_key_used)
        """
        start_time = time.time()
        
        try:
            # Check cache first for faster results
            from cache_manager import cache_manager
            cached_results = cache_manager.search_cache.get_search_results(keywords_text, max_results)
            if cached_results:
                logger.info(f"Cache HIT: Serving cached analysis for '{keywords_text[:50]}...'")
                return cached_results['results'], cached_results.get('api_key_used', 'cached')
            
            # Parse keywords
            keywords = self.parse_keywords(keywords_text)
            
            if not keywords:
                return [], None
            
            # Create search query
            query = ' '.join(keywords)
            
            # Search Google with API rotation
            search_results, api_key_used = self.api_manager.search_google_with_rotation(query, max_results)
            
            if not search_results:
                return [], api_key_used
            
            # Return ALL search results with full data (no filtering)
            all_results = []
            
            for result in search_results:
                competitor_domain = self.extract_domain_from_url(result['url'])
                
                # Check keyword match for analysis (but don't filter based on it)
                match_result = self.check_keyword_match(keywords, competitor_domain) if competitor_domain else {
                    'matches': [], 'match_count': 0, 'total_keywords': len(keywords), 'is_upgrade': False
                }
                
                # Include ALL results with full data - no filtering
                all_results.append({
                    'Keywords': keywords_text,
                    'Competitor_Domain': competitor_domain or 'N/A',
                    'Competitor_URL': result['url'],
                    'Search_Keywords': ', '.join(keywords),
                    'Matched_Keywords': ', '.join(match_result['matches']),
                    'Match_Count': match_result['match_count'],
                    'Total_Keywords': match_result['total_keywords'],
                    'Is_Upgrade': match_result['is_upgrade'],
                    'Google_Rank': result['rank'],
                    'Competitor_Title': result['title'],
                    'Competitor_Description': result.get('snippet', ''),
                    'Search_Query_Used': query
                })
            
            # Cache the results for future use
            if all_results:
                cache_manager.search_cache.cache_search_results(
                    keywords_text, 
                    all_results, 
                    max_results
                )
                logger.info(f"Cache MISS: Cached new analysis for '{keywords_text[:50]}...' ({len(all_results)} results)")
            
            return all_results, api_key_used
            
        except Exception as e:
            # Log the error
            logging.error(f"Error analyzing keywords {keywords_text}: {str(e)}")
            raise e