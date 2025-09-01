"""
Intelligent caching system for search results and API responses
"""
import json
import hashlib
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class InMemoryCache:
    """Simple in-memory cache with TTL support"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.cache: Dict[str, Dict] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.access_times: Dict[str, float] = {}
        self.hit_count = 0
        self.miss_count = 0
    
    def _generate_key(self, prefix: str, data: Any) -> str:
        """Generate cache key from data"""
        if isinstance(data, dict):
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)
        
        key_hash = hashlib.md5(data_str.encode()).hexdigest()
        return f"{prefix}:{key_hash}"
    
    def _is_expired(self, entry: Dict) -> bool:
        """Check if cache entry is expired"""
        return time.time() > entry['expires_at']
    
    def _cleanup_expired(self):
        """Remove expired entries"""
        current_time = time.time()
        expired_keys = [
            key for key, entry in self.cache.items() 
            if current_time > entry['expires_at']
        ]
        
        for key in expired_keys:
            del self.cache[key]
            if key in self.access_times:
                del self.access_times[key]
    
    def _evict_old_entries(self):
        """Evict least recently used entries if cache is full"""
        if len(self.cache) <= self.max_size:
            return
        
        # Sort by access time (oldest first)
        sorted_keys = sorted(
            self.access_times.items(), 
            key=lambda x: x[1]
        )
        
        # Remove oldest entries
        entries_to_remove = len(self.cache) - self.max_size + 1
        for key, _ in sorted_keys[:entries_to_remove]:
            if key in self.cache:
                del self.cache[key]
            if key in self.access_times:
                del self.access_times[key]
    
    def get(self, prefix: str, data: Any) -> Optional[Any]:
        """Get cached value"""
        key = self._generate_key(prefix, data)
        
        if key not in self.cache:
            self.miss_count += 1
            return None
        
        entry = self.cache[key]
        
        if self._is_expired(entry):
            del self.cache[key]
            if key in self.access_times:
                del self.access_times[key]
            self.miss_count += 1
            return None
        
        # Update access time
        self.access_times[key] = time.time()
        self.hit_count += 1
        
        logger.debug(f"Cache HIT for key: {key[:20]}...")
        return entry['value']
    
    def set(self, prefix: str, data: Any, value: Any, ttl: Optional[int] = None) -> bool:
        """Set cached value"""
        try:
            key = self._generate_key(prefix, data)
            
            # Clean up expired entries periodically
            if len(self.cache) % 100 == 0:
                self._cleanup_expired()
            
            # Evict old entries if needed
            self._evict_old_entries()
            
            expires_at = time.time() + (ttl or self.default_ttl)
            
            self.cache[key] = {
                'value': value,
                'created_at': time.time(),
                'expires_at': expires_at
            }
            
            self.access_times[key] = time.time()
            
            logger.debug(f"Cache SET for key: {key[:20]}... (TTL: {ttl or self.default_ttl}s)")
            return True
            
        except Exception as e:
            logger.error(f"Cache SET failed: {str(e)}")
            return False
    
    def delete(self, prefix: str, data: Any) -> bool:
        """Delete cached value"""
        key = self._generate_key(prefix, data)
        
        if key in self.cache:
            del self.cache[key]
            if key in self.access_times:
                del self.access_times[key]
            logger.debug(f"Cache DELETE for key: {key[:20]}...")
            return True
        
        return False
    
    def clear(self) -> int:
        """Clear all cache entries"""
        count = len(self.cache)
        self.cache.clear()
        self.access_times.clear()
        self.hit_count = 0
        self.miss_count = 0
        logger.info(f"Cache cleared: {count} entries removed")
        return count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.hit_count + self.miss_count
        hit_rate = (self.hit_count / total_requests * 100) if total_requests > 0 else 0
        
        return {
            'entries': len(self.cache),
            'max_size': self.max_size,
            'hit_count': self.hit_count,
            'miss_count': self.miss_count,
            'hit_rate': round(hit_rate, 2),
            'memory_usage_mb': self._estimate_memory_usage()
        }
    
    def _estimate_memory_usage(self) -> float:
        """Estimate memory usage in MB"""
        try:
            import sys
            total_size = 0
            
            for key, entry in self.cache.items():
                total_size += sys.getsizeof(key)
                total_size += sys.getsizeof(entry)
                total_size += sys.getsizeof(entry['value'])
            
            return round(total_size / (1024 * 1024), 2)
        except:
            return 0.0

class SearchResultsCache:
    """Specialized cache for search results"""
    
    def __init__(self, cache: InMemoryCache):
        self.cache = cache
        self.search_ttl = 1800  # 30 minutes for search results
        self.api_response_ttl = 300  # 5 minutes for API responses
        self.keyword_analysis_ttl = 600  # 10 minutes for keyword analysis
    
    def get_search_results(self, keywords: str, max_results: int = 10) -> Optional[List[Dict]]:
        """Get cached search results for keywords"""
        cache_data = {
            'keywords': keywords.lower().strip(),
            'max_results': max_results
        }
        
        return self.cache.get('search_results', cache_data)
    
    def cache_search_results(self, keywords: str, results: List[Dict], max_results: int = 10) -> bool:
        """Cache search results"""
        cache_data = {
            'keywords': keywords.lower().strip(),
            'max_results': max_results
        }
        
        # Add timestamp to results
        cached_results = {
            'results': results,
            'cached_at': datetime.utcnow().isoformat(),
            'result_count': len(results)
        }
        
        return self.cache.set('search_results', cache_data, cached_results, self.search_ttl)
    
    def get_api_response(self, api_key: str, query: str) -> Optional[Dict]:
        """Get cached API response"""
        cache_data = {
            'api_key_hash': hashlib.md5(api_key.encode()).hexdigest()[:8],  # Don't store full key
            'query': query.lower().strip()
        }
        
        return self.cache.get('api_response', cache_data)
    
    def cache_api_response(self, api_key: str, query: str, response: Dict) -> bool:
        """Cache API response"""
        cache_data = {
            'api_key_hash': hashlib.md5(api_key.encode()).hexdigest()[:8],
            'query': query.lower().strip()
        }
        
        return self.cache.set('api_response', cache_data, response, self.api_response_ttl)
    
    def get_keyword_analysis(self, domain: str) -> Optional[Dict]:
        """Get cached keyword analysis for a domain"""
        cache_data = {'domain': domain.lower().strip()}
        return self.cache.get('keyword_analysis', cache_data)
    
    def cache_keyword_analysis(self, domain: str, analysis: Dict) -> bool:
        """Cache keyword analysis"""
        cache_data = {'domain': domain.lower().strip()}
        return self.cache.set('keyword_analysis', cache_data, analysis, self.keyword_analysis_ttl)
    
    def invalidate_search_cache(self, keywords: str = None):
        """Invalidate search cache for specific keywords or all"""
        if keywords:
            # Invalidate specific search
            for max_results in [10, 20, 50, 100]:
                cache_data = {
                    'keywords': keywords.lower().strip(),
                    'max_results': max_results
                }
                self.cache.delete('search_results', cache_data)
        else:
            # This would require a more complex implementation to delete by prefix
            # For now, we'll log the request
            logger.info("Full search cache invalidation requested")

class CacheManager:
    """Main cache manager for the application"""
    
    def __init__(self, max_size: int = 2000, default_ttl: int = 3600):
        self.cache = InMemoryCache(max_size=max_size, default_ttl=default_ttl)
        self.search_cache = SearchResultsCache(self.cache)
        
        logger.info(f"Cache manager initialized (max_size: {max_size}, default_ttl: {default_ttl}s)")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        base_stats = self.cache.get_stats()
        
        return {
            **base_stats,
            'cache_type': 'InMemory',
            'search_ttl': self.search_cache.search_ttl,
            'api_response_ttl': self.search_cache.api_response_ttl,
            'status': 'active'
        }
    
    def clear_all_cache(self) -> Dict[str, int]:
        """Clear all caches"""
        entries_cleared = self.cache.clear()
        
        return {
            'entries_cleared': entries_cleared,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def health_check(self) -> Dict[str, Any]:
        """Perform cache health check"""
        try:
            # Test basic cache operations
            test_key = f"health_check_{int(time.time())}"
            test_value = {"test": True, "timestamp": time.time()}
            
            # Test set
            set_success = self.cache.set('health', test_key, test_value, 10)
            
            # Test get
            retrieved_value = self.cache.get('health', test_key)
            get_success = retrieved_value is not None
            
            # Test delete
            delete_success = self.cache.delete('health', test_key)
            
            return {
                'status': 'healthy' if all([set_success, get_success, delete_success]) else 'degraded',
                'operations': {
                    'set': set_success,
                    'get': get_success,
                    'delete': delete_success
                },
                'stats': self.get_cache_stats(),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Cache health check failed: {str(e)}")
            return {
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }

# Global cache manager instance
cache_manager = CacheManager(max_size=2000, default_ttl=1800)  # 30 minutes default