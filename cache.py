import json
from datetime import datetime, timedelta
from pathlib import Path
import threading

class ResultCache:
    """Thread-safe caching for domain results"""
    
    def __init__(self, cache_file="domain_cache.json", ttl_hours=24):
        self.cache_file = Path(cache_file)
        self.ttl = timedelta(hours=ttl_hours)
        self.cache = self._load_cache()
        self.lock = threading.Lock()
    
    def _load_cache(self):
        """Load cache from disk"""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    # Clean expired entries on load
                    return self._clean_expired(data)
            return {}
        except Exception:
            return {}
    
    def _clean_expired(self, cache_data):
        """Remove expired entries"""
        cleaned = {}
        now = datetime.now()
        
        for domain, entry in cache_data.items():
            try:
                cached_time = datetime.fromisoformat(entry["timestamp"])
                if now - cached_time < self.ttl:
                    cleaned[domain] = entry
            except:
                continue
        
        return cleaned
    
    def get(self, domain):
        """Retrieve cached result if valid"""
        with self.lock:
            domain = domain.lower().strip()
            
            if domain in self.cache:
                entry = self.cache[domain]
                try:
                    cached_time = datetime.fromisoformat(entry["timestamp"])
                    if datetime.now() - cached_time < self.ttl:
                        return entry["result"]
                except:
                    pass
            
            return None
    
    def set(self, domain, result):
        """Store result in cache"""
        with self.lock:
            domain = domain.lower().strip()
            
            self.cache[domain] = {
                "result": result,
                "timestamp": datetime.now().isoformat()
            }
            
            # Save to disk periodically (every 10 entries)
            if len(self.cache) % 10 == 0:
                self._save_cache()
    
    def _save_cache(self):
        """Save cache to disk"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception:
            pass
    
    def save(self):
        """Force save cache to disk"""
        with self.lock:
            self._save_cache()
    
    def clear(self):
        """Clear all cache"""
        with self.lock:
            self.cache = {}
            if self.cache_file.exists():
                self.cache_file.unlink()
    
    def get_stats(self):
        """Get cache statistics"""
        with self.lock:
            total = len(self.cache)
            
            if total == 0:
                return {"total": 0, "valid": 0, "expired": 0}
            
            valid = 0
            now = datetime.now()
            
            for entry in self.cache.values():
                try:
                    cached_time = datetime.fromisoformat(entry["timestamp"])
                    if now - cached_time < self.ttl:
                        valid += 1
                except:
                    pass
            
            return {
                "total": total,
                "valid": valid,
                "expired": total - valid
            }
