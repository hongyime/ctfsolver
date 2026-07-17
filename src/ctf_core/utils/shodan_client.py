"""Shodan API client for network reconnaissance."""

import logging
import os
import re
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class ShodanClient:
    """
    Client for interacting with the Shodan API.
    
    Provides methods for:
    - IP lookup
    - Search
    - API key validation
    """
    
    SHODAN_API_BASE = "https://api.shodan.io"
    
    # Shodan API key format: typically 32 characters alphanumeric
    API_KEY_PATTERN = re.compile(r'^[a-zA-Z0-9]{32}$')
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the Shodan client.
        
        Args:
            api_key: Shodan API key. If not provided, will look for SHODAN_API_KEY env var.
        """
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY")
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "CTF-Toolkit/1.0"})
        self._last_request = 0.0
        self._min_interval = float(os.environ.get("SHODAN_MIN_INTERVAL", "1.0"))
        
        # Validate API key format at startup
        if self.api_key:
            self._is_valid_format = self._validate_key_format(self.api_key)
            if not self._is_valid_format:
                logger.warning("Shodan API key format appears invalid (should be 32 alphanumeric characters)")
        else:
            self._is_valid_format = False
            logger.info("No Shodan API key provided - some features will be limited")
    
    def _validate_key_format(self, api_key: str) -> bool:
        """
        Validate the API key format.
        
        Args:
            api_key: The API key to validate
            
        Returns:
            True if the format is valid, False otherwise
        """
        return bool(self.API_KEY_PATTERN.match(api_key))
    
    def is_configured(self) -> bool:
        """Check if the client is properly configured with a valid API key."""
        return bool(self.api_key and self._is_valid_format)

    def _throttle(self) -> None:
        """Enforce a minimum interval between Shodan calls (free tier ~1 req/s) (P4-009)."""
        import time
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()
    
    def lookup_ip(self, ip: str) -> dict:
        """
        Look up information about an IP address using Shodan.
        
        Args:
            ip: IP address to look up
            
        Returns:
            Dict containing IP information from Shodan
            
        Raises:
            ValueError: If API key is not configured
            requests.RequestException: If the API request fails
        """
        if not self.is_configured():
            raise ValueError("Shodan API key not configured or invalid")
        
        url = f"{self.SHODAN_API_BASE}/shodan/host/{ip}"
        params = {"key": self.api_key}
        
        self._throttle()
        response = self._session.get(url, params=params)
        response.raise_for_status()
        
        return response.json()
    
    def search(self, query: str, limit: int = 10) -> dict:
        """
        Search Shodan for devices matching a query.
        
        Args:
            query: Search query
            limit: Maximum number of results to return
            
        Returns:
            Dict containing search results from Shodan
            
        Raises:
            ValueError: If API key is not configured
            requests.RequestException: If the API request fails
        """
        if not self.is_configured():
            raise ValueError("Shodan API key not configured or invalid")
        
        url = f"{self.SHODAN_API_BASE}/shodan/host/search"
        params = {
            "key": self.api_key,
            "query": query,
            "limit": min(limit, 100),  # Shodan limits to 100 per request
        }
        
        self._throttle()
        response = self._session.get(url, params=params)
        response.raise_for_status()
        
        return response.json()
    
    def get_service_info(self, ip: str, port: int) -> Optional[dict]:
        """
        Get information about a specific service on an IP:port.
        
        Args:
            ip: IP address
            port: Port number
            
        Returns:
            Dict containing service information, or None if not found
        """
        try:
            host_data = self.lookup_ip(ip)
            services = host_data.get("data", [])
            
            for service in services:
                if service.get("port") == port:
                    return service
            
            return None
        except requests.RequestException:
            return None
    
    def get_api_info(self) -> dict:
        """
        Get information about the Shodan API plan.
        
        Returns:
            Dict containing API plan information
            
        Raises:
            ValueError: If API key is not configured
            requests.RequestException: If the API request fails
        """
        if not self.is_configured():
            raise ValueError("Shodan API key not configured or invalid")
        
        url = f"{self.SHODAN_API_BASE}/api-info"
        params = {"key": self.api_key}
        
        self._throttle()
        response = self._session.get(url, params=params)
        response.raise_for_status()
        
        return response.json()
    
    def validate_key(self) -> tuple[bool, str]:
        """
        Validate the API key by making a test request.
        
        Returns:
            Tuple of (is_valid, message)
        """
        if not self.api_key:
            return False, "No API key provided"
        
        if not self._validate_key_format(self.api_key):
            return False, "API key format is invalid (should be 32 alphanumeric characters)"
        
        try:
            info = self.get_api_info()
            plan = info.get("plan", "unknown")
            return True, f"API key valid. Plan: {plan}"
        except requests.RequestException as e:
            return False, f"API key validation failed: {str(e)}"
    
    def __repr__(self):
        return f"ShodanClient(configured={self.is_configured()})"
