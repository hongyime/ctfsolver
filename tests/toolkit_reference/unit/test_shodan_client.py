"""Tests for ShodanClient class."""

import pytest
from unittest.mock import patch, MagicMock
import requests


class TestShodanClient:
    """Test the ShodanClient class."""

    def test_client_initialization_no_key(self):
        """Test that client initializes without API key."""
        with patch.dict('os.environ', {}, clear=True):
            from src.ctf_core.utils.shodan_client import ShodanClient
            client = ShodanClient()
            assert client.is_configured() is False

    def test_client_initialization_with_key(self):
        """Test that client initializes with API key."""
        with patch.dict('os.environ', {'SHODAN_API_KEY': 'a' * 32}):
            from src.ctf_core.utils.shodan_client import ShodanClient
            client = ShodanClient()
            assert client.is_configured() is True

    def test_invalid_key_format(self):
        """Test that invalid key format is detected."""
        from src.ctf_core.utils.shodan_client import ShodanClient
        client = ShodanClient(api_key="invalid-key")
        assert client.is_configured() is False

    def test_valid_key_format(self):
        """Test that valid key format is accepted."""
        from src.ctf_core.utils.shodan_client import ShodanClient
        client = ShodanClient(api_key="a" * 32)
        assert client.is_configured() is True

    def test_key_from_env_var(self):
        """Test that key is read from environment variable."""
        with patch.dict('os.environ', {'SHODAN_API_KEY': 'b' * 32}):
            from src.ctf_core.utils.shodan_client import ShodanClient
            client = ShodanClient()
            assert client.is_configured() is True
            assert client.api_key == 'b' * 32

    @patch('requests.Session.get')
    def test_lookup_ip_success(self, mock_get):
        """Test successful IP lookup."""
        from src.ctf_core.utils.shodan_client import ShodanClient
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'ip': '8.8.8.8',
            'ISP': 'Google',
            'org': 'Google LLC',
            'os': 'Linux',
            'data': [{'port': 443, 'product': 'nginx'}]
        }
        mock_get.return_value = mock_response
        
        client = ShodanClient(api_key='a' * 32)
        result = client.lookup_ip('8.8.8.8')
        
        assert result['ISP'] == 'Google'
        assert result['org'] == 'Google LLC'

    @patch('requests.Session.get')
    def test_search_success(self, mock_get):
        """Test successful search."""
        from src.ctf_core.utils.shodan_client import ShodanClient
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'total': 100,
            'matches': [
                {'ip_str': '1.2.3.4', 'port': 80, 'product': 'Apache', 'org': 'Test'},
            ]
        }
        mock_get.return_value = mock_response
        
        client = ShodanClient(api_key='a' * 32)
        result = client.search('apache')
        
        assert result['total'] == 100
        assert len(result['matches']) == 1

    def test_lookup_without_key_raises(self):
        """Test that lookup without API key raises ValueError."""
        from src.ctf_core.utils.shodan_client import ShodanClient
        
        client = ShodanClient()
        with pytest.raises(ValueError, match="not configured"):
            client.lookup_ip('8.8.8.8')

    def test_search_without_key_raises(self):
        """Test that search without API key raises ValueError."""
        from src.ctf_core.utils.shodan_client import ShodanClient
        
        client = ShodanClient()
        with pytest.raises(ValueError, match="not configured"):
            client.search('test')

    @patch('requests.Session.get')
    def test_validate_key_success(self, mock_get):
        """Test key validation with valid key."""
        from src.ctf_core.utils.shodan_client import ShodanClient
        
        mock_response = MagicMock()
        mock_response.json.return_value = {'plan': 'developer'}
        mock_get.return_value = mock_response
        
        client = ShodanClient(api_key='a' * 32)
        is_valid, message = client.validate_key()
        
        assert is_valid is True
        assert 'developer' in message

    def test_validate_key_no_key(self):
        """Test key validation with no key."""
        from src.ctf_core.utils.shodan_client import ShodanClient
        
        client = ShodanClient()
        is_valid, message = client.validate_key()
        
        assert is_valid is False
        assert 'No API key' in message

    def test_validate_key_invalid_format(self):
        """Test key validation with invalid format."""
        from src.ctf_core.utils.shodan_client import ShodanClient
        
        client = ShodanClient(api_key='invalid')
        is_valid, message = client.validate_key()
        
        assert is_valid is False
        assert 'invalid' in message.lower()

    @patch('requests.Session.get')
    def test_validate_key_api_error(self, mock_get):
        """Test key validation when API returns error."""
        from src.ctf_core.utils.shodan_client import ShodanClient
        
        mock_get.side_effect = requests.RequestException("API error")
        
        client = ShodanClient(api_key='a' * 32)
        is_valid, message = client.validate_key()
        
        assert is_valid is False
        assert 'failed' in message.lower()
