import re
import ipaddress
import logging
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_domain(domain: str) -> bool:
    """Check if string is a valid domain"""
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(domain))

def is_valid_url(url: str) -> bool:
    """Check if string is a valid URL"""
    try:
        result = urlparse(url)
        is_valid = all([result.scheme, result.netloc]) and result.scheme in ['http', 'https', 'ftp']
        logger.info(f"URL validation for '{url}': scheme={result.scheme}, netloc={result.netloc}, is_valid={is_valid}")
        return is_valid
    except Exception as e:
        logger.error(f"URL validation error for '{url}': {str(e)}")
        return False

def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from a URL"""
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            # Remove port if present
            domain = parsed.netloc.split(':')[0]
            logger.info(f"Extracted domain '{domain}' from URL '{url}'")
            return domain
        logger.warning(f"No netloc found in URL '{url}'")
        return None
    except Exception as e:
        logger.error(f"Domain extraction error for '{url}': {str(e)}")
        return None

def is_valid_hash(hash_value: str) -> bool:
    """
    Check if string is a valid hash (MD5, SHA1, SHA256)
    Accepts both uppercase and lowercase hex characters
    """
    if not hash_value:
        return False
    
    hash_patterns = {
        'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
        'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
        'sha256': re.compile(r'^[a-fA-F0-9]{64}$')
    }
    return any(pattern.match(hash_value) for pattern in hash_patterns.values())

def determine_ioc_type(ioc: str) -> str:
    """Determine the type of IOC"""
    ioc = ioc.strip()
    
    logger.info(f"Determining IOC type for: '{ioc}'")
    
    # Check if it's a URL first
    if is_valid_url(ioc):
        logger.info(f"IOC '{ioc}' identified as URL")
        return 'url'
    elif is_valid_ip(ioc):
        logger.info(f"IOC '{ioc}' identified as IP")
        return 'ip'
    elif is_valid_domain(ioc):
        logger.info(f"IOC '{ioc}' identified as domain")
        return 'domain'
    elif is_valid_hash(ioc):
        logger.info(f"IOC '{ioc}' identified as hash")
        return 'hash'
    else:
        logger.warning(f"IOC '{ioc}' type is unknown")
        return 'unknown'

def sanitize_ioc(ioc: str) -> str:
    """
    Sanitize IOC input
    
    - Strips whitespace
    - Lowercases domains, IPs, and URLs (for consistency)
    - Keeps hashes in original case (many APIs are case-sensitive for hashes)
    - For URLs, extracts the domain for analysis
    """
    if not ioc:
        return ""
    
    ioc = ioc.strip()
    
    # Determine IOC type to decide casing
    if is_valid_hash(ioc):
        # Keep hashes in original case (or uppercase for VirusTotal)
        return ioc.upper()
    elif is_valid_url(ioc):
        # For URLs, extract and return the domain
        domain = extract_domain_from_url(ioc)
        if domain:
            return domain.lower()
        # If extraction fails, return the original URL lowercased
        return ioc.lower()
    else:
        # Lowercase domains and IPs
        return ioc.lower()

def get_hash_type(hash_value: str) -> Optional[str]:
    """
    Get the specific type of hash
    Accepts both uppercase and lowercase hex characters
    """
    if not hash_value:
        return None
    
    if re.match(r'^[a-fA-F0-9]{32}$', hash_value):
        return 'md5'
    elif re.match(r'^[a-fA-F0-9]{40}$', hash_value):
        return 'sha1'
    elif re.match(r'^[a-fA-F0-9]{64}$', hash_value):
        return 'sha256'
    return None

def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private (RFC 1918) or reserved
    
    Args:
        ip (str): The IP address to check
        
    Returns:
        bool: True if private/reserved, False if public
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        # Check if it's a private IP address
        # Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        # Also checks for loopback, link-local, multicast, etc.
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_reserved or
            ip_obj.is_multicast
        )
    except ValueError:
        # Not a valid IP address
        return False

def should_analyze_ioc(ioc: str) -> tuple:
    """
    Determine if an IOC should be analyzed based on its type and characteristics
    
    Args:
        ioc (str): The IOC to check
        
    Returns:
        tuple: (should_analyze: bool, reason: str)
    """
    if not ioc or not ioc.strip():
        logger.warning("IOC is empty or invalid")
        return (False, "IOC is empty or invalid")
    
    ioc = ioc.strip()
    ioc_type = determine_ioc_type(ioc)
    
    logger.info(f"IOC type determined: '{ioc_type}' for IOC: '{ioc}'")
    
    # Check if IOC type is supported
    if ioc_type == 'unknown':
        logger.warning(f"IOC '{ioc}' has unknown type")
        return (False, "IOC type is unknown or not supported. Supported types: IP addresses, domains, URLs, and file hashes (MD5, SHA1, SHA256).")
    
    # Special check for IP addresses
    if ioc_type == 'ip':
        if is_private_ip(ioc):
            logger.warning(f"IOC '{ioc}' is a private IP address")
            return (False, f"IP address '{ioc}' is private/reserved and should not be analyzed against public threat intelligence sources. Private IP ranges include: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, loopback (127.0.0.0/8), and other reserved ranges.")
    
    # For URLs, extract domain and check if it's valid
    if ioc_type == 'url':
        domain = extract_domain_from_url(ioc)
        if not domain:
            logger.error(f"Could not extract domain from URL '{ioc}'")
            return (False, "Could not extract valid domain from URL")
        logger.info(f"Extracted domain '{domain}' from URL '{ioc}'")
        # Check if extracted domain is an IP and if it's private
        if is_valid_ip(domain) and is_private_ip(domain):
            logger.warning(f"URL '{ioc}' contains private IP '{domain}'")
            return (False, f"URL contains private IP address '{domain}' which should not be analyzed against public threat intelligence sources.")
    
    # All other IOC types are valid for analysis
    logger.info(f"IOC '{ioc}' is valid for analysis")
    return (True, "IOC is valid for analysis")