from fastapi import APIRouter, Depends
from datetime import datetime
import time
import os

from app.models import HealthResponse, SystemStatus, SourceSummary
from app.core.config import Settings, get_threat_intel_config

router = APIRouter(tags=["System"])

def get_settings() -> Settings:
    """Dependency to get application settings"""
    from app.core.config import load_settings
    return load_settings()

# Store startup time for uptime calculation
_startup_time = time.time()

@router.get("/health", response_model=HealthResponse)
async def health_check(settings: Settings = Depends(get_settings)):
    """
    Health check endpoint
    
    Returns system status and available threat intelligence sources
    """
    config = get_threat_intel_config(settings)
    
    available_sources = []
    if config.get('VIRUSTOTAL_API_KEY'):
        available_sources.append('VirusTotal')
    if config.get('ABUSEIPDB_API_KEY'):
        available_sources.append('AbuseIPDB')
    if config.get('MISP_URL') and config.get('MISP_KEY'):
        available_sources.append('MISP')
    if config.get('SHODAN_API_KEY'):
        available_sources.append('Shodan')
    if config.get('URLSCAN_API_KEY'):
        available_sources.append('URLScan')
    
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(),
        version=settings.app_version,
        available_sources=available_sources,
        ai_classification_enabled=bool(settings.openai_api_key)
    )

@router.get("/status", response_model=SystemStatus)
async def system_status(settings: Settings = Depends(get_settings)):
    """
    Detailed system status
    
    Returns detailed information about each threat intelligence source
    """
    config = get_threat_intel_config(settings)
    
    sources = []
    
    # VirusTotal status
    vt_available = bool(config.get('VIRUSTOTAL_API_KEY'))
    sources.append(SourceSummary(
        name="VirusTotal",
        available=vt_available,
        error=None if vt_available else "API key not configured"
    ))
    
    # AbuseIPDB status
    abuse_available = bool(config.get('ABUSEIPDB_API_KEY'))
    sources.append(SourceSummary(
        name="AbuseIPDB",
        available=abuse_available,
        error=None if abuse_available else "API key not configured"
    ))
    
    # MISP status
    misp_available = bool(config.get('MISP_URL') and config.get('MISP_KEY'))
    misp_error = None
    if not misp_available:
        if not config.get('MISP_URL'):
            misp_error = "MISP URL not configured"
        elif not config.get('MISP_KEY'):
            misp_error = "MISP API key not configured"
    
    sources.append(SourceSummary(
        name="MISP",
        available=misp_available,
        error=misp_error
    ))
    
    # Shodan status
    shodan_available = bool(config.get('SHODAN_API_KEY'))
    sources.append(SourceSummary(
        name="Shodan",
        available=shodan_available,
        error=None if shodan_available else "API key not configured"
    ))
    
    # URLScan status
    urlscan_available = bool(config.get('URLSCAN_API_KEY'))
    sources.append(SourceSummary(
        name="URLScan",
        available=urlscan_available,
        error=None if urlscan_available else "API key not configured"
    ))
    
    # Calculate uptime
    uptime_seconds = int(time.time() - _startup_time)
    
    return SystemStatus(
        status="operational" if any(s.available for s in sources) else "degraded",
        sources=sources,
        ai_classification_enabled=bool(settings.openai_api_key),
        version=settings.app_version,
        uptime_seconds=uptime_seconds
    )

@router.get("/info")
async def api_info(settings: Settings = Depends(get_settings)):
    """
    API information and documentation
    
    Returns basic API information and usage guidelines
    """
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "description": "Threat Intelligence Analysis API",
        "endpoints": {
            "analyze": {
                "method": "POST",
                "path": "/api/v1/analyze",
                "description": "Analyze a single IOC",
                "example": {
                    "ioc": "8.8.8.8",
                    "include_raw_data": False
                }
            },
            "batch_analyze": {
                "method": "POST", 
                "path": "/api/v1/analyze/batch",
                "description": "Analyze multiple IOCs",
                "example": {
                    "iocs": ["8.8.8.8", "malware-domain.com"],
                    "include_raw_data": False
                }
            },
            "health": {
                "method": "GET",
                "path": "/health",
                "description": "Health check"
            },
            "status": {
                "method": "GET",
                "path": "/status", 
                "description": "Detailed system status"
            }
        },
        "supported_ioc_types": [
            "IP addresses (IPv4/IPv6)",
            "Domain names",
            "File hashes (MD5, SHA1, SHA256)"
        ],
        "threat_intelligence_sources": [
            "VirusTotal - File, URL, IP, and domain reputation",
            "AbuseIPDB - IP address abuse reports",  
            "MISP - Malware Information Sharing Platform",
            "Shodan - IP address and domain intelligence",
            "URLScan.io - URL and domain security analysis"
        ],
        "classification_levels": [
            "MALICIOUS - Clear evidence of malicious activity",
            "SUSPICIOUS - Potential threat indicators",
            "BENIGN - No significant threat indicators",
            "ERROR - Classification failed"
        ]
    }