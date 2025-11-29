from pydantic import BaseModel
from typing import Dict, Optional
import os
from dotenv import load_dotenv

class Settings(BaseModel):
    """Application settings"""
    
    # API Settings
    app_name: str = "Threat Intelligence Analyzer API"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # Server Settings
    host: str = "0.0.0.0"
    port: int = 8000
    
    # CORS Settings
    cors_origins: list = ["*"]
    
    # API Keys
    openai_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    urlscan_api_key: Optional[str] = None
    alienvault_api_key: Optional[str] = None
    
    # MISP Settings
    misp_url: Optional[str] = None
    misp_key: Optional[str] = None
    misp_verifycert: bool = False
    
    # Rate Limiting
    rate_limit_per_minute: int = 60
    
    # Request Timeouts (seconds)
    request_timeout: int = 30
    
    # Batch Processing Limits
    max_batch_size: int = 100
    
    class Config:
        env_file = ".env"
        case_sensitive = False

def load_settings() -> Settings:
    """Load settings from environment variables"""
    load_dotenv()
    
    settings = Settings()
    
    # Load from environment variables
    settings.openai_api_key = os.getenv("OPENAI_API_KEY")
    settings.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    settings.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
    settings.shodan_api_key = os.getenv("SHODAN_API_KEY")
    settings.urlscan_api_key = os.getenv("URLSCAN_API_KEY")
    settings.alienvault_api_key = os.getenv("ALIENVAULT_API_KEY")
    settings.misp_url = os.getenv("MISP_URL")
    settings.misp_key = os.getenv("MISP_KEY")
    settings.misp_verifycert = os.getenv("MISP_VERIFYCERT", "False").lower() == "true"
    
    # Server settings
    settings.debug = os.getenv("DEBUG", "False").lower() == "true"
    settings.host = os.getenv("HOST", "0.0.0.0")
    settings.port = int(os.getenv("PORT", "8000"))
    
    return settings

def get_threat_intel_config(settings: Settings) -> Dict[str, str]:
    """Get threat intelligence configuration for services"""
    config = {}
    
    if settings.virustotal_api_key:
        config['VIRUSTOTAL_API_KEY'] = settings.virustotal_api_key
    
    if settings.abuseipdb_api_key:
        config['ABUSEIPDB_API_KEY'] = settings.abuseipdb_api_key
    
    if settings.shodan_api_key:
        config['SHODAN_API_KEY'] = settings.shodan_api_key
    
    if settings.urlscan_api_key:
        config['URLSCAN_API_KEY'] = settings.urlscan_api_key
    
    if settings.alienvault_api_key:
        config['ALIENVAULT_API_KEY'] = settings.alienvault_api_key
    
    if settings.misp_url:
        config['MISP_URL'] = settings.misp_url
    if settings.misp_key:
        config['MISP_KEY'] = settings.misp_key
    if settings.misp_verifycert is not None:
        config['MISP_VERIFYCERT'] = str(settings.misp_verifycert)
    
    return config
