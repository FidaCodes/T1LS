from pydantic import BaseModel, Field, validator
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum

class IOCType(str, Enum):
    """IOC types supported by the system"""
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    UNKNOWN = "unknown"

class ClassificationType(str, Enum):
    """Threat classification types"""
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    TEST_FILE = "TEST_FILE"  # For harmless test files like EICAR
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"

# Request Models
class IOCAnalysisRequest(BaseModel):
    """Request model for single IOC analysis"""
    ioc: str = Field(..., description="The IOC to analyze (IP, domain, or hash)")
    include_raw_data: bool = Field(False, description="Include raw API responses in the result")
    analyst_feedback: Optional[str] = Field(None, description="Previous analyst feedback for this IOC to use as context")
    
    @validator('ioc')
    def validate_ioc(cls, v):
        if not v or not v.strip():
            raise ValueError('IOC cannot be empty')
        return v.strip()

class BatchIOCAnalysisRequest(BaseModel):
    """Request model for batch IOC analysis"""
    iocs: List[str] = Field(..., description="List of IOCs to analyze")
    include_raw_data: bool = Field(False, description="Include raw API responses in the results")
    
    @validator('iocs')
    def validate_iocs(cls, v):
        if not v:
            raise ValueError('IOCs list cannot be empty')
        if len(v) > 100:  # Reasonable limit
            raise ValueError('Maximum 100 IOCs allowed per batch request')
        return [ioc.strip() for ioc in v if ioc.strip()]

# Source Data Models
class VirusTotalData(BaseModel):
    """VirusTotal source data"""
    source: str = "VirusTotal"
    malicious_count: int
    suspicious_count: int
    harmless_count: int
    total_engines: int
    raw_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class AbuseIPDBData(BaseModel):
    """AbuseIPDB source data"""
    source: str = "AbuseIPDB"
    abuse_confidence: int
    is_public: bool
    country_code: str
    isp: str
    total_reports: int
    raw_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class MISPData(BaseModel):
    """MISP source data"""
    source: str = "MISP"
    events_found: int
    events: Optional[List[Dict[str, Any]]] = None
    message: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class ShodanData(BaseModel):
    """Shodan source data"""
    source: str = "Shodan"
    ip: Optional[str] = None
    domain: Optional[str] = None
    resolved_ip: Optional[str] = None
    hostnames: Optional[List[str]] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    ports: Optional[List[int]] = None
    services: Optional[List[str]] = None
    vulnerabilities: Optional[List[str]] = None
    last_updated: Optional[str] = None
    message: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class URLScanData(BaseModel):
    """URLScan.io source data"""
    source: str = "URLScan"
    url: Optional[str] = None
    domain: Optional[str] = None
    ip: Optional[str] = None
    scan_id: Optional[str] = None
    result_url: Optional[str] = None
    screenshot_url: Optional[str] = None
    verdict: Optional[str] = None
    brands: Optional[List[str]] = None
    technologies: Optional[List[str]] = None
    server: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    asnname: Optional[str] = None
    malicious: Optional[bool] = None
    phishing_detected: Optional[bool] = None
    scan_date: Optional[str] = None
    total_results: Optional[int] = None
    message: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

# Classification Models
class ThreatClassification(BaseModel):
    """AI threat classification result"""
    classification: ClassificationType
    confidence_score: int = Field(..., ge=0, le=100)
    reasoning: str
    key_indicators: List[str]
    recommendations: str
    model_used: Optional[str] = None
    tokens_used: Optional[int] = None
    raw_llm_response: Optional[str] = None
    error: Optional[str] = None

# Intelligence Data Models
class IntelligenceData(BaseModel):
    """Complete intelligence data for an IOC"""
    ioc: str
    ioc_type: IOCType
    timestamp: datetime
    sources: Dict[str, Union[VirusTotalData, AbuseIPDBData, MISPData, ShodanData, URLScanData, Dict[str, Any]]]

# Response Models
class IOCAnalysisResponse(BaseModel):
    """Response model for single IOC analysis"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    intelligence_data: Optional[IntelligenceData] = None
    classification: Optional[ThreatClassification] = None
    processing_time_ms: Optional[int] = None

class BatchIOCAnalysisResponse(BaseModel):
    """Response model for batch IOC analysis"""
    success: bool
    message: str
    total_processed: int
    results: List[IOCAnalysisResponse]
    processing_time_ms: Optional[int] = None

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: datetime
    version: str
    available_sources: List[str]
    ai_classification_enabled: bool

class ErrorResponse(BaseModel):
    """Error response model"""
    success: bool = False
    error: str
    detail: Optional[str] = None
    timestamp: datetime

# Summary Models
class SourceSummary(BaseModel):
    """Summary of a threat intelligence source"""
    name: str
    available: bool
    error: Optional[str] = None

class SystemStatus(BaseModel):
    """System status information"""
    status: str
    sources: List[SourceSummary]
    ai_classification_enabled: bool
    version: str
    uptime_seconds: Optional[int] = None