from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import List
import time
import logging
from datetime import datetime

from app.models import (
    IOCAnalysisRequest, 
    IOCAnalysisResponse, 
    BatchIOCAnalysisRequest,
    BatchIOCAnalysisResponse,
    ErrorResponse
)
from app.services.threat_intel_collector import ThreatIntelligenceCollector
from app.services.threat_classifier import ThreatClassifier
from app.core.config import Settings, get_threat_intel_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Threat Intelligence"])

def get_settings() -> Settings:
    """Dependency to get application settings"""
    from app.core.config import load_settings
    return load_settings()

# Individual Source Endpoints

@router.post("/virustotal", response_model=dict)
async def analyze_virustotal(
    request: IOCAnalysisRequest,
    settings: Settings = Depends(get_settings)
):
    """
    Analyze IOC using VirusTotal with AI reasoning
    
    Returns structured JSON response with verdict and reasoning
    """
    start_time = time.time()
    
    try:
        config = get_threat_intel_config(settings)
        if not config.get('VIRUSTOTAL_API_KEY'):
            return {
                "success": False,
                "source": "VirusTotal",
                "error": "VirusTotal API key not configured",
                "processing_time_ms": int((time.time() - start_time) * 1000)
            }
        
        collector = ThreatIntelligenceCollector(config, timeout=settings.request_timeout)
        from app.utils.validators import determine_ioc_type
        ioc_type = determine_ioc_type(request.ioc)
        
        result = collector.query_virustotal(request.ioc, ioc_type)
        
        # Generate AI reasoning for VirusTotal data
        verdict = "UNKNOWN"
        reasoning = "No analysis performed"
        confidence_score = 0
        
        if result and 'error' not in result and settings.openai_api_key:
            try:
                classifier = ThreatClassifier(settings.openai_api_key)
                verdict, reasoning, confidence_score = _analyze_source_with_ai(
                    classifier, "VirusTotal", request.ioc, ioc_type, result
                )
            except Exception as e:
                logger.error(f"AI analysis error for VirusTotal: {str(e)}")
                reasoning = f"AI analysis failed: {str(e)}"
        elif result and 'error' not in result:
            # Fallback logic without AI
            verdict, reasoning, confidence_score = _analyze_virustotal_fallback(result)
        
        return {
            "success": True,
            "source": "VirusTotal",
            "ioc": request.ioc,
            "ioc_type": ioc_type,
            "data": result,
            "verdict": verdict,
            "reasoning": reasoning,
            "confidence_score": confidence_score,
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }
        
    except Exception as e:
        logger.error(f"VirusTotal analysis error for IOC {request.ioc}: {str(e)}")
        return {
            "success": False,
            "source": "VirusTotal",
            "ioc": request.ioc,
            "error": str(e),
            "verdict": "ERROR",
            "reasoning": f"Analysis failed: {str(e)}",
            "confidence_score": 0,
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }

@router.post("/abuseipdb", response_model=dict)
async def analyze_abuseipdb(
    request: IOCAnalysisRequest,
    settings: Settings = Depends(get_settings)
):
    """
    Analyze IOC using AbuseIPDB (IP addresses only) with AI reasoning
    
    Returns structured JSON response with verdict and reasoning
    """
    start_time = time.time()
    
    try:
        config = get_threat_intel_config(settings)
        if not config.get('ABUSEIPDB_API_KEY'):
            return {
                "success": False,
                "source": "AbuseIPDB",
                "error": "AbuseIPDB API key not configured",
                "verdict": "ERROR",
                "reasoning": "AbuseIPDB API key not configured",
                "confidence_score": 0,
                "processing_time_ms": int((time.time() - start_time) * 1000)
            }
        
        collector = ThreatIntelligenceCollector(config, timeout=settings.request_timeout)
        from app.utils.validators import determine_ioc_type
        ioc_type = determine_ioc_type(request.ioc)
        
        if ioc_type != 'ip':
            return {
                "success": False,
                "source": "AbuseIPDB",
                "ioc": request.ioc,
                "error": "AbuseIPDB only supports IP addresses",
                "verdict": "ERROR",
                "reasoning": "AbuseIPDB only supports IP addresses. This IOC appears to be a domain or hash.",
                "confidence_score": 0,
                "processing_time_ms": int((time.time() - start_time) * 1000)
            }
        
        result = collector.query_abuseipdb(request.ioc, ioc_type)
        
        # Generate AI reasoning for AbuseIPDB data
        verdict = "UNKNOWN"
        reasoning = "No analysis performed"
        confidence_score = 0
        
        if result and 'error' not in result and settings.openai_api_key:
            try:
                classifier = ThreatClassifier(settings.openai_api_key)
                verdict, reasoning, confidence_score = _analyze_source_with_ai(
                    classifier, "AbuseIPDB", request.ioc, ioc_type, result
                )
            except Exception as e:
                logger.error(f"AI analysis error for AbuseIPDB: {str(e)}")
                verdict, reasoning, confidence_score = _analyze_abuseipdb_fallback(result)
        elif result and 'error' not in result:
            # Fallback logic without AI
            verdict, reasoning, confidence_score = _analyze_abuseipdb_fallback(result)
        
        return {
            "success": True,
            "source": "AbuseIPDB",
            "ioc": request.ioc,
            "ioc_type": ioc_type,
            "data": result,
            "verdict": verdict,
            "reasoning": reasoning,
            "confidence_score": confidence_score,
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }
        
    except Exception as e:
        logger.error(f"AbuseIPDB analysis error for IOC {request.ioc}: {str(e)}")
        return {
            "success": False,
            "source": "AbuseIPDB",
            "ioc": request.ioc,
            "error": str(e),
            "verdict": "ERROR",
            "reasoning": f"Analysis failed: {str(e)}",
            "confidence_score": 0,
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }

@router.post("/shodan", response_model=dict)
async def analyze_shodan(
    request: IOCAnalysisRequest,
    settings: Settings = Depends(get_settings)
):
    """
    Analyze IOC using Shodan (IP addresses and domains)
    
    Returns structured JSON response for easy frontend consumption
    """
    start_time = time.time()
    
    try:
        config = get_threat_intel_config(settings)
        if not config.get('SHODAN_API_KEY'):
            return {
                "success": False,
                "source": "Shodan",
                "error": "Shodan API key not configured",
                "processing_time_ms": int((time.time() - start_time) * 1000)
            }
        
        collector = ThreatIntelligenceCollector(config, timeout=settings.request_timeout)
        from app.utils.validators import determine_ioc_type
        ioc_type = determine_ioc_type(request.ioc)
        
        result = collector.query_shodan(request.ioc, ioc_type)
        
        # Generate AI reasoning for Shodan data
        verdict = "UNKNOWN"
        reasoning = "No analysis performed"
        confidence_score = 0
        
        if result and 'error' not in result and settings.openai_api_key:
            try:
                classifier = ThreatClassifier(settings.openai_api_key)
                verdict, reasoning, confidence_score = _analyze_source_with_ai(
                    classifier, "Shodan", request.ioc, ioc_type, result
                )
            except Exception as e:
                logger.error(f"AI analysis error for Shodan: {str(e)}")
                verdict, reasoning, confidence_score = _analyze_shodan_fallback(result)
        elif result and 'error' not in result:
            verdict, reasoning, confidence_score = _analyze_shodan_fallback(result)
        
        return {
            "success": True,
            "source": "Shodan",
            "ioc": request.ioc,
            "ioc_type": ioc_type,
            "data": result,
            "verdict": verdict,
            "reasoning": reasoning,
            "confidence_score": confidence_score,
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }
        
    except Exception as e:
        logger.error(f"Shodan analysis error for IOC {request.ioc}: {str(e)}")
        return {
            "success": False,
            "source": "Shodan",
            "ioc": request.ioc,
            "error": str(e),
            "verdict": "ERROR",
            "reasoning": f"Analysis failed: {str(e)}",
            "confidence_score": 0,
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }

@router.post("/urlscan", response_model=dict)
async def analyze_urlscan(
    request: IOCAnalysisRequest,
    settings: Settings = Depends(get_settings)
):
    """
    Analyze IOC using URLScan.io (domains and IPs)
    
    Returns structured JSON response for easy frontend consumption
    """
    start_time = time.time()
    
    try:
        config = get_threat_intel_config(settings)
        if not config.get('URLSCAN_API_KEY'):
            return {
                "success": False,
                "source": "URLScan",
                "error": "URLScan API key not configured",
                "processing_time_ms": int((time.time() - start_time) * 1000)
            }
        
        collector = ThreatIntelligenceCollector(config, timeout=settings.request_timeout)
        from app.utils.validators import determine_ioc_type
        ioc_type = determine_ioc_type(request.ioc)
        
        result = collector.query_urlscan(request.ioc, ioc_type)
        
        return {
            "success": True,
            "source": "URLScan",
            "ioc": request.ioc,
            "ioc_type": ioc_type,
            "data": result,
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }
        
    except Exception as e:
        logger.error(f"URLScan analysis error for IOC {request.ioc}: {str(e)}")
        return {
            "success": False,
            "source": "URLScan",
            "ioc": request.ioc,
            "error": str(e),
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }

@router.post("/misp", response_model=dict)
async def analyze_misp(
    request: IOCAnalysisRequest,
    settings: Settings = Depends(get_settings)
):
    """
    Analyze IOC using MISP
    
    Returns structured JSON response for easy frontend consumption
    """
    start_time = time.time()
    
    try:
        config = get_threat_intel_config(settings)
        if not (config.get('MISP_URL') and config.get('MISP_KEY')):
            return {
                "success": False,
                "source": "MISP",
                "error": "MISP URL and API key not configured",
                "processing_time_ms": int((time.time() - start_time) * 1000)
            }
        
        collector = ThreatIntelligenceCollector(config, timeout=settings.request_timeout)
        from app.utils.validators import determine_ioc_type
        ioc_type = determine_ioc_type(request.ioc)
        
        result = collector.query_misp(request.ioc, ioc_type)
        
        return {
            "success": True,
            "source": "MISP",
            "ioc": request.ioc,
            "ioc_type": ioc_type,
            "data": result,
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }
        
    except Exception as e:
        logger.error(f"MISP analysis error for IOC {request.ioc}: {str(e)}")
        return {
            "success": False,
            "source": "MISP",
            "ioc": request.ioc,
            "error": str(e),
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }

@router.post("/alienvault", response_model=dict)
async def analyze_alienvault(
    request: IOCAnalysisRequest,
    settings: Settings = Depends(get_settings)
):
    """
    Analyze IOC using AlienVault OTX (Open Threat Exchange)
    
    Returns structured JSON response with threat intelligence from OTX pulses
    """
    start_time = time.time()
    
    try:
        config = get_threat_intel_config(settings)
        if not config.get('ALIENVAULT_API_KEY'):
            return {
                "success": False,
                "source": "AlienVault OTX",
                "error": "AlienVault OTX API key not configured",
                "processing_time_ms": int((time.time() - start_time) * 1000)
            }
        
        collector = ThreatIntelligenceCollector(config, timeout=settings.request_timeout)
        from app.utils.validators import determine_ioc_type
        ioc_type = determine_ioc_type(request.ioc)
        
        result = collector.query_alienvault(request.ioc, ioc_type)
        
        # Generate AI reasoning for AlienVault data
        verdict = "UNKNOWN"
        reasoning = "No analysis performed"
        confidence_score = 0
        
        if result and 'error' not in result and settings.openai_api_key:
            try:
                classifier = ThreatClassifier(settings.openai_api_key)
                verdict, reasoning, confidence_score = _analyze_source_with_ai(
                    classifier, "AlienVault OTX", request.ioc, ioc_type, result
                )
            except Exception as e:
                logger.error(f"AI analysis error for AlienVault OTX: {str(e)}")
                verdict, reasoning, confidence_score = _analyze_alienvault_fallback(result)
        elif result and 'error' not in result:
            # Fallback logic without AI
            verdict, reasoning, confidence_score = _analyze_alienvault_fallback(result)
        
        return {
            "success": True,
            "source": "AlienVault OTX",
            "ioc": request.ioc,
            "ioc_type": ioc_type,
            "data": result,
            "verdict": verdict,
            "reasoning": reasoning,
            "confidence_score": confidence_score,
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }
        
    except Exception as e:
        logger.error(f"AlienVault OTX analysis error for IOC {request.ioc}: {str(e)}")
        return {
            "success": False,
            "source": "AlienVault OTX",
            "ioc": request.ioc,
            "error": str(e),
            "verdict": "ERROR",
            "reasoning": f"Analysis failed: {str(e)}",
            "confidence_score": 0,
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }

# Combined Analysis Endpoint (legacy support)
@router.post("/analyze", response_model=IOCAnalysisResponse)
async def analyze_ioc(
    request: IOCAnalysisRequest,
    settings: Settings = Depends(get_settings)
):
    """
    Analyze a single IOC (IP, domain, or hash) for threat intelligence
    
    - **ioc**: The indicator of compromise to analyze
    - **include_raw_data**: Whether to include raw API responses (default: false)
    
    Returns detailed threat intelligence analysis with AI classification
    """
    start_time = time.time()
    
    try:
        # Get threat intelligence configuration
        config = get_threat_intel_config(settings)
        
        if not config:
            raise HTTPException(
                status_code=503,
                detail="No threat intelligence sources configured. Please add API keys."
            )
        
        # Collect intelligence data
        collector = ThreatIntelligenceCollector(config, timeout=settings.request_timeout)
        intel_data = collector.collect_intelligence(request.ioc, request.include_raw_data)
        
        # Check if we have any valid data
        sources_with_data = [
            name for name, data in intel_data['sources'].items() 
            if 'error' not in data
        ]
        
        if not sources_with_data:
            return IOCAnalysisResponse(
                success=False,
                message="No threat intelligence data could be collected from any source",
                intelligence_data=intel_data,
                processing_time_ms=int((time.time() - start_time) * 1000)
            )
        
        # Classify threat if OpenAI key is available
        classification = None
        if settings.openai_api_key:
            try:
                classifier = ThreatClassifier(settings.openai_api_key)
                classification = classifier.classify_threat(intel_data)
            except Exception as e:
                logger.error(f"Classification error: {str(e)}")
                classification = {
                    "classification": "ERROR",
                    "confidence_score": 0,
                    "reasoning": f"Classification failed: {str(e)}",
                    "key_indicators": [],
                    "recommendations": "Manual review required",
                    "error": str(e)
                }
        
        processing_time = int((time.time() - start_time) * 1000)
        
        response = IOCAnalysisResponse(
            success=True,
            message=f"Analysis completed. Data collected from {len(sources_with_data)} source(s): {', '.join(sources_with_data)}",
            intelligence_data=intel_data,
            classification=classification,
            processing_time_ms=processing_time
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Analysis error for IOC {request.ioc}: {str(e)}")
        processing_time = int((time.time() - start_time) * 1000)
        
        return IOCAnalysisResponse(
            success=False,
            message=f"Analysis failed: {str(e)}",
            processing_time_ms=processing_time
        )

# AI Agent Orchestration Endpoint
@router.post("/analyze/all-sources", response_model=dict)
async def analyze_all_sources(
    request: IOCAnalysisRequest,
    settings: Settings = Depends(get_settings)
):
    """
    Analyze IOC across all available threat intelligence sources
    
    Returns structured JSON with results from each source for AI agent consumption
    """
    start_time = time.time()
    
    try:
        config = get_threat_intel_config(settings)
        from app.utils.validators import determine_ioc_type, should_analyze_ioc, sanitize_ioc
        
        # Check if IOC should be analyzed (e.g., not a private IP)
        should_analyze, reason = should_analyze_ioc(request.ioc)
        if not should_analyze:
            return {
                "success": False,
                "message": reason,
                "ioc": request.ioc,
                "ioc_type": determine_ioc_type(request.ioc),
                "error": "IOC validation failed",
                "processing_time_ms": int((time.time() - start_time) * 1000)
            }
        
        # Determine IOC type and sanitize (extracts domain from URLs)
        original_ioc = request.ioc
        ioc_type = determine_ioc_type(request.ioc)
        sanitized_ioc = sanitize_ioc(request.ioc)
        
        logger.info(f"Original IOC: '{original_ioc}', Type: '{ioc_type}', Sanitized: '{sanitized_ioc}'")
        
        if not config:
            return {
                "success": False,
                "message": "No threat intelligence sources configured",
                "ioc": original_ioc,
                "ioc_type": ioc_type,
                "sources": {},
                "processing_time_ms": int((time.time() - start_time) * 1000)
            }
        
        collector = ThreatIntelligenceCollector(config, timeout=settings.request_timeout)
        sources_results = {}
        
        # Query each source individually
        sources = [
            ('virustotal', collector.query_virustotal),
            ('abuseipdb', collector.query_abuseipdb),
            ('misp', collector.query_misp),
            ('shodan', collector.query_shodan),
            ('urlscan', collector.query_urlscan),
            ('alienvault', collector.query_alienvault)
        ]
        
        for source_name, query_func in sources:
            source_start_time = time.time()
            try:
                # Check if source is configured
                source_key_map = {
                    'virustotal': 'VIRUSTOTAL_API_KEY',
                    'abuseipdb': 'ABUSEIPDB_API_KEY',
                    'shodan': 'SHODAN_API_KEY',
                    'urlscan': 'URLSCAN_API_KEY',
                    'alienvault': 'ALIENVAULT_API_KEY',
                    'misp': ['MISP_URL', 'MISP_KEY']
                }
                
                if source_name == 'misp':
                    configured = all(key in config for key in source_key_map[source_name])
                else:
                    configured = source_key_map[source_name] in config
                
                if not configured:
                    sources_results[source_name] = {
                        "success": False,
                        "error": f"{source_name.title()} not configured",
                        "processing_time_ms": 0
                    }
                    continue
                
                # Use sanitized IOC for querying (domain extracted from URL)
                result = query_func(sanitized_ioc, ioc_type if ioc_type != 'url' else 'domain')
                
                # Generate AI reasoning for each source
                verdict = "UNKNOWN"
                reasoning = "No analysis performed"
                confidence_score = 0
                
                if result and 'error' not in result and settings.openai_api_key:
                    try:
                        classifier = ThreatClassifier(settings.openai_api_key)
                        verdict, reasoning, confidence_score = _analyze_source_with_ai(
                            classifier, source_name.title(), sanitized_ioc, ioc_type if ioc_type != 'url' else 'domain', result
                        )
                    except Exception as e:
                        logger.error(f"AI analysis error for {source_name}: {str(e)}")
                        # Use fallback logic
                        fallback_funcs = {
                            'virustotal': _analyze_virustotal_fallback,
                            'abuseipdb': _analyze_abuseipdb_fallback,
                            'shodan': _analyze_shodan_fallback,
                            'urlscan': _analyze_urlscan_fallback,
                            'misp': _analyze_misp_fallback,
                            'alienvault': _analyze_alienvault_fallback
                        }
                        if source_name in fallback_funcs:
                            verdict, reasoning, confidence_score = fallback_funcs[source_name](result)
                elif result and 'error' not in result:
                    # Use fallback logic without AI
                    fallback_funcs = {
                        'virustotal': _analyze_virustotal_fallback,
                        'abuseipdb': _analyze_abuseipdb_fallback,
                        'shodan': _analyze_shodan_fallback,
                        'urlscan': _analyze_urlscan_fallback,
                        'misp': _analyze_misp_fallback,
                        'alienvault': _analyze_alienvault_fallback
                    }
                    if source_name in fallback_funcs:
                        verdict, reasoning, confidence_score = fallback_funcs[source_name](result)
                
                sources_results[source_name] = {
                    "success": True if result and 'error' not in result else False,
                    "data": result,
                    "verdict": verdict,
                    "reasoning": reasoning,
                    "confidence_score": confidence_score,
                    "processing_time_ms": int((time.time() - source_start_time) * 1000)
                }
                
            except Exception as e:
                logger.error(f"{source_name} analysis error: {str(e)}")
                sources_results[source_name] = {
                    "success": False,
                    "error": str(e),
                    "processing_time_ms": int((time.time() - source_start_time) * 1000)
                }
        
        # Count successful sources
        successful_sources = [name for name, result in sources_results.items() if result.get("success")]
        
        # Generate final verdict by combining all source results
        final_verdict = "UNKNOWN"
        final_reasoning = "No analysis performed"
        final_confidence = 0
        
        if successful_sources and settings.openai_api_key:
            try:
                classifier = ThreatClassifier(settings.openai_api_key)
                final_verdict, final_reasoning, final_confidence = _generate_final_verdict(
                    classifier, request.ioc, ioc_type, sources_results, successful_sources, request.analyst_feedback
                )
            except Exception as e:
                logger.error(f"Final verdict AI analysis error: {str(e)}")
                final_verdict, final_reasoning, final_confidence = _generate_final_verdict_fallback(
                    sources_results, successful_sources
                )
        elif successful_sources:
            # Fallback logic without AI
            final_verdict, final_reasoning, final_confidence = _generate_final_verdict_fallback(
                sources_results, successful_sources
            )
        
        response_data = {
            "success": len(successful_sources) > 0,
            "message": f"Analysis completed. Data collected from {len(successful_sources)} source(s): {', '.join(successful_sources)}",
            "ioc": original_ioc,
            "ioc_type": ioc_type,
            "analyzed_value": sanitized_ioc if ioc_type == 'url' else original_ioc,
            "sources": sources_results,
            "successful_sources_count": len(successful_sources),
            "total_sources_queried": len(sources_results),
            "final_verdict": {
                "verdict": final_verdict,
                "reasoning": final_reasoning,
                "confidence_score": final_confidence,
                "sources_consulted": successful_sources
            },
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }
        
        return response_data
        
    except Exception as e:
        logger.error(f"All sources analysis error for IOC {request.ioc}: {str(e)}")
        return {
            "success": False,
            "message": f"Analysis failed: {str(e)}",
            "ioc": request.ioc,
            "error": str(e),
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }

@router.post("/analyze/batch", response_model=BatchIOCAnalysisResponse)
async def analyze_batch_iocs(
    request: BatchIOCAnalysisRequest,
    background_tasks: BackgroundTasks,
    settings: Settings = Depends(get_settings)
):
    """
    Analyze multiple IOCs in batch
    
    - **iocs**: List of IOCs to analyze (max 100)
    - **include_raw_data**: Whether to include raw API responses (default: false)
    
    Returns analysis results for all IOCs
    """
    start_time = time.time()
    
    try:
        if len(request.iocs) > settings.max_batch_size:
            raise HTTPException(
                status_code=400,
                detail=f"Batch size too large. Maximum {settings.max_batch_size} IOCs allowed."
            )
        
        config = get_threat_intel_config(settings)
        
        if not config:
            raise HTTPException(
                status_code=503,
                detail="No threat intelligence sources configured. Please add API keys."
            )
        
        results = []
        collector = ThreatIntelligenceCollector(config, timeout=settings.request_timeout)
        classifier = ThreatClassifier(settings.openai_api_key) if settings.openai_api_key else None
        
        for ioc in request.iocs:
            ioc_start_time = time.time()
            
            try:
                # Collect intelligence
                intel_data = collector.collect_intelligence(ioc, request.include_raw_data)
                
                # Check for valid data
                sources_with_data = [
                    name for name, data in intel_data['sources'].items() 
                    if 'error' not in data
                ]
                
                # Classify if possible
                classification = None
                if classifier and sources_with_data:
                    try:
                        classification = classifier.classify_threat(intel_data)
                    except Exception as e:
                        logger.error(f"Classification error for {ioc}: {str(e)}")
                        classification = {
                            "classification": "ERROR",
                            "confidence_score": 0,
                            "reasoning": f"Classification failed: {str(e)}",
                            "key_indicators": [],
                            "recommendations": "Manual review required",
                            "error": str(e)
                        }
                
                ioc_processing_time = int((time.time() - ioc_start_time) * 1000)
                
                result = IOCAnalysisResponse(
                    success=bool(sources_with_data),
                    message=f"Analysis completed for {ioc}" if sources_with_data else f"No data available for {ioc}",
                    intelligence_data=intel_data,
                    classification=classification,
                    processing_time_ms=ioc_processing_time
                )
                
                results.append(result)
                
            except Exception as e:
                logger.error(f"Error analyzing IOC {ioc}: {str(e)}")
                ioc_processing_time = int((time.time() - ioc_start_time) * 1000)
                
                result = IOCAnalysisResponse(
                    success=False,
                    message=f"Analysis failed for {ioc}: {str(e)}",
                    processing_time_ms=ioc_processing_time
                )
                results.append(result)
        
        total_processing_time = int((time.time() - start_time) * 1000)
        
        return BatchIOCAnalysisResponse(
            success=True,
            message=f"Batch analysis completed for {len(request.iocs)} IOCs",
            total_processed=len(results),
            results=results,
            processing_time_ms=total_processing_time
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch analysis error: {str(e)}")
        total_processing_time = int((time.time() - start_time) * 1000)
        
        return BatchIOCAnalysisResponse(
            success=False,
            message=f"Batch analysis failed: {str(e)}",
            total_processed=0,
            results=[],
            processing_time_ms=total_processing_time
        )


# Helper function for IOC validation
def _validate_ioc(ioc: str) -> tuple:
    """
    Validate IOC before analysis
    
    Returns: (is_valid: bool, error_response: dict or None)
    """
    from app.utils.validators import should_analyze_ioc, determine_ioc_type
    
    should_analyze, reason = should_analyze_ioc(ioc)
    if not should_analyze:
        return (False, {
            "success": False,
            "ioc": ioc,
            "ioc_type": determine_ioc_type(ioc),
            "error": reason,
            "verdict": "SKIPPED",
            "reasoning": reason,
            "confidence_score": 0
        })
    
    return (True, None)


# Helper functions for AI reasoning
def _analyze_source_with_ai(classifier: ThreatClassifier, source_name: str, ioc: str, ioc_type: str, data: dict) -> tuple:
    """
    Analyze threat intelligence data from a specific source using AI
    
    Returns: (verdict, reasoning, confidence_score)
    """
    try:
        # Create a simplified intelligence data structure for the specific source
        intel_data = {
            'ioc': ioc,
            'ioc_type': ioc_type,
            'timestamp': datetime.now().isoformat(),
            'sources': {source_name.lower(): data}
        }
        
        # Use the existing classifier but with source-specific prompt
        classification = classifier.classify_threat(intel_data)
        
        return (
            classification.get('classification', 'UNKNOWN'),
            classification.get('reasoning', 'No reasoning provided'),
            classification.get('confidence_score', 0)
        )
        
    except Exception as e:
        logger.error(f"AI analysis failed for {source_name}: {str(e)}")
        return ("ERROR", f"AI analysis failed: {str(e)}", 0)


def _analyze_virustotal_fallback(data: dict) -> tuple:
    """Fallback analysis for VirusTotal without AI - includes code insights and context"""
    if not data or 'error' in data:
        return ("ERROR", "No valid VirusTotal data available", 0)
    
    malicious = data.get('malicious_count', 0)
    total = data.get('total_engines', 0)
    
    if total == 0:
        return ("UNKNOWN", "No scan results available from VirusTotal", 0)
    
    # Extract context and insights from VirusTotal
    popular_threat_label = data.get('popular_threat_label', '')
    meaningful_name = data.get('meaningful_name', '')
    type_description = data.get('type_description', '')
    tags = data.get('tags', [])
    
    # Check if this is EICAR test file or similar test strings
    is_test_file = False
    test_context = ""
    
    if popular_threat_label and 'eicar' in popular_threat_label.lower():
        is_test_file = True
        test_context = "⚠️ CODE INSIGHT: This is an EICAR test file - a harmless test string used to verify antivirus software functionality. It is NOT a real threat and cannot harm your computer. EICAR is a standardized test that triggers antivirus engines to demonstrate they're working properly."
    elif meaningful_name and 'eicar' in meaningful_name.lower():
        is_test_file = True
        test_context = "⚠️ CODE INSIGHT: This appears to be an EICAR test file based on its name. EICAR is a harmless dummy file used to test antivirus software, not an actual malware."
    elif any('eicar' in tag.lower() for tag in tags):
        is_test_file = True
        test_context = "⚠️ CODE INSIGHT: Tagged as EICAR test file. This is a benign test pattern used by security professionals to verify antivirus detection, not real malware."
    
    malicious_ratio = (malicious / total) * 100
    
    # Build reasoning with context
    reasoning_parts = []
    
    if is_test_file:
        reasoning_parts.append(test_context)
        reasoning_parts.append(f"\nDetection Stats: {malicious}/{total} engines ({malicious_ratio:.1f}%) flagged this (expected for test files).")
        return ("TEST_FILE", " ".join(reasoning_parts), 95)
    
    # Add meaningful context if available
    if popular_threat_label:
        reasoning_parts.append(f"Threat Classification: {popular_threat_label}.")
    
    if meaningful_name:
        reasoning_parts.append(f"Identified as: {meaningful_name}.")
    
    if type_description:
        reasoning_parts.append(f"File Type: {type_description}.")
    
    # Add detection statistics
    if malicious_ratio > 10:
        reasoning_parts.append(f"High malicious detection rate: {malicious}/{total} engines ({malicious_ratio:.1f}%) flagged this as malicious.")
        
        # Add vendor details if available
        malicious_vendors = data.get('malicious_vendors', [])
        if malicious_vendors and len(malicious_vendors) > 0:
            top_detections = [v.get('result', '') for v in malicious_vendors[:3] if v.get('result')]
            if top_detections:
                reasoning_parts.append(f"Common detections: {', '.join(top_detections)}.")
        
        return ("MALICIOUS", " ".join(reasoning_parts), 85)
    elif malicious_ratio > 0:
        reasoning_parts.append(f"Some engines detected threats: {malicious}/{total} engines ({malicious_ratio:.1f}%) flagged this as suspicious.")
        return ("SUSPICIOUS", " ".join(reasoning_parts), 60)
    else:
        reasoning_parts.append(f"Clean scan results: 0/{total} engines detected any threats.")
        return ("BENIGN", " ".join(reasoning_parts), 90)


def _analyze_abuseipdb_fallback(data: dict) -> tuple:
    """Fallback analysis for AbuseIPDB without AI"""
    if not data or 'error' in data:
        return ("ERROR", "No valid AbuseIPDB data available", 0)
    
    confidence = data.get('abuse_confidence', 0)
    reports = data.get('total_reports', 0)
    
    if confidence > 50:
        return ("MALICIOUS", f"High abuse confidence: {confidence}% with {reports} reports indicating malicious activity", 80)
    elif confidence > 10:
        return ("SUSPICIOUS", f"Moderate abuse confidence: {confidence}% with {reports} reports suggesting potential threats", 65)
    else:
        return ("BENIGN", f"Low abuse confidence: {confidence}% with {reports} reports, appears legitimate", 85)


def _analyze_shodan_fallback(data: dict) -> tuple:
    """Fallback analysis for Shodan without AI"""
    if not data or 'error' in data:
        return ("ERROR", "No valid Shodan data available", 0)
    
    vulnerabilities = data.get('vulnerabilities', [])
    ports = data.get('ports', [])
    services = data.get('services', [])
    
    vuln_count = len(vulnerabilities) if vulnerabilities else 0
    
    if vuln_count > 5:
        return ("MALICIOUS", f"Multiple serious vulnerabilities detected: {vuln_count} known CVEs found on open services", 75)
    elif vuln_count > 0:
        return ("SUSPICIOUS", f"Some vulnerabilities detected: {vuln_count} known issues found, requires attention", 60)
    elif len(ports) > 10:
        return ("SUSPICIOUS", f"Many open ports detected: {len(ports)} services exposed, potential attack surface", 50)
    else:
        return ("BENIGN", f"Standard network profile: {len(ports)} services, no significant vulnerabilities detected", 80)


def _analyze_urlscan_fallback(data: dict) -> tuple:
    """Fallback analysis for URLScan without AI"""
    if not data or 'error' in data:
        return ("ERROR", "No valid URLScan data available", 0)
    
    malicious = data.get('malicious', False)
    phishing = data.get('phishing_detected', False)
    verdict = data.get('verdict', 'unknown')
    
    if malicious or phishing:
        return ("MALICIOUS", f"URLScan detected threats: malicious={malicious}, phishing={phishing}, verdict={verdict}", 85)
    elif verdict == 'clean':
        return ("BENIGN", f"URLScan analysis shows clean verdict with no threats detected", 90)
    else:
        return ("SUSPICIOUS", f"URLScan results inconclusive: verdict={verdict}, requires manual review", 40)


def _analyze_misp_fallback(data: dict) -> tuple:
    """Fallback analysis for MISP without AI"""
    if not data or 'error' in data:
        return ("ERROR", "No valid MISP data available", 0)
    
    events_found = data.get('events_found', 0)
    
    if events_found > 3:
        return ("MALICIOUS", f"Multiple threat intelligence events: {events_found} events found in MISP database indicating known threats", 80)
    elif events_found > 0:
        return ("SUSPICIOUS", f"Some threat intelligence available: {events_found} events found, potential indicators of compromise", 65)
    else:
        return ("BENIGN", f"No threat intelligence events found in MISP database", 75)


def _analyze_alienvault_fallback(data: dict) -> tuple:
    """Fallback analysis for AlienVault OTX without AI"""
    if not data or 'error' in data:
        return ("ERROR", "No valid AlienVault OTX data available", 0)
    
    pulse_count = data.get('pulse_count', 0)
    threat_tags = data.get('threat_tags', [])
    malware_families = data.get('malware_families', [])
    adversaries = data.get('adversaries', [])
    reputation = data.get('reputation', 0)
    
    # Check for high-severity indicators
    high_severity_tags = ['malware', 'botnet', 'ransomware', 'apt', 'exploit', 'phishing', 'trojan']
    critical_tags = [tag for tag in threat_tags if any(severity in tag.lower() for severity in high_severity_tags)]
    
    if pulse_count > 5 or len(malware_families) > 0 or len(adversaries) > 0:
        reasoning_parts = [f"High threat intelligence activity: {pulse_count} threat pulse(s) found in AlienVault OTX."]
        
        if malware_families:
            reasoning_parts.append(f"Associated with malware families: {', '.join(malware_families[:3])}.")
        
        if adversaries:
            reasoning_parts.append(f"Linked to threat actors: {', '.join(adversaries)}.")
        
        if critical_tags:
            reasoning_parts.append(f"Critical threat tags: {', '.join(critical_tags[:5])}.")
        
        if reputation < -50:
            reasoning_parts.append(f"Poor reputation score: {reputation}.")
        
        return ("MALICIOUS", " ".join(reasoning_parts), 85)
    
    elif pulse_count > 0:
        reasoning = f"Moderate threat intelligence: {pulse_count} pulse(s) found in AlienVault OTX."
        
        if critical_tags:
            reasoning += f" Tags include: {', '.join(critical_tags[:3])}."
        elif threat_tags:
            reasoning += f" Tags include: {', '.join(threat_tags[:3])}."
        
        return ("SUSPICIOUS", reasoning, 60)
    
    else:
        return ("BENIGN", f"No threat intelligence pulses found in AlienVault OTX database. Reputation: {reputation}", 80)
    """Fallback analysis for MISP without AI"""
    if not data or 'error' in data:
        return ("ERROR", "No valid MISP data available", 0)
    
    events_found = data.get('events_found', 0)
    
    if events_found > 3:
        return ("MALICIOUS", f"Multiple threat intelligence events: {events_found} events found in MISP database indicating known threats", 80)
    elif events_found > 0:
        return ("SUSPICIOUS", f"Some threat intelligence available: {events_found} events found, potential indicators of compromise", 65)
    else:
        return ("BENIGN", f"No threat intelligence events found in MISP database", 75)


def _generate_final_verdict(classifier: ThreatClassifier, ioc: str, ioc_type: str, sources_results: dict, successful_sources: list, analyst_feedback: str = None) -> tuple:
    """Generate final verdict using AI by combining all source results and analyst feedback"""
    try:
        # Log if analyst feedback is present
        if analyst_feedback:
            # Count feedback entries (separated by ----)
            feedback_count = analyst_feedback.count('---') + 1 if '---' in analyst_feedback else 1
            logger.info(f"Analyst feedback detected for IOC {ioc}: {feedback_count} feedback entr{'y' if feedback_count == 1 else 'ies'}")
        else:
            logger.info(f"No analyst feedback for IOC {ioc}")
        
        # Create comprehensive intelligence data for final analysis
        combined_sources = {}
        for source_name in successful_sources:
            source_result = sources_results[source_name]
            if source_result.get('data'):
                combined_sources[source_name] = source_result['data']
        
        intel_data = {
            'ioc': ioc,
            'ioc_type': ioc_type,
            'timestamp': datetime.now().isoformat(),
            'sources': combined_sources
        }
        
        # Get AI classification with enhanced prompt for final verdict
        classification = classifier.classify_threat_final_verdict(intel_data, sources_results, analyst_feedback)
        
        return (
            classification.get('classification', 'UNKNOWN'),
            classification.get('reasoning', 'No reasoning provided'),
            classification.get('confidence_score', 0)
        )
        
    except Exception as e:
        logger.error(f"Final AI verdict failed: {str(e)}")
        return _generate_final_verdict_fallback(sources_results, successful_sources)


def _generate_final_verdict_fallback(sources_results: dict, successful_sources: list) -> tuple:
    """Generate final verdict using fallback logic without AI"""
    if not successful_sources:
        return ("UNKNOWN", "No successful threat intelligence sources available for analysis", 0)
    
    # Collect verdicts from all sources
    verdicts = []
    confidence_scores = []
    reasoning_parts = []
    
    for source_name in successful_sources:
        source_result = sources_results[source_name]
        verdict = source_result.get('verdict', 'UNKNOWN')
        confidence = source_result.get('confidence_score', 0)
        reasoning = source_result.get('reasoning', '')
        
        if verdict != 'UNKNOWN' and verdict != 'ERROR':
            verdicts.append(verdict)
            confidence_scores.append(confidence)
            reasoning_parts.append(f"{source_name.title()}: {reasoning}")
    
    if not verdicts:
        return ("UNKNOWN", "All sources returned inconclusive results", 0)
    
    # Simple voting logic
    malicious_count = verdicts.count('MALICIOUS')
    suspicious_count = verdicts.count('SUSPICIOUS')
    benign_count = verdicts.count('BENIGN')
    
    avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
    
    # Determine final verdict
    if malicious_count > 0:
        final_verdict = "MALICIOUS"
        final_reasoning = f"MALICIOUS verdict reached: {malicious_count} source(s) detected malicious activity. "
    elif suspicious_count > benign_count:
        final_verdict = "SUSPICIOUS"
        final_reasoning = f"SUSPICIOUS verdict reached: {suspicious_count} source(s) found suspicious indicators. "
    elif benign_count > 0:
        final_verdict = "BENIGN"
        final_reasoning = f"BENIGN verdict reached: {benign_count} source(s) found no significant threats. "
    else:
        final_verdict = "UNKNOWN"
        final_reasoning = "Unable to determine verdict from available sources. "
    
    # Add source summaries
    final_reasoning += f"\n\nSource Analysis Summary:\n" + "\n".join(reasoning_parts)
    
    return (final_verdict, final_reasoning, int(avg_confidence))


@router.post("/compare-analyses", response_model=dict)
async def compare_analyses(
    old_analysis: dict,
    new_analysis: dict,
    settings: Settings = Depends(get_settings)
):
    """
    Compare two IOC analyses and generate AI-powered insights about the differences
    
    Args:
        old_analysis: Previous analysis result with verdict, sources, etc.
        new_analysis: New analysis result with verdict, sources, etc.
        
    Returns:
        Comparison result with changes, summary, and AI-generated insights
    """
    start_time = time.time()
    
    try:
        # Extract key information from both analyses
        old_verdict = old_analysis.get('final_verdict', {}).get('verdict', 'UNKNOWN')
        new_verdict = new_analysis.get('final_verdict', {}).get('verdict', 'UNKNOWN')
        
        old_confidence = old_analysis.get('final_verdict', {}).get('confidence_score', 0)
        new_confidence = new_analysis.get('final_verdict', {}).get('confidence_score', 0)
        
        old_sources = old_analysis.get('sources', {})
        new_sources = new_analysis.get('sources', {})
        
        ioc = new_analysis.get('ioc', 'Unknown IOC')
        
        # Compare verdicts
        verdict_changed = old_verdict != new_verdict
        confidence_change = new_confidence - old_confidence
        
        # Compare source-level changes
        source_changes = {}
        all_sources = set(list(old_sources.keys()) + list(new_sources.keys()))
        
        for source in all_sources:
            old_source_data = old_sources.get(source, {})
            new_source_data = new_sources.get(source, {})
            
            old_source_verdict = old_source_data.get('verdict', 'UNKNOWN')
            new_source_verdict = new_source_data.get('verdict', 'UNKNOWN')
            
            if old_source_verdict != new_source_verdict:
                source_changes[source] = {
                    'old_verdict': old_source_verdict,
                    'new_verdict': new_source_verdict,
                    'changed': True
                }
            else:
                source_changes[source] = {
                    'verdict': new_source_verdict,
                    'changed': False
                }
        
        # Generate AI-powered comparison insights
        ai_insights = ""
        risk_assessment = "UNCHANGED"
        
        if settings.openai_api_key:
            try:
                classifier = ThreatClassifier(settings.openai_api_key)
                
                comparison_prompt = f"""Compare these two threat intelligence analyses for IOC: {ioc}

OLD ANALYSIS:
- Verdict: {old_verdict}
- Confidence: {old_confidence}%
- Sources: {', '.join(old_sources.keys())}

NEW ANALYSIS:
- Verdict: {new_verdict}
- Confidence: {new_confidence}%
- Sources: {', '.join(new_sources.keys())}

SOURCE-LEVEL CHANGES:
{_format_source_changes(source_changes)}

Provide a concise analysis covering:
1. What changed and why it matters
2. Risk level assessment (INCREASED, DECREASED, or UNCHANGED)
3. Recommended actions if any
4. Key takeaways

Keep your response focused and actionable (max 250 words)."""

                ai_insights = classifier._call_openai(comparison_prompt)
                
                # Determine risk assessment
                if verdict_changed:
                    if (old_verdict in ['BENIGN', 'UNKNOWN'] and new_verdict == 'MALICIOUS') or \
                       (old_verdict == 'BENIGN' and new_verdict == 'SUSPICIOUS'):
                        risk_assessment = "INCREASED"
                    elif (old_verdict in ['MALICIOUS', 'SUSPICIOUS'] and new_verdict == 'BENIGN') or \
                         (old_verdict == 'MALICIOUS' and new_verdict == 'SUSPICIOUS'):
                        risk_assessment = "DECREASED"
                elif confidence_change > 15:
                    risk_assessment = "INCREASED"
                elif confidence_change < -15:
                    risk_assessment = "DECREASED"
                    
            except Exception as e:
                logger.error(f"AI comparison error: {str(e)}")
                ai_insights = "AI-powered comparison unavailable. Please review the data manually."
        else:
            ai_insights = "OpenAI API key not configured. AI-powered insights unavailable."
        
        return {
            "success": True,
            "ioc": ioc,
            "comparison": {
                "verdict_changed": verdict_changed,
                "old_verdict": old_verdict,
                "new_verdict": new_verdict,
                "confidence_change": confidence_change,
                "old_confidence": old_confidence,
                "new_confidence": new_confidence,
                "risk_assessment": risk_assessment,
                "source_changes": source_changes,
                "sources_analyzed": len(all_sources),
                "sources_changed": sum(1 for s in source_changes.values() if s.get('changed', False))
            },
            "ai_insights": ai_insights,
            "old_analysis_timestamp": old_analysis.get('timestamp', 'Unknown'),
            "new_analysis_timestamp": new_analysis.get('timestamp', datetime.utcnow().isoformat()),
            "processing_time_ms": int((time.time() - start_time) * 1000)
        }
        
    except Exception as e:
        logger.error(f"Comparison error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Comparison failed: {str(e)}")


def _format_source_changes(source_changes: dict) -> str:
    """Format source changes for AI prompt"""
    formatted = []
    for source, change_data in source_changes.items():
        if change_data.get('changed', False):
            formatted.append(f"- {source}: {change_data['old_verdict']} → {change_data['new_verdict']}")
        else:
            formatted.append(f"- {source}: {change_data.get('verdict', 'UNKNOWN')} (unchanged)")
    return '\n'.join(formatted) if formatted else "No changes detected"