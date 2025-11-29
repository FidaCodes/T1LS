from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
import logging
import time
from datetime import datetime

from app.core.config import load_settings
from app.api import threat_intel, system
from app.models import ErrorResponse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load settings
settings = load_settings()

# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
    **Threat Intelligence Analyzer API**
    
    A comprehensive threat intelligence analysis system that collects IOC data from multiple sources 
    and uses AI to classify threats as MALICIOUS, SUSPICIOUS, or BENIGN.
    
    ## Features
    
    * **Multi-Source Intelligence**: VirusTotal, AbuseIPDB, MISP
    * **AI Classification**: OpenAI GPT-4 powered threat analysis
    * **Multiple IOC Types**: IPs, domains, file hashes
    * **Batch Processing**: Analyze multiple IOCs simultaneously
    * **RESTful API**: Clean, documented endpoints
    
    ## Supported IOC Types
    
    * **IP Addresses**: IPv4 and IPv6 addresses
    * **Domain Names**: Fully qualified domain names
    * **File Hashes**: MD5, SHA1, SHA256 hashes
    
    ## Authentication
    
    This API uses API keys configured server-side. No authentication required for clients.
    
    ## Rate Limits
    
    Please respect rate limits to ensure fair usage for all users.
    """,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(f"{process_time:.4f}")
    return response

# Logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # Log request
    logger.info(f"Request: {request.method} {request.url}")
    
    response = await call_next(request)
    
    # Log response
    process_time = time.time() - start_time
    logger.info(f"Response: {response.status_code} - {process_time:.4f}s")
    
    return response

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception handler caught: {type(exc).__name__}: {str(exc)}")
    
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal server error",
            detail=str(exc) if settings.debug else "An unexpected error occurred",
            timestamp=datetime.now()
        ).dict()
    )

# HTTP exception handler
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.detail,
            detail=getattr(exc, 'detail', None),
            timestamp=datetime.now()
        ).dict()
    )

# Include routers
app.include_router(threat_intel.router)
app.include_router(system.router)

# Root endpoint
@app.get("/")
async def root():
    """
    Root endpoint with API information
    """
    return {
        "message": f"Welcome to {settings.app_name}",
        "version": settings.app_version,
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "documentation": "/docs" if settings.debug else "Documentation disabled in production",
        "endpoints": {
            "health": "/health",
            "status": "/status", 
            "info": "/info",
            "analyze_all": "/api/v1/analyze/all-sources",
            "analyze_combined": "/api/v1/analyze",
            "virustotal": "/api/v1/virustotal",
            "abuseipdb": "/api/v1/abuseipdb",
            "shodan": "/api/v1/shodan",
            "urlscan": "/api/v1/urlscan",
            "misp": "/api/v1/misp",
            "batch_analyze": "/api/v1/analyze/batch"
        }
    }

# Custom OpenAPI schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title=settings.app_name,
        version=settings.app_version,
        description=app.description,
        routes=app.routes,
    )
    
    # Add custom tags
    openapi_schema["tags"] = [
        {
            "name": "Threat Intelligence",
            "description": "IOC analysis and threat classification endpoints"
        },
        {
            "name": "System",
            "description": "System health, status, and information endpoints"
        }
    ]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Startup event
@app.on_event("startup")
async def startup_event():
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    
    # Check available threat intelligence sources
    from app.core.config import get_threat_intel_config
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
    
    logger.info(f"Available threat intelligence sources: {', '.join(available_sources) if available_sources else 'None'}")
    logger.info(f"AI classification: {'Enabled' if settings.openai_api_key else 'Disabled'}")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info("Application startup complete")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down application")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info"
    )
