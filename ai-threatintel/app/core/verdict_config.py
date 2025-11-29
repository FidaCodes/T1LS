"""
Verdict Aggregation Configuration

This file defines configurable weights for different threat intelligence sources.
Weights can be customized per deployment or per customer to reflect their trust
levels in different sources.
"""

from typing import Dict, Any
from app.services.verdict_aggregation import SourceType


# Default source weights configuration
DEFAULT_SOURCE_WEIGHTS = {
    # Generic threat intelligence sources
    SourceType.GENERIC_THREAT_INTEL: {
        'VirusTotal': 0.85,         # Highly reliable, large vendor coverage
        'AbuseIPDB': 0.80,          # Good for IP reputation, community-driven
        'OTX': 0.75,                # AlienVault Open Threat Exchange - good pulse data
        'ThreatFox': 0.75,          # Abuse.ch threat intel
        'URLhaus': 0.75,            # Abuse.ch URL threat intel
        'IPQualityScore': 0.70,     # Commercial IP scoring service
        'PhishTank': 0.70,          # Phishing-specific database
        'Shodan': 0.65,             # Internet scanning, good for context
        'URLScan': 0.70,            # URL scanning service
        'GreyNoise': 0.65,          # Internet noise classification
        'default': 0.60             # Default weight for unknown sources
    },
    
    # Customer-specific ML models - highest weight for contextual intelligence
    SourceType.CUSTOMER_ML_MODEL: 0.90,
    
    # LLM-based analysis
    SourceType.LLM_ANALYSIS: 0.75
}


# Customer-specific weight overrides (example)
# Format: customer_id -> source weights
CUSTOMER_SPECIFIC_WEIGHTS = {
    # Example: Customer 1 trusts their ML model more and specific sources less
    'customer1': {
        SourceType.CUSTOMER_ML_MODEL: 0.95,
        SourceType.GENERIC_THREAT_INTEL: {
            'VirusTotal': 0.80,
            'AbuseIPDB': 0.75,
        }
    },
    
    # Example: Customer 2 focuses on phishing, so PhishTank gets higher weight
    'customer2': {
        SourceType.GENERIC_THREAT_INTEL: {
            'PhishTank': 0.85,
            'URLhaus': 0.80,
        }
    }
}


# Threat level score thresholds (can be adjusted for more/less sensitivity)
THREAT_SCORE_THRESHOLDS = {
    'critical': 4.5,    # Very high confidence of severe threat
    'high': 3.5,        # High confidence of significant threat
    'medium': 2.5,      # Moderate threat indicators
    'low': 1.5,         # Some suspicious activity
    'safe': 0.5         # Likely benign
}


# Agreement level thresholds for disagreement handling
AGREEMENT_THRESHOLDS = {
    'strong_consensus': 0.8,      # Sources strongly agree
    'moderate_agreement': 0.6,    # Sources somewhat agree
    'significant_disagreement': 0.5  # Trigger conservative escalation
}


# Confidence adjustment factors
CONFIDENCE_ADJUSTMENTS = {
    'data_age_penalty': {
        'enabled': True,
        'threshold_hours': 24,
        'max_penalty': 0.15,        # Max 15% confidence reduction
        'decay_period_hours': 168   # Over 1 week
    },
    
    'source_reliability_boost': {
        'enabled': True,
        'high_reliability_boost': 1.1,  # 10% boost for highly reliable sources
        'low_reliability_penalty': 0.9   # 10% penalty for less reliable sources
    },
    
    'multiple_source_boost': {
        'enabled': True,
        'min_sources': 3,
        'boost_factor': 1.05        # 5% boost when 3+ sources agree
    }
}


# Escalation rules for disagreement scenarios
DISAGREEMENT_RULES = {
    'escalate_on_any_critical': {
        'enabled': True,
        'min_confidence': 0.7,
        'escalate_to': 'medium'     # Escalate to at least MEDIUM if any source says CRITICAL
    },
    
    'conservative_on_disagreement': {
        'enabled': True,
        'agreement_threshold': 0.5,
        'prefer_higher_threat': True  # When in doubt, prefer higher threat level
    }
}


def get_weights_for_customer(customer_id: str = None) -> Dict[Any, Any]:
    """
    Get the appropriate weights configuration for a customer
    
    Args:
        customer_id: Optional customer identifier
        
    Returns:
        Dictionary of weights (either customer-specific or default)
    """
    if customer_id and customer_id in CUSTOMER_SPECIFIC_WEIGHTS:
        # Merge customer-specific weights with defaults
        weights = DEFAULT_SOURCE_WEIGHTS.copy()
        customer_weights = CUSTOMER_SPECIFIC_WEIGHTS[customer_id]
        
        for source_type, weight_value in customer_weights.items():
            if isinstance(weight_value, dict):
                # Merge nested dictionaries
                if source_type not in weights:
                    weights[source_type] = {}
                weights[source_type].update(weight_value)
            else:
                weights[source_type] = weight_value
        
        return weights
    
    return DEFAULT_SOURCE_WEIGHTS


def get_thresholds() -> Dict[str, float]:
    """Get threat score thresholds"""
    return THREAT_SCORE_THRESHOLDS.copy()


def get_confidence_adjustments() -> Dict[str, Any]:
    """Get confidence adjustment configuration"""
    return CONFIDENCE_ADJUSTMENTS.copy()


def get_disagreement_rules() -> Dict[str, Any]:
    """Get disagreement handling rules"""
    return DISAGREEMENT_RULES.copy()


def get_agreement_thresholds() -> Dict[str, float]:
    """Get agreement level thresholds"""
    return AGREEMENT_THRESHOLDS.copy()


# Example configuration for different deployment scenarios
DEPLOYMENT_PROFILES = {
    # Conservative profile - prefers false positives over false negatives
    'conservative': {
        'thresholds': {
            'critical': 4.0,
            'high': 3.0,
            'medium': 2.0,
            'low': 1.0,
            'safe': 0.5
        },
        'escalation': {
            'escalate_on_any_critical': True,
            'agreement_threshold': 0.4
        }
    },
    
    # Balanced profile - default behavior
    'balanced': {
        'thresholds': THREAT_SCORE_THRESHOLDS,
        'escalation': DISAGREEMENT_RULES
    },
    
    # Aggressive profile - requires stronger evidence, reduces false positives
    'aggressive': {
        'thresholds': {
            'critical': 5.0,
            'high': 4.0,
            'medium': 3.0,
            'low': 2.0,
            'safe': 1.0
        },
        'escalation': {
            'escalate_on_any_critical': False,
            'agreement_threshold': 0.6
        }
    }
}


def get_deployment_profile(profile_name: str = 'balanced') -> Dict[str, Any]:
    """
    Get configuration for a specific deployment profile
    
    Args:
        profile_name: Name of the profile (conservative, balanced, aggressive)
        
    Returns:
        Configuration dictionary for the profile
    """
    return DEPLOYMENT_PROFILES.get(profile_name, DEPLOYMENT_PROFILES['balanced'])
