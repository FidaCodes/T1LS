"""
Enhanced Threat Intelligence Orchestrator

This module orchestrates the collection of threat intelligence from multiple sources,
including generic threat intel APIs and LLM analysis,
then aggregates them into a final weighted verdict.
"""

from typing import Dict, Optional, Any, List
from datetime import datetime

from app.services.threat_intel_collector import ThreatIntelligenceCollector
from app.services.verdict_aggregation import (
    VerdictAggregationService,
    SourceVerdict,
    ThreatLevel,
    SourceType,
    AggregatedVerdict
)
from app.utils.validators import determine_ioc_type


class ThreatIntelOrchestrator:
    """
    Orchestrates threat intelligence collection and verdict aggregation
    
    Workflow:
    1. Collect intelligence from generic sources (VirusTotal, AbuseIPDB, etc.)
    2. Optionally use LLM for analysis
    3. Aggregate all verdicts with weighted scoring
    4. Return final verdict with confidence and reasoning
    """
    
    def __init__(
        self,
        config: Dict[str, str],
        custom_weights: Optional[Dict] = None
    ):
        """
        Initialize the orchestrator
        
        Args:
            config: Configuration with API keys for threat intel sources
            custom_weights: Custom weights for verdict aggregation
        """
        self.threat_intel_collector = ThreatIntelligenceCollector(config)
        self.verdict_aggregator = VerdictAggregationService(custom_weights)
        self.config = config
    
    def _convert_virustotal_to_verdict(self, vt_data: Dict, ioc: str) -> Optional[SourceVerdict]:
        """Convert VirusTotal response to SourceVerdict"""
        if not vt_data or 'error' in vt_data:
            return None
        
        malicious = vt_data.get('malicious_count', 0)
        suspicious = vt_data.get('suspicious_count', 0)
        total = vt_data.get('total_engines', 0)
        
        if total == 0:
            return None
        
        # Calculate threat level based on detection ratio
        detection_ratio = (malicious + suspicious) / total if total > 0 else 0
        
        if detection_ratio >= 0.7:
            threat_level = ThreatLevel.CRITICAL
        elif detection_ratio >= 0.5:
            threat_level = ThreatLevel.HIGH
        elif detection_ratio >= 0.3:
            threat_level = ThreatLevel.MEDIUM
        elif detection_ratio >= 0.1:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.SAFE
        
        # Confidence based on number of engines and reputation
        base_confidence = min(total / 70, 1.0)  # Normalize by ~70 engines
        reputation = vt_data.get('reputation', 0)
        if reputation < 0:
            base_confidence = min(base_confidence * 1.1, 1.0)
        
        return SourceVerdict(
            source_name="VirusTotal",
            source_type=SourceType.GENERIC_THREAT_INTEL,
            threat_level=threat_level,
            confidence=base_confidence,
            raw_score=detection_ratio,
            details={
                'malicious_count': malicious,
                'suspicious_count': suspicious,
                'total_engines': total,
                'detection_ratio': detection_ratio,
                'reputation': reputation,
                'tags': vt_data.get('tags', [])
            },
            timestamp=datetime.now()
        )
    
    def _convert_abuseipdb_to_verdict(self, abuse_data: Dict, ioc: str) -> Optional[SourceVerdict]:
        """Convert AbuseIPDB response to SourceVerdict"""
        if not abuse_data or 'error' in abuse_data:
            return None
        
        confidence_score = abuse_data.get('abuse_confidence', 0) / 100.0  # Convert to 0-1
        
        # Determine threat level based on abuse confidence
        if confidence_score >= 0.8:
            threat_level = ThreatLevel.CRITICAL
        elif confidence_score >= 0.6:
            threat_level = ThreatLevel.HIGH
        elif confidence_score >= 0.4:
            threat_level = ThreatLevel.MEDIUM
        elif confidence_score >= 0.2:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.SAFE
        
        # Use total reports as confidence modifier
        total_reports = abuse_data.get('total_reports', 0)
        report_confidence = min(total_reports / 50, 1.0)  # Normalize by 50 reports
        final_confidence = (confidence_score + report_confidence) / 2
        
        return SourceVerdict(
            source_name="AbuseIPDB",
            source_type=SourceType.GENERIC_THREAT_INTEL,
            threat_level=threat_level,
            confidence=final_confidence,
            raw_score=confidence_score,
            details={
                'abuse_confidence': abuse_data.get('abuse_confidence', 0),
                'total_reports': total_reports,
                'country': abuse_data.get('country_name', ''),
                'isp': abuse_data.get('isp', ''),
                'usage_type': abuse_data.get('usage_type', '')
            },
            timestamp=datetime.now()
        )
    
    def _convert_otx_to_verdict(self, otx_data: Dict, ioc: str) -> Optional[SourceVerdict]:
        """Convert AlienVault OTX response to SourceVerdict"""
        if not otx_data or 'error' in otx_data:
            return None
        
        pulse_count = otx_data.get('pulse_count', 0)
        pulse_info = otx_data.get('pulse_info', {})
        pulses = pulse_info.get('pulses', [])
        
        # Analyze pulse severity
        malicious_pulses = len([p for p in pulses if 'malware' in str(p).lower() or 'exploit' in str(p).lower()])
        
        # Calculate threat score
        if pulse_count > 10:
            threat_level = ThreatLevel.HIGH
        elif pulse_count > 5:
            threat_level = ThreatLevel.MEDIUM
        elif pulse_count > 0:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.SAFE
        
        # Boost if many pulses are malware-related
        if malicious_pulses > pulse_count * 0.5 and pulse_count > 0:
            if threat_level == ThreatLevel.HIGH:
                threat_level = ThreatLevel.CRITICAL
            elif threat_level == ThreatLevel.MEDIUM:
                threat_level = ThreatLevel.HIGH
        
        confidence = min(pulse_count / 20, 0.9)  # OTX is generally reliable but not as comprehensive
        
        return SourceVerdict(
            source_name="OTX",
            source_type=SourceType.GENERIC_THREAT_INTEL,
            threat_level=threat_level,
            confidence=confidence,
            raw_score=pulse_count,
            details={
                'pulse_count': pulse_count,
                'malicious_pulses': malicious_pulses,
                'pulse_names': [p.get('name', '') for p in pulses[:5]]
            },
            timestamp=datetime.now()
        )
    
    def _create_llm_verdict(self, llm_analysis: Dict, ioc: str) -> Optional[SourceVerdict]:
        """Convert LLM analysis to SourceVerdict"""
        if not llm_analysis:
            return None
        
        # Parse LLM verdict (this depends on your LLM response format)
        verdict_str = llm_analysis.get('verdict', 'unknown').lower()
        confidence = llm_analysis.get('confidence', 0.7)
        
        # Map verdict string to ThreatLevel
        threat_level_map = {
            'critical': ThreatLevel.CRITICAL,
            'high': ThreatLevel.HIGH,
            'medium': ThreatLevel.MEDIUM,
            'low': ThreatLevel.LOW,
            'safe': ThreatLevel.SAFE,
            'benign': ThreatLevel.SAFE,
            'malicious': ThreatLevel.HIGH,
            'suspicious': ThreatLevel.MEDIUM
        }
        
        threat_level = threat_level_map.get(verdict_str, ThreatLevel.UNKNOWN)
        
        return SourceVerdict(
            source_name="LLM-Analysis",
            source_type=SourceType.LLM_ANALYSIS,
            threat_level=threat_level,
            confidence=confidence,
            raw_score=confidence,
            details={
                'analysis': llm_analysis.get('analysis', ''),
                'reasoning': llm_analysis.get('reasoning', ''),
                'categories': llm_analysis.get('categories', [])
            },
            timestamp=datetime.now()
        )
    
    def analyze_ioc(
        self,
        ioc: str,
        ioc_type: Optional[str] = None,
        include_llm: bool = False
    ) -> AggregatedVerdict:
        """
        Analyze an IOC using all available intelligence sources
        
        Args:
            ioc: Indicator of Compromise to analyze
            ioc_type: Optional IOC type (auto-detected if not provided)
            include_llm: Whether to include LLM analysis (default: False for performance)
            
        Returns:
            AggregatedVerdict with final determination
        """
        # Determine IOC type if not provided
        if not ioc_type:
            ioc_type = determine_ioc_type(ioc)
        
        source_verdicts: List[SourceVerdict] = []
        
        # Step 1: Collect from generic threat intel sources
        print(f"Querying generic threat intelligence sources for {ioc}...")
        
        # VirusTotal
        vt_data = self.threat_intel_collector.query_virustotal(ioc, ioc_type)
        if vt_data:
            vt_verdict = self._convert_virustotal_to_verdict(vt_data, ioc)
            if vt_verdict:
                source_verdicts.append(vt_verdict)
        
        # AbuseIPDB (IP only)
        if ioc_type == 'ip':
            abuse_data = self.threat_intel_collector.query_abuseipdb(ioc, ioc_type)
            if abuse_data:
                abuse_verdict = self._convert_abuseipdb_to_verdict(abuse_data, ioc)
                if abuse_verdict:
                    source_verdicts.append(abuse_verdict)
        
        # AlienVault OTX
        otx_data = self.threat_intel_collector.query_alienvault_otx(ioc, ioc_type)
        if otx_data:
            otx_verdict = self._convert_otx_to_verdict(otx_data, ioc)
            if otx_verdict:
                source_verdicts.append(otx_verdict)
        
        # Step 2: LLM Analysis (optional, can be expensive)
        if include_llm:
            # TODO: Implement LLM analysis call
            # This would call your existing LLM threat classification
            print("LLM analysis not yet implemented in orchestrator")
            pass
        
        # Step 3: Aggregate all verdicts
        print(f"Aggregating {len(source_verdicts)} verdicts...")
        aggregated_verdict = self.verdict_aggregator.aggregate_verdicts(
            source_verdicts=source_verdicts,
            ioc=ioc,
            ioc_type=ioc_type
        )
        
        return aggregated_verdict
    
    def analyze_ioc_detailed(
        self,
        ioc: str,
        ioc_type: Optional[str] = None,
        include_llm: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze an IOC and return detailed explanation
        
        Returns both the verdict and detailed explanation of the scoring logic
        """
        aggregated_verdict = self.analyze_ioc(ioc, ioc_type, include_llm)
        
        explanation = self.verdict_aggregator.explain_verdict(aggregated_verdict)
        
        return {
            'verdict': {
                'final_verdict': aggregated_verdict.final_verdict.value,
                'confidence': aggregated_verdict.confidence_score,
                'weighted_score': aggregated_verdict.weighted_score,
                'agreement_level': aggregated_verdict.agreement_level,
                'reasoning': aggregated_verdict.reasoning
            },
            'metadata': aggregated_verdict.metadata,
            'detailed_explanation': explanation,
            'timestamp': aggregated_verdict.timestamp.isoformat()
        }
    

