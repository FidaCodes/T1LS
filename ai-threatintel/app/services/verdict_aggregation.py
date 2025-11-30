"""
Verdict Aggregation Service

This service aggregates threat intelligence verdicts from multiple sources:
- Generic threat intel sources (VirusTotal, AbuseIPDB, etc.)
- LLM-based analysis

It provides a weighted scoring system to determine the final verdict with confidence levels.
"""

from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass
from datetime import datetime


class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"
    UNKNOWN = "unknown"


class SourceType(Enum):
    """Types of intelligence sources"""
    GENERIC_THREAT_INTEL = "generic_threat_intel"
    LLM_ANALYSIS = "llm_analysis"


@dataclass
class SourceVerdict:
    """Verdict from a single intelligence source"""
    source_name: str
    source_type: SourceType
    threat_level: ThreatLevel
    confidence: float  # 0.0 to 1.0
    raw_score: float  # Original score from the source
    details: Dict[str, Any]
    timestamp: datetime
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AggregatedVerdict:
    """Final aggregated verdict with confidence and breakdown"""
    final_verdict: ThreatLevel
    confidence_score: float  # 0.0 to 1.0
    weighted_score: float  # Calculated weighted score
    reasoning: str
    source_verdicts: List[SourceVerdict]
    agreement_level: float  # How much sources agree (0.0 to 1.0)
    timestamp: datetime
    metadata: Dict[str, Any]


class VerdictAggregationService:
    """
    Aggregates and weighs verdicts from multiple threat intelligence sources
    
    Scoring Logic:
    - Each source provides a verdict with confidence
    - Sources are weighted based on type and reliability
    - Final score is calculated using weighted average
    - Agreement between sources boosts confidence
    - Disagreement triggers cautious verdict elevation
    """
    
    # Default weights for different source types (0.0 to 1.0)
    DEFAULT_WEIGHTS = {
        SourceType.GENERIC_THREAT_INTEL: {
            'VirusTotal': 0.85,
            'AbuseIPDB': 0.80,
            'OTX': 0.75,
            'ThreatFox': 0.75,
            'IPQualityScore': 0.70,
            'URLhaus': 0.75,
            'PhishTank': 0.70,
            'default': 0.60
        },
        SourceType.LLM_ANALYSIS: 0.75
    }
    
    # Threat level numeric mapping for calculations
    THREAT_LEVEL_SCORES = {
        ThreatLevel.CRITICAL: 5.0,
        ThreatLevel.HIGH: 4.0,
        ThreatLevel.MEDIUM: 3.0,
        ThreatLevel.LOW: 2.0,
        ThreatLevel.SAFE: 1.0,
        ThreatLevel.UNKNOWN: 0.0
    }
    
    # Score ranges for final verdict determination
    SCORE_THRESHOLDS = {
        ThreatLevel.CRITICAL: 4.5,
        ThreatLevel.HIGH: 3.5,
        ThreatLevel.MEDIUM: 2.5,
        ThreatLevel.LOW: 1.5,
        ThreatLevel.SAFE: 0.5
    }
    
    def __init__(self, custom_weights: Optional[Dict] = None):
        """
        Initialize the aggregation service
        
        Args:
            custom_weights: Optional custom weights to override defaults
        """
        self.weights = self.DEFAULT_WEIGHTS.copy()
        if custom_weights:
            self._update_weights(custom_weights)
    
    def _update_weights(self, custom_weights: Dict):
        """Update weights with custom values"""
        for source_type, weight_value in custom_weights.items():
            if isinstance(source_type, str):
                source_type = SourceType(source_type)
            
            if isinstance(weight_value, dict):
                if source_type not in self.weights:
                    self.weights[source_type] = {}
                self.weights[source_type].update(weight_value)
            else:
                self.weights[source_type] = weight_value
    
    def _get_source_weight(self, source_verdict: SourceVerdict) -> float:
        """Get the weight for a specific source"""
        source_type = source_verdict.source_type
        source_name = source_verdict.source_name
        
        # Get weight based on source type
        if source_type == SourceType.GENERIC_THREAT_INTEL:
            weights_dict = self.weights.get(source_type, {})
            return weights_dict.get(source_name, weights_dict.get('default', 0.60))
        else:
            return self.weights.get(source_type, 0.70)
    
    def _normalize_confidence(self, source_verdict: SourceVerdict) -> float:
        """
        Normalize and adjust confidence based on various factors
        
        Factors considered:
        - Source reliability
        - Data freshness
        - Historical accuracy (could be added with tracking)
        """
        base_confidence = source_verdict.confidence
        
        # Adjust confidence based on source weight
        source_weight = self._get_source_weight(source_verdict)
        adjusted_confidence = base_confidence * source_weight
        
        # Penalize old data (if timestamp is provided)
        if source_verdict.timestamp:
            age_hours = (datetime.now() - source_verdict.timestamp).total_seconds() / 3600
            if age_hours > 24:
                # Reduce confidence for data older than 24 hours
                age_penalty = max(0.85, 1.0 - (age_hours - 24) / (7 * 24))  # Max 15% reduction over a week
                adjusted_confidence *= age_penalty
        
        return min(1.0, adjusted_confidence)
    
    def _calculate_agreement_level(self, source_verdicts: List[SourceVerdict]) -> float:
        """
        Calculate how much sources agree with each other
        
        Returns:
            Agreement score from 0.0 (complete disagreement) to 1.0 (perfect agreement)
        """
        if len(source_verdicts) < 2:
            return 1.0  # Single source is perfect agreement with itself
        
        # Convert verdicts to numeric scores
        scores = [self.THREAT_LEVEL_SCORES[sv.threat_level] for sv in source_verdicts]
        
        # Calculate variance
        mean_score = sum(scores) / len(scores)
        variance = sum((score - mean_score) ** 2 for score in scores) / len(scores)
        
        # Normalize variance to 0-1 scale (max variance is 4.0 for our 1-5 scale)
        max_variance = 4.0
        normalized_variance = min(variance / max_variance, 1.0)
        
        # Agreement is inverse of variance
        agreement = 1.0 - normalized_variance
        
        return agreement
    
    def _calculate_weighted_score(self, source_verdicts: List[SourceVerdict]) -> tuple[float, float]:
        """
        Calculate weighted score from all sources
        
        Returns:
            Tuple of (weighted_score, total_confidence)
        """
        if not source_verdicts:
            return 0.0, 0.0
        
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for verdict in source_verdicts:
            # Get threat level numeric score
            threat_score = self.THREAT_LEVEL_SCORES[verdict.threat_level]
            
            # Get source weight
            source_weight = self._get_source_weight(verdict)
            
            # Get normalized confidence
            confidence = self._normalize_confidence(verdict)
            
            # Calculate contribution (score * confidence * source_weight)
            contribution = threat_score * confidence * source_weight
            
            total_weighted_score += contribution
            total_weight += (confidence * source_weight)
        
        # Calculate final weighted score
        if total_weight > 0:
            weighted_score = total_weighted_score / total_weight
        else:
            weighted_score = 0.0
        
        # Calculate overall confidence (normalized by max possible weight)
        max_possible_weight = len(source_verdicts) * 1.0  # Max weight * max confidence
        confidence_score = min(1.0, total_weight / max_possible_weight) if max_possible_weight > 0 else 0.0
        
        return weighted_score, confidence_score
    
    def _determine_threat_level(self, weighted_score: float) -> ThreatLevel:
        """Determine threat level based on weighted score"""
        if weighted_score >= self.SCORE_THRESHOLDS[ThreatLevel.CRITICAL]:
            return ThreatLevel.CRITICAL
        elif weighted_score >= self.SCORE_THRESHOLDS[ThreatLevel.HIGH]:
            return ThreatLevel.HIGH
        elif weighted_score >= self.SCORE_THRESHOLDS[ThreatLevel.MEDIUM]:
            return ThreatLevel.MEDIUM
        elif weighted_score >= self.SCORE_THRESHOLDS[ThreatLevel.LOW]:
            return ThreatLevel.LOW
        elif weighted_score >= self.SCORE_THRESHOLDS[ThreatLevel.SAFE]:
            return ThreatLevel.SAFE
        else:
            return ThreatLevel.UNKNOWN
    
    def _apply_disagreement_rules(
        self, 
        initial_verdict: ThreatLevel, 
        source_verdicts: List[SourceVerdict],
        agreement_level: float
    ) -> ThreatLevel:
        """
        Apply rules for handling disagreement between sources
        
        Conservative approach: When sources strongly disagree and any source
        indicates high threat, escalate the verdict for safety.
        """
        if agreement_level < 0.5:  # Significant disagreement
            # Check if any high-confidence source indicates serious threat
            for verdict in source_verdicts:
                if verdict.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                    if verdict.confidence > 0.7:
                        # Escalate to at least MEDIUM if not already higher
                        if self.THREAT_LEVEL_SCORES[initial_verdict] < self.THREAT_LEVEL_SCORES[ThreatLevel.MEDIUM]:
                            return ThreatLevel.MEDIUM
        
        return initial_verdict
    
    def _generate_reasoning(
        self,
        final_verdict: ThreatLevel,
        weighted_score: float,
        confidence_score: float,
        agreement_level: float,
        source_verdicts: List[SourceVerdict]
    ) -> str:
        """Generate human-readable reasoning for the verdict"""
        reasoning_parts = []
        
        # Overall verdict
        reasoning_parts.append(
            f"Final verdict: {final_verdict.value.upper()} "
            f"(score: {weighted_score:.2f}, confidence: {confidence_score:.1%})"
        )
        
        # Agreement analysis
        if agreement_level >= 0.8:
            reasoning_parts.append(f"Strong consensus among sources ({agreement_level:.1%} agreement).")
        elif agreement_level >= 0.6:
            reasoning_parts.append(f"Moderate agreement among sources ({agreement_level:.1%} agreement).")
        else:
            reasoning_parts.append(f"Significant disagreement among sources ({agreement_level:.1%} agreement).")
        
        # Source breakdown
        source_breakdown = {}
        for verdict in source_verdicts:
            level = verdict.threat_level.value
            source_breakdown[level] = source_breakdown.get(level, 0) + 1
        
        breakdown_str = ", ".join([f"{count} {level}" for level, count in source_breakdown.items()])
        reasoning_parts.append(f"Source breakdown: {breakdown_str}.")
        
        # Highlight key sources
        high_confidence_sources = [
            sv for sv in source_verdicts 
            if sv.confidence > 0.8 and sv.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]
        ]
        
        if high_confidence_sources:
            sources_str = ", ".join([sv.source_name for sv in high_confidence_sources[:3]])
            reasoning_parts.append(f"High-confidence threats detected by: {sources_str}.")
        
        return " ".join(reasoning_parts)
    
    def aggregate_verdicts(
        self,
        source_verdicts: List[SourceVerdict],
        ioc: str,
        ioc_type: str
    ) -> AggregatedVerdict:
        """
        Aggregate verdicts from multiple sources into a final verdict
        
        Args:
            source_verdicts: List of verdicts from different sources
            ioc: The indicator being analyzed
            ioc_type: Type of IOC (ip, domain, url, hash, etc.)
            
        Returns:
            AggregatedVerdict with final determination
        """
        if not source_verdicts:
            return AggregatedVerdict(
                final_verdict=ThreatLevel.UNKNOWN,
                confidence_score=0.0,
                weighted_score=0.0,
                reasoning="No intelligence sources provided verdicts.",
                source_verdicts=[],
                agreement_level=0.0,
                timestamp=datetime.now(),
                metadata={'ioc': ioc, 'ioc_type': ioc_type}
            )
        
        # Calculate weighted score and confidence
        weighted_score, confidence_score = self._calculate_weighted_score(source_verdicts)
        
        # Calculate agreement level
        agreement_level = self._calculate_agreement_level(source_verdicts)
        
        # Determine initial threat level
        initial_verdict = self._determine_threat_level(weighted_score)
        
        # Apply disagreement rules
        final_verdict = self._apply_disagreement_rules(
            initial_verdict, 
            source_verdicts, 
            agreement_level
        )
        
        # Generate reasoning
        reasoning = self._generate_reasoning(
            final_verdict,
            weighted_score,
            confidence_score,
            agreement_level,
            source_verdicts
        )
        
        # Compile metadata
        metadata = {
            'ioc': ioc,
            'ioc_type': ioc_type,
            'total_sources': len(source_verdicts),
            'sources_by_type': {
                'generic': len([sv for sv in source_verdicts if sv.source_type == SourceType.GENERIC_THREAT_INTEL]),
                'llm': len([sv for sv in source_verdicts if sv.source_type == SourceType.LLM_ANALYSIS])
            },
            'disagreement_applied': final_verdict != initial_verdict
        }
        
        return AggregatedVerdict(
            final_verdict=final_verdict,
            confidence_score=confidence_score,
            weighted_score=weighted_score,
            reasoning=reasoning,
            source_verdicts=source_verdicts,
            agreement_level=agreement_level,
            timestamp=datetime.now(),
            metadata=metadata
        )
    
    def explain_verdict(self, aggregated_verdict: AggregatedVerdict) -> Dict[str, Any]:
        """
        Generate detailed explanation of the verdict for transparency
        
        Returns a dictionary with breakdown of scoring logic
        """
        explanation = {
            'final_verdict': aggregated_verdict.final_verdict.value,
            'confidence': f"{aggregated_verdict.confidence_score:.1%}",
            'weighted_score': f"{aggregated_verdict.weighted_score:.2f}",
            'agreement_level': f"{aggregated_verdict.agreement_level:.1%}",
            'reasoning': aggregated_verdict.reasoning,
            'source_details': []
        }
        
        for verdict in aggregated_verdict.source_verdicts:
            source_weight = self._get_source_weight(verdict)
            normalized_conf = self._normalize_confidence(verdict)
            threat_score = self.THREAT_LEVEL_SCORES[verdict.threat_level]
            contribution = threat_score * normalized_conf * source_weight
            
            explanation['source_details'].append({
                'source': verdict.source_name,
                'type': verdict.source_type.value,
                'verdict': verdict.threat_level.value,
                'confidence': f"{verdict.confidence:.1%}",
                'weight': f"{source_weight:.2f}",
                'normalized_confidence': f"{normalized_conf:.1%}",
                'contribution_score': f"{contribution:.2f}",
                'details': verdict.details
            })
        
        return explanation
