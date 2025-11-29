"""
Example Usage of Verdict Aggregation System

This script demonstrates how to use the verdict aggregation system
with customer-specific ML models.
"""

from app.services.threat_intel_orchestrator import ThreatIntelOrchestrator
from app.services.verdict_aggregation import ThreatLevel
from app.core.verdict_config import get_weights_for_customer
import os


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)


def print_verdict_summary(verdict):
    """Print a formatted verdict summary"""
    print(f"\n📊 VERDICT SUMMARY")
    print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"Final Verdict:    {verdict.final_verdict.value.upper()}")
    print(f"Confidence:       {verdict.confidence_score:.1%}")
    print(f"Weighted Score:   {verdict.weighted_score:.2f}")
    print(f"Agreement Level:  {verdict.agreement_level:.1%}")
    print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"\n💬 Reasoning:\n{verdict.reasoning}")
    print(f"\n📈 Source Breakdown:")
    for sv in verdict.source_verdicts:
        print(f"  • {sv.source_name:20} → {sv.threat_level.value.upper():10} "
              f"(confidence: {sv.confidence:.1%})")


def example_basic_analysis():
    """Example 1: Basic IOC analysis without customer model"""
    print_section("Example 1: Basic Analysis (No Customer Model)")
    
    # Initialize orchestrator with config
    config = {
        'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY', 'demo_key'),
        'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY', 'demo_key'),
    }
    
    orchestrator = ThreatIntelOrchestrator(config)
    
    # Analyze an IOC
    ioc = "8.8.8.8"
    print(f"\nAnalyzing IOC: {ioc}")
    print("Querying generic threat intel sources only...")
    
    verdict = orchestrator.analyze_ioc(ioc)
    print_verdict_summary(verdict)


def example_with_customer_model():
    """Example 2: Analysis with customer-specific ML model"""
    print_section("Example 2: Analysis with Customer-Specific ML Model")
    
    config = {
        'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY', 'demo_key'),
        'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY', 'demo_key'),
    }
    
    orchestrator = ThreatIntelOrchestrator(config)
    
    # Analyze with customer ID
    ioc = "192.168.1.100"
    customer_id = "customer1"
    
    print(f"\nAnalyzing IOC: {ioc}")
    print(f"Customer ID: {customer_id}")
    print("Querying generic sources + customer ML model...")
    
    # Check if customer has a model
    model_status = orchestrator.get_customer_model_status(customer_id)
    print(f"\nCustomer Model Status:")
    print(f"  Has Model: {model_status['has_any_model']}")
    for model_type, available in model_status['models_available'].items():
        print(f"  {model_type}: {'✓' if available else '✗'}")
    
    verdict = orchestrator.analyze_ioc(ioc, customer_id=customer_id)
    print_verdict_summary(verdict)


def example_detailed_explanation():
    """Example 3: Detailed analysis with scoring explanation"""
    print_section("Example 3: Detailed Analysis with Explanation")
    
    config = {
        'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY', 'demo_key'),
        'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY', 'demo_key'),
    }
    
    orchestrator = ThreatIntelOrchestrator(config)
    
    ioc = "malicious-domain.com"
    customer_id = "customer1"
    
    print(f"\nAnalyzing IOC: {ioc}")
    print(f"Customer ID: {customer_id}")
    print("Getting detailed explanation of scoring logic...\n")
    
    detailed = orchestrator.analyze_ioc_detailed(ioc, customer_id)
    
    print(f"📊 VERDICT: {detailed['verdict']['final_verdict'].upper()}")
    print(f"Confidence: {detailed['verdict']['confidence']:.1%}")
    print(f"Agreement: {detailed['verdict']['agreement_level']:.1%}\n")
    
    print("📝 DETAILED SCORING BREAKDOWN:")
    print("─" * 70)
    
    for source in detailed['detailed_explanation']['source_details']:
        print(f"\n{source['source']} ({source['type']})")
        print(f"  Verdict:              {source['verdict'].upper()}")
        print(f"  Confidence:           {source['confidence']}")
        print(f"  Source Weight:        {source['weight']}")
        print(f"  Normalized Conf:      {source['normalized_confidence']}")
        print(f"  Contribution Score:   {source['contribution_score']}")
    
    print("\n" + "─" * 70)
    print(f"\n💬 {detailed['verdict']['reasoning']}")


def example_custom_weights():
    """Example 4: Using custom weights for specific deployment"""
    print_section("Example 4: Custom Weights Configuration")
    
    from app.services.verdict_aggregation import SourceType
    
    config = {
        'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY', 'demo_key'),
        'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY', 'demo_key'),
    }
    
    # Define custom weights
    custom_weights = {
        SourceType.CUSTOMER_ML_MODEL: 0.95,  # Trust customer model more
        SourceType.GENERIC_THREAT_INTEL: {
            'VirusTotal': 0.90,  # Increase VirusTotal trust
            'AbuseIPDB': 0.85,
            'PhishTank': 0.80
        },
        SourceType.LLM_ANALYSIS: 0.80
    }
    
    print("\nCustom Weights Configuration:")
    print("  Customer ML Model:  0.95 (↑ from 0.90)")
    print("  VirusTotal:         0.90 (↑ from 0.85)")
    print("  AbuseIPDB:          0.85 (↑ from 0.80)")
    print("  LLM Analysis:       0.80 (↑ from 0.75)")
    
    orchestrator = ThreatIntelOrchestrator(config, custom_weights=custom_weights)
    
    ioc = "suspicious-url.com"
    customer_id = "customer1"
    
    print(f"\nAnalyzing IOC: {ioc}")
    print(f"Customer ID: {customer_id}")
    print("Using custom weights for this analysis...\n")
    
    verdict = orchestrator.analyze_ioc(ioc, customer_id)
    print_verdict_summary(verdict)


def example_comparison_scenarios():
    """Example 5: Compare verdicts with and without customer model"""
    print_section("Example 5: Comparison - With vs Without Customer Model")
    
    config = {
        'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY', 'demo_key'),
        'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY', 'demo_key'),
    }
    
    orchestrator = ThreatIntelOrchestrator(config)
    
    ioc = "10.0.0.50"  # Internal IP that might be flagged externally
    customer_id = "customer1"
    
    print(f"\nScenario: Analyzing internal IP that may be flagged by external sources")
    print(f"IOC: {ioc}")
    
    # Without customer model
    print("\n" + "─" * 70)
    print("🔍 Analysis WITHOUT Customer Model:")
    print("─" * 70)
    verdict_no_ml = orchestrator.analyze_ioc(ioc)
    print(f"Verdict: {verdict_no_ml.final_verdict.value.upper()}")
    print(f"Confidence: {verdict_no_ml.confidence_score:.1%}")
    print(f"Sources used: {len(verdict_no_ml.source_verdicts)}")
    
    # With customer model
    print("\n" + "─" * 70)
    print("🔍 Analysis WITH Customer Model:")
    print("─" * 70)
    verdict_with_ml = orchestrator.analyze_ioc(ioc, customer_id=customer_id)
    print(f"Verdict: {verdict_with_ml.final_verdict.value.upper()}")
    print(f"Confidence: {verdict_with_ml.confidence_score:.1%}")
    print(f"Sources used: {len(verdict_with_ml.source_verdicts)}")
    
    # Compare
    print("\n" + "─" * 70)
    print("📊 COMPARISON:")
    print("─" * 70)
    print(f"Verdict Change: {verdict_no_ml.final_verdict.value} → {verdict_with_ml.final_verdict.value}")
    print(f"Confidence Change: {verdict_no_ml.confidence_score:.1%} → {verdict_with_ml.confidence_score:.1%}")
    print(f"Additional Sources: +{len(verdict_with_ml.source_verdicts) - len(verdict_no_ml.source_verdicts)}")
    
    print("\n💡 Key Insight:")
    print("   Customer-specific ML model provides contextual intelligence that")
    print("   can adjust verdicts based on the customer's unique environment.")


def example_batch_analysis():
    """Example 6: Batch analysis of multiple IOCs"""
    print_section("Example 6: Batch Analysis")
    
    config = {
        'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY', 'demo_key'),
        'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY', 'demo_key'),
    }
    
    orchestrator = ThreatIntelOrchestrator(config)
    
    # List of IOCs to analyze
    iocs = [
        "8.8.8.8",
        "malicious.com",
        "192.168.1.1",
        "https://suspicious-url.com/login",
    ]
    
    customer_id = "customer1"
    
    print(f"\nAnalyzing {len(iocs)} IOCs for customer: {customer_id}\n")
    
    results = []
    for ioc in iocs:
        print(f"Analyzing: {ioc}...")
        verdict = orchestrator.analyze_ioc(ioc, customer_id)
        results.append((ioc, verdict))
        print(f"  → {verdict.final_verdict.value.upper()} ({verdict.confidence_score:.0%} confidence)")
    
    # Summary
    print("\n" + "="*70)
    print("BATCH ANALYSIS SUMMARY")
    print("="*70)
    
    threat_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'safe': 0,
        'unknown': 0
    }
    
    for ioc, verdict in results:
        threat_counts[verdict.final_verdict.value] += 1
    
    print(f"\nThreat Distribution:")
    for level, count in threat_counts.items():
        if count > 0:
            bar = "█" * count
            print(f"  {level.upper():10} {bar} ({count})")


def main():
    """Run all examples"""
    print("\n" + "█"*70)
    print("  VERDICT AGGREGATION SYSTEM - EXAMPLE USAGE")
    print("█"*70)
    
    print("\nThis demonstration shows how the verdict aggregation system")
    print("combines intelligence from multiple sources including customer-specific")
    print("ML models to produce weighted threat verdicts.\n")
    
    print("Note: This is a demonstration. For real analysis, ensure you have:")
    print("  ✓ Valid API keys in environment variables")
    print("  ✓ Trained ML models in ml/models/customer_X/ directories")
    print("  ✓ Network connectivity to threat intel APIs")
    
    try:
        # Run examples
        example_basic_analysis()
        example_with_customer_model()
        example_detailed_explanation()
        example_custom_weights()
        example_comparison_scenarios()
        example_batch_analysis()
        
        print("\n" + "█"*70)
        print("  DEMONSTRATION COMPLETE")
        print("█"*70)
        print("\nFor more information, see VERDICT_AGGREGATION.md")
        
    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")
        print("\nNote: Some examples may fail without actual API keys and trained models.")


if __name__ == "__main__":
    main()
