import openai
from typing import Dict, Any
import json
import logging
from app.models import ClassificationType

logger = logging.getLogger(__name__)

class ThreatClassifier:
    """
    Uses OpenAI LLM to classify IOCs based on threat intelligence data
    """
    
    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.client = openai.OpenAI(api_key=api_key)
        self.model = model
        
    def format_intel_data(self, intel_data: Dict[str, Any]) -> str:
        """Format intelligence data for LLM analysis"""
        formatted_data = []
        
        ioc = intel_data.get('ioc', 'Unknown')
        ioc_type = intel_data.get('ioc_type', 'Unknown')
        
        formatted_data.append(f"IOC: {ioc}")
        formatted_data.append(f"Type: {ioc_type.upper()}")
        formatted_data.append(f"Analysis Timestamp: {intel_data.get('timestamp', 'Unknown')}")
        formatted_data.append("\\nThreat Intelligence Sources:")
        
        sources = intel_data.get('sources', {})
        
        for source_name, source_data in sources.items():
            if 'error' in source_data:
                formatted_data.append(f"\\n{source_name.upper()}: Error - {source_data['error']}")
                continue
                
            formatted_data.append(f"\\n{source_name.upper()}:")
            
            if source_name == 'virustotal':
                malicious = source_data.get('malicious_count', 0)
                suspicious = source_data.get('suspicious_count', 0)
                harmless = source_data.get('harmless_count', 0)
                total = source_data.get('total_engines', 0)
                
                # Add context and insights
                popular_threat_label = source_data.get('popular_threat_label', '')
                meaningful_name = source_data.get('meaningful_name', '')
                type_description = source_data.get('type_description', '')
                tags = source_data.get('tags', [])
                
                # Check for EICAR or test files
                if popular_threat_label and 'eicar' in popular_threat_label.lower():
                    formatted_data.append(f"  ⚠️ CODE INSIGHT: This is an EICAR TEST FILE - a harmless test string used to verify antivirus software.")
                    formatted_data.append(f"  - It is NOT a real threat and cannot harm systems.")
                    formatted_data.append(f"  - EICAR is a standardized test that triggers antivirus engines to demonstrate they're working properly.")
                elif meaningful_name and 'eicar' in meaningful_name.lower():
                    formatted_data.append(f"  ⚠️ CODE INSIGHT: Identified as EICAR test file (harmless test pattern for antivirus verification).")
                elif any('eicar' in tag.lower() for tag in tags):
                    formatted_data.append(f"  ⚠️ CODE INSIGHT: Tagged as EICAR - this is a benign test file, not real malware.")
                
                # Add threat classification if available
                if popular_threat_label:
                    formatted_data.append(f"  - Threat Classification: {popular_threat_label}")
                
                if meaningful_name:
                    formatted_data.append(f"  - Identified as: {meaningful_name}")
                
                if type_description:
                    formatted_data.append(f"  - File Type: {type_description}")
                
                formatted_data.append(f"  - Malicious detections: {malicious}/{total}")
                formatted_data.append(f"  - Suspicious detections: {suspicious}/{total}")
                formatted_data.append(f"  - Harmless detections: {harmless}/{total}")
                
                if total > 0:
                    malicious_ratio = (malicious / total) * 100
                    suspicious_ratio = (suspicious / total) * 100
                    formatted_data.append(f"  - Malicious ratio: {malicious_ratio:.1f}%")
                    formatted_data.append(f"  - Suspicious ratio: {suspicious_ratio:.1f}%")
                
                # Add top malicious vendor detections
                malicious_vendors = source_data.get('malicious_vendors', [])
                if malicious_vendors:
                    top_detections = [v.get('result', '') for v in malicious_vendors[:3] if v.get('result')]
                    if top_detections:
                        formatted_data.append(f"  - Common detections: {', '.join(top_detections)}")
                
            elif source_name == 'abuseipdb':
                confidence = source_data.get('abuse_confidence', 0)
                reports = source_data.get('total_reports', 0)
                country = source_data.get('country_code', 'Unknown')
                isp = source_data.get('isp', 'Unknown')
                
                formatted_data.append(f"  - Abuse confidence: {confidence}%")
                formatted_data.append(f"  - Total reports: {reports}")
                formatted_data.append(f"  - Country: {country}")
                formatted_data.append(f"  - ISP: {isp}")
                
            elif source_name == 'misp':
                events = source_data.get('events_found', 0)
                formatted_data.append(f"  - Events found: {events}")
                
                if events > 0:
                    events_data = source_data.get('events_summary', [])
                    for i, event in enumerate(events_data[:3], 1):
                        formatted_data.append(f"    Event {i}: {event.get('info', 'No description')}")
            
            elif source_name == 'shodan':
                # Handle both IP and domain Shodan data
                if source_data.get('ip'):
                    # IP data
                    ip = source_data.get('ip', 'Unknown')
                    country = source_data.get('country_code', 'Unknown')
                    org = source_data.get('organization', 'Unknown')
                    isp = source_data.get('isp', 'Unknown')
                    ports = source_data.get('ports', [])
                    services = source_data.get('services', [])
                    vulns = source_data.get('vulnerabilities', [])
                    
                    formatted_data.append(f"  - IP: {ip}")
                    formatted_data.append(f"  - Country: {country}")
                    formatted_data.append(f"  - Organization: {org}")
                    formatted_data.append(f"  - ISP: {isp}")
                    if ports:
                        formatted_data.append(f"  - Open ports: {len(ports)} ({', '.join(map(str, ports[:5]))}{'...' if len(ports) > 5 else ''})")
                    if services:
                        formatted_data.append(f"  - Services: {len(services)} ({', '.join(services[:3])}{'...' if len(services) > 3 else ''})")
                    if vulns:
                        formatted_data.append(f"  - Vulnerabilities: {len(vulns)}")
                        formatted_data.append(f"    Top vulnerabilities: {', '.join(vulns[:3])}{'...' if len(vulns) > 3 else ''}")
                elif source_data.get('domain'):
                    # Domain data
                    domain = source_data.get('domain', 'Unknown')
                    resolved_ip = source_data.get('resolved_ip', 'Unknown')
                    org = source_data.get('organization', 'Unknown')
                    
                    formatted_data.append(f"  - Domain: {domain}")
                    formatted_data.append(f"  - Resolved IP: {resolved_ip}")
                    if org != 'Unknown':
                        formatted_data.append(f"  - Organization: {org}")
                
                # Add message if present
                if source_data.get('message'):
                    formatted_data.append(f"  - Note: {source_data.get('message')}")
            
            elif source_name == 'urlscan':
                # Handle URLScan.io data
                url = source_data.get('url', 'Unknown')
                domain = source_data.get('domain', 'Unknown')
                verdict = source_data.get('verdict', 'Unknown')
                malicious = source_data.get('malicious', False)
                phishing = source_data.get('phishing_detected', False)
                total_results = source_data.get('total_results', 0)
                country = source_data.get('country', 'Unknown')
                server = source_data.get('server', 'Unknown')
                
                formatted_data.append(f"  - URL: {url}")
                formatted_data.append(f"  - Domain: {domain}")
                formatted_data.append(f"  - Verdict: {verdict}")
                formatted_data.append(f"  - Malicious: {malicious}")
                formatted_data.append(f"  - Phishing detected: {phishing}")
                formatted_data.append(f"  - Total scans found: {total_results}")
                formatted_data.append(f"  - Country: {country}")
                if server != 'Unknown':
                    formatted_data.append(f"  - Server: {server}")
                
                # Add message if present
                if source_data.get('message'):
                    formatted_data.append(f"  - Note: {source_data.get('message')}")
            
            elif source_name == 'alienvault':
                # Handle AlienVault OTX data
                pulse_count = source_data.get('pulse_count', 0)
                reputation = source_data.get('reputation', 0)
                threat_tags = source_data.get('threat_tags', [])
                malware_families = source_data.get('malware_families', [])
                adversaries = source_data.get('adversaries', [])
                attack_ids = source_data.get('attack_ids', [])
                
                formatted_data.append(f"  - Threat Pulses: {pulse_count}")
                formatted_data.append(f"  - Reputation Score: {reputation}")
                
                if malware_families:
                    formatted_data.append(f"  - Malware Families: {', '.join(malware_families[:5])}")
                
                if adversaries:
                    formatted_data.append(f"  - Threat Actors: {', '.join(adversaries)}")
                
                if attack_ids:
                    formatted_data.append(f"  - MITRE ATT&CK IDs: {', '.join(attack_ids[:5])}")
                
                if threat_tags:
                    formatted_data.append(f"  - Threat Tags: {', '.join(threat_tags[:10])}")
                
                # Add pulses summary if available
                pulses = source_data.get('pulses', [])
                if pulses:
                    formatted_data.append(f"  - Recent Pulses:")
                    for i, pulse in enumerate(pulses[:3], 1):
                        pulse_name = pulse.get('name', 'Unknown')
                        pulse_tags = ', '.join(pulse.get('tags', [])[:3])
                        formatted_data.append(f"    {i}. {pulse_name} (Tags: {pulse_tags})")
                
                # Add message if present
                if source_data.get('message'):
                    formatted_data.append(f"  - Note: {source_data.get('message')}")
        
        return "\\n".join(formatted_data)
    
    def get_classification_prompt(self, intel_data_formatted: str, analyst_feedback: str = None) -> str:
        """Create the prompt for LLM classification"""
        feedback_instruction = ""
        feedback_section = ""
        
        if analyst_feedback:
            feedback_section = f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  PREVIOUS ANALYST EXPERT FEEDBACK (HIGHEST PRIORITY)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{analyst_feedback}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"""
            feedback_instruction = """

CRITICAL INSTRUCTIONS REGARDING ANALYST FEEDBACK:
1. The analyst feedback above was provided by human expert(s) who previously analyzed this IOC
2. If there are MULTIPLE feedback entries (separated by ---), consider ALL of them - they show the evolution of understanding over time
3. You MUST explicitly reference this feedback in your reasoning
4. Your reasoning should read like a conversation: "Security analysts previously noted that [feedback]. Based on this context and the current data..."
5. If there are conflicting feedback entries, acknowledge the evolution: "Initially identified as [X], but later assessment noted [Y]..."
6. If the feedback contradicts automated sources, give the feedback priority and explain why
7. Make your response human-like and contextual, showing awareness of the previous analysis history
8. Use phrases like "Previously identified as...", "Analysts noted...", "Building on the previous assessments...", "The investigation history shows..."
"""
        
        return f"""You are a cybersecurity threat intelligence analyst. Analyze the following IOC (Indicator of Compromise) data and provide a classification.

{intel_data_formatted}
{feedback_section}{feedback_instruction}
Based on this threat intelligence data, classify this IOC as one of the following:
1. MALICIOUS - Clear evidence of malicious activity (high confidence threat)
2. SUSPICIOUS - Indicators suggest potential threat but not definitive (medium confidence)
3. BENIGN - No significant threat indicators found (low/no threat)
4. TEST_FILE - Recognized test file (e.g., EICAR) used for security testing, not a real threat

Classification Guidelines:
- TEST_FILE: EICAR test file or similar security testing artifacts that are harmless by design. These should NOT be classified as MALICIOUS even though antivirus engines detect them. Add clear explanation that it's a test file.
- MALICIOUS: >10% malicious detections OR >50% abuse confidence OR multiple MISP events OR >5 vulnerabilities in Shodan OR URLScan verdict is malicious/phishing (UNLESS it's a known test file)
- SUSPICIOUS: 1-10% malicious detections OR 10-50% abuse confidence OR 1-2 MISP events OR 1-5 vulnerabilities in Shodan OR suspicious port combinations OR URLScan shows suspicious patterns
- BENIGN: 0% malicious detections AND <10% abuse confidence AND no MISP events AND no known vulnerabilities AND URLScan shows clean verdict

IMPORTANT: Always check for CODE INSIGHTS that indicate test files (like EICAR). If detected, classify as TEST_FILE with high confidence and explain it's harmless.

For your classification, consider:
- CODE INSIGHTS and contextual information (highest priority for test files)
- Detection rates from antivirus engines (VirusTotal)
- Abuse confidence scores and report counts (AbuseIPDB)
- Historical threat intelligence events (MISP)
- Network infrastructure and vulnerabilities (Shodan)
- URL and domain security analysis (URLScan.io)
- Geolocation and ISP information context
- Open ports, services, and known vulnerabilities
- Web security verdicts, phishing detection, and brand impersonation
- Known legitimate services vs suspicious patterns

Provide your response ONLY in the following JSON format (no additional text):
{{
    "classification": "MALICIOUS|SUSPICIOUS|BENIGN|TEST_FILE",
    "confidence_score": <1-100>,
    "reasoning": "Detailed explanation of why you classified it this way, including CODE INSIGHTS if applicable",
    "key_indicators": ["list", "of", "key", "threat", "indicators"],
    "recommendations": "What actions should be taken based on this classification"
}}"""

    def classify_threat(self, intel_data: Dict[str, Any], analyst_feedback: str = None) -> Dict[str, Any]:
        """Classify threat using OpenAI LLM"""
        try:
            formatted_data = self.format_intel_data(intel_data)
            prompt = self.get_classification_prompt(formatted_data, analyst_feedback)
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system", 
                        "content": "You are an expert cybersecurity threat intelligence analyst. Respond only with valid JSON."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # Low temperature for consistent results
                max_tokens=800
            )
            
            response_content = response.choices[0].message.content.strip()
            logger.info(f"LLM Response: {response_content}")
            
            # Parse JSON response
            try:
                classification_result = json.loads(response_content)
                
                # Validate classification
                classification = classification_result.get('classification', 'UNKNOWN')
                if classification not in [e.value for e in ClassificationType]:
                    classification = 'UNKNOWN'
                
                # Ensure confidence score is within bounds
                confidence_score = classification_result.get('confidence_score', 0)
                confidence_score = max(0, min(100, int(confidence_score)))
                
                result = {
                    "classification": classification,
                    "confidence_score": confidence_score,
                    "reasoning": classification_result.get('reasoning', 'No reasoning provided'),
                    "key_indicators": classification_result.get('key_indicators', []),
                    "recommendations": classification_result.get('recommendations', 'No recommendations provided'),
                    "model_used": self.model,
                    "tokens_used": response.usage.total_tokens if response.usage else 0
                }
                
                return result
                    
            except json.JSONDecodeError as e:
                logger.error(f"JSON parsing error: {e}, Response: {response_content}")
                return self._create_fallback_classification(response_content, "JSON parsing failed")
            
        except openai.RateLimitError:
            logger.error("OpenAI rate limit exceeded")
            return self._create_error_classification("Rate limit exceeded - try again later")
        except openai.AuthenticationError:
            logger.error("OpenAI authentication failed")
            return self._create_error_classification("Authentication failed - check API key")
        except Exception as e:
            logger.error(f"Classification error: {str(e)}")
            return self._create_error_classification(f"Classification service error: {str(e)}")
    
    def _create_fallback_classification(self, response_content: str, error_reason: str) -> Dict[str, Any]:
        """Create a fallback classification when JSON parsing fails"""
        # Simple fallback logic based on response content
        content_lower = response_content.lower()
        
        if 'malicious' in content_lower:
            classification = 'MALICIOUS'
            confidence = 60
        elif 'suspicious' in content_lower:
            classification = 'SUSPICIOUS'
            confidence = 50
        elif 'benign' in content_lower:
            classification = 'BENIGN'
            confidence = 70
        else:
            classification = 'UNKNOWN'
            confidence = 0
        
        return {
            "classification": classification,
            "confidence_score": confidence,
            "reasoning": f"Fallback classification due to {error_reason}. Raw response: {response_content[:200]}...",
            "key_indicators": ["Fallback classification used"],
            "recommendations": "Manual review recommended due to parsing error",
            "model_used": self.model,
            "error": error_reason
        }
    
    def _create_error_classification(self, error_message: str) -> Dict[str, Any]:
        """Create an error classification response"""
        return {
            "classification": "ERROR",
            "confidence_score": 0,
            "reasoning": f"Error during classification: {error_message}",
            "key_indicators": [],
            "recommendations": "Manual review required due to classification error",
            "model_used": self.model,
            "error": error_message
        }
    
    def generate_summary(self, intel_data: Dict[str, Any], classification: Dict[str, Any]) -> str:
        """Generate a brief summary of the analysis"""
        ioc = intel_data.get('ioc', 'Unknown')
        ioc_type = intel_data.get('ioc_type', 'unknown').upper()
        classification_result = classification.get('classification', 'UNKNOWN')
        confidence = classification.get('confidence_score', 0)
        
        summary = f"IOC {ioc} ({ioc_type}) classified as {classification_result} with {confidence}% confidence."
        
        # Add key source information
        sources = intel_data.get('sources', {})
        source_info = []
        
        if 'virustotal' in sources and 'error' not in sources['virustotal']:
            vt_data = sources['virustotal']
            malicious = vt_data.get('malicious_count', 0)
            total = vt_data.get('total_engines', 0)
            if total > 0:
                source_info.append(f"VirusTotal: {malicious}/{total} detections")
        
        if 'abuseipdb' in sources and 'error' not in sources['abuseipdb']:
            abuse_data = sources['abuseipdb']
            confidence_pct = abuse_data.get('abuse_confidence', 0)
            source_info.append(f"AbuseIPDB: {confidence_pct}% abuse confidence")
        
        if source_info:
            summary += f" Sources: {', '.join(source_info)}."
        
        return summary
    
    def classify_threat_final_verdict(self, intel_data: Dict[str, Any], sources_results: Dict[str, Any], analyst_feedback: str = None) -> Dict[str, Any]:
        """
        Generate final verdict by analyzing all threat intelligence sources together
        """
        try:
            # Format data from all sources
            formatted_data = self.format_intel_data(intel_data)
            
            # Add individual source verdicts to the analysis
            source_verdicts = []
            for source_name, result in sources_results.items():
                if result.get('success') and result.get('verdict'):
                    verdict = result.get('verdict', 'UNKNOWN')
                    reasoning = result.get('reasoning', 'No reasoning')
                    confidence = result.get('confidence_score', 0)
                    source_verdicts.append(f"{source_name.title()}: {verdict} ({confidence}% confidence) - {reasoning}")
            
            # Create enhanced prompt for final verdict
            prompt = self.get_final_verdict_prompt(formatted_data, source_verdicts, analyst_feedback)
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system", 
                        "content": "You are an expert cybersecurity analyst combining multiple threat intelligence sources for a final verdict. Respond only with valid JSON."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1000
            )
            
            response_content = response.choices[0].message.content.strip()
            logger.info(f"Final Verdict LLM Response: {response_content}")
            
            try:
                classification_result = json.loads(response_content)
                
                # Validate classification
                classification = classification_result.get('classification', 'UNKNOWN')
                if classification not in [e.value for e in ClassificationType]:
                    classification = 'UNKNOWN'
                
                confidence_score = max(0, min(100, int(classification_result.get('confidence_score', 0))))
                
                result = {
                    "classification": classification,
                    "confidence_score": confidence_score,
                    "reasoning": classification_result.get('reasoning', 'No reasoning provided'),
                    "key_indicators": classification_result.get('key_indicators', []),
                    "recommendations": classification_result.get('recommendations', 'No recommendations provided'),
                    "model_used": self.model,
                    "tokens_used": response.usage.total_tokens if response.usage else 0
                }
                
                return result
                    
            except json.JSONDecodeError as e:
                logger.error(f"JSON parsing error in final verdict: {e}")
                return self._create_fallback_classification(response_content, "Final verdict JSON parsing failed")
            
        except Exception as e:
            logger.error(f"Final verdict classification error: {str(e)}")
            return self._create_error_classification(f"Final verdict service error: {str(e)}")
    
    def get_final_verdict_prompt(self, intel_data_formatted: str, source_verdicts: list, analyst_feedback: str = None) -> str:
        """Create the prompt for final verdict analysis"""
        source_verdicts_text = "\\n".join(source_verdicts) if source_verdicts else "No individual source verdicts available"
        
        feedback_instruction = ""
        feedback_section = ""
        
        if analyst_feedback:
            feedback_section = f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  PREVIOUS ANALYST EXPERT FEEDBACK (HIGHEST PRIORITY - MUST REFERENCE)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HISTORICAL CONTEXT FROM PREVIOUS ANALYSIS/ANALYSES:
{analyst_feedback}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"""
            feedback_instruction = """

CRITICAL: YOU MUST INCORPORATE THE ANALYST FEEDBACK INTO YOUR REASONING
Your response should:
1. START by acknowledging the previous analysis/analyses: "This IOC has been analyzed before. Security analysts noted that [summarize all feedback]..."
2. If there are MULTIPLE feedback entries (separated by ---), synthesize them: "The investigation history shows an evolution: [timeline of assessments]..."
3. Compare current findings with the previous assessments: "The current analysis shows [new findings], which [aligns with/differs from] the previous assessments..."
4. If feedback says it's a false positive or benign: "Analysts previously identified this as [context from feedback]. Current data [confirms/contradicts] this assessment..."
5. If feedback provides additional context: "Building on previous analyses where [feedback context], the current scan reveals..."
6. Make it conversational and show temporal awareness: Use phrases like "previously", "historically", "in past analyses", "now we see", "current findings", "over time", "the pattern shows"
7. If there are changes: "While earlier analyses indicated [X], later assessments noted [Y], and current data now shows [Z], suggesting [evolution/change]..."
8. Give the analyst feedback priority weight - if they said it's safe and current automated sources show minor flags, trust the human experts
9. If feedback entries conflict, explain: "Initial assessment was [X], but subsequent investigation revealed [Y], so current verdict is based on [latest understanding]..."

Your reasoning MUST feel like a continuation of an ongoing investigation with full awareness of its history, not a fresh analysis.
"""
        
        return f"""You are a senior cybersecurity analyst reviewing an IOC that may have been analyzed before. Provide a FINAL VERDICT by synthesizing all available intelligence.

THREAT INTELLIGENCE DATA:
{intel_data_formatted}

INDIVIDUAL SOURCE VERDICTS:
{source_verdicts_text}
{feedback_section}{feedback_instruction}
Your job is to analyze ALL the evidence above and provide a final, authoritative verdict. Consider:

1. **Historical Context**: What did previous analysts conclude? (IF FEEDBACK EXISTS)
2. **Consensus Analysis**: Do multiple sources agree on the threat level?
3. **Evidence Weight**: Which sources provide the most compelling evidence?
4. **False Positive Risk**: Could this be a false positive from any source?
5. **Threat Severity**: What is the actual risk level based on all evidence?
6. **Temporal Changes**: How do current findings compare to previous assessments? (IF FEEDBACK EXISTS)

FINAL VERDICT GUIDELINES:
- MALICIOUS: Strong evidence from multiple sources OR high-confidence evidence from authoritative source
- SUSPICIOUS: Mixed signals OR moderate evidence requiring further investigation  
- BENIGN: Consistent clean results across sources OR evidence strongly suggests legitimate activity
- UNKNOWN: Insufficient or conflicting data to make determination

Provide your FINAL VERDICT in this exact JSON format:
{{
    "classification": "MALICIOUS|SUSPICIOUS|BENIGN|UNKNOWN",
    "confidence_score": <1-100>,
    "reasoning": "IMPORTANT: If analyst feedback exists, BEGIN your reasoning by referencing it (e.g., 'This IOC was previously assessed by an analyst who noted that [feedback summary]...'). Then provide comprehensive analysis explaining the final verdict, comparing current findings with historical context, addressing any conflicts between sources, and explaining the decision-making process. Make it conversational and show awareness of the investigation timeline.",
    "key_indicators": ["list", "of", "most", "important", "threat", "indicators", "from", "all", "sources"],
    "recommendations": "Specific actionable recommendations based on the final verdict and historical context"
}}"""