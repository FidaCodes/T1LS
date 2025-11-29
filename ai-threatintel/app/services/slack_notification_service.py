"""
Slack Notification Service
Sends threat intelligence analysis results to Slack channels via the notification-service
"""

import requests
import os
from datetime import datetime
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class SlackNotificationService:
    """Service to send threat intelligence alerts to Slack"""
    
    def __init__(self):
        self.notification_service_url = os.getenv('NOTIFICATION_SERVICE_URL', 'http://localhost:3003')
        self.slack_channel_id = os.getenv('SLACK_CHANNEL_ID', 'C09KWMQSWDT')
        self.enabled = os.getenv('SLACK_NOTIFICATIONS_ENABLED', 'true').lower() == 'true'
        
    def send_analysis_alert(self, analysis_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Send a threat intelligence analysis alert to Slack
        
        Args:
            analysis_result: The complete analysis result dictionary containing:
                - ioc: The indicator of compromise
                - ioc_type: Type of IOC (ip, domain, hash, url)
                - verdict: Final verdict (MALICIOUS, SUSPICIOUS, BENIGN, etc.)
                - confidence_score: Confidence percentage
                - sources: Dict of threat intelligence source results
                - timestamp: Analysis timestamp
                
        Returns:
            Response from notification service or None if disabled/failed
        """
        if not self.enabled:
            logger.info("Slack notifications are disabled")
            return None
            
        if not self.slack_channel_id:
            logger.warning("SLACK_CHANNEL_ID not configured")
            return None
            
        try:
            # Extract data from analysis result
            ioc = analysis_result.get('ioc', 'Unknown')
            ioc_type = analysis_result.get('ioc_type', 'Unknown')
            verdict = analysis_result.get('verdict', 'UNKNOWN')
            confidence = analysis_result.get('confidence_score', 0)
            reasoning = analysis_result.get('reasoning', 'No reasoning provided')
            sources = analysis_result.get('sources', {})
            timestamp = analysis_result.get('timestamp', datetime.now().isoformat())
            
            # Prepare alert data
            alert_data = {
                'ioc': ioc,
                'iocType': ioc_type,
                'verdict': verdict,
                'confidence': confidence,
                'sources': self._format_sources(sources),
                'timestamp': timestamp,
                'analyst': 'AI Threat Intelligence System'
            }
            
            # Send to notification service
            response = requests.post(
                f'{self.notification_service_url}/api/slack/alert',
                json={
                    'channelId': self.slack_channel_id,
                    'alertData': alert_data
                },
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully sent Slack alert for IOC: {ioc}")
                return response.json()
            else:
                logger.error(f"Failed to send Slack alert: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending Slack notification: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in send_analysis_alert: {str(e)}")
            return None
    
    def send_custom_message(self, message: str, blocks: Optional[list] = None) -> Optional[Dict[str, Any]]:
        """
        Send a custom message to Slack
        
        Args:
            message: Plain text message
            blocks: Optional Slack Block Kit blocks
            
        Returns:
            Response from notification service or None if failed
        """
        if not self.enabled or not self.slack_channel_id:
            return None
            
        try:
            payload = {
                'channelId': self.slack_channel_id,
                'text': message
            }
            
            if blocks:
                payload['blocks'] = blocks
                
            response = requests.post(
                f'{self.notification_service_url}/api/slack/send',
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Successfully sent custom Slack message")
                return response.json()
            else:
                logger.error(f"Failed to send custom message: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error sending custom Slack message: {str(e)}")
            return None
    
    def send_analysis_with_custom_blocks(
        self,
        ioc: str,
        ioc_type: str,
        verdict: str,
        confidence: int,
        description: str,
        sources: Dict[str, Any] = None,
        timestamp: str = None
    ) -> Optional[Dict[str, Any]]:
        """
        Send analysis notification with custom formatted Slack blocks
        
        Args:
            ioc: The indicator of compromise
            ioc_type: Type of IOC (ip, domain, hash, url)
            verdict: Analysis verdict
            confidence: Confidence score (0-100)
            description: Custom description message
            sources: Optional threat intelligence sources
            timestamp: Optional timestamp (defaults to now)
            
        Returns:
            Response from notification service or None if failed
        """
        if not self.enabled or not self.slack_channel_id:
            return None
            
        try:
            if timestamp is None:
                timestamp = datetime.now().isoformat()
            
            # Build custom blocks
            blocks = self._build_analysis_blocks(
                ioc=ioc,
                ioc_type=ioc_type,
                verdict=verdict,
                confidence=confidence,
                description=description,
                sources=sources,
                timestamp=timestamp
            )
            
            response = requests.post(
                f'{self.notification_service_url}/api/slack/blocks',
                json={
                    'channelId': self.slack_channel_id,
                    'text': f'New IOC Analysis: {ioc} - {verdict}',
                    'blocks': blocks
                },
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully sent custom block analysis for IOC: {ioc}")
                return response.json()
            else:
                logger.error(f"Failed to send custom blocks: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error sending custom block analysis: {str(e)}")
            return None
    
    def _build_analysis_blocks(
        self,
        ioc: str,
        ioc_type: str,
        verdict: str,
        confidence: int,
        description: str,
        sources: Dict[str, Any] = None,
        timestamp: str = None
    ) -> list:
        """Build Slack Block Kit blocks for analysis notification"""
        
        # Get verdict emoji
        verdict_emoji = self._get_verdict_emoji(verdict)
        
        blocks = [
            # Header
            {
                'type': 'header',
                'text': {
                    'type': 'plain_text',
                    'text': f'{verdict_emoji} New Threat Intelligence Analysis',
                    'emoji': True
                }
            },
            # Description
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f'*{description}*'
                }
            },
            {
                'type': 'divider'
            },
            # IOC Details
            {
                'type': 'section',
                'fields': [
                    {
                        'type': 'mrkdwn',
                        'text': f'*IOC:*\n`{ioc}`'
                    },
                    {
                        'type': 'mrkdwn',
                        'text': f'*Type:*\n{ioc_type.upper()}'
                    },
                    {
                        'type': 'mrkdwn',
                        'text': f'*Verdict:*\n{verdict_emoji} {verdict}'
                    },
                    {
                        'type': 'mrkdwn',
                        'text': f'*Confidence:*\n{confidence}%'
                    }
                ]
            }
        ]
        
        # Add sources if provided
        if sources:
            blocks.append({'type': 'divider'})
            blocks.append({
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': '*Threat Intelligence Sources:*'
                }
            })
            
            source_fields = []
            for source_name, source_data in list(sources.items())[:8]:  # Limit to 8 sources
                if isinstance(source_data, dict):
                    verdict_text = source_data.get('verdict', 'N/A')
                    source_fields.append({
                        'type': 'mrkdwn',
                        'text': f'*{source_name}:*\n{verdict_text}'
                    })
            
            if source_fields:
                blocks.append({
                    'type': 'section',
                    'fields': source_fields
                })
        
        # Footer with timestamp
        if timestamp:
            formatted_time = self._format_timestamp(timestamp)
            blocks.append({
                'type': 'context',
                'elements': [
                    {
                        'type': 'mrkdwn',
                        'text': f'🤖 AI Threat Intelligence System | 🕒 {formatted_time}'
                    }
                ]
            })
        
        return blocks
    
    def _format_sources(self, sources: Dict[str, Any]) -> Dict[str, Any]:
        """Format sources data for notification service"""
        formatted = {}
        
        for source_name, source_data in sources.items():
            if isinstance(source_data, dict):
                formatted[source_name] = {
                    'verdict': source_data.get('verdict', 'UNKNOWN'),
                    'confidence': source_data.get('confidence_score', 0)
                }
                
                # Add count if available (e.g., VirusTotal detections)
                if 'malicious_count' in source_data:
                    formatted[source_name]['count'] = source_data['malicious_count']
        
        return formatted
    
    def _get_verdict_emoji(self, verdict: str) -> str:
        """Get emoji based on verdict"""
        verdict_upper = verdict.upper()
        
        if verdict_upper == 'MALICIOUS':
            return '🔴'
        elif verdict_upper == 'SUSPICIOUS':
            return '🟡'
        elif verdict_upper == 'BENIGN' or verdict_upper == 'CLEAN':
            return '🟢'
        else:
            return '⚪'
    
    def _format_timestamp(self, timestamp: str) -> str:
        """Format ISO timestamp to readable string"""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            return timestamp
    
    def test_connection(self) -> bool:
        """Test connection to notification service"""
        try:
            response = requests.get(
                f'{self.notification_service_url}/api/slack/test',
                timeout=5
            )
            return response.status_code == 200
        except:
            return False


# Global instance - initialized lazily
_slack_service_instance = None

def get_slack_service() -> SlackNotificationService:
    """Get the global Slack notification service instance (lazy initialization)"""
    global _slack_service_instance
    if _slack_service_instance is None:
        _slack_service_instance = SlackNotificationService()
        logger.info(f"Initialized Slack service - Enabled: {_slack_service_instance.enabled}, Channel: {_slack_service_instance.slack_channel_id}")
    return _slack_service_instance

# Backwards compatibility
slack_service = get_slack_service()
