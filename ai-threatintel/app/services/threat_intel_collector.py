import requests
from typing import Dict, Optional, Any
from datetime import datetime
from app.utils.validators import determine_ioc_type

class ThreatIntelligenceCollector:
    """
    Collects threat intelligence from multiple sources including MISP and other APIs
    """
    
    def __init__(self, config: Dict[str, str], timeout: int = 10):
        self.config = config
        self.timeout = timeout
        
    def query_virustotal(self, ioc: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal API"""
        if 'VIRUSTOTAL_API_KEY' not in self.config:
            return None
            
        api_key = self.config['VIRUSTOTAL_API_KEY']
        headers = {'x-apikey': api_key}
        
        try:
            if ioc_type == 'ip':
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
            elif ioc_type == 'domain':
                url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
            elif ioc_type == 'hash':
                url = f"https://www.virustotal.com/api/v3/files/{ioc}"
            else:
                return None
                
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                last_analysis_results = attributes.get('last_analysis_results', {})
                
                # Extract vendor-specific detections
                malicious_vendors = []
                phishing_vendors = []
                malware_vendors = []
                suspicious_vendors = []
                clean_vendors = []
                
                for engine, result in last_analysis_results.items():
                    category = result.get('category', '')
                    result_str = result.get('result', '') or ''  # Ensure result_str is never None
                    method = result.get('method', '')
                    
                    vendor_info = {
                        'engine': engine,
                        'category': category,
                        'result': result_str,
                        'method': method
                    }
                    
                    # Convert result_str to lowercase safely
                    result_str_lower = result_str.lower() if result_str else ''
                    
                    if category == 'malicious':
                        malicious_vendors.append(vendor_info)
                    elif category == 'phishing' or 'phish' in result_str_lower:
                        phishing_vendors.append(vendor_info)
                    elif 'malware' in result_str_lower or 'trojan' in result_str_lower:
                        malware_vendors.append(vendor_info)
                    elif category == 'suspicious':
                        suspicious_vendors.append(vendor_info)
                    elif category == 'clean' or category == 'undetected':
                        clean_vendors.append(vendor_info)
                
                # Get additional metadata
                reputation = attributes.get('reputation', 0)
                tags = attributes.get('tags', [])
                categories = attributes.get('categories', {})
                last_analysis_date = attributes.get('last_analysis_date')
                
                # Extract VirusTotal's popular threat label and community insights
                popular_threat_label = attributes.get('popular_threat_classification', {}).get('suggested_threat_label')
                popular_threat_category = attributes.get('popular_threat_classification', {})
                
                # Get file type and meaningful name (for hashes)
                type_description = attributes.get('type_description', '')
                meaningful_name = attributes.get('meaningful_name', '')
                names = attributes.get('names', [])
                
                # Get crowd-sourced context
                crowdsourced_labels = []
                if 'crowdsourced_ids_results' in attributes:
                    for result in attributes.get('crowdsourced_ids_results', []):
                        if result.get('alert_severity'):
                            crowdsourced_labels.append({
                                'rule_category': result.get('rule_category'),
                                'alert_severity': result.get('alert_severity'),
                                'rule_msg': result.get('rule_msg')
                            })
                
                # Get sandbox verdicts
                sandbox_verdicts = attributes.get('sandbox_verdicts', {})
                
                # Get sigma analysis (detects behavior patterns)
                sigma_analysis_stats = attributes.get('sigma_analysis_stats', {})
                
                result_data = {
                    'source': 'VirusTotal',
                    'malicious_count': stats.get('malicious', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'harmless_count': stats.get('harmless', 0),
                    'undetected_count': stats.get('undetected', 0),
                    'total_engines': sum(stats.values()) if stats else 0,
                    'malicious_vendors': malicious_vendors[:10],  # Top 10
                    'phishing_vendors': phishing_vendors[:10],  # Top 10
                    'malware_vendors': malware_vendors[:10],  # Top 10
                    'suspicious_vendors': suspicious_vendors[:5],  # Top 5
                    'clean_vendors': clean_vendors[:3],  # Sample 3
                    'reputation': reputation,
                    'tags': tags,
                    'categories': categories,
                    'last_analysis_date': last_analysis_date,
                    # Add context and insights
                    'popular_threat_label': popular_threat_label,
                    'popular_threat_category': popular_threat_category,
                    'type_description': type_description,
                    'meaningful_name': meaningful_name,
                    'names': names[:5] if names else [],  # Top 5 names
                    'crowdsourced_labels': crowdsourced_labels[:5],  # Top 5
                    'sandbox_verdicts': sandbox_verdicts,
                    'sigma_analysis_stats': sigma_analysis_stats,
                    'raw_data': data if self._include_raw_data() else None
                }
                
                # Add domain-specific data if available
                if ioc_type == 'domain':
                    whois = attributes.get('whois')
                    popularity_ranks = attributes.get('popularity_ranks', {})
                    if whois:
                        result_data['whois'] = whois
                    if popularity_ranks:
                        result_data['popularity_ranks'] = popularity_ranks
                
                return result_data
            elif response.status_code == 404:
                return {
                    'source': 'VirusTotal',
                    'malicious_count': 0,
                    'suspicious_count': 0,
                    'harmless_count': 0,
                    'undetected_count': 0,
                    'total_engines': 0,
                    'message': 'IOC not found in VirusTotal database'
                }
            else:
                return {'source': 'VirusTotal', 'error': f'HTTP {response.status_code}: {response.text}'}
                
        except requests.exceptions.Timeout:
            return {'source': 'VirusTotal', 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            return {'source': 'VirusTotal', 'error': f'Request error: {str(e)}'}
        except Exception as e:
            return {'source': 'VirusTotal', 'error': f'Unexpected error: {str(e)}'}
    
    def query_abuseipdb(self, ioc: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        """Query AbuseIPDB API (IP addresses only)"""
        if ioc_type != 'ip' or 'ABUSEIPDB_API_KEY' not in self.config:
            return None
            
        api_key = self.config['ABUSEIPDB_API_KEY']
        headers = {'Key': api_key, 'Accept': 'application/json'}
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            params = {'ipAddress': ioc, 'maxAgeInDays': 90, 'verbose': ''}
            
            response = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                ip_data = data.get('data', {})
                
                # Extract recent reports
                reports = ip_data.get('reports', [])
                recent_reports = []
                for report in reports[:10]:  # Last 10 reports
                    recent_reports.append({
                        'date': report.get('reportedAt'),
                        'comment': report.get('comment', ''),
                        'categories': report.get('categories', []),
                        'reporter_country': report.get('reporterCountryCode', '')
                    })
                
                # Abuse category mapping
                abuse_categories = {
                    3: 'Fraud Orders',
                    4: 'DDoS Attack',
                    5: 'FTP Brute-Force',
                    6: 'Ping of Death',
                    7: 'Phishing',
                    8: 'Fraud VoIP',
                    9: 'Open Proxy',
                    10: 'Web Spam',
                    11: 'Email Spam',
                    12: 'Blog Spam',
                    13: 'VPN IP',
                    14: 'Port Scan',
                    15: 'Hacking',
                    16: 'SQL Injection',
                    17: 'Spoofing',
                    18: 'Brute-Force',
                    19: 'Bad Web Bot',
                    20: 'Exploited Host',
                    21: 'Web App Attack',
                    22: 'SSH',
                    23: 'IoT Targeted'
                }
                
                # Calculate top abuse categories
                from collections import Counter
                all_categories = []
                for report in reports:
                    all_categories.extend(report.get('categories', []))
                
                category_counts = Counter(all_categories)
                top_abuse_categories = [
                    {'category': abuse_categories.get(cat_id, f'Category {cat_id}'), 'count': count}
                    for cat_id, count in category_counts.most_common(5)
                ]
                
                return {
                    'source': 'AbuseIPDB',
                    'abuse_confidence': ip_data.get('abuseConfidencePercentage', 0),
                    'is_public': ip_data.get('isPublic', False),
                    'country_code': ip_data.get('countryCode', ''),
                    'country_name': ip_data.get('countryName', ''),
                    'isp': ip_data.get('isp', ''),
                    'domain': ip_data.get('domain', ''),
                    'hostnames': ip_data.get('hostnames', []),
                    'usage_type': ip_data.get('usageType', ''),
                    'total_reports': ip_data.get('totalReports', 0),
                    'num_distinct_users': ip_data.get('numDistinctUsers', 0),
                    'last_reported_at': ip_data.get('lastReportedAt'),
                    'is_whitelisted': ip_data.get('isWhitelisted', False),
                    'recent_reports': recent_reports,
                    'top_abuse_categories': top_abuse_categories,
                    'raw_data': data if self._include_raw_data() else None
                }
            elif response.status_code == 422:
                return {'source': 'AbuseIPDB', 'error': 'Invalid IP address format'}
            else:
                return {'source': 'AbuseIPDB', 'error': f'HTTP {response.status_code}: {response.text}'}
                
        except requests.exceptions.Timeout:
            return {'source': 'AbuseIPDB', 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            return {'source': 'AbuseIPDB', 'error': f'Request error: {str(e)}'}
        except Exception as e:
            return {'source': 'AbuseIPDB', 'error': f'Unexpected error: {str(e)}'}
    
    def query_misp(self, ioc: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        """Query MISP instance"""
        if not all(key in self.config for key in ['MISP_URL', 'MISP_KEY']):
            return None
            
        try:
            from pymisp import PyMISP
            
            misp_url = self.config['MISP_URL']
            misp_key = self.config['MISP_KEY']
            misp_verifycert = self.config.get('MISP_VERIFYCERT', 'False').lower() == 'true'
            
            misp = PyMISP(misp_url, misp_key, misp_verifycert)
            
            # Search for the IOC
            search_result = misp.search(value=ioc, limit=10)
            
            if search_result and len(search_result) > 0:
                from collections import Counter
                
                events_info = []
                threat_levels = []
                all_tags = []
                threat_actors_malware = []
                
                for event in search_result[:10]:  # Analyze up to 10 events
                    if isinstance(event, dict) and 'Event' in event:
                        event_data = event['Event']
                        
                        # Map threat level ID to name
                        threat_level_id = event_data.get('threat_level_id', 4)
                        threat_level_map = {
                            1: 'High',
                            2: 'Medium',
                            3: 'Low',
                            4: 'Undefined'
                        }
                        threat_level = threat_level_map.get(int(threat_level_id), 'Undefined')
                        threat_levels.append(threat_level)
                        
                        # Extract tags
                        tags = []
                        if 'Tag' in event_data:
                            for tag in event_data['Tag']:
                                tag_name = tag.get('name', '')
                                tags.append(tag_name)
                                all_tags.append(tag_name)
                        
                        # Extract Galaxy information (threat actors, malware families, etc.)
                        galaxies = []
                        if 'Galaxy' in event_data:
                            for galaxy in event_data['Galaxy']:
                                galaxy_name = galaxy.get('name', '')
                                galaxies.append(galaxy_name)
                                
                                # Extract specific threat intel from galaxy clusters
                                if 'GalaxyCluster' in galaxy:
                                    for cluster in galaxy['GalaxyCluster']:
                                        cluster_value = cluster.get('value', '')
                                        if cluster_value:
                                            threat_actors_malware.append(cluster_value)
                        
                        events_info.append({
                            'id': event_data.get('id'),
                            'info': event_data.get('info'),
                            'threat_level': threat_level,
                            'org': event_data.get('Orgc', {}).get('name', '') if 'Orgc' in event_data else '',
                            'date': event_data.get('date'),
                            'published': event_data.get('published', False),
                            'attribute_count': event_data.get('attribute_count', 0),
                            'tags': tags,
                            'galaxies': galaxies
                        })
                
                # Calculate threat level distribution
                threat_level_distribution = dict(Counter(threat_levels))
                
                # Get top tags
                tag_counts = Counter(all_tags)
                top_tags = [{'tag': tag, 'count': count} for tag, count in tag_counts.most_common(10)]
                
                return {
                    'source': 'MISP',
                    'events_found': len(search_result),
                    'events_summary': events_info[:5],  # Return top 5 for summary
                    'threat_level_distribution': threat_level_distribution,
                    'top_tags': top_tags,
                    'threat_actors_malware': list(set(threat_actors_malware))[:10],  # Top 10 unique
                    'raw_data': search_result if self._include_raw_data() else None
                }
            else:
                return {
                    'source': 'MISP',
                    'events_found': 0,
                    'message': 'No events found in MISP'
                }
                
        except ImportError:
            return {'source': 'MISP', 'error': 'PyMISP library not available'}
        except Exception as e:
            return {'source': 'MISP', 'error': f'MISP query error: {str(e)}'}
    
    def query_shodan(self, ioc: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        """Query Shodan API for IP and domain information using free endpoints"""
        if 'SHODAN_API_KEY' not in self.config:
            return None
            
        # Shodan primarily supports IP addresses, but also has domain search
        if ioc_type not in ['ip', 'domain']:
            return None
            
        api_key = self.config['SHODAN_API_KEY']
        
        try:
            if ioc_type == 'ip':
                # Use the search API instead of host API (works with free accounts)
                url = "https://api.shodan.io/shodan/search"
                params = {
                    'key': api_key,
                    'query': f'ip:{ioc}',
                    'limit': 1
                }
                
                response = requests.get(url, params=params, timeout=self.timeout)
                
                if response.status_code == 200:
                    data = response.json()
                    matches = data.get('matches', [])
                    
                    if matches:
                        # Aggregate data from all matches
                        all_ports = set()
                        all_vulns = []
                        all_tags = set()
                        services = []
                        os_info = None
                        
                        # Use first match for general info
                        first_match = matches[0]
                        
                        # Process all matches
                        for match in matches:
                            # Collect ports
                            if match.get('port'):
                                all_ports.add(match.get('port'))
                            
                            # Collect vulnerabilities
                            if match.get('vulns'):
                                all_vulns.extend(match.get('vulns', []))
                            
                            # Collect tags
                            if match.get('tags'):
                                all_tags.update(match.get('tags', []))
                            
                            # Collect service information
                            service_info = {
                                'port': match.get('port'),
                                'transport': match.get('transport'),
                                'product': match.get('product'),
                                'version': match.get('version'),
                                'banner': match.get('data', '')[:200]  # First 200 chars
                            }
                            services.append(service_info)
                            
                            # Get OS if available
                            if not os_info and match.get('os'):
                                os_info = match.get('os')
                        
                        # Get location info
                        location = first_match.get('location', {})
                        
                        return {
                            'source': 'Shodan',
                            'ip': first_match.get('ip_str', ioc),
                            'hostnames': first_match.get('hostnames', []),
                            'country_code': location.get('country_code'),
                            'country_name': location.get('country_name'),
                            'city': location.get('city'),
                            'region_code': location.get('region_code'),
                            'postal_code': location.get('postal_code'),
                            'latitude': location.get('latitude'),
                            'longitude': location.get('longitude'),
                            'organization': first_match.get('org'),
                            'ports': sorted(list(all_ports)),
                            'open_ports_count': len(all_ports),
                            'services': services,
                            'vulnerabilities': list(set(all_vulns)),
                            'vulnerability_count': len(set(all_vulns)),
                            'tags': list(all_tags),
                            'os': os_info,
                            'last_updated': first_match.get('timestamp'),
                            'isp': first_match.get('isp'),
                            'asn': first_match.get('asn'),
                            'total_results': data.get('total', len(matches)),
                            'raw_data': data if self._include_raw_data() else None
                        }
                    else:
                        return {
                            'source': 'Shodan',
                            'message': 'IP address not found in Shodan database'
                        }
                elif response.status_code == 401:
                    return {'source': 'Shodan', 'error': 'Invalid API key'}
                elif response.status_code == 403:
                    return {'source': 'Shodan', 'error': 'API key does not have sufficient permissions'}
                else:
                    return {'source': 'Shodan', 'error': f'HTTP {response.status_code}: {response.text}'}
                    
            elif ioc_type == 'domain':
                # Try DNS resolve first (free endpoint)
                url = f"https://api.shodan.io/dns/resolve"
                params = {
                    'key': api_key,
                    'hostnames': ioc
                }
                
                response = requests.get(url, params=params, timeout=self.timeout)
                
                if response.status_code == 200:
                    data = response.json()
                    ip_address = data.get(ioc)
                    
                    if ip_address:
                        # If we get an IP, try to search for it
                        search_url = "https://api.shodan.io/shodan/search"
                        search_params = {
                            'key': api_key,
                            'query': f'hostname:{ioc}',
                            'limit': 1
                        }
                        
                        search_response = requests.get(search_url, params=search_params, timeout=self.timeout)
                        
                        if search_response.status_code == 200:
                            search_data = search_response.json()
                            matches = search_data.get('matches', [])
                            
                            if matches:
                                match = matches[0]
                                return {
                                    'source': 'Shodan',
                                    'domain': ioc,
                                    'resolved_ip': ip_address,
                                    'organization': match.get('org'),
                                    'country_code': match.get('location', {}).get('country_code'),
                                    'city': match.get('location', {}).get('city'),
                                    'isp': match.get('isp'),
                                    'asn': match.get('asn'),
                                    'ports': [match.get('port')] if match.get('port') else [],
                                    'raw_data': search_data if self._include_raw_data() else None
                                }
                        
                        # Fallback: just return resolved IP
                        return {
                            'source': 'Shodan',
                            'domain': ioc,
                            'resolved_ip': ip_address,
                            'message': 'Domain resolved to IP address'
                        }
                    else:
                        return {
                            'source': 'Shodan',
                            'message': 'Domain could not be resolved'
                        }
                elif response.status_code == 401:
                    return {'source': 'Shodan', 'error': 'Invalid API key'}
                else:
                    return {'source': 'Shodan', 'error': f'HTTP {response.status_code}: {response.text}'}
                    
        except requests.exceptions.Timeout:
            return {'source': 'Shodan', 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            return {'source': 'Shodan', 'error': f'Request error: {str(e)}'}
        except Exception as e:
            return {'source': 'Shodan', 'error': f'Unexpected error: {str(e)}'}
    
    def query_urlscan(self, ioc: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        """Query URLScan.io API for domain and URL information"""
        if 'URLSCAN_API_KEY' not in self.config:
            return None
            
        # URLScan.io primarily works with domains and URLs
        if ioc_type not in ['domain', 'ip']:
            return None
            
        api_key = self.config['URLSCAN_API_KEY']
        headers = {'API-Key': api_key}
        
        try:
            # Use the search API to find existing scans
            if ioc_type == 'domain':
                search_query = f'domain:{ioc}'
            elif ioc_type == 'ip':
                search_query = f'ip:{ioc}'
            else:
                return None
                
            url = "https://urlscan.io/api/v1/search/"
            params = {
                'q': search_query,
                'size': 5  # Limit to 5 most recent results
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])
                total = data.get('total', 0)
                
                if results:
                    # Get information from the most recent scan
                    latest_scan = results[0]
                    task = latest_scan.get('task', {})
                    page = latest_scan.get('page', {})
                    stats = latest_scan.get('stats', {})
                    
                    # Extract relevant information
                    scan_id = latest_scan.get('_id')
                    scan_url = task.get('url', '')
                    domain = task.get('domain', '')
                    
                    # Extract page information
                    ip = page.get('ip', '')
                    country = page.get('country', '')
                    server = page.get('server', '')
                    asn = page.get('asn', '')
                    asnname = page.get('asnname', '')
                    
                    # Extract multi-source verdict information
                    verdicts = latest_scan.get('verdicts', {})
                    overall_verdict = verdicts.get('overall', {})
                    urlscan_verdict = verdicts.get('urlscan', {})
                    engines_verdict = verdicts.get('engines', {})
                    community_verdict = verdicts.get('community', {})
                    
                    urlscan_malicious = urlscan_verdict.get('malicious', False)
                    engines_malicious = engines_verdict.get('malicious', False)
                    community_malicious = community_verdict.get('malicious', False)
                    
                    # Calculate malicious score based on multiple sources
                    malicious_sources = sum([
                        urlscan_malicious,
                        engines_malicious,
                        community_malicious
                    ])
                    malicious_score = int((malicious_sources / 3.0) * 100)
                    
                    # Extract page details
                    page_title = page.get('title', '')
                    status_code = page.get('status')
                    redirected = page.get('redirected', '')
                    
                    # Extract certificate information
                    certificates = []
                    if 'lists' in latest_scan:
                        lists_data = latest_scan['lists']
                        if 'certificates' in lists_data:
                            for cert in lists_data.get('certificates', [])[:3]:
                                cert_info = {
                                    'subject': cert.get('subjectName', ''),
                                    'issuer': cert.get('issuer', ''),
                                    'valid_from': cert.get('validFrom'),
                                    'valid_to': cert.get('validTo')
                                }
                                certificates.append(cert_info)
                        
                        # Extract contacted IPs and domains
                        contacted_ips = lists_data.get('ips', [])[:10]
                        contacted_domains = lists_data.get('linkDomains', [])[:10]
                    else:
                        contacted_ips = []
                        contacted_domains = []
                    
                    return {
                        'source': 'URLScan',
                        'url': scan_url,
                        'domain': domain,
                        'ip': ip,
                        'scan_id': scan_id,
                        'result_url': f"https://urlscan.io/result/{scan_id}/",
                        'screenshot_url': f"https://urlscan.io/screenshots/{scan_id}.png",
                        'verdict': 'malicious' if (urlscan_malicious or engines_malicious or community_malicious) else 'clean',
                        'urlscan_malicious': urlscan_malicious,
                        'engines_malicious': engines_malicious,
                        'community_malicious': community_malicious,
                        'malicious_score': malicious_score,
                        'page_title': page_title,
                        'status_code': status_code,
                        'redirected_to': redirected,
                        'certificates': certificates,
                        'contacted_ips': contacted_ips,
                        'contacted_domains': contacted_domains,
                        'server': server,
                        'country': country,
                        'asn': asn,
                        'asnname': asnname,
                        'phishing_detected': verdicts.get('phishing', {}).get('malicious', False),
                        'malware_detected': verdicts.get('malware', {}).get('malicious', False),
                        'scan_date': task.get('time'),
                        'total_results': total,
                        'raw_data': data if self._include_raw_data() else None
                    }
                else:
                    return {
                        'source': 'URLScan',
                        'message': f'No scans found for {ioc}',
                        'total_results': 0
                    }
                    
            elif response.status_code == 401:
                return {'source': 'URLScan', 'error': 'Invalid API key'}
            elif response.status_code == 429:
                return {'source': 'URLScan', 'error': 'Rate limit exceeded'}
            else:
                return {'source': 'URLScan', 'error': f'HTTP {response.status_code}: {response.text}'}
                
        except requests.exceptions.Timeout:
            return {'source': 'URLScan', 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            return {'source': 'URLScan', 'error': f'Request error: {str(e)}'}
        except Exception as e:
            return {'source': 'URLScan', 'error': f'Unexpected error: {str(e)}'}
    
    def query_alienvault(self, ioc: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        """Query AlienVault OTX (Open Threat Exchange)"""
        if 'ALIENVAULT_API_KEY' not in self.config:
            return None
            
        api_key = self.config['ALIENVAULT_API_KEY']
        headers = {'X-OTX-API-KEY': api_key}
        
        try:
            base_url = "https://otx.alienvault.com/api/v1/indicators"
            
            # Determine the appropriate endpoint based on IOC type
            if ioc_type == 'ip':
                url = f"{base_url}/IPv4/{ioc}/general"
            elif ioc_type == 'domain':
                url = f"{base_url}/domain/{ioc}/general"
            elif ioc_type == 'hash':
                url = f"{base_url}/file/{ioc}/general"
            else:
                return {'source': 'AlienVault OTX', 'error': 'Unsupported IOC type'}
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract pulse information (threat intelligence reports)
                pulse_info = data.get('pulse_info', {})
                pulses = pulse_info.get('pulses', [])
                pulse_count = pulse_info.get('count', 0)
                
                # Extract detailed pulse information
                pulse_details = []
                threat_tags = set()
                adversaries = set()
                malware_families = set()
                attack_ids = set()
                
                for pulse in pulses[:10]:  # Top 10 pulses
                    pulse_detail = {
                        'name': pulse.get('name', ''),
                        'description': pulse.get('description', '')[:200],  # First 200 chars
                        'created': pulse.get('created', ''),
                        'modified': pulse.get('modified', ''),
                        'author_name': pulse.get('author_name', ''),
                        'tlp': pulse.get('TLP', ''),  # Traffic Light Protocol
                        'tags': pulse.get('tags', [])[:5],  # Top 5 tags per pulse
                        'references': pulse.get('references', [])[:3],  # Top 3 references
                        'indicator_count': pulse.get('indicator_count', 0)
                    }
                    pulse_details.append(pulse_detail)
                    
                    # Collect tags
                    for tag in pulse.get('tags', []):
                        threat_tags.add(tag)
                    
                    # Collect adversaries
                    if pulse.get('adversary'):
                        adversaries.add(pulse.get('adversary'))
                    
                    # Collect malware families
                    for family in pulse.get('malware_families', []):
                        if isinstance(family, dict):
                            malware_families.add(family.get('display_name', ''))
                        else:
                            malware_families.add(str(family))
                    
                    # Collect attack IDs (MITRE ATT&CK)
                    for attack_id in pulse.get('attack_ids', []):
                        if isinstance(attack_id, dict):
                            attack_ids.add(attack_id.get('id', ''))
                        else:
                            attack_ids.add(str(attack_id))
                
                # Get reputation score (varies by IOC type)
                reputation = data.get('reputation', 0)
                
                # Additional type-specific data
                type_specific_data = {}
                
                if ioc_type == 'ip':
                    # Get additional IP-specific data
                    country = data.get('country_name', '')
                    asn = data.get('asn', '')
                    city = data.get('city', '')
                    continent = data.get('continent_code', '')
                    
                    type_specific_data = {
                        'country': country,
                        'asn': asn,
                        'city': city,
                        'continent': continent
                    }
                elif ioc_type == 'domain':
                    # Get additional domain-specific data
                    alexa_rank = data.get('alexa', '')
                    whois_url = data.get('whois', '')
                    
                    type_specific_data = {
                        'alexa_rank': alexa_rank,
                        'whois_url': whois_url
                    }
                elif ioc_type == 'hash':
                    # Get additional file-specific data
                    file_type = data.get('file_type', '')
                    file_class = data.get('file_class', '')
                    
                    type_specific_data = {
                        'file_type': file_type,
                        'file_class': file_class
                    }
                
                result_data = {
                    'source': 'AlienVault OTX',
                    'pulse_count': pulse_count,
                    'pulses': pulse_details,
                    'reputation': reputation,
                    'threat_tags': list(threat_tags)[:20],  # Top 20 unique tags
                    'adversaries': list(adversaries),
                    'malware_families': list(malware_families),
                    'attack_ids': list(attack_ids),  # MITRE ATT&CK IDs
                    **type_specific_data,
                    'raw_data': data if self._include_raw_data() else None
                }
                
                return result_data
            elif response.status_code == 404:
                return {
                    'source': 'AlienVault OTX',
                    'pulse_count': 0,
                    'message': 'IOC not found in AlienVault OTX database'
                }
            elif response.status_code == 403:
                return {'source': 'AlienVault OTX', 'error': 'Invalid API key or access denied'}
            else:
                return {'source': 'AlienVault OTX', 'error': f'HTTP {response.status_code}: {response.text}'}
                
        except requests.exceptions.Timeout:
            return {'source': 'AlienVault OTX', 'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            return {'source': 'AlienVault OTX', 'error': f'Request error: {str(e)}'}
        except Exception as e:
            return {'source': 'AlienVault OTX', 'error': f'Unexpected error: {str(e)}'}
    
    def collect_intelligence(self, ioc: str, include_raw_data: bool = False) -> Dict[str, Any]:
        """Collect intelligence from all available sources"""
        self._set_include_raw_data(include_raw_data)
        ioc_type = determine_ioc_type(ioc)
        
        results = {
            'ioc': ioc,
            'ioc_type': ioc_type,
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }
        
        # Query all available sources
        sources = [
            ('virustotal', self.query_virustotal),
            ('abuseipdb', self.query_abuseipdb),
            ('misp', self.query_misp),
            ('shodan', self.query_shodan),
            ('urlscan', self.query_urlscan),
            ('alienvault', self.query_alienvault)
        ]
        
        for source_name, query_func in sources:
            try:
                result = query_func(ioc, ioc_type)
                if result:
                    results['sources'][source_name] = result
            except Exception as e:
                results['sources'][source_name] = {'source': source_name, 'error': f'Service error: {str(e)}'}
        
        return results
    
    def _include_raw_data(self) -> bool:
        """Check if raw data should be included"""
        return getattr(self, '_raw_data_flag', False)
    
    def _set_include_raw_data(self, include: bool):
        """Set raw data inclusion flag"""
        self._raw_data_flag = include
    
    def get_available_sources(self) -> Dict[str, bool]:
        """Get status of available threat intelligence sources"""
        sources = {
            'virustotal': 'VIRUSTOTAL_API_KEY' in self.config,
            'abuseipdb': 'ABUSEIPDB_API_KEY' in self.config,
            'misp': all(key in self.config for key in ['MISP_URL', 'MISP_KEY']),
            'shodan': 'SHODAN_API_KEY' in self.config,
            'urlscan': 'URLSCAN_API_KEY' in self.config,
            'alienvault': 'ALIENVAULT_API_KEY' in self.config
        }
        return sources