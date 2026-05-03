import re
import json
from datetime import datetime
from urllib.parse import parse_qs
import pandas as pd
from typing import Dict, Any

class FeatureExtractor:
    """
    Extract 23 engineered features matching the feature_engineering notebook.
    Features aligned with v0.1.1 OJS access log ML pipeline.
    """

    # Suspicious patterns in paths
    SUSPICIOUS_PATTERNS = ['eval', 'exec', 'system', 'shell', 'cmd', 'bash', 'php', 'sql']
    
    # SQL injection patterns
    SQL_PATTERNS = ['union', 'select', 'drop', 'insert', 'update', 'delete', 'or', '--']
    
    # Suspicious tools in user agent
    SUSPICIOUS_TOOLS = ['curl', 'wget', 'python', 'sqlmap']
    
    # Code indicators in body
    CODE_KEYWORDS = ['<?php', 'shell_exec', 'base64']

    def extract_from_raw(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract all 23 features from raw HTTP request data.
        
        Args:
            data: Dict with keys: path, query, body, headers, ip, timestamp (optional)
        
        Returns:
            Dict with all 23 engineered features
        """
        path = str(data.get("path", ""))
        query = str(data.get("query", ""))
        body = str(data.get("body", ""))
        headers = self._parse_headers(data.get("headers", {}))
        ip = data.get("ip", "")
        timestamp = data.get("timestamp")

        features = {}

        # ========== Section 2: URL/Path Features (5 features - path_special_chars removed by SelectKBest) ==========
        features['path_depth'] = path.count('/')
        # Removed: features['path_special_chars'] = len(re.findall(r'[^\w/.-]', path))  # Not selected by SelectKBest
        features['path_encoded_chars'] = path.count('%')
        features['query_param_count'] = query.count('&') + (1 if query and query != '' else 0)
        features['query_special_chars'] = len(re.findall(r'[^\w&=.]', query))
        features['suspicious_path'] = sum(1 for p in self.SUSPICIOUS_PATTERNS if p.lower() in path.lower())

        # ========== Section 3: HTTP Header Features (2 features - suspicious_headers removed by SelectKBest) ==========
        features['header_count'] = len(headers)
        features['user_agent_length'] = len(headers.get('User-Agent', ''))
        # Removed: features['suspicious_headers'] = self._check_suspicious_headers(headers)  # Not selected by SelectKBest

        # ========== Section 4: Request Body Analysis (2 features) ==========
        features['body_contains_code'] = 1 if any(kw in body.lower() for kw in self.CODE_KEYWORDS) else 0
        features['body_special_chars_ratio'] = len(re.findall(r'[^\w\s]', body)) / max(len(body), 1)

        # ========== Section 5: IP-based Features (3 features) ==========
        # Note: These require statistical info from training data
        # For real-time prediction, use pre-computed IP statistics
        features['ip_attack_rate'] = 0.0  # Will be filled from IP statistics
        features['ip_request_count'] = 1.0  # Will be filled from IP statistics
        features['is_high_risk_ip'] = 0  # Will be filled from IP statistics

        # ========== Section 6: Time-based Features (5 features) ==========
        if timestamp:
            try:
                if isinstance(timestamp, str):
                    dt = pd.to_datetime(timestamp)
                else:
                    dt = timestamp
                features['hour'] = dt.hour
                features['day_of_week'] = dt.dayofweek
                features['is_business_hours'] = 1 if (9 <= dt.hour <= 17) else 0
                features['is_night_time'] = 1 if (dt.hour >= 22 or dt.hour <= 5) else 0
            except:
                features['hour'] = 0
                features['day_of_week'] = 0
                features['is_business_hours'] = 0
                features['is_night_time'] = 0
        else:
            features['hour'] = 0
            features['day_of_week'] = 0
            features['is_business_hours'] = 0
            features['is_night_time'] = 0
        
        features['request_freq_per_hour'] = 1  # Will be filled from historical data

        # ========== Section 7: Encoding & Pattern Detection (4 features - sql_injection_score removed by SelectKBest) ==========
        features['has_url_encoding'] = 1 if '%' in path else 0
        features['has_double_encoding'] = 1 if '%25' in path else 0
        features['has_directory_traversal'] = 1 if '../' in path else 0
        # Removed: sql_injection_score (not selected by SelectKBest)

        return features

    def _parse_headers(self, headers) -> Dict[str, str]:
        """Parse headers from string or dict format."""
        if isinstance(headers, dict):
            return headers
        
        if isinstance(headers, str):
            if not headers or headers == '{}':
                return {}
            try:
                return json.loads(headers)
            except:
                return {}
        
        return {}

    def _check_suspicious_headers(self, headers: Dict[str, str]) -> int:
        """Check for suspicious patterns in headers."""
        suspicious_count = 0
        user_agent = headers.get('User-Agent', '').lower()
        
        if any(tool in user_agent for tool in self.SUSPICIOUS_TOOLS):
            suspicious_count += 1
        
        return suspicious_count

    @staticmethod
    def get_feature_names():
        """Return list of 20 feature names selected by trained model.
        
        Model was trained with SelectKBest and selected 20 out of 23 engineered features.
        Removed features: path_special_chars, suspicious_headers, sql_injection_score
        """
        return [
            # URL/Path Features (5)
            'path_depth', 'path_encoded_chars', 'query_param_count',
            'query_special_chars', 'suspicious_path',
            # HTTP Header Features (2)
            'header_count', 'user_agent_length',
            # Request Body Features (2)
            'body_contains_code', 'body_special_chars_ratio',
            # IP-based Features (3)
            'ip_attack_rate', 'ip_request_count', 'is_high_risk_ip',
            # Time-based Features (5)
            'hour', 'day_of_week', 'is_business_hours', 'is_night_time',
            'request_freq_per_hour',
            # Encoding & Pattern Features (4)
            'has_url_encoding', 'has_double_encoding', 'has_directory_traversal'
        ]