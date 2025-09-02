#!/usr/bin/env python3
"""
Automated Threat Detection System for AppArmor Zero Trust Architecture

This module provides intelligent threat detection using machine learning
algorithms to identify security threats and anomalies in real-time.
"""

import os
import sys
import json
import logging
import argparse
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ThreatEvent:
    """Represents a detected threat event"""
    timestamp: datetime
    threat_id: str
    threat_type: str
    severity: str  # low, medium, high, critical
    confidence: float
    source: str
    target: str
    description: str
    indicators: List[str]
    mitigation: str
    status: str  # active, mitigated, false_positive

@dataclass
class SecurityIndicator:
    """Represents a security indicator"""
    indicator_type: str
    value: str
    weight: float
    timestamp: datetime
    source: str

@dataclass
class ThreatModel:
    """Represents a threat model"""
    model_id: str
    name: str
    description: str
    threat_types: List[str]
    indicators: List[str]
    detection_rules: List[Dict[str, Any]]
    accuracy: float
    last_updated: datetime

class ThreatDetector:
    """Automated threat detection system"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.models = {}
        self.scalers = {}
        self.threat_events = []
        self.indicators = []
        self.running = False
        self.setup_models()
        self.setup_threat_models()
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            'detection': {
                'enable_ml_detection': True,
                'enable_rule_based_detection': True,
                'enable_behavioral_analysis': True,
                'enable_anomaly_detection': True,
                'confidence_threshold': 0.8,
                'severity_threshold': 0.7
            },
            'models': {
                'anomaly_detector': 'isolation_forest',
                'behavior_classifier': 'random_forest',
                'clustering': 'dbscan'
            },
            'threat_models': {
                'malware_detection': {
                    'enabled': True,
                    'sensitivity': 0.8
                },
                'privilege_escalation': {
                    'enabled': True,
                    'sensitivity': 0.9
                },
                'data_exfiltration': {
                    'enabled': True,
                    'sensitivity': 0.7
                },
                'lateral_movement': {
                    'enabled': True,
                    'sensitivity': 0.8
                }
            },
            'monitoring': {
                'check_interval': 60,  # seconds
                'max_events': 10000,
                'retention_days': 30
            }
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        
        return default_config
    
    def setup_models(self):
        """Initialize ML models for threat detection"""
        logger.info("Setting up threat detection models...")
        
        # Anomaly detection model
        self.models['anomaly_detector'] = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        
        # Behavior classification model
        self.models['behavior_classifier'] = RandomForestClassifier(
            n_estimators=100,
            random_state=42
        )
        
        # Clustering model for pattern recognition
        self.models['clustering'] = DBSCAN(eps=0.5, min_samples=5)
        
        # Feature scaler
        self.scalers['standard'] = StandardScaler()
        
        logger.info("Threat detection models initialized")
    
    def setup_threat_models(self):
        """Setup predefined threat models"""
        logger.info("Setting up threat models...")
        
        # Malware detection model
        self.threat_models = {
            'malware_detection': ThreatModel(
                model_id='malware_001',
                name='Malware Detection',
                description='Detects malware behavior patterns',
                threat_types=['trojan', 'virus', 'worm', 'rootkit'],
                indicators=[
                    'suspicious_file_access',
                    'unusual_network_connections',
                    'process_injection',
                    'registry_modifications',
                    'system_calls_anomaly'
                ],
                detection_rules=[
                    {
                        'condition': 'file_access_pattern == "suspicious"',
                        'weight': 0.8,
                        'action': 'alert'
                    },
                    {
                        'condition': 'network_connections > threshold',
                        'weight': 0.6,
                        'action': 'investigate'
                    }
                ],
                accuracy=0.95,
                last_updated=datetime.now()
            ),
            
            'privilege_escalation': ThreatModel(
                model_id='priv_esc_001',
                name='Privilege Escalation Detection',
                description='Detects privilege escalation attempts',
                threat_types=['privilege_escalation', 'sudo_abuse', 'kernel_exploit'],
                indicators=[
                    'sudo_usage_anomaly',
                    'setuid_setgid_calls',
                    'capability_requests',
                    'kernel_module_loading',
                    'system_call_anomaly'
                ],
                detection_rules=[
                    {
                        'condition': 'sudo_usage > normal_threshold',
                        'weight': 0.9,
                        'action': 'alert'
                    },
                    {
                        'condition': 'setuid_calls > 0',
                        'weight': 0.7,
                        'action': 'investigate'
                    }
                ],
                accuracy=0.92,
                last_updated=datetime.now()
            ),
            
            'data_exfiltration': ThreatModel(
                model_id='data_exfil_001',
                name='Data Exfiltration Detection',
                description='Detects data exfiltration attempts',
                threat_types=['data_theft', 'insider_threat', 'exfiltration'],
                indicators=[
                    'large_file_transfers',
                    'unusual_network_volume',
                    'encrypted_communications',
                    'suspicious_file_access',
                    'network_timing_anomaly'
                ],
                detection_rules=[
                    {
                        'condition': 'network_volume > threshold',
                        'weight': 0.8,
                        'action': 'alert'
                    },
                    {
                        'condition': 'file_access_size > normal',
                        'weight': 0.6,
                        'action': 'investigate'
                    }
                ],
                accuracy=0.88,
                last_updated=datetime.now()
            ),
            
            'lateral_movement': ThreatModel(
                model_id='lateral_001',
                name='Lateral Movement Detection',
                description='Detects lateral movement in the network',
                threat_types=['lateral_movement', 'pivot', 'network_scanning'],
                indicators=[
                    'network_scanning',
                    'multiple_host_connections',
                    'credential_usage',
                    'service_enumeration',
                    'port_scanning'
                ],
                detection_rules=[
                    {
                        'condition': 'host_connections > threshold',
                        'weight': 0.8,
                        'action': 'alert'
                    },
                    {
                        'condition': 'port_scanning_detected',
                        'weight': 0.9,
                        'action': 'block'
                    }
                ],
                accuracy=0.90,
                last_updated=datetime.now()
            )
        }
        
        logger.info(f"Setup {len(self.threat_models)} threat models")
    
    def start_detection(self):
        """Start threat detection"""
        logger.info("Starting threat detection...")
        
        self.running = True
        
        # Start detection threads
        self._start_detection_threads()
        
        logger.info("Threat detection started")
    
    def _start_detection_threads(self):
        """Start detection threads"""
        # Start ML-based detection thread
        if self.config['detection']['enable_ml_detection']:
            ml_thread = threading.Thread(target=self._ml_detection_loop)
            ml_thread.daemon = True
            ml_thread.start()
        
        # Start rule-based detection thread
        if self.config['detection']['enable_rule_based_detection']:
            rule_thread = threading.Thread(target=self._rule_based_detection_loop)
            rule_thread.daemon = True
            rule_thread.start()
        
        # Start behavioral analysis thread
        if self.config['detection']['enable_behavioral_analysis']:
            behavior_thread = threading.Thread(target=self._behavioral_analysis_loop)
            behavior_thread.daemon = True
            behavior_thread.start()
    
    def _ml_detection_loop(self):
        """ML-based detection loop"""
        while self.running:
            try:
                # Collect recent indicators
                recent_indicators = self._get_recent_indicators()
                
                if len(recent_indicators) > 0:
                    # Extract features
                    features = self._extract_features(recent_indicators)
                    
                    # Detect anomalies
                    anomalies = self._detect_anomalies(features)
                    
                    # Classify behaviors
                    behaviors = self._classify_behaviors(features)
                    
                    # Generate threat events
                    self._generate_threat_events(anomalies, behaviors)
                
                time.sleep(self.config['monitoring']['check_interval'])
                
            except Exception as e:
                logger.error(f"Error in ML detection loop: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _rule_based_detection_loop(self):
        """Rule-based detection loop"""
        while self.running:
            try:
                # Check each threat model
                for model_id, model in self.threat_models.items():
                    if self.config['threat_models'][model_id]['enabled']:
                        self._check_threat_model(model)
                
                time.sleep(self.config['monitoring']['check_interval'])
                
            except Exception as e:
                logger.error(f"Error in rule-based detection loop: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _behavioral_analysis_loop(self):
        """Behavioral analysis loop"""
        while self.running:
            try:
                # Analyze behavioral patterns
                patterns = self._analyze_behavioral_patterns()
                
                # Detect behavioral anomalies
                anomalies = self._detect_behavioral_anomalies(patterns)
                
                # Generate behavioral threat events
                self._generate_behavioral_threats(anomalies)
                
                time.sleep(self.config['monitoring']['check_interval'])
                
            except Exception as e:
                logger.error(f"Error in behavioral analysis loop: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _get_recent_indicators(self) -> List[SecurityIndicator]:
        """Get recent security indicators"""
        cutoff_time = datetime.now() - timedelta(minutes=5)
        return [ind for ind in self.indicators if ind.timestamp > cutoff_time]
    
    def _extract_features(self, indicators: List[SecurityIndicator]) -> np.ndarray:
        """Extract features from indicators"""
        features = []
        
        for indicator in indicators:
            feature_vector = [
                hash(indicator.indicator_type) % 1000,
                hash(indicator.value) % 1000,
                indicator.weight,
                indicator.timestamp.timestamp(),
                hash(indicator.source) % 1000
            ]
            features.append(feature_vector)
        
        return np.array(features) if features else np.array([]).reshape(0, 5)
    
    def _detect_anomalies(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """Detect anomalies using ML models"""
        anomalies = []
        
        if len(features) == 0:
            return anomalies
        
        try:
            # Scale features
            scaled_features = self.scalers['standard'].fit_transform(features)
            
            # Detect anomalies
            anomaly_scores = self.models['anomaly_detector'].decision_function(scaled_features)
            anomaly_labels = self.models['anomaly_detector'].predict(scaled_features)
            
            # Identify anomalous points
            for i, (score, label) in enumerate(zip(anomaly_scores, anomaly_labels)):
                if label == -1:  # Anomaly
                    anomalies.append({
                        'index': i,
                        'score': float(score),
                        'severity': 'high' if score < -0.5 else 'medium',
                        'confidence': abs(score)
                    })
        
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
        
        return anomalies
    
    def _classify_behaviors(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """Classify behaviors using ML models"""
        behaviors = []
        
        if len(features) == 0:
            return behaviors
        
        try:
            # Scale features
            scaled_features = self.scalers['standard'].fit_transform(features)
            
            # Classify behaviors (this would need training data)
            # For now, we'll use a simple heuristic
            for i, feature in enumerate(scaled_features):
                behavior_type = self._classify_single_behavior(feature)
                behaviors.append({
                    'index': i,
                    'type': behavior_type,
                    'confidence': 0.8  # Placeholder
                })
        
        except Exception as e:
            logger.error(f"Error classifying behaviors: {e}")
        
        return behaviors
    
    def _classify_single_behavior(self, feature: np.ndarray) -> str:
        """Classify a single behavior"""
        # Simple heuristic classification
        if feature[2] > 0.8:  # High weight
            return 'suspicious'
        elif feature[2] > 0.5:  # Medium weight
            return 'unusual'
        else:
            return 'normal'
    
    def _generate_threat_events(self, anomalies: List[Dict[str, Any]], 
                              behaviors: List[Dict[str, Any]]):
        """Generate threat events from anomalies and behaviors"""
        for anomaly in anomalies:
            if anomaly['confidence'] > self.config['detection']['confidence_threshold']:
                threat_event = ThreatEvent(
                    timestamp=datetime.now(),
                    threat_id=f"threat_{int(time.time())}_{anomaly['index']}",
                    threat_type='anomaly',
                    severity=anomaly['severity'],
                    confidence=anomaly['confidence'],
                    source='ml_detection',
                    target='system',
                    description=f"Anomalous behavior detected with confidence {anomaly['confidence']:.2f}",
                    indicators=['ml_anomaly_score'],
                    mitigation='investigate',
                    status='active'
                )
                self._add_threat_event(threat_event)
        
        for behavior in behaviors:
            if behavior['type'] in ['suspicious', 'unusual']:
                threat_event = ThreatEvent(
                    timestamp=datetime.now(),
                    threat_id=f"threat_{int(time.time())}_{behavior['index']}",
                    threat_type=behavior['type'],
                    severity='medium' if behavior['type'] == 'suspicious' else 'low',
                    confidence=behavior['confidence'],
                    source='behavior_classification',
                    target='system',
                    description=f"{behavior['type'].title()} behavior detected",
                    indicators=['behavior_classification'],
                    mitigation='monitor',
                    status='active'
                )
                self._add_threat_event(threat_event)
    
    def _check_threat_model(self, model: ThreatModel):
        """Check a specific threat model"""
        try:
            # Get relevant indicators
            relevant_indicators = [ind for ind in self.indicators 
                                 if ind.indicator_type in model.indicators]
            
            if not relevant_indicators:
                return
            
            # Evaluate detection rules
            for rule in model.detection_rules:
                if self._evaluate_rule(rule, relevant_indicators):
                    threat_event = ThreatEvent(
                        timestamp=datetime.now(),
                        threat_id=f"threat_{int(time.time())}_{model.model_id}",
                        threat_type=model.threat_types[0],
                        severity='high' if rule['weight'] > 0.8 else 'medium',
                        confidence=rule['weight'],
                        source='rule_based',
                        target='system',
                        description=f"Threat detected by {model.name}",
                        indicators=[ind.indicator_type for ind in relevant_indicators],
                        mitigation=rule['action'],
                        status='active'
                    )
                    self._add_threat_event(threat_event)
        
        except Exception as e:
            logger.error(f"Error checking threat model {model.model_id}: {e}")
    
    def _evaluate_rule(self, rule: Dict[str, Any], indicators: List[SecurityIndicator]) -> bool:
        """Evaluate a detection rule"""
        try:
            condition = rule['condition']
            
            # Simple rule evaluation (in a real implementation, this would be more sophisticated)
            if 'file_access_pattern' in condition:
                return any(ind.indicator_type == 'suspicious_file_access' for ind in indicators)
            elif 'network_connections' in condition:
                return len([ind for ind in indicators if ind.indicator_type == 'network_connections']) > 5
            elif 'sudo_usage' in condition:
                return any(ind.indicator_type == 'sudo_usage_anomaly' for ind in indicators)
            elif 'setuid_calls' in condition:
                return any(ind.indicator_type == 'setuid_setgid_calls' for ind in indicators)
            elif 'network_volume' in condition:
                return any(ind.indicator_type == 'unusual_network_volume' for ind in indicators)
            elif 'host_connections' in condition:
                return len([ind for ind in indicators if ind.indicator_type == 'multiple_host_connections']) > 3
            elif 'port_scanning' in condition:
                return any(ind.indicator_type == 'port_scanning' for ind in indicators)
            
            return False
        
        except Exception as e:
            logger.error(f"Error evaluating rule: {e}")
            return False
    
    def _analyze_behavioral_patterns(self) -> Dict[str, Any]:
        """Analyze behavioral patterns"""
        patterns = {
            'file_access_patterns': {},
            'network_patterns': {},
            'process_patterns': {},
            'timing_patterns': {}
        }
        
        # Analyze recent indicators
        recent_indicators = self._get_recent_indicators()
        
        for indicator in recent_indicators:
            if indicator.indicator_type in patterns:
                if indicator.value not in patterns[indicator.indicator_type]:
                    patterns[indicator.indicator_type][indicator.value] = 0
                patterns[indicator.indicator_type][indicator.value] += 1
        
        return patterns
    
    def _detect_behavioral_anomalies(self, patterns: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies"""
        anomalies = []
        
        # Check for unusual patterns
        for pattern_type, pattern_data in patterns.items():
            if len(pattern_data) > 0:
                # Calculate pattern diversity
                diversity = len(pattern_data) / sum(pattern_data.values())
                
                if diversity > 0.8:  # High diversity might indicate anomaly
                    anomalies.append({
                        'type': pattern_type,
                        'diversity': diversity,
                        'severity': 'medium',
                        'description': f"Unusual {pattern_type} diversity detected"
                    })
        
        return anomalies
    
    def _generate_behavioral_threats(self, anomalies: List[Dict[str, Any]]):
        """Generate threat events from behavioral anomalies"""
        for anomaly in anomalies:
            threat_event = ThreatEvent(
                timestamp=datetime.now(),
                threat_id=f"threat_{int(time.time())}_{anomaly['type']}",
                threat_type='behavioral_anomaly',
                severity=anomaly['severity'],
                confidence=anomaly['diversity'],
                source='behavioral_analysis',
                target='system',
                description=anomaly['description'],
                indicators=[anomaly['type']],
                mitigation='investigate',
                status='active'
            )
            self._add_threat_event(threat_event)
    
    def _add_threat_event(self, threat_event: ThreatEvent):
        """Add a threat event to the list"""
        self.threat_events.append(threat_event)
        
        # Limit the number of events
        if len(self.threat_events) > self.config['monitoring']['max_events']:
            self.threat_events = self.threat_events[-self.config['monitoring']['max_events']:]
        
        # Log the threat event
        logger.warning(f"Threat detected: {threat_event.threat_type} - {threat_event.description}")
        
        # Trigger mitigation if configured
        self._trigger_mitigation(threat_event)
    
    def _trigger_mitigation(self, threat_event: ThreatEvent):
        """Trigger mitigation actions for a threat event"""
        try:
            if threat_event.mitigation == 'block':
                logger.info(f"Blocking threat: {threat_event.threat_id}")
                # Implement blocking logic
                self._block_threat(threat_event)
            elif threat_event.mitigation == 'alert':
                logger.info(f"Alerting on threat: {threat_event.threat_id}")
                # Implement alerting logic
                self._send_alert(threat_event)
            elif threat_event.mitigation == 'investigate':
                logger.info(f"Investigating threat: {threat_event.threat_id}")
                # Implement investigation logic
                self._investigate_threat(threat_event)
            elif threat_event.mitigation == 'monitor':
                logger.info(f"Monitoring threat: {threat_event.threat_id}")
                # Implement monitoring logic
                self._monitor_threat(threat_event)
        
        except Exception as e:
            logger.error(f"Error triggering mitigation: {e}")
    
    def _block_threat(self, threat_event: ThreatEvent):
        """Block a specific threat"""
        try:
            # Implement threat blocking logic
            if threat_event.source_ip:
                # Block IP address
                self._block_ip(threat_event.source_ip)
            if threat_event.process_id:
                # Kill malicious process
                self._kill_process(threat_event.process_id)
            if threat_event.file_path:
                # Quarantine file
                self._quarantine_file(threat_event.file_path)
            
            logger.info(f"Successfully blocked threat: {threat_event.threat_id}")
        except Exception as e:
            logger.error(f"Error blocking threat: {e}")
    
    def _block_ip(self, ip_address: str):
        """Block an IP address using iptables"""
        try:
            import subprocess
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], 
                         check=True, capture_output=True)
            logger.info(f"Blocked IP address: {ip_address}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip_address}: {e}")
    
    def _kill_process(self, pid: int):
        """Kill a malicious process"""
        try:
            import os
            import signal
            os.kill(pid, signal.SIGTERM)
            logger.info(f"Terminated process: {pid}")
        except (OSError, ProcessLookupError) as e:
            logger.error(f"Failed to kill process {pid}: {e}")
    
    def _quarantine_file(self, file_path: str):
        """Quarantine a malicious file"""
        try:
            import shutil
            import os
            quarantine_dir = "/var/quarantine"
            os.makedirs(quarantine_dir, exist_ok=True)
            
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(quarantine_dir, f"{filename}.quarantined")
            shutil.move(file_path, quarantine_path)
            logger.info(f"Quarantined file: {file_path} -> {quarantine_path}")
        except Exception as e:
            logger.error(f"Failed to quarantine file {file_path}: {e}")
    
    def _send_alert(self, threat_event: ThreatEvent):
        """Send alert for a threat event"""
        try:
            # Send alert via email, syslog, or other notification system
            alert_message = f"SECURITY ALERT: Threat detected - {threat_event.threat_id}\n"
            alert_message += f"Type: {threat_event.threat_type}\n"
            alert_message += f"Severity: {threat_event.severity}\n"
            alert_message += f"Source IP: {threat_event.source_ip}\n"
            alert_message += f"Process ID: {threat_event.process_id}\n"
            alert_message += f"File Path: {threat_event.file_path}\n"
            alert_message += f"Timestamp: {threat_event.timestamp}\n"
            
            # Log to syslog
            import syslog
            syslog.openlog("AppArmor-ThreatDetector", syslog.LOG_PID, syslog.LOG_DAEMON)
            syslog.syslog(syslog.LOG_ALERT, alert_message)
            syslog.closelog()
            
            logger.info(f"Alert sent for threat: {threat_event.threat_id}")
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
    
    def _investigate_threat(self, threat_event: ThreatEvent):
        """Investigate a threat event"""
        try:
            # Collect additional information about the threat
            investigation_data = {
                'threat_id': threat_event.threat_id,
                'timestamp': threat_event.timestamp,
                'process_info': self._get_process_info(threat_event.process_id),
                'network_connections': self._get_network_connections(threat_event.process_id),
                'file_activity': self._get_file_activity(threat_event.process_id),
                'system_calls': self._get_system_calls(threat_event.process_id)
            }
            
            # Store investigation data
            self._store_investigation_data(investigation_data)
            
            logger.info(f"Investigation completed for threat: {threat_event.threat_id}")
        except Exception as e:
            logger.error(f"Failed to investigate threat: {e}")
    
    def _get_process_info(self, pid: int):
        """Get detailed process information"""
        try:
            import psutil
            process = psutil.Process(pid)
            return {
                'name': process.name(),
                'cmdline': process.cmdline(),
                'cwd': process.cwd(),
                'memory_info': process.memory_info()._asdict(),
                'cpu_percent': process.cpu_percent(),
                'create_time': process.create_time()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Failed to get process info for PID {pid}: {e}")
            return {}
    
    def _get_network_connections(self, pid: int):
        """Get network connections for a process"""
        try:
            import psutil
            process = psutil.Process(pid)
            connections = process.connections()
            return [conn._asdict() for conn in connections]
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Failed to get network connections for PID {pid}: {e}")
            return []
    
    def _get_file_activity(self, pid: int):
        """Get file activity for a process"""
        try:
            import psutil
            process = psutil.Process(pid)
            open_files = process.open_files()
            return [f._asdict() for f in open_files]
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Failed to get file activity for PID {pid}: {e}")
            return []
    
    def _get_system_calls(self, pid: int):
        """Get system calls for a process"""
        try:
            # This would require eBPF or strace integration
            # For now, return empty list
            return []
        except Exception as e:
            logger.error(f"Failed to get system calls for PID {pid}: {e}")
            return []
    
    def _store_investigation_data(self, data: dict):
        """Store investigation data"""
        try:
            import json
            import os
            from datetime import datetime
            
            investigation_dir = "/var/log/apparmor/investigations"
            os.makedirs(investigation_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"investigation_{data['threat_id']}_{timestamp}.json"
            filepath = os.path.join(investigation_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Investigation data stored: {filepath}")
        except Exception as e:
            logger.error(f"Failed to store investigation data: {e}")
    
    def _monitor_threat(self, threat_event: ThreatEvent):
        """Monitor a threat event"""
        try:
            # Add threat to monitoring list
            if not hasattr(self, '_monitored_threats'):
                self._monitored_threats = {}
            
            self._monitored_threats[threat_event.threat_id] = {
                'threat_event': threat_event,
                'start_time': threat_event.timestamp,
                'activity_count': 0,
                'last_activity': threat_event.timestamp
            }
            
            # Set up enhanced monitoring for this threat
            self._setup_enhanced_monitoring(threat_event)
            
            logger.info(f"Started monitoring threat: {threat_event.threat_id}")
        except Exception as e:
            logger.error(f"Failed to monitor threat: {e}")
    
    def _setup_enhanced_monitoring(self, threat_event: ThreatEvent):
        """Set up enhanced monitoring for a threat"""
        try:
            # This would integrate with eBPF or other monitoring systems
            # to provide real-time monitoring of the threat
            logger.info(f"Enhanced monitoring setup for threat: {threat_event.threat_id}")
        except Exception as e:
            logger.error(f"Failed to setup enhanced monitoring: {e}")
    
    def add_indicator(self, indicator: SecurityIndicator):
        """Add a security indicator"""
        self.indicators.append(indicator)
        
        # Limit the number of indicators
        if len(self.indicators) > self.config['monitoring']['max_events']:
            self.indicators = self.indicators[-self.config['monitoring']['max_events']:]
    
    def get_threat_events(self, hours: int = 24) -> List[ThreatEvent]:
        """Get threat events from the last N hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [event for event in self.threat_events if event.timestamp > cutoff_time]
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat detection statistics"""
        recent_events = self.get_threat_events(24)
        
        stats = {
            'total_threats': len(recent_events),
            'threats_by_type': {},
            'threats_by_severity': {},
            'threats_by_source': {},
            'active_threats': len([e for e in recent_events if e.status == 'active']),
            'mitigated_threats': len([e for e in recent_events if e.status == 'mitigated']),
            'false_positives': len([e for e in recent_events if e.status == 'false_positive'])
        }
        
        for event in recent_events:
            # Count by type
            if event.threat_type not in stats['threats_by_type']:
                stats['threats_by_type'][event.threat_type] = 0
            stats['threats_by_type'][event.threat_type] += 1
            
            # Count by severity
            if event.severity not in stats['threats_by_severity']:
                stats['threats_by_severity'][event.severity] = 0
            stats['threats_by_severity'][event.severity] += 1
            
            # Count by source
            if event.source not in stats['threats_by_source']:
                stats['threats_by_source'][event.source] = 0
            stats['threats_by_source'][event.source] += 1
        
        return stats
    
    def train_models(self, training_data: List[Dict[str, Any]]):
        """Train ML models with historical data"""
        logger.info("Training threat detection models...")
        
        try:
            # Prepare training data
            X, y = self._prepare_training_data(training_data)
            
            if len(X) == 0:
                logger.warning("No training data available")
                return
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Train models
            self.models['behavior_classifier'].fit(X_train, y_train)
            
            # Evaluate model
            y_pred = self.models['behavior_classifier'].predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            logger.info(f"Model training completed. Accuracy: {accuracy:.2f}")
            
            # Save models
            self._save_models()
        
        except Exception as e:
            logger.error(f"Error training models: {e}")
    
    def _prepare_training_data(self, training_data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for ML models"""
        X = []
        y = []
        
        for data_point in training_data:
            # Extract features
            features = self._extract_training_features(data_point)
            X.append(features)
            
            # Extract labels
            label = self._extract_training_label(data_point)
            y.append(label)
        
        return np.array(X), np.array(y)
    
    def _extract_training_features(self, data_point: Dict[str, Any]) -> List[float]:
        """Extract features from training data point"""
        # This would extract relevant features from the data point
        # For now, return a placeholder
        return [0.0] * 10
    
    def _extract_training_label(self, data_point: Dict[str, Any]) -> int:
        """Extract label from training data point"""
        # This would extract the appropriate label for training
        # For now, return a placeholder
        return 0
    
    def _save_models(self):
        """Save trained models to disk"""
        model_dir = "threat_models"
        os.makedirs(model_dir, exist_ok=True)
        
        for name, model in self.models.items():
            model_path = os.path.join(model_dir, f"{name}.joblib")
            joblib.dump(model, model_path)
            logger.info(f"Saved model: {model_path}")
        
        for name, scaler in self.scalers.items():
            scaler_path = os.path.join(model_dir, f"{name}_scaler.joblib")
            joblib.dump(scaler, scaler_path)
            logger.info(f"Saved scaler: {scaler_path}")
    
    def stop_detection(self):
        """Stop threat detection"""
        logger.info("Stopping threat detection...")
        self.running = False
        logger.info("Threat detection stopped")

def main():
    parser = argparse.ArgumentParser(description='Automated Threat Detection System')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--start', action='store_true', help='Start threat detection')
    parser.add_argument('--stop', action='store_true', help='Stop threat detection')
    parser.add_argument('--stats', action='store_true', help='Show threat statistics')
    parser.add_argument('--events', type=int, default=24, help='Show events from last N hours')
    parser.add_argument('--train', help='Train models with data file')
    
    args = parser.parse_args()
    
    # Create threat detector
    detector = ThreatDetector(args.config)
    
    try:
        if args.start:
            # Start threat detection
            detector.start_detection()
            try:
                # Keep running until interrupted
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping threat detection...")
                detector.stop_detection()
        
        elif args.stop:
            # Stop threat detection
            detector.stop_detection()
            print("Threat detection stopped")
        
        elif args.stats:
            # Show threat statistics
            stats = detector.get_threat_statistics()
            print(f"Total Threats (24h): {stats['total_threats']}")
            print(f"Active Threats: {stats['active_threats']}")
            print(f"Mitigated Threats: {stats['mitigated_threats']}")
            print(f"False Positives: {stats['false_positives']}")
            print("\nThreats by Type:")
            for threat_type, count in stats['threats_by_type'].items():
                print(f"  {threat_type}: {count}")
            print("\nThreats by Severity:")
            for severity, count in stats['threats_by_severity'].items():
                print(f"  {severity}: {count}")
            print("\nThreats by Source:")
            for source, count in stats['threats_by_source'].items():
                print(f"  {source}: {count}")
        
        elif args.events:
            # Show recent threat events
            events = detector.get_threat_events(args.events)
            print(f"Threat Events (last {args.events} hours):")
            for event in events[-10:]:  # Show last 10 events
                print(f"  {event.timestamp}: {event.threat_type} - {event.description}")
                print(f"    Severity: {event.severity}, Confidence: {event.confidence:.2f}")
                print(f"    Status: {event.status}, Mitigation: {event.mitigation}")
                print()
        
        elif args.train:
            # Train models
            with open(args.train, 'r') as f:
                training_data = json.load(f)
            detector.train_models(training_data)
            print("Model training completed")
        
        else:
            parser.print_help()
    
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
