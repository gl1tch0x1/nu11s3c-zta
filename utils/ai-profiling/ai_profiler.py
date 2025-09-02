#!/usr/bin/env python3
"""
AI/ML-Driven AppArmor Profile Generation and Optimization

This module provides intelligent profile generation using machine learning
algorithms to analyze application behavior and generate optimized AppArmor profiles.
"""

import os
import sys
import json
import logging
import argparse
import subprocess
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
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
class SystemCall:
    """Represents a system call with metadata"""
    timestamp: datetime
    syscall: str
    pid: int
    ppid: int
    uid: int
    gid: int
    comm: str
    exe: str
    args: List[str]
    result: str
    duration: float
    file_path: Optional[str] = None
    network_protocol: Optional[str] = None
    network_port: Optional[int] = None

@dataclass
class FileAccess:
    """Represents file access patterns"""
    path: str
    operation: str  # read, write, execute, create, delete
    frequency: int
    last_access: datetime
    permissions: str
    size: Optional[int] = None

@dataclass
class NetworkAccess:
    """Represents network access patterns"""
    protocol: str
    port: int
    address: str
    frequency: int
    last_access: datetime
    direction: str  # inbound, outbound

@dataclass
class ProfileRule:
    """Represents an AppArmor profile rule"""
    rule_type: str  # file, network, capability, etc.
    path: str
    permissions: List[str]
    conditions: List[str]
    priority: int
    confidence: float
    source: str  # manual, ai_generated, optimized

@dataclass
class ApplicationProfile:
    """Represents a complete application profile"""
    name: str
    version: str
    executable: str
    rules: List[ProfileRule]
    file_access_patterns: List[FileAccess]
    network_access_patterns: List[NetworkAccess]
    system_calls: List[SystemCall]
    risk_score: float
    optimization_suggestions: List[str]
    generated_at: datetime
    ai_model_version: str

class AIProfiler:
    """AI/ML-driven AppArmor profile generator and optimizer"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.models = {}
        self.scalers = {}
        self.profiles = {}
        self.setup_models()
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            'models': {
                'behavior_classifier': 'random_forest',
                'anomaly_detector': 'isolation_forest',
                'clustering': 'dbscan'
            },
            'training': {
                'test_size': 0.2,
                'random_state': 42,
                'n_estimators': 100
            },
            'profiling': {
                'monitoring_duration': 3600,  # 1 hour
                'min_confidence': 0.8,
                'max_rules': 1000
            },
            'optimization': {
                'enable_ml_optimization': True,
                'enable_behavioral_analysis': True,
                'enable_anomaly_detection': True
            }
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        
        return default_config
    
    def setup_models(self):
        """Initialize ML models"""
        logger.info("Setting up AI/ML models...")
        
        # Behavior classification model
        self.models['behavior_classifier'] = RandomForestClassifier(
            n_estimators=self.config['training']['n_estimators'],
            random_state=self.config['training']['random_state']
        )
        
        # Anomaly detection model
        self.models['anomaly_detector'] = IsolationForest(
            contamination=0.1,
            random_state=self.config['training']['random_state']
        )
        
        # Clustering model for pattern recognition
        self.models['clustering'] = DBSCAN(eps=0.5, min_samples=5)
        
        # Feature scaler
        self.scalers['standard'] = StandardScaler()
        
        logger.info("AI/ML models initialized successfully")
    
    def collect_behavioral_data(self, executable: str, duration: int = None) -> List[SystemCall]:
        """Collect behavioral data using eBPF and system monitoring"""
        if duration is None:
            duration = self.config['profiling']['monitoring_duration']
        
        logger.info(f"Collecting behavioral data for {executable} for {duration} seconds...")
        
        # Use eBPF to trace system calls
        system_calls = self._trace_system_calls(executable, duration)
        
        # Parse and enrich the data
        enriched_calls = self._enrich_system_calls(system_calls)
        
        logger.info(f"Collected {len(enriched_calls)} system calls")
        return enriched_calls
    
    def _trace_system_calls(self, executable: str, duration: int) -> List[Dict]:
        """Trace system calls using eBPF"""
        # This would use eBPF programs to trace system calls
        # For now, we'll simulate the data collection
        
        logger.info("Starting eBPF tracing...")
        
        # Simulate system call collection
        # In a real implementation, this would use tools like:
        # - eBPF programs for kernel-level tracing
        # - strace for user-space tracing
        # - perf for performance monitoring
        
        system_calls = []
        start_time = datetime.now()
        
        # Simulate data collection
        # TODO: Implement actual eBPF tracing
        logger.warning("Using simulated data - implement actual eBPF tracing")
        
        return system_calls
    
    def _enrich_system_calls(self, raw_calls: List[Dict]) -> List[SystemCall]:
        """Enrich system call data with additional metadata"""
        enriched_calls = []
        
        for call in raw_calls:
            try:
                enriched_call = SystemCall(
                    timestamp=datetime.fromisoformat(call.get('timestamp', datetime.now().isoformat())),
                    syscall=call.get('syscall', ''),
                    pid=call.get('pid', 0),
                    ppid=call.get('ppid', 0),
                    uid=call.get('uid', 0),
                    gid=call.get('gid', 0),
                    comm=call.get('comm', ''),
                    exe=call.get('exe', ''),
                    args=call.get('args', []),
                    result=call.get('result', ''),
                    duration=call.get('duration', 0.0),
                    file_path=call.get('file_path'),
                    network_protocol=call.get('network_protocol'),
                    network_port=call.get('network_port')
                )
                enriched_calls.append(enriched_call)
            except Exception as e:
                logger.warning(f"Failed to enrich system call: {e}")
                continue
        
        return enriched_calls
    
    def analyze_behavior_patterns(self, system_calls: List[SystemCall]) -> Dict[str, Any]:
        """Analyze behavioral patterns using ML algorithms"""
        logger.info("Analyzing behavior patterns...")
        
        # Extract features from system calls
        features = self._extract_features(system_calls)
        
        # Perform clustering to identify behavior patterns
        clusters = self._cluster_behaviors(features)
        
        # Detect anomalies
        anomalies = self._detect_anomalies(features)
        
        # Generate behavior summary
        behavior_summary = {
            'total_calls': len(system_calls),
            'unique_syscalls': len(set(call.syscall for call in system_calls)),
            'file_operations': len([c for c in system_calls if c.file_path]),
            'network_operations': len([c for c in system_calls if c.network_protocol]),
            'clusters': clusters,
            'anomalies': anomalies,
            'risk_score': self._calculate_risk_score(system_calls, anomalies)
        }
        
        return behavior_summary
    
    def _extract_features(self, system_calls: List[SystemCall]) -> np.ndarray:
        """Extract numerical features from system calls"""
        features = []
        
        for call in system_calls:
            feature_vector = [
                hash(call.syscall) % 1000,  # Syscall type
                call.pid % 1000,           # Process ID
                call.uid,                  # User ID
                call.gid,                  # Group ID
                call.duration * 1000,      # Duration in milliseconds
                1 if call.file_path else 0,  # File access
                1 if call.network_protocol else 0,  # Network access
                len(call.args),            # Number of arguments
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    def _cluster_behaviors(self, features: np.ndarray) -> Dict[str, Any]:
        """Cluster behaviors to identify patterns"""
        if len(features) == 0:
            return {'clusters': [], 'labels': []}
        
        # Scale features
        scaled_features = self.scalers['standard'].fit_transform(features)
        
        # Perform clustering
        cluster_labels = self.models['clustering'].fit_predict(scaled_features)
        
        # Analyze clusters
        unique_labels = set(cluster_labels)
        clusters = []
        
        for label in unique_labels:
            if label == -1:  # Noise
                continue
            
            cluster_points = features[cluster_labels == label]
            clusters.append({
                'label': int(label),
                'size': len(cluster_points),
                'centroid': cluster_points.mean(axis=0).tolist(),
                'description': self._describe_cluster(cluster_points)
            })
        
        return {
            'clusters': clusters,
            'labels': cluster_labels.tolist(),
            'n_clusters': len(clusters)
        }
    
    def _detect_anomalies(self, features: np.ndarray) -> Dict[str, Any]:
        """Detect anomalous behaviors"""
        if len(features) == 0:
            return {'anomalies': [], 'anomaly_scores': []}
        
        # Scale features
        scaled_features = self.scalers['standard'].fit_transform(features)
        
        # Detect anomalies
        anomaly_scores = self.models['anomaly_detector'].decision_function(scaled_features)
        anomaly_labels = self.models['anomaly_detector'].predict(scaled_features)
        
        # Identify anomalous points
        anomalies = []
        for i, (score, label) in enumerate(zip(anomaly_scores, anomaly_labels)):
            if label == -1:  # Anomaly
                anomalies.append({
                    'index': i,
                    'score': float(score),
                    'severity': 'high' if score < -0.5 else 'medium'
                })
        
        return {
            'anomalies': anomalies,
            'anomaly_scores': anomaly_scores.tolist(),
            'n_anomalies': len(anomalies)
        }
    
    def _calculate_risk_score(self, system_calls: List[SystemCall], anomalies: Dict[str, Any]) -> float:
        """Calculate overall risk score for the application"""
        risk_factors = []
        
        # Factor 1: Number of system calls (more calls = higher risk)
        risk_factors.append(min(len(system_calls) / 1000, 1.0))
        
        # Factor 2: Number of anomalies
        risk_factors.append(min(anomalies.get('n_anomalies', 0) / 10, 1.0))
        
        # Factor 3: Network access
        network_calls = len([c for c in system_calls if c.network_protocol])
        risk_factors.append(min(network_calls / 100, 1.0))
        
        # Factor 4: File system access
        file_calls = len([c for c in system_calls if c.file_path])
        risk_factors.append(min(file_calls / 500, 1.0))
        
        # Calculate weighted risk score
        weights = [0.3, 0.4, 0.2, 0.1]
        risk_score = sum(w * f for w, f in zip(weights, risk_factors))
        
        return min(risk_score, 1.0)
    
    def _describe_cluster(self, cluster_points: np.ndarray) -> str:
        """Generate a human-readable description of a cluster"""
        if len(cluster_points) == 0:
            return "Empty cluster"
        
        # Analyze the cluster characteristics
        avg_duration = cluster_points[:, 4].mean() if cluster_points.shape[1] > 4 else 0
        file_access_ratio = cluster_points[:, 5].mean() if cluster_points.shape[1] > 5 else 0
        network_access_ratio = cluster_points[:, 6].mean() if cluster_points.shape[1] > 6 else 0
        
        description = f"Cluster with {len(cluster_points)} operations"
        if avg_duration > 0.1:
            description += f", avg duration {avg_duration:.3f}s"
        if file_access_ratio > 0.5:
            description += ", heavy file access"
        if network_access_ratio > 0.5:
            description += ", heavy network access"
        
        return description
    
    def generate_profile_rules(self, system_calls: List[SystemCall], 
                             behavior_analysis: Dict[str, Any]) -> List[ProfileRule]:
        """Generate AppArmor profile rules based on behavioral analysis"""
        logger.info("Generating profile rules...")
        
        rules = []
        
        # Generate file access rules
        file_rules = self._generate_file_rules(system_calls)
        rules.extend(file_rules)
        
        # Generate network rules
        network_rules = self._generate_network_rules(system_calls)
        rules.extend(network_rules)
        
        # Generate capability rules
        capability_rules = self._generate_capability_rules(system_calls)
        rules.extend(capability_rules)
        
        # Generate conditional rules based on anomalies
        conditional_rules = self._generate_conditional_rules(behavior_analysis)
        rules.extend(conditional_rules)
        
        # Optimize rules
        optimized_rules = self._optimize_rules(rules)
        
        logger.info(f"Generated {len(optimized_rules)} profile rules")
        return optimized_rules
    
    def _generate_file_rules(self, system_calls: List[SystemCall]) -> List[ProfileRule]:
        """Generate file access rules"""
        rules = []
        file_accesses = {}
        
        # Analyze file access patterns
        for call in system_calls:
            if call.file_path:
                path = call.file_path
                if path not in file_accesses:
                    file_accesses[path] = {'read': 0, 'write': 0, 'execute': 0}
                
                # Determine operation type based on syscall
                if call.syscall in ['open', 'openat', 'read', 'readv']:
                    file_accesses[path]['read'] += 1
                elif call.syscall in ['write', 'writev', 'pwrite', 'pwritev']:
                    file_accesses[path]['write'] += 1
                elif call.syscall in ['execve', 'execveat']:
                    file_accesses[path]['execute'] += 1
        
        # Generate rules for frequently accessed files
        for path, accesses in file_accesses.items():
            permissions = []
            if accesses['read'] > 0:
                permissions.append('r')
            if accesses['write'] > 0:
                permissions.append('w')
            if accesses['execute'] > 0:
                permissions.append('x')
            
            if permissions:
                rule = ProfileRule(
                    rule_type='file',
                    path=path,
                    permissions=permissions,
                    conditions=[],
                    priority=100 - len(permissions) * 10,
                    confidence=min(sum(accesses.values()) / 10, 1.0),
                    source='ai_generated'
                )
                rules.append(rule)
        
        return rules
    
    def _generate_network_rules(self, system_calls: List[SystemCall]) -> List[ProfileRule]:
        """Generate network access rules"""
        rules = []
        network_accesses = {}
        
        # Analyze network access patterns
        for call in system_calls:
            if call.network_protocol and call.network_port:
                key = f"{call.network_protocol}:{call.network_port}"
                if key not in network_accesses:
                    network_accesses[key] = 0
                network_accesses[key] += 1
        
        # Generate rules for network access
        for key, frequency in network_accesses.items():
            protocol, port = key.split(':')
            
            rule = ProfileRule(
                rule_type='network',
                path=f"network {protocol} port {port}",
                permissions=['allow'],
                conditions=[],
                priority=50,
                confidence=min(frequency / 5, 1.0),
                source='ai_generated'
            )
            rules.append(rule)
        
        return rules
    
    def _generate_capability_rules(self, system_calls: List[SystemCall]) -> List[ProfileRule]:
        """Generate capability rules based on system calls"""
        rules = []
        
        # Map system calls to capabilities
        capability_map = {
            'chown': 'cap_chown',
            'setuid': 'cap_setuid',
            'setgid': 'cap_setgid',
            'kill': 'cap_kill',
            'mount': 'cap_sys_admin',
            'umount': 'cap_sys_admin',
            'ptrace': 'cap_sys_ptrace',
        }
        
        used_capabilities = set()
        for call in system_calls:
            if call.syscall in capability_map:
                used_capabilities.add(capability_map[call.syscall])
        
        # Generate capability rules
        for capability in used_capabilities:
            rule = ProfileRule(
                rule_type='capability',
                path=capability,
                permissions=['allow'],
                conditions=[],
                priority=30,
                confidence=0.9,
                source='ai_generated'
            )
            rules.append(rule)
        
        return rules
    
    def _generate_conditional_rules(self, behavior_analysis: Dict[str, Any]) -> List[ProfileRule]:
        """Generate conditional rules based on behavioral analysis"""
        rules = []
        
        # Generate rules for anomaly detection
        if behavior_analysis.get('anomalies', {}).get('n_anomalies', 0) > 0:
            rule = ProfileRule(
                rule_type='conditional',
                path='anomaly_detected',
                permissions=['audit'],
                conditions=['anomaly_score > 0.5'],
                priority=10,
                confidence=0.8,
                source='ai_generated'
            )
            rules.append(rule)
        
        # Generate rules for high-risk behaviors
        if behavior_analysis.get('risk_score', 0) > 0.7:
            rule = ProfileRule(
                rule_type='conditional',
                path='high_risk_behavior',
                permissions=['deny'],
                conditions=['risk_score > 0.7'],
                priority=5,
                confidence=0.9,
                source='ai_generated'
            )
            rules.append(rule)
        
        return rules
    
    def _optimize_rules(self, rules: List[ProfileRule]) -> List[ProfileRule]:
        """Optimize rules by removing duplicates and merging similar rules"""
        optimized_rules = []
        seen_paths = set()
        
        # Sort rules by priority (higher priority first)
        sorted_rules = sorted(rules, key=lambda r: r.priority, reverse=True)
        
        for rule in sorted_rules:
            # Skip duplicate paths
            if rule.path in seen_paths:
                continue
            
            # Merge similar rules
            merged_rule = self._merge_similar_rules(rule, sorted_rules)
            optimized_rules.append(merged_rule)
            seen_paths.add(rule.path)
        
        return optimized_rules[:self.config['profiling']['max_rules']]
    
    def _merge_similar_rules(self, rule: ProfileRule, all_rules: List[ProfileRule]) -> ProfileRule:
        """Merge similar rules to reduce redundancy"""
        # Find similar rules
        similar_rules = [r for r in all_rules if r.rule_type == rule.rule_type and r.path == rule.path]
        
        if len(similar_rules) <= 1:
            return rule
        
        # Merge permissions
        all_permissions = set()
        for r in similar_rules:
            all_permissions.update(r.permissions)
        
        # Calculate average confidence
        avg_confidence = sum(r.confidence for r in similar_rules) / len(similar_rules)
        
        # Create merged rule
        merged_rule = ProfileRule(
            rule_type=rule.rule_type,
            path=rule.path,
            permissions=list(all_permissions),
            conditions=rule.conditions,
            priority=rule.priority,
            confidence=avg_confidence,
            source='ai_optimized'
        )
        
        return merged_rule
    
    def create_apparmor_profile(self, executable: str, rules: List[ProfileRule], 
                              behavior_analysis: Dict[str, Any]) -> str:
        """Create a complete AppArmor profile"""
        profile_name = os.path.basename(executable)
        
        profile_content = f"""#include <tunables/global>

# AI-Generated AppArmor Profile for {profile_name}
# Generated on: {datetime.now().isoformat()}
# Risk Score: {behavior_analysis.get('risk_score', 0):.2f}
# Total System Calls: {behavior_analysis.get('total_calls', 0)}
# Anomalies Detected: {behavior_analysis.get('anomalies', {}).get('n_anomalies', 0)}

profile {profile_name} {{
  #include <abstractions/base>
  #include <abstractions/nameservice>
  
  # AI-Generated Rules
"""
        
        # Add rules by type
        rule_types = ['file', 'network', 'capability', 'conditional']
        for rule_type in rule_types:
            type_rules = [r for r in rules if r.rule_type == rule_type]
            if type_rules:
                profile_content += f"\n  # {rule_type.title()} Rules\n"
                for rule in type_rules:
                    if rule.rule_type == 'file':
                        perms = ''.join(rule.permissions)
                        profile_content += f"  {rule.path} {perms},\n"
                    elif rule.rule_type == 'network':
                        profile_content += f"  {rule.path},\n"
                    elif rule.rule_type == 'capability':
                        profile_content += f"  capability {rule.path},\n"
                    elif rule.rule_type == 'conditional':
                        condition = ' '.join(rule.conditions)
                        action = ' '.join(rule.permissions)
                        profile_content += f"  conditional {condition} {action},\n"
        
        profile_content += "}\n"
        return profile_content
    
    def save_profile(self, profile_content: str, output_path: str):
        """Save the generated profile to a file"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write(profile_content)
        
        logger.info(f"Profile saved to: {output_path}")
    
    def load_profile(self, profile_path: str) -> str:
        """Load an existing profile"""
        with open(profile_path, 'r') as f:
            return f.read()
    
    def optimize_existing_profile(self, profile_path: str, 
                                behavioral_data: List[SystemCall]) -> str:
        """Optimize an existing profile using AI/ML"""
        logger.info(f"Optimizing existing profile: {profile_path}")
        
        # Load existing profile
        existing_profile = self.load_profile(profile_path)
        
        # Analyze current behavior
        behavior_analysis = self.analyze_behavior_patterns(behavioral_data)
        
        # Generate new rules
        new_rules = self.generate_profile_rules(behavioral_data, behavior_analysis)
        
        # Create optimized profile
        optimized_profile = self.create_apparmor_profile(
            profile_path, new_rules, behavior_analysis
        )
        
        return optimized_profile
    
    def train_models(self, training_data: List[Dict[str, Any]]):
        """Train ML models with historical data"""
        logger.info("Training AI/ML models...")
        
        # Prepare training data
        X, y = self._prepare_training_data(training_data)
        
        if len(X) == 0:
            logger.warning("No training data available")
            return
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=self.config['training']['test_size'],
            random_state=self.config['training']['random_state']
        )
        
        # Train behavior classifier
        self.models['behavior_classifier'].fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.models['behavior_classifier'].predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        logger.info(f"Model training completed. Accuracy: {accuracy:.2f}")
        
        # Save models
        self._save_models()
    
    def _prepare_training_data(self, training_data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for ML models"""
        X = []
        y = []
        
        for data_point in training_data:
            # Extract features
            features = self._extract_features_from_data(data_point)
            X.append(features)
            
            # Extract labels (risk level, behavior type, etc.)
            label = self._extract_label_from_data(data_point)
            y.append(label)
        
        return np.array(X), np.array(y)
    
    def _extract_features_from_data(self, data_point: Dict[str, Any]) -> List[float]:
        """Extract numerical features from a data point"""
        # This would extract relevant features from the data point
        # For now, return a placeholder
        return [0.0] * 10
    
    def _extract_label_from_data(self, data_point: Dict[str, Any]) -> int:
        """Extract label from a data point"""
        # This would extract the appropriate label for training
        # For now, return a placeholder
        return 0
    
    def _save_models(self):
        """Save trained models to disk"""
        model_dir = "models"
        os.makedirs(model_dir, exist_ok=True)
        
        for name, model in self.models.items():
            model_path = os.path.join(model_dir, f"{name}.joblib")
            joblib.dump(model, model_path)
            logger.info(f"Saved model: {model_path}")
        
        for name, scaler in self.scalers.items():
            scaler_path = os.path.join(model_dir, f"{name}_scaler.joblib")
            joblib.dump(scaler, scaler_path)
            logger.info(f"Saved scaler: {scaler_path}")
    
    def _load_models(self):
        """Load trained models from disk"""
        model_dir = "models"
        
        for name in self.models.keys():
            model_path = os.path.join(model_dir, f"{name}.joblib")
            if os.path.exists(model_path):
                self.models[name] = joblib.load(model_path)
                logger.info(f"Loaded model: {model_path}")
        
        for name in self.scalers.keys():
            scaler_path = os.path.join(model_dir, f"{name}_scaler.joblib")
            if os.path.exists(scaler_path):
                self.scalers[name] = joblib.load(scaler_path)
                logger.info(f"Loaded scaler: {scaler_path}")

def main():
    parser = argparse.ArgumentParser(description='AI/ML-Driven AppArmor Profile Generator')
    parser.add_argument('--executable', required=True, help='Path to executable to profile')
    parser.add_argument('--output', required=True, help='Output profile path')
    parser.add_argument('--duration', type=int, default=3600, help='Monitoring duration in seconds')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--optimize', help='Optimize existing profile')
    parser.add_argument('--train', help='Train models with data file')
    
    args = parser.parse_args()
    
    # Create AI profiler
    profiler = AIProfiler(args.config)
    
    if args.train:
        # Training mode
        with open(args.train, 'r') as f:
            training_data = json.load(f)
        profiler.train_models(training_data)
        return
    
    if args.optimize:
        # Optimization mode
        behavioral_data = profiler.collect_behavioral_data(args.executable, args.duration)
        optimized_profile = profiler.optimize_existing_profile(args.optimize, behavioral_data)
        profiler.save_profile(optimized_profile, args.output)
        return
    
    # Profile generation mode
    logger.info(f"Starting AI profiling for: {args.executable}")
    
    # Collect behavioral data
    behavioral_data = profiler.collect_behavioral_data(args.executable, args.duration)
    
    if not behavioral_data:
        logger.error("No behavioral data collected")
        return
    
    # Analyze behavior patterns
    behavior_analysis = profiler.analyze_behavior_patterns(behavioral_data)
    
    # Generate profile rules
    rules = profiler.generate_profile_rules(behavioral_data, behavior_analysis)
    
    # Create AppArmor profile
    profile_content = profiler.create_apparmor_profile(args.executable, rules, behavior_analysis)
    
    # Save profile
    profiler.save_profile(profile_content, args.output)
    
    logger.info("AI profiling completed successfully")

if __name__ == "__main__":
    main()
