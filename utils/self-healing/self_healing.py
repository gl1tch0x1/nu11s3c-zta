#!/usr/bin/env python3
"""
Self-Healing Policy System for AppArmor Zero Trust Architecture

This module provides automated policy adaptation and self-healing capabilities
to automatically respond to security threats and policy violations.
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
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class PolicyViolation:
    """Represents a policy violation"""
    timestamp: datetime
    violation_id: str
    profile_name: str
    rule_type: str
    resource: str
    action: str
    severity: str
    frequency: int
    context: Dict[str, Any]
    mitigation_applied: bool

@dataclass
class HealingAction:
    """Represents a healing action"""
    action_id: str
    action_type: str
    target: str
    parameters: Dict[str, Any]
    confidence: float
    timestamp: datetime
    status: str  # pending, applied, failed, reverted
    result: Optional[str]

@dataclass
class PolicyAdaptation:
    """Represents a policy adaptation"""
    adaptation_id: str
    profile_name: str
    rule_changes: List[Dict[str, Any]]
    reason: str
    confidence: float
    timestamp: datetime
    status: str  # pending, applied, failed, reverted
    effectiveness: Optional[float]

class SelfHealingSystem:
    """Self-healing policy system"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.violations = []
        self.healing_actions = []
        self.policy_adaptations = []
        self.running = False
        self.healing_rules = {}
        self.setup_healing_rules()
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            'healing': {
                'enable_automatic_healing': True,
                'enable_policy_adaptation': True,
                'enable_rule_optimization': True,
                'confidence_threshold': 0.8,
                'violation_threshold': 5,
                'adaptation_cooldown': 300  # 5 minutes
            },
            'actions': {
                'enable_rule_addition': True,
                'enable_rule_modification': True,
                'enable_rule_removal': True,
                'enable_profile_switching': True,
                'enable_temporary_restrictions': True
            },
            'monitoring': {
                'check_interval': 30,  # seconds
                'violation_window': 300,  # 5 minutes
                'max_violations': 1000,
                'retention_days': 7
            },
            'safety': {
                'enable_rollback': True,
                'max_adaptations_per_hour': 10,
                'require_approval': False,
                'test_mode': False
            }
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        
        return default_config
    
    def setup_healing_rules(self):
        """Setup healing rules for different violation types"""
        logger.info("Setting up healing rules...")
        
        self.healing_rules = {
            'file_access_violation': {
                'description': 'Handle file access violations',
                'actions': [
                    {
                        'type': 'add_rule',
                        'condition': 'frequency > 3',
                        'rule_template': '  {resource} {action},',
                        'confidence': 0.9
                    },
                    {
                        'type': 'modify_rule',
                        'condition': 'frequency > 1',
                        'rule_template': '  {resource} {action},',
                        'confidence': 0.8
                    }
                ]
            },
            'network_violation': {
                'description': 'Handle network access violations',
                'actions': [
                    {
                        'type': 'add_network_rule',
                        'condition': 'frequency > 2',
                        'rule_template': '  network {protocol} {port},',
                        'confidence': 0.9
                    },
                    {
                        'type': 'temporary_restriction',
                        'condition': 'severity == "high"',
                        'rule_template': '  deny network,',
                        'confidence': 0.7
                    }
                ]
            },
            'capability_violation': {
                'description': 'Handle capability violations',
                'actions': [
                    {
                        'type': 'add_capability',
                        'condition': 'frequency > 1',
                        'rule_template': '  capability {capability},',
                        'confidence': 0.8
                    }
                ]
            },
            'process_violation': {
                'description': 'Handle process execution violations',
                'actions': [
                    {
                        'type': 'add_execution_rule',
                        'condition': 'frequency > 2',
                        'rule_template': '  {executable} ix,',
                        'confidence': 0.9
                    }
                ]
            },
            'mount_violation': {
                'description': 'Handle mount violations',
                'actions': [
                    {
                        'type': 'add_mount_rule',
                        'condition': 'frequency > 1',
                        'rule_template': '  mount {source} -> {target},',
                        'confidence': 0.8
                    }
                ]
            }
        }
        
        logger.info(f"Setup {len(self.healing_rules)} healing rules")
    
    def start_healing(self):
        """Start the self-healing system"""
        logger.info("Starting self-healing system...")
        
        self.running = True
        
        # Start healing threads
        self._start_healing_threads()
        
        logger.info("Self-healing system started")
    
    def _start_healing_threads(self):
        """Start healing threads"""
        # Start violation monitoring thread
        violation_thread = threading.Thread(target=self._violation_monitoring_loop)
        violation_thread.daemon = True
        violation_thread.start()
        
        # Start healing action thread
        healing_thread = threading.Thread(target=self._healing_action_loop)
        healing_thread.daemon = True
        healing_thread.start()
        
        # Start policy adaptation thread
        adaptation_thread = threading.Thread(target=self._policy_adaptation_loop)
        adaptation_thread.daemon = True
        adaptation_thread.start()
    
    def _violation_monitoring_loop(self):
        """Monitor for policy violations"""
        while self.running:
            try:
                # Check for new violations
                new_violations = self._detect_violations()
                
                for violation in new_violations:
                    self._add_violation(violation)
                
                time.sleep(self.config['monitoring']['check_interval'])
                
            except Exception as e:
                logger.error(f"Error in violation monitoring loop: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _healing_action_loop(self):
        """Process healing actions"""
        while self.running:
            try:
                # Process pending healing actions
                pending_actions = [action for action in self.healing_actions 
                                 if action.status == 'pending']
                
                for action in pending_actions:
                    self._execute_healing_action(action)
                
                time.sleep(self.config['monitoring']['check_interval'])
                
            except Exception as e:
                logger.error(f"Error in healing action loop: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _policy_adaptation_loop(self):
        """Process policy adaptations"""
        while self.running:
            try:
                # Process pending policy adaptations
                pending_adaptations = [adaptation for adaptation in self.policy_adaptations 
                                     if adaptation.status == 'pending']
                
                for adaptation in pending_adaptations:
                    self._execute_policy_adaptation(adaptation)
                
                time.sleep(self.config['monitoring']['check_interval'])
                
            except Exception as e:
                logger.error(f"Error in policy adaptation loop: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _detect_violations(self) -> List[PolicyViolation]:
        """Detect new policy violations"""
        violations = []
        
        # This would integrate with AppArmor audit logs or eBPF events
        # For now, we'll simulate violation detection
        
        # TODO: Implement actual violation detection
        # This would parse audit logs, eBPF events, or other sources
        
        return violations
    
    def _add_violation(self, violation: PolicyViolation):
        """Add a policy violation"""
        self.violations.append(violation)
        
        # Limit the number of violations
        if len(self.violations) > self.config['monitoring']['max_violations']:
            self.violations = self.violations[-self.config['monitoring']['max_violations']:]
        
        # Check if healing is needed
        if self._should_trigger_healing(violation):
            self._trigger_healing(violation)
    
    def _should_trigger_healing(self, violation: PolicyViolation) -> bool:
        """Check if healing should be triggered for a violation"""
        if not self.config['healing']['enable_automatic_healing']:
            return False
        
        # Check violation frequency
        recent_violations = self._get_recent_violations(violation.profile_name, 
                                                      violation.rule_type, 
                                                      violation.resource)
        
        if len(recent_violations) >= self.config['healing']['violation_threshold']:
            return True
        
        # Check severity
        if violation.severity in ['high', 'critical']:
            return True
        
        return False
    
    def _get_recent_violations(self, profile_name: str, rule_type: str, 
                             resource: str) -> List[PolicyViolation]:
        """Get recent violations for a specific profile, rule type, and resource"""
        cutoff_time = datetime.now() - timedelta(seconds=self.config['monitoring']['violation_window'])
        
        return [v for v in self.violations 
                if v.timestamp > cutoff_time and 
                v.profile_name == profile_name and 
                v.rule_type == rule_type and 
                v.resource == resource]
    
    def _trigger_healing(self, violation: PolicyViolation):
        """Trigger healing for a violation"""
        logger.info(f"Triggering healing for violation: {violation.violation_id}")
        
        # Check if we're in cooldown period
        if self._is_in_cooldown(violation):
            logger.info("Healing in cooldown period, skipping")
            return
        
        # Find appropriate healing rule
        healing_rule = self.healing_rules.get(violation.rule_type)
        if not healing_rule:
            logger.warning(f"No healing rule found for violation type: {violation.rule_type}")
            return
        
        # Evaluate healing actions
        for action_config in healing_rule['actions']:
            if self._evaluate_healing_condition(action_config, violation):
                self._create_healing_action(action_config, violation)
    
    def _is_in_cooldown(self, violation: PolicyViolation) -> bool:
        """Check if healing is in cooldown period"""
        cooldown_time = datetime.now() - timedelta(seconds=self.config['healing']['adaptation_cooldown'])
        
        recent_adaptations = [a for a in self.policy_adaptations 
                            if a.timestamp > cooldown_time and 
                            a.profile_name == violation.profile_name]
        
        return len(recent_adaptations) > 0
    
    def _evaluate_healing_condition(self, action_config: Dict[str, Any], 
                                  violation: PolicyViolation) -> bool:
        """Evaluate if a healing action condition is met"""
        condition = action_config['condition']
        
        if 'frequency' in condition:
            recent_violations = self._get_recent_violations(violation.profile_name, 
                                                          violation.rule_type, 
                                                          violation.resource)
            frequency = len(recent_violations)
            
            if 'frequency > 3' in condition:
                return frequency > 3
            elif 'frequency > 2' in condition:
                return frequency > 2
            elif 'frequency > 1' in condition:
                return frequency > 1
        
        if 'severity' in condition:
            if 'severity == "high"' in condition:
                return violation.severity == 'high'
            elif 'severity == "critical"' in condition:
                return violation.severity == 'critical'
        
        return False
    
    def _create_healing_action(self, action_config: Dict[str, Any], 
                             violation: PolicyViolation):
        """Create a healing action"""
        action = HealingAction(
            action_id=f"healing_{int(time.time())}_{violation.violation_id}",
            action_type=action_config['type'],
            target=violation.profile_name,
            parameters={
                'violation_id': violation.violation_id,
                'rule_type': violation.rule_type,
                'resource': violation.resource,
                'action': violation.action,
                'rule_template': action_config['rule_template']
            },
            confidence=action_config['confidence'],
            timestamp=datetime.now(),
            status='pending',
            result=None
        )
        
        self.healing_actions.append(action)
        logger.info(f"Created healing action: {action.action_id}")
    
    def _execute_healing_action(self, action: HealingAction):
        """Execute a healing action"""
        logger.info(f"Executing healing action: {action.action_id}")
        
        try:
            if action.action_type == 'add_rule':
                result = self._add_rule_to_profile(action)
            elif action.action_type == 'modify_rule':
                result = self._modify_rule_in_profile(action)
            elif action.action_type == 'add_network_rule':
                result = self._add_network_rule_to_profile(action)
            elif action.action_type == 'add_capability':
                result = self._add_capability_to_profile(action)
            elif action.action_type == 'add_execution_rule':
                result = self._add_execution_rule_to_profile(action)
            elif action.action_type == 'add_mount_rule':
                result = self._add_mount_rule_to_profile(action)
            elif action.action_type == 'temporary_restriction':
                result = self._apply_temporary_restriction(action)
            else:
                result = f"Unknown action type: {action.action_type}"
            
            action.status = 'applied'
            action.result = result
            
            logger.info(f"Healing action executed successfully: {action.action_id}")
            
        except Exception as e:
            action.status = 'failed'
            action.result = str(e)
            logger.error(f"Failed to execute healing action {action.action_id}: {e}")
    
    def _add_rule_to_profile(self, action: HealingAction) -> str:
        """Add a rule to a profile"""
        profile_name = action.target
        rule_template = action.parameters['rule_template']
        resource = action.parameters['resource']
        action_type = action.parameters['action']
        
        # Format the rule
        rule = rule_template.format(resource=resource, action=action_type)
        
        # Apply the rule (this would integrate with AppArmor)
        # TODO: Implement actual rule addition
        
        return f"Added rule to profile {profile_name}: {rule}"
    
    def _modify_rule_in_profile(self, action: HealingAction) -> str:
        """Modify a rule in a profile"""
        profile_name = action.target
        rule_template = action.parameters['rule_template']
        resource = action.parameters['resource']
        action_type = action.parameters['action']
        
        # Format the rule
        rule = rule_template.format(resource=resource, action=action_type)
        
        # Apply the rule modification (this would integrate with AppArmor)
        # TODO: Implement actual rule modification
        
        return f"Modified rule in profile {profile_name}: {rule}"
    
    def _add_network_rule_to_profile(self, action: HealingAction) -> str:
        """Add a network rule to a profile"""
        profile_name = action.target
        rule_template = action.parameters['rule_template']
        
        # Extract network parameters from violation context
        context = action.parameters.get('context', {})
        protocol = context.get('protocol', 'inet')
        port = context.get('port', '')
        
        # Format the rule
        rule = rule_template.format(protocol=protocol, port=port)
        
        # Apply the network rule (this would integrate with AppArmor)
        # TODO: Implement actual network rule addition
        
        return f"Added network rule to profile {profile_name}: {rule}"
    
    def _add_capability_to_profile(self, action: HealingAction) -> str:
        """Add a capability to a profile"""
        profile_name = action.target
        rule_template = action.parameters['rule_template']
        
        # Extract capability from violation context
        context = action.parameters.get('context', {})
        capability = context.get('capability', 'unknown')
        
        # Format the rule
        rule = rule_template.format(capability=capability)
        
        # Apply the capability rule (this would integrate with AppArmor)
        # TODO: Implement actual capability addition
        
        return f"Added capability to profile {profile_name}: {rule}"
    
    def _add_execution_rule_to_profile(self, action: HealingAction) -> str:
        """Add an execution rule to a profile"""
        profile_name = action.target
        rule_template = action.parameters['rule_template']
        
        # Extract executable from violation context
        context = action.parameters.get('context', {})
        executable = context.get('executable', action.parameters['resource'])
        
        # Format the rule
        rule = rule_template.format(executable=executable)
        
        # Apply the execution rule (this would integrate with AppArmor)
        # TODO: Implement actual execution rule addition
        
        return f"Added execution rule to profile {profile_name}: {rule}"
    
    def _add_mount_rule_to_profile(self, action: HealingAction) -> str:
        """Add a mount rule to a profile"""
        profile_name = action.target
        rule_template = action.parameters['rule_template']
        
        # Extract mount parameters from violation context
        context = action.parameters.get('context', {})
        source = context.get('source', 'unknown')
        target = context.get('target', 'unknown')
        
        # Format the rule
        rule = rule_template.format(source=source, target=target)
        
        # Apply the mount rule (this would integrate with AppArmor)
        # TODO: Implement actual mount rule addition
        
        return f"Added mount rule to profile {profile_name}: {rule}"
    
    def _apply_temporary_restriction(self, action: HealingAction) -> str:
        """Apply a temporary restriction"""
        profile_name = action.target
        rule_template = action.parameters['rule_template']
        
        # Format the restriction rule
        rule = rule_template
        
        # Apply the temporary restriction (this would integrate with AppArmor)
        # TODO: Implement actual temporary restriction
        
        return f"Applied temporary restriction to profile {profile_name}: {rule}"
    
    def _execute_policy_adaptation(self, adaptation: PolicyAdaptation):
        """Execute a policy adaptation"""
        logger.info(f"Executing policy adaptation: {adaptation.adaptation_id}")
        
        try:
            # Apply rule changes
            for rule_change in adaptation.rule_changes:
                self._apply_rule_change(rule_change, adaptation.profile_name)
            
            adaptation.status = 'applied'
            adaptation.effectiveness = self._measure_effectiveness(adaptation)
            
            logger.info(f"Policy adaptation executed successfully: {adaptation.adaptation_id}")
            
        except Exception as e:
            adaptation.status = 'failed'
            logger.error(f"Failed to execute policy adaptation {adaptation.adaptation_id}: {e}")
    
    def _apply_rule_change(self, rule_change: Dict[str, Any], profile_name: str):
        """Apply a rule change to a profile"""
        # This would integrate with AppArmor to apply rule changes
        # TODO: Implement actual rule change application
        pass
    
    def _measure_effectiveness(self, adaptation: PolicyAdaptation) -> float:
        """Measure the effectiveness of a policy adaptation"""
        # This would measure how effective the adaptation was
        # by monitoring violation reduction
        # TODO: Implement effectiveness measurement
        return 0.8  # Placeholder
    
    def add_violation(self, violation: PolicyViolation):
        """Add a policy violation (external interface)"""
        self._add_violation(violation)
    
    def get_healing_statistics(self) -> Dict[str, Any]:
        """Get healing system statistics"""
        recent_actions = [action for action in self.healing_actions 
                         if action.timestamp > datetime.now() - timedelta(hours=24)]
        
        recent_adaptations = [adaptation for adaptation in self.policy_adaptations 
                            if adaptation.timestamp > datetime.now() - timedelta(hours=24)]
        
        stats = {
            'total_violations': len(self.violations),
            'total_healing_actions': len(self.healing_actions),
            'total_adaptations': len(self.policy_adaptations),
            'recent_actions': len(recent_actions),
            'recent_adaptations': len(recent_adaptations),
            'successful_actions': len([a for a in recent_actions if a.status == 'applied']),
            'failed_actions': len([a for a in recent_actions if a.status == 'failed']),
            'successful_adaptations': len([a for a in recent_adaptations if a.status == 'applied']),
            'failed_adaptations': len([a for a in recent_adaptations if a.status == 'failed']),
            'actions_by_type': {},
            'adaptations_by_reason': {}
        }
        
        # Count actions by type
        for action in recent_actions:
            if action.action_type not in stats['actions_by_type']:
                stats['actions_by_type'][action.action_type] = 0
            stats['actions_by_type'][action.action_type] += 1
        
        # Count adaptations by reason
        for adaptation in recent_adaptations:
            if adaptation.reason not in stats['adaptations_by_reason']:
                stats['adaptations_by_reason'][adaptation.reason] = 0
            stats['adaptations_by_reason'][adaptation.reason] += 1
        
        return stats
    
    def stop_healing(self):
        """Stop the self-healing system"""
        logger.info("Stopping self-healing system...")
        self.running = False
        logger.info("Self-healing system stopped")

def main():
    parser = argparse.ArgumentParser(description='Self-Healing Policy System')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--start', action='store_true', help='Start self-healing system')
    parser.add_argument('--stop', action='store_true', help='Stop self-healing system')
    parser.add_argument('--stats', action='store_true', help='Show healing statistics')
    parser.add_argument('--violations', action='store_true', help='Show recent violations')
    parser.add_argument('--actions', action='store_true', help='Show recent healing actions')
    
    args = parser.parse_args()
    
    # Create self-healing system
    healing_system = SelfHealingSystem(args.config)
    
    try:
        if args.start:
            # Start self-healing system
            healing_system.start_healing()
            try:
                # Keep running until interrupted
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping self-healing system...")
                healing_system.stop_healing()
        
        elif args.stop:
            # Stop self-healing system
            healing_system.stop_healing()
            print("Self-healing system stopped")
        
        elif args.stats:
            # Show healing statistics
            stats = healing_system.get_healing_statistics()
            print(f"Total Violations: {stats['total_violations']}")
            print(f"Total Healing Actions: {stats['total_healing_actions']}")
            print(f"Total Adaptations: {stats['total_adaptations']}")
            print(f"Recent Actions (24h): {stats['recent_actions']}")
            print(f"Recent Adaptations (24h): {stats['recent_adaptations']}")
            print(f"Successful Actions: {stats['successful_actions']}")
            print(f"Failed Actions: {stats['failed_actions']}")
            print(f"Successful Adaptations: {stats['successful_adaptations']}")
            print(f"Failed Adaptations: {stats['failed_adaptations']}")
            print("\nActions by Type:")
            for action_type, count in stats['actions_by_type'].items():
                print(f"  {action_type}: {count}")
            print("\nAdaptations by Reason:")
            for reason, count in stats['adaptations_by_reason'].items():
                print(f"  {reason}: {count}")
        
        elif args.violations:
            # Show recent violations
            recent_violations = [v for v in healing_system.violations 
                               if v.timestamp > datetime.now() - timedelta(hours=24)]
            print(f"Recent Violations (24h): {len(recent_violations)}")
            for violation in recent_violations[-10:]:  # Show last 10
                print(f"  {violation.timestamp}: {violation.profile_name} - {violation.rule_type}")
                print(f"    Resource: {violation.resource}, Action: {violation.action}")
                print(f"    Severity: {violation.severity}, Frequency: {violation.frequency}")
                print()
        
        elif args.actions:
            # Show recent healing actions
            recent_actions = [a for a in healing_system.healing_actions 
                            if a.timestamp > datetime.now() - timedelta(hours=24)]
            print(f"Recent Healing Actions (24h): {len(recent_actions)}")
            for action in recent_actions[-10:]:  # Show last 10
                print(f"  {action.timestamp}: {action.action_type} - {action.target}")
                print(f"    Confidence: {action.confidence:.2f}, Status: {action.status}")
                if action.result:
                    print(f"    Result: {action.result}")
                print()
        
        else:
            parser.print_help()
    
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
