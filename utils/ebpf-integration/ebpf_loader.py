#!/usr/bin/env python3
"""
eBPF Loader and Management Utility for AppArmor Zero Trust Architecture

This module provides functionality to load, manage, and interact with eBPF programs
for advanced runtime monitoring and policy enforcement.
"""

import os
import sys
import json
import logging
import argparse
import subprocess
import tempfile
import time
import struct
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import ctypes
import mmap

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class EBpfEvent:
    """Represents an eBPF event"""
    event_type: int
    timestamp: int
    pid: int
    uid: int
    gid: int
    data: bytes

@dataclass
class EBpfStats:
    """Represents eBPF statistics"""
    total_events: int
    syscall_events: int
    file_events: int
    network_events: int
    process_events: int
    anomaly_events: int
    violation_events: int
    denied_operations: int
    allowed_operations: int
    audited_operations: int

class EBpfLoader:
    """eBPF program loader and manager"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.programs = {}
        self.maps = {}
        self.event_handlers = {}
        self.running = False
        self._stats = EBpfStats(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        self.setup_ebpf_environment()
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            'ebpf': {
                'program_path': '/usr/local/bin/apparmor_ebpf.o',
                'map_path': '/sys/fs/bpf/apparmor',
                'ringbuf_size': 256 * 1024,
                'max_events': 1000
            },
            'monitoring': {
                'enable_syscall_tracing': True,
                'enable_file_monitoring': True,
                'enable_network_monitoring': True,
                'enable_process_monitoring': True,
                'enable_anomaly_detection': True
            },
            'policy': {
                'default_action': 'audit',
                'violation_threshold': 10,
                'anomaly_threshold': 5
            }
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config
    
    def setup_ebpf_environment(self):
        """Setup eBPF environment and check requirements"""
        logger.info("Setting up eBPF environment...")
        
        # Check if eBPF is available
        if not self._check_ebpf_support():
            raise RuntimeError("eBPF support not available on this system")
        
        # Check if required tools are available
        required_tools = ['bpftool', 'clang', 'llc']
        for tool in required_tools:
            if not self._check_tool_available(tool):
                logger.warning(f"Tool {tool} not found - some features may be limited")
        
        # Create eBPF map directory
        map_dir = self.config['ebpf']['map_path']
        os.makedirs(map_dir, exist_ok=True)
        
        logger.info("eBPF environment setup complete")
    
    def _check_ebpf_support(self) -> bool:
        """Check if eBPF is supported on this system"""
        try:
            # Check if /sys/fs/bpf exists
            if not os.path.exists('/sys/fs/bpf'):
                return False
            
            # Check if BPF filesystem is mounted
            with open('/proc/mounts', 'r') as f:
                mounts = f.read()
                if 'bpf' not in mounts:
                    return False
            
            return True
        except Exception as e:
            logger.error(f"Error checking eBPF support: {e}")
            return False
    
    def _check_tool_available(self, tool: str) -> bool:
        """Check if a tool is available in PATH"""
        try:
            subprocess.run(['which', tool], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def compile_ebpf_program(self, source_path: str, output_path: str) -> bool:
        """Compile eBPF C source to object file"""
        logger.info(f"Compiling eBPF program: {source_path}")
        
        try:
            # Compile with clang
            cmd = [
                'clang',
                '-O2',
                '-target', 'bpf',
                '-c', source_path,
                '-o', output_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Compilation failed: {result.stderr}")
                return False
            
            logger.info(f"eBPF program compiled successfully: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error compiling eBPF program: {e}")
            return False
    
    def load_ebpf_program(self, program_path: str, program_name: str) -> bool:
        """Load eBPF program into kernel"""
        logger.info(f"Loading eBPF program: {program_name}")
        
        try:
            # Load program using bpftool
            cmd = [
                'bpftool', 'prog', 'load',
                program_path,
                f'/sys/fs/bpf/{program_name}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to load eBPF program: {result.stderr}")
                return False
            
            # Parse program ID from output
            program_id = self._parse_program_id(result.stdout)
            if program_id:
                self.programs[program_name] = {
                    'id': program_id,
                    'path': program_path,
                    'loaded': True
                }
                logger.info(f"eBPF program loaded with ID: {program_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error loading eBPF program: {e}")
            return False
    
    def _parse_program_id(self, output: str) -> Optional[int]:
        """Parse program ID from bpftool output"""
        try:
            # Look for "id X" in the output
            for line in output.split('\n'):
                if 'id' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'id' and i + 1 < len(parts):
                            return int(parts[i + 1])
        except Exception as e:
            logger.error(f"Error parsing program ID: {e}")
        
        return None
    
    def attach_program(self, program_name: str, target: str) -> bool:
        """Attach eBPF program to a target"""
        logger.info(f"Attaching program {program_name} to {target}")
        
        try:
            if program_name not in self.programs:
                logger.error(f"Program {program_name} not loaded")
                return False
            
            program_id = self.programs[program_name]['id']
            
            # Attach using bpftool
            cmd = [
                'bpftool', 'prog', 'attach',
                str(program_id),
                target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to attach program: {result.stderr}")
                return False
            
            self.programs[program_name]['attached'] = True
            logger.info(f"Program {program_name} attached successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error attaching program: {e}")
            return False
    
    def create_ringbuf_map(self, map_name: str, size: int) -> bool:
        """Create a ring buffer map"""
        logger.info(f"Creating ring buffer map: {map_name}")
        
        try:
            # Create ring buffer map using bpftool
            cmd = [
                'bpftool', 'map', 'create',
                f'/sys/fs/bpf/{map_name}',
                'type', 'ringbuf',
                'entries', str(size)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to create ring buffer map: {result.stderr}")
                return False
            
            self.maps[map_name] = {
                'type': 'ringbuf',
                'size': size,
                'path': f'/sys/fs/bpf/{map_name}'
            }
            
            logger.info(f"Ring buffer map created: {map_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating ring buffer map: {e}")
            return False
    
    def create_hash_map(self, map_name: str, key_size: int, value_size: int, max_entries: int) -> bool:
        """Create a hash map"""
        logger.info(f"Creating hash map: {map_name}")
        
        try:
            # Create hash map using bpftool
            cmd = [
                'bpftool', 'map', 'create',
                f'/sys/fs/bpf/{map_name}',
                'type', 'hash',
                'key', str(key_size),
                'value', str(value_size),
                'entries', str(max_entries)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to create hash map: {result.stderr}")
                return False
            
            self.maps[map_name] = {
                'type': 'hash',
                'key_size': key_size,
                'value_size': value_size,
                'max_entries': max_entries,
                'path': f'/sys/fs/bpf/{map_name}'
            }
            
            logger.info(f"Hash map created: {map_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating hash map: {e}")
            return False
    
    def start_monitoring(self):
        """Start eBPF monitoring"""
        logger.info("Starting eBPF monitoring...")
        
        try:
            # Load and attach programs
            if not self._load_all_programs():
                return False
            
            # Create maps
            if not self._create_all_maps():
                return False
            
            # Start event processing
            self.running = True
            self._start_event_processing()
            
            logger.info("eBPF monitoring started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error starting eBPF monitoring: {e}")
            return False
    
    def _load_all_programs(self) -> bool:
        """Load all eBPF programs"""
        program_path = self.config['ebpf']['program_path']
        
        if not os.path.exists(program_path):
            logger.error(f"eBPF program not found: {program_path}")
            return False
        
        # Load main monitoring program
        if not self.load_ebpf_program(program_path, 'apparmor_monitor'):
            return False
        
        # Attach to tracepoints
        if self.config['monitoring']['enable_syscall_tracing']:
            self.attach_program('apparmor_monitor', 'tracepoint/syscalls/sys_enter_openat')
            self.attach_program('apparmor_monitor', 'tracepoint/syscalls/sys_exit_openat')
        
        if self.config['monitoring']['enable_process_monitoring']:
            self.attach_program('apparmor_monitor', 'tracepoint/sched/sched_process_fork')
            self.attach_program('apparmor_monitor', 'tracepoint/sched/sched_process_exit')
        
        return True
    
    def _create_all_maps(self) -> bool:
        """Create all required eBPF maps"""
        # Create ring buffer for events
        if not self.create_ringbuf_map('events', self.config['ebpf']['ringbuf_size']):
            return False
        
        # Create hash maps for profiles and rules
        if not self.create_hash_map('profiles', 4, 200, 1000):
            return False
        
        if not self.create_hash_map('network_rules', 4, 50, 100):
            return False
        
        if not self.create_hash_map('conditional_rules', 4, 50, 1000):
            return False
        
        if not self.create_hash_map('process_stats', 4, 8, 1000):
            return False
        
        # Create array map for global stats
        if not self.create_array_map('global_stats', 4, 1):
            return False
        
        return True
    
    def create_array_map(self, map_name: str, value_size: int, max_entries: int) -> bool:
        """Create an array map"""
        logger.info(f"Creating array map: {map_name}")
        
        try:
            # Create array map using bpftool
            cmd = [
                'bpftool', 'map', 'create',
                f'/sys/fs/bpf/{map_name}',
                'type', 'array',
                'value', str(value_size),
                'entries', str(max_entries)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to create array map: {result.stderr}")
                return False
            
            self.maps[map_name] = {
                'type': 'array',
                'value_size': value_size,
                'max_entries': max_entries,
                'path': f'/sys/fs/bpf/{map_name}'
            }
            
            logger.info(f"Array map created: {map_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating array map: {e}")
            return False
    
    def _start_event_processing(self):
        """Start processing eBPF events"""
        logger.info("Starting event processing...")
        
        # Start event processing thread
        import threading
        self.event_thread = threading.Thread(target=self._process_events)
        self.event_thread.daemon = True
        self.event_thread.start()
    
    def _process_events(self):
        """Process eBPF events from ring buffer"""
        try:
            # Open ring buffer map
            events_map_path = self.maps['events']['path']
            
            with open(events_map_path, 'rb') as f:
                # Map the ring buffer
                with mmap.mmap(f.fileno(), 0) as mm:
                    while self.running:
                        # Read events from ring buffer
                        events = self._read_ringbuf_events(mm)
                        
                        for event in events:
                            self._handle_event(event)
                        
                        time.sleep(0.001)  # Small delay to prevent busy waiting
                        
        except Exception as e:
            logger.error(f"Error processing events: {e}")
    
    def _read_ringbuf_events(self, mm: mmap.mmap) -> List[EBpfEvent]:
        """Read events from ring buffer"""
        events = []
        
        try:
            # This is a simplified implementation
            # In a real implementation, you would use libbpf or similar
            # to properly read from the ring buffer
            
            # Read events from ring buffer
            # This is a simplified implementation - in production, use libbpf
            try:
                # Read available data from ring buffer
                data = mm.read(4096)  # Read up to 4KB
                if data:
                    # Parse events from the data
                    offset = 0
                    while offset < len(data) - 8:  # Minimum event size
                        # Parse event header (simplified)
                        event_type = struct.unpack('<I', data[offset:offset+4])[0]
                        timestamp = struct.unpack('<Q', data[offset+4:offset+12])[0]
                        pid = struct.unpack('<I', data[offset+12:offset+16])[0]
                        uid = struct.unpack('<I', data[offset+16:offset+20])[0]
                        gid = struct.unpack('<I', data[offset+20:offset+24])[0]
                        
                        # Create event object
                        event = EBpfEvent(
                            event_type=event_type,
                            timestamp=timestamp,
                            pid=pid,
                            uid=uid,
                            gid=gid,
                            data=data[offset+24:offset+32]  # Remaining data
                        )
                        events.append(event)
                        offset += 32  # Move to next event
            except (struct.error, IndexError):
                # Handle parsing errors gracefully
                pass
            
        except Exception as e:
            logger.error(f"Error reading ring buffer events: {e}")
        
        return events
    
    def _handle_event(self, event: EBpfEvent):
        """Handle a single eBPF event"""
        try:
            # Call registered event handlers
            if event.event_type in self.event_handlers:
                for handler in self.event_handlers[event.event_type]:
                    handler(event)
            
            # Update statistics
            self._update_stats(event)
            
        except Exception as e:
            logger.error(f"Error handling event: {e}")
    
    def _update_stats(self, event: EBpfEvent):
        """Update statistics based on event"""
        try:
            # Update global statistics based on event type
            if hasattr(self, '_stats'):
                self._stats.total_events += 1
                
                # Categorize events by type
                if event.event_type == 1:  # Syscall event
                    self._stats.syscall_events += 1
                elif event.event_type == 2:  # File event
                    self._stats.file_events += 1
                elif event.event_type == 3:  # Network event
                    self._stats.network_events += 1
                elif event.event_type == 4:  # Process event
                    self._stats.process_events += 1
                elif event.event_type == 5:  # Anomaly event
                    self._stats.anomaly_events += 1
                elif event.event_type == 6:  # Violation event
                    self._stats.violation_events += 1
                    self._stats.denied_operations += 1
                elif event.event_type == 7:  # Allow event
                    self._stats.allowed_operations += 1
                elif event.event_type == 8:  # Audit event
                    self._stats.audited_operations += 1
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
    
    def register_event_handler(self, event_type: int, handler):
        """Register an event handler"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        
        self.event_handlers[event_type].append(handler)
        logger.info(f"Registered handler for event type {event_type}")
    
    def get_statistics(self) -> EBpfStats:
        """Get current eBPF statistics"""
        try:
            # Return current statistics
            return self._stats
                
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return EBpfStats(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    def update_network_rules(self, rules: List[Dict[str, Any]]):
        """Update network microsegmentation rules"""
        logger.info(f"Updating {len(rules)} network rules")
        
        try:
            # Update network_rules map
            if 'network_rules' in self.maps:
                map_path = self.maps['network_rules']['path']
                
                # Write rules to the eBPF map
                with open(map_path, 'wb') as f:
                    for i, rule in enumerate(rules):
                        # Serialize rule data
                        rule_data = json.dumps(rule).encode('utf-8')
                        # Write rule index and data
                        f.write(struct.pack('<I', i))  # Rule index
                        f.write(struct.pack('<I', len(rule_data)))  # Data length
                        f.write(rule_data)  # Rule data
                
                logger.info("Network rules updated successfully")
            else:
                logger.warning("Network rules map not found")
            
        except Exception as e:
            logger.error(f"Error updating network rules: {e}")
    
    def update_conditional_rules(self, rules: List[Dict[str, Any]]):
        """Update conditional policy rules"""
        logger.info(f"Updating {len(rules)} conditional rules")
        
        try:
            # Update conditional_rules map
            if 'conditional_rules' in self.maps:
                map_path = self.maps['conditional_rules']['path']
                
                # Write rules to the eBPF map
                with open(map_path, 'wb') as f:
                    for i, rule in enumerate(rules):
                        # Serialize rule data
                        rule_data = json.dumps(rule).encode('utf-8')
                        # Write rule index and data
                        f.write(struct.pack('<I', i))  # Rule index
                        f.write(struct.pack('<I', len(rule_data)))  # Data length
                        f.write(rule_data)  # Rule data
                
                logger.info("Conditional rules updated successfully")
            else:
                logger.warning("Conditional rules map not found")
            
        except Exception as e:
            logger.error(f"Error updating conditional rules: {e}")
    
    def stop_monitoring(self):
        """Stop eBPF monitoring"""
        logger.info("Stopping eBPF monitoring...")
        
        self.running = False
        
        # Wait for event processing thread to finish
        if hasattr(self, 'event_thread'):
            self.event_thread.join(timeout=5)
        
        # Detach and unload programs
        self._unload_all_programs()
        
        # Clean up maps
        self._cleanup_maps()
        
        logger.info("eBPF monitoring stopped")
    
    def _unload_all_programs(self):
        """Unload all eBPF programs"""
        for program_name, program_info in self.programs.items():
            try:
                if program_info.get('attached', False):
                    # Detach program
                    cmd = ['bpftool', 'prog', 'detach', str(program_info['id'])]
                    subprocess.run(cmd, capture_output=True)
                
                # Unload program
                cmd = ['bpftool', 'prog', 'unload', str(program_info['id'])]
                subprocess.run(cmd, capture_output=True)
                
                logger.info(f"Unloaded program: {program_name}")
                
            except Exception as e:
                logger.error(f"Error unloading program {program_name}: {e}")
    
    def _cleanup_maps(self):
        """Clean up eBPF maps"""
        for map_name, map_info in self.maps.items():
            try:
                # Remove map file
                if os.path.exists(map_info['path']):
                    os.unlink(map_info['path'])
                
                logger.info(f"Cleaned up map: {map_name}")
                
            except Exception as e:
                logger.error(f"Error cleaning up map {map_name}: {e}")

def main():
    parser = argparse.ArgumentParser(description='eBPF Loader for AppArmor Zero Trust')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--compile', help='Compile eBPF source file')
    parser.add_argument('--load', help='Load eBPF program')
    parser.add_argument('--start', action='store_true', help='Start monitoring')
    parser.add_argument('--stop', action='store_true', help='Stop monitoring')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    
    args = parser.parse_args()
    
    # Create eBPF loader
    loader = EBpfLoader(args.config)
    
    try:
        if args.compile:
            # Compile eBPF program
            output_path = args.compile.replace('.c', '.o')
            if loader.compile_ebpf_program(args.compile, output_path):
                print(f"eBPF program compiled successfully: {output_path}")
            else:
                print("Failed to compile eBPF program")
                sys.exit(1)
        
        elif args.load:
            # Load eBPF program
            if loader.load_ebpf_program(args.load, 'apparmor_monitor'):
                print("eBPF program loaded successfully")
            else:
                print("Failed to load eBPF program")
                sys.exit(1)
        
        elif args.start:
            # Start monitoring
            if loader.start_monitoring():
                print("eBPF monitoring started")
                try:
                    # Keep running until interrupted
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\nStopping monitoring...")
                    loader.stop_monitoring()
            else:
                print("Failed to start eBPF monitoring")
                sys.exit(1)
        
        elif args.stop:
            # Stop monitoring
            loader.stop_monitoring()
            print("eBPF monitoring stopped")
        
        elif args.stats:
            # Show statistics
            stats = loader.get_statistics()
            print(f"Total Events: {stats.total_events}")
            print(f"Syscall Events: {stats.syscall_events}")
            print(f"File Events: {stats.file_events}")
            print(f"Network Events: {stats.network_events}")
            print(f"Process Events: {stats.process_events}")
            print(f"Anomaly Events: {stats.anomaly_events}")
            print(f"Violation Events: {stats.violation_events}")
            print(f"Denied Operations: {stats.denied_operations}")
            print(f"Allowed Operations: {stats.allowed_operations}")
            print(f"Audited Operations: {stats.audited_operations}")
        
        else:
            parser.print_help()
    
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
