from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import random
from enum import Enum
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Any
import threading
import queue
import json

app = Flask(__name__)
CORS(app)

# Enums and Data Classes
class State(Enum):
    IDLE = 0
    SYN_RECEIVED = 1
    ACK_RECEIVED = 2

@dataclass
class Packet:
    data: str
    checksum: int
    flags: int
    timestamp: float
    is_valid: bool = True
    
    def compute_checksum(self):
        return ord(self.data) ^ 0xFF
    
    def verify_checksum(self):
        return self.checksum == self.compute_checksum()

@dataclass
class SimulationResult:
    input_packet: Packet
    output_data: str
    state_before: State
    state_after: State
    checksum_valid: bool
    response_type: str
    timestamp: float

# TCP/IP Stack Simulator
class TCPIPStackSimulator:
    def __init__(self):
        self.state = State.IDLE
        self.reset()
        
    def reset(self):
        self.state = State.IDLE
        self.packet_history = []
        self.simulation_results = []
        self.statistics = {
            'total_packets': 0,
            'passed_packets': 0,
            'failed_packets': 0,
            'checksum_errors': 0,
            'state_transitions': 0
        }
        
    def process_packet(self, packet: Packet) -> Dict[str, Any]:
        """Process a single packet through the TCP/IP stack"""
        self.statistics['total_packets'] += 1
        
        state_before = self.state
        output_data = ""
        response_type = "normal"
        
        # Verify checksum first
        if not packet.verify_checksum():
            output_data = "E"
            response_type = "error"
            self.statistics['checksum_errors'] += 1
            self.statistics['failed_packets'] += 1
        else:
            # Process based on current state and input
            if self.state == State.IDLE:
                if packet.data == "S":
                    self.state = State.SYN_RECEIVED
                    output_data = "A"
                    response_type = "syn_ack"
                    self.statistics['state_transitions'] += 1
                else:
                    output_data = packet.data
                    response_type = "echo"
                    
            elif self.state == State.SYN_RECEIVED:
                if packet.data == "K":
                    self.state = State.ACK_RECEIVED
                    output_data = "C"
                    response_type = "ack_complete"
                    self.statistics['state_transitions'] += 1
                else:
                    output_data = packet.data
                    response_type = "echo"
                    
            elif self.state == State.ACK_RECEIVED:
                output_data = packet.data
                response_type = "data_transfer"
                
            self.statistics['passed_packets'] += 1
        
        # Create simulation result
        result = SimulationResult(
            input_packet=packet,
            output_data=output_data,
            state_before=state_before,
            state_after=self.state,
            checksum_valid=packet.verify_checksum(),
            response_type=response_type,
            timestamp=time.time()
        )
        
        self.simulation_results.append(result)
        self.packet_history.append(packet)
        
        return {
            'input_data': packet.data,
            'output_data': output_data,
            'state_before': state_before.name,
            'state_after': self.state.name,
            'checksum_valid': packet.verify_checksum(),
            'response_type': response_type,
            'timestamp': result.timestamp
        }

# Global simulator instance
simulator = TCPIPStackSimulator()

# Coverage tracking
class CoverageTracker:
    def __init__(self):
        self.input_coverage = {
            'syn': 0,
            'ack': 0,
            'noise': 0,
            'misc': 0
        }
        self.fsm_transitions = {
            'idle_to_syn': 0,
            'syn_to_ack': 0,
            'resets': 0
        }
        
    def update_input_coverage(self, data: str):
        if data == "S":
            self.input_coverage['syn'] += 1
        elif data == "K":
            self.input_coverage['ack'] += 1
        elif data == "Z":
            self.input_coverage['noise'] += 1
        else:
            self.input_coverage['misc'] += 1
            
    def update_fsm_coverage(self, state_before: State, state_after: State):
        if state_before == State.IDLE and state_after == State.SYN_RECEIVED:
            self.fsm_transitions['idle_to_syn'] += 1
        elif state_before == State.SYN_RECEIVED and state_after == State.ACK_RECEIVED:
            self.fsm_transitions['syn_to_ack'] += 1
            
    def get_coverage_report(self):
        total_inputs = sum(self.input_coverage.values())
        total_transitions = sum(self.fsm_transitions.values())
        
        return {
            'input_coverage': self.input_coverage,
            'fsm_transitions': self.fsm_transitions,
            'input_coverage_percentage': (total_inputs / max(1, total_inputs)) * 100,
            'fsm_coverage_percentage': (total_transitions / max(1, total_transitions)) * 100
        }

coverage_tracker = CoverageTracker()

# API Endpoints
@app.route('/api/reset', methods=['POST'])
def reset_simulation():
    """Reset the simulation state"""
    global simulator, coverage_tracker
    simulator.reset()
    coverage_tracker = CoverageTracker()
    return jsonify({
        'message': 'Simulation reset successfully',
        'state': simulator.state.name,
        'timestamp': time.time()
    })

@app.route('/api/send-packet', methods=['POST'])
def send_packet():
    """Send a single packet to the TCP/IP stack"""
    try:
        data = request.json
        
        # Create packet
        packet = Packet(
            data=data['data'],
            checksum=data.get('checksum', ord(data['data']) ^ 0xFF),
            flags=data.get('flags', 0),
            timestamp=time.time()
        )
        
        # Process packet
        state_before = simulator.state
        result = simulator.process_packet(packet)
        
        # Update coverage
        coverage_tracker.update_input_coverage(packet.data)
        coverage_tracker.update_fsm_coverage(state_before, simulator.state)
        
        return jsonify({
            'success': True,
            'result': result,
            'statistics': simulator.statistics
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/handshake', methods=['POST'])
def perform_handshake():
    """Perform a complete 3-way handshake"""
    try:
        # Reset to ensure clean state
        simulator.reset()
        
        results = []
        
        # Step 1: Send SYN
        syn_packet = Packet(data="S", checksum=ord("S") ^ 0xFF, flags=1, timestamp=time.time())
        syn_result = simulator.process_packet(syn_packet)
        results.append(syn_result)
        
        # Step 2: Send ACK
        ack_packet = Packet(data="K", checksum=ord("K") ^ 0xFF, flags=2, timestamp=time.time())
        ack_result = simulator.process_packet(ack_packet)
        results.append(ack_result)
        
        # Update coverage
        coverage_tracker.update_input_coverage("S")
        coverage_tracker.update_input_coverage("K")
        coverage_tracker.update_fsm_coverage(State.IDLE, State.SYN_RECEIVED)
        coverage_tracker.update_fsm_coverage(State.SYN_RECEIVED, State.ACK_RECEIVED)
        
        return jsonify({
            'success': True,
            'handshake_complete': simulator.state == State.ACK_RECEIVED,
            'results': results,
            'final_state': simulator.state.name,
            'statistics': simulator.statistics
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/run-test', methods=['POST'])
def run_test():
    """Run a comprehensive test with random packets"""
    try:
        data = request.json
        num_packets = data.get('num_packets', 10)
        include_errors = data.get('include_errors', True)
        
        # Reset simulation
        simulator.reset()
        
        results = []
        
        # Perform handshake first
        for packet_data in ["S", "K"]:
            packet = Packet(
                data=packet_data,
                checksum=ord(packet_data) ^ 0xFF,
                flags=1 if packet_data == "S" else 2,
                timestamp=time.time()
            )
            result = simulator.process_packet(packet)
            results.append(result)
        
        # Send random packets
        test_chars = ["X", "Y", "Z", "A", "B", "C"]
        
        for i in range(num_packets):
            # Random data
            data_char = random.choice(test_chars)
            
            # Introduce checksum errors 20% of the time if enabled
            if include_errors and random.random() < 0.2:
                checksum = ord(data_char) ^ 0xAA  # Wrong checksum
            else:
                checksum = ord(data_char) ^ 0xFF  # Correct checksum
            
            packet = Packet(
                data=data_char,
                checksum=checksum,
                flags=random.randint(0, 3),
                timestamp=time.time()
            )
            
            result = simulator.process_packet(packet)
            results.append(result)
            
            # Update coverage
            coverage_tracker.update_input_coverage(data_char)
        
        # Generate coverage report
        coverage_report = coverage_tracker.get_coverage_report()
        
        return jsonify({
            'success': True,
            'results': results,
            'statistics': simulator.statistics,
            'coverage': coverage_report,
            'final_state': simulator.state.name
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current simulation status"""
    return jsonify({
        'current_state': simulator.state.name,
        'statistics': simulator.statistics,
        'packet_count': len(simulator.packet_history),
        'coverage': coverage_tracker.get_coverage_report()
    })

@app.route('/api/history', methods=['GET'])
def get_history():
    """Get simulation history"""
    return jsonify({
        'packet_history': [asdict(p) for p in simulator.packet_history],
        'simulation_results': [asdict(r) for r in simulator.simulation_results],
        'statistics': simulator.statistics
    })

@app.route('/api/validate-checksum', methods=['POST'])
def validate_checksum():
    """Validate checksum for given data"""
    try:
        data = request.json
        char = data['data']
        provided_checksum = data.get('checksum')
        
        correct_checksum = ord(char) ^ 0xFF
        is_valid = provided_checksum == correct_checksum if provided_checksum is not None else True
        
        return jsonify({
            'data': char,
            'correct_checksum': correct_checksum,
            'provided_checksum': provided_checksum,
            'is_valid': is_valid
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/generate-packet', methods=['POST'])
def generate_packet():
    """Generate a random packet for testing"""
    try:
        data = request.json
        packet_type = data.get('type', 'random')  # 'syn', 'ack', 'data', 'random'
        introduce_error = data.get('introduce_error', False)
        
        if packet_type == 'syn':
            char = 'S'
            flags = 1
        elif packet_type == 'ack':
            char = 'K'
            flags = 2
        elif packet_type == 'data':
            char = random.choice(['X', 'Y', 'Z', 'A', 'B', 'C'])
            flags = 0
        else:  # random
            char = random.choice(['S', 'K', 'X', 'Y', 'Z', 'A', 'B', 'C'])
            flags = random.randint(0, 3)
        
        # Calculate checksum
        if introduce_error:
            checksum = ord(char) ^ 0xAA  # Wrong checksum
        else:
            checksum = ord(char) ^ 0xFF  # Correct checksum
        
        packet = {
            'data': char,
            'checksum': checksum,
            'flags': flags,
            'timestamp': time.time(),
            'checksum_valid': not introduce_error
        }
        
        return jsonify({
            'success': True,
            'packet': packet
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'version': '1.0.0'
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'message': 'The requested API endpoint does not exist'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500

