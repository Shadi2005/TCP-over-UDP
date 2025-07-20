import socket
import random
import time
import threading
import logging

from lib.packet import Packet
from lib.state import State
from lib.RSA import RSA


MSS = 500
MAX_RETRIES = 3
HANDSHAKE_TIMEOUT = 240
LAST_ACTIVITY_TIMEOUT = 300
DUPLICATE_TOLERANCE = 4 * MSS

MAX_SEQ_NUM = 2**32
HALF_SEQ_NUM = 2**31

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

connections_to_remove = []

def is_greater(a: int, b: int) -> bool:
    return (a - b) % MAX_SEQ_NUM < HALF_SEQ_NUM and a != b

class Connection:
    def __init__(self, udp_socket: socket.socket, src_addr, dest_addr):
        self.state = State.CLOSED
        
        self.udp_socket = udp_socket
        self.src_addr = src_addr
        self.dest_addr = dest_addr

        # Sequence Numbers
        self.seq_number = random.randint(0, 2**32 - 1)
        self.ack_number = 0

        # Buffers
        self.send_buffer = b''
        self.recv_buffer = {}  # For out-of-order packets
        self.recv_data = b''

        # Sliding Window
        self.send_window = {}  # seq_num -> (packet, timestamp, retries)
        self.window_size = 5
        self.send_base = self.seq_number

        # Flow Control 
        self.rwnd = 65535  # Receiver window size (default)
        self.remote_rwnd = 65535  

        # Congestion Control
        self.cwnd = MSS # Congestion window (start with 1 MSS)
        self.ssthresh = 65535  # Slow start threshold
        self.congestion_state = "SLOW_START"  # SLOW_START, CONGESTION_AVOIDANCE, FAST_RECOVERY
        self.duplicate_ack_count = 0
        self.last_ack_received = 0
        self.fast_recovery_seq = 0

        # Zero Window Probing
        self.zero_window_probe_timer = None
        self.zero_window_probe_interval = 5.0  # Start with 5 seconds
        self.max_zero_window_probe_interval = 60.0  # Maximum 60 seconds
        self.zero_window_probe_seq = None

        # Handshake Timeout 
        self.handshake_start = None

        # Threading
        self.connection_thread = threading.Thread(target=self._thread_management, daemon=True)
        self.connection_thread.start()
        self.recv_condition = threading.Condition()
        self.send_condition = threading.Condition()
        self.running = True

        # Activity Tracking
        self.last_activity = time.time()

        # Dynamic Timeout 
        self.srtt = None 
        self.rttvar = None  
        self.rto = 1.0  
        self.rtt_measurements = {}  # seq_num -> send_time for measuring RTT

        # Close Tracking
        self.close_timeout = None
        self.fin_acked = False

        # Encryption
        self.rsa: RSA = None
        self.max_encryptable_len = None

        logger.info(f"Connection created: {self.src_addr} -> {self.dest_addr}")

    def _thread_management(self):
        logger.info(f"Connection thread started for {self.dest_addr}")

        while self.state != State.ESTABLISHED:
            self._handle_handshake_timeout()
        
        while self.running:
            try:
                self._handle_send_buffer()
                self._handle_retransmissions()
                self._handle_timeout()
                self._handle_close_timeout()
                
                # Handle zero window probing
                if (self.remote_rwnd == 0 and 
                    len(self.send_buffer) > 0 and 
                    self.state == State.ESTABLISHED):
                    self._handle_zero_window()
                
                time.sleep(0.01)
            except Exception as e:
                logger.error(f"Error in connection thread: {e}")
                break
        
        logger.info(f"Connection thread stopped for {self.dest_addr}")

    def _handle_handshake_timeout(self):
        if self.handshake_start is not None and time.time() - self.handshake_start > HANDSHAKE_TIMEOUT:
            logger.warning("Handshake timeout exceeded before completion.")
            self._force_close()

    def _force_close(self):
        self.state = State.CLOSED
        self.running = False
        
        # Wake up any waiting threads
        with self.send_condition:
            self.send_condition.notify_all()
        with self.recv_condition:
            self.recv_condition.notify_all()

        connections_to_remove.append(self.dest_addr)
        
        logger.info(f"Connection to {self.dest_addr} force closed")

    def _handle_send_buffer(self):
        with self.send_condition:
            while (len(self.send_buffer) > 0 and
                   self.state == State.ESTABLISHED):
                
                # Calculate effective window size (min of congestion and flow control)
                effective_window = min(self.cwnd, self.remote_rwnd)
                
                # Calculate bytes in flight
                bytes_in_flight = sum(len(packet.payload) for packet, _, _ in self.send_window.values())
                
                # Handle zero window condition
                if self.remote_rwnd == 0:
                    self._handle_zero_window()
                    break
                
                # Check if we can send more data
                if bytes_in_flight >= effective_window:
                    break
                    
                # Send up to MSS bytes
                available_window = effective_window - bytes_in_flight
                if self.max_encryptable_len is None:
                    raise Exception("max_encryptable_len not initialized")

                data_to_send = min(self.max_encryptable_len, len(self.send_buffer), available_window)

                if data_to_send <= 0:
                    break
                    
                # Send data packet  
                data = self.send_buffer[:data_to_send]
                self.send_buffer = self.send_buffer[data_to_send:]
                self._send_data_packet(data)

    def _handle_zero_window(self):
        current_time = time.time()
        
        # If no probe timer is set, start one
        if self.zero_window_probe_timer is None:
            self.zero_window_probe_timer = current_time + self.zero_window_probe_interval
            logger.info(f"Zero window detected, starting probe timer for {self.dest_addr}")
            return
        
        # Check if it's time to send a probe
        if current_time >= self.zero_window_probe_timer:
            self._send_zero_window_probe()
            
            # Exponential backoff for probe interval (up to maximum)
            self.zero_window_probe_interval = min(
                self.zero_window_probe_interval * 2,
                self.max_zero_window_probe_interval
            )
            
            # Set next probe time
            self.zero_window_probe_timer = current_time + self.zero_window_probe_interval
            
            logger.debug(f"Sent zero window probe to {self.dest_addr}, next probe in {self.zero_window_probe_interval}s")

    def _send_zero_window_probe(self):
        # Send 1 byte of data that's already been sent (or next byte if available)
        probe_data = b''
        probe_seq = self.seq_number
        
        if len(self.send_buffer) > 0:
            # Send the next byte from send buffer
            probe_data = self.send_buffer[:1]
            self.zero_window_probe_seq = self.seq_number
        elif self.send_window:
            # Resend 1 byte from an unacknowledged packet
            min_seq = min(self.send_window.keys())
            original_packet = self.send_window[min_seq][0]
            if len(original_packet.payload) > 0:
                probe_data = original_packet.payload[:1]
                probe_seq = min_seq
        else:
            # Send empty probe with current sequence number
            probe_data = b''
            probe_seq = self.seq_number
        
        # Encrypt the probe data if it's not empty
        if probe_data:
            probe_data = self.rsa.encrypt(probe_data)
        
        self._update_rwnd()
        
        probe_packet = Packet(
            source_port=self.src_addr[1],
            destination_port=self.dest_addr[1],
            seq_number=probe_seq,
            ack_number=self.ack_number,
            rwnd=self.rwnd,
            payload=probe_data,
            ACK=True
        )
        
        serialized_packet = probe_packet.serialize_packet()
        self.udp_socket.sendto(serialized_packet, self.dest_addr)
        
        logger.debug(f"Sent zero window probe: seq={probe_seq}, data_len={len(probe_data)}")

    def _send_data_packet(self, data):
        data = self.rsa.encrypt(data)

        self._update_rwnd()

        packet = Packet(
            source_port=self.src_addr[1],
            destination_port=self.dest_addr[1],
            seq_number=self.seq_number,
            ack_number=self.ack_number,
            rwnd= self.rwnd,
            payload=data,
            ACK=True
        )

        self.send_window[self.seq_number] = (packet, time.time(), 0)
        self.rtt_measurements[self.seq_number] = time.time()
        self.seq_number = (self.seq_number + len(data)) % MAX_SEQ_NUM

        serialized_packet = packet.serialize_packet()
        self.udp_socket.sendto(serialized_packet, self.dest_addr)

        self.last_activity = time.time()

        logger.info(f"Sent data packet: seq={packet.seq_number}, ack={packet.ack_number}, len={len(packet.payload)}")

    def _handle_retransmissions(self):
        current_time = time.time()
        to_retransmit = []
        timeout_occurred = False

        for seq_num, (packet, timestamp, retries) in self.send_window.items():
            if current_time - timestamp > self.rto:
                if retries < MAX_RETRIES:
                    to_retransmit.append(seq_num)
                    timeout_occurred = True
                else:
                    logger.error(f"Max retries exceeded for seq [{seq_num}]")
                    self._force_close()
                    return

        if timeout_occurred:
            # Timeout occurred - enter slow start
            self.ssthresh = max(self.cwnd // 2, 2 * MSS)
            self.cwnd = MSS
            self.congestion_state = "SLOW_START"
            self.duplicate_ack_count = 0
            logger.warning(f"Timeout occurred: cwnd={self.cwnd}, ssthresh={self.ssthresh}")

        for seq_num in to_retransmit:
            packet, _, retries = self.send_window[seq_num]
            self.send_window[seq_num] = (packet, current_time, retries + 1)
            
            serialized_packet = packet.serialize_packet()
            self.udp_socket.sendto(serialized_packet, self.dest_addr)
            
            logger.warning(f"Retransmitted packet: seq={seq_num}, attempt={retries + 1}")

    def _handle_timeout(self):
        if (time.time() - self.last_activity > LAST_ACTIVITY_TIMEOUT and
            self.state == State.ESTABLISHED):
            logger.warning(f"Connection timeout for {self.dest_addr}")
            self.close()

    def _handle_close_timeout(self):
        if self.close_timeout and time.time() > self.close_timeout:
            if self.state == State.FIN_WAIT_1:
                logger.warning(f"FIN_WAIT_1 timeout for {self.dest_addr}")
                self._force_close()
            elif self.state == State.FIN_WAIT_2:
                logger.info(f"FIN_WAIT_2 timeout for {self.dest_addr} - normal close")
                self._force_close()
            elif self.state == State.CLOSING:
                logger.warning(f"CLOSING timeout for {self.dest_addr}")
                self._force_close()
            elif self.state == State.LAST_ACK:
                logger.warning(f"LAST_ACK timeout for {self.dest_addr}")
                self._force_close()
            elif self.state == State.TIME_WAIT:
                logger.info(f"TIME_WAIT timeout for {self.dest_addr} - connection closed")
                self._force_close()

    def process_packet(self, packet: Packet): 

        if not self.running:
            logger.error(f"The connection for {self.dest_addr} is not running")
            return 

        if packet.get_packet_type() == "UNKNOWN":
            logger.warning(f"Received an invalid packet from {self.dest_addr}")
            return 

        # Handle RST packets first
        if packet.get_packet_type() == "RST":
            logger.info(f"Received RST from {self.dest_addr}, closing connection")
            self._force_close()
            return
        
        # Validate packet before processing
        if not self._is_valid_packet(packet):
            logger.warning(f"Invalid packet from {self.dest_addr}: seq={packet.seq_number}, ack={packet.ack_number}, flags={packet.get_packet_type()}")
            self._send_rst_response(self.dest_addr, packet)
            return
        
        # Update last activity tracker 
        self.last_activity = time.time()

        # Handle handshake packets
        if packet.SYN and packet.ACK and self.state == State.SYN_SENT:
            self._handle_syn_ack(packet)
            return
        elif packet.ACK and self.state == State.SYN_RCVD:
            self._handle_handshake_ack(packet)
            return

        if packet.ACK:
            self._handle_ack(packet)

        if packet.payload and len(packet.payload) > 0 and self.state in [State.ESTABLISHED, State.FIN_WAIT_1, State.FIN_WAIT_2]:
            self._handle_data(packet)

        if packet.FIN:
            self._handle_fin(packet)

    def _is_valid_packet(self, packet: Packet) -> bool:
        # Check for valid ACK number
        if self.state == State.ESTABLISHED:
            # For established connections, check if seq_number is within acceptable range
            if packet.payload and len(packet.payload) > 0:
                self._update_rwnd()
                if is_greater((self.ack_number - DUPLICATE_TOLERANCE) % MAX_SEQ_NUM, packet.seq_number) or is_greater(packet.seq_number, (self.ack_number + self.rwnd) % MAX_SEQ_NUM):
                    return False
        
        # Check for valid ACK number
        if packet.ACK:
            if self.state == State.ESTABLISHED:
                # ACK should acknowledge data we've actually sent
                if is_greater(packet.ack_number, (self.seq_number + 1000) % MAX_SEQ_NUM):  # Allow some buffer
                    return False
            elif self.state == State.SYN_SENT:
                # In SYN_SENT, ACK should acknowledge our SYN
                if packet.ack_number != (self.seq_number + 1) % MAX_SEQ_NUM:
                    return False
        
        return True
    
    def _send_rst_response(self, addr, invalid_packet: Packet):
        if invalid_packet.ACK:
            # If the incoming packet has ACK, RST seq should be the ACK number
            rst_seq = invalid_packet.ack_number
            rst_ack = 0
            rst_ack_flag = False
        else:
            # If no ACK, RST should ACK the incoming packet
            rst_seq = 0
            rst_ack = (invalid_packet.seq_number + len(invalid_packet.payload)) % MAX_SEQ_NUM
            if invalid_packet.SYN:
                rst_ack = (rst_ack + 1) % MAX_SEQ_NUM
            if invalid_packet.FIN:
                rst_ack = (rst_ack + 1) % MAX_SEQ_NUM
            rst_ack_flag = True
        
        rst = Packet(
            source_port=self.src_addr[1],
            destination_port=addr[1],
            seq_number=rst_seq,
            ack_number=rst_ack,
            rwnd= 0,
            payload=b'',
            RST=True,
            ACK=rst_ack_flag
        )
        
        serialized_rst = rst.serialize_packet()
        self.udp_socket.sendto(serialized_rst, addr)
        logger.warning(f"Sent RST to {addr} for invalid packet")

    def _handle_syn_ack(self, packet: Packet):
        self.ack_number = (packet.seq_number + 1) % MAX_SEQ_NUM
        self.seq_number = (self.seq_number + 1) % MAX_SEQ_NUM
        
        self.remote_rwnd = packet.rwnd
        self.rsa.remote_public_key = RSA.deserialize_public_key(packet.payload)
            

        e, n = self.rsa.remote_public_key
        cipher_len = (n.bit_length() + 7) // 8

        if cipher_len > MSS:
            raise Exception(f"RSA encrypted size ({cipher_len}) exceeds MSS ({MSS})")
        self.max_encryptable_len = min((n.bit_length() - 1) // 8 - 2, 64) 
                
        self._update_rwnd()
        payload = self.rsa.serialize_public_key()

        # Send ACK to complete handshake
        ack = Packet(
            source_port=self.src_addr[1],
            destination_port=self.dest_addr[1],
            seq_number=self.seq_number,
            ack_number=self.ack_number,
            rwnd=self.rwnd,
            payload=payload,
            ACK=True
        )

        serialized_ack = ack.serialize_packet()
        self.udp_socket.sendto(serialized_ack, self.dest_addr)
        
        self.state = State.ESTABLISHED
        logger.info(f"Handshake completed with {self.dest_addr}")

    def _update_rwnd(self):
        buffer_used = len(self.recv_data) + sum(len(data) for data in self.recv_buffer.values())
        max_buffer = 65535  # Maximum buffer size
        self.rwnd = max(0, max_buffer - buffer_used)

    def _handle_handshake_ack(self, packet: Packet):
        # Server receiving final ACK of handshake
        if packet.ack_number == self.seq_number:
            self.state = State.ESTABLISHED
            
            # Extract window size and public key
            self.remote_rwnd = packet.rwnd
            self.rsa.remote_public_key = RSA.deserialize_public_key(packet.payload)
            
            e, n = self.rsa.remote_public_key
            cipher_len = (n.bit_length() + 7) // 8

            if cipher_len > MSS:
                raise Exception(f"RSA encrypted size ({cipher_len}) exceeds MSS ({MSS})")
            self.max_encryptable_len = min((n.bit_length() - 1) // 8 - 2, 64)
            
            logger.info(f"Connection established with {self.dest_addr}")
            return True
        return False

    def _handle_ack(self, packet: Packet):
        ack_number = packet.ack_number
        
        old_remote_rwnd = self.remote_rwnd
        self.remote_rwnd = packet.rwnd
        
        # Handle window update
        if old_remote_rwnd == 0 and self.remote_rwnd > 0:
            # Window opened up!
            self.zero_window_probe_timer = None
            self.zero_window_probe_interval = 5.0  # Reset probe interval
            self.zero_window_probe_seq = None
            
            # Wake up send thread to resume sending
            with self.send_condition:
                self.send_condition.notify()
            
            logger.info(f"Window opened for {self.dest_addr}: rwnd={self.remote_rwnd}")
        
        # Check for duplicate ACKs
        if ack_number == self.last_ack_received:
            self.duplicate_ack_count += 1
            
            # Fast retransmit on 3 duplicate ACKs
            if self.duplicate_ack_count == 3:
                self._handle_fast_retransmit(ack_number)
                # Enter fast recovery
                self.ssthresh = max(self.cwnd // 2, 2 * MSS)
                self.cwnd = self.ssthresh + 3 * MSS
                self.congestion_state = "FAST_RECOVERY"
                self.fast_recovery_seq = ack_number
                logger.info(f"Entered FAST_RECOVERY: cwnd={self.cwnd}, ssthresh={self.ssthresh}")
            
            elif self.congestion_state == "FAST_RECOVERY":
                # Inflate window during fast recovery
                self.cwnd += MSS
                
        else:
            # New ACK received
            if ack_number in self.rtt_measurements:
                send_time = self.rtt_measurements.pop(ack_number)
                rtt_sample = time.time() - send_time

                if self.srtt is None:
                    # First RTT measurement
                    self.srtt = rtt_sample
                    self.rttvar = rtt_sample / 2
                else:
                    alpha = 1 / 8
                    beta = 1 / 4
                    self.rttvar = (1 - beta) * self.rttvar + beta * abs(self.srtt - rtt_sample)
                    self.srtt = (1 - alpha) * self.srtt + alpha * rtt_sample

                self.rto = self.srtt + max(0.01, 4 * self.rttvar)
                self.rto = max(1.0, min(self.rto, 60.0))  # clamp between 1 and 60 seconds for stability

                logger.debug(f"Updated RTO: {self.rto:.3f}s, SRTT: {self.srtt:.3f}s, RTTVAR: {self.rttvar:.3f}s")

            self.last_ack_received = packet.ack_number
            self.duplicate_ack_count = 1
            self.last_ack_received = ack_number
            
            # Remove acknowledged packets
            to_remove = []
            
            for seq_num in self.send_window:
                if is_greater(ack_number, seq_num):
                    to_remove.append(seq_num)

            for seq_num in to_remove:
                del self.send_window[seq_num]

            if to_remove:
                self.send_base = max(self.send_base, ack_number)
                
                # Congestion control based on current state
                if self.congestion_state == "FAST_RECOVERY":
                    if is_greater(ack_number, self.fast_recovery_seq):
                        # Exit fast recovery
                        self.cwnd = self.ssthresh
                        self.congestion_state = "CONGESTION_AVOIDANCE"
                        logger.info(f"Exited FAST_RECOVERY: cwnd={self.cwnd}")
                
                elif self.congestion_state == "SLOW_START":
                    # Slow start: increase cwnd by MSS for each ACK
                    self.cwnd += MSS
                    
                    # Check if we should enter congestion avoidance
                    if self.cwnd >= self.ssthresh:
                        self.congestion_state = "CONGESTION_AVOIDANCE"
                        logger.info(f"Entered CONGESTION_AVOIDANCE: cwnd={self.cwnd}")
                
                elif self.congestion_state == "CONGESTION_AVOIDANCE":
                    # Congestion avoidance: increase cwnd by MSS²/cwnd for each ACK
                    self.cwnd += (MSS * MSS) // self.cwnd
                
                with self.send_condition:
                    self.send_condition.notify()
                
                logger.debug(f"ACK processed: {ack_number}, cwnd={self.cwnd}, state={self.congestion_state}")

            # Handle close-related ACKs (keep existing logic)
            if self.state == State.FIN_WAIT_1:
                if is_greater(ack_number, self.seq_number) or ack_number == self.seq_number:
                    self.state = State.FIN_WAIT_2
                    self.close_timeout = time.time() + 30
                    logger.info(f"FIN acknowledged, moved to FIN_WAIT_2 for {self.dest_addr}")

            elif self.state == State.CLOSING:
                if is_greater(ack_number, self.seq_number) or ack_number == self.seq_number:
                    self.state = State.TIME_WAIT
                    self.close_timeout = time.time() + 15
                    logger.info(f"FIN acknowledged in CLOSING, moved to TIME_WAIT for {self.dest_addr}")

            elif self.state == State.LAST_ACK:
                if is_greater(ack_number, self.seq_number) or ack_number == self.seq_number:
                    logger.info(f"FIN acknowledged in LAST_ACK, closing connection to {self.dest_addr}")
                    self._force_close()

    def _handle_fast_retransmit(self, ack_number):
        # Find the packet to retransmit
        for seq_num, (packet, timestamp, retries) in self.send_window.items():
            if is_greater(seq_num, ack_number) or seq_num == ack_number:
                self.send_window[seq_num] = (packet, time.time(), retries + 1)
                serialized_packet = packet.serialize_packet()
                self.udp_socket.sendto(serialized_packet, self.dest_addr)
                logger.warning(f"Fast retransmit: seq={seq_num}")
                break

    def _handle_data(self, packet: Packet):
        logger.info(f"Recieved packet: seq={packet.seq_number}, ack={packet.ack_number}")
        decrypted = self.rsa.decrypt(packet.payload)

        if packet.seq_number == self.ack_number:
            # In-order packet
            self.recv_data += decrypted
            self.ack_number =  (self.ack_number + len(packet.payload)) % MAX_SEQ_NUM

            # Check for buffered out-of-order packets
            while self.ack_number in self.recv_buffer:
                buffered_data = self.recv_buffer.pop(self.ack_number)
                self.recv_data += self.rsa.decrypt(buffered_data)
                self.ack_number = (self.ack_number + len(buffered_data)) % MAX_SEQ_NUM

            # Send ACK
            self._send_ack()

            with self.recv_condition:
                self.recv_condition.notify_all()

            logger.debug(f"Received in-order data: seq={packet.seq_number}, len={len(decrypted)}")

        elif is_greater(packet.seq_number, self.ack_number):
            # Out-of-order packet - buffer it
            self.recv_buffer[packet.seq_number] = packet.payload
            self._send_ack()  # Send duplicate ACK
            logger.debug(f"Received out-of-order data: seq={packet.seq_number}, expected={self.ack_number}")

        else:
            # Duplicate packet - just send ACK
            self._send_ack()
            logger.debug(f"Received duplicate data: seq={packet.seq_number}")

    def _send_ack(self):
        self._update_rwnd()

        ack = Packet(
            source_port=self.src_addr[1],
            destination_port=self.dest_addr[1],
            seq_number=self.seq_number,
            ack_number=self.ack_number,
            rwnd= self.rwnd,
            payload=b'', 
            ACK=True
        )

        serialized_ack = ack.serialize_packet()
        self.udp_socket.sendto(serialized_ack, self.dest_addr)
        logger.info(f"[TEST] Sent ACK: ack={self.ack_number}, rwnd={self.rwnd}")

    def _handle_fin(self, packet: Packet):
        if self.state == State.ESTABLISHED:
            self.state = State.CLOSE_WAIT
            self.ack_number = (packet.seq_number + 1) % MAX_SEQ_NUM

            self._update_rwnd()

            # Send ACK for FIN
            ack = Packet(
                source_port=self.src_addr[1],
                destination_port=self.dest_addr[1],
                seq_number=self.seq_number,
                ack_number=self.ack_number,
                rwnd= self.rwnd,
                payload=b'',
                ACK=True
            )

            serialized_ack = ack.serialize_packet()
            self.udp_socket.sendto(serialized_ack, self.dest_addr)

            logger.info(f"Received FIN from {self.dest_addr}, moved to CLOSE_WAIT")

        elif self.state == State.FIN_WAIT_1:
            # Simultaneous close or FIN received before ACK
            self.ack_number = (packet.seq_number + 1) % MAX_SEQ_NUM
            self._send_ack()
            
            # Check if we also received ACK for our FIN
            if is_greater(packet.ack_number, (self.seq_number - 1) % MAX_SEQ_NUM):
                self.state = State.TIME_WAIT
                self.close_timeout = time.time() + 60  # 2*MSL
                logger.info(f"Simultaneous close - moved to TIME_WAIT for {self.dest_addr}")
            else:
                self.state = State.CLOSING
                self.close_timeout = time.time() + 30  # 30 second timeout
                logger.info(f"Simultaneous close - moved to CLOSING for {self.dest_addr}")

        elif self.state == State.FIN_WAIT_2:
            self.state = State.TIME_WAIT
            self.ack_number = (packet.seq_number + 1) % MAX_SEQ_NUM
            self._send_ack()
            self.close_timeout = time.time() + 60  # 2*MSL
            logger.info(f"Received FIN in FIN_WAIT_2, moved to TIME_WAIT for {self.dest_addr}")

    def send(self, data: bytes):
        if self.state not in [State.ESTABLISHED, State.CLOSE_WAIT]:
            raise Exception(f"Cannot send data in state {self.state}")
        
        with self.send_condition:
            self.send_buffer += data
            self.send_condition.notify()

        logger.debug(f"Added {len(data)} bytes to send buffer")

    def recv(self, size, timeout=60):
        if self.state not in [State.ESTABLISHED, State.CLOSE_WAIT]:
            raise Exception(f"Cannot receive data in state {self.state}")
        
        # add this for testing 
        # size = min(size, len(self.recv_data))

        start_time = time.time()
        with self.recv_condition:
            while len(self.recv_data) < size and self.state in [State.ESTABLISHED, State.CLOSE_WAIT] and (time.time() - start_time < timeout):
                self.recv_condition.wait(timeout=1.0)

            if len(self.recv_data) == 0:
                return b''

        data = self.recv_data[:size]
        self.recv_data = self.recv_data[size:]
        return data

    def close(self):
        self._update_rwnd()
        if self.state == State.ESTABLISHED:
            # Active close - send FIN
            fin = Packet(
                source_port=self.src_addr[1],
                destination_port=self.dest_addr[1],
                seq_number=self.seq_number,
                ack_number=self.ack_number,
                rwnd=self.rwnd,
                payload=b'',
                FIN=True,
                ACK=True
            )

            serialized_fin = fin.serialize_packet()
            self.udp_socket.sendto(serialized_fin, self.dest_addr)

            self.seq_number = (self.seq_number + 1) % MAX_SEQ_NUM  # Increment for FIN consumption
            self.state = State.FIN_WAIT_1
            self.close_timeout = time.time() + 30  # 30 second timeout
            logger.info(f"Sent FIN to {self.dest_addr}, moved to FIN_WAIT_1")

        elif self.state == State.CLOSE_WAIT:
            # Passive close - send FIN
            fin = Packet(
                source_port=self.src_addr[1],
                destination_port=self.dest_addr[1],
                seq_number=self.seq_number,
                ack_number=self.ack_number,
                rwnd=self.rwnd,
                payload=b'',
                FIN=True,
                ACK=True
            )

            serialized_fin = fin.serialize_packet()
            self.udp_socket.sendto(serialized_fin, self.dest_addr)

            self.seq_number = (self.seq_number + 1) % MAX_SEQ_NUM # Increment for FIN consumption
            self.state = State.LAST_ACK
            self.close_timeout = time.time() + 30  # 30 second timeout
            logger.info(f"Sent FIN to {self.dest_addr}, moved to LAST_ACK")

        elif self.state == State.CLOSED:
            logger.info(f"Connection to {self.dest_addr} already closed")

        else:
            logger.warning(f"Cannot close connection in state {self.state}")

    

    