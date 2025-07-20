import socket
import random
import time
import threading
import queue
from typing import Dict, Tuple

from lib.connection import Connection, logger, connections_to_remove, MAX_SEQ_NUM
from lib.packet import Packet
from lib.state import State
from lib.RSA import RSA

BUFFER_SIZE = 65536

class Socket:
    def __init__(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.src_addr = None
        self.state = State.CLOSED
        self.running = False

        # Server-specific attributes
        self.accept_queue = queue.Queue()
        self.accept_queue_size = None

        # Connection management
        self.connections: Dict[Tuple[str, int], Connection] = {}
        self.accepted_connections: Dict[Tuple[str, int], Connection] = {}  # Track accepted connections separately
        self.client_connection = None  # For client mode

        # Threading
        self.recv_thread = None

        # Encryption
        self.rsa = RSA()

    def __del__(self):
        if self.state != State.CLOSED:
            self.close()
        
        for conn in list(self.accepted_connections.values()):
            conn.close()
        self.accepted_connections.clear()
        
        for conn in list(self.connections.values()):
            conn.close()
        self.connections.clear()

        if self.client_connection:
            self.client_connection.close
        
        self.running = False
        self.udp_socket.close()
        logger.info("Socket forcefully closed")

    def bind(self, addr):
        try:
            self.udp_socket.bind(addr)
            self.src_addr = addr
            logger.info(f"Socket bound to {addr}")
        except OSError as e:
            logger.error(f"Socket binding failed: {e}")
            raise

    def listen(self, size=5):
        if self.src_addr is None:
            raise Exception("Socket must be bound before listening")

        self.accept_queue_size = size
        self.state = State.LISTEN
        self.running = True

        self.recv_thread = threading.Thread(target=self._server_thread, daemon=True)
        self.recv_thread.start()

        logger.info(f"Socket listening with accept queue size {size}")

    def _server_thread(self):
        logger.info("Server receive thread started")

        while self.running:
            try:
                if connections_to_remove:
                    self._remove_closed_connections()

                data, addr = self.udp_socket.recvfrom(BUFFER_SIZE)   
                packet = Packet.deserialize_packet(data)

                if not packet:
                    continue

                logger.debug(f"Received packet from {addr}: {packet.get_packet_type()}")

                if packet.get_packet_type() == "RST":
                    if addr in self.connections:
                        self.connections[addr].process_packet(packet)
                    elif addr in self.accepted_connections:
                        self.accepted_connections[addr].process_packet(packet)
                    continue

                if packet.get_packet_type() == "SYN":
                    if self.state == State.LISTEN:
                        self._handle_syn(packet, addr)
                    else:
                        self._send_rst_to_addr(addr, packet)
                        
                elif packet.get_packet_type() == "ACK" and addr in self.connections:
                    conn = self.connections[addr]
                    if conn.state == State.SYN_RCVD:
                        # Validate final handshake ACK
                        if packet.ack_number != conn.seq_number:
                            logger.warning(f"Invalid handshake ACK from {addr}")
                            self._send_rst_to_addr(addr, packet)
                            del self.connections[addr]
                            continue
                            
                        if conn._handle_handshake_ack(packet):
                            self.accept_queue.put(addr)
                    else:
                        conn.process_packet(packet)
    
                elif addr in self.connections:
                    self.connections[addr].process_packet(packet)

                elif addr in self.accepted_connections:
                    self.accepted_connections[addr].process_packet(packet)

                else:
                    self._send_rst_to_addr(addr, packet)

            except socket.timeout:
                continue
            except OSError as e:
                # Handle connection reset by peer
                if e.errno == 10054:
                    logger.debug(f"Connection reset by peer - normal during close sequence")
                elif self.running:
                    logger.error(f"Error in server thread: {e}")
                    break
                else:
                    break
            except Exception as e:
                if self.running:
                    logger.error(f"Error in server thread: {e}")
                break

        logger.info("Server receive thread stopped")

    def _remove_closed_connections(self):
        for addr in connections_to_remove:
            if addr in self.connections:
                del self.connections[addr]
            if addr in self.accepted_connections:
                del self.accepted_connections[addr]
 
    def _handle_syn(self, packet: Packet, addr):
        if self.state != State.LISTEN:
            logger.info(f"Ignoring SYN from {addr} - not listening")
            return
        
        if self.accept_queue.qsize() >= self.accept_queue_size:
            logger.warning(f"Accept queue full, ignoring SYN from {addr}")
            return

        conn = Connection(self.udp_socket, self.src_addr, addr)
        conn.state = State.SYN_RCVD
        conn.ack_number = (packet.seq_number + 1) % MAX_SEQ_NUM
        conn.rsa = self.rsa
        conn.handshake_start = time.time()

        payload = self.rsa.serialize_public_key()

        conn._update_rwnd()

        # Send SYN-ACK
        syn_ack = Packet(
            source_port=self.src_addr[1],
            destination_port=addr[1],
            seq_number=conn.seq_number,
            ack_number=conn.ack_number,
            payload=payload,
            rwnd= conn.rwnd,
            SYN=True,
            ACK=True
        )

        serialized_syn_ack = syn_ack.serialize_packet()
        self.udp_socket.sendto(serialized_syn_ack, addr)

        conn.seq_number = (conn.seq_number + 1) % MAX_SEQ_NUM
        self.connections[addr] = conn

        logger.info(f"Sent SYN-ACK to {addr}")

    def _send_rst_to_addr(self, addr, invalid_packet: Packet = None):
        if invalid_packet:
            if invalid_packet.ACK:
                rst_seq = invalid_packet.ack_number
                rst_ack = 0
                rst_ack_flag = False
            else:
                rst_seq = 0
                rst_ack = (invalid_packet.seq_number + len(invalid_packet.payload)) % MAX_SEQ_NUM
                if invalid_packet.SYN:
                    rst_ack += 1
                if invalid_packet.FIN:
                    rst_ack += 1
                rst_ack_flag = True
        else:
            # Generic RST
            rst_seq = 0
            rst_ack = 0
            rst_ack_flag = False
        
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
        logger.warning(f"Sent RST to {addr}")

    def accept(self, timeout=60):
        if self.state != State.LISTEN:
            raise Exception("Socket not listening")

        start_time = time.time()
        while self.running and (time.time() - start_time < timeout):
            try:
                addr = self.accept_queue.get(timeout=0.1)
                conn = self.connections[addr]
                
                if not conn:
                    continue

                del self.connections[addr]
                self.accepted_connections[addr] = conn
                logger.info(f"Accepted connection from {addr}")
                return conn, addr
            except queue.Empty:
                continue

        if not self.running:
            raise Exception("Socket closed")
        
        raise Exception("Accept timrout")

    def connect(self, dest_addr):
        if self.state != State.CLOSED:
            raise Exception("Socket must be closed before connecting")
        
        if not self.src_addr:
            # Auto-bind to random port
            while True:
                try:
                    self.src_addr = ('', random.randint(1024, 65535))
                    self.udp_socket.bind(self.src_addr)
                    break
                except OSError as e:
                    continue

        conn = Connection(self.udp_socket, self.src_addr, dest_addr)
        conn.rsa = self.rsa
        conn._update_rwnd()

        # Send SYN
        syn = Packet(
            source_port=self.src_addr[1],
            destination_port=dest_addr[1],
            seq_number=conn.seq_number,
            ack_number=0,
            rwnd= conn.rwnd,
            payload=b'',
            SYN=True
        )

        counter = 0 
        is_ack_received = False
        conn.handshake_start = time.time()

        while not is_ack_received:
            serialized_syn = syn.serialize_packet()
            self.udp_socket.sendto(serialized_syn, dest_addr)
            conn.state = State.SYN_SENT

            logger.info(f"Sent SYN to {dest_addr}")

            # Wait for SYN-ACK
            start_time = time.time()
            while time.time() - start_time < 15:  # 15 second timeout
                try:
                    self.udp_socket.settimeout(0.1)
                    data, addr = self.udp_socket.recvfrom(BUFFER_SIZE)
                    packet = Packet.deserialize_packet(data)

                    if packet and packet.SYN and packet.ACK:
                        conn.process_packet(packet)
                        is_ack_received = True
                        break
                except socket.timeout:
                    continue
                except Exception as e:
                    raise Exception(f"Error during handshake: {e}")
            else:
                counter += 1
                if counter == 3:
                    raise Exception("Connection timeout")

        conn.dest_addr = addr
        self.connections[addr] = conn
        self.client_connection = conn

        # Start client receive thread
        self.running = True
        self.recv_thread = threading.Thread(target=self._client_thread, daemon=True)
        self.recv_thread.start()

        logger.info(f"Connected to {dest_addr}")

    def _client_thread(self):
        logger.info("Client receive thread started")

        while self.running:
            try:
                data, addr = self.udp_socket.recvfrom(BUFFER_SIZE)
                packet = Packet.deserialize_packet(data)

                if packet and addr == self.client_connection.dest_addr:
                    # Let the connection handle validation and RST
                    self.client_connection.process_packet(packet)
                elif packet:
                    # Unexpected packet from unknown source
                    logger.warning(f"Unexpected packet from {addr}")
                    self._send_rst_to_addr(addr, packet)

            except socket.timeout:
                continue
            except OSError as e:
                if e.errno == 10054:
                    logger.debug(f"Connection reset by peer - normal during close sequence")
                    break
                elif self.running:
                    logger.error(f"Error in client thread: {e}")
                    break
                else:
                    break
            except Exception as e:
                if self.running:
                    logger.error(f"Error in client thread: {e}")
                break

        logger.info("Client receive thread stopped")

    def send(self, data: bytes):
        if self.client_connection and self.client_connection.state == State.ESTABLISHED:
            self.client_connection.send(data)
        else:
            raise Exception("No established connection")

    def recv(self, size: int) -> bytes:
        if self.client_connection and self.client_connection.state == State.ESTABLISHED:
            return self.client_connection.recv(size)
        else:
            raise Exception("No established connection")

    def close(self):
        # Handle client connection
        if self.client_connection and self.client_connection.state == State.ESTABLISHED:
            self.client_connection.close()
            
            # Wait for graceful close to complete
            start_time = time.time()
            while (self.client_connection.state not in [State.CLOSED, State.TIME_WAIT] and 
                time.time() - start_time < 10):  # 10 second timeout
                time.sleep(0.1)
            
            self.running = False
            self.state = State.CLOSED
            self.udp_socket.close()
            logger.info("Client connection closed")
            return

        # Handle server closure
        if self.state == State.LISTEN:
            # Change state to prevent new connections
            self.state = State.CLOSED
            
            # Close all connections in accept queue (not yet accepted)
            pending_connections = list(self.accept_queue.queue)
            for addr in pending_connections:
                conn = self.connections[addr]
                conn.close()
                logger.info(f"Closed pending connection from {addr}")
            
            # Clear the accept queue
            while not self.accept_queue.empty():
                try:
                    self.accept_queue.get_nowait()
                except queue.Empty:
                    break
            
            logger.info("Server stopped accepting new connections, existing accepted connections remain active")
        
        elif self.state == State.CLOSED:
            logger.info("Socket already closed")
            return
        

   
  