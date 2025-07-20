# TCP-over-UDP

## Description
An educational prototype demonstrating core TCP features using UDP sockets in Python. The goal was to understand the principles of the TCP protocol, including reliable data transfer, connection management, handling out-of-order data, ACK management, and termination management.

## TCP Features 
1. TCP 3-Way Handshake Implementation
Simulates the standard SYN, SYN-ACK, and ACK sequence for connection establishment.

2. Reliable Data Transfer
Ensures in-order delivery using acknowledgments and retransmission; handles out-of-order packets.

3. Graceful and Abrupt Connection Termination
Supports connection teardown using FIN and RST flags.

4. Concurrent Client Handling
The server can manage multiple client connections simultaneously.

5. End-to-End Encryption with RSA
Secures data transmission using RSA-based asymmetric encryption.

6. Flow Control
Regulates data flow between sender and receiver to prevent buffer overflow.

7. Congestion Control
Adjusts sending rate based on network conditions to minimize packet loss and congestion.

8. Dynamic Timeout Calculation
Calculates retransmission timeouts based on estimated round-trip time (RTT).

9. Sequence Number Wrapping
Correctly handles sequence number overflow using modulo arithmetic.

## Installation
1. Download or clone the repository.
2. Install or upgrade to Python 3.
3. Install the required cryptographic library.
   ```bash
   pip3 install pycryptodome
   ```
4. Run the server or client.
   
   



