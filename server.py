from lib.socket import Socket
import time

# Create and bind server socket
server = Socket()
server.bind(("127.0.0.1", 9000))
server.listen()

print("Server listening on port 9000...")

# Accept connection
conn, addr = server.accept()
print(f"Accepted connection from {addr}")

# Receive data in chunks, displaying cumulative ACK behavior
total_received = b""
while True:
    time.sleep(3)
    data = conn.recv(250, timeout=10)
    if not data:
        break
    print(f"Server received: {data}")
    total_received += data

print(f"Total data received: {total_received}")
print(f"[Length: {len(total_received)}]")
time.sleep(2)
conn.close()
server.close()
