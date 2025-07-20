from lib.socket import Socket
import time

client = Socket()

# Connect to server
client.connect(("127.0.0.1", 9000))
print("Client connected to server.")

# Send a message large enough to force segmentation
msg = b"A" * 1000  # ~3-4 segments given MSS=1460

print(f"Client sending {len(msg)} bytes")
client.send(msg)

# Wait to allow packet processing and ACK display
time.sleep(5)

client.close()
print("Client closed.")
