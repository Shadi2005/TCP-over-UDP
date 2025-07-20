import base64
import json

class Packet:
    def __init__(self, source_port, destination_port, seq_number, ack_number, rwnd, payload: bytes, 
                 SYN=False, ACK=False, FIN=False, RST=False):
        self.source_port = source_port
        self.destination_port = destination_port
        self.seq_number = seq_number
        self.ack_number = ack_number
        self.rwnd = rwnd
        self.SYN = SYN
        self.ACK = ACK
        self.FIN = FIN
        self.RST = RST
        self.payload_length = len(payload)
        self.payload = payload

    def get_packet_type(self):
        if (self.RST and not self.SYN and not self.FIN):
            return "RST"
        
        if (self.SYN and self.ACK and not self.RST and not self.FIN):
            return "SYN-ACK"
        
        if (self.SYN and not self.ACK and not self.RST and not self.FIN):
            return "SYN"
        
        if (self.FIN and self.ACK and not self.RST and not self.SYN):
            return "FIN-ACK"
        
        if (self.FIN and not self.RST and not self.SYN):
            return "FIN"
        
        if (self.ACK and not self.FIN and not self.RST and not self.SYN):
            return "ACK"
        
        return "UNKNOWN"

    def serialize_packet(self) -> bytes:
        obj = {
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'seq_number': self.seq_number,
            'ack_number': self.ack_number,
            'rwnd': self.rwnd,
            'payload': base64.b64encode(self.payload).decode('utf-8'),
            'payload_length': self.payload_length,
            'SYN': self.SYN,
            'ACK': self.ACK,
            'FIN': self.FIN,
            'RST': self.RST
        }
        return json.dumps(obj).encode('utf-8')

    @staticmethod
    def deserialize_packet(data: bytes):
        try:
            obj = json.loads(data.decode('utf-8'))
            payload_bytes = base64.b64decode(obj['payload'])
            
            return Packet(
                source_port=obj['source_port'],
                destination_port=obj['destination_port'],
                seq_number=obj['seq_number'],
                ack_number=obj['ack_number'],
                rwnd=obj['rwnd'],
                payload=payload_bytes,
                SYN=obj.get('SYN', False),
                ACK=obj.get('ACK', False),
                FIN=obj.get('FIN', False),
                RST=obj.get('RST', False)
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            return None