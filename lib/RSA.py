from Crypto.Util import number
import json
import base64
import struct

class RSA:
    def __init__(self, bits=1024):
        self.bits = bits

        # Keys 
        self.public_key = None
        self.private_key = None
        self.remote_public_key = None 

        self.generate_keys() 

    def egcd(self, a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def modinv(self, a, m):
        g, x, y = self.egcd(a, m)
        if g != 1:
            raise Exception('Modular inverse does not exist')
        else:
            return x % m

    def generate_keys(self):
        p = number.getPrime(self.bits // 2)
        q = number.getPrime(self.bits // 2)

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537  # standard choice

        d = self.modinv(e, phi)

        self.public_key = (e, n)
        self.private_key = (d, n)

    def encrypt(self, message_bytes):
        if self.remote_public_key is None:
            raise Exception("Remote public key not set")
        
        e, n = self.remote_public_key
        max_message_length = (n.bit_length() - 1) // 8
        
        if len(message_bytes) > max_message_length:
            raise Exception(f"Message too large for RSA encryption. Max length: {max_message_length}, got: {len(message_bytes)}")
        
        if len(message_bytes) == 0:
            message_bytes = b'\x00'
        elif message_bytes[0] == 0:
            message_bytes = b'\x01' + message_bytes
        
        m = int.from_bytes(message_bytes, byteorder='big')
        c = pow(m, e, n)
        
        byte_length = (n.bit_length() + 7) // 8
        return c.to_bytes(byte_length, byteorder='big')

    def decrypt(self, ciphertext_bytes):
        d, n = self.private_key
        
        c = int.from_bytes(ciphertext_bytes, byteorder='big')
        m = pow(c, d, n)
        
        if m == 0:
            return b'\x00'
        
        byte_length = (m.bit_length() + 7) // 8
        message_bytes = m.to_bytes(byte_length, byteorder='big')
        
        if len(message_bytes) > 1 and message_bytes[0] == 1:
            message_bytes = message_bytes[1:]
        
        return message_bytes
    
    def serialize_public_key(self) -> bytes:
        obj = {
            'e': self.public_key[0],
            'n': self.public_key[1]
        }
        return json.dumps(obj).encode('utf-8')

    @staticmethod
    def deserialize_public_key(data: bytes):
        try:
            obj = json.loads(data.decode('utf-8'))
            
            return (
                obj['e'],
                obj['n']
            )
        
        except (json.JSONDecodeError, KeyError, ValueError):
            return None
        
    