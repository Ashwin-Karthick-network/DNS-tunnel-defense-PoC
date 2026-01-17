import socket
import binascii
import math
import time
from scapy.all import DNS, DNSQR

ip = "0.0.0.0"
port = 53

# Patterns to block
bad_words = ["union select", "cat ", "/etc/passwd", "whoami"]
history = {}

# Calculate Entropy (Randomness)
# High entropy = Encrypted data (Tunnel)
# Low entropy = Normal words (Google)
def get_entropy(text):
    if not text: return 0
    count = {}
    for char in text:
        if char in count:
            count[char] += 1
        else:
            count[char] = 1
            
    entropy = 0
    length = len(text)
    for char in count:
        p = count[char] / length
        entropy = entropy - (p * math.log(p, 2))
    return entropy

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.bind((ip, port))
    print("Firewall Active. Monitoring DNS traffic...")
except:
    print("Error: Port busy.")
    exit()

while True:
    try:
        data, addr = s.recvfrom(512)
        p = DNS(data)
        
        if p.haslayer(DNSQR):
            query = p[DNSQR].qname.decode('utf-8').rstrip('.')
            
            if "ip-172" in query: continue
            
            payload = query.split('.')[0]
            
            # Anti-spam
            check = payload.lower()
            if check in history and time.time() - history[check] < 5:
                continue
            history[check] = time.time()
            
            # Decoding
            decoded = payload
            is_hex = False
            try:
                decoded = binascii.unhexlify(payload).decode('utf-8')
                is_hex = True
            except: pass
            
            # 1. Signature Check (Blacklist)
            blocked = False
            for word in bad_words:
                if word in decoded:
                    print(f"🛑 [BLOCK] Attack Detected: {decoded}")
                    blocked = True
                    break
            
            if blocked: continue

            # 2. Anomaly Check (Entropy)
            score = get_entropy(payload)
            
            if score > 3.5 or is_hex:
                print(f"⚠️  [WARN] Tunnel Detected from {addr[0]}")
                print(f"    Payload: {decoded}")
                print(f"    Entropy: {score:.2f}")
            else:
                print(f"✅ [ALLOW] Normal: {query}")

    except KeyboardInterrupt: break
    except: pass
