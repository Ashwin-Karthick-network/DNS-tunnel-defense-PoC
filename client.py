import socket
import binascii

# The public DNS server (Google) that forwards our packets
dns_server = "8.8.8.8"
# My domain that points to my AWS server
target_domain = "tunnel.karthicknetwork.in"

print("--- DNS Tunnel Client ---")
print("Enter your message to send it secretly via DNS.")

while True:
    message = input("Your Secret Message: ")
    
    # Step 1: Convert message to Hex so it fits in a URL
    # We use hex because DNS doesn't allow spaces or symbols
    hex_data = binascii.hexlify(message.encode()).decode()
    
    # Step 2: Create the fake domain name
    # Example: 68656c6c6f.tunnel.karthicknetwork.in
    full_domain = hex_data + "." + target_domain
    
    # Step 3: Build the DNS packet manually
    # (This part creates a standard DNS query packet)
    transaction_id = b'\xaa\xaa' 
    flags = b'\x01\x00' 
    questions = b'\x00\x01' 
    answers = b'\x00\x00' 
    authority = b'\x00\x00' 
    additional = b'\x00\x00'
    
    header = transaction_id + flags + questions + answers + authority + additional
    
    # Convert domain parts to bytes
    domain_bytes = b''
    for part in full_domain.split('.'):
        domain_bytes += bytes([len(part)]) + part.encode()
    domain_bytes += b'\x00' # End of domain
    
    # Type A (Host Address) and Class IN (Internet)
    footer = b'\x00\x01\x00\x01'
    
    packet = header + domain_bytes + footer
    
    # Step 4: Send via UDP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(packet, (dns_server, 53))
        print(f"[+] Message sent to Google: {full_domain}")
    except:
        print("[-] Error sending packet.")
