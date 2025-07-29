import socket
import re
from datetime import datetime

# --- Configuration ---
HOST = '0.0.0.0'  # Listen on all available network interfaces
PORT = 5060       # Standard SIP port
# --- End Configuration ---

# A simple dictionary to store registered users and their locations (IP:Port)
# Format: { 'user': 'ip:port' }
user_locations = {}

def parse_sip_message(data):
    """Parses the essential information from a SIP message."""
    message = data.decode('utf-8', 'ignore') # Use 'ignore' to prevent errors on weird characters
    
    # Use regular expressions to find key headers
    from_header = re.search(r'From:.*<sip:([^@]+)@.*>', message, re.IGNORECASE)
    to_header = re.search(r'To:.*<sip:([^@]+)@.*>', message, re.IGNORECASE)
    
    # --- THIS IS THE CORRECTED LINE ---
    # The new regex ([^;>]+) captures characters until it hits a semicolon (;) or a >
    # This correctly strips parameters like ';ob' from the Contact URI.
    contact_header = re.search(r'Contact:.*<sip:.*@([^;>]+)', message, re.IGNORECASE)
    
    cseq_header = re.search(r'CSeq: \d+ (\w+)', message, re.IGNORECASE)
    request_line_match = re.match(r'(\w+) sip:.*', message)
    
    method = cseq_header.group(1) if cseq_header else None
    if not method and request_line_match:
        method = request_line_match.group(1)

    from_user = from_header.group(1) if from_header else None
    to_user = to_header.group(1) if to_header else None
    contact_address = contact_header.group(1) if contact_header else None
    
    return {
        "method": method,
        "from_user": from_user,
        "to_user": to_user,
        "contact_address": contact_address,
        "message": message
    }

def main():
    """Main function to run the SIP server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        sock.bind((HOST, PORT))
        try:
            # Try to get the primary local IP to display for convenience
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except OSError:
            local_ip = '127.0.0.1'
        print(f"[*] SIP Server listening on {local_ip}:{PORT} (and all other interfaces)")
    except OSError as e:
        print(f"[!] Error binding to port {PORT}: {e}")
        print("[!] Is another SIP server (or application) already running on this port?")
        return

    while True:
        try:
            # Wait for a message
            data, addr = sock.recvfrom(4096)
            
            sip_info = parse_sip_message(data)
            method = sip_info.get("method")
            
            print(f"\n--- {datetime.now()} ---")
            print(f"[*] Received {method or 'response'} from {addr}")
            
            if method == 'REGISTER':
                user = sip_info.get("from_user")
                contact = sip_info.get("contact_address")
                
                user_address = contact if contact else f"{addr[0]}:{addr[1]}"

                if user:
                    user_locations[user] = user_address
                    print(f"[*] Registered user '{user}' at '{user_locations[user]}'")
                    
                    # Construct and send a 200 OK response
                    # A proper response requires copying several headers from the request
                    response_lines = [f"SIP/2.0 200 OK"]
                    for line in sip_info["message"].splitlines():
                        if line.lower().startswith(("via:", "from:", "to:", "call-id:", "cseq:")):
                            response_lines.append(line)
                    response_lines.append(f"Contact: <sip:{user}@{user_address}>")
                    response_lines.append("Content-Length: 0")
                    response_lines.append("\r\n") # End of headers
                    
                    sock.sendto("\r\n".join(response_lines).encode('utf-8'), addr)

            elif method in ['INVITE', 'ACK', 'BYE', 'CANCEL', 'OPTIONS', 'UPDATE']:
                to_user = sip_info.get("to_user")
                
                if to_user and to_user in user_locations:
                    destination_address_str = user_locations[to_user]
                    dest_ip, dest_port = destination_address_str.split(':')
                    destination_address = (dest_ip, int(dest_port))
                    
                    print(f"[*] Proxying {method} from '{sip_info.get('from_user')}' to '{to_user}' at {destination_address}")
                    sock.sendto(data, destination_address)
                else:
                    print(f"[!] User '{to_user}' not found or not registered.")
                    # In a real server, you would send a 404 Not Found response
            
            # Also proxy responses (like 180 Ringing, 200 OK) back to the caller
            elif sip_info["message"].startswith("SIP/2.0"):
                from_user = sip_info.get("from_user")
                if from_user and from_user in user_locations:
                    destination_address_str = user_locations[from_user]
                    dest_ip, dest_port = destination_address_str.split(':')
                    destination_address = (dest_ip, int(dest_port))
                    
                    print(f"[*] Proxying response to '{from_user}' at {destination_address}")
                    sock.sendto(data, destination_address)

        except Exception as e:
            print(f"[!] An error occurred: {e}")

if __name__ == '__main__':
    main()