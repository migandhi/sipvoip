import socket
import re
import threading
import time
import requests

# --- Configuration ---
HOST = '0.0.0.0'  # Listen on all available network interfaces
SIP_PORT = 5060   # The standard port for SIP signaling
RTP_PORT_START = 16384 # Start of the RTP port range (even numbers)
# --- End Configuration ---

# --- Global State ---
SERVER_PUBLIC_IP = '' # Will be fetched automatically at startup
user_locations = {}   # Maps user -> signaling address ('ip:port')
active_calls = {}     # Maps Call-ID -> call details
next_rtp_port = RTP_PORT_START
# --- End Global State ---


def get_public_ip():
    """Fetches the server's public IP address using an external service."""
    try:
        ip = requests.get('https://api.ipify.org', timeout=5).text
        print(f"[*] Successfully fetched public IP: {ip}")
        return ip
    except Exception as e:
        print(f"[!] FATAL: Could not fetch public IP address: {e}")
        return None

def parse_header(message, header_name):
    """A simple regex-based parser for a specific SIP header."""
    try:
        # Search for the header, case-insensitive, across multiple lines
        match = re.search(rf'^{header_name}: (.*)$', message, re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).strip()
    except Exception:
        pass
    return None

def rtp_relay_thread(sock_a, sock_b, initial_addr_a, initial_addr_b):
    """
    A thread that relays RTP packets between two endpoints.
    It learns the client's real RTP port from the first packet received.
    """
    addr_a, addr_b = initial_addr_a, initial_addr_b
    known_addrs = {initial_addr_a, initial_addr_b}
    
    # Learn the real addresses from the first packets
    try:
        data_a, learned_addr_a = sock_a.recvfrom(2048)
        addr_a = learned_addr_a
        print(f"[*] Learned address A: {addr_a}")

        data_b, learned_addr_b = sock_b.recvfrom(2048)
        addr_b = learned_addr_b
        print(f"[*] Learned address B: {addr_b}")

        # Start relaying the first packets immediately
        sock_b.sendto(data_a, addr_b)
        sock_a.sendto(data_b, addr_a)
    except socket.timeout:
        print("[!] Timed out waiting for initial RTP packets. Closing relay.")
        return
    except Exception as e:
        print(f"[!] Error during initial packet learning: {e}")
        return

    # Create relay loops
    def relay_loop(source_sock, dest_sock, dest_addr):
        while True:
            try:
                data, _ = source_sock.recvfrom(2048)
                dest_sock.sendto(data, dest_addr)
            except Exception:
                break # Socket closed or error
        print(f"[*] Relay to {dest_addr} stopped.")

    print(f"[*] Starting bidirectional RTP relay: {addr_a} <--> {addr_b}")
    threading.Thread(target=relay_loop, args=(sock_a, sock_b, addr_b), daemon=True).start()
    threading.Thread(target=relay_loop, args=(sock_b, sock_a, addr_a), daemon=True).start()


def handle_sip_packet(data, addr, sip_socket):
    """The main logic for processing a single SIP packet."""
    global next_rtp_port
    message = data.decode('utf-8', 'ignore')
    request_line = message.splitlines()[0]
    method = request_line.split(' ')[0]

    # --- HANDLE REGISTRATION ---
    if method == "REGISTER":
        from_user = re.search(r'From:.*<sip:([^@]+)', message).group(1)
        contact_uri = re.search(r'Contact:.*<sip:.*@([^;>]+)', message).group(1)
        user_locations[from_user] = {'addr': addr, 'contact_uri': contact_uri}
        print(f"[*] Registered '{from_user}' at {addr}")
        # Respond with a simple 200 OK by echoing the request back
        # A real server would construct a proper response
        sip_socket.sendto(data, addr)

    # --- HANDLE NEW CALL INVITATION ---
    elif method == "INVITE":
        call_id = parse_header(message, "Call-ID")
        from_user = re.search(r'From:.*<sip:([^@]+)', message).group(1)
        to_user = re.search(r'To:.*<sip:([^@]+)', message).group(1)
        print(f"\n--- INVITE received for Call-ID: {call_id} ---")
        print(f"[*] Call from '{from_user}' to '{to_user}'")

        if to_user not in user_locations:
            print(f"[!] Callee '{to_user}' is not registered. Ignoring call.")
            # In a real server, send a 404 Not Found response
            return
        
        # --- SDP Modification ---
        # Allocate two ports on the server for the two legs of the audio relay
        caller_relay_port = next_rtp_port
        callee_relay_port = next_rtp_port + 2 # RTP uses even numbers, RTCP odd
        next_rtp_port += 4
        
        # Modify the SDP to tell the callee to send audio to OUR server
        modified_sdp = re.sub(r'c=IN IP4 .*\r\n', f'c=IN IP4 {SERVER_PUBLIC_IP}\r\n', message)
        modified_sdp = re.sub(r'm=audio \d+ ', f'm=audio {callee_relay_port} ', modified_sdp)
        print(f"[*] Modified SDP. Will ask callee to send audio to port {callee_relay_port}")

        active_calls[call_id] = {
            'caller': {'user': from_user, 'addr': addr, 'rtp_port': caller_relay_port},
            'callee': {'user': to_user, 'addr': user_locations[to_user]['addr'], 'rtp_port': callee_relay_port}
        }
        
        # Forward the modified INVITE to the callee
        callee_addr = user_locations[to_user]['addr']
        sip_socket.sendto(modified_sdp.encode(), callee_addr)
        print(f"[*] Forwarding modified INVITE to {to_user} at {callee_addr}")

    # --- HANDLE CALL ACCEPTANCE ---
    elif "SIP/2.0 200 OK" in request_line and parse_header(message, "CSeq").endswith("INVITE"):
        call_id = parse_header(message, "Call-ID")
        print(f"\n--- 200 OK received for Call-ID: {call_id} ---")

        if call_id not in active_calls:
            return

        call_info = active_calls[call_id]

        # --- SDP Modification for the Caller ---
        # Modify the SDP in the OK to tell the ORIGINAL caller to send audio to our server
        modified_ok = re.sub(r'c=IN IP4 .*\r\n', f'c=IN IP4 {SERVER_PUBLIC_IP}\r\n', message)
        modified_ok = re.sub(r'm=audio \d+ ', f'm=audio {call_info["caller"]["rtp_port"]} ', modified_ok)
        print(f"[*] Modified 200 OK. Will ask caller to send audio to port {call_info['caller']['rtp_port']}")
        
        # Forward the modified OK back to the original caller
        caller_addr = call_info['caller']['addr']
        sip_socket.sendto(modified_ok.encode(), caller_addr)
        print(f"[*] Forwarding modified 200 OK to original caller.")

        # --- START THE RTP RELAY ---
        try:
            print("[*] Preparing to start RTP relay...")
            sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_a.bind((HOST, call_info['caller']['rtp_port']))
            sock_a.settimeout(5.0) # 5 second timeout to receive first packet

            sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_b.bind((HOST, call_info['callee']['rtp_port']))
            sock_b.settimeout(5.0)

            # Store sockets for later cleanup
            call_info['sockets'] = [sock_a, sock_b]

            # Start the relay in a new thread
            threading.Thread(
                target=rtp_relay_thread,
                args=(sock_a, sock_b, call_info['caller']['addr'], call_info['callee']['addr']),
                daemon=True
            ).start()
        except Exception as e:
            print(f"[!!!] FATAL ERROR starting RTP relay: {e}")

    # --- HANDLE HANGUP ---
    elif method == "BYE":
        call_id = parse_header(message, "Call-ID")
        print(f"\n--- BYE received for Call-ID: {call_id} ---")
        
        if call_id in active_calls:
            call_info = active_calls[call_id]
            
            # Determine who sent the BYE and forward it to the other party
            if addr == call_info['caller']['addr']:
                print(f"[*] Caller hung up. Forwarding BYE to callee.")
                sip_socket.sendto(data, call_info['callee']['addr'])
            else:
                print(f"[*] Callee hung up. Forwarding BYE to caller.")
                sip_socket.sendto(data, call_info['caller']['addr'])

            # Clean up the call resources
            if 'sockets' in call_info:
                for sock in call_info['sockets']:
                    sock.close()
                print("[*] Relay sockets closed.")
            del active_calls[call_id]
            print("[*] Call information cleaned up.")

    # --- HANDLE OTHER MESSAGES (e.g., ACK) ---
    else:
        # Simple proxying for other messages like ACK
        if call_id := parse_header(message, "Call-ID"):
            if call_id in active_calls:
                call_info = active_calls[call_id]
                if addr == call_info['caller']['addr']:
                    sip_socket.sendto(data, call_info['callee']['addr'])
                else:
                    sip_socket.sendto(data, call_info['caller']['addr'])


def main():
    """Main server function."""
    global SERVER_PUBLIC_IP
    SERVER_PUBLIC_IP = get_public_ip()
    if not SERVER_PUBLIC_IP:
        return

    sip_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sip_socket.bind((HOST, SIP_PORT))
    print(f"[*] SIP and Audio Relay Server listening on {HOST}:{SIP_PORT}")
    
    while True:
        try:
            data, addr = sip_socket.recvfrom(4096)
            # Handle each packet in a new thread to avoid blocking the main loop
            threading.Thread(target=handle_sip_packet, args=(data, addr, sip_socket)).start()
        except Exception as e:
            print(f"[!] Error in main loop: {e}")

if __name__ == "__main__":
    main()