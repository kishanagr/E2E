# Server.py
import socket
import threading 
import time
import sys 

# --- Configuration ---
HOST_IP = socket.gethostbyname(socket.gethostname()) # Get host IP address
HOST_PORT = 42000  # Fixed port as per instructions
MAX_CLIENTS = 2    # Server handles two clients for a peer-to-peer chat

# --- Global Variables ---
clients_lock = threading.Lock() # Lock for synchronizing access to client_data
client_data = {} # Stores {'conn': conn_obj, 'addr': address, 'name': name, 'public_key': (e, n)} for each client
client_connections = [] # List of active client connection objects

def broadcast_message(message, sender_conn=None):
    """
    Sends a message to all connected clients except the sender.
    If sender_conn is None, sends to all.
    """
    with clients_lock:
        for client_conn in client_connections:
            if client_conn != sender_conn:
                try:
                    client_conn.sendall(message.encode('utf-8'))
                except socket.error as e:
                    print(f"[SERVER] Error broadcasting to a client: {e}")
                    # Potentially remove problematic client here if needed
                    pass # Keep it simple for now

def handle_client(conn, addr):
    """
    Handles an individual client connection.
    Manages registration, public key exchange, and message relay.
    """
    print(f"[SERVER] New connection from {addr}")
    client_id = None # To store the connection object as a key in client_data
    client_name = "Unknown" # Default name until registration

    try:
        # 1. Registration: Client sends "REG::{name}::{e},{n}"
        reg_data = conn.recv(2048).decode('utf-8')
        if not reg_data or not reg_data.startswith("REG::"):
            print(f"[SERVER] Invalid registration from {addr}. Closing connection.")
            conn.close()
            return

        parts = reg_data.split("::", 2)
        client_name = parts[1]
        pub_key_str = parts[2]
        try:
            e_str, n_str = pub_key_str.split(',')
            public_key = (int(e_str), int(n_str))
        except ValueError:
            print(f"[SERVER] Invalid public key format from {client_name}@{addr}. Closing connection.")
            conn.close()
            return

        with clients_lock:
            if len(client_connections) >= MAX_CLIENTS:
                print(f"[SERVER] Max clients reached. Rejecting {client_name}@{addr}")
                conn.sendall("ERR::Server is full.".encode('utf-8'))
                conn.close()
                return
            
            client_id = conn # Use connection object as a unique ID
            client_data[client_id] = {
                'conn': conn,
                'addr': addr,
                'name': client_name,
                'public_key': public_key
            }
            client_connections.append(conn)
            print(f"[SERVER] Client '{client_name}' from {addr} registered with public key {public_key}.")
            conn.sendall(f"ACK::Welcome, {client_name}! Waiting for other client...".encode('utf-8'))

            # If two clients are now connected, exchange their public keys
            if len(client_connections) == MAX_CLIENTS:
                print("[SERVER] Two clients connected. Exchanging public keys...")
                
                client1_conn = client_connections[0]
                client2_conn = client_connections[1]

                client1_info = client_data[client1_conn]
                client2_info = client_data[client2_conn]

                # Send client2's key to client1
                key_msg_for_client1 = f"KEY::{client2_info['name']}::{client2_info['public_key'][0]},{client2_info['public_key'][1]}"
                client1_conn.sendall(key_msg_for_client1.encode('utf-8'))
                print(f"[SERVER] Sent {client2_info['name']}'s public key to {client1_info['name']}.")

                # Send client1's key to client2
                key_msg_for_client2 = f"KEY::{client1_info['name']}::{client1_info['public_key'][0]},{client1_info['public_key'][1]}"
                client2_conn.sendall(key_msg_for_client2.encode('utf-8'))
                print(f"[SERVER] Sent {client1_info['name']}'s public key to {client2_info['name']}.")
                
                print("[SERVER] Public key exchange complete. Chat can begin.")
                # Notify clients they can start chatting
                client1_conn.sendall("INFO::Key exchange complete. You can start chatting.".encode('utf-8'))
                client2_conn.sendall("INFO::Key exchange complete. You can start chatting.".encode('utf-8'))


        # 2. Message Relaying Loop
        # The client now sends MSG::base64_encoded_payload
        while True:
            message = conn.recv(8192).decode('utf-8') # Increased buffer for Base64 encoded messages
            if not message:
                print(f"[SERVER] Client '{client_name}' from {addr} disconnected (empty message).")
                break # Connection closed by client

            if message.startswith("MSG::"):
                # The encrypted_content is now the Base64 string
                encrypted_content = message.split("::", 1)[1] 
                print(f"[SERVER] Received Base64 Encrypted message from '{client_name}': {encrypted_content[:80]}...") # Log snippet

                # Relay to the other client
                with clients_lock:
                    # Find the other client
                    other_client_conn = None
                    for c_id, c_info in client_data.items():
                        if c_info['conn'] != conn:
                            other_client_conn = c_info['conn']
                            break
                    
                    if other_client_conn:
                        try:
                            # The relayed message is RELAY::sender_name::base64_payload
                            relay_msg = f"RELAY::{client_name}::{encrypted_content}"
                            other_client_conn.sendall(relay_msg.encode('utf-8'))
                            print(f"[SERVER] Relayed message from '{client_name}' to '{client_data[other_client_conn]['name']}'.")
                        except socket.error as e:
                            print(f"[SERVER] Error relaying message: {e}")
                            # Handle potential disconnection of the other client
                            # For simplicity, we'll let the other client's handler manage its own disconnection
                    else:
                        print(f"[SERVER] No other client to relay message to from '{client_name}'.")
            else:
                print(f"[SERVER] Received unknown message format from '{client_name}': {message}")


    except socket.error as e:
        print(f"[SERVER] Socket error with client '{client_name}' from {addr}: {e}")
    except Exception as e:
        print(f"[SERVER] Unexpected error with client '{client_name}' from {addr}: {e}")
    finally:
        with clients_lock:
            if client_id and client_id in client_data:
                disconnected_client_name = client_data[client_id]['name']
                print(f"[SERVER] Client '{disconnected_client_name}' from {addr} has disconnected.")
                if conn in client_connections:
                    client_connections.remove(conn)
                
                # Notify the other client about the disconnection
                # This needs to be robust: find the other client if it exists
                other_client_to_notify = None
                if client_id in client_data: # Check if client_id was not already deleted by another thread
                    del client_data[client_id] # Remove the disconnected client

                # Find the remaining client to notify
                if len(client_connections) == 1:
                    other_client_to_notify = client_connections[0]
                
                if other_client_to_notify:
                    try:
                        other_client_to_notify.sendall(f"INFO::{disconnected_client_name} has disconnected. Chat ended.".encode('utf-8'))
                    except socket.error as notify_error:
                        print(f"[SERVER] Error notifying other client about disconnection: {notify_error}")
            else:
                 print(f"[SERVER] Connection from {addr} closed (was not fully registered or already removed).")

            if conn:
                try:
                    conn.close()
                except socket.error:
                    pass # Already closed
            
            if len(client_connections) < MAX_CLIENTS and len(client_connections) > 0: # One client left
                print("[SERVER] A client disconnected. Waiting for one more client to form a pair.")
            elif len(client_connections) == 0: # No clients left
                 print("[SERVER] All clients disconnected. Waiting for new connections.")


def start_server():
    """Initializes and starts the socket server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reusing address

    try:
        server_socket.bind((HOST_IP, HOST_PORT))
    except socket.error as e:
        print(f"[SERVER] Failed to bind server to {HOST_IP}:{HOST_PORT}. Error: {e}")
        print("[SERVER] Ensure the IP is correct and the port is not in use.")
        print(f"[SERVER] If {HOST_IP} is 0.0.0.0, it means listening on all available interfaces.")
        print(f"[SERVER] If {HOST_IP} is a specific local IP, ensure it's the one clients should use on the LAN.")
        sys.exit(1)

    server_socket.listen(MAX_CLIENTS + 2) # Listen for a bit more than MAX_CLIENTS to handle rapid connections
    print(f"[SERVER] Server started on IP: {HOST_IP}, Port: {HOST_PORT}")
    print(f"[SERVER] Waiting for {MAX_CLIENTS} clients to connect...")

    try:
        while True: 
            conn = None # Initialize conn to None
            try:
                if len(client_connections) < MAX_CLIENTS:
                    conn, addr = server_socket.accept()
                    # Start a new thread for each client
                    thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                    thread.start()
                else:
                    # Server is "full" with an active pair.
                    # Briefly accept and reject to avoid backlog, or just sleep.
                    # For simplicity, we'll just sleep, relying on handle_client to reject.
                    time.sleep(0.1) 
            except socket.error as accept_err:
                print(f"[SERVER] Error accepting connection: {accept_err}")
                if conn: conn.close() # Ensure connection is closed if accept succeeded but thread failed
            except Exception as e_thread:
                print(f"[SERVER] Error starting client thread: {e_thread}")
                if conn: conn.close()


    except KeyboardInterrupt:
        print("[SERVER] Server shutting down by KeyboardInterrupt...")
    except Exception as e:
        print(f"[SERVER] An unexpected error occurred in server's main loop: {e}")
    finally:
        print("[SERVER] Closing all client connections...")
        with clients_lock:
            active_conns_copy = list(client_connections) # Iterate over a copy
            for c_conn in active_conns_copy:
                try:
                    c_conn.sendall("INFO::Server is shutting down.".encode('utf-8'))
                    c_conn.close()
                except socket.error:
                    pass 
            client_connections.clear()
            client_data.clear()
        if hasattr(server_socket, 'close'): # Check if server_socket exists and has close method
            server_socket.close()
        print("[SERVER] Server shutdown complete.")

if __name__ == "__main__":
    start_server()

  
