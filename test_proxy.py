import socket
import threading

# proxyTCP.py

def main():
    # Configuration
    LISTEN_IP = "127.0.0.2"
    LISTEN_PORT = 8080
    DESTINATION_IP = "ftp.sun.ac.za"
    DESTINATION_PORT = 21
    
    start_proxy(LISTEN_IP, LISTEN_PORT, DESTINATION_IP, DESTINATION_PORT)

def start_proxy(listen_ip, listen_port, destination_ip, destination_port):
    # Set up the proxy server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((listen_ip, listen_port))
    server.listen(5)
    print(f"[*] Listening on {listen_ip}:{listen_port}")
    
    while True:
        client_socket, addr = server.accept()
        print(f"[*] Received incoming connection from {addr}")
        
        # Start a new thread to handle the client
        client_thread = threading.Thread(target=handle_client,
                                         args=(client_socket,
                                               destination_ip,
                                               destination_port))
        client_thread.start()

def handle_client(client_socket, destination_ip, destination_port):
    # Connect to the destination server
    dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest_socket.connect((destination_ip, destination_port))
    
    # Start threads to forward data between client and destination
    client_to_dest = threading.Thread(target=forward_data, args=(client_socket, dest_socket))
    dest_to_client = threading.Thread(target=forward_data, args=(dest_socket, client_socket))
    
    client_to_dest.start()
    dest_to_client.start()

    client_to_dest.join()
    dest_to_client.join()

    client_socket.close()
    dest_socket.close()

def forward_data(source_socket, destination_socket):
    while True:
        data = receive_data(source_socket)
        if not data:
            break
        send_data(destination_socket, data)

def receive_data(socket):
    try:
        return socket.recv(4096)
    except:
        return None

def send_data(socket, data):
    try:
        socket.send(data)
    except:
        pass

if __name__ == "__main__":
    main()
