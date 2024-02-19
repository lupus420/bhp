import socket

def main():
    SERVER_IP = "127.0.0.2"
    SERVER_PORT = 8080

    # create a TCP IPv4 socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect to the server
    client_socket.connect((SERVER_IP, SERVER_PORT))
    print(f"[*] Connected to {SERVER_IP}:{SERVER_PORT}")
    
    try:
        while True:
            request = input("Input request below:\n")
            request += '\r\n'
            client_socket.sendall(request.encode())
            response = client_socket.recv(4096)
            print(f"[*] Response: {response.decode()}")

    except KeyboardInterrupt:
        print("\n[*] Exiting client...")
        
    finally:
        client_socket.close()


if __name__ == "__main__":
    main()