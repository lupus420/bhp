import socket
import threading

bind_ip = "0.0.0.0"
bind_port = 9998

def main():
    # create a socket with IPv4 address using TCP 
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # define the ip and port on which server will listen
    server.bind((bind_ip, bind_port))
    # max calls in queue set to 5
    server.listen(5)
    print(f'[*] Start listening on {bind_ip}:{bind_port}')

    # Wait for request calls - loop
    while True:
        # When the connection with client is established
        # save the client socket and its address 
        client, address = server.accept()
        print(f'[*] Received call from {address[0]}:{address[1]}')
        # Create a new Thread object which points to function handle_client
        # and as a argument is passed the client socket
        client_handler = threading.Thread(target=handle_client, args=(client,))
        # start thread which drive the connection with client
        client_handler.start()

def handle_client(client_socket):
    with client_socket as sock:
        request = sock.recv(1024)
        print(f'[*] Received: {request.decode("utf-8")}')
        sock.send(b'ACKKK')

if __name__ == '__main__':
    main()