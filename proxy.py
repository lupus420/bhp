import sys
import socket
import threading
import signal

HEX_FILTER = ''.join(
### Make all ASCII character representation
# '................................ 
# !"#$%&\'()*+,-./0123456789:;<=>?@
# ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`
# abcdefghijklmnopqrstuvwxyz{|}~...
# ...............................
# ¡¢£¤¥¦§¨©ª«¬.®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂ
# ÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãä
# åæçèéêëìíîïðñòóôõö÷øùúûüýþÿ'
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)]
)


def hexdump(src, length=16, show=True):
    """Display data being send and received
    in a readable hex dump format for debugging"""
    # If there is a set ob bytes in src -> decode it
    if isinstance(src, bytes):
        src = src.decode()
    results = list()
    # Take part of src and devide it to two variables:
    # printable is string representation
    # hexa      is a hexadecimal representation 
    for i in range(0, len(src), length):
        word = str(src[i:i+length])
        printable = word.translate(HEX_FILTER)
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length*3
        # Make a table containing: indexes (HEX) _ 16 Hex data fragments _ 16 string data fragments
        results.append(f'{i:04x}   {hexa:<{hexwidth}}   {printable}')
    if show:
        for line in results:
            print(line)
    else:
        return results

def receive_from(connection):
    """Read from a socket until a specific condition is met,
    like the end of a message or a timeout"""
    buffer = b""
    connection.settimeout(10)
    # connection.setblocking(True)
    try:
        # read data and save it in buffer
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except socket.timeout:
        print("Error: Socket timed out")
    except Exception as e:
        print('Error receive_from - ', e)
    return buffer

def request_handler(buffer):
    """Modify incoming client request before forwarding"""
    return buffer

def response_handler(buffer):
    """Modify server response before sending back to client"""
    return buffer

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    """The core function that decides how to route the incoming data.
    It receives data from one end, applies any transformations or logging,
    and sends it out the other end.\n
    Optionally receives data first from either client or server based on 'receive_first'
    """
    remote_buffer = b''
    try:
        # connect with remote host
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((remote_host, remote_port))
    except socket.error as e:
        print(f"[!!] Failed to connect to {remote_host}:{remote_port} - {e}")
        return
        
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        if remote_buffer is None:
            print("[!!] Failed to receive data from remote server.")
            return
        hexdump(remote_buffer)

    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print(f"[==>] Sent {len(remote_buffer)} bytes to local host.")
        # send remote_buffer to local client
        client_socket.send(remote_buffer)

    while True:
        # get data from local client_socket
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            line = f"Received {len(local_buffer)} bytes from local host."
            print(line)
            hexdump(local_buffer)
            # modify request
            local_buffer = request_handler(local_buffer)
            # send response to remote host
            remote_socket.send(local_buffer)
            print("[==>] Send to remote host")

        # get data from remote host
        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print(f"[<==] Received {len(remote_buffer)} bytes from remote host.")
            hexdump(remote_buffer)
            # modify reponse
            remote_buffer = response_handler(remote_buffer)
            # send response to local client
            client_socket.send(remote_buffer)
            print("[==>] Sent to local host.")

        if not len(local_buffer) and not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing conecction.")
            break


def initialize_backend_connection(remote_host, remote_port):
    """Initialize and manage a connection to the backend server"""
    pass

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    """Main loop to listen for incoming client connections and spawn threads for proxy handler"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def graceful_shutdown(signum, frame):
        print("[*] Shuttin down gracefully...")
        server.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, graceful_shutdown)
    
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print(f'Problem with creating socket {e}')
        print(f"[!!] Failed to listen at {local_host}:{local_port}")
        print(f"[!!] Check other listening sockets or change permissions.")
        sys.exit(0)

    server.listen(5)
    print(f"[*] Listening on {local_host}:{local_port}")
    while True:
        try:
            client_socket, addr = server.accept()
            # Display information about local connection
            print(f"[*] Received connection from {addr[0]}:{addr[1]}")
            # Start thread for communication with remote host
            proxy_thread = threading.Thread(
                target = proxy_handler,
                args=(client_socket,
                      remote_host,
                      remote_port,
                      receive_first))
            proxy_thread.start()
        except Exception as e:
            print(f"[!!] Error accepting the connection: {e}")


def error_handler(error_message):
    """Log the handle errors or exceptions, possibly terminating the proxy"""
    pass


def main():
    if len(sys.argv[1:]) != 5:
        print("Use: ./proxy.pl [local host] [local port]", end=" ")
        print("[remote host] [remote port] [receive first]")
        print("Example: python proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)
    
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    receive_first = sys.argv[5]

    if 'True' in receive_first:
        receive_first = True
    else:
        recieve_first = False

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == "__main__":
    """Main entry point, parse arguments and set up the local listening socket
    Call the server loop"""
    main()
