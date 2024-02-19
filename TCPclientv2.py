import socket

def send_request(client, request):
    client.send(request.encode())

def receive_response(client, buffer_size=4096):
    response = b""
    while True:
        part = client.recv(buffer_size)
        if not part:
            break
        response += part
        response += b'\nnew response'
    return response

try:
    target_host = "0.0.0.0"
    target_port = 9998

    # create socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Set a timeout for the connection (in seconds)
    client.settimeout(10)  # Adjust the timeout value as needed

    # connect to server
    client.connect((target_host, target_port))

    # Send an HTTP request
    request = "GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"
    send_request(client, request)

    # Receive the server's response
    response = receive_response(client)
    print(response.decode())

except socket.timeout:
    print("Connection timed out. The server did not respond within the specified time.")

except ConnectionRefusedError:
    print("Connection refused. The server may be down or the target host/port is incorrect.")

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    client.close()
