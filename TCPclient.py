import socket

target_host = "127.0.0.2"
target_port = 8080

# create socket object
# AF_INET - IPv4 address or host
# SOCK_STREAM - create TCP protocol
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect to server
client.connect((target_host, target_port))

# send data
# request = "GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"
# request = "USER anonymous\r\n"
request = "PASS sekret\r\n"
client.send(request.encode())

# recieve data
response = client.recv(4096)

print(response.decode())
client.close()