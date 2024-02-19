import socket

target_host = "127.0.0.1"
target_port = 9997

# create socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# send data
client.sendto("AAABBBCCC", (target_host, target_port))

# recieve data
data, addr = client.recvform(4096)

print(data.decode())
client.close()