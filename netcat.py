import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading

# python netcat.py -t 10.0.2.15 -p 5555
class NetCat:
    def __init__(self, args, buffer=None):
        """
        args is namespace from praser.prase_args()\n
        eg. Namespace(t='192.168.0.1', p=8000, l=True)
        """
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # set socket option reuse the local address and port to 1 (enable)
        # useful for quickly restarting the script after it has terminated
        # after socket is closed and go to WAIT_TIME next socket can take
        # its place by 'stealing' its association
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        """Set NetCat mode to:\n
        send() with args: -t -p\n
        listen() with args: -t -p -l (optional -c -e -u) """
        # namespace([listen = True]) from '-l' or '--listen' command-line option
        if self.args.listen:
            self.listen()
        else:
            self.send()
    
    def send(self):
        self.socket.connect((self.args.target, self.args.port))
        # if buffer is not '' or None -> send the data to receiver (request)
        if self.buffer:
            self.socket.send(self.buffer)

        try:
            while True:
                recv_len = 1
                response = ''
                # receive response from target computer as long as there 
                # is data to aquire in chunks of up to 4096 bytes
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                # if there is a response, print it and get new data to send
                if response:
                    print(response)
                    buffer = input('> ')
                    buffer += '\n'
                    self.socket.send(buffer.encode())

        # If Ctrl+C is pressed - interruption and exit the connection
        except KeyboardInterrupt:
            print('Operation stopped by user')
            self.socket.close()
            sys.exit()

    def listen(self):
        print("Listening...")
        try:
            self.socket.bind((self.args.target, self.args.port))
        except socket.error as e:
            print(f"Error on socket binding: {e}")
            return
        self.socket.listen(5) # max 5 queued up connections
        while True:
            # return a new socket for communication with the client
            client_socket, _ = self.socket.accept()
            # create a new thread for each incoming connection
            client_thread = threading.Thread(target=self.handle, args=(client_socket,))
            # execute the self.handle()
            client_thread.start()

    def handle(self, client_socket):
        """listening mode ON\n
        Run the function specified in args"""
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())
            
        elif self.args.upload:
            file_buffer = b''
            while True:
                # get data in chunks of 4096 bytes
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            # open declared file in write-binary mode
            with open(self.args.upload, 'wb') as f:
                # write/save the received data in file
                f.write(file_buffer)
                message = f'Saved file: {self.args.upload}'
                # send the message back to the client
                client_socket.send(message.encode())
        
        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    # send ' #> ' to the client - ready to receive command
                    client_socket.send(b' #> ')
                    # get a complete command terminated by new line character
                    while '\n' not in cmd_buffer.decode():
                        # receive data in chunks of 64 bytes
                        cmd_buffer += client_socket.recv(64)
                    # decode completed command and execute it
                    response = execute(cmd_buffer.decode())
                    # if there is a response send it back to client
                    if response:
                        client_socket.send(response.encode())
                    # clear the cmd_buffer
                    cmd_buffer = b''
                except Exception as e:
                    print(f'Server stopped {e}')
                    self.socket.close()
                    sys.exit()
    
    
                


def execute(cmd):
    """Take cmd command, execute it and return the output = (stdout+stderr)
    """
    # remove leading and trailing whitespaces
    cmd = cmd.strip()

    # check if command is empty
    if not cmd:
        return
    
    # shlex.split(cmd) -> split the command into list of aruments
    # subprocess.check_output() -> executes the command and captures its stdout
    # stderr=subprocess.STDOUT redirects stderr to stdout so errors+output is captured
    output = subprocess.check_output(shlex.split(cmd),
                                     stderr = subprocess.STDOUT)

    # decode the captured binary output into a string
    return output.decode()

# if script is run as a main program
# -c -e -u arguments are extension for -l (listening mode)
# for sending just -t and -p need to be provided
if __name__ == '__main__':
    # Create a command-line argument parser
    parser = argparse.ArgumentParser(
        description='BHP tool',
        formatter_class= argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Examples:
            netcat.py -t 192.168.1.108 -p 5555 -l -c
            netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.whatisup
            netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\"
            
            echo 'ABCDEFGHI' | ./netcal.py -t 192.168.1.108 -p 135
            netcat.py -t 102.168.1.108 -p 5555
            ''')
    )
    # if '-c' argument appear, bcs of action='store_true' c=True  
    parser.add_argument('-c', '--command', action='store_true', help='open shell')
    parser.add_argument('-e', '--execute', help='run input task')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int, default=5555, help='target port ID')
    parser.add_argument('-t', '--target', default='192.168.1.203', help='target IP address')
    parser.add_argument('-u', '--upload', help='upload the file')

    # parse the command line arguments and return populated namespace
    args = parser.parse_args()

    # If program is opened as a listener (-l) buffer is empty
    if args.listen:
        buffer = ''
    # if program is opened in sender mode stdin is read
    else:
        buffer = sys.stdin.read()

    # Create an instance of the NetCat class with parsed arguments
    nc = NetCat(args, buffer.encode('utf-8'))
    # Start NetCat utility
    nc.run()