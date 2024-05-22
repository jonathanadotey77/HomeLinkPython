import os
import socket

def _makeParentDirectory(dir: str):
    temp = dir
    if temp[-1] == '/':
        temp = temp[:-1]

    for last in range(len(temp) - 2, -1, -1):
        if temp[last] == '/':
            temp = temp[:last]
            break

    p = 1
    while p < len(temp):
        if temp[p] == '/':
            os.makedirs(temp, exist_ok=True)
        p += 1

    os.makedirs(temp, exist_ok=True)

def sendBufferTcp(dataSocket: socket.socket, buffer: bytearray) -> bool:
    bytesSent = 0
    
    for _ in range(10):
        if bytesSent >= len(buffer):
            break
        
        rc = 0
        try:
            rc = dataSocket.send(buffer[bytesSent:])
        except socket.timeout:
            continue
        except socket.error as e:
            print(f"send() failed [{e.errno}]")
            return False
        
        bytesSent += rc
    return bytesSent == len(buffer)

def receiveBufferTcp(dataSocket: socket.socket, n: int) -> bytearray | None:
    bytesReceived = 0
    buffer = bytearray()
    
    for _ in range(10):
        if len(buffer) >= n:
            break
        data = None
        try:
            data = dataSocket.recv(n - bytesReceived)
        except socket.timeout:
            continue
        except socket.error as e:
            print(f"recv() failed [{e.errno}]")
            return None
        buffer.extend(data)
        
        bytesReceived += len(data)
    return buffer