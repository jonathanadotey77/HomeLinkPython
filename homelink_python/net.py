import socket

def sendBufferTcp(dataSocket: socket.socket, buffer: bytearray) -> bool:
    bytesSent = 0
    
    for _ in range(10):
        if bytesSent >= len(buffer):
            break
        
        rc = dataSocket.send(buffer[bytesSent:])
        
        if rc < 0:
            print(f"send() failed [{socket.error}]")
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
            print(bytesReceived)
            continue
        
        if data == None:
            print(f"recv() failed [{socket.error}]")
            return None
        buffer.extend(data)
        
        bytesReceived += len(data)
    return buffer