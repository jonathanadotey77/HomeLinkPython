from homelink_python.net import sendBufferTcp, receiveBufferTcp

from homelink_python.packet import (
    KeyRequestPacket,
    KeyResponsePacket,
    CommandPacket,
    LoginRequestPacket,
    LoginResponsePacket,
    RegisterRequestPacket,
    RegisterResponsePacket,
    LoginStatus,
)

from homelink_python.security import (
    RSA_KEY_SIZE,
    rsaEncrypt,
    rsaDecrypt,
    aesEncrypt,
    aesDecrypt,
    randomBytes,
    getRSAPublicKey,
    hashString,
)

import ipaddress
import os
import random
import socket
import struct

FILE_BLOCK_SIZE = 8192


class HomeLinkClient:
    def __init__(
        self,
        hostId: str,
        serviceId: str,
        serverIpAddress: str,
        serverControlPort: int,
        serverDataPort: int,
    ):
        ipv6Address = str(ipaddress.IPv6Address(f"::ffff:{serverIpAddress}"))
        self.controlSocket = None
        self.serverTcpAddress = (ipv6Address, serverDataPort)
        self.serverUdpAddress = (ipv6Address, serverControlPort)
        self.controlAddress = [None, None]
        self.serverPort = None
        self.serverPublicKey = None
        self.clientPublicKey = None
        self.hostId = hostId
        self.serviceId = serviceId
        self.connectionId = None
        self.aesKey = None

    def initialize(self, serviceId):
        self.serviceId = serviceId
        self.controlSocket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.controlAddress = ("::0.0.0.0", random.randint(50000, 59999))
        self.controlSocket.bind(self.controlAddress)
        self.controlSocket.settimeout(3)
        self.controlSocket.connect(self.serverUdpAddress)
        self.clientPublicKey = getRSAPublicKey()

    def shutdown(self):
        self.controlSocket.close()

    def login(self, password: str):
        connectionId = 0
        while True:
            connectionId = random.randint(0, 4294967295)
            keyRequestPacket = KeyRequestPacket(connectionId, self.clientPublicKey)
            data = KeyRequestPacket.serialize(keyRequestPacket)
            self.controlSocket.sendto(data, self.serverUdpAddress)
            try:
                data, _ = self.controlSocket.recvfrom(1024)
            except socket.timeout:
                continue

            keyResponsePacket = KeyResponsePacket.deserialize(data)
            self.serverPublicKey = keyResponsePacket.rsaPublicKey.rstrip("\x00")
            if keyResponsePacket.success == 0:
                continue
            else:
                self.aesKey = rsaDecrypt(keyResponsePacket.aesKey, None)
                break

        while True:
            passwordData = struct.pack(
                "32s65s7s24s",
                randomBytes(32),
                hashString(password).encode("UTF-8"),
                bytes([0] * 8),
                randomBytes(24),
            )
            registerRequestPacket = RegisterRequestPacket(
                connectionId,
                self.host_id,
                self.serviceId,
                rsaEncrypt(passwordData, self.serverPublicKey),
            )
            data = RegisterRequestPacket.serialize(registerRequestPacket)
            self.controlSocket.sendto(data, self.serverUdpAddress)
            try:
                data, _ = self.controlSocket.recvfrom(1024)
            except socket.timeout:
                continue

            registerResponsePacket = RegisterResponsePacket.deserialize(data)
            if (
                registerResponsePacket.status == LoginStatus.USER_ALREADY_EXISTS
                or registerResponsePacket.status == LoginStatus.LOGIN_SUCCESS
            ):
                break
            else:
                return None

        while True:
            tag = random.randint(0, 4294967295)
            passwordData = struct.pack(
                "!I28s65s7s24s",
                tag,
                randomBytes(28),
                hashString(password).encode("UTF-8"),
                bytes([0] * 8),
                randomBytes(24),
            )
            loginRequestPacket = LoginRequestPacket(
                connectionId,
                self.host_id,
                self.serviceId,
                rsaEncrypt(passwordData, self.serverPublicKey),
            )
            data = LoginRequestPacket.serialize(loginRequestPacket)
            self.controlSocket.sendto(data, self.serverUdpAddress)
            try:
                data, _ = self.controlSocket.recvfrom(1024)
            except socket.timeout:
                continue

            loginResponsePacket = LoginResponsePacket.deserialize(data)
            if loginResponsePacket.status == LoginStatus.LOGIN_SUCCESS:
                self.sessionToken = rsaDecrypt(
                    loginResponsePacket.sessionKey, None
                ).decode("UTF-8")
                break
            else:
                return None

        self.connectionId = connectionId
        return connectionId

    def sendFile(
        self,
        destinationHostId: str,
        destinationServiceId: str,
        filepath: str,
        filename: str,
    ):
        dataSocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        dataSocket.connect(self.serverTcpAddress)
        fileSize = os.stat(filepath).st_size
        self.sendCommand(
            dataSocket,
            f"WRITE_FILE {destinationHostId} {destinationServiceId} {filename} {fileSize}",
        )
        fileInfo = bytearray(f"{filename} {fileSize}".encode("UTF-8"))
        if len(fileInfo) < 128:
            fileInfo.extend(bytearray(128 - len(fileInfo)))
        iv = randomBytes(16)
        sendBuffer, tag = aesEncrypt(fileInfo, self.aesKey, iv)
        sendBuffer = bytearray(sendBuffer)
        if len(sendBuffer) < 128:
            sendBuffer.extend(bytearray(128 - len(sendBuffer)))
        sendBuffer.extend(iv)
        sendBuffer.extend(tag)

        sendBufferTcp(dataSocket, sendBuffer)

        recvBuffer = receiveBufferTcp(dataSocket, 17)
        if recvBuffer == None:
            return

        with open(filepath, "rb") as f:
            bytesSent = 0
            fileData = bytearray(f.read(FILE_BLOCK_SIZE))
            if len(fileData) < FILE_BLOCK_SIZE:
                fileData.extend(bytearray(FILE_BLOCK_SIZE - len(fileData)))
            while bytesSent < fileSize:
                iv = recvBuffer[1:]
                sendBuffer, tag = aesEncrypt(fileData, self.aesKey, iv)
                sendBuffer.extend(tag)
                status = sendBufferTcp(dataSocket, sendBuffer)
                if not status:
                    print(f"sendBufferTcp() failed")
                    break

                recvBuffer = self.receiveBufferTcp(dataSocket, 17)
                if recvBuffer == None:
                    print(f"recvBufferTcp() failed")
                    break
                if recvBuffer[0] == 0:
                    bytesSent += FILE_BLOCK_SIZE
                    fileData = bytearray(f.read(FILE_BLOCK_SIZE))
                    if len(fileData) < FILE_BLOCK_SIZE:
                        fileData.extend(bytearray(FILE_BLOCK_SIZE - len(fileData)))

        dataSocket.close()

    def recvFile(self, prefix: str, display: bool):
        dataSocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        dataSocket.connect(self.serverTcpAddress)

        self.sendCommand(dataSocket, "READ_FILE")

        info = self.receiveBufferTcp(dataSocket, 1)

        if not info:
            print("recvBufferTcp() failed")

        if info[0] == 0:
            return ""

        fileInfo = self.receiveBufferTcp(dataSocket, 160)
        if not fileInfo:
            print("Could not fetch file info")
            return None

        fileInfo = aesDecrypt(
            fileInfo[:128], self.aesKey, fileInfo[128:144], fileInfo[144:]
        )
        if fileInfo == None:
            print("Could not fetch file info")
            return None

        fileInfo = fileInfo.decode("UTF-8").rstrip("\x00")
        fileInfo = fileInfo.split()
        if len(fileInfo) != 2 or len(fileInfo[0]) == 0:
            print("Invalid file info")
            return None

        filename, fileSize = fileInfo
        fileSize = int(fileSize)
        iv = randomBytes(16)
        status = sendBufferTcp(dataSocket, bytearray(1) + iv)
        if not status:
            print("Could not send first ACK")
            return None

        filePath = prefix + filename
        bytesReceived = 0
        success = True
        with open(filePath, "wb") as f:
            blockNumber = 0

            while bytesReceived < fileSize:
                buffer = self.receiveBufferTcp(dataSocket, FILE_BLOCK_SIZE + 16)
                if not buffer:
                    print("recvBufferTcp() failed")
                    success = False
                    break

                data = buffer[:FILE_BLOCK_SIZE]
                tag = buffer[FILE_BLOCK_SIZE:]
                data = aesDecrypt(data, self.aesKey, iv, tag)
                if data:
                    bytesReceived += FILE_BLOCK_SIZE
                    numBytes = FILE_BLOCK_SIZE
                    if bytesReceived >= fileSize:
                        numBytes = fileSize - FILE_BLOCK_SIZE * blockNumber
                    blockNumber += 1

                    f.write(data[:numBytes])

                iv = randomBytes(16)
                status = sendBufferTcp(dataSocket, bytearray(1) + iv)

        if not success or bytesReceived < fileSize:
            os.remove(filePath)
            return None

        if display:
            with open(filePath, "r") as f:
                try:
                    i = 1
                    for line in f:
                        print(f"{i}| {line}")
                except UnicodeDecodeError:
                    print("File is not in UTF-8 format")

        dataSocket.close()
        return filePath

    def sendCommand(self, dataSocket: socket.socket, command: str):
        sessionToken = rsaEncrypt(
            self.sessionToken.encode("UTF-8"), self.serverPublicKey
        )
        data = randomBytes(32)
        data.extend(command.encode("UTF-8"))
        if len(data) < 200:
            data.extend(bytearray(200 - len(data)))
        data = rsaEncrypt(data, self.serverPublicKey)
        commandPacket = CommandPacket(self.connectionId, sessionToken, data)
        buffer = CommandPacket.serialize(commandPacket)
        sendBufferTcp(dataSocket, buffer)
