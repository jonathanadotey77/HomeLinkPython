from homelink_python.net import sendBufferTcp, receiveBufferTcp

from homelink_python.packet import *

from homelink_python.security import *

import ipaddress
import os
import socket
import sys

FILE_BLOCK_SIZE = 8192

class HomeLinkClient:
    def __init__(
        self,
        hostId: str,
        serviceId: str,
        serverIpAddress: str,
        serverPort: int,
    ):
        self.serverAddressStr = str(ipaddress.IPv6Address(f"::ffff:{serverIpAddress}"))
        self.serverAddress = (self.serverAddressStr, serverPort)
        self.serverPort = serverPort
        self.keypair = generateRSAKeys()
        self.serverPublicKey = None
        self.clientPublicKey = getRSAPublicKey(self.keypair)
        self.aesKey = None
        self.hostId = hostId
        self.serviceId = serviceId
        self.connectionId = None    
        self.sessionKey = None
        self.active = True
        self.syncSocket = None
        self.asyncFileSocket = None
        self.asyncFileThread = None

    def _getHostKey():
        hostKeyfilePath = f"{os.getenv('HOME')}/.config/homelink/host.key"

        if not os.path.isfile(hostKeyfilePath):
            with open(hostKeyfilePath, "w") as hostKeyFile:
                hostKey = randomBytes(32)
                hostKeyStr = hostKey.hex()
                hostKeyFile.write(hostKeyStr)
        
        hostKey = None
        with open(hostKeyfilePath, "r") as hostKeyFile:
            hostKey = hostKeyFile.readline()
        
        return hostKey

                

    def _readFileAsyncThread(client, directory, callback, context):
        pass

    def _sendCommand(client, command: str):
        if len(command) > 223:
            print("Command is too long!", file=sys.stderr)
            return
        
        commandData = command.encode("UTF-8")
        commandData = randomBytes(32) + commandData + bytearray(len(commandData))
        if len(commandData) < 224:
            commandData += bytearray(224 - len(commandData))

        iv = randomBytes(16)
        data, tag = aesEncrypt(commandData, client.aesKey, iv)

        commandPacket = CommandPacket(client.connectionId, encryptSessionKey(client.sessionKey, client.aesKey), data + iv + tag)
        status = sendBufferTcp(client.syncSocket, CommandPacket.serialize(commandPacket))
        if not status:
            print("sendBufferTcp() failed", file=sys.stderr)

    def connect(self):
        self.syncSocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

        try:
            self.syncSocket.connect(self.serverAddress)
        except socket.error as e:
            print(f"connect() failed [{e.errno}]", file=sys.stderr)
            return False
        
        connectionId = int.from_bytes(randomBytes(4))
        rsaPublicKey = getRSAPublicKey(self.keypair)

        connectionRequestPacket = ConnectionRequestPacket(connectionId, rsaPublicKey)

        status = sendPacket(self.syncSocket, connectionRequestPacket)
        if not status:
            return False
        
        connectionResponsePacket = recvPacket(self.syncSocket, ConnectionResponsePacket)
        if not connectionResponsePacket:
            return False
        
        if connectionResponsePacket.success:
            self.serverPublicKey = connectionResponsePacket.rsaPublicKey.rstrip("\x00")
            self.aesKey = rsaDecrypt(connectionResponsePacket.aesKey, self.keypair)
            self.connectionId = connectionId

        return connectionResponsePacket.success
        
        

    def registerHost(self) -> RegisterStatus:
        hostKey = HomeLinkClient._getHostKey()
        data = randomBytes(32) + hostKey.encode("UTF-8")
        data += bytearray(128 - len(data))
        data = rsaEncrypt(data, self.serverPublicKey)

        registerRequestPacket = RegisterRequestPacket(RegistrationType.HOST_REGISTRATION, self.hostId, "", data)

        status = sendPacket(self.syncSocket, registerRequestPacket)
        if not status:
            return RegisterStatus.REGISTER_FAILED
        
        registerResponsePacket = recvPacket(self.syncSocket, RegisterResponsePacket)
        if not registerResponsePacket:
            return RegisterStatus.REGISTER_FAILED
        
        return registerResponsePacket.status


    def registerService(self, serviceId: str, password: str):
        if len(serviceId > 32):
            print("ServiceId must be at most 32 characters", file=sys.stderr)

        hashedPassword = hashString(password)
        hostKey = HomeLinkClient._getHostKey()

        passwordData = randomBytes(32) + hostKey.encode("UTF-8") + hashedPassword.encode("UTF-8")
        passwordData += bytearray(192 - len(passwordData))

        data = rsaEncrypt(passwordData, self.serverPublicKey)

        registerRequestPacket = RegisterRequestPacket(RegistrationType.SERVICE_REGISTRATION, self.hostId, serviceId, data)

        status = sendPacket(self.syncSocket, registerRequestPacket)
        if not status:
            return RegisterStatus.REGISTER_FAILED
        
        registerResponsePacket = recvPacket(self.syncSocket, RegisterResponsePacket)
        if not registerResponsePacket:
            return RegisterStatus.REGISTER_FAILED
        
        return registerResponsePacket.status

    def login(self, password: str):
        hashedPassword = hashString(password)
        hostKey = HomeLinkClient._getHostKey()

        passwordData = randomBytes(32) + hostKey.encode("UTF-8") + bytearray(1) + hashedPassword.encode("UTF-8") + bytearray(1)
        passwordData += randomBytes(192 - len(passwordData))

        data = rsaEncrypt(passwordData, self.serverPublicKey)

        loginRequestPacket = LoginRequestPacket(self.connectionId, self.hostId, self.serviceId, data)
        status = sendPacket(self.syncSocket, loginRequestPacket)
        if not status:
            return LoginStatus.LOGIN_FAILED
        
        loginResponsePacket = recvPacket(self.syncSocket, LoginResponsePacket)
        if not loginResponsePacket:
            return LoginStatus.LOGIN_FAILED
        
        if loginResponsePacket.status == LoginStatus.LOGIN_SUCCESS:
            self.sessionKey = decryptSessionKey(loginResponsePacket.sessionKey, self.aesKey)
        
        return loginResponsePacket.status

    def logout(self):
        data = rsaEncrypt(self.aesKey, self.serverPublicKey)
        logoutPacket = LogoutPacket(self.connectionId, data)
        status = sendPacket(self.syncSocket, logoutPacket)
        if not status:
            return
        
        self.active = False

    def readFileAsync(self, directory: str, callback, context):
        pass

    def waitAsync(self):
        pass

    def stopAsync(self):
        pass

    def readFile(self):
        pass

    def writeFile(self, destinationHostId: str, destinationServiceId: str, localPath: str, remotePath: str):
        pass

    def destruct(self):
        if self.syncSocket:
            self.syncSocket.close()
        
        if self.asyncFileSocket:
            self.asyncFileSocket.close()

    

