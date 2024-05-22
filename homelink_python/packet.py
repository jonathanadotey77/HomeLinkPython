from homelink_python.net import sendBufferTcp, receiveBufferTcp
import socket
import struct
import sys

class PacketTypeException(Exception):
    pass

class LoginStatus:
    LOGIN_FAILED = 0
    LOGIN_SUCCESS = 1
    NO_SUCH_SERVICE = 2

class RegisterStatus:
    REGISTER_FAILED = 0
    REGISTER_SUCCESS = 1
    ALREADY_EXISTS = 2

class PacketType:
    ACK = 1
    KEY_REQUEST = 2
    KEY_RESPONSE = 3
    HANDSHAKE = 4
    COMMAND = 5
    LOGIN_REQUEST = 6
    LOGIN_RESPONSE = 7
    REGISTER_REQUEST = 8
    REGISTER_RESPONSE = 9
    LOGOUT = 10
    ASYNC_NOTIFICATION = 11

class RegistrationType:
    HOST_REGISTRATION = 1
    SERVICE_REGISTRATION = 2

class AsyncEventType:
    FILE_EVENT = 1
    ANY_EVENT = 255

class AckPacket:
    byteFormat = "!BI"
    def __init__(self, value: int):
        self.packetType = PacketType.ACK
        self.value = value

    @staticmethod
    def serialize(packet):
        return struct.pack(AckPacket.byteFormat, packet.packetType, packet.value)

    @staticmethod
    def deserialize(buffer):
        packetType, value = struct.unpack(AckPacket.byteFormat, buffer)
        if packetType != PacketType.ACK:
            raise PacketTypeException()
        return ConnectionResponsePacket(value)

class ConnectionRequestPacket:
    byteFormat = "!BI512s"
    def __init__(self, connectionId: int, rsaPublicKey: str):
        self.packetType = PacketType.KEY_REQUEST
        self.connectionId = connectionId
        self.rsaPublicKey = rsaPublicKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            ConnectionRequestPacket.byteFormat,
            packet.packetType,
            packet.connectionId,
            packet.rsaPublicKey.encode("utf-8"),
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, rsaPublicKey = struct.unpack(ConnectionRequestPacket.byteFormat, buffer)
        if packetType != PacketType.KEY_REQUEST:
            raise PacketTypeException()
        return ConnectionRequestPacket(connectionId, rsaPublicKey)


class ConnectionResponsePacket:
    byteFormat = "BB512s256s"
    def __init__(self, success: bool, rsaPublicKey: str, aesKey: bytearray):
        self.packetType = PacketType.KEY_RESPONSE
        self.success = success
        self.rsaPublicKey = rsaPublicKey
        self.aesKey = aesKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            ConnectionResponsePacket.byteFormat,
            packet.packetType,
            1 if packet.success else 0,
            packet.rsaPublicKey.encode("utf8"),
            packet.aesKey,
        )

    @staticmethod
    def deserialize(buffer):
        packetType, success, rsaPublicKey, aesKey = struct.unpack(ConnectionResponsePacket.byteFormat, buffer)
        if packetType != PacketType.KEY_RESPONSE:
            raise PacketTypeException()
        return ConnectionResponsePacket(success == 1, rsaPublicKey.decode("utf-8"), aesKey)

class CommandPacket:
    byteFormat = "!BI80s256s"
    def __init__(self, connectionId: int, sessionToken: bytearray, data: bytearray):
        self.packetType = PacketType.COMMAND
        self.connectionId = connectionId
        self.sessionToken = sessionToken
        self.data = data
    
    @staticmethod
    def size():
        return struct.calcsize(CommandPacket.byteFormat)

    @staticmethod
    def serialize(packet):
        return struct.pack(
            CommandPacket.byteFormat,
            packet.packetType,
            packet.connectionId,
            packet.sessionToken,
            packet.data
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, sessionToken, data = struct.unpack(CommandPacket.byteFormat, buffer)
        if packetType != PacketType.COMMAND:
            raise PacketTypeException()
        return CommandPacket(connectionId, sessionToken, data)

class LoginRequestPacket:
    byteFormat = "!BI33s33s256s"
    def __init__(self, connectionId: int, hostId: str, serviceId: str, data: bytearray):
        self.packetType = PacketType.LOGIN_REQUEST
        self.connectionId = connectionId
        self.hostId = hostId
        self.serviceId = serviceId
        self.data = data

    @staticmethod
    def serialize(packet):
        return struct.pack(
            LoginRequestPacket.byteFormat,
            packet.packetType,
            packet.connectionId,
            packet.hostId.encode("UTF-8"),
            packet.serviceId.encode("UTF-8"),
            packet.data
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, hostId, serviceId, data = struct.unpack(LoginRequestPacket.byteFormat, buffer)
        if packetType != PacketType.LOGIN_REQUEST:
            raise PacketTypeException()
        return LoginRequestPacket(connectionId, hostId, serviceId, data)

class LoginResponsePacket:
    byteFormat = "!BB80s"
    def __init__(self, status: bool, sessionKey: bytearray):
        self.packetType = PacketType.LOGIN_RESPONSE
        self.status = status
        self.sessionKey = sessionKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            LoginResponsePacket.byteFormat,
            packet.packetType,
            packet.status,
            packet.sessionKey
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, status, sessionKey = struct.unpack(LoginResponsePacket.byteFormat, buffer)
        if packetType != PacketType.LOGIN_RESPONSE:
            raise PacketTypeException()
        return LoginResponsePacket(status, sessionKey)

class RegisterRequestPacket:
    byteFormat = "BB33s33s256s"
    def __init__(self, registrationType: int, hostId: str, serviceId: str, data: bytearray):
        self.packetType = PacketType.REGISTER_REQUEST
        self.registrationType = registrationType
        self.hostId = hostId
        self.serviceId = serviceId
        self.data = data

    @staticmethod
    def serialize(packet):
        return struct.pack(
            RegisterRequestPacket.byteFormat,
            packet.packetType,
            packet.registrationType,
            packet.hostId.encode("UTF-8"),
            packet.serviceId.encode("UTF-8"),
            packet.data
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, registrationType, hostId, serviceId, sessionKey = struct.unpack(RegisterRequestPacket.byteFormat, buffer)
        if packetType != PacketType.REGISTER_REQUEST:
            raise PacketTypeException()
        return RegisterRequestPacket(registrationType, hostId, serviceId, sessionKey)


class RegisterResponsePacket:
    byteFormat = "!BB"
    def __init__(self, status: bool):
        self.packetType = PacketType.REGISTER_RESPONSE
        self.status = status

    @staticmethod
    def serialize(packet):
        return struct.pack(
            RegisterResponsePacket.byteFormat,
            packet.packetType,
            packet.status
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, status = struct.unpack(RegisterResponsePacket.byteFormat, buffer)
        if packetType != PacketType.REGISTER_RESPONSE:
            raise PacketTypeException()
        return RegisterResponsePacket(status)

class LogoutPacket:
    byteFormat = "!BI256s"
    def __init__(self, connectionId: int, data: bytearray):
        self.packetType = PacketType.LOGOUT
        self.connectionId = connectionId
        self.data = data
    
    @staticmethod
    def serialize(packet):
        return struct.pack(
            LogoutPacket.byteFormat,
            packet.packetType,
            packet.connectionId,
            packet.data
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, data = struct.unpack(LogoutPacket.byteFormat, buffer)
        if packetType != PacketType.LOGOUT:
            raise PacketTypeException()
        return LogoutPacket(connectionId, data)

class AsyncNotificationPacket:
    byteFormat = "!BBI"
    def __init__(self, eventType: int, tag: int):
        self.packetType = PacketType.ASYNC_NOTIFICATION
        self.eventType = eventType
        self.tag = tag
    
    @staticmethod
    def serialize(packet):
        return struct.pack(
            AsyncNotificationPacket.byteFormat,
            packet.packetType,
            packet.eventType,
            packet.tag
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, eventType, tag = struct.unpack(AsyncNotificationPacket.byteFormat, buffer)
        if packetType != PacketType.ASYNC_NOTIFICATION:
            raise PacketTypeException()
        return AsyncNotificationPacket(eventType, tag)

def sendPacket(dataSocket: socket.socket, packet) -> bool:
    status = sendBufferTcp(dataSocket, packet.__class__.serialize(packet))
    if not status:
        print("sendBufferTcp() failed", file=sys.stderr)
    return status

def recvPacket(dataSocket: socket.socket, PacketClass: type) -> bytearray | None:
    data = receiveBufferTcp(dataSocket, struct.calcsize(PacketClass.byteFormat))
    if not data:
        print("recvBufferTcp() failed", file=sys.stderr)
        return None
    
    return PacketClass.deserialize(data)