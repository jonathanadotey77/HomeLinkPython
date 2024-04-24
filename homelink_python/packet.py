import struct

class PacketTypeException(Exception):
    pass

class LoginStatus:
    LOGIN_FAILED = 0
    LOGIN_SUCCESS = 1
    NO_AVAILABLE_PORT = 2
    NO_SUCH_USER = 3
    USER_ALREADY_EXISTS = 4

class PacketType:
    CLI = 255
    ACK = 0
    KEY_REQUEST = 1
    KEY_RESPONSE = 2
    HANDSHAKE = 3
    COMMAND = 4
    LOGIN_REQUEST = 5
    LOGIN_RESPONSE = 6
    REGISTER_REQUEST = 7
    REGISTER_RESPONSE = 8
    LOGOUT = 9

class AckPacket:
    packetType = PacketType.ACK
    def __init__(self, value: int):
        self.value = value

    @staticmethod
    def serialize(packet):
        return struct.pack("!BI", packet.packetType, packet.value)

    @staticmethod
    def deserialize(buffer):
        packetType, value = struct.unpack("!BI", buffer)
        if packetType != PacketType.ACK:
            raise PacketTypeException()
        return KeyResponsePacket(value)

class KeyRequestPacket:
    def __init__(self, connectionId: int, rsaPublicKey: str):
        self.packetType = PacketType.KEY_REQUEST
        self.connectionId = connectionId
        self.rsaPublicKey = rsaPublicKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BI512s",
            packet.packetType,
            packet.connectionId,
            packet.rsaPublicKey.encode("utf-8"),
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, rsaPublicKey = struct.unpack("!BI512s", buffer)
        if packetType != PacketType.KEY_REQUEST:
            raise PacketTypeException()
        return KeyRequestPacket(connectionId, rsaPublicKey)


class KeyResponsePacket:
    def __init__(self, success: bool, rsaPublicKey: str, aesKey: bytearray):
        self.packetType = PacketType.KEY_RESPONSE
        self.success = success
        self.rsaPublicKey = rsaPublicKey
        self.aesKey = aesKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "BB512s256s",
            packet.packetType,
            1 if packet.success else 0,
            packet.rsaPublicKey.encode("utf8"),
            packet.aesKey,
        )

    @staticmethod
    def deserialize(buffer):
        packetType, success, rsaPublicKey, aesKey = struct.unpack("BB512s256s", buffer)
        if packetType != PacketType.KEY_RESPONSE:
            raise PacketTypeException()
        return KeyResponsePacket(success == 1, rsaPublicKey.decode("utf-8"), aesKey)

class CommandPacket:
    def __init__(self, connectionId: int, sessionToken: bytearray, data: bytearray):
        self.packetType = PacketType.COMMAND
        self.connectionId = connectionId
        self.sessionToken = sessionToken
        self.data = data

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BI256s256s",
            packet.packetType,
            packet.connectionId,
            packet.sessionToken,
            packet.data
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, sessionToken, data = struct.unpack("!BI256s256s", buffer)
        if packetType != PacketType.COMMAND:
            raise PacketTypeException()
        return CommandPacket(connectionId, sessionToken, data)

class LoginRequestPacket:
    def __init__(self, connectionId: int, hostId: str, serviceId: str, data: bytearray):
        self.packetType = PacketType.LOGIN_REQUEST
        self.connectionId = connectionId
        self.hostId = hostId
        self.serviceId = serviceId
        self.data = data

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BI33s33s256s",
            packet.packetType,
            packet.connectionId,
            packet.hostId.encode("UTF-8"),
            packet.serviceId.encode("UTF-8"),
            packet.data
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, hostId, serviceId, data = struct.unpack("!BI33s33s256s", buffer)
        if packetType != PacketType.LOGIN_REQUEST:
            raise PacketTypeException()
        return LoginRequestPacket(connectionId, hostId, serviceId, data)

class LoginResponsePacket:
    def __init__(self, status: bool, sessionKey: bytearray):
        self.packetType = PacketType.LOGIN_RESPONSE
        self.status = status
        self.sessionKey = sessionKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BB256s",
            packet.packetType,
            packet.status,
            packet.sessionKey
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, status, sessionKey = struct.unpack("!BB256s", buffer)
        if packetType != PacketType.LOGIN_RESPONSE:
            raise PacketTypeException()
        return LoginResponsePacket(status, sessionKey)

class RegisterRequestPacket:
    def __init__(self, connectionId: int, hostId: str, serviceId: str, sessionKey: bytearray):
        self.packetType = PacketType.REGISTER_REQUEST
        self.connectionId = connectionId
        self.hostId = hostId
        self.serviceId = serviceId
        self.sessionKey = sessionKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BI33s33s256s",
            packet.packetType,
            packet.connectionId,
            packet.hostId.encode("UTF-8"),
            packet.serviceId.encode("UTF-8"),
            packet.sessionKey
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, hostId, serviceId, sessionKey = struct.unpack("!BI33s33s256s", buffer)
        if packetType != PacketType.REGISTER_REQUEST:
            raise PacketTypeException()
        return RegisterRequestPacket(connectionId, hostId, serviceId, sessionKey)


class RegisterResponsePacket:
    def __init__(self, status: bool):
        self.packetType = PacketType.REGISTER_RESPONSE
        self.status = status

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BB",
            packet.packetType,
            packet.status
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, status = struct.unpack("!BB", buffer)
        if packetType != PacketType.REGISTER_RESPONSE:
            raise PacketTypeException()
        return RegisterResponsePacket(status)

class LogoutPacket:
    def __init__(self, connectionId: int, sessionKey: bytearray):
        self.packetType = PacketType.LOGOUT
        self.connectionId = connectionId
        self.sessionKey = sessionKey
    
    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BI256s",
            packet.packetType,
            packet.connectionId,
            packet.sessionToken
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, sessionToken = struct.unpack("!BI256s", buffer)
        if packetType != PacketType.LOGOUT:
            raise PacketTypeException()
        return LogoutPacket(connectionId, sessionToken)
