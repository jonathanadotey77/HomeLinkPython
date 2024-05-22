from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 256
SESSION_KEY_SIZE = 48


def randomBytes(n: int):
    return bytearray(Random.get_random_bytes(n))


def generateRSAKeys():
    return RSA.generate(RSA_KEY_SIZE)


def getRSAPublicKey(keypair) -> str:
    return keypair.publickey().exportKey("PEM").decode("UTF-8")


def printRSAPublicKey(keypair):
    print(getRSAPublicKey(keypair))


def aesEncrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    temp = cipher.encrypt_and_digest(data)
    temp = (bytearray(temp[0]), bytearray(temp[1]))

    return temp


def aesDecrypt(data, key, iv, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    temp = cipher.decrypt_and_verify(data, tag)

    return bytearray(temp) if temp else None


def rsaEncrypt(data: bytearray | bytes, key: str):
    pubkey = RSA.importKey(key)
    cipher = PKCS1_OAEP.new(pubkey)

    return bytearray(cipher.encrypt(data))


def rsaDecrypt(data, keypair):
    cipher = PKCS1_OAEP.new(keypair)

    return bytearray(cipher.decrypt(data))

def encryptSessionKey(sessionKey: str, aesKey: bytearray | bytes): 
    sessionKeyBytes = bytearray(sessionKey.encode("UTF-8"))
    sessionKeyBytes.extend(bytearray(48 - len(sessionKeyBytes)))

    iv = randomBytes(16)
    data, tag = aesEncrypt(sessionKeyBytes, aesKey, iv)
    return data + iv + tag

def decryptSessionKey(encryptedSessionKey: bytearray | bytes, aesKey: bytearray | bytes):
    sessionKeyBytes = encryptedSessionKey[:SESSION_KEY_SIZE]
    iv = encryptedSessionKey[SESSION_KEY_SIZE:SESSION_KEY_SIZE + 16]
    tag = encryptedSessionKey[SESSION_KEY_SIZE + 16:]

    data = aesDecrypt(sessionKeyBytes, aesKey, iv, tag)
    data = data[:33]
    data = data.decode("UTF-8")

    return data



def hashString(string: str):
    hash_object = SHA256.new(data=string.encode())
    sha256_hash = hash_object.hexdigest()

    return sha256_hash
