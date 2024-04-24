from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

RSA_KEY_SIZE = 2048

_keypair = None

def randomBytes(n: int):
    return bytearray(Random.get_random_bytes(n))


def initializeSecurity():
    global _keypair
    _keypair = RSA.generate(RSA_KEY_SIZE)


def getRSAPublicKey():
    return _keypair.publickey().exportKey("PEM").decode("utf-8")


def printRSAPublicKey():
    print(getRSAPublicKey())


def rsaEncrypt(data, key):
    pubkey = RSA.importKey(key)
    cipher = PKCS1_OAEP.new(pubkey)

    return bytearray(cipher.encrypt(data))


def rsaDecrypt(data, key):
    cipher = PKCS1_OAEP.new(_keypair if key == None else key)
    
    return bytearray(cipher.decrypt(data))

def aesEncrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    
    temp = cipher.encrypt_and_digest(data)
    temp = (bytearray(temp[0]), bytearray(temp[1]))
    
    return temp

def aesDecrypt(data, key, iv, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    
    temp = cipher.decrypt_and_verify(data, tag)

    return bytearray(temp) if temp else None

def hashString(string: str):
    hash_object = SHA256.new(data=string.encode())
    sha256_hash = hash_object.hexdigest()
    
    return sha256_hash